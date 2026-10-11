#!/usr/bin/env python
"""03b_check_flows.py -- sanity checks on a CICFlowMeter flow CSV (measure + report only).

Reads the single-packet-patched CICFlowMeter output for the benign pcap, runs nine
checks, prints a compact summary table, and writes
<out-dir>/flow_check_report.md and <out-dir>/flow_check_report.json.

Nothing is modified: the input CSV is opened read-only and no data is "fixed".

The CSV is read in chunks of --chunk rows (default 500,000), so memory does not grow with the
file (a 26.7M-packet SYN-flood part gives ~11M flows; loading it whole needed ~30 GB). Every
check is accumulated chunk by chunk and finalised exactly as the single-frame version did:
sums / counts / min / max add up; the time-span check keeps one record per distinct Timestamp
string (second resolution, so bounded by the capture length); value_counts orderings (protocol
mix, top-10 IPs) are rebuilt from global first-appearance order plus pandas' stable sort; the
duplicate check hashes each data row's raw text (64-bit) instead of comparing parsed values.

Usage:
    python 03b_check_flows.py [--csv PATH] [--pcap PATH] [--out-dir DIR] [--capinfos EXE]
                              [--strict] [--json PATH] [--chunk N]

Exit status: 0 = no FAIL (WARN allowed), 1 = at least one FAIL (or a WARN with --strict,
or a FATAL input problem such as a missing required column), 2 = unexpected exception
(traceback on stderr).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import itertools
import json
import math
import platform
import re
import shutil
import subprocess
import sys
import traceback
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import DATASET, EXTRACTOR, FLOWS_DIR, RESULTS_DIR

DEFAULT_CSV = FLOWS_DIR / "benign" / f"{DATASET.benign_pcap}_Flow__{EXTRACTOR.build}.csv"
DEFAULT_PCAP = DATASET.benign_pcap_path
DEFAULT_OUT = RESULTS_DIR / "step4"

FLOW_TIMEOUT_US = 120_000_000       # hard-coded flowTimeout (120 s) in CICFlowMeter 4.0

# Logical name -> accepted header spellings, compared after normalisation
# (lower-case, all non-alphanumerics removed).
COLUMN_ALIASES = {
    "flow_id": ["flowid"],
    "src_ip": ["srcip", "sourceip"],
    "dst_ip": ["dstip", "destinationip"],
    "src_port": ["srcport", "sourceport"],
    "dst_port": ["dstport", "destinationport"],
    "protocol": ["protocol"],
    "timestamp": ["timestamp"],
    "flow_duration": ["flowduration"],
    "tot_fwd_pkts": ["totalfwdpacket", "totalfwdpackets", "totfwdpkts"],
    "tot_bwd_pkts": ["totalbwdpacket", "totalbwdpackets", "totbwdpkts",
                     "totalbackwardpackets"],
    "flow_bytes_s": ["flowbytess", "flowbytespers"],
    "flow_pkts_s": ["flowpacketss", "flowpktss", "flowpacketspers"],
}

PROTO_NAMES = {6: "TCP", 17: "UDP", 0: "other/unknown"}
CHUNK_ROWS = 500_000

TIMESTAMP_FORMATS = [
    "%d/%m/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
]


# --------------------------------------------------------------------------- helpers

def norm(name: str) -> str:
    return re.sub(r"[^0-9a-z]", "", name.lower())


def map_columns(header: list[str]) -> dict[str, str]:
    """Map each logical column to the actual header name; exit loudly if any is missing."""
    lookup = {norm(h): h for h in header}
    mapping, missing = {}, []
    for key, aliases in COLUMN_ALIASES.items():
        hit = next((lookup[a] for a in aliases if a in lookup), None)
        if hit is None:
            missing.append(f"{key} (tried: {aliases})")
        else:
            mapping[key] = hit
    if missing:
        sys.exit("FATAL: could not match required columns:\n  " + "\n  ".join(missing))
    return mapping


def sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def pct(n: float, d: float) -> float:
    return round(100.0 * n / d, 4) if d else float("nan")


def result(name: str, status: str, key: str, reason: str, **data) -> dict:
    return {"check": name, "status": status, "key_number": key, "reason": reason, "data": data}


def to_jsonable(obj):
    """Recursively convert numpy / pandas / float specials into JSON-safe values."""
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating, float)):
        f = float(obj)
        return None if math.isnan(f) else (str(f) if math.isinf(f) else f)
    if isinstance(obj, (pd.Timestamp, dt.datetime)):
        return obj.isoformat()
    if isinstance(obj, np.bool_):
        return bool(obj)
    return obj


# --------------------------------------------------------------------------- streaming

def first_order(order: dict, s: pd.Series) -> None:
    """Record values of s in global first-appearance order (dict insertion order)."""
    for v in pd.unique(s.dropna()):
        if v not in order:
            order[v] = None


def stable_counts(order, counts: dict) -> pd.Series:
    """What Series.value_counts() returns on the whole column: counts in first-appearance
    order, then pandas' stable descending sort."""
    keys = list(order)
    return pd.Series([counts[k] for k in keys], index=pd.Index(keys, dtype=object),
                     dtype="int64").sort_values(ascending=False, kind="stable")


def merged_dtype(dtypes: list) -> str:
    """dtype the whole column would have been read as (chunks may infer narrower types)."""
    u = list(dict.fromkeys(dtypes))
    if len(u) == 1:
        return str(u[0])
    if any(d == object or not pd.api.types.is_numeric_dtype(d) for d in u):
        return "object"
    return str(np.result_type(*u))


class Stream:
    """Per-check accumulators, fed one chunk at a time."""

    def __init__(self, header: list[str], c: dict, non_numeric: set[str]):
        self.c, self.non_numeric, self.header = c, non_numeric, header
        self.rows, self.ncols = 0, None
        self.sum_fwd = self.sum_bwd = 0
        self.ppf = Counter()
        self.n1 = self.n_le0 = 0
        self.ts = {}                      # raw Timestamp string -> [first row, rows, max clipped dur]
        self.raw_first = self.raw_last = None
        self.dur = {"max": None, "min": None, "over": 0, "neg": 0, "zero": 0}
        self.bad = {}                     # numeric column -> [nan, +inf, -inf]
        self.dtypes = defaultdict(list)
        self.rate = {k: Counter() for k in ("flow_bytes_s", "flow_pkts_s")}
        self.proto_order, self.proto = {}, Counter()
        self.h_full, self.h_noid = [], []
        self.fid_pat = re.compile(r"^((?:[^,]*,){%d})[^,]*," % header.index(c["flow_id"]))
        self.blank_src = self.blank_dst = 0
        self.src_order, self.dst_order = {}, {}
        self.src_n, self.dst_n = Counter(), Counter()
        self.src_set, self.dst_set = set(), set()

    def add(self, df: pd.DataFrame, lines: list[str]) -> None:
        c, n0 = self.c, self.rows
        df.index = pd.RangeIndex(n0, n0 + len(df))
        self.rows += len(df)
        self.ncols = df.shape[1]
        fwd, bwd = df[c["tot_fwd_pkts"]], df[c["tot_bwd_pkts"]]
        # 2 / 3
        self.sum_fwd += fwd.sum()
        self.sum_bwd += bwd.sum()
        ppf = fwd + bwd
        self.n1 += int((ppf == 1).sum())
        self.n_le0 += int((ppf <= 0).sum())
        bins = [0, 1, 2, 10, 100, 1000, np.inf]
        labels = ["1", "2", "3-10", "11-100", "101-1000", ">1000"]
        self.ppf.update(pd.cut(ppf, bins=bins, labels=labels).value_counts().to_dict())
        # 4
        raw = df[c["timestamp"]].astype(str)
        if self.raw_first is None:
            self.raw_first = raw.iloc[0]
        self.raw_last = raw.iloc[-1]
        dur = df[c["flow_duration"]]
        g = pd.DataFrame({"r": raw, "i": df.index, "d": dur.clip(lower=0)}).groupby("r", sort=False)
        agg = g.agg(i=("i", "min"), n=("i", "size"), d=("d", "max"))
        for r, (i, n, d) in zip(agg.index, agg.itertuples(index=False)):
            rec = self.ts.get(r)
            if rec is None:
                self.ts[r] = [i, n, d]
            else:
                rec[1] += n
                if pd.notna(d) and (pd.isna(rec[2]) or d > rec[2]):
                    rec[2] = d
        # 5
        mx, mn = dur.max(), dur.min()
        self.dur["max"] = mx if self.dur["max"] is None else max(self.dur["max"], mx)
        self.dur["min"] = mn if self.dur["min"] is None else min(self.dur["min"], mn)
        self.dur["over"] += int((dur > FLOW_TIMEOUT_US).sum())
        self.dur["neg"] += int((dur < 0).sum())
        self.dur["zero"] += int((dur == 0).sum())
        # 6
        zero_dur = dur == 0
        for col in df.columns:
            if col in self.non_numeric:
                continue
            s = df[col]
            self.dtypes[col].append(s.dtype)
            if not pd.api.types.is_numeric_dtype(s):
                s = pd.to_numeric(s.astype(object).replace({"Infinity": np.inf, "-Infinity": -np.inf}),
                                  errors="coerce")
            b = self.bad.setdefault(col, [0, 0, 0])
            b[0] += int(s.isna().sum())
            b[1] += int((s == np.inf).sum())
            b[2] += int((s == -np.inf).sum())
            for key in ("flow_bytes_s", "flow_pkts_s"):
                if col == c[key]:
                    bad = s.isna() | np.isinf(s)
                    self.rate[key]["bad_total"] += int(bad.sum())
                    self.rate[key]["bad_with_duration_0"] += int((bad & zero_dur).sum())
                    self.rate[key]["bad_with_duration_gt0"] += int((bad & ~zero_dur).sum())
        # 7
        pr = df[c["protocol"]]
        first_order(self.proto_order, pr)
        self.proto.update(pr.value_counts().to_dict())
        # 8: 64-bit hashes of the raw row text (full row, and without the Flow ID field)
        txt = pd.Series(lines, dtype=object)
        self.h_full.append(pd.util.hash_array(txt.to_numpy()))
        self.h_noid.append(pd.util.hash_array(txt.str.replace(self.fid_pat, r"\1", n=1, regex=True)
                                              .to_numpy(dtype=object)))
        # 9
        src, dst = df[c["src_ip"]], df[c["dst_ip"]]

        def blank(x):
            return x.isna() | (x.astype(str).str.strip() == "")

        self.blank_src += int(blank(src).sum())
        self.blank_dst += int(blank(dst).sum())
        d2 = dst.where(dst != src)
        first_order(self.src_order, src)
        first_order(self.dst_order, d2)
        self.src_n.update(src.value_counts().to_dict())
        self.dst_n.update(d2.value_counts().to_dict())
        self.src_set.update(src.dropna().unique())
        self.dst_set.update(dst.dropna().unique())


def read_stream(csv_path: Path, header: list[str], c: dict, non_numeric: set[str],
                chunk: int) -> Stream:
    """Parse the CSV chunk by chunk; the raw text of each data row goes to the duplicate check."""
    st = Stream(header, c, non_numeric)
    with open(csv_path, "rb") as fh:                 # bytes: io.StringIO would hold 4 B / char
        head = fh.readline()
        while True:
            block = [l.rstrip(b"\r\n") for l in itertools.islice(fh, chunk)]
            if not block:
                break
            block = [l for l in block if l.strip() != b""]          # pandas skips blank lines
            if not block:
                continue
            buf = io.BytesIO(head + b"\n".join(block) + b"\n")
            df = pd.read_csv(buf, low_memory=False, encoding="utf-8")
            del buf
            lines = [l.decode("utf-8", errors="replace") for l in block]
            del block
            if len(df) != len(lines):
                sys.exit(f"FATAL: parsed {len(df)} rows from {len(lines)} lines near row {st.rows}")
            st.add(df, lines)
            del df, lines
            print(f"  {st.rows:>12,} rows", flush=True)
    return st


# --------------------------------------------------------------------------- checks

def check_structure(csv_path: Path, n_header: int) -> dict:
    """1. Structure: rows whose field count differs from the header (csv module, not pandas)."""
    bad, n_rows = [], 0
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            n_rows += 1
            if len(row) != n_header:
                bad.append((reader.line_num, len(row)))
    status = "PASS" if not bad else "FAIL"
    reason = (f"all {n_rows:,} data rows have {n_header} fields" if not bad
              else f"{len(bad):,} rows with wrong field count")
    return result("1 Structure", status, f"{len(bad):,} bad rows", reason,
                  data_rows_csv_module=n_rows, header_fields=n_header, bad_rows=len(bad),
                  first_bad_lines=[{"line": ln, "fields": nf} for ln, nf in bad[:5]])


def pcap_packet_count(exe: str | None, pcap: Path) -> tuple[int | None, str]:
    """Packet count of the given pcap (`capinfos -c -M`: exact number, no k / M suffix)."""
    if exe is None:
        return None, "capinfos not found"
    try:
        proc = subprocess.run([exe, "-c", "-M", str(pcap)], capture_output=True, text=True,
                              timeout=1800)
    except Exception as e:  # report, don't crash the whole run
        return None, f"capinfos error: {e}"
    m = re.search(r"Number of packets:\s+(\d+)", proc.stdout)
    if proc.returncode != 0 or not m:
        return None, f"capinfos failed (rc={proc.returncode}): {proc.stdout}{proc.stderr}".strip()
    return int(m.group(1)), ""


def check_packet_total(A: Stream, c: dict, pcap: Path, capinfos_exe: str | None) -> dict:
    """2. Packet total: sum of fwd+bwd packets across flows vs the --pcap's own packet count
    (capinfos), so the check holds for any pcap, not only the benign capture."""
    total = int(A.sum_fwd + A.sum_bwd)
    pcap_total, err = pcap_packet_count(capinfos_exe, pcap)
    if pcap_total is None:
        return result("2 Packet total", "WARN", f"{total:,} / ?", f"pcap packet count not measured: {err}",
                      flow_packet_sum=total, pcap_packets=None, gap_abs=None, gap_pct=None)
    gap = pcap_total - total
    gap_pct = pct(gap, pcap_total)
    if total > pcap_total:
        status, reason = "FAIL", "flows contain MORE packets than the pcap (double counting?)"
    elif gap == 0:
        status, reason = "PASS", "flow packet sum equals pcap packet count"
    else:
        status = "WARN"
        reason = (f"{gap:,} packets ({gap_pct}%) not in flows -- expected for non-IP "
                  "(ARP, etc.) and possibly IPv6/unsupported packets")
    return result("2 Packet total", status, f"{total:,} / {pcap_total:,}", reason,
                  flow_packet_sum=total, pcap_packets=pcap_total,
                  gap_abs=gap, gap_pct=gap_pct)


def check_single_packet(A: Stream, c: dict) -> dict:
    """3. Single-packet flows exist (patched build) + packets-per-flow distribution."""
    n, n1 = A.rows, A.n1
    labels = ["1", "2", "3-10", "11-100", "101-1000", ">1000"]
    dist = {lab: {"flows": int(A.ppf.get(lab, 0)), "pct": pct(A.ppf.get(lab, 0), n)} for lab in labels}
    n_zero = A.n_le0
    status = "PASS" if n1 > 0 else "FAIL"
    reason = ("single-packet flows present -> patched CICFlowMeter build was used" if n1 > 0
              else "no single-packet flows -> looks like the stock build (packetCount() > 1)")
    return result("3 Single-packet flows", status, f"{n1:,} ({pct(n1, n)}%)", reason,
                  single_packet_flows=n1, single_packet_pct=pct(n1, n),
                  flows_with_le0_packets=n_zero, packets_per_flow=dist)


def parse_timestamps(raw: pd.Series) -> tuple[str, pd.Series, list[dict]]:
    """Try each candidate format on the unique strings; pick the fully-parsing one with the
    smallest span (disambiguates dd/mm vs mm/dd when both happen to parse)."""
    uniq = pd.Series(raw.dropna().unique())
    trials = []
    for fmt in TIMESTAMP_FORMATS:
        parsed = pd.to_datetime(uniq, format=fmt, errors="coerce")
        n_fail = int(parsed.isna().sum())
        span = (parsed.max() - parsed.min()).total_seconds() if n_fail < len(uniq) else None
        trials.append({"format": fmt, "unparsed_unique": n_fail, "span_s": span})
    ok = [t for t in trials if t["unparsed_unique"] == 0]
    if not ok:
        sys.exit(f"FATAL: no timestamp format parsed every value: {trials}")
    best = min(ok, key=lambda t: t["span_s"])
    return best["format"], pd.to_datetime(raw, format=best["format"], errors="coerce"), trials


def find_capinfos(user_path: str | None) -> str | None:
    if user_path:
        return user_path
    for cand in ("capinfos", "capinfos.exe"):
        if p := shutil.which(cand):
            return p
    for p in (r"C:\Program Files\Wireshark\capinfos.exe",
              "/mnt/c/Program Files/Wireshark/capinfos.exe"):
        if Path(p).exists():
            return p
    return None


def run_capinfos(exe: str, pcap: Path) -> dict:
    """Run `capinfos -a -e -S` (epoch seconds -> timezone-free) and parse first/last times."""
    proc = subprocess.run([exe, "-a", "-e", "-S", str(pcap)],
                          capture_output=True, text=True, timeout=1800)
    out = proc.stdout
    first = re.search(r"First packet time:\s+([\d.]+)", out)
    last = re.search(r"Last packet time:\s+([\d.]+)", out)
    if proc.returncode != 0 or not first or not last:
        raise RuntimeError(f"capinfos failed (rc={proc.returncode}): {out}{proc.stderr}")
    f_epoch, l_epoch = float(first.group(1)), float(last.group(1))
    return {"raw_output": out.strip(), "first_epoch": f_epoch, "last_epoch": l_epoch,
            "first_utc": pd.Timestamp(f_epoch, unit="s"),
            "last_utc": pd.Timestamp(l_epoch, unit="s")}


def fmt_utc_offset(hours: float) -> str:
    sign = "+" if hours >= 0 else "-"
    total_min = int(round(abs(hours) * 60))
    return f"UTC{sign}{total_min // 60:02d}:{total_min % 60:02d}"


def check_time_span(A: Stream, c: dict, pcap: Path, capinfos_exe: str | None) -> dict:
    """4. Time span: CSV first/last timestamps vs capinfos first/last packet; detect TZ shift.
    Computed from one record per distinct Timestamp string (first row, rows, max duration)."""
    raws = list(A.ts)
    first = np.array([A.ts[r][0] for r in raws])
    fmt, parsed, trials = parse_timestamps(pd.Series(raws, dtype=object))
    n_nat = int(sum(A.ts[r][1] for r, t in zip(raws, parsed) if pd.isna(t)))
    csv_min, csv_max = parsed.min(), parsed.max()
    at_min = raws[int(np.argmin(np.where(parsed == csv_min, first, np.iinfo(np.int64).max)))]
    at_max = raws[int(np.argmin(np.where(parsed == csv_max, first, np.iinfo(np.int64).max)))]
    flow_end = parsed + pd.to_timedelta(pd.Series([A.ts[r][2] for r in raws]), unit="us")
    data = {
        "raw_first_row": A.raw_first, "raw_last_row": A.raw_last,
        "raw_at_min": at_min, "raw_at_max": at_max,
        "format_detected": fmt, "format_trials": trials, "unparsed_rows": n_nat,
        "csv_min": csv_min, "csv_max": csv_max,
        "csv_max_flow_end": flow_end.max(),
        "csv_span_s": (csv_max - csv_min).total_seconds(),
        "local_tz_of_this_run": dt.datetime.now().astimezone().tzname(),
    }

    if capinfos_exe is None:
        return result("4 Time span", "WARN", f"{csv_min} -> {csv_max}",
                      "capinfos not found; CSV-vs-pcap offset not measured", **data)
    try:
        cap = run_capinfos(capinfos_exe, pcap)
    except Exception as e:  # report, don't crash the whole run
        return result("4 Time span", "WARN", f"{csv_min} -> {csv_max}",
                      f"capinfos error: {e}", **data)

    offset_h = (csv_min - cap["first_utc"]).total_seconds() / 3600.0
    end_offset_h = (data["csv_max_flow_end"] - cap["last_utc"]).total_seconds() / 3600.0
    data.update({
        "capinfos_exe": capinfos_exe, "capinfos_output": cap["raw_output"],
        "pcap_first_epoch": cap["first_epoch"], "pcap_last_epoch": cap["last_epoch"],
        "pcap_first_utc": cap["first_utc"], "pcap_last_utc": cap["last_utc"],
        "pcap_span_s": cap["last_epoch"] - cap["first_epoch"],
        "offset_csv_min_minus_pcap_first_h": round(offset_h, 4),
        "offset_csv_end_minus_pcap_last_h": round(end_offset_h, 4),
        "csv_apparent_tz": fmt_utc_offset(offset_h),
        "pcap_tz": "UTC (capinfos -S gives epoch seconds; converted here as UTC)",
    })

    # Tolerance: CSV timestamps have 1 s resolution; allow 3 minutes of slack.
    tol_h = 3 / 60
    near_half_hour = abs(offset_h * 2 - round(offset_h * 2)) * 0.5 < tol_h
    if abs(offset_h) < tol_h:
        status = "PASS"
        reason = (f"CSV start matches pcap first packet within {abs(offset_h) * 3600:.0f} s; "
                  "both sides in UTC")
    elif near_half_hour:
        status = "WARN"
        reason = (f"offset {offset_h:+.3f} h ~ whole/half hour -> timezone shift: CSV is naive "
                  f"local time in {fmt_utc_offset(offset_h)} (JVM tz of the CICFlowMeter run), "
                  "pcap epoch is UTC")
    else:
        status = "FAIL"
        reason = f"offset {offset_h:+.3f} h is not a clean timezone shift -- unexplained"
    return result("4 Time span", status, f"offset {offset_h:+.3f} h", reason, **data)


def check_duration(A: Stream, c: dict) -> dict:
    """5. Flow duration: max and number of flows longer than the 120 s flow timeout."""
    mx, mn = A.dur["max"], A.dur["min"]
    n_over, n_neg = A.dur["over"], A.dur["neg"]
    status = "PASS" if n_over == 0 else "FAIL"
    reason = ("no flow exceeds the 120 s flow timeout" if n_over == 0
              else f"{n_over:,} flows exceed the 120 s flow timeout")
    return result("5 Flow duration", status, f"max {int(mx):,} us", reason,
                  max_duration_us=int(mx), max_duration_s=mx / 1e6,
                  min_duration_us=int(mn), flows_over_120s=n_over,
                  negative_durations=n_neg,
                  zero_duration_flows=A.dur["zero"])


def check_nan_inf(A: Stream, c: dict, non_numeric: set[str]) -> dict:
    """6. NaN / +-Infinity per numeric column; attribute flow-rate bad values to duration==0."""
    per_col, total_bad = {}, 0
    for col, (n_nan, n_pinf, n_ninf) in A.bad.items():
        if n_nan or n_pinf or n_ninf:
            per_col[col] = {"nan": n_nan, "+inf": n_pinf, "-inf": n_ninf,
                            "dtype_read": merged_dtype(A.dtypes[col])}
            total_bad += n_nan + n_pinf + n_ninf
    rate_attr = {c[key]: {k: A.rate[key][k] for k in ("bad_total", "bad_with_duration_0",
                                                       "bad_with_duration_gt0")}
                 for key in ("flow_bytes_s", "flow_pkts_s")}

    status = "PASS" if total_bad == 0 else "WARN"
    unexplained = sum(v["bad_with_duration_gt0"] for v in rate_attr.values())
    reason = ("no NaN/inf in numeric columns" if total_bad == 0 else
              f"{total_bad:,} NaN/inf cells in {len(per_col)} columns; rate columns: "
              f"{unexplained:,} bad values NOT explained by duration==0 (expected artefact)")
    return result("6 NaN / Infinity", status, f"{total_bad:,} bad cells", reason,
                  numeric_columns_checked=len(A.bad), columns_with_bad_values=per_col,
                  rate_columns_vs_zero_duration=rate_attr,
                  zero_duration_flows=A.dur["zero"])


def check_protocols(A: Stream, c: dict) -> dict:
    """7. Protocol mix: counts and % per IP protocol number."""
    vc = stable_counts(A.proto_order, A.proto)
    mix = {int(p): {"name": PROTO_NAMES.get(int(p), "unexpected"), "flows": int(n),
                    "pct": pct(n, A.rows)} for p, n in vc.items()}
    unexpected = [p for p in mix if p not in PROTO_NAMES]
    status = "PASS" if not unexpected else "WARN"
    reason = ("only protocols 0/6/17 present" if not unexpected
              else f"unexpected protocol numbers: {unexpected}")
    key = ", ".join(f"{v['name']} {v['pct']:.1f}%" for v in mix.values())
    return result("7 Protocol mix", status, key, reason, protocols=mix)


def check_duplicates(A: Stream, c: dict) -> dict:
    """8. Duplicates: exact full-row duplicates, and duplicates ignoring Flow ID (raw row text,
    64-bit hashes; a duplicate is any row whose text equals an earlier row's)."""
    n = A.rows
    n_full = n - int(np.unique(np.concatenate(A.h_full)).size) if A.h_full else 0
    n_no_id = n - int(np.unique(np.concatenate(A.h_noid)).size) if A.h_noid else 0
    worst = max(n_full, n_no_id)
    status = "WARN" if pct(worst, n) > 0.1 else "PASS"
    reason = (f"duplicates {pct(worst, n)}% of rows "
              f"({'>' if status == 'WARN' else '<='} 0.1% threshold)")
    return result("8 Duplicates", status, f"{n_full:,} full / {n_no_id:,} w/o FlowID", reason,
                  full_row_duplicates=n_full, full_row_dup_pct=pct(n_full, n),
                  dups_ignoring_flow_id=n_no_id, dups_ignoring_flow_id_pct=pct(n_no_id, n))


def check_ips(A: Stream, c: dict) -> dict:
    """9. IPs: blanks, distinct src/dst counts, top-10 IPs by flow count (src or dst)."""
    n_blank_src, n_blank_dst = A.blank_src, A.blank_dst
    # Count each flow once per IP, even when src == dst (whole-column order: src then dst).
    order = dict(A.src_order)
    for k in A.dst_order:
        order.setdefault(k, None)
    both = stable_counts(order, {k: A.src_n.get(k, 0) + A.dst_n.get(k, 0) for k in order})
    top10 = {ip: int(n) for ip, n in both.head(10).items()}
    status = "PASS" if n_blank_src + n_blank_dst == 0 else "FAIL"
    reason = ("no blank src/dst IPs" if status == "PASS"
              else f"{n_blank_src:,} blank src / {n_blank_dst:,} blank dst IPs")
    return result("9 IPs", status, f"{len(A.src_set):,} src / {len(A.dst_set):,} dst distinct",
                  reason, blank_src=n_blank_src, blank_dst=n_blank_dst,
                  distinct_src=len(A.src_set), distinct_dst=len(A.dst_set),
                  distinct_any=len(A.src_set | A.dst_set), top10_ips=top10)


# --------------------------------------------------------------------------- reporting

def print_summary(results: list[dict]) -> None:
    w1 = max(len(r["check"]) for r in results)
    w3 = max(len(r["key_number"]) for r in results)
    line = f"+-{'-' * w1}-+--------+-{'-' * w3}-+"
    print("\n" + line)
    print(f"| {'Check':<{w1}} | Status | {'Key number':<{w3}} |")
    print(line)
    for r in results:
        print(f"| {r['check']:<{w1}} | {r['status']:<6} | {r['key_number']:<{w3}} |")
    print(line)


def md_value(v) -> str:
    if isinstance(v, float):
        return f"{v:,.4f}".rstrip("0").rstrip(".") if math.isfinite(v) else str(v)
    if isinstance(v, int):
        return f"{v:,}"
    return str(v)


def md_block(data: dict, indent: int = 0) -> list[str]:
    out, pad = [], "  " * indent
    for k, v in data.items():
        if isinstance(v, dict):
            out.append(f"{pad}- **{k}**:")
            out.extend(md_block(v, indent + 1))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            out.append(f"{pad}- **{k}**:")
            for item in v:
                out.append(f"{pad}  - " + ", ".join(f"{ik}={md_value(iv)}" for ik, iv in item.items()))
        elif isinstance(v, str) and "\n" in v:
            out.append(f"{pad}- **{k}**:\n\n```\n{v}\n```\n")
        else:
            out.append(f"{pad}- **{k}**: {md_value(v)}")
    return out


def write_reports(out_dir: Path, meta: dict, columns: list[str], mapping: dict,
                  results: list[dict]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out_dir / "flow_check_report.json", out_dir / "flow_check_report.md"

    payload = {"meta": meta, "columns": columns, "column_mapping": mapping, "checks": results}
    json_path.write_text(json.dumps(to_jsonable(payload), indent=2), encoding="utf-8")

    j = to_jsonable(payload)  # reuse the JSON-safe form for markdown rendering
    lines = ["# Flow CSV check report", ""]
    lines += [f"- **{k}**: {md_value(v)}" for k, v in j["meta"].items()]
    lines += ["", "## Summary", "", "| Check | Status | Key number | Reason |", "|---|---|---|---|"]
    lines += [f"| {r['check']} | **{r['status']}** | {r['key_number']} | {r['reason']} |"
              for r in j["checks"]]
    lines += ["", "## Column mapping", ""]
    lines += [f"- {k} -> `{v}`" for k, v in j["column_mapping"].items()]
    for r in j["checks"]:
        lines += ["", f"## {r['check']} -- {r['status']}", "", f"_{r['reason']}_", ""]
        lines += md_block(r["data"])
    lines += ["", "## All CSV columns", ""]
    lines += [f"{i}. `{col}`" for i, col in enumerate(j["columns"], 1)]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return md_path, json_path


# --------------------------------------------------------------------------- main

def write_json_summary(path: Path, csv_path: Path, rows, results: list[dict],
                       overall: str, strict: bool, fatal: str | None = None) -> None:
    """Machine-readable summary: {check: {status, detail}}, overall, input, row count."""
    payload = {"input_file": str(csv_path), "row_count": rows, "overall_status": overall,
               "strict": strict,
               "checks": {r["check"]: {"status": r["status"], "detail": r["reason"],
                                       "key_number": r["key_number"]} for r in results}}
    if fatal:
        payload["fatal"] = fatal
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_jsonable(payload), indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--capinfos", default=None, help="path to capinfos (default: search PATH)")
    ap.add_argument("--strict", action="store_true", help="count WARN as failure (exit 1)")
    ap.add_argument("--json", type=Path, default=None,
                    help="also write a machine-readable summary to PATH")
    ap.add_argument("--chunk", type=int, default=CHUNK_ROWS,
                    help=f"rows per chunk (default {CHUNK_ROWS:,})")
    args = ap.parse_args()
    try:
        return run(args)
    except SystemExit as e:  # FATAL input problems (sys.exit("FATAL: ...")) -> exit 1
        if args.json and isinstance(e.code, str):
            write_json_summary(args.json, args.csv, None, [], "FAIL", args.strict, fatal=e.code)
        raise


def run(args) -> int:
    if not args.csv.exists():
        sys.exit(f"FATAL: CSV not found: {args.csv}")

    # Header first (csv module) -- print every column, then map the ones we need.
    with open(args.csv, newline="", encoding="utf-8") as f:
        header = next(csv.reader(f))
    print(f"CSV header: {len(header)} columns")
    for i, col in enumerate(header, 1):
        print(f"  {i:2d}. {col}")
    mapping = map_columns(header)
    print("\nColumn mapping:")
    for k, v in mapping.items():
        print(f"  {k:<14} -> {v!r}")

    run_ts = dt.datetime.now().astimezone()
    print("\nHashing CSV ...")
    digest = sha256(args.csv)
    non_numeric = {mapping["flow_id"], mapping["src_ip"], mapping["dst_ip"],
                   mapping["timestamp"]} | {h for h in header if norm(h) == "label"}
    print(f"Reading CSV with pandas in chunks of {args.chunk:,} rows ...")
    A = read_stream(args.csv, header, mapping, non_numeric, args.chunk)

    meta = {
        "input_csv": str(args.csv), "input_pcap": str(args.pcap),
        "file_size_bytes": args.csv.stat().st_size,
        "file_size_mb": round(args.csv.stat().st_size / 2**20, 2),
        "sha256": digest, "rows_pandas": A.rows, "columns_pandas": A.ncols,
        "columns_header": len(header), "run_timestamp": run_ts.isoformat(timespec="seconds"),
        "python_version": platform.python_version(), "pandas_version": pd.__version__,
        "conda_env_prefix": sys.prefix,
    }

    capinfos_exe = find_capinfos(args.capinfos)
    checks = [
        ("structure", lambda: check_structure(args.csv, len(header))),
        ("packets", lambda: check_packet_total(A, mapping, args.pcap, capinfos_exe)),
        ("single", lambda: check_single_packet(A, mapping)),
        ("time", lambda: check_time_span(A, mapping, args.pcap, capinfos_exe)),
        ("duration", lambda: check_duration(A, mapping)),
        ("naninf", lambda: check_nan_inf(A, mapping, non_numeric)),
        ("proto", lambda: check_protocols(A, mapping)),
        ("dups", lambda: check_duplicates(A, mapping)),
        ("ips", lambda: check_ips(A, mapping)),
    ]
    results = []
    for name, fn in checks:
        print(f"Running check: {name} ...")
        results.append(fn())

    md_path, json_path = write_reports(args.out_dir, meta, header, mapping, results)
    print_summary(results)
    print(f"\nReports written:\n  {md_path}\n  {json_path}")

    statuses = [r["status"] for r in results]
    overall = "FAIL" if "FAIL" in statuses else "WARN" if "WARN" in statuses else "PASS"
    failed = overall == "FAIL" or (args.strict and overall == "WARN")
    if args.json:
        write_json_summary(args.json, args.csv, A.rows, results, overall, args.strict)
        print(f"  {args.json}")
    print(f"\nOverall: {overall} ({statuses.count('PASS')} PASS, {statuses.count('WARN')} WARN, "
          f"{statuses.count('FAIL')} FAIL){' [strict]' if args.strict else ''} -> "
          f"exit {1 if failed else 0}")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
