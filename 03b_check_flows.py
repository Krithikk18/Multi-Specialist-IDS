#!/usr/bin/env python
"""03b_check_flows.py -- sanity checks on a CICFlowMeter flow CSV (measure + report only).

Reads the single-packet-patched CICFlowMeter output for the benign pcap, runs nine
checks, prints a compact summary table, and writes
<out-dir>/flow_check_report.md and <out-dir>/flow_check_report.json.

Nothing is modified: the input CSV is opened read-only and no data is "fixed".

Usage:
    python 03b_check_flows.py [--csv PATH] [--pcap PATH] [--out-dir DIR] [--capinfos EXE]
                              [--strict] [--json PATH]

Exit status: 0 = no FAIL (WARN allowed), 1 = at least one FAIL (or a WARN with --strict,
or a FATAL input problem such as a missing required column), 2 = unexpected exception
(traceback on stderr).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import platform
import re
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import DATASET, EXTRACTOR, FLOWS_DIR, RESULTS_DIR

DEFAULT_CSV = FLOWS_DIR / "benign" / f"{DATASET.benign_pcap}_Flow__{EXTRACTOR.build}.csv"
DEFAULT_PCAP = DATASET.benign_pcap_path
DEFAULT_OUT = RESULTS_DIR / "step4"

PCAP_TOTAL_PACKETS = 3_664_164      # from capinfos
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


def check_packet_total(df: pd.DataFrame, c: dict) -> dict:
    """2. Packet total: sum of fwd+bwd packets across flows vs the pcap packet count."""
    total = int(df[c["tot_fwd_pkts"]].sum() + df[c["tot_bwd_pkts"]].sum())
    gap = PCAP_TOTAL_PACKETS - total
    gap_pct = pct(gap, PCAP_TOTAL_PACKETS)
    if total > PCAP_TOTAL_PACKETS:
        status, reason = "FAIL", "flows contain MORE packets than the pcap (double counting?)"
    elif gap == 0:
        status, reason = "PASS", "flow packet sum equals pcap packet count"
    else:
        status = "WARN"
        reason = (f"{gap:,} packets ({gap_pct}%) not in flows -- expected for non-IP "
                  "(ARP, etc.) and possibly IPv6/unsupported packets")
    return result("2 Packet total", status, f"{total:,} / {PCAP_TOTAL_PACKETS:,}", reason,
                  flow_packet_sum=total, pcap_packets=PCAP_TOTAL_PACKETS,
                  gap_abs=gap, gap_pct=gap_pct)


def check_single_packet(df: pd.DataFrame, c: dict) -> dict:
    """3. Single-packet flows exist (patched build) + packets-per-flow distribution."""
    ppf = df[c["tot_fwd_pkts"]] + df[c["tot_bwd_pkts"]]
    n1 = int((ppf == 1).sum())
    bins = [0, 1, 2, 10, 100, 1000, np.inf]
    labels = ["1", "2", "3-10", "11-100", "101-1000", ">1000"]
    counts = pd.cut(ppf, bins=bins, labels=labels).value_counts().reindex(labels)
    dist = {lab: {"flows": int(n), "pct": pct(n, len(df))} for lab, n in counts.items()}
    n_zero = int((ppf <= 0).sum())
    status = "PASS" if n1 > 0 else "FAIL"
    reason = ("single-packet flows present -> patched CICFlowMeter build was used" if n1 > 0
              else "no single-packet flows -> looks like the stock build (packetCount() > 1)")
    return result("3 Single-packet flows", status, f"{n1:,} ({pct(n1, len(df))}%)", reason,
                  single_packet_flows=n1, single_packet_pct=pct(n1, len(df)),
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


def check_time_span(df: pd.DataFrame, c: dict, pcap: Path, capinfos_exe: str | None) -> dict:
    """4. Time span: CSV first/last timestamps vs capinfos first/last packet; detect TZ shift."""
    raw = df[c["timestamp"]].astype(str)
    fmt, ts, trials = parse_timestamps(raw)
    n_nat = int(ts.isna().sum())
    i_min, i_max = ts.idxmin(), ts.idxmax()
    csv_min, csv_max = ts.min(), ts.max()
    flow_end = ts + pd.to_timedelta(df[c["flow_duration"]].clip(lower=0), unit="us")
    data = {
        "raw_first_row": raw.iloc[0], "raw_last_row": raw.iloc[-1],
        "raw_at_min": raw.loc[i_min], "raw_at_max": raw.loc[i_max],
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


def check_duration(df: pd.DataFrame, c: dict) -> dict:
    """5. Flow duration: max and number of flows longer than the 120 s flow timeout."""
    dur = df[c["flow_duration"]]
    n_over = int((dur > FLOW_TIMEOUT_US).sum())
    n_neg = int((dur < 0).sum())
    status = "PASS" if n_over == 0 else "FAIL"
    reason = ("no flow exceeds the 120 s flow timeout" if n_over == 0
              else f"{n_over:,} flows exceed the 120 s flow timeout")
    return result("5 Flow duration", status, f"max {int(dur.max()):,} us", reason,
                  max_duration_us=int(dur.max()), max_duration_s=dur.max() / 1e6,
                  min_duration_us=int(dur.min()), flows_over_120s=n_over,
                  negative_durations=n_neg,
                  zero_duration_flows=int((dur == 0).sum()))


def check_nan_inf(df: pd.DataFrame, c: dict, non_numeric: set[str]) -> dict:
    """6. NaN / +-Infinity per numeric column; attribute flow-rate bad values to duration==0."""
    per_col, total_bad = {}, 0
    numeric = {}
    for col in df.columns:
        if col in non_numeric:
            continue
        s = df[col]
        if not pd.api.types.is_numeric_dtype(s):  # e.g. literal "Infinity"/"NaN" kept as text
            s = pd.to_numeric(s.astype(object).replace({"Infinity": np.inf, "-Infinity": -np.inf}),
                              errors="coerce")
        numeric[col] = s
        n_nan, n_pinf, n_ninf = int(s.isna().sum()), int((s == np.inf).sum()), int((s == -np.inf).sum())
        if n_nan or n_pinf or n_ninf:
            per_col[col] = {"nan": n_nan, "+inf": n_pinf, "-inf": n_ninf, "dtype_read": str(df[col].dtype)}
            total_bad += n_nan + n_pinf + n_ninf

    zero_dur = df[c["flow_duration"]] == 0
    rate_attr = {}
    for key in ("flow_bytes_s", "flow_pkts_s"):
        s = numeric[c[key]]
        bad = s.isna() | np.isinf(s)
        rate_attr[c[key]] = {"bad_total": int(bad.sum()),
                             "bad_with_duration_0": int((bad & zero_dur).sum()),
                             "bad_with_duration_gt0": int((bad & ~zero_dur).sum())}

    status = "PASS" if total_bad == 0 else "WARN"
    unexplained = sum(v["bad_with_duration_gt0"] for v in rate_attr.values())
    reason = ("no NaN/inf in numeric columns" if total_bad == 0 else
              f"{total_bad:,} NaN/inf cells in {len(per_col)} columns; rate columns: "
              f"{unexplained:,} bad values NOT explained by duration==0 (expected artefact)")
    return result("6 NaN / Infinity", status, f"{total_bad:,} bad cells", reason,
                  numeric_columns_checked=len(numeric), columns_with_bad_values=per_col,
                  rate_columns_vs_zero_duration=rate_attr,
                  zero_duration_flows=int(zero_dur.sum()))


def check_protocols(df: pd.DataFrame, c: dict) -> dict:
    """7. Protocol mix: counts and % per IP protocol number."""
    vc = df[c["protocol"]].value_counts()
    mix = {int(p): {"name": PROTO_NAMES.get(int(p), "unexpected"), "flows": int(n),
                    "pct": pct(n, len(df))} for p, n in vc.items()}
    unexpected = [p for p in mix if p not in PROTO_NAMES]
    status = "PASS" if not unexpected else "WARN"
    reason = ("only protocols 0/6/17 present" if not unexpected
              else f"unexpected protocol numbers: {unexpected}")
    key = ", ".join(f"{v['name']} {v['pct']:.1f}%" for v in mix.values())
    return result("7 Protocol mix", status, key, reason, protocols=mix)


def check_duplicates(df: pd.DataFrame, c: dict) -> dict:
    """8. Duplicates: exact full-row duplicates, and duplicates ignoring Flow ID."""
    n_full = int(df.duplicated().sum())
    n_no_id = int(df.drop(columns=[c["flow_id"]]).duplicated().sum())
    worst = max(n_full, n_no_id)
    status = "WARN" if pct(worst, len(df)) > 0.1 else "PASS"
    reason = (f"duplicates {pct(worst, len(df))}% of rows "
              f"({'>' if status == 'WARN' else '<='} 0.1% threshold)")
    return result("8 Duplicates", status, f"{n_full:,} full / {n_no_id:,} w/o FlowID", reason,
                  full_row_duplicates=n_full, full_row_dup_pct=pct(n_full, len(df)),
                  dups_ignoring_flow_id=n_no_id, dups_ignoring_flow_id_pct=pct(n_no_id, len(df)))


def check_ips(df: pd.DataFrame, c: dict) -> dict:
    """9. IPs: blanks, distinct src/dst counts, top-10 IPs by flow count (src or dst)."""
    src, dst = df[c["src_ip"]], df[c["dst_ip"]]

    def blank(s):
        return s.isna() | (s.astype(str).str.strip() == "")

    n_blank_src, n_blank_dst = int(blank(src).sum()), int(blank(dst).sum())
    # Count each flow once per IP, even when src == dst.
    both = pd.concat([src, dst.where(dst != src)]).dropna()
    top10 = {ip: int(n) for ip, n in both.value_counts().head(10).items()}
    status = "PASS" if n_blank_src + n_blank_dst == 0 else "FAIL"
    reason = ("no blank src/dst IPs" if status == "PASS"
              else f"{n_blank_src:,} blank src / {n_blank_dst:,} blank dst IPs")
    return result("9 IPs", status, f"{src.nunique():,} src / {dst.nunique():,} dst distinct",
                  reason, blank_src=n_blank_src, blank_dst=n_blank_dst,
                  distinct_src=int(src.nunique()), distinct_dst=int(dst.nunique()),
                  distinct_any=int(pd.concat([src, dst]).nunique()), top10_ips=top10)


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
    print("Loading CSV with pandas ...")
    df = pd.read_csv(args.csv, low_memory=False)

    meta = {
        "input_csv": str(args.csv), "input_pcap": str(args.pcap),
        "file_size_bytes": args.csv.stat().st_size,
        "file_size_mb": round(args.csv.stat().st_size / 2**20, 2),
        "sha256": digest, "rows_pandas": len(df), "columns_pandas": df.shape[1],
        "columns_header": len(header), "run_timestamp": run_ts.isoformat(timespec="seconds"),
        "python_version": platform.python_version(), "pandas_version": pd.__version__,
        "conda_env_prefix": sys.prefix,
    }

    non_numeric = {mapping["flow_id"], mapping["src_ip"], mapping["dst_ip"],
                   mapping["timestamp"]} | {h for h in header if norm(h) == "label"}

    capinfos_exe = find_capinfos(args.capinfos)
    checks = [
        ("structure", lambda: check_structure(args.csv, len(header))),
        ("packets", lambda: check_packet_total(df, mapping)),
        ("single", lambda: check_single_packet(df, mapping)),
        ("time", lambda: check_time_span(df, mapping, args.pcap, capinfos_exe)),
        ("duration", lambda: check_duration(df, mapping)),
        ("naninf", lambda: check_nan_inf(df, mapping, non_numeric)),
        ("proto", lambda: check_protocols(df, mapping)),
        ("dups", lambda: check_duplicates(df, mapping)),
        ("ips", lambda: check_ips(df, mapping)),
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
        write_json_summary(args.json, args.csv, len(df), results, overall, args.strict)
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
