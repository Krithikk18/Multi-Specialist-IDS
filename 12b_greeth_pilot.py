#!/usr/bin/env python
"""12b_greeth_pilot.py -- PILOT: can the LOCKED extractor turn a Mirai greeth_flood (GRE) capture into usable flows?

One part only: Mirai-greeth_flood.pcap (the base part). Parts 9 / 18 (training candidates) and 27 / 28 (RESERVED fresh
test, config/mirai_reserve.md) are never opened, read, hashed, copied or extracted: the script refuses any other
pcap name. test.parquet is never opened. Nothing under config/, data/ or earlier results/ is written.

Steps
  0 copy      df -h ~ (>= MIN_FREE_GB free -> copy the base part to CACHE_DIR/pilot_greeth/, else read it from
              /mnt/d and say so); sha256 of the copy (or the /mnt/d file) == config/sha256_greeth.txt, else STOP.
              A cached copy whose sha256 matches is reused.
  1 packets   capinfos (packets, first / last packet UTC, duration) + ONE full-dissection tshark pass (TZ=UTC, -M
              session reset as in 07a; every occurrence of eth / ip fields, first = outer, last = inner):
              frame.protocols stacks (protocol hierarchy), outer ip.proto, GRE payload type and the inner
              protocols inside GRE; attacker packets = outer eth.src matching config ATTACKER_MACS (07a's att_src);
              victims = outer eth.dst of attacker packets, named with 07a's Devices.dest_class, grouped with
              config/groupings/behaviour_k2.json (G1 / G2 / GEN; gateway and non-iot hosts are not grouped);
              attacker IP set = outer ip.src of attacker packets, unicast LAN / external only (07's T1b rule).
              Cached in CACHE_DIR/pilot_greeth/packets.json (keyed by pcap sha256 + code version).
  2 extract   extraction/run_cicflowmeter.py (the locked wrapper: verify_lock(), jar sha256, TZ=UTC, -Xmx6g,
              120 s / 5 s, idle-sweeper check) -> CACHE_DIR/pilot_greeth/flows/, suffix singlepkt. Reused when the
              sidecar's pcap and jar sha256 match.
  3 flows     flows by Protocol (47 / 0 / 6 / 17 / other), all and attacker flows (Src IP or Dst IP in the
              attacker IP set); coverage = Total Fwd + Bwd packets of attacker flows / attacker packets (and the
              stricter sent-side coverage: only the packets of the attacker-IP direction); attacker flows'
              packets per flow, duration, ports; the 70 features (config/features_v1.json) over attacker flows:
              NaN / +-inf / constant, next to the Mirai-udpplain attack flows (07 labelled CSV, train + val
              source, read-only) as reference; 03b_check_flows.py on the CSV (reports in the cache dir).
  4 verdict   proposal only: PASS if the attacker GRE traffic is in flows with a usable (non-0) protocol,
              coverage >= 90 % and the 70 features are not degenerate; else FAIL with the reason.

Outputs -> results/step12b/: summary.md, protocol_mix.csv, attacker_flows_profile.csv, run_meta.json
(+ run.log, gitignored). Heavy steps run one at a time; peak RSS per step from /usr/bin/time -v.

Exit status: 0 ok, 1 bad input / check failed, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import importlib.util
import ipaddress as ipa
import json
import math
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import (ATTACK_FLOWS_DIR, ATTACKER_MACS, CACHE_DIR, CONFIG_DIR, DATA_RAW, DEVICE_TABLE, EXTRACTOR,
                           NETWORK, REPO_ROOT, RESULTS_DIR, sha256_file, verify_lock)


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m07a = _load("attack_coverage", "07a_attack_coverage.py")
norm_mac, ip_scope = m07a.norm_mac, m07a.ip_scope

SCRIPT = "12b_greeth_pilot.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
PACKETS_VERSION = 1
PART = "Mirai-greeth_flood.pcap"                       # the ONLY pcap this script may touch
SRC_PCAP = DATA_RAW / "ciciot2023" / "Mirai" / "Mirai-greeth_flood" / PART
SHA_FILE = CONFIG_DIR / "sha256_greeth.txt"
K2_JSON = CONFIG_DIR / "groupings" / "behaviour_k2.json"
FEATURES = CONFIG_DIR / "features_v1.json"
PILOT = CACHE_DIR / "pilot_greeth"
FLOWS_OUT = PILOT / "flows"
CHECK_OUT = PILOT / "03b"
TIME_DIR = PILOT / "time"
SUFFIX = EXTRACTOR.build
REF_STEM = "Mirai-udpplain"                            # train + val source; NOT the test session udpplain24
REF_CSV = ATTACK_FLOWS_DIR / REF_STEM / f"{REF_STEM}_labelled.csv.gz"
OUT = RESULTS_DIR / "step12b"
MIN_FREE_GB = 5.0
TSHARK_RESET = 200_000
CHUNK = 250_000
FLOW_CHUNK = 500_000
CAP = 100_000                                          # distinct-value sets are capped (then "100000+")
COVERAGE_MIN = 0.90
FLOW_TIMEOUT_S = float(EXTRACTOR.flow_timeout_s)
PROTO_NAMES = {0: "0 (no IP protocol / unknown)", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6"}
PKT_BINS = [0, 1, 2, 10, 100, 1_000, 10_000, 100_000, np.inf]
PKT_LABELS = ["1", "2", "3-10", "11-100", "101-1k", "1k-10k", "10k-100k", ">100k"]
# A flood flow whose shape features are all constant tells the model nothing beyond the protocol.
CORE_FEATURES = ["Flow Duration", "Total Fwd Packet", "Total Length of Fwd Packet", "Fwd Packet Length Mean",
                 "Flow IAT Mean", "Flow Packets/s"]
FIELDS = ["frame.time_epoch", "frame.len", "frame.protocols", "eth.src", "eth.dst", "ip.src", "ip.dst", "ip.proto",
          "gre.proto", "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport"]
COLS = ["t", "flen", "stack", "esrc", "edst", "ipsrc", "ipdst", "proto", "greproto", "usport", "uport", "tsport",
        "tport"]
ID_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]

_LOG_PATH: Path | None = None


def log(msg: str) -> None:
    line = f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    if _LOG_PATH is not None:
        with open(_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def fatal(msg: str) -> None:
    log(f"FATAL: {msg}")
    sys.exit(1)


def read_json(p: Path) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)) + "\n",
                 encoding="utf-8")


def rel(p) -> str:
    p = Path(p).expanduser().resolve()
    for base, tag in ((REPO_ROOT.resolve(), ""), (Path.home().resolve(), "~/")):
        if p.is_relative_to(base):
            return tag + str(p.relative_to(base))
    return str(p)


def fnum(v, nd: int = 2) -> str:
    if v is None or (isinstance(v, float) and (math.isnan(v) or math.isinf(v))):
        return "N/A"
    if isinstance(v, (bool, np.bool_)):
        return str(v)
    return f"{v:,.{nd}f}" if isinstance(v, (float, np.floating)) else f"{v:,}" if isinstance(v, (int, np.integer)) \
        else str(v)


def md_table(rows: list[dict], cols: list[str]) -> list[str]:
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(fnum(r.get(c, "")) if not isinstance(r.get(c, ""), str) else r.get(c, "")
                              for c in cols) + " |" for r in rows]
    return out


def pct(n: float, d: float) -> float:
    return 100.0 * n / d if d else math.nan


def pname(p) -> str:
    try:
        return PROTO_NAMES.get(int(p), str(int(p)))
    except (TypeError, ValueError):
        return str(p)


def guard(p: Path) -> Path:
    """Every pcap path goes through here: only the base part may be touched."""
    if Path(p).name != PART:
        fatal(f"refusing to touch {p}: this pilot may only use {PART}")
    return Path(p)


def timed(cmd: list[str], name: str) -> list[str]:
    """Prefix /usr/bin/time -v (per-step wall time + peak RSS) when it exists."""
    if not Path("/usr/bin/time").is_file():
        return cmd
    TIME_DIR.mkdir(parents=True, exist_ok=True)
    return ["/usr/bin/time", "-v", "-o", str(TIME_DIR / f"{name}.time"), *cmd]


def time_log(name: str) -> dict:
    """/usr/bin/time -v output -> elapsed s, peak RSS MB (as 12a)."""
    path = TIME_DIR / f"{name}.time"
    if not path.is_file():
        return {}
    T = path.read_text(encoding="utf-8", errors="replace")
    out = {}
    m = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:.]+)", T)
    if m:
        parts = [float(x) for x in m.group(1).split(":")]
        out["elapsed_s"] = round(sum(v * 60 ** i for i, v in enumerate(reversed(parts))), 1)
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", T)
    if m:
        out["peak_rss_mb"] = round(int(m.group(1)) / 1024, 1)
    return out


def expected_sha() -> str:
    for line in SHA_FILE.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == PART:
            return parts[0].lower()
    fatal(f"{SHA_FILE.name} has no entry for {PART}")


# --------------------------------------------------------------------------- 0: copy

def stage_copy(M: dict) -> Path:
    want = expected_sha()
    src = guard(SRC_PCAP)
    if not src.is_file():
        fatal(f"base part not found: {src}")
    free_gb = shutil.disk_usage(Path.home()).free / 1e9
    df_h = subprocess.run(["df", "-h", str(Path.home())], capture_output=True, text=True).stdout.strip()
    log(f"df -h ~:\n{df_h}")
    M["disk"] = {"home_free_gb": round(free_gb, 1), "df_h": df_h, "min_free_gb": MIN_FREE_GB}
    t0 = time.monotonic()
    if free_gb < MIN_FREE_GB:
        log(f"only {free_gb:.1f} GB free on ~ (< {MIN_FREE_GB} GB): reading the part from /mnt/d, not copying")
        pcap, how = src, f"read from /mnt/d ({free_gb:.1f} GB free < {MIN_FREE_GB} GB)"
    else:
        pcap = guard(PILOT / PART)
        PILOT.mkdir(parents=True, exist_ok=True)
        side = pcap.with_name(pcap.name + ".sha256.json")
        if pcap.is_file() and side.is_file() and read_json(side).get("sha256") == want \
                and read_json(side).get("size") == pcap.stat().st_size == src.stat().st_size:
            log(f"reusing cached copy {rel(pcap)} (sidecar sha256 matches config)")
            how = "cached copy reused"
        else:
            log(f"copying {rel(src)} ({src.stat().st_size / 1e9:.2f} GB) -> {rel(pcap)}")
            tmp = pcap.with_name(pcap.name + ".part")
            shutil.copyfile(src, tmp)
            tmp.replace(pcap)
            how = "copied to the cache"
    copy_s = time.monotonic() - t0
    t1 = time.monotonic()
    got = sha256_file(pcap)
    hash_s = time.monotonic() - t1
    log(f"sha256 {got} ({'==' if got == want else '!='} {SHA_FILE.name}) in {hash_s:.0f} s")
    if got != want:
        fatal(f"sha256 of {pcap} != {SHA_FILE.name} entry {want}; STOP")
    if pcap != src:
        write_json(pcap.with_name(pcap.name + ".sha256.json"),
                   {"file": PART, "sha256": got, "size": pcap.stat().st_size, "source": str(src)})
    M["pcap"] = {"file": PART, "source": str(src), "used_path": str(pcap), "how": how,
                 "size_bytes": pcap.stat().st_size, "sha256": got, "sha256_expected": want,
                 "sha256_match": got == want, "copy_s": round(copy_s, 1), "sha256_s": round(hash_s, 1)}
    return pcap


# --------------------------------------------------------------------------- 1: packets

def capinfos(pcap: Path) -> dict:
    r = subprocess.run(timed(["capinfos", "-M", "-c", "-a", "-e", "-u", "-S", "-T", "-m", str(guard(pcap))],
                             "capinfos"), capture_output=True, text=True, env={**os.environ, "TZ": "UTC"})
    rows = list(csv.reader(r.stdout.strip().splitlines()))
    if r.returncode != 0 or len(rows) < 2:
        fatal(f"capinfos failed: {r.stderr.strip()[:300]}")
    d = dict(zip(rows[0], rows[1]))
    first = float(d.get("First packet time") or d["Start time"])     # -u labels them Start / End time
    last = float(d.get("Last packet time") or d["End time"])
    return {"packets": int(d["Number of packets"]), "first_epoch": first, "last_epoch": last,
            "first_utc": dt.datetime.fromtimestamp(first, dt.timezone.utc).isoformat(timespec="seconds"),
            "last_utc": dt.datetime.fromtimestamp(last, dt.timezone.utc).isoformat(timespec="seconds"),
            "duration_s": float(d.get("Capture duration (seconds)", last - first) or (last - first)), "raw": d}


class Distinct:
    """Distinct values, capped at CAP (then the count is a lower bound)."""

    def __init__(self):
        self.s, self.over = set(), False

    def add(self, values) -> None:
        if self.over:
            return
        self.s.update(v for v in values if v != "")
        if len(self.s) > CAP:
            self.over = True

    def out(self):
        return f"{CAP}+" if self.over else len(self.s)


def tshark_pass(pcap: Path) -> dict:
    cmd = ["tshark", "-n", "-M", str(TSHARK_RESET), "-o", "tcp.analyze_sequence_numbers:FALSE",
           "-o", "tcp.desegment_tcp_streams:FALSE", "-r", str(guard(pcap)), "-T", "fields", "-E", "separator=/t",
           "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n"]
    for f in FIELDS:
        cmd += ["-e", f]
    cmd = timed(cmd, "tshark")
    log(f"  tshark: {' '.join(cmd)}")
    S = {"packets": 0, "att": 0, "t_min": math.inf, "t_max": -math.inf, "att_first": math.inf,
         "att_last": -math.inf, "gre_all": 0, "gre_att": 0, "gre_not_att": 0}
    stacks, stacks_att, proto_o, proto_o_att = Counter(), Counter(), Counter(), Counter()
    gre_type, inner_proto, inner_stack = Counter(), Counter(), Counter()
    pairs_mac, att_ipsrc, att_ipdst_mac = Counter(), Counter(), Counter()
    streams: dict[tuple, list] = {}                          # (outer ip.src, ip.dst, proto) -> [n, lo, hi]
    inner = {k: Distinct() for k in ("eth_src", "eth_dst", "ip_src", "ip_dst", "udp_sport", "udp_dport",
                                     "tcp_sport", "tcp_dport")}
    inner_dst_eq_outer = 0
    flen = {"n": 0, "min": math.inf, "max": -math.inf, "sum": 0.0}
    att_cache: dict[str, bool] = {}

    def is_att(series: pd.Series) -> pd.Series:
        for m in pd.unique(series):
            if m not in att_cache:
                att_cache[m] = bool(m) and ATTACKER_MACS.matches(m)
        return series.map(att_cache).astype(bool)

    def first(s: pd.Series) -> pd.Series:
        return s.str.partition(",")[0]

    def last(s: pd.Series) -> pd.Series:
        return s.str.rpartition(",")[2]

    def n_occ(s: pd.Series) -> pd.Series:
        return s.str.count(",") + (s != "").astype(int)

    t0 = time.monotonic()
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, env={**os.environ, "TZ": "UTC"})
        reader = pd.read_csv(proc.stdout, sep="\t", header=None, names=COLS, dtype=str, keep_default_na=False,
                             quoting=csv.QUOTE_NONE, chunksize=CHUNK, engine="c")
        for c in reader:
            c["t"] = pd.to_numeric(c["t"], errors="coerce")
            c = c[c["t"].notna()]
            if c.empty:
                continue
            esrc_o = first(c["esrc"]).map(norm_mac)
            edst_o = first(c["edst"]).map(norm_mac)
            p_o = first(c["proto"])
            a = is_att(esrc_o).to_numpy()
            gre = (p_o == "47").to_numpy()
            S["packets"] += len(c)
            S["att"] += int(a.sum())
            S["t_min"], S["t_max"] = min(S["t_min"], c["t"].min()), max(S["t_max"], c["t"].max())
            S["gre_all"] += int(gre.sum())
            S["gre_att"] += int((gre & a).sum())
            S["gre_not_att"] += int((gre & ~a).sum())
            stacks.update(c["stack"].value_counts().to_dict())
            proto_o.update(p_o.value_counts().to_dict())
            if not a.any():
                continue
            A = c[a]
            S["att_first"], S["att_last"] = min(S["att_first"], A["t"].min()), max(S["att_last"], A["t"].max())
            stacks_att.update(A["stack"].value_counts().to_dict())
            proto_o_att.update(p_o[a].value_counts().to_dict())
            ips_o, ipd_o = first(A["ipsrc"]), first(A["ipdst"])
            pairs_mac.update(pd.DataFrame({"s": esrc_o[a], "d": edst_o[a]}).value_counts().to_dict())
            att_ipsrc.update(ips_o.value_counts().to_dict())
            att_ipdst_mac.update(pd.DataFrame({"i": ipd_o, "m": edst_o[a]}).value_counts().to_dict())
            g = pd.DataFrame({"s": ips_o, "d": ipd_o, "p": p_o[a], "t": A["t"]}).groupby(["s", "d", "p"])["t"] \
                .agg(["size", "min", "max"])
            for key, (n, lo, hi) in g.iterrows():
                r = streams.get(key)
                if r is None:
                    streams[key] = [int(n), float(lo), float(hi)]
                else:
                    r[0], r[1], r[2] = r[0] + int(n), min(r[1], lo), max(r[2], hi)
            G = A[gre[a]]
            if G.empty:
                continue
            gre_type.update(G["greproto"].value_counts().to_dict())
            two_ip = n_occ(G["ipsrc"]) >= 2
            ip_in = G["proto"].where(two_ip, "")
            inner_proto.update(last(ip_in).replace("", "(no inner IPv4)").value_counts().to_dict())
            inner_stack.update(G["stack"].str.partition(":gre:")[2].replace("", "(nothing after gre)")
                               .value_counts().to_dict())
            two_eth = n_occ(G["esrc"]) >= 2
            inner["eth_src"].add(last(G["esrc"])[two_eth].unique())
            inner["eth_dst"].add(last(G["edst"])[two_eth].unique())
            inner["ip_src"].add(last(G["ipsrc"])[two_ip].unique())
            inner["ip_dst"].add(last(G["ipdst"])[two_ip].unique())
            inner_dst_eq_outer += int((two_ip & (last(G["ipdst"]) == first(G["ipdst"]))).sum())
            for k, col in (("udp_sport", "usport"), ("udp_dport", "uport"), ("tcp_sport", "tsport"),
                           ("tcp_dport", "tport")):
                inner[k].add(G[col].unique())
            fl = pd.to_numeric(G["flen"], errors="coerce").dropna()
            if len(fl):
                flen["n"] += len(fl)
                flen["min"], flen["max"] = min(flen["min"], fl.min()), max(flen["max"], fl.max())
                flen["sum"] += float(fl.sum())
            log(f"    {S['packets']:>11,} packets  {time.monotonic() - t0:7.1f} s  attacker {S['att']:,}  "
                f"GRE {S['gre_all']:,}")
        rc = proc.wait()
        errf.seek(0)
        err = "\n".join(l for l in errf.read().decode(errors="replace").splitlines()
                        if l.strip() != "resetting session.")
    if rc != 0:
        fatal(f"tshark exited {rc}: {err[-2000:]}")
    S["tshark_seconds"] = round(time.monotonic() - t0, 1)
    log(f"  tshark done: {S['packets']:,} packets in {S['tshark_seconds']} s")
    return {"S": S, "stacks": dict(stacks), "stacks_att": dict(stacks_att), "proto_outer": dict(proto_o),
            "proto_outer_att": dict(proto_o_att), "gre_payload_type": dict(gre_type),
            "gre_inner_ip_proto": dict(inner_proto), "gre_inner_stack": dict(inner_stack),
            "att_mac_pairs": [[s, d, n] for (s, d), n in pairs_mac.most_common()],
            "att_ip_src": dict(att_ipsrc.most_common()),
            "att_ip_dst_mac": [[i, m, n] for (i, m), n in att_ipdst_mac.most_common()],
            "att_streams": [[s, d, p, *v] for (s, d, p), v in sorted(streams.items(), key=lambda kv: -kv[1][0])],
            "gre_inner_distinct": {k: v.out() for k, v in inner.items()},
            "gre_inner_ip_dst_equals_outer": inner_dst_eq_outer,
            "gre_att_frame_len": {"n": flen["n"], "min": flen["min"], "max": flen["max"],
                                  "mean": flen["sum"] / flen["n"] if flen["n"] else math.nan},
            "stderr_tail": err[-1000:]}


def stage_packets(pcap: Path, M: dict) -> dict:
    cache = PILOT / "packets.json"
    key = {"pcap_sha256": M["pcap"]["sha256"], "version": PACKETS_VERSION, "fields": FIELDS,
           "attacker_macs": [list(ATTACKER_MACS.exact), list(ATTACKER_MACS.prefixes)]}
    if cache.is_file() and read_json(cache).get("key") == key:
        log(f"reusing {rel(cache)} (key matches)")
        return read_json(cache)
    log("capinfos ...")
    cap = capinfos(pcap)
    log(f"  {cap['packets']:,} packets, {cap['first_utc']} .. {cap['last_utc']} ({cap['duration_s']:.1f} s)")
    P = {"key": key, "capinfos": cap, "capinfos_time": time_log("capinfos")}
    P.update(tshark_pass(pcap))
    P["tshark_time"] = time_log("tshark")
    if P["S"]["packets"] != cap["packets"]:
        fatal(f"tshark saw {P['S']['packets']:,} packets, capinfos {cap['packets']:,}; STOP")
    write_json(cache, P)
    return P


def victims(P: dict, dev, k2: dict) -> list[dict]:
    tot = P["S"]["att"]
    agg: dict[str, dict] = {}
    for s, d, n in P["att_mac_pairs"]:
        r = agg.setdefault(d, {"attacker_packets": 0, "attacker_macs": set()})
        r["attacker_packets"] += n
        r["attacker_macs"].add(s)
    rows = []
    for mac, r in sorted(agg.items(), key=lambda kv: -kv[1]["attacker_packets"]):
        name, cls = dev.dest_class(mac) if m07a.mac_is_unicast(mac) else ("broadcast / multicast", "bcast")
        k = k2.get(mac)
        rows.append({"dst_mac": mac, "device": name, "class_07a": cls,
                     "group_k2": k if k else ("gateway (not grouped)" if cls == "gateway" else "not grouped"),
                     "attacker_packets": r["attacker_packets"], "pct_of_attacker": pct(r["attacker_packets"], tot),
                     "attacker_macs": " ".join(sorted(r["attacker_macs"]))})
    return rows


def attacker_ip_set(P: dict) -> tuple[set, list[dict]]:
    """07's T1b rule: outer ip.src of attacker-MAC packets, unicast LAN / external only."""
    bcast = {ipa.ip_network(n).broadcast_address for n in NETWORK.subnets}
    keep, rows = set(), []
    for ip, n in P["att_ip_src"].items():
        if not ip:
            rows.append({"ip": "(no IPv4)", "packets": n, "used": False, "why": "non-IPv4"})
            continue
        a, why = ip_scope(ip)
        ok = why in (None, "not_lan_scope") and a not in bcast
        if ok:
            keep.add(ip)
        rows.append({"ip": ip, "packets": n, "used": ok, "why": why or "lan"})
    return keep, rows


# --------------------------------------------------------------------------- 2: extract

def stage_extract(pcap: Path, M: dict) -> Path:
    csv_path = FLOWS_OUT / f"{PART}_Flow__{SUFFIX}.csv"
    meta_path = csv_path.with_name(csv_path.name + ".meta.json")
    if csv_path.is_file() and meta_path.is_file():
        meta = read_json(meta_path)
        if meta.get("input_pcap_sha256") == M["pcap"]["sha256"] and meta.get("jar_sha256") == EXTRACTOR.jar_sha256:
            log(f"reusing {rel(csv_path)} (sidecar pcap + jar sha256 match)")
            M["extract"] = {"reused": True, "meta": meta, "time": time_log("extract")}
            return csv_path
    cmd = timed([sys.executable, str(REPO_ROOT / "extraction" / "run_cicflowmeter.py"), "--pcap", str(guard(pcap)),
                 "--out-dir", str(FLOWS_OUT), "--suffix", SUFFIX], "extract")
    log(f"extract: {' '.join(cmd)}")
    t0 = time.monotonic()
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    el = time.monotonic() - t0
    (PILOT / "extract.log").write_text(r.stdout + "\n--- stderr ---\n" + r.stderr, encoding="utf-8")
    if r.returncode != 0:
        fatal(f"extraction failed (exit {r.returncode}) after {el:.0f} s; see {rel(PILOT / 'extract.log')}:\n"
              + "\n".join((r.stdout + r.stderr).strip().splitlines()[-20:]))
    if not (csv_path.is_file() and meta_path.is_file()):
        fatal(f"extraction exited 0 but {csv_path.name} / its meta sidecar is missing")
    meta = read_json(meta_path)
    log(f"  {meta['row_count']:,} flows in {el:.0f} s; packets {meta['packets']}; sweeper {meta['idle_sweeper']}")
    M["extract"] = {"reused": False, "meta": meta, "time": time_log("extract"),
                    "stdout_tail": "\n".join(r.stdout.strip().splitlines()[-12:])}
    return csv_path


# --------------------------------------------------------------------------- 3: flows

class FeatStats:
    """Per-feature NaN / +-inf counts, finite min / max, and up to 3 distinct finite values."""

    def __init__(self, feats: list[str]):
        self.f = feats
        self.n = 0
        self.nan = Counter()
        self.pinf = Counter()
        self.ninf = Counter()
        self.lo = {f: math.inf for f in feats}
        self.hi = {f: -math.inf for f in feats}
        self.vals = {f: set() for f in feats}
        self.rows = set()                                # distinct 70-feature rows (hashed), capped

    def add(self, X: pd.DataFrame) -> None:
        if X.empty:
            return
        self.n += len(X)
        for f in self.f:
            x = X[f].to_numpy(float)
            fin = np.isfinite(x)
            self.nan[f] += int(np.isnan(x).sum())
            self.pinf[f] += int(np.isposinf(x).sum())
            self.ninf[f] += int(np.isneginf(x).sum())
            if fin.any():
                self.lo[f], self.hi[f] = min(self.lo[f], float(x[fin].min())), max(self.hi[f], float(x[fin].max()))
                if len(self.vals[f]) < 3:
                    self.vals[f].update(np.unique(x[fin])[:3].tolist())
        if len(self.rows) <= CAP:
            self.rows.update(pd.util.hash_pandas_object(X[self.f], index=False).tolist())

    def table(self) -> dict:
        out = {}
        for f in self.f:
            bad = self.nan[f] + self.pinf[f] + self.ninf[f]
            const = self.n > 0 and bad == 0 and self.lo[f] == self.hi[f]
            out[f] = {"nan": self.nan[f], "+inf": self.pinf[f], "-inf": self.ninf[f], "min": self.lo[f],
                      "max": self.hi[f], "constant": bool(const), "value_if_constant": self.lo[f] if const else None}
        return out


def read_flows(csv_path: Path, feats: list[str], att_ips: set) -> dict:
    header = next(csv.reader(open(csv_path, newline="", encoding="utf-8")))
    miss = [c for c in ID_COLS + feats if c not in header]
    if miss:
        fatal(f"flow CSV lacks columns {miss}")
    use = list(dict.fromkeys(ID_COLS + feats))
    proto_all, proto_att, pk_all, pk_att, pk_att_sent = Counter(), Counter(), Counter(), Counter(), Counter()
    FS = FeatStats(feats)
    FL = FeatStats(feats)                                # flood flows: attacker flows that are not TCP / UDP
    prof = []
    n = 0
    for c in pd.read_csv(csv_path, usecols=use, chunksize=FLOW_CHUNK, low_memory=False,
                         dtype={k: str for k in ("Flow ID", "Src IP", "Dst IP", "Timestamp")}):
        n += len(c)
        c["Protocol"] = pd.to_numeric(c["Protocol"], errors="coerce").fillna(-1).astype("int64")
        pk = c["Total Fwd Packet"].fillna(0) + c["Total Bwd packets"].fillna(0)
        proto_all.update(c["Protocol"].value_counts().to_dict())
        pk_all.update(pk.groupby(c["Protocol"]).sum().to_dict())
        s_att, d_att = c["Src IP"].isin(att_ips), c["Dst IP"].isin(att_ips)
        m = (s_att | d_att).to_numpy()
        if not m.any():
            continue
        A = c[m].copy()
        A["packets"] = pk[m]
        A["sent"] = A["Total Fwd Packet"].fillna(0).where(s_att[m], 0) + \
            A["Total Bwd packets"].fillna(0).where(d_att[m], 0)
        proto_att.update(A["Protocol"].value_counts().to_dict())
        pk_att.update(A.groupby("Protocol")["packets"].sum().to_dict())
        pk_att_sent.update(A.groupby("Protocol")["sent"].sum().to_dict())
        FS.add(A[feats])
        FL.add(A.loc[~A["Protocol"].isin([6, 17]), feats])
        prof.append(A[["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
                       "Total Fwd Packet", "Total Bwd packets", "packets", "sent"]])
        log(f"    {n:>11,} flows read; attacker flows so far {sum(len(p) for p in prof):,}")
    AF = pd.concat(prof, ignore_index=True) if prof else pd.DataFrame(
        columns=["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
                 "Total Fwd Packet", "Total Bwd packets", "packets", "sent"])
    return {"rows": n, "proto_all": proto_all, "proto_att": proto_att, "pk_all": pk_all, "pk_att": pk_att,
            "pk_att_sent": pk_att_sent, "FS": FS, "FL": FL, "AF": AF}


def ref_features(feats: list[str]) -> dict | None:
    """Mirai-udpplain attack flows (07 labelled CSV; train + val source) as the reference for 'constant'."""
    if not REF_CSV.is_file():
        return None
    FS = FeatStats(feats)
    for c in pd.read_csv(REF_CSV, usecols=feats + ["label"], chunksize=FLOW_CHUNK, low_memory=False):
        FS.add(c.loc[c["label"] == "attack", feats])
    return {"n": FS.n, "table": FS.table(), "distinct_rows": len(FS.rows)}


def qstats(x: np.ndarray, prefix: str) -> dict:
    if not len(x):
        return {f"{prefix}_{k}": math.nan for k in ("min", "p25", "median", "p75", "p90", "max", "mean")}
    q = np.percentile(x, [0, 25, 50, 75, 90, 100])
    return {f"{prefix}_min": float(q[0]), f"{prefix}_p25": float(q[1]), f"{prefix}_median": float(q[2]),
            f"{prefix}_p75": float(q[3]), f"{prefix}_p90": float(q[4]), f"{prefix}_max": float(q[5]),
            f"{prefix}_mean": float(x.mean())}


def port_desc(s: pd.Series) -> str:
    vc = s.astype(str).value_counts()
    return "; ".join(f"{k} ({v:,})" for k, v in vc.head(5).items()) + (f"; ... {len(vc) - 5:,} more" if len(vc) > 5
                                                                        else "")


def profile_rows(AF: pd.DataFrame, att_ips: set, ip2victim: dict) -> list[dict]:
    """One row per (protocol, attacker IP, other IP) stream, plus a TOTAL row per protocol and ALL."""
    if AF.empty:
        return []
    AF = AF.copy()
    AF["attacker_ip"] = AF["Src IP"].where(AF["Src IP"].isin(att_ips), AF["Dst IP"])
    AF["other_ip"] = AF["Dst IP"].where(AF["Src IP"].isin(att_ips), AF["Src IP"])
    AF["dur_s"] = AF["Flow Duration"].fillna(0) / 1e6

    def row(d: pd.DataFrame, scope: str, proto, aip: str, oip: str) -> dict:
        x = d["packets"].to_numpy(float)
        h = pd.cut(x, PKT_BINS, labels=PKT_LABELS, right=True).value_counts().reindex(PKT_LABELS).fillna(0)
        return {"scope": scope, "protocol": proto, "protocol_name": pname(proto) if proto != "ALL" else "ALL",
                "attacker_ip": aip, "other_ip": oip, "other_device": ip2victim.get(oip, "") if oip != "*" else "",
                "flows": len(d), "packets_sum": int(x.sum()), "sent_by_attacker_sum": int(d["sent"].sum()),
                "fwd_sum": int(d["Total Fwd Packet"].sum()), "bwd_sum": int(d["Total Bwd packets"].sum()),
                **qstats(x, "pkts"), **qstats(d["dur_s"].to_numpy(float), "dur_s"),
                "flows_dur_ge_115s": int((d["dur_s"] >= FLOW_TIMEOUT_S - 5).sum()),
                "src_ports_distinct": int(d["Src Port"].nunique()), "dst_ports_distinct": int(d["Dst Port"].nunique()),
                "src_port_top": port_desc(d["Src Port"]), "dst_port_top": port_desc(d["Dst Port"]),
                **{f"pkts_{k}": int(v) for k, v in h.items()}}

    rows = []
    for (p, a, o), d in AF.groupby(["Protocol", "attacker_ip", "other_ip"], sort=False):
        rows.append(row(d, "stream", int(p), a, o))
    rows.sort(key=lambda r: (r["protocol"], -r["packets_sum"]))
    for p, d in AF.groupby("Protocol"):
        rows.append(row(d, "TOTAL protocol", int(p), "*", "*"))
    rows.append(row(AF, "TOTAL ALL", "ALL", "*", "*"))
    return rows


def stage_03b(csv_path: Path, pcap: Path) -> dict:
    cmd = timed([sys.executable, str(REPO_ROOT / "03b_check_flows.py"), "--csv", str(csv_path), "--pcap",
                 str(guard(pcap)), "--out-dir", str(CHECK_OUT), "--json", str(CHECK_OUT / "summary.json")], "03b")
    log(f"03b: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    (PILOT / "03b.log").write_text(r.stdout + "\n--- stderr ---\n" + r.stderr, encoding="utf-8")
    if r.returncode == 2 or not (CHECK_OUT / "flow_check_report.json").is_file():
        fatal(f"03b crashed (exit {r.returncode}); see {rel(PILOT / '03b.log')}")
    J = read_json(CHECK_OUT / "flow_check_report.json")
    out = {"exit": r.returncode, "overall": read_json(CHECK_OUT / "summary.json").get("overall_status"),
           "time": time_log("03b"), "report": rel(CHECK_OUT / "flow_check_report.md"),
           "checks": [{"check": c["check"], "status": c["status"], "key_number": c["key_number"],
                       "reason": c["reason"]} for c in J["checks"]],
           "protocol_mix": next((c["data"].get("protocols") for c in J["checks"] if c["check"].startswith("7")), None),
           "packet_total": next((c["data"] for c in J["checks"] if c["check"].startswith("2")), None)}
    log(f"  03b overall {out['overall']} (exit {r.returncode})")
    return out


# --------------------------------------------------------------------------- 4: verdict

def verdict(P: dict, F: dict, feat: dict, ref: dict | None) -> dict:
    att_pk = P["S"]["att"]
    att_gre = P["S"]["gre_att"]
    pk_att = sum(F["pk_att"].values())
    sent = sum(F["pk_att_sent"].values())
    cov = pk_att / att_pk if att_pk else math.nan
    cov_sent = sent / att_pk if att_pk else math.nan
    by_p = sorted(F["pk_att_sent"].items(), key=lambda kv: -kv[1])
    dom = by_p[0][0] if by_p else None
    dom_share = by_p[0][1] / sent if sent else math.nan
    p0_share = F["pk_att_sent"].get(0, 0) / sent if sent else math.nan
    gre_flows = F["proto_all"].get(47, 0)
    # degeneracy is judged on the flood flows (attacker flows that are not TCP / UDP: the GRE stream); the attacker's
    # TCP / UDP side flows are the Pis' ordinary traffic and get NaN IATs only as 1-packet flows (03b check 6)
    fl = {f: v["flood"] for f, v in feat.items()}
    bad = {f: v for f, v in fl.items() if v["nan"] or v["+inf"] or v["-inf"]}
    bad_all = sorted(f for f, v in feat.items() if v["nan"] or v["+inf"] or v["-inf"])
    const = [f for f, v in fl.items() if v["constant"]]
    ref_var = [f for f in const if ref and not ref["table"][f]["constant"]]
    core_const = [f for f in CORE_FEATURES if f in const]
    zero_const = [f for f in const if fl[f]["value_if_constant"] == 0]
    n_att_flows = F["FS"].n
    n_flood = F["FL"].n
    reasons = []
    if n_att_flows == 0 or sent == 0:
        reasons.append("dropped: no flow carries the attacker's packets")
    elif dom == 0 or p0_share >= 0.10:
        reasons.append(f"protocol 0: {p0_share:.1%} of the attacker-sent packets in flows are in Protocol-0 flows")
    if not (cov >= COVERAGE_MIN):
        reasons.append(f"coverage {cov:.1%} < {COVERAGE_MIN:.0%} (dropped / partially dropped)")
    if att_pk and n_att_flows and n_att_flows <= 2 and att_pk > 1e5:
        reasons.append(f"merged: {att_pk:,} attacker packets in only {n_att_flows} flow(s)")
    if n_flood == 0:
        reasons.append("dropped: no non-TCP/UDP attacker flow (the GRE stream) in the CSV")
    if bad:
        reasons.append(f"degenerate: NaN / inf in {len(bad)} feature(s) over the {n_flood} flood flows "
                       f"({', '.join(bad)})")
    if core_const:
        vals = ", ".join(f"{f} = {fl[f]['value_if_constant']:g}" for f in core_const)
        reasons.append(f"degenerate: core shape feature(s) constant over the {n_flood} flood flows ({vals})")
    proto_ok = n_att_flows > 0 and dom not in (None, 0) and p0_share < 0.10
    notes = []
    if proto_ok and dom != 47:
        notes.append(f"attacker flows carry Protocol {dom} ({pname(dom)}), not 47 (GRE): {dom_share:.1%} of the "
                     "attacker-sent packets in flows. The GRE packets are keyed by the extractor under another "
                     "protocol value (see summary for which ports it used).")
    if bad_all and not bad:
        notes.append(f"NaN / inf over ALL attacker flows in {', '.join(bad_all)}, all in the TCP / UDP side flows "
                     "(1-packet flows: duration 0, no IAT; 03b check 6 attributes them to duration == 0; 08 sets "
                     "them to 0), none in the flood flows")
    if zero_const:
        notes.append(f"{len(zero_const)} of the 70 features are constant 0 over the flood flows: "
                     f"{', '.join(zero_const)}")
    if cov >= COVERAGE_MIN and not (cov_sent >= COVERAGE_MIN):
        notes.append(f"the requested coverage passes ({cov:.1%}) but the sent-side coverage is {cov_sent:.1%}: "
                     "replies / benign Pi traffic inflate the requested ratio")
    return {"verdict": "PASS" if not reasons else "FAIL", "reasons": reasons, "notes": notes,
            "attacker_packets": att_pk, "attacker_gre_packets": att_gre, "attacker_flows": n_att_flows,
            "attacker_flow_packets": pk_att, "attacker_flow_packets_sent_side": sent,
            "coverage": cov, "coverage_sent_side": cov_sent, "coverage_min": COVERAGE_MIN,
            "dominant_protocol": dom, "dominant_protocol_share_sent": dom_share, "protocol0_share_sent": p0_share,
            "protocol_ok": proto_ok, "gre_protocol47_flows_all": gre_flows,
            "flood_flows": n_flood, "features_nan_inf_all_attacker_flows": bad_all,
            "features_nan_inf": sorted(bad), "features_constant": const, "features_constant_zero": zero_const,
            "features_constant_here_but_varying_in_udpplain": ref_var, "core_features_constant": core_const}


# --------------------------------------------------------------------------- main

def main() -> int:
    global _LOG_PATH
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--no-reuse", action="store_true", help="redo the packet pass and the extraction")
    args = ap.parse_args()
    t0 = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "run.log").unlink(missing_ok=True)
    _LOG_PATH = OUT / "run.log"
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...")
    lock = verify_lock(strict=False)
    for name, ok, detail in lock["checks"]:
        log(f"  lock {'PASS' if ok else 'FAIL'}  {name}: {detail}")
    if not lock["ok"]:
        fatal("verify_lock() failed; STOP")
    M = {"script": SCRIPT, "code_sha256": CODE_SHA256, "run_utc": run_utc, "argv": sys.argv,
         "git_head": subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True,
                                    text=True).stdout.strip(),
         "scope": f"{PART} only; parts 9 / 18 / 27 / 28 not touched; test.parquet never opened",
         "verify_lock": [{"check": n, "ok": o, "detail": d} for n, o, d in lock["checks"]],
         "extractor_lock": {k: str(v) for k, v in vars(EXTRACTOR).items()} | {"jar_path": str(EXTRACTOR.jar_path)},
         "steps": {}}
    if args.no_reuse:
        for p in (PILOT / "packets.json", FLOWS_OUT / f"{PART}_Flow__{SUFFIX}.csv.meta.json"):
            p.unlink(missing_ok=True)

    # ---- 0
    s = time.monotonic()
    pcap = stage_copy(M)
    M["steps"]["0_copy_and_hash"] = {"wall_s": round(time.monotonic() - s, 1)}
    # ---- 1
    s = time.monotonic()
    P = stage_packets(pcap, M)
    M["steps"]["1_packets"] = {"wall_s": round(time.monotonic() - s, 1), "capinfos": P.get("capinfos_time"),
                               "tshark": P.get("tshark_time")}
    dev = m07a.Devices(DEVICE_TABLE)
    k2 = {norm_mac(m): g for m, g in read_json(K2_JSON)["devices"].items()}
    V = victims(P, dev, k2)
    att_ips, att_ip_rows = attacker_ip_set(P)
    log(f"attacker packets {P['S']['att']:,} ({pct(P['S']['att'], P['S']['packets']):.1f} %), GRE "
        f"{P['S']['gre_all']:,}; attacker IPs {sorted(att_ips)}; victims {len(V)}")
    # ---- 2
    s = time.monotonic()
    csv_path = stage_extract(pcap, M)
    M["steps"]["2_extract"] = {"wall_s": round(time.monotonic() - s, 1), **M["extract"]["time"]}
    # ---- 3
    s = time.monotonic()
    feats = read_json(FEATURES)["features"]
    if len(feats) != 70:
        fatal(f"features_v1.json lists {len(feats)} features, expected 70")
    log("reading flows ...")
    F = read_flows(csv_path, feats, att_ips)
    feat = F["FS"].table()
    for f, v in F["FL"].table().items():
        feat[f]["flood"] = v
    log(f"  {F['rows']:,} flows; attacker flows {F['FS'].n:,}")
    log(f"reference: {rel(REF_CSV)} attack flows ...")
    ref = ref_features(feats)
    for f in feats:
        feat[f]["udpplain_constant"] = ref["table"][f]["constant"] if ref else None
        feat[f]["udpplain_value_if_constant"] = ref["table"][f]["value_if_constant"] if ref else None
    M["steps"]["3a_flows"] = {"wall_s": round(time.monotonic() - s, 1),
                              "peak_rss_self_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)}
    s = time.monotonic()
    C = stage_03b(csv_path, pcap)
    M["steps"]["3b_03b_check"] = {"wall_s": round(time.monotonic() - s, 1), **C["time"]}
    # ---- 4
    VD = verdict(P, F, feat, ref)
    log(f"VERDICT (proposal): {VD['verdict']}  {VD['reasons']}  notes {VD['notes']}")

    # ---- outputs
    victim_ip = victim_ip_names(P, dev, k2)
    prof = profile_rows(F["AF"], att_ips, victim_ip)
    pd.DataFrame(prof).to_csv(OUT / "attacker_flows_profile.csv", index=False, lineterminator="\n")
    PM = protocol_mix(P, F)
    pd.DataFrame(PM).to_csv(OUT / "protocol_mix.csv", index=False, lineterminator="\n")
    M.update({"packets": {k: P[k] for k in P if k not in ("key",)}, "victims": V, "attacker_ip_set": att_ip_rows,
              "victim_ip_names": victim_ip,
              "flows": {"csv": str(csv_path), "rows": F["rows"], "attacker_flows": F["FS"].n,
                        "attacker_distinct_feature_rows": len(F["FS"].rows),
                        "by_protocol_all": dict(F["proto_all"]), "by_protocol_attacker": dict(F["proto_att"]),
                        "packets_by_protocol_attacker": dict(F["pk_att"]),
                        "sent_packets_by_protocol_attacker": dict(F["pk_att_sent"])},
              "features": feat, "reference_udpplain": {"csv": rel(REF_CSV), "attack_flows": ref["n"] if ref else None,
                                                       "distinct_rows": ref["distinct_rows"] if ref else None},
              "check_03b": C, "verdict": VD,
              "peak_rss_mb": {"python_self": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
                              "children_max": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024, 1)},
              "test_parquet": "never opened"})
    M["runtime_s"] = round(time.monotonic() - t0, 1)
    write_json(OUT / "run_meta.json", M)
    write_summary(M, P, V, F, feat, prof, PM, C, VD, att_ip_rows)
    log(f"done in {M['runtime_s']:.0f} s -> {rel(OUT)}/summary.md")
    return 0


def victim_ip_names(P: dict, dev, k2: dict) -> dict:
    """Outer ip.dst of attacker packets -> 'device (k2 group)' of the eth.dst that carried most of them."""
    best: dict[str, tuple[int, str]] = {}
    for ip, mac, n in P["att_ip_dst_mac"]:
        if ip and n > best.get(ip, (0, ""))[0]:
            best[ip] = (n, mac)
    out = {}
    for ip, (n, mac) in best.items():
        name, cls = dev.dest_class(mac) if m07a.mac_is_unicast(mac) else ("broadcast / multicast", "bcast")
        out[ip] = f"{name} ({k2.get(mac, cls)})"
    return out


def protocol_mix(P: dict, F: dict) -> list[dict]:
    rows = []
    tot, att = P["S"]["packets"], P["S"]["att"]
    for p, n in sorted(P["proto_outer"].items(), key=lambda kv: -kv[1]):
        a = P["proto_outer_att"].get(p, 0)
        rows.append({"level": "packets: outer ip.proto", "key": p or "(none: non-IPv4)",
                     "name": pname(p) if p else "non-IPv4 (ARP, IPv6, ...)", "all": n, "all_pct": pct(n, tot),
                     "attacker": a, "attacker_pct": pct(a, att)})
    for st, n in sorted(P["stacks"].items(), key=lambda kv: -kv[1]):
        a = P["stacks_att"].get(st, 0)
        rows.append({"level": "packets: frame.protocols", "key": st, "name": "", "all": n, "all_pct": pct(n, tot),
                     "attacker": a, "attacker_pct": pct(a, att)})
    g = P["S"]["gre_att"]
    for k, n in sorted(P["gre_inner_ip_proto"].items(), key=lambda kv: -kv[1]):
        rows.append({"level": "packets: inner ip.proto inside GRE (attacker)", "key": k, "name": pname(k),
                     "all": "", "all_pct": "", "attacker": n, "attacker_pct": pct(n, g)})
    nf, na = F["rows"], F["FS"].n
    for p in sorted(set(F["proto_all"]) | set(F["proto_att"])):
        rows.append({"level": "flows: Protocol", "key": p, "name": pname(p), "all": F["proto_all"].get(p, 0),
                     "all_pct": pct(F["proto_all"].get(p, 0), nf), "attacker": F["proto_att"].get(p, 0),
                     "attacker_pct": pct(F["proto_att"].get(p, 0), na),
                     "all_packets": int(F["pk_all"].get(p, 0)), "attacker_packets": int(F["pk_att"].get(p, 0)),
                     "attacker_sent_packets": int(F["pk_att_sent"].get(p, 0))})
    return rows


def write_summary(M, P, V, F, feat, prof, PM, C, VD, att_ip_rows) -> None:
    cap, S = P["capinfos"], P["S"]
    L = ["# Step 12b -- Mirai greeth_flood pilot: does the locked extractor turn GRE into usable flows?", "",
         f"- run {M['run_utc']}, git HEAD `{M['git_head']}`, {SCRIPT} sha256 `{CODE_SHA256[:16]}...`",
         f"- scope: {M['scope']}",
         f"- pcap `{PART}`: {M['pcap']['how']}; sha256 `{M['pcap']['sha256']}` "
         f"{'==' if M['pcap']['sha256_match'] else '!='} config/sha256_greeth.txt; {M['pcap']['size_bytes'] / 1e9:.2f} GB",
         f"- extractor: verify_lock() {'PASS' if all(c['ok'] for c in M['verify_lock']) else 'FAIL'}; jar sha256 "
         f"`{EXTRACTOR.jar_sha256[:16]}...` ({EXTRACTOR.upstream}@{EXTRACTOR.commit} + {EXTRACTOR.patch} + "
         f"{EXTRACTOR.patch_sweeper}), {EXTRACTOR.flow_timeout_s} s / {EXTRACTOR.activity_timeout_s} s, TZ=UTC, "
         f"{EXTRACTOR.java_heap_max}; run through extraction/run_cicflowmeter.py", ""]
    L += [f"## Verdict (proposal -- you decide): **{VD['verdict']}**", ""]
    L += [f"- {r}" for r in VD["reasons"]] or ["- no failing criterion"]
    L += [f"- note: {n}" for n in VD["notes"]]
    L += ["", md_kv([("attacker packets (outer eth.src = attacker MAC)", VD["attacker_packets"]),
                     ("  of which GRE (outer ip.proto 47)", VD["attacker_gre_packets"]),
                     ("attacker flows (Src or Dst IP in the attacker IP set)", VD["attacker_flows"]),
                     ("Total Fwd + Bwd packets of attacker flows", VD["attacker_flow_packets"]),
                     ("coverage (requested definition)", f"{VD['coverage']:.2%}"),
                     ("sent-side coverage (attacker-IP direction only)", f"{VD['coverage_sent_side']:.2%}"),
                     ("dominant Protocol of attacker flows (by attacker-sent packets)",
                      f"{VD['dominant_protocol']} ({pname(VD['dominant_protocol'])}), "
                      f"{VD['dominant_protocol_share_sent']:.1%}"),
                     ("Protocol-47 flows in the whole CSV", VD["gre_protocol47_flows_all"]),
                     ("flood flows (attacker flows, Protocol not TCP / UDP)", VD["flood_flows"]),
                     ("features with NaN / inf (flood flows)", ", ".join(VD["features_nan_inf"]) or "none"),
                     ("features with NaN / inf (all attacker flows)",
                      ", ".join(VD["features_nan_inf_all_attacker_flows"]) or "none"),
                     ("features constant over the flood flows", len(VD["features_constant"])),
                     ("  of those, constant 0", len(VD["features_constant_zero"])),
                     ("  of those, varying over Mirai-udpplain attack flows",
                      ", ".join(VD["features_constant_here_but_varying_in_udpplain"]) or "none"),
                     ("core shape features constant (flood flows)",
                      ", ".join(VD["core_features_constant"]) or "none")]), ""]
    L += ["Criteria: PASS if the attacker GRE traffic appears as flows with a usable (non-0) Protocol, coverage >= "
          f"{COVERAGE_MIN:.0%}, and the 70 features are not degenerate over the flood flows (no NaN / inf, and none "
          f"of {', '.join(CORE_FEATURES)} constant).", ""]
    L += ["## 1. Packet-level truth (tshark / capinfos, base part only)", ""]
    L += [md_kv([("packets (capinfos)", cap["packets"]), ("packets (tshark)", S["packets"]),
                 ("capture start (UTC)", cap["first_utc"]), ("capture end (UTC)", cap["last_utc"]),
                 ("duration", f"{cap['duration_s']:,.1f} s ({cap['duration_s'] / 60:,.1f} min)"),
                 ("GRE packets (outer ip.proto 47)", f"{S['gre_all']:,} ({pct(S['gre_all'], S['packets']):.2f} %)"),
                 ("  sent by attacker MACs / by others", f"{S['gre_att']:,} / {S['gre_not_att']:,}"),
                 ("attacker packets", f"{S['att']:,} ({pct(S['att'], S['packets']):.2f} %)"),
                 ("attacker first / last packet (UTC)",
                  f"{utc(S['att_first'])} .. {utc(S['att_last'])} ({(S['att_last'] - S['att_first']) / 60:,.1f} min)"),
                 ("GRE payload type (gre.proto, attacker)", fmt_counter(P["gre_payload_type"], S["gre_att"])),
                 ("inner ip.proto inside GRE (attacker)", fmt_counter(P["gre_inner_ip_proto"], S["gre_att"])),
                 ("inner ip.dst == outer ip.dst (attacker GRE)", f"{P['gre_inner_ip_dst_equals_outer']:,}"),
                 ("distinct inner values (attacker GRE)",
                  ", ".join(f"{k} {v}" for k, v in P["gre_inner_distinct"].items())),
                 ("attacker GRE frame length min / mean / max",
                  f"{fnum(P['gre_att_frame_len']['min'], 0)} / {fnum(P['gre_att_frame_len']['mean'], 1)} / "
                  f"{fnum(P['gre_att_frame_len']['max'], 0)} B"),
                 ("tshark pass", f"{S['tshark_seconds']} s, peak RSS {fnum(P.get('tshark_time', {}).get('peak_rss_mb'), 0)} MB")]), ""]
    L += ["### Protocol hierarchy (frame.protocols; all packets, attacker packets)", ""]
    L += md_table([r for r in PM if r["level"] == "packets: frame.protocols"][:15],
                  ["key", "all", "all_pct", "attacker", "attacker_pct"])
    L += ["", "### Inner protocol stacks after `gre` (attacker GRE packets)", ""]
    L += md_table([{"inner stack": k, "packets": v, "pct": pct(v, S["gre_att"])}
                   for k, v in sorted(P["gre_inner_stack"].items(), key=lambda kv: -kv[1])[:10]],
                  ["inner stack", "packets", "pct"])
    L += ["", "### Victims (outer eth.dst of attacker packets; 07a's device mapping, behaviour_k2 group)", ""]
    L += md_table(V[:15], ["device", "dst_mac", "class_07a", "group_k2", "attacker_packets", "pct_of_attacker",
                           "attacker_macs"])
    L += ["", "### Attacker IP set (outer ip.src of attacker packets; 07's T1b rule)", ""]
    L += md_table(att_ip_rows[:15], ["ip", "packets", "used", "why"])
    L += ["", "### Attacker streams (outer ip.src, ip.dst, ip.proto) and what the 120 s timeout alone would give", ""]
    st = [{"src": s, "dst": d, "proto": f"{p} ({pname(p)})" if p else "(non-IPv4)", "packets": n,
           "span_s": hi - lo, "flows_if_only_120s_timeout": max(1, math.ceil((hi - lo) / FLOW_TIMEOUT_S))}
          for s, d, p, n, lo, hi in P["att_streams"][:15]]
    L += md_table(st, ["src", "dst", "proto", "packets", "span_s", "flows_if_only_120s_timeout"])
    L += ["", "## 2. Extraction", ""]
    E = M["extract"]["meta"]
    L += [md_kv([("CSV", rel(E["csv"])), ("rows", E["row_count"]), ("cfm packets", str(E["packets"])),
                 ("idle sweeper", str(E["idle_sweeper"])), ("elapsed", f"{E['elapsed_s']} s"),
                 ("peak RSS (wrapper + JVM)", f"{fnum(M['steps']['2_extract'].get('peak_rss_mb'), 0)} MB"),
                 ("reused", M["extract"]["reused"])]), ""]
    L += ["## 3. Flow-level check", "", "### Flows by Protocol", ""]
    L += md_table([r for r in PM if r["level"] == "flows: Protocol"],
                  ["key", "name", "all", "all_pct", "all_packets", "attacker", "attacker_pct", "attacker_packets",
                   "attacker_sent_packets"])
    L += ["", "attacker = Src IP or Dst IP in the attacker IP set; attacker_sent_packets = Total Fwd packets when the "
              "attacker IP is the Src IP, Total Bwd when it is the Dst IP.", ""]
    L += ["### Attacker flows: packets per flow, duration, ports (per protocol; per stream in attacker_flows_profile.csv)",
          ""]
    tots = [r for r in prof if r["scope"] != "stream"]
    L += md_table(tots, ["scope", "protocol_name", "flows", "packets_sum", "sent_by_attacker_sum", "pkts_min",
                         "pkts_median", "pkts_max", "dur_s_median", "dur_s_max", "flows_dur_ge_115s",
                         "src_ports_distinct", "dst_ports_distinct", "src_port_top", "dst_port_top"])
    L += ["", "### Top attacker streams (flows per attacker IP / other IP / protocol)", ""]
    L += md_table([r for r in prof if r["scope"] == "stream"][:15],
                  ["protocol_name", "attacker_ip", "other_ip", "flows", "packets_sum", "pkts_median", "dur_s_median",
                   "src_port_top", "dst_port_top"])
    L += ["", f"### The 70 features: {F['FL'].n:,} flood flows ({len(F['FL'].rows):,} distinct rows) and all "
              f"{F['FS'].n:,} attacker flows ({len(F['FS'].rows):,} distinct rows)", ""]
    frows = [{"feature": f, "flood_nan_inf": v["flood"]["nan"] + v["flood"]["+inf"] + v["flood"]["-inf"],
              "flood_min": v["flood"]["min"], "flood_max": v["flood"]["max"],
              "flood_constant": "yes" if v["flood"]["constant"] else "",
              "all_nan": v["nan"], "all_inf": v["+inf"] + v["-inf"], "all_min": v["min"], "all_max": v["max"],
              "udpplain_constant": "yes" if v["udpplain_constant"] else ""}
             for f, v in feat.items()]
    L += md_table(frows, ["feature", "flood_nan_inf", "flood_min", "flood_max", "flood_constant", "all_nan", "all_inf",
                          "all_min", "all_max", "udpplain_constant"])
    ref = M["reference_udpplain"]
    L += ["", f"udpplain_constant = constant over the {fnum(ref['attack_flows'])} Mirai-udpplain attack flows "
              f"({ref['csv']}, train + val source; read-only reference for what a UDP flood leaves constant).", ""]
    L += ["### 03b checks on the CSV", ""]
    L += md_table(C["checks"], ["check", "status", "key_number", "reason"])
    L += ["", f"03b overall {C['overall']} (exit {C['exit']}); full report {C['report']} (cache, not in git).", ""]
    L += ["## Run cost", ""]
    L += md_table([{"step": k, **{kk: vv for kk, vv in v.items() if not isinstance(vv, dict)},
                    **{f"{kk}_{x}": y for kk, vv in v.items() if isinstance(vv, dict) for x, y in vv.items()}}
                   for k, v in M["steps"].items()],
                  ["step", "wall_s", "elapsed_s", "peak_rss_mb", "capinfos_peak_rss_mb", "tshark_elapsed_s",
                   "tshark_peak_rss_mb", "peak_rss_self_mb"])
    L += ["", f"Total {M['runtime_s']:,.0f} s. Steps ran one at a time."]
    (OUT / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def md_kv(items: list[tuple]) -> str:
    return "\n".join(["| item | value |", "|---|---|"] + [f"| {k} | {fnum(v) if not isinstance(v, str) else v} |"
                                                         for k, v in items])


def utc(t: float) -> str:
    if t is None or not math.isfinite(t):
        return "N/A"
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds")


def fmt_counter(d: dict, tot: int) -> str:
    return "; ".join(f"{k or '(empty)'} {v:,} ({pct(v, tot):.1f} %)" for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:6])


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        log("UNEXPECTED ERROR\n" + traceback.format_exc())
        sys.exit(2)
