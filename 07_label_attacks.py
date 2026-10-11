#!/usr/bin/env python
"""07_label_attacks.py -- label every CICFlowMeter flow of each attack pcap attack / benign / excluded.

Inputs: config/attack_set.json (locked attack set; --pcap overrides), config/device_table.csv,
07a's per-pcap outputs (<coverage-dir>/<stem>_stats.json, _pairs.csv, _victims.csv,
control_baseline.json). Nothing under config/ is written.

Per pcap (every step reuses the existing scripts' functions):
  1  flows    06c.extract_flows (extraction/run_cicflowmeter.py: locked jar, singlepkt, TZ=UTC)
              into ATTACK_FLOWS_DIR/<stem>/ (reused when the CSV + meta sidecar match the pcap
              SHA256 and the locked jar), then 06c.check_flows (03b; exit 1 / 2 aborts; its
              packet-total check uses this pcap's own capinfos packet count).
  2  map      06c.build_map (02's logic) on THIS pcap -> CACHE_DIR/maps/<stem>_ip_mac_map.csv,
              reused when its .meta.json matches (pcap, device_table, 02 source SHA256).
  3  tag      04's logic exactly as 06c.tag_flows (resolve_side, sender-MAC conflict
              resolution, assign_owner, exclude reasons), but in CHUNKS of --chunk raw CSV lines:
              a prescan finds the ambiguous flows on map-conflict IPs (only those can be
              resolved) and collects the UDP flow keys for T4's ICMP mirror test, the conflict-IP packets are extracted ONCE per pcap
              (04.extract_conflict_packets, same tshark window as 04 / 06c), matched to the
              ambiguous flows in chunks (04.match_packets_sender), and the per-flow result is
              applied when the main pass reaches that row. The 84 original columns are copied
              as raw bytes (never re-parsed or re-formatted); tag + label columns are appended.
  4  label    for each attacker-MAC endpoint A (src_mac / dst_mac after tagging, one MAC) with
              other endpoint O, tests in order:
                T1  A matches ATTACKER_MACS, or
                T1b A's IP is in this pcap's attacker IP set (every ip.src on packets whose
                    eth.src matches ATTACKER_MACS; one lean tshark pass per pcap, cached in
                    CACHE_DIR/maps/<stem>_attacker_ips.json; unicast LAN / external addresses
                    only -- 0.0.0.0, ::, multicast, broadcast are shared by every host, e.g.
                    DHCP, and are listed but not used) AND no non-attacker MAC holds that
                    IP in this pcap's map during the flow ([first_seen - 1 s, last_seen + 1 s]
                    overlapping the flow lifetime). The endpoint is then evaluated as each
                    attacker MAC that sent from that IP (best outcome wins). Catches spoofed /
                    unmapped attacker sources whose IP resolves to no attacker MAC; an IP a real
                    host also holds keeps the sender-MAC resolution / spoof_collision handling.
                T2  the flow lifetime [t, t + Flow Duration + 1 s] overlaps one of 07a's burst
                    windows OF A, padded by --pad-s each side (t = Timestamp, truncated to whole
                    seconds by CICFlowMeter, hence 04's 1 s tolerance on the end). pad_only =
                    True when it overlaps only thanks to the padding.
                T3  (A, O) is a victim pair in 07a's <stem>_pairs.csv (victim True)
                T4  the flow's service is not in 07a's control service set for the pair (A, O).
                    07a's service = (ip.proto, min(src port, dst port)) for TCP/UDP. Flows of
                    CICFlowMeter Protocol 0 (no ports) count as a known service when the pair's
                    control set has any port-less non-TCP/UDP service. A pair whose control set
                    hit 07a's cap was never tested for new services in 07a -> known.
                    07a's services are those of packets SENT BY the attacker MAC, so two flow
                    shapes are mapped back to that definition: a flow in which the attacker side
                    sent no packets (Total Fwd / Bwd packets) carries no attacker service ->
                    known; and a UDP flow the attacker "sends" that has a mirror flow (same port
                    pair, IPs swapped) is CICFlowMeter's reading of the attacker's ICMP errors
                    (outer IPs, quoted inner ports, see 04) -> its service is 07a's ICMP (1, none).
                    Example: a device's SSDP replies from UDP/1900 to a closed Pi port; the Pi
                    answers ICMP port-unreachable, which 07a counts as ICMP, not UDP/1900.
              With A on both sides the orientation that gets furthest is used. Outcome:
                not T1                      -> benign, unless spoof_collision (below)
                T1, not T2                  -> excluded attacker_offwindow
                T1 T2, not T3               -> excluded attacker_normal_traffic, or
                                               victim_ambiguous when O is still ambiguous after
                                               conflict resolution (several candidate MACs;
                                               04's ip_conflict_unresolved)
                T1 T2 T3, not T4            -> excluded attack_normal_service_ambiguous if the
                                               pair's 07a reason has "rate" (rate/both), else
                                               attacker_normal_traffic
                T1 T2 T3 T4                 -> attack, attack_family from the attack set
              spoof_collision: no attacker endpoint (T1 / T1b), one endpoint IP is an attacker
              source IP that collides with a real smart-home device IP (attacker IP set
              intersected with the role-iot IPs of this pcap's map; cross-checked against 07a's
              spoof block), the other endpoint is a 07a victim, and the flow overlaps a 07a burst
              window (any attacker, padded).
              04's exclude_reason is kept; label columns: label, attack_family, label_tests
              (tests passed, e.g. "T1,T2,T3,T4"; "T1b,..." when T1 holds only via T1b),
              label_exclude_reason, pad_only. The report counts the flows that pass T1 only via
              T1b and what they would have been without it (benign or spoof_collision).
  5  owner    unchanged from 04: an attack flow to a smart-home device is owned by the victim;
              a victim that is the gateway or any non-iot host leaves the flow unowned (counted
              separately: the known gateway-target blind spot).

Outputs
  ATTACK_FLOWS_DIR/<stem>/<stem>_labelled.csv.gz       84 original + 14 tag + 5 label columns
  <out-dir>/<stem>_label_report.md / .json              counts, checks, runtime, peak RSS,
                                                        completion key (written last)
  <out-dir>/<stem>_timeline.png                         flows / minute by label, bursts shaded
  <out-dir>/label_summary.csv / .md                     rebuilt from every report each run

Checks per pcap. HARD (exit 1 after all pcaps): no attack flow outside 07a burst windows (+pad);
every attack victim is a 07a victim of the pcap; exactly one outcome per flow (label in
attack/benign/excluded, label_exclude_reason set iff excluded, attack_family set iff attack);
rows written == flow CSV rows == extractor meta row_count. SOFT (reported): per-group attack
victims vs 07a coverage verdicts; attack flows / 07a attacker packets; benign owned-flow share
per device vs the benign capture; benign flows inside bursts touching a 07a victim.

--skip-done skips a pcap whose report has the same completion key (pcap, device_table and 07a
stats SHA256, pad, 07a K, family, label version, SHA256 of this script, locked extractor jar
SHA256) and whose labelled CSV exists. If 07a's stats were computed with another device_table
(or another pcap), exit 1: re-run 07a for that stem.

One run at a time: an exclusive flock on <out-dir>/.07_label.lock and <flows-dir>/.07_label.lock
is held for the whole run; a second run on either dir exits 1 (concurrent runs each started a
cfm on the same pcap and crashed each other). The wrapper also locks each flow out-dir.

Exit status: 0 ok, 1 bad input / stale 07a / hard check failed / another run active,
2 unexpected exception.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import gzip
import importlib.util
import io
import ipaddress as ipa
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import (ATTACK_FLOWS_DIR, ATTACKER_MACS, CACHE_DIR, CONFIG_DIR, DEVICE_TABLE, EXTRACTOR,
                           NETWORK, REPO_ROOT, RESULTS_DIR)


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m06c = _load("place_new_device", "06c_place_new_device.py")
m07a = _load("attack_coverage", "07a_attack_coverage.py")
m02, m04 = m06c.m02, m06c.m04
log, fatal, sha256, norm_mac, md_table, utc = m02.log, m02.fatal, m02.sha256, m02.norm_mac, m02.md_table, m02.utc

ATTACK_SET = CONFIG_DIR / "attack_set.json"
ATTACK_BASE = CACHE_DIR / "ciciot2023" / "attack"
COVERAGE_DIR = RESULTS_DIR / "step7" / "coverage"
OUT_DIR = RESULTS_DIR / "step7" / "labels"
MAPS_DIR = CACHE_DIR / "maps"
BENIGN_TAGGED = m06c.BENIGN_TAGGED
TOL = 1.0                       # 04's default window tolerance (Timestamps truncated to seconds)
LABEL_VERSION = 3               # 2: T1b attacker IP set; 3: victim_ambiguous, 03b pcap count
CODE_SHA256 = sha256(Path(__file__).resolve())   # completion key: any edit of 07 re-runs
ATT_IP_CAP = 2_000_000          # distinct (attacker MAC, ip.src) pairs kept by the T1b pass
ATT_IP_VERSION = 1
T1B_MAX_MACS = 4                # attacker MACs tried per T1b endpoint
PARSE_COLS = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
              "Total Fwd Packet", "Total Bwd packets"]
LABEL_COLS = ["label", "attack_family", "label_tests", "label_exclude_reason", "pad_only"]
LABELS = ["attack", "benign", "excluded"]
REASONS = ["attacker_offwindow", "attacker_normal_traffic", "victim_ambiguous",
           "attack_normal_service_ambiguous", "spoof_collision"]
GROUPS_OUT = ["G1", "G2", "GEN", "ungrouped", "unowned"]
PORT_PROTOS = (6, 17)
SVC_BASE = 100_000              # service code = proto * SVC_BASE + port
BURST_RE = re.compile(r"^(\d\d):(\d\d):(\d\d)-(\d\d):(\d\d):(\d\d) \(([\d,]+) pkts\)$")
TESTS = {c: ",".join(f"T{i + 1}" for i in range(4) if c >> i & 1) for c in range(16)}

# Chart tokens (dataviz reference palette, light mode): benign = slot 1, attack = slot 2.
SURFACE, TEXT1, TEXT2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e0"
COLOR = {"benign": "#2a78d6", "attack": "#eb6834", "excluded": "#a3a29b"}
BURST_FILL = "#e6e5e0"


# --------------------------------------------------------------------------- inputs

def load_attack_set(path: Path) -> list[dict]:
    S = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for e in S["pcaps"]:
        p = ATTACK_BASE / e["path"]
        out.append({"pcap": p, "family": e["family"], "sha256": e["sha256"], "set_path": e["path"]})
    return out


def iso_epoch(s: str) -> float:
    return dt.datetime.fromisoformat(s).timestamp()


def parse_bursts(P: dict) -> tuple[list[tuple[float, float]], dict[str, list[tuple[float, float]]]]:
    """07a's overall burst windows (dated) and per-attacker-MAC windows. The per-MAC windows are
    stored as 'HH:MM:SS-HH:MM:SS (n pkts); ...' without a date; each is anchored to the first day
    (from the capture start) that puts it after the previous window of that MAC and inside one
    of the overall windows (a per-MAC hot minute is always an overall hot minute)."""
    overall = [(iso_epoch(b["start"]), iso_epoch(b["end"])) for b in P["bursts"]]
    d0 = dt.datetime.fromisoformat(P["capture"]["first_utc"]).replace(hour=0, minute=0, second=0,
                                                                     microsecond=0)
    d1 = dt.datetime.fromisoformat(P["capture"]["last_utc"])
    days = [(d0 + dt.timedelta(days=i)).timestamp() for i in range((d1 - d0).days + 2)]
    per_mac = {}
    for r in P["per_mac"]:
        mac, wins, prev = norm_mac(r["attacker_mac"]), [], -np.inf
        if r["bursts"] != "-":
            for part in r["bursts"].split("; "):
                g = BURST_RE.match(part.strip())
                if not g:
                    fatal(f"{P['stem']}: cannot parse 07a per-MAC burst {part!r} ({mac})")
                h1, m1, s1, h2, m2, s2 = (int(x) for x in g.groups()[:6])
                a_off, b_off = h1 * 3600 + m1 * 60 + s1, h2 * 3600 + m2 * 60 + s2
                hit = None
                for day in days:
                    lo = day + a_off
                    hi = day + b_off + (86400 if b_off <= a_off else 0)
                    if lo >= prev and any(olo <= lo and hi <= ohi for olo, ohi in overall):
                        hit = (lo, hi)
                        break
                if hit is None:
                    fatal(f"{P['stem']}: per-MAC burst {part!r} of {mac} fits no overall burst window")
                wins.append(hit)
                prev = hit[1]
        per_mac[mac] = wins
    return overall, per_mac


def load_07a(cov: Path, stem: str, pcap_sha: str, dev_sha: str) -> dict:
    spath = cov / f"{stem}_stats.json"
    if not spath.is_file():
        fatal(f"no 07a stats {spath}: re-run 07a for {stem}")
    P = json.loads(spath.read_text(encoding="utf-8"))
    if P.get("stats_version") != m07a.STATS_VERSION:
        fatal(f"{spath.name}: stats_version {P.get('stats_version')} != {m07a.STATS_VERSION}; re-run 07a for {stem}")
    if P["params"].get("device_table_sha256") != dev_sha:
        fatal(f"{spath.name} was computed with device_table sha256 "
              f"{P['params'].get('device_table_sha256')}, current is {dev_sha}: re-run 07a for {stem}")
    if P.get("sha256") != pcap_sha:
        fatal(f"{spath.name} is for pcap sha256 {P.get('sha256')}, this pcap is {pcap_sha}: re-run 07a for {stem}")
    bpath = cov / "control_baseline.json"
    if not bpath.is_file():
        fatal(f"{bpath} missing: re-run 07a for {stem}")
    B = json.loads(bpath.read_text(encoding="utf-8"))
    if B.get("sha256") != P["params"]["control_sha256"]:
        fatal(f"{bpath.name} is for control {B.get('sha256')}, {spath.name} used "
              f"{P['params']['control_sha256']}: re-run 07a for {stem}")
    pairs = pd.read_csv(cov / f"{stem}_pairs.csv", dtype=str, keep_default_na=False)
    victims = pd.read_csv(cov / f"{stem}_victims.csv", dtype=str, keep_default_na=False)
    vp = pairs[pairs["victim"] == "True"]
    overall, per_mac = parse_bursts(P)
    C = m07a.control_view(B)
    ctl = {}
    for (s, d), svcs in C["svc"].items():
        ctl[f"{s}|{d}"] = ({p * SVC_BASE + q for p, q in svcs if p in PORT_PROTOS and q >= 0},
                           any(p not in PORT_PROTOS for p, _ in svcs), (s, d) in C["over"],
                           (1, -1) in svcs)
    return {"P": P, "stats_path": spath, "stats_sha256": sha256(spath),
            "victim_pairs": {f"{norm_mac(a)}|{norm_mac(m)}": r
                             for a, m, r in zip(vp["attacker_mac"], vp["mac"], vp["reason"])},
            "victim_macs": set(victims["mac"].map(norm_mac)),
            "victims": victims, "overall": overall, "per_mac": per_mac, "control": ctl,
            "control_over_pairs": len(C["over"])}


def get_map(pcap: Path, pcap_sha: str, dev_sha: str, d02: pd.DataFrame) -> tuple[Path, dict]:
    """06c.build_map on this pcap, reused when the sidecar key matches."""
    out = MAPS_DIR / f"{pcap.stem}_ip_mac_map.csv"
    meta = out.with_name(out.name + ".meta.json")
    key = {"pcap_sha256": pcap_sha, "device_table_sha256": dev_sha,
           "m02_sha256": sha256(REPO_ROOT / "02_mac_ip_map.py")}
    if out.is_file() and meta.is_file():
        old = json.loads(meta.read_text(encoding="utf-8"))
        if old.get("key") == key:
            log(f"  reusing {out} (meta key matches)")
            return out, {**old["info"], "action": "reused"}
    info = m06c.build_map(pcap, d02, out)
    meta.write_text(json.dumps({"key": key, "info": info}, indent=1) + "\n", encoding="utf-8")
    return out, {**info, "action": "built"}


def attacker_ips(pcap: Path, pcap_sha: str) -> dict:
    """T1b: every (eth.src, ip.src) on packets sent by an attacker MAC, with packets and
    first/last time. One lean tshark pass (02's flags, display filter on the attacker MACs);
    cached per pcap."""
    out = MAPS_DIR / f"{pcap.stem}_attacker_ips.json"
    key = {"pcap_sha256": pcap_sha, "exact": list(ATTACKER_MACS.exact),
           "prefixes": list(ATTACKER_MACS.prefixes), "version": ATT_IP_VERSION}
    if out.is_file():
        old = json.loads(out.read_text(encoding="utf-8"))
        if old.get("key") == key:
            log(f"  reusing {out} (key matches)")
            return old
    clauses = [f"eth.src == {m}" for m in ATTACKER_MACS.exact]
    clauses += [f"eth.src[0:{len(p.split(':'))}] == {p}" for p in ATTACKER_MACS.prefixes]
    cmd = ["tshark", "-n", *m02.TSHARK_LEAN, "-r", str(pcap), "-Y", " || ".join(clauses),
           "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
           "-e", "frame.time_epoch", "-e", "eth.src", "-e", "ip.src", "-e", "ipv6.src"]
    log("  attacker IP pass: " + " ".join(cmd))
    t0 = time.monotonic()
    agg: dict[tuple[str, str], list] = {}
    over, n = 0, 0
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, env={**os.environ, "TZ": "UTC"})
        reader = pd.read_csv(proc.stdout, sep="\t", header=None, names=["t", "mac", "ip4", "ip6"],
                             dtype=str, keep_default_na=False, quoting=csv.QUOTE_NONE,
                             chunksize=500_000, engine="c")
        for c in reader:
            n += len(c)
            c["ip"] = c["ip4"].where(c["ip4"] != "", c["ip6"])
            c = c[c["ip"] != ""]
            c["t"] = pd.to_numeric(c["t"], errors="coerce")
            g = c.groupby(["mac", "ip"])["t"].agg(["size", "min", "max"])
            for (mac, ip), (k, lo, hi) in g.iterrows():
                r = agg.get((norm_mac(mac), ip))
                if r is None:
                    if len(agg) >= ATT_IP_CAP:
                        over += int(k)
                        continue
                    agg[(norm_mac(mac), ip)] = [int(k), float(lo), float(hi)]
                else:
                    r[0] += int(k)
                    r[1], r[2] = min(r[1], float(lo)), max(r[2], float(hi))
        rc = proc.wait()
        errf.seek(0)
        err = "\n".join(l for l in errf.read().decode(errors="replace").splitlines()
                        if l.strip() != "resetting session.")
    if rc != 0:
        fatal(f"tshark exited {rc} on {pcap}: {err[-2000:]}")
    res = {"key": key, "packets": n, "overflow_packets": over, "cap": ATT_IP_CAP,
           "tshark_seconds": round(time.monotonic() - t0, 1),
           "pairs": sorted([[m, ip, k, lo, hi] for (m, ip), (k, lo, hi) in agg.items()],
                           key=lambda r: -r[2])}
    MAPS_DIR.mkdir(parents=True, exist_ok=True)
    m07a.write_json(out, res)
    log(f"  attacker IP pass: {n:,} packets, {len(agg):,} (mac, ip) pairs in {res['tshark_seconds']} s")
    return res


def attacker_ip_table(AI: dict, m: pd.DataFrame, roles: dict, names: dict) -> list[dict]:
    """Per attacker source IP: MACs, packets, scope, and how this pcap's map resolves it."""
    by_ip = defaultdict(list)
    for mac, ip, k, lo, hi in AI["pairs"]:
        by_ip[ip].append((mac, k, lo, hi))
    rows = []
    for ip, lst in sorted(by_ip.items(), key=lambda kv: -sum(x[1] for x in kv[1])):
        lo, hi = min(x[2] for x in lst), max(x[3] for x in lst)
        mr = m[m["ip"] == m04.norm_ip(ip)]
        is_att = np.array([ATTACKER_MACS.matches(x) for x in mr["mac"]], dtype=bool)
        att_rows, oth = mr.loc[is_att], mr.loc[~is_att]
        ovl = oth[(oth["first_seen_epoch"] - TOL <= hi) & (oth["last_seen_epoch"] + TOL >= lo)]
        own = att_rows[att_rows["mac"].isin([x[0] for x in lst])]
        covers = bool(((own["first_seen_epoch"] - TOL <= lo) & (own["last_seen_epoch"] + TOL >= hi)).any())
        a, why = m02.ip_scope(ip)
        rows.append({"ip": ip, "scope": "LAN" if why is None else why,
                     "attacker_macs": ";".join(x[0] for x in lst), "packets": sum(x[1] for x in lst),
                     "first_utc": utc(lo), "last_utc": utc(hi),
                     "map_macs": ";".join(f"{r.mac} ({names.get(r.mac, roles.get(r.mac, 'unlisted'))})"
                                          for r in mr.itertuples()) or "-",
                     "resolves_to_attacker": ("whole span" if covers else "partly" if len(own) else "no"),
                     "non_attacker_host_overlaps": ";".join(sorted(set(names.get(x, x) for x in ovl["mac"]))) or "-"})
    return rows


# --------------------------------------------------------------------------- chunked reading

def read_header(csv_path: Path) -> tuple[bytes, list[str]]:
    with open(csv_path, "rb") as fh:
        header = fh.readline()
    cols = next(csv.reader([header.decode("utf-8").rstrip("\r\n")]))
    return header, cols


def iter_chunks(csv_path: Path, chunk: int):
    """(offset, parsed PARSE_COLS frame indexed by global row, raw line bytes). Parsing the raw
    lines themselves keeps the frame aligned with what is copied to the output."""
    with open(csv_path, "rb") as fh:
        header = fh.readline()
        off = 0
        while True:
            lines = list(itertools.islice(fh, chunk))
            if not lines:
                break
            f = pd.read_csv(io.BytesIO(header + b"".join(lines)), usecols=PARSE_COLS, dtype=str,
                            keep_default_na=False, skip_blank_lines=False)
            if len(f) != len(lines):
                fatal(f"{csv_path}: parsed {len(f)} rows from {len(lines)} lines at row {off}")
            f.index = pd.RangeIndex(off, off + len(lines))
            yield off, f, lines
            off += len(lines)


def flow_time(ts: pd.Series) -> pd.Series:
    t = pd.to_datetime(ts, format=m04.TS_FORMAT, utc=True, errors="coerce")
    if t.isna().any():
        fatal(f"{int(t.isna().sum())} unparseable Timestamps, e.g. {ts[t.isna()].head(3).tolist()}")
    return ((t - pd.Timestamp(0, tz="UTC")) // pd.Timedelta(seconds=1)).astype("int64")


def conflict_rows(f: pd.DataFrame, t: pd.Series, s: pd.DataFrame, d: pd.DataFrame,
                  proto: pd.Series, amb: pd.Series) -> pd.DataFrame:
    """06c / 04's matching frame for the ambiguous flows."""
    return pd.DataFrame({"sip": s["ip"], "dip": d["ip"],
                         "sport": pd.to_numeric(f["Src Port"], errors="coerce"),
                         "dport": pd.to_numeric(f["Dst Port"], errors="coerce"),
                         "proto": proto, "lo": t - TOL,
                         "hi": t + pd.to_numeric(f["Flow Duration"], errors="coerce").fillna(0) / 1e6 + TOL,
                         "cside": np.where(s["role"] == "ambiguous", "src", "dst")}, index=f.index)[amb]


def resolve_conflicts(csv_path: Path, pcap: Path, m: pd.DataFrame, dev: pd.DataFrame,
                      conflicts: list[dict], bcast: set, chunk: int) -> dict:
    """Prescan (rows touching a conflict IP only), one tshark pass, chunked sender-MAC matching.
    Returns per-row results keyed by global row number."""
    res = {"one": pd.Series(dtype=object), "artifact": pd.Index([]), "both": pd.Index([]),
           "udp_keys": set(), "info": {"conflicts": len(conflicts), "ambiguous_on_conflict_ips": 0}}
    cips = {c["ip"] for c in conflicts}
    nip_cache: dict[str, str] = {}

    def nip(s: pd.Series) -> pd.Series:
        for u in pd.unique(s):
            if u not in nip_cache:
                nip_cache[u] = m04.norm_ip(u)
        return s.map(nip_cache)

    parts = []
    t0 = time.monotonic()
    for off, f, _ in iter_chunks(csv_path, chunk):
        u = f[f["Protocol"] == "17"]
        res["udp_keys"].update(u["Src IP"] + "|" + u["Src Port"] + "|" + u["Dst IP"] + "|" + u["Dst Port"])
        if not cips:
            continue
        hit = nip(f["Src IP"]).isin(cips) | nip(f["Dst IP"]).isin(cips)
        if not hit.any():
            continue
        g = f[hit]
        t = flow_time(g["Timestamp"])
        s = m04.resolve_side(g["Src IP"], t, m, dev, bcast, TOL)
        d = m04.resolve_side(g["Dst IP"], t, m, dev, bcast, TOL)
        amb = (s["role"] == "ambiguous") | (d["role"] == "ambiguous")
        if amb.any():
            parts.append(conflict_rows(g, t, s, d, pd.to_numeric(g["Protocol"], errors="coerce"), amb))
    fl = pd.concat(parts) if parts else pd.DataFrame(columns=["sip", "dip", "sport", "dport", "proto",
                                                              "lo", "hi", "cside"])
    res["info"]["ambiguous_on_conflict_ips"] = len(fl)
    res["info"]["prescan_seconds"] = round(time.monotonic() - t0, 1)
    res["info"]["udp_flow_keys"] = len(res["udp_keys"])
    log(f"  prescan: {len(fl):,} ambiguous flows on {len(cips)} conflict IP(s), "
        f"{len(res['udp_keys']):,} UDP flow keys ({res['info']['prescan_seconds']} s)")
    if fl.empty:
        return res
    for c in conflicts:                       # 04 / 06c tshark window
        on_ip = (fl["sip"] == c["ip"]) | (fl["dip"] == c["ip"])
        c["tshark_lo"] = min(c["overlap_start"] - m04.TSHARK_PAD_S,
                             float(fl.loc[on_ip, "lo"].min()) if on_ip.any() else float("inf"))
        c["tshark_hi"] = max(c["overlap_end"] + m04.TSHARK_PAD_S,
                             float(fl.loc[on_ip, "hi"].max()) if on_ip.any() else float("-inf"))
    v4 = [c for c in conflicts if ":" not in c["ip"]]
    pk, xinfo = m04.extract_conflict_packets(pcap, v4)
    fm = fl.dropna(subset=["sport", "dport", "proto"])
    macs, unreach = [], []
    for i in range(0, len(fm), chunk):
        mc, ua, _ = m04.match_packets_sender(pk, fm.iloc[i:i + chunk], v4)
        macs.append(mc)
        unreach.append(ua)
    macs = pd.concat(macs) if macs else pd.Series(dtype=object)
    unreach = pd.concat(unreach) if unreach else pd.Series(dtype=bool)
    one = macs[macs.str.len() == 1].str[0].sort_index()
    art = unreach.reindex(one.index).fillna(False).astype(bool)
    res.update({"one": one, "artifact": art[art].index.sort_values(),
                "both": macs[macs.str.len() > 1].index.sort_values()})
    res["info"].update({"packets_extracted": xinfo["packets_extracted"],
                        "tshark_seconds": xinfo["tshark_seconds"], "resolved_flows": len(one),
                        "both_macs_in_flow": len(res["both"]), "ip_clash_artifact": int(art.sum()),
                        "resolved_to": {k: int(v) for k, v in one.value_counts().items()}})
    return res


def in_range(idx: pd.Index | pd.Series, lo: int, hi: int):
    """Slice of a sorted index (or Series by its index) to global rows [lo, hi)."""
    ix = idx if isinstance(idx, pd.Index) else idx.index
    a, b = ix.searchsorted(lo, "left"), ix.searchsorted(hi, "left")
    return idx[a:b] if isinstance(idx, pd.Index) else idx.iloc[a:b]


def tag_chunk(f: pd.DataFrame, m: pd.DataFrame, dev: pd.DataFrame, bcast: set, R: dict,
              enabled: bool) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.DataFrame, pd.Series]:
    """06c.tag_flows on one chunk, with the pcap-wide conflict results R."""
    t = flow_time(f["Timestamp"])
    proto = pd.to_numeric(f["Protocol"], errors="coerce")
    s = m04.resolve_side(f["Src IP"], t, m, dev, bcast, TOL)
    d = m04.resolve_side(f["Dst IP"], t, m, dev, bcast, TOL)
    amb_mask = (s["role"] == "ambiguous") | (d["role"] == "ambiguous")
    resolution = pd.Series("ip_time", index=f.index)
    reason = pd.Series("", index=f.index)
    artifact = pd.Series(False, index=f.index)
    lo, hi = f.index[0], f.index[-1] + 1
    if enabled and amb_mask.any():
        one = in_range(R["one"], lo, hi)
        artifact[in_range(R["artifact"], lo, hi)] = True
        both = in_range(R["both"], lo, hi)
        for side in (s, d):
            rows = one.index[side.loc[one.index, "role"] == "ambiguous"]
            m04.set_device(side, rows, one.loc[rows], dev)
        resolution[amb_mask] = "unresolved"
        resolution[one.index] = "pcap_packet_mac"
        reason[amb_mask] = "no_packet_match"
        reason[both] = "both_macs_in_flow"
        reason[one.index] = ""
    elif amb_mask.any():
        resolution[amb_mask] = "unresolved"
        reason[amb_mask] = "not_attempted"
    own = m04.assign_owner(s, d, proto)
    exclude = pd.Series("", index=f.index)
    exclude[own["owner_status"] == "ambiguous"] = "ip_conflict_unresolved"
    exclude[own["owner_status"] == "invalid_parse"] = "invalid_parse"
    exclude[artifact] = "ip_clash_artifact"
    tags = pd.DataFrame({"src_mac": s["mac"], "src_device": s["device"], "src_role": s["role"],
                         "dst_mac": d["mac"], "dst_device": d["device"], "dst_role": d["role"],
                         **{c: own[c] for c in own.columns},
                         "owner_resolution": resolution, "ambiguous_reason": reason,
                         "exclude_reason": exclude})[m04.TAG_COLS]
    return tags, t, s, d, proto


# --------------------------------------------------------------------------- labelling

def overlap_idx(lo: np.ndarray, hi: np.ndarray, wins: list[tuple[float, float]], pad: float) -> np.ndarray:
    """Index of the first window [ws - pad, we + pad) that [lo, hi] overlaps, else -1. Windows are
    sorted and disjoint, so their padded ends are increasing."""
    if not wins:
        return np.full(len(lo), -1, dtype=np.int64)
    ws = np.array([w[0] for w in wins]) - pad
    we = np.array([w[1] for w in wins]) + pad
    i = np.searchsorted(we, lo, side="right")
    ic = np.minimum(i, len(ws) - 1)
    return np.where((i < len(ws)) & (ws[ic] <= hi), ic, -1)


class Labeller:
    def __init__(self, A: dict, family: str, pad: float, coll_ips: set[str], udp_keys: set[str],
                 att_ip_macs: dict[str, list[str]], m: pd.DataFrame):
        self.A, self.family, self.pad, self.coll_ips, self.udp_keys = A, family, pad, coll_ips, udp_keys
        self.att_cache: dict[str, bool] = {}
        self.att_ip_macs = att_ip_macs
        self.att_ips = pd.Index(list(att_ip_macs), dtype=object)
        self.k_max = min(max((len(v) for v in att_ip_macs.values()), default=0), T1B_MAX_MACS)
        self.nonatt = m.loc[~m["mac"].map(ATTACKER_MACS.matches), ["ip", "first_seen_epoch", "last_seen_epoch"]]

    def t1b_side(self, ips: pd.Series, t1: np.ndarray, lo: np.ndarray, hi: np.ndarray) -> np.ndarray:
        """Endpoint IP in the attacker IP set and held by no non-attacker MAC during the flow."""
        cand = ~t1 & ips.isin(self.att_ips).to_numpy()
        if not cand.any():
            return cand
        idx = np.flatnonzero(cand)
        q = pd.DataFrame({"ip": ips.to_numpy()[idx], "row": idx, "lo": lo[idx], "hi": hi[idx]})
        j = q.merge(self.nonatt, on="ip", how="inner")
        used = j.loc[(j["first_seen_epoch"] - TOL <= j["hi"]) & (j["last_seen_epoch"] + TOL >= j["lo"]), "row"]
        cand[used.unique()] = False
        return cand

    def best_orient(self, side: pd.DataFrame, other: pd.DataFrame, t1: np.ndarray, t1b: np.ndarray,
                    lo, hi, code, portless, sent, pseudo) -> dict:
        """orient() for this side; T1b endpoints are tried as each of their attacker MACs."""
        macs = side["mac"].to_numpy()
        best = self.orient(side["mac"], other["mac"], t1, lo, hi, code, portless, sent, pseudo)
        best["b"] = np.zeros(len(lo), dtype=bool)
        if not t1b.any():
            return best
        ips = side["ip"].to_numpy()
        for k in range(self.k_max):
            mk = np.array([(self.att_ip_macs[ip][k] if b and len(self.att_ip_macs[ip]) > k else "")
                           for ip, b in zip(ips, t1b)], dtype=object)
            use = mk != ""
            if not use.any():
                break
            amac = pd.Series(np.where(t1, macs, mk), dtype=object)
            R = self.orient(amac, other["mac"], t1 | use, lo, hi, code, portless, sent, pseudo)
            R["b"] = use & ~t1
            better = R["score"] > best["score"]
            for key in best:
                best[key] = np.where(better, R[key], best[key])
        return best

    def is_att(self, macs: pd.Series) -> np.ndarray:
        for u in pd.unique(macs):
            if u not in self.att_cache:
                self.att_cache[u] = bool(u) and ";" not in u and ATTACKER_MACS.matches(u)
        return macs.map(self.att_cache).to_numpy(dtype=bool)

    def orient(self, amac: pd.Series, omac: pd.Series, t1: np.ndarray, lo, hi, code, portless,
               sent: np.ndarray, icmp_pseudo: np.ndarray) -> dict:
        n = len(amac)
        t2, t2raw, t3, t4 = (np.zeros(n, dtype=bool) for _ in range(4))
        rate = np.zeros(n, dtype=bool)
        idx = np.flatnonzero(t1)
        if len(idx):
            a = amac.to_numpy()[idx]
            for mac in np.unique(a):
                sel = idx[a == mac]
                w = self.A["per_mac"].get(mac, [])
                t2[sel] = overlap_idx(lo[sel], hi[sel], w, self.pad) >= 0
                t2raw[sel] = overlap_idx(lo[sel], hi[sel], w, 0.0) >= 0
            key = pd.Series(a, dtype=object) + "|" + pd.Series(omac.to_numpy()[idx], dtype=object)
            vr = key.map(self.A["victim_pairs"])
            t3[idx] = vr.notna().to_numpy()
            rate[idx] = vr.fillna("").isin(["rate", "both"]).to_numpy()
            for k, pos in key.groupby(key).indices.items():
                rows = idx[pos]
                codes, pl, over, icmp = self.A["control"].get(k, (set(), False, False, False))
                if over:
                    known = np.ones(len(rows), dtype=bool)
                else:
                    known = np.where(icmp_pseudo[rows], icmp,
                                     np.where(portless[rows], pl, np.isin(code[rows], list(codes))))
                t4[rows] = ~(known | (sent[rows] == 0))
        level = t1.astype(int) + (t1 & t2) + (t1 & t2 & t3) + (t1 & t2 & t3 & t4)
        return {"t1": t1, "t2": t2, "t2raw": t2raw, "t3": t3, "t4": t4, "rate": rate,
                "level": level, "score": level * 2 + ((level == 3) & rate), "omac": omac.to_numpy()}

    def label(self, s: pd.DataFrame, d: pd.DataFrame, f: pd.DataFrame, t: pd.Series,
              proto: pd.Series) -> tuple[pd.DataFrame, dict]:
        lo = t.to_numpy(dtype=float)
        dur = pd.to_numeric(f["Flow Duration"], errors="coerce").fillna(0).to_numpy() / 1e6
        hi = lo + dur + TOL
        pr = proto.fillna(-1).to_numpy().astype(np.int64)
        sp = pd.to_numeric(f["Src Port"], errors="coerce").to_numpy()
        dp = pd.to_numeric(f["Dst Port"], errors="coerce").to_numpy()
        svc = np.fmin(sp, dp)
        portless = ~np.isin(pr, PORT_PROTOS)
        code = np.where(portless | np.isnan(svc), -1, pr * SVC_BASE + np.nan_to_num(svc, nan=0)).astype(np.int64)
        att_s, att_d = self.is_att(s["mac"]), self.is_att(d["mac"])
        fwd = pd.to_numeric(f["Total Fwd Packet"], errors="coerce").fillna(0).to_numpy()
        bwd = pd.to_numeric(f["Total Bwd packets"], errors="coerce").fillna(0).to_numpy()
        b_s = self.t1b_side(s["ip"], att_s, lo, hi)
        b_d = self.t1b_side(d["ip"], att_d, lo, hi)
        # ICMP-error pseudo-flow sent by the Src side: a UDP flow with a mirror (IPs swapped)
        pseudo = np.zeros(len(lo), dtype=bool)
        cand = (pr == 17) & (att_s | b_s)
        if cand.any() and self.udp_keys:
            g = f[cand]
            mk = g["Dst IP"] + "|" + g["Src Port"] + "|" + g["Src IP"] + "|" + g["Dst Port"]
            pseudo[np.flatnonzero(cand)] = mk.isin(self.udp_keys).to_numpy()
        S = self.best_orient(s, d, att_s, b_s, lo, hi, code, portless, fwd, pseudo)
        D = self.best_orient(d, s, att_d, b_d, lo, hi, code, portless, bwd, np.zeros(len(lo), dtype=bool))
        use_s = S["score"] >= D["score"]
        pick = {k: np.where(use_s, S[k], D[k])
                for k in ("t1", "t2", "t2raw", "t3", "t4", "rate", "level", "omac", "b")}
        via_b = pick["b"] & pick["t1"]
        lvl = pick["level"]
        burst_any = overlap_idx(lo, hi, self.A["overall"], self.pad)
        vm = self.A["victim_macs"]
        smac, dmac = s["mac"].to_numpy(), d["mac"].to_numpy()
        spoof = np.zeros(len(lo), dtype=bool)
        if self.coll_ips:
            sip, dip = s["ip"].isin(self.coll_ips).to_numpy(), d["ip"].isin(self.coll_ips).to_numpy()
            spoof_raw = ((burst_any >= 0)
                         & ((sip & pd.Series(dmac).isin(vm).to_numpy()) | (dip & pd.Series(smac).isin(vm).to_numpy())))
            spoof = (lvl == 0) & spoof_raw
        else:
            spoof_raw = spoof
        # victim side still ambiguous after conflict resolution ("a;b" candidates, 04's
        # ip_conflict_unresolved): T3 cannot be decided, which is not normal traffic
        vamb = pd.Series(pick["omac"], dtype=object).str.contains(";", regex=False).to_numpy()
        reason = np.select([spoof, lvl == 1, (lvl == 2) & vamb, lvl == 2, (lvl == 3) & pick["rate"], lvl == 3],
                           ["spoof_collision", "attacker_offwindow", "victim_ambiguous",
                            "attacker_normal_traffic", "attack_normal_service_ambiguous",
                            "attacker_normal_traffic"], "")
        label = np.where(lvl == 4, "attack", np.where(reason != "", "excluded", "benign"))
        tcode = (pick["t1"] * 1 + (pick["t1"] & pick["t2"]) * 2 + (pick["t1"] & pick["t3"]) * 4
                 + (pick["t1"] & pick["t4"]) * 8)
        pad_only = (lvl >= 2) & pick["t2"] & ~pick["t2raw"]
        out = pd.DataFrame({"label": label,
                            "attack_family": np.where(label == "attack", self.family, ""),
                            "label_tests": [("T1b" + TESTS[c][2:]) if b else TESTS[c]
                                            for c, b in zip(tcode, via_b)],
                            "label_exclude_reason": reason, "pad_only": pad_only}, index=f.index)
        extra = {"victim": np.where(label == "attack", pick["omac"], ""), "burst_any": burst_any,
                 "icmp_pseudo": pseudo & use_s & pick["t1"],
                 "via_t1b": via_b,
                 "without_t1b": np.where(spoof_raw, "excluded:spoof_collision", "benign"),
                 "no_attacker_packets": pick["t1"] & (np.where(use_s, fwd, bwd) == 0),
                 "minute": (t.to_numpy() // 60), "smac": smac, "dmac": dmac}
        return out, extra


# --------------------------------------------------------------------------- per-pcap run

class GzOut:
    """gzip writer: pigz when available (parallel), else the gzip module."""

    def __init__(self, path: Path):
        self.path, self.tmp = path, path.with_name(path.name + ".tmp")
        self.proc = None
        if shutil.which("pigz"):
            self.fh = open(self.tmp, "wb")
            self.proc = subprocess.Popen(["pigz", "-c", "-6", "-p", str(max(os.cpu_count() or 2, 2))],
                                         stdin=subprocess.PIPE, stdout=self.fh)
            self.w = self.proc.stdin
        else:
            self.w = gzip.open(self.tmp, "wb", compresslevel=6)

    def write(self, b: bytes) -> None:
        self.w.write(b)

    def close(self) -> None:
        self.w.close()
        if self.proc is not None:
            rc = self.proc.wait()
            self.fh.close()
            if rc != 0:
                fatal(f"pigz exited {rc} writing {self.tmp}")
        self.tmp.replace(self.path)


def collision_ips(map_csv: Path, roles: dict[str, str]) -> set[str]:
    """Attacker source IPs that are also real smart-home device IPs in this pcap's map: an
    attacker MAC has ip.src evidence for the IP and a role-iot MAC also owns it."""
    mp = pd.read_csv(map_csv, dtype={"ip": str, "mac": str}, keep_default_na=False)
    mp["mac"] = mp["mac"].map(norm_mac)
    att = mp[mp["mac"].map(ATTACKER_MACS.matches) & (pd.to_numeric(mp["evidence_src"]) > 0)]
    iot = set(mp.loc[mp["mac"].map(roles).eq("iot"), "ip"])
    return set(att["ip"]) & iot


def benign_shares() -> dict[str, float] | None:
    if not BENIGN_TAGGED.is_file():
        return None
    b = pd.read_csv(BENIGN_TAGGED, usecols=["owner_mac", "owner_status"], dtype=str, keep_default_na=False)
    b = b[b["owner_status"] == "owned"]["owner_mac"].value_counts()
    return (b / b.sum()).to_dict()


def run_pcap(item: dict, args, dev: pd.DataFrame, d02: pd.DataFrame, dev_sha: str, devtab: pd.DataFrame,
             benign_share_fn) -> dict:
    t_start = time.monotonic()
    pcap, family, stem = item["pcap"], item["family"], item["pcap"].stem
    pcap_sha = sha256(pcap, pcap.name)
    if item.get("sha256") and item["sha256"] != pcap_sha:
        fatal(f"{pcap}: sha256 {pcap_sha} != attack_set.json {item['sha256']}")
    A = load_07a(args.coverage_dir, stem, pcap_sha, dev_sha)
    P = A["P"]
    key = {"pcap_sha256": pcap_sha, "device_table_sha256": dev_sha, "stats07a_sha256": A["stats_sha256"],
           "pad_s": args.pad_s, "rate_k": P["params"]["rate_k"],
           "min_new_services": P["params"]["min_new_services"], "attack_family": family,
           "label_version": LABEL_VERSION, "code_sha256": CODE_SHA256,
           "jar_sha256": EXTRACTOR.jar_sha256}
    fdir = args.flows_dir / stem
    out_gz = fdir / f"{stem}_labelled.csv.gz"
    rpath = args.out_dir / f"{stem}_label_report.json"
    if args.skip_done and rpath.is_file() and out_gz.is_file():
        old = json.loads(rpath.read_text(encoding="utf-8"))
        if old.get("completion_key") == key:
            log(f"  --skip-done: {rpath.name} matches the completion key; skipped")
            old["_skipped"] = True
            return old
        log(f"  --skip-done: key differs in {m07a.stale_keys(old.get('completion_key', {}), key)}; re-running")

    log("[1] flows")
    flows_csv, finfo = m06c.extract_flows(pcap, pcap_sha, fdir)
    chk = m06c.check_flows(flows_csv, pcap, args.out_dir / "flow_check")
    log("[2] IP->MAC map from this pcap (02)")
    map_csv, minfo = get_map(pcap, pcap_sha, dev_sha, d02)
    log("[3-4] tag (04, chunked) + label")
    header, cols = read_header(flows_csv)
    if len(cols) != m04.EXPECTED_FLOW_COLS:
        fatal(f"expected {m04.EXPECTED_FLOW_COLS} flow columns, found {len(cols)}")
    if (set(m04.TAG_COLS) | set(LABEL_COLS)) & set(cols):
        fatal("flows already contain tag / label columns")
    bcast = {ipa.ip_network(s).broadcast_address for s in NETWORK.subnets}
    bcast.add(ipa.IPv4Address("169.254.255.255"))
    m = m04.load_map(map_csv)
    conflicts = m04.find_conflicts(m, dev)
    R = resolve_conflicts(flows_csv, pcap, m, dev, conflicts, bcast, args.chunk)
    roles = dict(zip(dev["mac"], dev["role"]))
    names = dict(zip(dev["mac"], dev["device_name"]))
    groups = dict(zip(devtab["mac"], devtab["behaviour_group"]))
    gw_mac = dev.loc[dev["role"] == "gateway", "mac"].iloc[0]
    AI = attacker_ips(pcap, pcap_sha)
    # T1b uses unicast addresses only (04's ip_class lan / external): 0.0.0.0, ::, multicast and
    # broadcast are shared by every host (DHCP, mDNS, ...) and never identify the attacker
    att_ip_macs = defaultdict(list)
    for mac, ip, k, lo, hi in AI["pairs"]:                  # sorted by packets, descending
        nip = m04.norm_ip(ip)
        if m04.ip_class(nip, bcast) in ("lan", "external"):
            att_ip_macs[nip].append(mac)
    ip_tbl = attacker_ip_table(AI, m, roles, names)
    for r in ip_tbl:
        r["used_for_T1b"] = m04.norm_ip(r["ip"]) in att_ip_macs
    iot_ips = set(m.loc[m["mac"].map(roles).eq("iot"), "ip"])
    coll = (set(att_ip_macs) & iot_ips) | collision_ips(map_csv, roles)
    L = Labeller(A, family, args.pad_s, coll, R["udp_keys"], dict(att_ip_macs), m)

    C = defaultdict(Counter)
    n_rows = 0
    hard = Counter()
    fdir.mkdir(parents=True, exist_ok=True)
    w = GzOut(out_gz)
    w.write(header.rstrip(b"\r\n") + b"," + ",".join(m04.TAG_COLS + LABEL_COLS).encode() + b"\n")
    t0 = time.monotonic()
    for off, f, lines in iter_chunks(flows_csv, args.chunk):
        tags, t, s, d, proto = tag_chunk(f, m, dev, bcast, R, bool(conflicts))
        lab, ex = L.label(s, d, f, t, proto)
        part = pd.concat([tags, lab], axis=1).to_csv(index=False, header=False, lineterminator="\n")
        tl = part.encode("utf-8").split(b"\n")[:-1]
        if len(tl) != len(lines):
            fatal(f"tag lines {len(tl)} != flow lines {len(lines)} at row {off}")
        w.write(b"".join(l.rstrip(b"\r\n") + b"," + x + b"\n" for l, x in zip(lines, tl)))
        n_rows += len(lines)

        # ---- accumulate
        lb, rs = lab["label"], lab["label_exclude_reason"]
        is_att = (lb == "attack").to_numpy()
        C["label"].update(lb.value_counts().to_dict())
        C["reason"].update(rs[rs != ""].value_counts().to_dict())
        C["family"].update(lab.loc[is_att, "attack_family"].value_counts().to_dict())
        og = np.where(tags["owner_status"] != "owned", "unowned",
                      tags["owner_mac"].map(groups).fillna("").replace("", "ungrouped"))
        C["group_label"].update(pd.Series(list(zip(og, lb))).value_counts().to_dict())
        C["ex04_label"].update(pd.Series(list(zip(tags["exclude_reason"].replace("", "(blank)"), lb)))
                               .value_counts().to_dict())
        C["minute_label"].update(pd.Series(list(zip(ex["minute"], lb))).value_counts().to_dict())
        vic = ex["victim"][is_att]
        C["victim"].update(pd.Series(vic).value_counts().to_dict())
        C["burst"].update(pd.Series(ex["burst_any"][is_att]).value_counts().to_dict())
        C["pad_only"]["attack"] += int((lab["pad_only"] & is_att).sum())
        C["pad_only"]["all"] += int(lab["pad_only"].sum())
        C["t4_mapping"]["icmp_error_pseudo_flows"] += int(ex["icmp_pseudo"].sum())
        vb = ex["via_t1b"]
        if vb.any():
            lr = (lb + ":" + rs).str.rstrip(":").to_numpy()
            C["t1b_after"].update(pd.Series(lr[vb]).value_counts().to_dict())
            C["t1b_before"].update(pd.Series(ex["without_t1b"][vb]).value_counts().to_dict())
        C["t4_mapping"]["attacker_sent_no_packets"] += int(ex["no_attacker_packets"].sum())
        C["victim_role"].update(pd.Series(vic).map(roles).fillna("unlisted").value_counts().to_dict())
        ben = (lb == "benign").to_numpy()
        C["benign_owned"].update(tags.loc[ben & (tags["owner_status"] == "owned").to_numpy(), "owner_mac"]
                                 .value_counts().to_dict())
        # diagnostic: benign flows inside a burst with a 07a victim on one side
        vm = A["victim_macs"]
        sv, dv = pd.Series(ex["smac"]).isin(vm).to_numpy(), pd.Series(ex["dmac"]).isin(vm).to_numpy()
        bb = ben & (ex["burst_any"] >= 0) & (sv | dv)
        if bb.any():
            other_role = np.where(sv, d["role"].to_numpy(), s["role"].to_numpy())[bb]
            C["benign_burst_victim"].update(pd.Series(other_role).value_counts().to_dict())
        # hard checks
        hard["attack_outside_burst"] += int((is_att & (ex["burst_any"] < 0)).sum())
        hard["attack_victim_not_07a"] += int((~pd.Series(vic).isin(vm)).sum())
        ok = (lb.isin(LABELS) & ((lb == "excluded") == (rs != ""))
              & ((lb == "attack") == (lab["attack_family"] != "")))
        hard["bad_outcome"] += int((~ok).sum())
        log(f"    {n_rows:>11,} flows  {time.monotonic() - t0:7.1f} s  attack {C['label']['attack']:,}  "
            f"excluded {C['label']['excluded']:,}  benign {C['label']['benign']:,}")
    w.close()

    meta_rows = finfo["meta"].get("row_count")
    hard_checks = {
        "attack flows outside 07a burst windows (+pad)": (hard["attack_outside_burst"], hard["attack_outside_burst"] == 0),
        "attack flows whose victim is not a 07a victim": (hard["attack_victim_not_07a"], hard["attack_victim_not_07a"] == 0),
        "flows without exactly one outcome": (hard["bad_outcome"], hard["bad_outcome"] == 0),
        "rows written == flow CSV rows == meta row_count": (f"{n_rows:,} / {meta_rows if meta_rows is None else f'{meta_rows:,}'}",
                                                             meta_rows is None or n_rows == meta_rows),
        "label counts sum to rows": (sum(C["label"].values()), sum(C["label"].values()) == n_rows),
    }

    # ---- soft checks
    v_ok, _ = m07a.verdicts(P, args.min_victims)
    by_g = Counter(groups.get(v, "") or roles.get(v, "unlisted") for v in C["victim"])
    cover07 = {c["group"]: c["n_victims"] for c in P["cover"]}
    soft_groups = []
    for g in ("G1", "G2", "GEN"):
        n = by_g.get(g, 0)
        mine = "PASS" if n >= args.min_victims else "FAIL"
        soft_groups.append({"group": g, "victims_with_attack_flows": n, "07a_victims": cover07.get(g, 0),
                            "07a_verdict": v_ok[g], "verdict": mine,
                            "match": "ok" if (v_ok[g] != "PASS" or mine == "PASS") else "MISMATCH"})
    shares = benign_share_fn()
    share_rows = []
    tot_b = sum(C["benign_owned"].values())
    if shares is not None and tot_b:
        for mac in set(C["benign_owned"]) | {k for k, v in shares.items() if v > 0.01}:
            here = C["benign_owned"].get(mac, 0) / tot_b
            share_rows.append({"device": names.get(mac, mac), "group": groups.get(mac, ""),
                               "benign_flows_here": C["benign_owned"].get(mac, 0),
                               "share_here_pct": round(100 * here, 2),
                               "share_benign_capture_pct": round(100 * shares.get(mac, 0.0), 2),
                               "diff_pp": round(100 * (here - shares.get(mac, 0.0)), 2)})
        share_rows.sort(key=lambda r: -abs(r["diff_pp"]))
    spoof07 = P["spoof"]
    rss = m07a.peak_rss()
    victims_tbl = []
    vinfo = {norm_mac(r["mac"]): r for r in A["victims"].to_dict("records")}
    for mac, n in C["victim"].most_common():
        r = vinfo.get(mac, {})
        victims_tbl.append({"mac": mac, "device": names.get(mac, r.get("device", "?")),
                            "group": groups.get(mac, "") or r.get("group", ""), "role": roles.get(mac, "unlisted"),
                            "attack_flows": n, "07a_reason": r.get("reason", ""),
                            "07a_attack_packets": int(r.get("attack_packets", 0) or 0)})
    burst_tbl = []
    for i, (blo, bhi) in enumerate(A["overall"]):
        b = P["bursts"][i]
        burst_tbl.append({"window": i, "start": b["start"], "end": b["end"], "07a_packets": b["packets"],
                          "attack_flows": C["burst"].get(i, 0)})
    R_ = {
        "stem": stem, "pcap": str(pcap), "family": family, "completion_key": key,
        "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "params": {"pad_s": args.pad_s, "chunk": args.chunk, "min_victims": args.min_victims,
                   "tolerance_s": TOL, "07a_params": P["params"]},
        "inputs": {"flows_csv": str(flows_csv), "flows": finfo["action"], "check_03b": chk,
                   "map": {**minfo, "csv": str(map_csv)}, "stats07a": str(A["stats_path"]),
                   "labelled_csv": str(out_gz)},
        "conflicts": R["info"],
        "attacker_ip_set": {
            "distinct_ips": len(ip_tbl), "lan": sum(r["scope"] == "LAN" for r in ip_tbl),
            "used_for_t1b": len(att_ip_macs),
            "external_or_other": sum(r["scope"] != "LAN" for r in ip_tbl),
            "packets": AI["packets"], "overflow_packets": AI["overflow_packets"],
            "tshark_seconds": AI["tshark_seconds"], "ips": ip_tbl[:50]},
        "t1b": {"flows_via_t1b_only": sum(C["t1b_after"].values()),
                "after": dict(C["t1b_after"]), "before_without_t1b": dict(C["t1b_before"])},
        "spoof": {"collision_ips": sorted(coll), "07a_collide_with_device_ips": spoof07["collide_with_device_ips"],
                  "07a_distinct_ip_src": spoof07["distinct_ip_src"], "07a_flag": spoof07["flag"]},
        "bursts": {"overall": len(A["overall"]),
                   "per_mac": {mac: [(utc(a), utc(b)) for a, b in w_] for mac, w_ in A["per_mac"].items() if w_}},
        "flows": n_rows,
        "by_label": {k: C["label"].get(k, 0) for k in LABELS},
        "by_exclude_reason": {k: C["reason"].get(k, 0) for k in REASONS},
        "by_family": dict(C["family"]),
        "by_owner_group": {g: {l: C["group_label"].get((g, l), 0) for l in LABELS} for g in GROUPS_OUT},
        "by_04_exclude_reason": [{"exclude_reason": a, "label": b, "flows": n}
                                 for (a, b), n in sorted(C["ex04_label"].items())],
        "attack_per_victim": victims_tbl, "attack_per_burst": burst_tbl,
        "pad_only": dict(C["pad_only"]),
        "t4_flow_mapping": dict(C["t4_mapping"]),
        "attack_victim_roles": dict(C["victim_role"]),
        "gateway_victim_attack_flows": C["victim"].get(gw_mac, 0),
        "non_iot_victim_attack_flows": sum(n for r, n in C["victim_role"].items() if r != "iot"),
        "hard_checks": {k: {"value": v, "PASS": bool(ok)} for k, (v, ok) in hard_checks.items()},
        "hard_pass": all(ok for _, ok in hard_checks.values()),
        "soft": {"groups_vs_07a": soft_groups,
                 "attack_flows_per_07a_attacker_packet": round(C["label"].get("attack", 0) / P["S"]["att_src"], 6)
                 if P["S"]["att_src"] else None,
                 "07a_attacker_packets": P["S"]["att_src"],
                 "benign_share_vs_benign_capture": share_rows[:15],
                 "benign_in_burst_touching_victim_by_other_role": dict(C["benign_burst_victim"])},
        "runtime_s": round(time.monotonic() - t_start, 1), "peak_rss": rss,
    }
    png = args.out_dir / f"{stem}_timeline.png"
    plot_timeline(stem, C["minute_label"], A["overall"], args.pad_s, png)
    R_["png"] = png.name
    write_report(args.out_dir, R_)
    return R_


# --------------------------------------------------------------------------- outputs

def plot_timeline(stem: str, ml: Counter, overall: list, pad: float, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    if not ml:
        return
    mins = sorted({int(m) for m, _ in ml})
    # segments: flow minutes split by gaps > 30 min, so multi-day captures stay readable
    segs, cur = [], [mins[0], mins[0]]
    for x in mins[1:]:
        if x - cur[1] > 30:
            segs.append(cur)
            cur = [x, x]
        else:
            cur[1] = x
    segs.append(cur)
    tot = {tuple(s): sum(n for (m, _), n in ml.items() if s[0] <= m <= s[1]) for s in segs}
    segs = sorted(sorted(segs, key=lambda s: -tot[tuple(s)])[:6])
    widths = [max(s[1] - s[0] + 1, 20) for s in segs]
    fig, axes = plt.subplots(1, len(segs), figsize=(10, 3.4), sharey=True, facecolor=SURFACE,
                             gridspec_kw={"width_ratios": widths, "wspace": 0.06}, squeeze=False)
    order = ["benign", "excluded", "attack"]
    for ax, (a, b) in zip(axes[0], segs):
        ax.set_facecolor(SURFACE)
        xs = list(range(a, b + 1))
        x = [dt.datetime.fromtimestamp(m * 60, tz=dt.timezone.utc) for m in xs] + \
            [dt.datetime.fromtimestamp((b + 1) * 60, tz=dt.timezone.utc)]
        for lo, hi in overall:
            if hi >= a * 60 and lo <= (b + 1) * 60:
                ax.axvspan(dt.datetime.fromtimestamp(lo, tz=dt.timezone.utc),
                           dt.datetime.fromtimestamp(hi, tz=dt.timezone.utc), color=BURST_FILL, lw=0, zorder=0)
        base = np.zeros(len(xs))
        for lab in order:
            y = np.array([ml.get((m, lab), 0) for m in xs], dtype=float)
            ax.stairs(base + y, x, baseline=base, fill=True, color=COLOR[lab], lw=0, zorder=2,
                      label=lab if ax is axes[0][0] else None)
            base = base + y
        ax.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=2, maxticks=4))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d\n%H:%M", tz=dt.timezone.utc))
        ax.grid(axis="y", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        for sp in ("left", "bottom"):
            ax.spines[sp].set_color(GRID)
        ax.tick_params(colors=TEXT2, labelsize=7)
    axes[0][0].set_ylabel("flows / minute", color=TEXT2, fontsize=9)
    h, l = axes[0][0].get_legend_handles_labels()
    import matplotlib.patches as mpatches
    h.append(mpatches.Patch(color=BURST_FILL))
    l.append("07a burst window")
    fig.legend(h[::-1][1:] + [h[-1]], l[::-1][1:] + [l[-1]], loc="upper right", frameon=False, fontsize=8,
               ncol=4, labelcolor=TEXT2)
    fig.suptitle(f"Flows per minute by label — {stem}" + (" (busiest segments)" if len(segs) > 1 else ""),
                 x=0.01, ha="left", color=TEXT1, fontsize=10)
    fig.text(0.01, 0.01, f"time (UTC); bursts shaded unpadded (labelling pad ±{pad:g} s)",
             color=TEXT2, fontsize=7)
    fig.subplots_adjust(left=0.08, right=0.99, top=0.82, bottom=0.2)
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def kv_rows(d: dict, k: str = "value", v: str = "flows") -> list[dict]:
    return [{k: a, v: b} for a, b in d.items()]


def write_report(out: Path, R: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    jpath = out / f"{R['stem']}_label_report.json"
    mpath = out / f"{R['stem']}_label_report.md"
    n = R["flows"]
    L = [f"# Step 7 -- attack labels: {R['stem']} ({R['family']})", "",
         f"- pcap `{R['pcap']}`; run {R['run_utc']}; runtime {R['runtime_s']} s; peak RSS python "
         f"{R['peak_rss']['self_mb']:,} MB, largest child {R['peak_rss']['tshark_mb']:,} MB",
         f"- flows `{R['inputs']['flows_csv']}` ({R['inputs']['flows']}); 03b **{R['inputs']['check_03b']['overall']}**",
         f"- map `{R['inputs']['map']['csv']}` ({R['inputs']['map']['action']}, {R['inputs']['map']['rows']} rows, "
         f"{R['inputs']['map']['ip_conflicts_overlapping']} overlapping IP conflicts); conflict resolution {R['conflicts']}",
         f"- 07a stats `{R['inputs']['stats07a']}`; pad ±{R['params']['pad_s']:g} s; K {R['params']['07a_params']['rate_k']:g}",
         f"- labelled CSV `{R['inputs']['labelled_csv']}`; timeline `{R.get('png', '')}`",
         f"- spoof: collision IPs {R['spoof']['collision_ips'] or 'none'} (07a: {R['spoof']['07a_collide_with_device_ips']} "
         f"device-IP collisions, {R['spoof']['07a_distinct_ip_src']} distinct attacker ip.src)", "",
         f"## Hard checks: **{'PASS' if R['hard_pass'] else 'FAIL'}**", ""]
    L += md_table([{"check": k, "value": v["value"], "result": "PASS" if v["PASS"] else "FAIL"}
                   for k, v in R["hard_checks"].items()], ["check", "value", "result"])
    AS, TB = R["attacker_ip_set"], R["t1b"]
    L += ["", f"## Attacker IP set (T1b): {AS['distinct_ips']} IPs ({AS['lan']} LAN, "
          f"{AS['external_or_other']} external / other; {AS['used_for_t1b']} unicast used for T1b) from "
          f"{AS['packets']:,} attacker-MAC packets"
          + (f"; **{AS['overflow_packets']:,} packets over the {ATT_IP_CAP:,}-pair cap**" if AS["overflow_packets"] else ""), ""]
    L += md_table(AS["ips"], ["ip", "scope", "used_for_T1b", "attacker_macs", "packets", "resolves_to_attacker",
                              "non_attacker_host_overlaps", "map_macs", "first_utc", "last_utc"])
    after_all = Counter()
    for k, v in R["by_label"].items():
        if k != "excluded":
            after_all[k] = v
    for k, v in R["by_exclude_reason"].items():
        after_all[f"excluded:{k}"] = v
    before = Counter(after_all)
    for k, v in TB["after"].items():
        before[k] -= v
    for k, v in TB["before_without_t1b"].items():
        before[k] += v
    L += ["", f"### Flows passing T1 only via T1b: {TB['flows_via_t1b_only']:,}", ""]
    L += md_table([{"outcome": k, "without_T1b": before.get(k, 0), "with_T1b": after_all.get(k, 0)}
                   for k in sorted(set(before) | set(after_all))], ["outcome", "without_T1b", "with_T1b"])
    L += ["", f"## Labels ({n:,} flows)", ""]
    L += md_table([{"label": k, "flows": v, "pct": m02.pct(v, n)} for k, v in R["by_label"].items()],
                  ["label", "flows", "pct"])
    L += ["", "### Excluded by reason", ""] + md_table(kv_rows(R["by_exclude_reason"], "reason"), ["reason", "flows"])
    L += ["", f"- attack by family: {R['by_family'] or 'none'}",
          f"- pad_only: {R['pad_only'].get('attack', 0):,} attack flows ({R['pad_only'].get('all', 0):,} flows "
          "overall) pass T2 only thanks to the padding",
          f"- T4 flow mapping (attacker-MAC flows): {R.get('t4_flow_mapping', {})}",
          f"- **gateway-victim attack flows: {R['gateway_victim_attack_flows']:,}** (unowned; non-iot victims "
          f"total {R['non_iot_victim_attack_flows']:,}: {R['attack_victim_roles']})", "",
          "### By owner group (04 ownership)", ""]
    L += md_table([{"group": g, **v} for g, v in R["by_owner_group"].items()], ["group"] + LABELS)
    L += ["", "### 04 exclude_reason x label", ""]
    L += md_table(R["by_04_exclude_reason"], ["exclude_reason", "label", "flows"])
    L += ["", "### Attack flows per victim device", ""]
    L += md_table(R["attack_per_victim"], ["device", "group", "role", "mac", "attack_flows", "07a_reason",
                                           "07a_attack_packets"])
    L += ["", "### Attack flows per 07a burst window", ""]
    L += md_table(R["attack_per_burst"], ["window", "start", "end", "07a_packets", "attack_flows"])
    S = R["soft"]
    L += ["", "## Soft checks", "", "### Victim groups vs 07a coverage", ""]
    L += md_table(S["groups_vs_07a"], ["group", "victims_with_attack_flows", "07a_victims", "07a_verdict",
                                       "verdict", "match"])
    L += ["", f"- attack flows / 07a attacker packets: {S['attack_flows_per_07a_attacker_packet']} "
          f"({R['by_label']['attack']:,} / {S['07a_attacker_packets']:,})",
          f"- benign flows inside a burst with a 07a victim on one side, by the other side's role: "
          f"{S['benign_in_burst_touching_victim_by_other_role'] or 'none'} (external / lan_unmapped here would "
          "be spoofed attack traffic that T1 cannot see)", "",
          "### Benign owned-flow share per device vs the benign capture (largest differences)", ""]
    L += md_table(S["benign_share_vs_benign_capture"], ["device", "group", "benign_flows_here", "share_here_pct",
                                                        "share_benign_capture_pct", "diff_pp"])
    L += ["", "### Per-attacker-MAC burst windows used for T2 (07a, anchored)", ""]
    L += [f"- {mac}: " + "; ".join(f"{a[11:19]}-{b[11:19]} ({a[:10]})" for a, b in w)
          for mac, w in R["bursts"]["per_mac"].items()] or ["_none_"]
    mpath.write_text("\n".join(L) + "\n", encoding="utf-8")
    m07a.write_json(jpath, R)          # completion marker: written last


def rebuild_summary(out: Path) -> list[dict]:
    rows = []
    for f in sorted(out.glob("*_label_report.json")):
        try:
            R = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        g = R["by_owner_group"]
        rows.append({"pcap": R["stem"], "family": R["family"], "flows": R["flows"],
                     **{k: R["by_label"][k] for k in LABELS},
                     **{k: R["by_exclude_reason"].get(k, 0) for k in REASONS},
                     **{f"attack_{k}": g[k]["attack"] for k in GROUPS_OUT},
                     "gateway_victim_attack": R["gateway_victim_attack_flows"],
                     "pad_only_attack": R["pad_only"].get("attack", 0),
                     "attacker_ips": R.get("attacker_ip_set", {}).get("distinct_ips", ""),
                     "t1b_only_flows": R.get("t1b", {}).get("flows_via_t1b_only", ""),
                     "victims": len(R["attack_per_victim"]),
                     "groups_vs_07a": " ".join(f"{x['group']}:{x['verdict']}/{x['07a_verdict']}"
                                               for x in R["soft"]["groups_vs_07a"]),
                     "hard": "PASS" if R["hard_pass"] else "FAIL", "runtime_s": R["runtime_s"],
                     "peak_rss_mb": max(R["peak_rss"].values()), "run_utc": R["run_utc"]})
    if rows:
        m07a.write_csv(out / "label_summary.csv", rows, list(rows[0].keys()))
        L = ["# Step 7 -- attack label summary", "",
             f"- rebuilt {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')} from "
             f"{len(rows)} report(s) in `{out}`", ""]
        L += md_table(rows, list(rows[0].keys()))
        (out / "label_summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    return rows


# --------------------------------------------------------------------------- main

RUN_LOCK = ".07_label.lock"


def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.07_label.lock, held for the whole run (the kernel
    releases it on exit, so a crash leaves no stale lock). Concurrent 07 runs on the same dirs
    each start their own cfm on the same pcap; every start deletes the CSV the others write
    (NPE in InsertCsvRow.insert) and together they exhaust memory."""
    d.mkdir(parents=True, exist_ok=True)
    path = d / RUN_LOCK
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another 07_label_attacks.py run is using {d} (lock {path} held by: {holder}); "
              "refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}"
             f" argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pcap-set", type=Path, default=ATTACK_SET)
    ap.add_argument("--pcap", type=Path, nargs="+", default=None,
                    help="label these pcaps instead of the set (family from the set by SHA256 / "
                         "stem, else --family)")
    ap.add_argument("--family", default=None, help="attack_family for --pcap files not in the set")
    ap.add_argument("--pad-s", type=float, default=60.0)
    ap.add_argument("--min-victims", type=int, default=2, help="for the soft 07a coverage comparison")
    ap.add_argument("--chunk", type=int, default=500_000)
    ap.add_argument("--coverage-dir", type=Path, default=COVERAGE_DIR, help="07a outputs")
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--flows-dir", type=Path, default=ATTACK_FLOWS_DIR)
    ap.add_argument("--skip-done", action="store_true")
    args = ap.parse_args()
    t0 = time.monotonic()
    args.out_dir = args.out_dir if args.out_dir.is_absolute() else REPO_ROOT / args.out_dir
    args.coverage_dir = args.coverage_dir if args.coverage_dir.is_absolute() else REPO_ROOT / args.coverage_dir
    if args.out_dir.resolve().is_relative_to(CONFIG_DIR.resolve()):
        fatal("--out-dir must not be under config/")
    if args.pad_s < 0 or args.chunk < 1000:
        fatal("--pad-s must be >= 0 and --chunk >= 1000")
    for tool in ("tshark",):
        if shutil.which(tool) is None:
            fatal(f"{tool} not found on PATH")
    # One 07 run at a time on these dirs; the handles stay open until the process exits.
    run_locks = [run_lock(d) for d in dict.fromkeys([args.out_dir.resolve(), args.flows_dir.resolve()])]

    aset = load_attack_set(args.pcap_set)
    if args.pcap:
        items = []
        for p in args.pcap:
            if not p.is_file():
                fatal(f"pcap not found: {p}")
            hit = [e for e in aset if e["pcap"].resolve() == p.resolve() or e["pcap"].stem == p.stem]
            if hit:
                items.append({**hit[0], "pcap": p})
            elif args.family:
                items.append({"pcap": p, "family": args.family, "sha256": None})
            else:
                fatal(f"{p} is not in {args.pcap_set}; pass --family")
    else:
        items = aset
    stems = [i["pcap"].stem for i in items]
    if len(set(stems)) != len(stems):
        fatal(f"pcap stems must be unique: {stems}")
    for i in items:
        if not i["pcap"].is_file():
            fatal(f"pcap not found: {i['pcap']}")

    dev = m04.load_devices(DEVICE_TABLE)
    d02, _ = m02.load_devices(DEVICE_TABLE)
    devtab = pd.read_csv(DEVICE_TABLE, dtype=str, keep_default_na=False)
    devtab["mac"] = devtab["mac"].map(norm_mac)
    dev_sha = sha256(DEVICE_TABLE)
    m07a.Devices(DEVICE_TABLE).safety_check()
    cache: dict = {}

    def shares():
        if "s" not in cache:
            cache["s"] = benign_shares()
        return cache["s"]

    results = []
    for k, it in enumerate(items, 1):
        log(f"\n=== {k}/{len(items)}: {it['pcap']} ({it['family']})")
        results.append(run_pcap(it, args, dev, d02, dev_sha, devtab, shares))
        rebuild_summary(args.out_dir)

    log("\n" + "=" * 112)
    log(f"LABEL SUMMARY  pad ±{args.pad_s:g} s   out: {args.out_dir}")
    log(f"{'pcap':<22} {'flows':>11} {'attack':>10} {'benign':>9} {'excluded':>10} {'offwin':>8} {'normal':>8} {'vamb':>6} "
        f"{'ambig':>8} {'spoof':>6} {'gw_att':>7} {'pad_only':>8} {'t1b':>7}  hard  groups(07 / 07a)")
    for R in results:
        e = R["by_exclude_reason"]
        log(f"{R['stem'][:22]:<22} {R['flows']:>11,} {R['by_label']['attack']:>10,} {R['by_label']['benign']:>9,} "
            f"{R['by_label']['excluded']:>10,} {e['attacker_offwindow']:>8,} {e['attacker_normal_traffic']:>8,} {e.get('victim_ambiguous', 0):>6,} "
            f"{e['attack_normal_service_ambiguous']:>8,} {e['spoof_collision']:>6,} "
            f"{R['gateway_victim_attack_flows']:>7,} {R['pad_only'].get('attack', 0):>8,} "
            f"{R.get('t1b', {}).get('flows_via_t1b_only', 0):>7,}  "
            f"{'PASS' if R['hard_pass'] else 'FAIL'}  "
            + " ".join(f"{x['group']}:{x['verdict']}/{x['07a_verdict']}" for x in R["soft"]["groups_vs_07a"])
            + ("  (skipped)" if R.get("_skipped") else ""))
    rss = m07a.peak_rss()
    log(f"runtime {time.monotonic() - t0:.1f} s; peak RSS python {rss['self_mb']:,} MB, child {rss['tshark_mb']:,} MB")
    log("=" * 112)
    bad = [R["stem"] for R in results if not R["hard_pass"]]
    if bad:
        log(f"HARD CHECK FAILED: {bad}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
