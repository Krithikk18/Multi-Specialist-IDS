#!/usr/bin/env python
"""13c_rate_guard_benign_fp.py -- ONE-SHOT false-alarm test of the FROZEN rate guard (config/rate_guard_v1.json) on the
Step 10 TEST-period benign packets.

The test period was opened once by Step 10 (results/step10/TEST_OPENED.json) for the ML evaluation; the guard has never
seen it (13 calibrated on train / val only, 13b used greeth parts). This run reads it once.

Captures (nothing else is opened; guard() refuses every other name) -- the TEST time ranges only, as 08 / 08b cut them
  daytime   BenignTraffic1 / 2 / 3 (08b test_only sessions): the whole capture is test
  night     benign_night (BenignTraffic.pcap) and Recon-PortScan: time_split, only packets with 08's label "test":
            label = splits[bisect_right(boundaries_epoch, frame.time_epoch)] with results/step8/manifest_v1.json
            session_cuts; tshark gets the display filter frame.time_epoch >= <start of test>, so no train / val / gap
            packet leaves tshark (every timestamp is re-checked here: a gap@val|test packet is counted and dropped, a
            train / val packet exits 1).
            DDoS-SYN_Flood10, DDoS-SYN_Flood15, Mirai-udpplain24 (test sessions): the whole capture is test.
  never     any train / val range, any greeth part, test.parquet.

Guards (abort on failure), before any pcap byte is read
  - config/rate_guard_v1.json tracked in git and its blob == HEAD's; sha256(rate_guard.py) == results/step13/run_meta.json
    (13b's check_frozen(), imported unchanged)
  - results/step10/TEST_OPENED.json exists (the test period was already opened by Step 10)
  - sha256 of every capture used == its records: config DATASET + the cache's download record (benign_night); attack_set
    + 07's label report in manifest_v1 (attack sessions); split_plan_v1_1 + manifest_v1_1 (daytime). All hashed before
    the first tshark.

Packets   13's tshark_ipv4_packets() unchanged: outer header, IPv4 only, no protocol filter, one tshark at a time,
          streamed line by line.
Exclusion 13's rule unchanged, in EVERY capture: a packet whose eth.src or eth.dst is an attacker / testbed-Pi MAC (13's
          MacBook: config ATTACKER_MACS or device_table role testbed_pi) is dropped before the guard (not counted, not a
          clock tick) and counted per reason / MAC / proto -- the guard sees the population it was calibrated on. So no
          guard key can carry an attacker / Pi MAC packet.
Guard     one RateGuard(**frozen args, proto keys -> int, record_counts=True) per capture range; every kept IPv4 packet
          in file order (TCP / UDP = clock ticks), flush() at the end. record_counts only records per-window counts for
          the headroom table; it does not change alerting.
Classes   benign-key alert = every alert in a benign capture, and an alert in an attack-session capture whose key carried
          NO kept packet with ip.src or ip.dst in that capture's attacker IP set in the alert's window. attack-related =
          the other alerts in attack-session captures (Recon-PortScan, SYN10, SYN15, Mirai-udpplain24); not in C4.
          Attacker IP set = 07's cached CACHE_DIR/maps/<stem>_attacker_ips.json (every ip.src on packets whose eth.src
          matches ATTACKER_MACS, whole capture; cache key must match the pcap sha256 and ATTACKER_MACS), IPv4 unicast only
          (0.0.0.0 / multicast / broadcast dropped, 07's T1b rule). Kept packets that send FROM a set IP are reported as
          IP collisions.
Hours     exposure = packet active time: per capture range, the kept IPv4 packets are split into segments at pauses
          > active_idle_gap_seconds (split_plan_v1_1: 300 s) between consecutive packets (running max of ts); hours = sum
          of (last - first) per segment. For comparison only: raw span (last - first kept packet) and 08 / 08b's
          flow-based active benign hours (manifest_v1 / manifest_v1_1).

Criterion (pre-declared, fixed before this run; not changed here)
  C4  benign-key guard alerts (both levels, all protos) over daytime + night test benign combined: exact Garwood 95 %
      upper bound of alerts per hour <= 0.5 / h (upper = chi2.ppf(0.975, 2k + 2) / 2 / hours).
  Reported, no criterion: daytime and night separately (count, per hour, 95 % CI); every benign-key alert; attack-related
  alerts; headroom per level x proto (max benign packets / window, max / threshold, key / devices / time).

Outputs -> results/step13c/ (--dry-run: results/step13c/dry_run, Recon-PortScan test part only, checks only, no C4
verdict): summary.md, benign_alerts.csv, attack_related_alerts.csv, headroom.csv, per_capture.csv, run_meta.json. The
log goes to stdout (nohup ... > <out-dir>/run.log). One run at a time: an exclusive flock on <out-dir>/.13c_fp.lock.

Exit status: 0 ok, 1 bad input / guard or check failed / another run active, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import bisect
import datetime as dt
import fcntl
import hashlib
import importlib.util
import math
import os
import subprocess
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

import pandas as pd
from scipy.stats import chi2

from config.config import (ATTACKER_MACS, CACHE_DIR, CONFIG_DIR, DATASET, DEVICE_TABLE, REPO_ROOT, RESULTS_DIR,
                           sha256_file)
from rate_guard import STREAM, TCP_UDP, VICTIM, RateGuard, proto_name


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m07a = _load("attack_coverage", "07a_attack_coverage.py")      # Devices (07's device_table mapping + safety check)
m13 = _load("rate_guard_calibrate", "13_rate_guard_calibrate.py")   # reader, MacBook exclusion, helpers: unchanged
m13b = _load("rate_guard_eval", "13b_rate_guard_eval.py")       # check_frozen: unchanged

log, fatal, read_json, write_json, utc = m13.log, m13.fatal, m13.read_json, m13.write_json, m13.utc
fnum, md_table, peak_rss = m13.fnum, m13.md_table, m13.peak_rss

SCRIPT = "13c_rate_guard_benign_fp.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
MANIFEST_V1 = RESULTS_DIR / "step8" / "manifest_v1.json"
MANIFEST_V11 = RESULTS_DIR / "step8b" / "manifest_v1_1.json"
SPLIT_PLAN_V11 = CONFIG_DIR / "split_plan_v1_1.json"
ATTACK_SET = CONFIG_DIR / "attack_set.json"
TEST_OPENED = RESULTS_DIR / "step10" / "TEST_OPENED.json"
ATTACK_PCAPS = CACHE_DIR / "ciciot2023" / "attack"
MAPS_DIR = CACHE_DIR / "maps"
BENIGN_DOWNLOAD_RECORD = CACHE_DIR / "BenignTraffic.pcap.sha256.json"
OUT = RESULTS_DIR / "step13c"
RUN_LOCK = ".13c_fp.lock"

BENIGN_NIGHT = "benign_night"
DAYTIME = ("BenignTraffic1", "BenignTraffic2", "BenignTraffic3")
NIGHT = (BENIGN_NIGHT, "Recon-PortScan", "DDoS-SYN_Flood10", "DDoS-SYN_Flood15", "Mirai-udpplain24")
SESSIONS = NIGHT + DAYTIME
DRY_SESSIONS = ("Recon-PortScan",)
ALLOWED = {"BenignTraffic.pcap", "Recon-PortScan.pcap", "DDoS-SYN_Flood10.pcap", "DDoS-SYN_Flood15.pcap",
           "Mirai-udpplain24.pcap", "BenignTraffic1.pcap", "BenignTraffic2.pcap", "BenignTraffic3.pcap"}
TEST = "test"
LEVELS = (STREAM, VICTIM)
C4_MAX_PER_H = 0.5
CONF = 0.95
CRITERIA = {"C4": "benign-key guard alerts (both levels, all protos; key has no attacker / testbed-Pi MAC packets) over "
                  "daytime + night test benign combined: exact Garwood 95 % UPPER bound of alerts per hour <= "
                  f"{C4_MAX_PER_H} / h"}
KEY_CAP = 1_000_000          # device-map keys and attacker-IP window keys per capture; more -> STOP (memory)
DRAIN_EVERY = 500_000        # kept packets between pop_counts() drains

ALERT_COLS = ["capture", "period", "capture_kind", "key_class", "level", "key", "src_ip", "dst_ip", "proto", "proto_name",
              "dst_kind", "packets", "threshold", "packets_over_threshold", "rate_pps", "window_start_utc",
              "window_end_utc", "first_seen_utc", "last_seen_utc", "emitted_utc", "emitted_by",
              "attacker_ip_packets_in_window", "senders", "receivers", "alert_src_macs"]


def guard(p: Path) -> Path:
    """Every capture path goes through here: only the eight test-period captures."""
    if Path(p).name not in ALLOWED:
        fatal(f"refusing to touch {p}: only {', '.join(sorted(ALLOWED))} may be used")
    return Path(p)


def garwood(k: int, conf: float = CONF) -> tuple[float, float]:
    """Exact (Garwood) two-sided Poisson CI for a count k."""
    a = 1 - conf
    lo = chi2.ppf(a / 2, 2 * k) / 2 if k > 0 else 0.0
    return float(lo), float(chi2.ppf(1 - a / 2, 2 * k + 2) / 2)


def period(s: str) -> str:
    return "daytime" if s in DAYTIME else "night"


# --------------------------------------------------------------------------- inputs + guards

def check_inputs(sessions: list[str], M: dict) -> list[dict]:
    checks = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail})
        if not ok:
            log(f"  CHECK FAIL {name}: {detail}")

    if not TEST_OPENED.is_file():
        fatal(f"{TEST_OPENED.relative_to(REPO_ROOT)} missing: the test period was not opened by Step 10; STOP")
    M["test_opened"] = read_json(TEST_OPENED)
    log(f"guard ok: {TEST_OPENED.relative_to(REPO_ROOT)} exists (opened {M['test_opened'].get('opened_utc')})")

    man, man11, v11, aset = read_json(MANIFEST_V1), read_json(MANIFEST_V11), read_json(SPLIT_PLAN_V11), \
        read_json(ATTACK_SET)
    check("manifest_v1 hard_pass", man.get("hard_pass") is True, str(MANIFEST_V1.relative_to(REPO_ROOT)))
    check("manifest_v1_1 hard_pass", man11.get("hard_pass") is True, str(MANIFEST_V11.relative_to(REPO_ROOT)))
    check("manifest_v1 attack_set == config/attack_set.json",
          man["config"]["attack_set"]["sha256"] == sha256_file(ATTACK_SET), ATTACK_SET.name)
    rows = {r["session"]: r for r in man["sessions"]}
    inputs = {r["session"]: r for r in man["inputs"]}
    inputs11 = {r["session"]: r for r in man11["inputs"]}
    by_stem = {Path(e["path"]).stem: e for e in aset["pcaps"]}
    gap_s = float(v11["active_idle_gap_seconds"])
    flow_h = {**{s: float(h[TEST]) for s, h in man["benign_active_hours"]["per_session"].items()},
              **{s: float(h) for s, h in man11["hours"]["per_session"].items()}}
    out = []
    for s in sessions:
        mode = v11["sessions"].get(s)
        if s in DAYTIME:
            check(f"{s}: split_plan_v1_1 mode test_only", mode == "test_only", str(mode))
            t = v11["test_only_sessions"][s]
            pcap = Path(t["pcap"])
            sha = t["pcap_sha256"]
            check(f"{s}: pcap sha256 split_plan_v1_1 == manifest_v1_1 input == its 07 label key",
                  inputs11[s]["pcap_sha256"] == sha and inputs11[s]["label_completion_key"]["pcap_sha256"] == sha,
                  f"{sha[:16]}...")
            labels, bounds, kind, cuts_utc = [TEST], [], "benign", []
        else:
            check(f"{s}: manifest_v1 mode == split_plan_v1_1", rows[s]["mode"] == mode, f"{rows[s]['mode']} / {mode}")
            cuts = man["session_cuts"][s]
            labels, bounds, cuts_utc = cuts["splits"], [float(x) for x in cuts["boundaries_epoch"]], \
                cuts["boundaries_utc"]
            if mode == "time_split":
                check(f"{s}: time_split cuts end ... gap@val|test, test",
                      labels[-2:] == ["gap@val|test", TEST] and len(labels) == len(bounds) + 1
                      and bounds == sorted(bounds), f"{labels} / {bounds}")
            else:
                check(f"{s}: test session is all test", mode == TEST and labels == [TEST] and not bounds,
                      f"{mode} {labels}")
            if s == BENIGN_NIGHT:
                pcap, sha, kind = DATASET.benign_pcap_cached, DATASET.benign_pcap_sha256, "benign"
                rec = read_json(BENIGN_DOWNLOAD_RECORD)["sha256"] if BENIGN_DOWNLOAD_RECORD.is_file() else None
                check(f"{s}: config sha256 == download record {BENIGN_DOWNLOAD_RECORD.name}", rec == sha,
                      f"{sha[:16]}... / {str(rec)[:16]}...")
            else:
                e = by_stem[s]
                pcap, sha, kind = ATTACK_PCAPS / e["path"], e["sha256"], "attack"
                check(f"{s}: 07 label report pcap (manifest_v1) == attack set",
                      inputs[s]["label_report"]["completion_key"]["pcap_sha256"] == sha, f"{sha[:16]}...")
        start = bounds[-1] if labels[-1] == TEST and bounds else None
        out.append({"session": s, "mode": mode, "kind": kind, "period": period(s), "pcap": guard(pcap),
                    "sha256_expected": sha, "labels": labels, "bounds": bounds, "boundaries_utc": cuts_utc,
                    "test_start": start, "display_filter": f"frame.time_epoch >= {start:.6f}" if start else None,
                    "flow_active_h": flow_h.get(s, math.nan), "gap_s": gap_s})
    M["input_checks"] = checks
    if not all(c["pass"] for c in checks):
        fatal("input checks failed (see above)")
    return out


def attacker_ips(S: dict) -> tuple[set, dict]:
    """07's cached attacker IP set for an attack capture, IPv4 unicast only (07's T1b rule)."""
    p = MAPS_DIR / f"{S['pcap'].stem}_attacker_ips.json"
    if not p.is_file():
        fatal(f"{p} missing (07's attacker IP cache for {S['session']}); STOP")
    A = read_json(p)
    k = A["key"]
    ok = (k["pcap_sha256"] == S["sha256_expected"] and k["exact"] == list(ATTACKER_MACS.exact)
          and k["prefixes"] == list(ATTACKER_MACS.prefixes) and not A.get("overflow_packets"))
    if not ok:
        fatal(f"{p}: key {k} / overflow {A.get('overflow_packets')} does not match the pcap sha256 / ATTACKER_MACS")
    ips = {ip for _, ip, *_ in A["pairs"] if "." in ip and ip != "0.0.0.0" and m13.dst_kind(ip) == "unicast"}
    return ips, {"source": str(p), "pairs": len(A["pairs"]), "ipv4_unicast_ips": sorted(ips)}


def hash_all(S_list: list[dict]) -> None:
    """sha256 of every capture used == its records, all before the first tshark."""
    for S in S_list:
        t0 = time.monotonic()
        if not S["pcap"].is_file():
            fatal(f"not found: {S['pcap']}")
        got = sha256_file(S["pcap"])
        ok = got == S["sha256_expected"]
        log(f"  {S['session']}: sha256 {got[:16]}... {'==' if ok else '!='} record ({time.monotonic() - t0:.0f} s)")
        if not ok:
            fatal(f"sha256 of {S['pcap']} {got} != record {S['sha256_expected']}; STOP")
        S["sha256"] = got
        S["size_bytes"] = S["pcap"].stat().st_size


# --------------------------------------------------------------------------- one capture range

class Headroom:
    """Per (period, level, proto): non-empty benign windows, max packets and its window (first one on ties)."""

    def __init__(self):
        self.g: dict[tuple, list] = {}       # (period, level, proto) -> [windows, max, tied, rec, over_threshold]

    def add(self, per: str, level: str, proto: int, packets: int, thr: int | None, rec: tuple) -> None:
        g = self.g.get((per, level, proto))
        over = int(thr is not None and packets > thr)
        if g is None:
            self.g[(per, level, proto)] = [1, packets, 1, rec, over]
            return
        g[0] += 1
        g[4] += over
        if packets > g[1]:
            g[1], g[2], g[3] = packets, 1, rec
        elif packets == g[1]:
            g[2] += 1


def describe(level: str, key: tuple, sm: dict, vm: dict, book) -> dict:
    """Key string, IPs and devices (07 device_table mapping of the MACs seen on the key, as 13)."""
    if level == STREAM:
        src, dst, proto = key
        m = sm.get(key, (set(), set()))
        senders, receivers = m[0], m[1]
    else:
        (dst, proto), src = key, ""
        m = vm.get(key, (set(), set()))
        receivers, senders = m[0], m[1]
    fmt = lambda s: "; ".join(sorted(book.label(x) for x in s)) + (" (+more)" if len(s) >= m13.MAC_KEEP else "")
    return {"key": m13.key_str(level, key), "src_ip": src, "dst_ip": dst, "proto": proto,
            "proto_name": proto_name(proto), "dst_kind": m13.dst_kind(dst), "senders": fmt(senders),
            "receivers": fmt(receivers)}


def run_capture(S: dict, gargs: dict, book, hr: Headroom) -> dict:
    s, pcap, per = S["session"], S["pcap"], S["period"]
    t0 = time.monotonic()
    log(f"== {s} ({S['mode']}, {S['kind']} capture, {per}): {pcap}; filter: {S['display_filter'] or 'none (all test)'}")
    A, ainfo = attacker_ips(S) if S["kind"] == "attack" else (set(), None)
    if ainfo:
        log(f"  attacker IP set ({len(A)} IPv4 unicast): {sorted(A)}")
    g = RateGuard(**gargs, record_counts=True)
    w = g.window_s
    bounds, labels, start, gap_s = S["bounds"], S["labels"], S["test_start"], S["gap_s"]
    get = book.get
    sm, vm = {}, {}
    attip: Counter = Counter()        # (level, key, window index) -> kept packets with an attacker-set IP
    coll: Counter = Counter()         # (ip.src in the attacker set, eth.src) of kept packets: IP collisions
    alerts: list[tuple] = []          # (Alert, emitted_ts, emitted_by)
    c, rc, gap, by_proto = Counter(), Counter(), Counter(), Counter()
    excl, excl_mac, excl_proto = Counter(), Counter(), Counter()
    drained = Counter()
    segs: list[list[float]] = []      # packet active segments [first, last]
    t_lo, t_hi = math.inf, -math.inf

    def drain() -> None:
        for r in g.pop_counts():
            key = (r.src_ip, r.dst_ip, r.proto) if r.level == STREAM else (r.dst_ip, r.proto)
            drained[r.level] += r.packets
            if attip.get((r.level, key, round(r.window_start / w))):
                c[f"attack_related_windows_{r.level}"] += 1
                continue
            hr.add(per, r.level, r.proto, r.packets, g.threshold_for(r.level, r.proto),
                   (r.packets, s, r.window_start, key, r.first_seen_ts, r.last_seen_ts, r.level))
            hr.add("all", r.level, r.proto, r.packets, g.threshold_for(r.level, r.proto),
                   (r.packets, s, r.window_start, key, r.first_seen_ts, r.last_seen_ts, r.level))

    t1 = time.monotonic()
    try:
        for ts, src, dst, proto, smac, dmac in m13.tshark_ipv4_packets(pcap, S["display_filter"], rc):
            if start is not None and ts < start:
                fatal(f"{s}: packet at {ts} < test start {start}: the tshark filter failed")
            lab = labels[bisect.bisect_right(bounds, ts)]
            if lab != TEST:
                if lab.startswith("gap@"):
                    gap[lab] += 1
                    continue
                fatal(f"{s}: packet at {ts} is in the {lab} range; STOP")
            c["ipv4"] += 1
            ms, md = get(smac), get(dmac)
            if ms[0] or md[0]:
                reason = f"eth.src {ms[0]}" if ms[0] else f"eth.dst {md[0]}"
                excl[reason] += 1
                excl_mac[smac if ms[0] else dmac] += 1
                excl_proto[proto] += 1
                if proto not in TCP_UDP:
                    excl[f"in_scope {reason}"] += 1
                continue
            c["kept"] += 1
            if ts < t_lo:
                t_lo = ts
            if ts > t_hi:                     # segs[-1][1] == t_hi: older packets fall inside the open segment
                if segs and ts - t_hi <= gap_s:
                    segs[-1][1] = ts
                else:
                    segs.append([ts, ts])
                t_hi = ts
            if A and src in A:
                coll[(src, smac)] += 1
            if proto in TCP_UDP:
                c["tcp_udp"] += 1
            else:
                by_proto[proto] += 1
                skey, vkey = (src, dst, proto), (dst, proto)
                for d, k, a, b, name in ((sm, skey, smac, dmac, "stream"), (vm, vkey, dmac, smac, "victim")):
                    if k not in d and len(d) >= KEY_CAP:
                        fatal(f"{s}: more than {KEY_CAP:,} {name} keys; STOP")
                    m13.remember(d, k, a, b)
                if A and (src in A or dst in A):
                    k10 = math.floor(ts / w)
                    attip[(STREAM, skey, k10)] += 1
                    attip[(VICTIM, vkey, k10)] += 1
                    if len(attip) >= KEY_CAP:
                        fatal(f"{s}: more than {KEY_CAP:,} attacker-IP window keys; STOP")
            for a in g.update(ts, src, dst, proto, smac, dmac):
                alerts.append((a, ts, "packet"))
            if c["kept"] % DRAIN_EVERY == 0:
                drain()
                if c["kept"] % (10 * DRAIN_EVERY) == 0:
                    log(f"  {c['kept']:,} kept packets, {rc['frames']:,} frames, {len(alerts):,} alerts, "
                        f"{time.monotonic() - t1:.0f} s")
    except RuntimeError as e:
        fatal(str(e))
    for a in g.flush():
        alerts.append((a, a.window_end, "flush"))
    drain()
    tshark_s = time.monotonic() - t1
    gs = g.stats()

    # ---- consistency
    in_scope = sum(by_proto.values())
    excl_n = sum(v for k, v in excl.items() if not k.startswith("in_scope"))
    checks = [
        {"check": f"{s}: guard packets_seen == kept packets == IPv4 - excluded",
         "pass": gs["packets_seen"] == c["kept"] == c["ipv4"] - excl_n,
         "detail": f"{gs['packets_seen']:,} / {c['kept']:,} / {c['ipv4'] - excl_n:,}"},
        {"check": f"{s}: guard packets_in_scope == kept non-TCP/UDP", "pass": gs["packets_in_scope"] == in_scope,
         "detail": f"{gs['packets_in_scope']:,} vs {in_scope:,}"},
        {"check": f"{s}: drained stream == victim == in scope - late",
         "pass": drained[STREAM] == drained[VICTIM] == in_scope - gs["late_packets"],
         "detail": f"{drained[STREAM]:,} / {drained[VICTIM]:,} vs {in_scope - gs['late_packets']:,}"},
        {"check": f"{s}: guard alerts == alerts collected", "pass": gs["alerts"] == len(alerts),
         "detail": f"{gs['alerts']:,} vs {len(alerts):,}"},
    ]

    # ---- alerts
    arows = []
    for a, ets, eby in alerts:
        key = (a.src_ip, a.dst_ip, a.proto) if a.level == STREAM else (a.dst_ip, a.proto)
        att = attip.get((a.level, key, round(a.window_start / w)), 0)
        arows.append({"capture": s, "period": per, "capture_kind": S["kind"],
                      "key_class": "attack_related" if att else "benign", **describe(a.level, key, sm, vm, book),
                      "level": a.level, "packets": a.packets, "threshold": a.threshold,
                      "packets_over_threshold": a.packets / a.threshold if a.threshold else math.inf,
                      "rate_pps": a.rate_pps, "window_start_utc": utc(a.window_start), "window_end_utc": utc(a.window_end),
                      "first_seen_utc": utc(a.first_seen_ts), "last_seen_utc": utc(a.last_seen_ts),
                      "emitted_utc": utc(ets), "emitted_by": eby, "attacker_ip_packets_in_window": att,
                      "alert_src_macs": " ".join(a.src_macs)})
    n_ben = sum(r["key_class"] == "benign" for r in arows)
    n_att = len(arows) - n_ben

    # ---- headroom maxima of this capture: resolve device labels now (sm / vm are per capture)
    for (pp, lv, proto), G in hr.g.items():
        rec = G[3]
        if rec[1] == s and len(rec) == 7:
            G[3] = rec + (describe(lv, rec[3], sm, vm, book),)

    act_h = sum(b - a for a, b in segs) / 3600
    span_h = (t_hi - t_lo) / 3600 if t_hi > t_lo else 0.0
    rt = time.monotonic() - t0
    row = {"capture": s, "period": per, "capture_kind": S["kind"], "mode": S["mode"],
           "range": f"[{S['boundaries_utc'][-1]}, end]" if S["test_start"] else "whole capture",
           "frames_read": rc["frames"], "ipv4_test_packets": c["ipv4"], "gap_packets_dropped": sum(gap.values()),
           "excluded_packets": excl_n,
           "excluded_in_scope": sum(v for k, v in excl.items() if k.startswith("in_scope")),
           "kept_packets": c["kept"], "tcp_udp_packets": c["tcp_udp"], "in_scope_packets": in_scope,
           "in_scope_by_proto": "; ".join(f"{proto_name(p)}: {v:,}" for p, v in by_proto.most_common()),
           "first_kept_utc": utc(t_lo), "last_kept_utc": utc(t_hi),
           "active_segments": len(segs), "active_hours": act_h, "raw_span_hours": span_h,
           "flow_active_hours_08": S["flow_active_h"],
           "windows_closed": gs["windows_closed"], "late_packets": gs["late_packets"],
           "max_active_keys": gs["max_active_keys"], "stream_keys": len(sm), "victim_keys": len(vm),
           "alerts": len(arows), "benign_key_alerts": n_ben, "attack_related_alerts": n_att,
           "benign_alerts_per_h": n_ben / act_h if act_h > 0 else math.nan,
           "attacker_ip_collision_packets": sum(coll.values()),
           "non_ipv4_frames": rc["non_ipv4"], "bad_lines": rc["bad_lines"],
           "tshark_s": round(tshark_s, 1), "runtime_s": round(rt, 1)}
    log(f"  test IPv4 {c['ipv4']:,}, excluded {excl_n:,}, kept {c['kept']:,}, in scope {in_scope:,} "
        f"({row['in_scope_by_proto'] or '-'}); gap dropped {sum(gap.values()):,}; active {act_h:.3f} h in {len(segs)} "
        f"segment(s) (raw span {span_h:.3f} h, 08 flow-based {S['flow_active_h']:.3f} h)")
    log(f"  alerts {len(arows)} (benign-key {n_ben}, attack-related {n_att}), late {gs['late_packets']:,}, "
        f"{tshark_s:.0f} s, {rc['frames'] / max(tshark_s, 1e-9):,.0f} frames/s, rss {peak_rss()}")
    for x in checks:
        if not x["pass"]:
            log(f"  CHECK FAIL {x['check']}: {x['detail']}")
    if not all(x["pass"] for x in checks):
        fatal(f"{s}: consistency checks failed")
    meta = {"session": s, "period": per, "kind": S["kind"], "mode": S["mode"], "pcap": str(pcap),
            "pcap_sha256": S["sha256"], "sha256_expected": S["sha256_expected"], "sha256_match": True,
            "size_bytes": S["size_bytes"], "cut_labels": S["labels"], "boundaries_epoch": S["bounds"],
            "boundaries_utc": S["boundaries_utc"], "test_start_epoch": S["test_start"],
            "tshark_display_filter": S["display_filter"],
            "tshark_cmd": " ".join(m13.tshark_cmd(pcap, S["display_filter"])),
            "reader_counts": dict(rc), "gap_dropped": dict(gap),
            "excluded_by_reason": dict(excl), "excluded_by_mac": {f"{book.label(m)} ({m})": v
                                                                  for m, v in excl_mac.most_common()},
            "excluded_by_proto": {m13.pname(p): v for p, v in excl_proto.most_common()},
            "active_segments_utc": [[utc(a), utc(b)] for a, b in segs], "active_hours": act_h,
            "raw_span_hours": span_h, "flow_active_hours_08": S["flow_active_h"],
            "attacker_ip_set": ainfo,
            "attacker_ip_collisions": [{"ip": ip, "eth_src": f"{book.label(m)} ({m})", "packets": n}
                                       for (ip, m), n in coll.most_common(20)],
            "attack_related_windows": {lv: c[f"attack_related_windows_{lv}"] for lv in LEVELS},
            "guard_stats": gs, "checks": checks, "tshark_s": round(tshark_s, 1), "runtime_s": round(rt, 1),
            "peak_rss_after": peak_rss()}
    return {"alerts": arows, "row": row, "meta": meta}


# --------------------------------------------------------------------------- tables

def headroom_rows(hr: Headroom, gargs_g: RateGuard) -> list[dict]:
    rows = []
    for (pp, lv, proto) in sorted(hr.g, key=lambda k: (("all", "daytime", "night").index(k[0]), LEVELS.index(k[1]),
                                                       k[2])):
        n, mx, tied, rec, over = hr.g[(pp, lv, proto)]
        thr = gargs_g.threshold_for(lv, proto)
        d = rec[7] if len(rec) > 7 else {}
        rows.append({"period": pp, "level": lv, "proto": proto, "proto_name": proto_name(proto),
                     "proto_class": m13.pclass(proto), "threshold": thr, "nonempty_benign_windows": n,
                     "max_packets": mx, "max_over_threshold": mx / thr if thr else math.nan,
                     "headroom_factor": thr / mx if mx else math.inf, "windows_at_max": tied,
                     "windows_over_threshold": over, "max_capture": rec[1], "max_key": d.get("key", ""),
                     "max_dst_kind": d.get("dst_kind", ""), "max_senders": d.get("senders", ""),
                     "max_receivers": d.get("receivers", ""), "max_window_start_utc": utc(rec[2]),
                     "max_first_seen_utc": utc(rec[4]), "max_last_seen_utc": utc(rec[5])})
    return rows


def rate_row(name: str, k: int, h: float) -> dict:
    lo, hi = garwood(k)
    return {"scope": name, "benign_key_alerts": k, "hours": h, "alerts_per_h": k / h if h > 0 else math.nan,
            "ci95_lower_per_h": lo / h if h > 0 else math.nan, "ci95_upper_per_h": hi / h if h > 0 else math.nan,
            "ci95_count": f"[{lo:.3f}, {hi:.3f}]"}


# --------------------------------------------------------------------------- summary

def write_summary(out: Path, M: dict, per: list[dict], ben: list[dict], att: list[dict], head: list[dict],
                  rates: list[dict], dry: bool) -> None:
    F = M["frozen"]
    kw = F["rate_guard_kwargs"]
    L = ["# Step 13c -- frozen rate guard v1: benign false-alarm test on the Step 10 TEST period (one shot)", ""]
    if dry:
        L += [f"**DRY RUN: {', '.join(M['sessions'])} test part only -- pipeline checks, NO C4 verdict.**", ""]
    L += [f"- run {M['run_utc']}, git HEAD `{M['git_head']}`, {SCRIPT} sha256 `{CODE_SHA256[:16]}...`, runtime "
          f"{fnum(M['runtime_s'], 0)} s, peak RSS python {fnum(M['peak_rss']['python_self_mb'], 0)} MB / tshark "
          f"{fnum(M['peak_rss']['tshark_max_mb'], 0)} MB",
          f"- frozen guard: `{F['config']}` (sha256 `{F['config_sha256'][:16]}...`, git blob `{F['config_git_blob'][:12]}`"
          f" == HEAD), rate_guard.py sha256 `{F['rate_guard_sha256'][:16]}...` == results/step13/run_meta.json; window "
          f"{kw['window_s']:g} s; alert iff packets > threshold: stream {kw['stream_threshold']} / victim "
          f"{kw['victim_threshold']} (DEFAULT, incl. GRE), ICMP {kw['stream_proto_thresholds']['1']} / "
          f"{kw['victim_proto_thresholds']['1']}, IGMP {kw['stream_proto_thresholds']['2']} / "
          f"{kw['victim_proto_thresholds']['2']}",
          f"- test period already opened by Step 10: results/step10/TEST_OPENED.json ({M['test_opened'].get('opened_utc')})",
          f"- input checks {sum(c['pass'] for c in M['input_checks'])}/{len(M['input_checks'])} PASS; consistency "
          f"checks {sum(c['pass'] for p in M['per_capture'] for c in p['checks'])}/"
          f"{sum(len(p['checks']) for p in M['per_capture'])} PASS; every pcap sha256 == its record",
          "- read: the TEST ranges only (08 / 08b cuts: time_split sessions from the start of test via the tshark "
          "filter, test / test_only sessions whole); never opened: train / val ranges, greeth parts, test.parquet",
          "- packets: 13's reader unchanged (outer header, IPv4, no protocol filter); 13's exclusion unchanged in EVERY "
          "capture (attacker / testbed-Pi MAC as eth.src or eth.dst -> dropped before the guard); one RateGuard per "
          "capture range (TCP / UDP = clock ticks), flush() at the end",
          "- benign-key alert = any alert in a benign capture, or in an attack-session capture an alert whose key "
          "carried no kept packet to / from that capture's attacker IP set in its window (07's cached set, IPv4 unicast);"
          " attack-related = the rest (not in C4)", ""]
    L += ["## Pre-declared criterion (fixed before this run)", ""] + [f"- **{k}** {v}" for k, v in CRITERIA.items()] + [""]
    if dry:
        L += ["**C4: not evaluated (dry run).**", ""]
    else:
        C = M["C4"]
        L += [f"**C4: {'PASS' if C['pass'] else 'FAIL'}** -- {C['benign_key_alerts']} benign-key alerts over "
              f"{C['hours']:.3f} h; exact Garwood 95 % upper bound {C['upper_count']:.3f} alerts = "
              f"**{C['upper_per_h']:.4f} / h** (limit {C4_MAX_PER_H} / h)", ""]
    L += ["## Benign-key alerts per hour (exact Garwood 95 % CI)", ""]
    L += md_table(rates, ["scope", "benign_key_alerts", "hours", "alerts_per_h", "ci95_lower_per_h", "ci95_upper_per_h",
                          "ci95_count"], 4) + [""]
    L += ["## Hours (how computed)", "",
          f"Exposure = packet active time. Per capture range the KEPT IPv4 packets (after the exclusion) are split into "
          f"segments at pauses > {M['active_idle_gap_seconds']:g} s (split_plan_v1_1 active_idle_gap_seconds) between "
          "consecutive packets (running max of the timestamp); hours = sum over segments of (last - first), summed over "
          "captures. For comparison: raw span = last - first kept packet; 08 / 08b = the flow-based active benign hours "
          "of manifest_v1 / manifest_v1_1 (Step 10's FP / hour denominator).", ""]
    L += md_table(per, ["capture", "period", "range", "first_kept_utc", "last_kept_utc", "active_segments",
                        "active_hours", "raw_span_hours", "flow_active_hours_08"], 3) + [""]
    tot = {k: sum(r[k] for r in per) for k in ("active_hours", "raw_span_hours", "flow_active_hours_08")}
    L += [f"Totals: packet active {tot['active_hours']:.3f} h (C4 denominator); raw span {tot['raw_span_hours']:.3f} h; "
          f"08 / 08b flow-based {tot['flow_active_hours_08']:.3f} h.", ""]
    L += ["## Every benign-key alert", ""]
    L += md_table(ben, ["capture", "level", "key", "proto_name", "packets", "threshold", "window_start_utc",
                        "first_seen_utc", "last_seen_utc", "senders", "receivers"], 2) + [""]
    L += ["## Attack-related alerts (attack-session captures; NOT in C4)", ""]
    L += md_table(att, ["capture", "level", "key", "proto_name", "packets", "threshold", "window_start_utc",
                        "attacker_ip_packets_in_window", "senders", "receivers"], 2) + [""]
    L += ["## Headroom: max benign packets per 10 s window vs threshold", "",
          "Benign windows = non-empty windows of benign keys (attack-related key-windows left out). max_over_threshold "
          "= max / threshold (alert iff > 1); headroom_factor = threshold / max. Ties: the first window is listed, "
          "windows_at_max counts all.", ""]
    L += md_table(head, ["period", "level", "proto_name", "threshold", "nonempty_benign_windows", "max_packets",
                         "max_over_threshold", "headroom_factor", "windows_over_threshold", "max_capture", "max_key",
                         "max_senders", "max_receivers", "max_window_start_utc"], 3) + [""]
    L += ["## Per capture", ""]
    L += md_table(per, ["capture", "period", "capture_kind", "ipv4_test_packets", "excluded_packets", "kept_packets",
                        "in_scope_packets", "in_scope_by_proto", "gap_packets_dropped", "late_packets", "alerts",
                        "benign_key_alerts", "attack_related_alerts", "attacker_ip_collision_packets", "runtime_s"], 1)
    L += [""]
    L += ["Excluded packets (attacker / testbed-Pi MAC) per capture:", ""]
    for p in M["per_capture"]:
        L += [f"- {p['session']}: " + ("; ".join(f"{k}: {v:,}" for k, v in sorted(p["excluded_by_reason"].items())
                                                 if not k.startswith("in_scope")) or "none")
              + (" | by proto: " + ", ".join(f"{k} {v:,}" for k, v in p["excluded_by_proto"].items())
                 if p["excluded_by_proto"] else "")]
    L += ["", "Attacker IP sets (07's cache, attack-session captures) and IP collisions (kept packets sending from a set "
          "IP):", ""]
    for p in M["per_capture"]:
        if p["attacker_ip_set"]:
            L += [f"- {p['session']}: {', '.join(p['attacker_ip_set']['ipv4_unicast_ips'])}; collisions: "
                  + (", ".join(f"{x['ip']} from {x['eth_src']} {x['packets']:,}" for x in p["attacker_ip_collisions"])
                     or "none")]
    L += ["", "## Outputs", "", "summary.md, benign_alerts.csv, attack_related_alerts.csv, headroom.csv, per_capture.csv, "
          "run_meta.json", ""]
    (out / "summary.md").write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- main

def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.13c_fp.lock for the whole run (released by the kernel on exit)."""
    d.mkdir(parents=True, exist_ok=True)
    path = d / RUN_LOCK
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another {SCRIPT} run is using {d} (lock {path} held by: {holder}); refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}"
             f" argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true",
                    help=f"pipeline checks on the {', '.join(DRY_SESSIONS)} test part only -> results/step13c/dry_run")
    args = ap.parse_args()
    t0 = time.monotonic()
    out = OUT / "dry_run" if args.dry_run else OUT
    sessions = list(DRY_SESSIONS if args.dry_run else SESSIONS)
    lock = run_lock(out)
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...  -> {out}")
    M = {"script": SCRIPT, "code_sha256": CODE_SHA256,
         "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "argv": sys.argv,
         "dry_run": args.dry_run, "git_head": m13b.git("rev-parse", "HEAD").stdout.strip(),
         "tshark_version": subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.split("\n")[0],
         "criteria": CRITERIA, "sessions": sessions, "periods": {s: period(s) for s in sessions},
         "attacker_macs": {"exact": list(ATTACKER_MACS.exact), "prefixes": list(ATTACKER_MACS.prefixes)},
         "reader_sha256": sha256_file(REPO_ROOT / "13_rate_guard_calibrate.py"),
         "eval_13b_sha256": sha256_file(REPO_ROOT / "13b_rate_guard_eval.py"),
         "never_opened": "train / val ranges of every session; greeth parts (any); test.parquet"}
    gargs = m13b.check_frozen(M)
    M["frozen"]["config_blob_id"] = M["frozen"]["config_git_blob"]
    S_list = check_inputs(sessions, M)
    M["active_idle_gap_seconds"] = S_list[0]["gap_s"]
    dev = m07a.Devices(DEVICE_TABLE)
    M["device_table_attacker_rows"] = dev.safety_check()
    book = m13.MacBook(dev)
    log("sha256 of every capture (before any tshark):")
    hash_all(S_list)

    hr = Headroom()
    res = [run_capture(S, gargs, book, hr) for S in S_list]
    M["per_capture"] = [R["meta"] for R in res]
    per = [R["row"] for R in res]
    alerts = [r for R in res for r in R["alerts"]]
    ben = [r for r in alerts if r["key_class"] == "benign"]
    att = [r for r in alerts if r["key_class"] == "attack_related"]
    head = headroom_rows(hr, RateGuard(**gargs))

    # benign windows over threshold (headroom) must equal the benign-key alerts
    over = sum(r["windows_over_threshold"] for r in head if r["period"] == "all")
    if over != len(ben):
        fatal(f"headroom windows over threshold {over} != benign-key alerts {len(ben)}")

    hours = {p: sum(r["active_hours"] for r in per if r["period"] == p) for p in ("daytime", "night")}
    rates = [rate_row("daytime + night (C4)", len(ben), hours["daytime"] + hours["night"]),
             rate_row("daytime", sum(r["period"] == "daytime" for r in ben), hours["daytime"]),
             rate_row("night", sum(r["period"] == "night" for r in ben), hours["night"])]
    rates = [r for r in rates if r["hours"] > 0]
    H = hours["daytime"] + hours["night"]
    lo, hi = garwood(len(ben))
    M["hours"] = {"definition": f"packet active time: kept IPv4 packets per capture range split at pauses > "
                                f"{M['active_idle_gap_seconds']:g} s; sum of (last - first) per segment, summed over "
                                "captures",
                  "per_capture": {r["capture"]: r["active_hours"] for r in per}, **hours, "total": H,
                  "raw_span_total": sum(r["raw_span_hours"] for r in per),
                  "flow_active_08_total": sum(r["flow_active_hours_08"] for r in per)}
    M["rates"] = rates
    if not args.dry_run:
        M["C4"] = {"pass": hi / H <= C4_MAX_PER_H, "benign_key_alerts": len(ben), "hours": H,
                   "lower_count": lo, "upper_count": hi, "upper_per_h": hi / H, "point_per_h": len(ben) / H,
                   "limit_per_h": C4_MAX_PER_H, "method": "exact Garwood: upper = chi2.ppf(0.975, 2k + 2) / 2"}
    M["alerts_total"] = {"benign_key": len(ben), "attack_related": len(att)}

    pd.DataFrame(ben, columns=ALERT_COLS).to_csv(out / "benign_alerts.csv", index=False, lineterminator="\n")
    pd.DataFrame(att, columns=ALERT_COLS).to_csv(out / "attack_related_alerts.csv", index=False, lineterminator="\n")
    pd.DataFrame(head).to_csv(out / "headroom.csv", index=False, lineterminator="\n")
    pd.DataFrame(per).to_csv(out / "per_capture.csv", index=False, lineterminator="\n")
    M["peak_rss"] = peak_rss()
    M["runtime_s"] = round(time.monotonic() - t0, 1)
    write_json(out / "run_meta.json", M)
    write_summary(out, M, per, ben, att, head, rates, args.dry_run)
    if args.dry_run:
        log(f"DRY RUN: benign-key alerts {len(ben)}, attack-related {len(att)}, hours {H:.3f} -- no C4 verdict")
    else:
        C = M["C4"]
        log(f"C4 {'PASS' if C['pass'] else 'FAIL'}: {C['benign_key_alerts']} benign-key alerts / {H:.3f} h, Garwood 95 % "
            f"upper {C['upper_per_h']:.4f} / h (limit {C4_MAX_PER_H})")
    log(f"done in {M['runtime_s']:.0f} s, peak RSS {M['peak_rss']} -> {out / 'summary.md'}")
    lock.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(2)
