#!/usr/bin/env python
"""13_rate_guard_calibrate.py -- calibrate rate_guard.py on BENIGN train / val packets and PROPOSE thresholds.

PROPOSAL ONLY: this script measures benign per-window packet counts and proposes thresholds at fixed margins over the
TRAIN max. It decides nothing and changes no config; rate_guard.py is imported read-only.

Data (nothing else is opened)
  sessions  the train / val sessions of the split plan = the manifest_v1 sessions with mode train or time_split
            (results/step8/manifest_v1.json, built by 08 from config/split_plan.json v1.0; config/split_plan_v1_1.json
            only adds test_only sessions): benign_night (BenignTraffic.pcap), DDoS-SYN_Flood, DDoS-SYN_Flood5,
            Recon-PortScan, Mirai-udpplain. Never opened: the test sessions (DDoS-SYN_Flood10 / 15, Mirai-udpplain24),
            the test_only sessions (BenignTraffic1-3), any greeth part, test.parquet (guard() refuses the names).
  cuts      08's split rule on packet time: split = splits[bisect_right(boundaries_epoch, frame.time_epoch)] with
            manifest_v1 session_cuts (08's boundaries, 08's side='right'). train and val packets are kept;
            gap@train|val packets are counted and dropped. A capture with a test part (time_split) is read with the
            tshark display filter frame.time_epoch < <start of gap@val|test>, so no packet of the val -> test gap or
            of the test range leaves tshark (every timestamp is re-checked here; a violation exits 1).
  packets   tshark_ipv4_packets() (13b imports it unchanged): outer-header fields only (-E occurrence=f)
            frame.time_epoch, eth.src, eth.dst, ip.src, ip.dst, ip.proto; IPv4 only (frames without ip.src are
            counted as non-IPv4); no protocol filter, so GRE (which carries inner UDP) stays outer proto 47.
            Dissectors frame, eth, ethertype, ip, vlan only (inner headers are never parsed): field output
            md5-identical to 02's lean set on Recon-PortScan (831,856 frames) and 37 % faster; per-conversation
            state reset every 200k packets (-M).
  exclusion every capture, benign_night included: a packet whose eth.src or eth.dst is an attacker / testbed-Pi MAC
            (config ATTACKER_MACS, or device_table role testbed_pi: 07's T1 MAC rule) is dropped before the guard
            (not counted, not a clock tick) and counted per reason (eth.src checked first), per MAC and per proto.
  guard     per capture x split x window (10 s design; 1 s and 60 s sensitivity) one RateGuard(window_s,
            record_counts=True): every kept IPv4 packet goes to update() (TCP / UDP = clock ticks), flush() at the end
            of the capture, counts drained with pop_counts(). Train and val never share a guard, so no window spans
            two captures or two splits. Empty windows emit nothing and are not in any statistic.

Statistics (per split; train and val are never pooled)
  windows   non-empty windows per (level, proto, destination kind): count, max, p99, p99.9 (nearest rank, numpy
            method inverted_cdf), max rate (max / window_s); the key(s) of the max (ties: up to 5) with window start,
            first / last packet and devices: 07's device_table mapping of the MACs seen on that key's packets
            (stream: senders -> receivers; victim: receivers, senders).
  classes   ICMP (1), IGMP (2), DEFAULT (every other non-TCP/UDP proto, incl. GRE) -- the threshold classes.
  dst kind  unicast / multicast (224.0.0.0/4) / broadcast (255.255.255.255 or the directed broadcast of a config
            NETWORK subnet); reported separately and pooled ("all").
  phones    packets with a role-"excluded" MAC (randomised phone / laptop MAC) on either side stay IN; per 10 s
            window their packets are also counted on the side, giving their share of each max and the max without
            them.
  proposal  per level x class: threshold = margin x TRAIN max (10 s windows, all destination kinds), margins 2 / 3 / 5;
            DEFAULT is floored: max(margin x DEFAULT train max, the ICMP threshold of the same level and margin); raw
            and floored values are both reported (DEFAULT_FLOOR_NOTE). RateGuard alerts iff packets > threshold. Val
            exceedances at each margin (at the proposed, floored thresholds; windows over threshold, by key / device)
            are the honesty check. For context only, the 12b GRE flood level (results/step12b/run_meta.json
            att_streams: per GRE stream packets / (last - first) x 10; per GRE victim the streams' packets over their
            joint span) vs each DEFAULT threshold -- design data, not used to choose. The stated recommendation rule:
            the smallest margin with zero val exceedances across both levels and all three classes.

Outputs -> --out-dir (default results/step13; --dry-run: results/step13/dry_run with Recon-PortScan only):
summary.md, calib_per_session.csv, calib_max_by_level_proto.csv, calib_top_keys.csv, calib_sensitivity_windows.csv,
rate_guard_thresholds_proposed.json, run_meta.json. The log goes to stdout (nohup ... > <out-dir>/run.log).

One run at a time: an exclusive flock on <out-dir>/.13_calib.lock. One tshark at a time.

Exit status: 0 ok, 1 bad input / check failed / another run active, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import bisect
import datetime as dt
import fcntl
import hashlib
import heapq
import importlib.util
import ipaddress as ipa
import json
import math
import os
import resource
import subprocess
import sys
import tempfile
import time
import traceback
from array import array
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import (ATTACKER_MACS, CACHE_DIR, CONFIG_DIR, DATASET, DEVICE_TABLE, NETWORK, REPO_ROOT,
                           RESULTS_DIR, sha256_file)
from rate_guard import STREAM, TCP_UDP, VICTIM, RateGuard, proto_name


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m07a = _load("attack_coverage", "07a_attack_coverage.py")   # Devices (07's device_table mapping + safety check)

SCRIPT = "13_rate_guard_calibrate.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
LABEL = "PROPOSAL ONLY -- thresholds are proposed here, not decided"
RATE_GUARD = REPO_ROOT / "rate_guard.py"
MANIFEST_V1 = RESULTS_DIR / "step8" / "manifest_v1.json"
SPLIT_PLAN = CONFIG_DIR / "split_plan.json"
SPLIT_PLAN_V11 = CONFIG_DIR / "split_plan_v1_1.json"
ATTACK_SET = CONFIG_DIR / "attack_set.json"
ATTACK_PCAPS = CACHE_DIR / "ciciot2023" / "attack"
STEP12B_META = RESULTS_DIR / "step12b" / "run_meta.json"
STEP12C_META = RESULTS_DIR / "step12c" / "run_meta.json"
OUT = RESULTS_DIR / "step13"
DRY_SESSIONS = ["Recon-PortScan"]
RUN_LOCK = ".13_calib.lock"

BENIGN_SESSION = "benign_night"
KEEP_MODES = ("train", "time_split")
SPLITS = ("train", "val")
KEEP_LABELS = ("train", "gap@train|val", "val")       # labels before the val -> test gap
FORBIDDEN = ("benigntraffic1", "benigntraffic2", "benigntraffic3", "ddos-syn_flood10", "ddos-syn_flood15",
             "mirai-udpplain24", "greeth", "test")
WINDOWS = (1, 10, 60)
DESIGN_W = 10
MARGINS = (2, 3, 5)
LEVELS = (STREAM, VICTIM)
CLASSES = ("ICMP", "IGMP", "DEFAULT")
DEFAULT_FLOOR_NOTE = ("floor = ICMP threshold; legitimate VPN tunnels (GRE/ESP) are not represented in this benign data "
                      "-- known limitation")
SCOPES = ("all", "unicast", "mcast_bcast")
MAX_TIES = 3                 # distinct keys listed for a max (all tied windows are counted)
TOP_KEYS = 10                # calib_top_keys.csv rows per (split, level, class)
VAL_KEEP = 5000              # largest 10 s val windows kept per (level, proto) for the exceedance check
MAC_KEEP = 6                 # MACs remembered per key for the device mapping
KEY_CAP = 1_000_000          # keys per capture in the device-mapping maps (spoofed floods); overflow is counted
DRAIN_EVERY = 500_000        # kept packets between pop_counts() drains

TSHARK_PROTOCOLS = "frame,eth,ethertype,ip,vlan"
TSHARK_RESET = 200_000
TSHARK_FIELDS = ("frame.time_epoch", "eth.src", "eth.dst", "ip.src", "ip.dst", "ip.proto")


def log(msg: str) -> None:
    print(f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {msg}", flush=True)


def fatal(msg: str) -> None:
    log(f"FATAL: {msg}")
    sys.exit(1)


def read_json(p: Path) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def write_json(p: Path, obj) -> None:
    p.write_text(json.dumps(obj, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)) + "\n",
                 encoding="utf-8")


def guard(p: Path) -> Path:
    """Never a test / test_only capture, a greeth part or a test split file."""
    name = Path(p).name.lower()
    if any(f in name for f in FORBIDDEN):
        fatal(f"refusing to touch {p}")
    return Path(p)


def utc(epoch: float | None) -> str:
    if epoch is None or not math.isfinite(epoch):
        return ""
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fnum(v, nd: int = 2) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    if isinstance(v, (bool, np.bool_)):
        return str(v)
    if isinstance(v, (float, np.floating)):
        return "inf" if math.isinf(v) else f"{v:,.{nd}f}"
    return f"{v:,}" if isinstance(v, (int, np.integer)) else str(v)


def md_table(rows: list[dict], cols: list[str], nd: int = 2) -> list[str]:
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(r.get(c, "") if isinstance(r.get(c, ""), str) else fnum(r.get(c), nd) for c in cols)
            + " |" for r in rows]
    return out


def peak_rss() -> dict:
    return {"python_self_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
            "tshark_max_mb": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024, 1)}


# --------------------------------------------------------------------------- packet reader (13b imports this)

def tshark_cmd(pcap: Path, display_filter: str | None = None) -> list[str]:
    cmd = ["tshark", "-n", "-M", str(TSHARK_RESET), "--disable-all-protocols", "--enable-protocol", TSHARK_PROTOCOLS,
           "-r", str(pcap)]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f", "-E", "quote=n"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    return cmd


def tshark_ipv4_packets(pcap: Path, display_filter: str | None = None, counts: Counter | None = None):
    """Yield (ts, src_ip, dst_ip, proto, src_mac, dst_mac) -- RateGuard.update()'s argument order -- for every IPv4
    packet of `pcap`: outer header only, streamed line by line from one tshark process (TZ=UTC), file order.
    `counts` (optional) receives frames / non_ipv4 / no_eth / bad_lines. Raises RuntimeError if tshark fails; closing
    the generator early kills tshark."""
    c = counts if counts is not None else Counter()
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(tshark_cmd(pcap, display_filter), stdout=subprocess.PIPE, stderr=errf,
                                env={**os.environ, "TZ": "UTC"}, text=True, encoding="ascii", errors="replace",
                                bufsize=1 << 20)
        try:
            for line in proc.stdout:
                c["frames"] += 1
                f = line.rstrip("\n").split("\t")
                if len(f) != 6:
                    c["bad_lines"] += 1
                    continue
                if not f[3]:
                    c["non_ipv4"] += 1
                    continue
                try:
                    ts, proto = float(f[0]), int(f[5])
                except ValueError:
                    c["bad_lines"] += 1
                    continue
                if not f[1]:
                    c["no_eth"] += 1
                yield ts, f[3], f[4], proto, f[1], f[2]
            rc = proc.wait()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        errf.seek(0)
        err = "\n".join(l for l in errf.read().decode(errors="replace").splitlines()
                        if l.strip() != "resetting session.")
    if rc != 0:
        raise RuntimeError(f"tshark exited {rc} on {pcap}: {err[-1500:]}")
    c["stderr_tail"] = err[-500:]


# --------------------------------------------------------------------------- keys, MACs, destinations

_SUBNET_BCAST = {str(ipa.ip_network(n).broadcast_address) for n in NETWORK.subnets}
_DKIND: dict[str, str] = {}


def dst_kind(ip: str) -> str:
    k = _DKIND.get(ip)
    if k is None:
        try:
            a = ipa.ip_address(ip)
            k = ("broadcast" if ip == "255.255.255.255" or ip in _SUBNET_BCAST
                 else "multicast" if a.is_multicast else "unicast")
        except ValueError:
            k = "unicast"
        _DKIND[ip] = k
    return k


def in_scope(kind: str, scope: str) -> bool:
    return scope == "all" or (kind == "unicast") == (scope == "unicast")


def pclass(proto: int) -> str:
    return "ICMP" if proto == 1 else "IGMP" if proto == 2 else "DEFAULT"


def pname(proto: int) -> str:
    return {6: "TCP", 17: "UDP"}.get(proto) or proto_name(proto)


def key_str(level: str, key: tuple) -> str:
    if level == STREAM:
        return f"{key[0]} -> {key[1]} {proto_name(key[2])}"
    return f"* -> {key[0]} {proto_name(key[1])}"


class MacBook:
    """Per-MAC facts (cached): (exclusion reason, phone / laptop) and a device label."""

    def __init__(self, dev):
        self.dev = dev
        self._c: dict[str, tuple[str, bool]] = {}

    def get(self, mac: str) -> tuple[str, bool]:
        r = self._c.get(mac)
        if r is None:
            role = self.dev.role.get(mac)
            excl = ("ATTACKER_MACS" if mac and ATTACKER_MACS.matches(mac)
                    else "device_table testbed_pi" if role == "testbed_pi" else "")
            r = self._c[mac] = (excl, role == "excluded")
        return r

    def label(self, mac: str) -> str:
        if not mac:
            return "(no eth)"
        if mac == "ff:ff:ff:ff:ff:ff":
            return "broadcast"
        if not m07a.mac_is_unicast(mac):
            return f"multicast {mac}"
        name, role = self.dev.name.get(mac), self.dev.role.get(mac)
        if name is None:
            return f"attacker {mac}" if ATTACKER_MACS.matches(mac) else f"unlisted {mac}"
        return name if role == "iot" else f"{name} [{role}]"


def remember(d: dict, key: tuple, a: str, b: str) -> bool:
    """Add MACs a / b to key's two small sets; returns False if the key is new and the map is full (KEY_CAP)."""
    m = d.get(key)
    if m is None:
        if len(d) >= KEY_CAP:
            return False
        d[key] = ({a}, {b})
        return True
    for s, x in ((m[0], a), (m[1], b)):
        if x not in s and len(s) < MAC_KEEP:
            s.add(x)
    return False


# --------------------------------------------------------------------------- aggregation

class Agg:
    """Streaming reduction of the drained WindowCount records (bounded: per-group count arrays, maxima, per-key
    summaries, a capped heap of the largest val windows)."""

    def __init__(self, book: MacBook):
        self.book = book
        self.counts: dict[tuple, array] = {}         # (split, w, level, proto, dkind) -> packets per non-empty window
        self.best: dict[tuple, list] = {}            # same -> [max, [rec of a distinct key, ...], tied windows]
        self.max_wo: dict[tuple, int] = {}           # (split, level, proto, dkind) -> max without phone packets
        self.keys: dict[tuple, list] = {}            # (split, level, session, key) -> [windows, packets, best rec]
        self.val: dict[tuple, list] = defaultdict(list)   # (level, proto) -> min-heap (packets, seq, rec), 10 s val
        self.val_dropped: Counter = Counter()
        self.seq = 0
        self.maps: dict[str, tuple[dict, dict]] = {}  # session -> (stream key -> MACs, victim key -> MACs)

    def add(self, session: str, split: str, w: int, recs: list, phone: Counter) -> dict:
        sums = Counter()
        for r in recs:
            key = (r.src_ip, r.dst_ip, r.proto) if r.level == STREAM else (r.dst_ip, r.proto)
            dk = dst_kind(r.dst_ip)
            g = (split, w, r.level, r.proto, dk)
            sums[r.level] += r.packets
            a = self.counts.get(g)
            if a is None:
                a = self.counts[g] = array("I")
            a.append(r.packets)
            ph = 0
            if w == DESIGN_W:
                ph = phone.get((split, round(r.window_start / w), r.level, key), 0)
            rec = (r.packets, session, r.window_start, key, r.first_seen_ts, r.last_seen_ts, ph, r.level)
            b = self.best.get(g)
            if b is None or r.packets > b[0]:
                self.best[g] = [r.packets, [rec], 1]
            elif r.packets == b[0]:
                b[2] += 1
                if len(b[1]) < MAX_TIES and all((x[1], x[3]) != (session, key) for x in b[1]):
                    b[1].append(rec)
            if w != DESIGN_W:
                continue
            k = (split, r.level, r.proto, dk)
            if r.packets - ph > self.max_wo.get(k, -1):
                self.max_wo[k] = r.packets - ph
            kk = (split, r.level, session, key)
            e = self.keys.get(kk)
            if e is None:
                self.keys[kk] = [1, r.packets, rec]
            else:
                e[0] += 1
                e[1] += r.packets
                if r.packets > e[2][0]:
                    e[2] = rec
            if split == "val":
                h = self.val[(r.level, r.proto)]
                self.seq += 1
                if len(h) < VAL_KEEP:
                    heapq.heappush(h, (r.packets, self.seq, rec))
                else:
                    self.val_dropped[(r.level, r.proto)] += 1
                    heapq.heappushpop(h, (r.packets, self.seq, rec))
        return sums

    def groups(self, split: str, w: int, level: str, cls: str | None = None, proto: int | None = None,
               scope: str = "all") -> list[tuple]:
        return [g for g in self.counts if g[0] == split and g[1] == w and g[2] == level
                and (cls is None or pclass(g[3]) == cls) and (proto is None or g[3] == proto)
                and in_scope(g[4], scope)]

    def stats(self, split: str, w: int, level: str, cls: str | None = None, proto: int | None = None,
              scope: str = "all") -> dict:
        gs = self.groups(split, w, level, cls, proto, scope)
        if not gs:
            return {"windows": 0, "max": 0, "p99": math.nan, "p99_9": math.nan, "max_rate_pps": 0.0, "recs": [],
                    "tied": 0, "max_wo_phone": 0}
        x = np.concatenate([np.frombuffer(self.counts[g], dtype=np.dtype(f"u{self.counts[g].itemsize}"))
                            for g in gs])
        mx = int(x.max())
        p99, p999 = np.percentile(x, [99, 99.9], method="inverted_cdf")
        top = [g for g in gs if self.best[g][0] == mx]
        recs = sorted((r for g in top for r in self.best[g][1]), key=lambda r: (r[2], r[1], str(r[3])))[:MAX_TIES]
        out = {"windows": int(len(x)), "max": mx, "p99": float(p99), "p99_9": float(p999), "max_rate_pps": mx / w,
               "recs": recs, "tied": sum(self.best[g][2] for g in top), "max_wo_phone": None}
        if w == DESIGN_W:
            out["max_wo_phone"] = max(self.max_wo.get((g[0], g[2], g[3], g[4]), 0) for g in gs)
        return out

    def describe(self, level: str, session: str, key: tuple) -> dict:
        sm, vm = self.maps.get(session, ({}, {}))
        lab = self.book.label
        if level == STREAM:
            src, dst, proto = key
            m = sm.get(key, (set(), set()))
            senders, receivers = m[0], m[1]
        else:
            (dst, proto), src = key, ""
            m = vm.get(key, (set(), set()))
            receivers, senders = m[0], m[1]
        fmt = lambda s: "; ".join(sorted(lab(x) for x in s)) + (" (+more)" if len(s) >= MAC_KEEP else "")
        return {"key": key_str(level, key), "src_ip": src, "dst_ip": dst, "proto": proto,
                "proto_name": proto_name(proto), "dst_kind": dst_kind(dst), "senders": fmt(senders),
                "receivers": fmt(receivers)}

    def rec_row(self, rec: tuple) -> dict:
        packets, session, start, key, first, last, ph, level = rec
        d = self.describe(level, session, key)
        return {"session": session, **d, "packets": packets, "window_start_utc": utc(start),
                "first_seen_utc": utc(first), "last_seen_utc": utc(last), "phone_packets": ph}


# --------------------------------------------------------------------------- inputs

def check_inputs(sessions_wanted: list[str] | None, M: dict) -> list[dict]:
    checks = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail})
        if not ok:
            log(f"  CHECK FAIL {name}: {detail}")

    man = read_json(MANIFEST_V1)
    plan_sha = sha256_file(SPLIT_PLAN)
    v11 = read_json(SPLIT_PLAN_V11)
    aset = read_json(ATTACK_SET)
    check("manifest_v1 hard_pass", man.get("hard_pass") is True, f"{MANIFEST_V1.relative_to(REPO_ROOT)}")
    check("manifest split plan == config/split_plan.json", man["config"]["split_plan"]["sha256"] == plan_sha,
          f"{plan_sha[:16]}...")
    check("split_plan_v1_1 base plan == config/split_plan.json", v11["base_plan"]["sha256"] == plan_sha,
          f"{v11['base_plan']['sha256'][:16]}...")
    check("manifest device_table == config/device_table.csv",
          man["config"]["device_table"]["sha256"] == sha256_file(DEVICE_TABLE), str(DEVICE_TABLE.name))
    check("manifest attack_set == config/attack_set.json",
          man["config"]["attack_set"]["sha256"] == sha256_file(ATTACK_SET), str(ATTACK_SET.name))
    rows = {r["session"]: r for r in man["sessions"]}
    for s, r in rows.items():
        check(f"{s}: mode manifest == split_plan_v1_1", v11["sessions"].get(s) == r["mode"],
              f"{r['mode']} vs {v11['sessions'].get(s)}")
    for s, m in v11["sessions"].items():
        if s not in rows and m in KEEP_MODES:
            check(f"{s}: train / val session missing from manifest_v1", False, m)
    inputs = {r["session"]: r for r in man["inputs"]}
    by_stem = {Path(e["path"]).stem: e for e in aset["pcaps"]}
    keep = [s for s, r in rows.items() if r["mode"] in KEEP_MODES]
    if sessions_wanted:
        bad = [s for s in sessions_wanted if s not in keep]
        if bad:
            fatal(f"--sessions {bad} are not train / val sessions (allowed: {keep})")
        keep = [s for s in keep if s in sessions_wanted]
    out = []
    for s in keep:
        cuts = man["session_cuts"][s]
        labels, bounds = cuts["splits"], [float(x) for x in cuts["boundaries_epoch"]]
        check(f"{s}: cut labels", len(labels) == len(bounds) + 1 and labels[0] == "train"
              and bounds == sorted(bounds), f"{labels} / {bounds}")
        stop = None
        for i, lab in enumerate(labels):
            if lab not in KEEP_LABELS:
                stop = bounds[i - 1]
                break
        if rows[s]["mode"] == "time_split":
            check(f"{s}: time_split has a val -> test cut", stop is not None and labels[i] == "gap@val|test",
                  f"stop {stop}")
        if s == BENIGN_SESSION:
            pcap, sha, kind = DATASET.benign_pcap_cached, DATASET.benign_pcap_sha256, "benign"
        else:
            e = by_stem[s]
            pcap, sha, kind = ATTACK_PCAPS / e["path"], e["sha256"], "attack"
            check(f"{s}: 07 label report pcap == attack set",
                  inputs[s]["label_report"]["completion_key"]["pcap_sha256"] == sha, f"{sha[:16]}...")
        out.append({"session": s, "mode": rows[s]["mode"], "kind": kind, "pcap": guard(pcap),
                    "sha256_expected": sha, "labels": labels, "bounds": bounds, "stop": stop,
                    "display_filter": f"frame.time_epoch < {stop:.6f}" if stop is not None else None,
                    "boundaries_utc": cuts["boundaries_utc"]})
    M["input_checks"] = checks
    if not all(c["pass"] for c in checks):
        fatal("input checks failed (see above)")
    return out


def gre_design() -> dict:
    """12b pilot (base part) GRE streams: average packets per 10 s over each stream's span -- design data only."""
    R = read_json(STEP12B_META)
    st = [s for s in R["packets"]["att_streams"] if str(s[2]) == "47"]
    if not st:
        fatal(f"{STEP12B_META}: no GRE streams in packets.att_streams")
    per = [s[3] / (s[5] - s[4]) * DESIGN_W for s in st if s[5] > s[4]]
    vic = defaultdict(lambda: [0, math.inf, -math.inf])
    for s in st:
        v = vic[s[1]]
        v[0] += s[3]
        v[1], v[2] = min(v[1], s[4]), max(v[2], s[5])
    vper = {d: n / (hi - lo) * DESIGN_W for d, (n, lo, hi) in vic.items() if hi > lo}
    return {"source": str(STEP12B_META.relative_to(REPO_ROOT)), "pcap_sha256": R["pcap"]["sha256"],
            "label": "design data, not used to choose",
            "method": "per GRE stream (src, dst, 47): packets / (last - first) x 10 s; per GRE victim (dst, 47): the "
                      "streams' packets / (latest last - earliest first) x 10 s. Averages over the span, not "
                      "per-window maxima.",
            "streams": len(per), "stream_min_10s": min(per), "stream_median_10s": float(np.median(per)),
            "stream_max_10s": max(per), "victims": {d: round(v, 1) for d, v in vper.items()},
            "victim_min_10s": min(vper.values()), "victim_median_10s": float(np.median(list(vper.values())))}


# --------------------------------------------------------------------------- one capture

class SplitState:
    def __init__(self):
        self.guards = {w: RateGuard(window_s=w, record_counts=True) for w in WINDOWS}
        self.c = Counter()
        self.by_proto = Counter()
        self.excl = Counter()
        self.excl_mac = Counter()
        self.excl_proto = Counter()
        self.drained = Counter()          # (w, level) -> packets in drained records
        self.t = [math.inf, -math.inf]


def run_session(S: dict, agg: Agg, book: MacBook) -> dict:
    s, pcap = S["session"], S["pcap"]
    t0 = time.monotonic()
    log(f"== {s} ({S['mode']}, {S['kind']}): {pcap}")
    got = sha256_file(pcap)
    if got != S["sha256_expected"]:
        fatal(f"{pcap} sha256 {got} != expected {S['sha256_expected']}")
    log(f"  sha256 ok ({got[:16]}...) in {time.monotonic() - t0:.0f} s; filter: {S['display_filter'] or 'none'}")
    bounds, labels, stop = S["bounds"], S["labels"], S["stop"]
    states = {sp: SplitState() for sp in SPLITS}
    sm, vm = {}, {}
    agg.maps[s] = (sm, vm)
    phone = Counter()        # (split, 10 s window index, level, key) -> phone / laptop packets
    gap, rc = Counter(), Counter()
    kept = 0
    get = book.get

    def drain(final: bool) -> None:
        for sp, st in states.items():
            for w, g in st.guards.items():
                if final:
                    g.flush()
                for lv, n in agg.add(s, sp, w, g.pop_counts(), phone).items():
                    st.drained[(w, lv)] += n

    t1 = time.monotonic()
    try:
        for ts, src, dst, proto, smac, dmac in tshark_ipv4_packets(pcap, S["display_filter"], rc):
            if stop is not None and ts >= stop:
                fatal(f"{s}: packet at {ts} >= val -> test cut {stop}: the tshark filter failed")
            lab = labels[bisect.bisect_right(bounds, ts)]
            st = states.get(lab)
            if st is None:
                gap[lab] += 1
                continue
            st.c["ipv4"] += 1
            ms, md = get(smac), get(dmac)
            if ms[0] or md[0]:
                reason = f"eth.src {ms[0]}" if ms[0] else f"eth.dst {md[0]}"
                st.excl[reason] += 1
                st.excl_mac[smac if ms[0] else dmac] += 1
                st.excl_proto[proto] += 1
                if proto not in TCP_UDP:
                    st.excl[f"in_scope {reason}"] += 1
                continue
            if ts < st.t[0]:
                st.t[0] = ts
            if ts > st.t[1]:
                st.t[1] = ts
            if proto in TCP_UDP:
                st.c["tcp_udp"] += 1
            else:
                st.by_proto[proto] += 1
                skey, vkey = (src, dst, proto), (dst, proto)
                if not remember(sm, skey, smac, dmac):
                    rc["map_overflow_stream"] += 1
                if not remember(vm, vkey, dmac, smac):
                    rc["map_overflow_victim"] += 1
                if ms[1] or md[1]:
                    k10 = math.floor(ts / DESIGN_W)
                    st.c["phone_in_scope"] += 1
                    phone[(lab, k10, STREAM, skey)] += 1
                    phone[(lab, k10, VICTIM, vkey)] += 1
            for g in st.guards.values():
                g.update(ts, src, dst, proto, smac, dmac)
            kept += 1
            if kept % DRAIN_EVERY == 0:
                drain(False)
                if kept % (20 * DRAIN_EVERY) == 0:
                    log(f"  {kept:,} kept packets, {rc['frames']:,} frames, {time.monotonic() - t1:.0f} s")
    except RuntimeError as e:
        fatal(str(e))
    drain(True)
    tshark_s = time.monotonic() - t1

    checks, rows = [], []
    for sp, st in states.items():
        in_scope_n = sum(st.by_proto.values())
        for w, g in st.guards.items():
            gs = g.stats()
            ok = (gs["packets_seen"] == st.c["ipv4"] - sum(v for k, v in st.excl.items() if not k.startswith("in_scope"))
                  and gs["packets_in_scope"] == in_scope_n
                  and st.drained[(w, STREAM)] == st.drained[(w, VICTIM)] == in_scope_n - gs["late_packets"])
            checks.append({"check": f"{s} {sp} {w} s: guard counts == packets fed, drained == in scope - late",
                           "pass": ok, "detail": f"seen {gs['packets_seen']:,}, in scope {gs['packets_in_scope']:,} "
                                                 f"/ {in_scope_n:,}, drained stream {st.drained[(w, STREAM)]:,} victim "
                                                 f"{st.drained[(w, VICTIM)]:,}, late {gs['late_packets']:,}"})
            st.c[f"windows_{w}s"] = gs["windows_closed"]
            st.c[f"late_{w}s"] = gs["late_packets"]
            st.c[f"max_active_keys_{w}s"] = gs["max_active_keys"]
        excl_n = sum(v for k, v in st.excl.items() if not k.startswith("in_scope"))
        rows.append({
            "session": s, "mode": S["mode"], "kind": S["kind"], "split": sp, "ipv4_packets": st.c["ipv4"],
            "excluded_packets": excl_n,
            "excluded_in_scope": sum(v for k, v in st.excl.items() if k.startswith("in_scope")),
            "excluded_by_reason": "; ".join(f"{k}: {v:,}" for k, v in sorted(st.excl.items())
                                            if not k.startswith("in_scope")),
            "excluded_by_proto": "; ".join(f"{pname(p)}: {v:,}" for p, v in st.excl_proto.most_common()),
            "excluded_by_mac": "; ".join(f"{book.label(m)} ({m}): {v:,}" for m, v in st.excl_mac.most_common()),
            "kept_packets": st.c["ipv4"] - excl_n, "tcp_udp_packets": st.c["tcp_udp"],
            "in_scope_packets": sum(st.by_proto.values()),
            "in_scope_ICMP": st.by_proto[1], "in_scope_IGMP": st.by_proto[2],
            "in_scope_DEFAULT": sum(v for p, v in st.by_proto.items() if pclass(p) == "DEFAULT"),
            "in_scope_by_proto": "; ".join(f"{proto_name(p)}: {v:,}" for p, v in st.by_proto.most_common()),
            "phone_in_scope": st.c["phone_in_scope"],
            "windows_1s": st.c["windows_1s"], "windows_10s": st.c["windows_10s"], "windows_60s": st.c["windows_60s"],
            "late_10s": st.c["late_10s"], "first_packet_utc": utc(st.t[0]), "last_packet_utc": utc(st.t[1]),
            "gap_packets_dropped": sum(gap.values()), "non_ipv4_frames": rc["non_ipv4"], "frames_read": rc["frames"],
            "tshark_s": round(tshark_s, 1), "runtime_s": round(time.monotonic() - t0, 1)})
    if not all(c["pass"] for c in checks):
        for c in checks:
            if not c["pass"]:
                log(f"  CHECK FAIL {c['check']}: {c['detail']}")
        fatal(f"{s}: guard consistency checks failed")
    for r in rows:
        log(f"  {r['split']:<5} ipv4 {r['ipv4_packets']:>12,}  excluded {r['excluded_packets']:>12,}  in scope "
            f"{r['in_scope_packets']:>9,} ({r['in_scope_by_proto'] or '-'})  10 s windows {r['windows_10s']:,}")
    log(f"  gap dropped {sum(gap.values()):,}, non-IPv4 {rc['non_ipv4']:,}, bad lines {rc['bad_lines']:,}, "
        f"tshark+loop {tshark_s:.0f} s, {rc['frames'] / max(tshark_s, 1e-9):,.0f} frames/s, keys {len(sm):,} stream "
        f"/ {len(vm):,} victim, rss {peak_rss()}")
    return {"rows": rows, "checks": checks,
            "meta": {"session": s, "mode": S["mode"], "kind": S["kind"], "pcap": str(pcap), "pcap_sha256": got,
                     "sha256_match": True, "cut_labels": labels, "boundaries_epoch": bounds,
                     "boundaries_utc": S["boundaries_utc"], "tshark_display_filter": S["display_filter"],
                     "tshark_cmd": " ".join(tshark_cmd(pcap, S["display_filter"])),
                     "reader_counts": {k: v for k, v in rc.items()}, "gap_dropped": dict(gap),
                     "stream_keys": len(sm), "victim_keys": len(vm), "tshark_s": round(tshark_s, 1),
                     "runtime_s": round(time.monotonic() - t0, 1)}}


# --------------------------------------------------------------------------- tables

def max_rows(agg: Agg) -> list[dict]:
    rows = []
    for sp in SPLITS:
        for lv in LEVELS:
            protos = sorted({g[3] for g in agg.counts if g[0] == sp and g[2] == lv})
            items = [(c, None) for c in CLASSES] + [(pclass(p), p) for p in protos if pclass(p) == "DEFAULT"]
            for cls, p in items:
                for sc in SCOPES:
                    st = agg.stats(sp, DESIGN_W, lv, cls, p, sc)
                    if sc != "all" and not st["windows"]:
                        continue
                    rows.append(stat_row(agg, sp, DESIGN_W, lv, cls, p, sc, st))
    return rows


def stat_row(agg: Agg, sp: str, w: int, lv: str, cls: str, p: int | None, sc: str, st: dict) -> dict:
    R = [agg.rec_row(r) for r in st["recs"]]
    return {"split": sp, "window_s": w, "level": lv, "proto_class": cls,
            "proto": "all" if p is None else f"{p} ({proto_name(p)})", "dst_scope": sc,
            "nonempty_windows": st["windows"], "max_packets": st["max"], "p99": st["p99"], "p99_9": st["p99_9"],
            "max_rate_pps": st["max_rate_pps"], "windows_at_max": st["tied"],
            "max_phone_packets": max((r["phone_packets"] for r in R), default=0) if w == DESIGN_W else None,
            "max_without_phone": st["max_wo_phone"],
            "max_keys": " | ".join(r["key"] for r in R), "max_dst_kind": " | ".join(r["dst_kind"] for r in R),
            "max_senders": " | ".join(r["senders"] for r in R), "max_receivers": " | ".join(r["receivers"] for r in R),
            "max_session": " | ".join(r["session"] for r in R),
            "max_window_start_utc": " | ".join(r["window_start_utc"] for r in R),
            "max_first_seen_utc": " | ".join(r["first_seen_utc"] for r in R),
            "max_last_seen_utc": " | ".join(r["last_seen_utc"] for r in R)}


def sens_rows(agg: Agg) -> list[dict]:
    rows = []
    for sp in SPLITS:
        for lv in LEVELS:
            for cls in CLASSES:
                ref = agg.stats(sp, DESIGN_W, lv, cls)["max_rate_pps"]
                for w in WINDOWS:
                    r = stat_row(agg, sp, w, lv, cls, None, "all", agg.stats(sp, w, lv, cls))
                    r["max_rate_vs_10s"] = r["max_rate_pps"] / ref if ref else math.nan
                    rows.append(r)
    return rows


def top_key_rows(agg: Agg) -> list[dict]:
    rows = []
    for sp in SPLITS:
        for lv in LEVELS:
            for cls in CLASSES:
                es = [(kk, e) for kk, e in agg.keys.items() if kk[0] == sp and kk[1] == lv
                      and pclass(kk[3][-1]) == cls]
                es.sort(key=lambda x: (-x[1][2][0], x[0][2], str(x[0][3])))
                for i, (kk, e) in enumerate(es[:TOP_KEYS], 1):
                    rr = agg.rec_row(e[2])
                    rows.append({"split": sp, "level": lv, "proto_class": cls, "rank": i, "session": kk[2],
                                 "key": rr["key"], "src_ip": rr["src_ip"], "dst_ip": rr["dst_ip"],
                                 "proto": rr["proto"], "dst_kind": rr["dst_kind"],
                                 "max_packets_10s": e[2][0], "max_rate_pps": e[2][0] / DESIGN_W,
                                 "max_window_start_utc": rr["window_start_utc"], "first_seen_utc": rr["first_seen_utc"],
                                 "last_seen_utc": rr["last_seen_utc"], "nonempty_windows": e[0], "packets_total": e[1],
                                 "phone_packets_in_max": rr["phone_packets"],
                                 "senders": rr["senders"], "receivers": rr["receivers"]})
    return rows


def val_exceed(agg: Agg, lv: str, cls: str, thr: int) -> dict:
    hs = [(k, h) for k, h in agg.val.items() if k[0] == lv and pclass(k[1]) == cls]
    items = sorted((it for _, h in hs for it in h if it[0] > thr), key=lambda it: (-it[0], it[1]))
    lower = any(agg.val_dropped[k] and h and h[0][0] > thr for k, h in hs)
    R = [agg.rec_row(it[2]) for it in items]
    keys = Counter((r["session"], r["key"]) for r in R)
    devs = Counter(r["senders"] for r in R)
    return {"windows": len(items), "windows_is_lower_bound": lower, "distinct_keys": len(keys),
            "by_key": [{"session": s, "key": k, "windows": n} for (s, k), n in keys.most_common(10)],
            "by_sender_devices": [{"senders": d, "windows": n} for d, n in devs.most_common(10)],
            "top": [{k: r[k] for k in ("session", "key", "packets", "window_start_utc", "senders", "receivers",
                                       "dst_kind", "phone_packets")} for r in R[:10]]}


def proposal(agg: Agg, gre: dict) -> dict:
    basis = {}
    for lv in LEVELS:
        basis[lv] = {}
        for cls in CLASSES:
            st = agg.stats("train", DESIGN_W, lv, cls)
            sv = agg.stats("val", DESIGN_W, lv, cls)
            basis[lv][cls] = {"train_max": st["max"], "train_p99_9": st["p99_9"], "train_windows": st["windows"],
                              "train_max_keys": [agg.rec_row(r)["key"] for r in st["recs"]],
                              "val_max": sv["max"], "val_windows": sv["windows"],
                              "val_over_train_max": sv["max"] / st["max"] if st["max"] else math.inf if sv["max"]
                              else math.nan}
        protos = sorted({g[3] for g in agg.groups("train", DESIGN_W, lv, "DEFAULT")})
        basis[lv]["DEFAULT"]["per_proto_train_max"] = {
            f"{p} ({proto_name(p)})": agg.stats("train", DESIGN_W, lv, None, p)["max"] for p in protos}
    margins = {}
    for m in MARGINS:
        raw = {lv: {cls: int(m * basis[lv][cls]["train_max"]) for cls in CLASSES} for lv in LEVELS}
        T = {lv: {**raw[lv], "DEFAULT": max(raw[lv]["DEFAULT"], raw[lv]["ICMP"])} for lv in LEVELS}
        exc = {lv: {cls: val_exceed(agg, lv, cls, T[lv][cls]) for cls in CLASSES} for lv in LEVELS}
        # None = threshold 0 (only if the ICMP floor is 0 too): any packet alerts, the factor is undefined
        gre_f = {f"{lv}_{q}": gre[f"{lv}_{q}_10s"] / T[lv]["DEFAULT"] if T[lv]["DEFAULT"] else None
                 for lv in LEVELS for q in ("min", "median")}
        margins[f"{m}x"] = {
            "margin": m, "thresholds": T, "thresholds_raw": raw,
            "default_floored": {lv: T[lv]["DEFAULT"] > raw[lv]["DEFAULT"] for lv in LEVELS},
            "default_floor_note": DEFAULT_FLOOR_NOTE,
            "rate_guard_kwargs": {"window_s": float(DESIGN_W), "stream_threshold": T[STREAM]["DEFAULT"],
                                  "victim_threshold": T[VICTIM]["DEFAULT"],
                                  "stream_proto_thresholds": {"1": T[STREAM]["ICMP"], "2": T[STREAM]["IGMP"]},
                                  "victim_proto_thresholds": {"1": T[VICTIM]["ICMP"], "2": T[VICTIM]["IGMP"]}},
            "val_exceedances": exc,
            "val_exceedance_windows_total": sum(exc[lv][c]["windows"] for lv in LEVELS for c in CLASSES),
            "gre_design_factor": gre_f}
    clean = [m for m in MARGINS if margins[f"{m}x"]["val_exceedance_windows_total"] == 0]
    pick = clean[0] if clean else None
    if pick is not None:
        f = margins[f"{pick}x"]["gre_design_factor"]
        text = (f"Proposal: {pick}x the train max (10 s windows; DEFAULT floored at the ICMP threshold) -- the smallest "
                f"tested margin with zero val exceedances at both levels and all three classes; the 12b GRE flood "
                f"(design data, not used to choose) sits {fnum(f['stream_min'], 1)}x (slowest stream) / "
                f"{fnum(f['victim_min'], 1)}x (smaller victim) above the DEFAULT thresholds.")
    else:
        text = ("No proposal from the rule: every tested margin (2x / 3x / 5x) has val exceedances -- see the "
                "exceedance tables; a larger margin or a per-key exception needs your decision.")
    text += f" Note: {DEFAULT_FLOOR_NOTE}."
    return {"label": LABEL, "window_s": DESIGN_W, "alert_rule": "alert iff packets in a window > threshold",
            "kwargs_note": "rate_guard_kwargs map to RateGuard(...); JSON keys are strings, so convert the "
                           "*_proto_thresholds keys to int",
            "threshold_rule": "int(margin x train max), 10 s windows, all destination kinds pooled; DEFAULT = "
                              "max(int(margin x DEFAULT train max), ICMP threshold of the same level and margin) "
                              "(thresholds_raw = before the floor)",
            "default_floor_note": DEFAULT_FLOOR_NOTE,
            "classes": {"ICMP": "ip.proto 1", "IGMP": "ip.proto 2",
                        "DEFAULT": "every other non-TCP/UDP ip.proto (incl. 47 GRE)"},
            "basis": basis, "margins": margins, "gre_design": gre,
            "recommendation": {"rule": "smallest margin in (2, 3, 5) with zero val exceedances over both levels and "
                                       "all classes", "margin": pick, "text": text}}


# --------------------------------------------------------------------------- summary

def write_summary(out: Path, M: dict, per: list[dict], mx: list[dict], sens: list[dict], tops: list[dict],
                  P: dict, dry: bool) -> None:
    L = [f"# Step 13 -- rate_guard calibration on benign train / val packets ({LABEL})", ""]
    if dry:
        L += [f"**DRY RUN: sessions {', '.join(M['sessions'])} only. The numbers below are a pipeline test, not a "
              "calibration.**", ""]
    L += [f"- run {M['run_utc']}, git HEAD `{M['git_head']}`, {SCRIPT} sha256 `{CODE_SHA256[:16]}...`, rate_guard.py "
          f"sha256 `{M['rate_guard_sha256'][:16]}...`, runtime {fnum(M['runtime_s'], 0)} s, peak RSS python "
          f"{fnum(M['peak_rss']['python_self_mb'], 0)} MB / tshark {fnum(M['peak_rss']['tshark_max_mb'], 0)} MB",
          f"- input checks: {sum(c['pass'] for c in M['input_checks'])}/{len(M['input_checks'])} PASS; guard "
          f"consistency checks: {sum(c['pass'] for c in M['guard_checks'])}/{len(M['guard_checks'])} PASS",
          "- sessions read (train / val only, cuts from results/step8/manifest_v1.json, 08's rule on packet time): "
          + ", ".join(f"{s['session']} ({s['mode']}, filter `{s['tshark_display_filter'] or 'none'}`)"
                      for s in M["session_meta"]),
          "- never opened: DDoS-SYN_Flood10 / 15, Mirai-udpplain24 (test), BenignTraffic1-3 (test_only), any greeth "
          "part, test.parquet; packets at or after the val -> test gap start are dropped inside tshark",
          "- packets: tshark outer-header fields (-E occurrence=f), IPv4 only, no protocol filter; RateGuard per "
          "capture x split x window, TCP / UDP = clock ticks, flush() per capture; percentiles over NON-EMPTY windows "
          "(nearest rank)",
          "- exclusion: EVERY capture (benign_night included) drops packets with an attacker / testbed-Pi MAC on either "
          "side (ATTACKER_MACS or device_table role testbed_pi); phone / laptop packets stay in and are reported as "
          "shares", ""]
    if M.get("cross_check_12c"):
        c = M["cross_check_12c"]
        L += [f"- cross-check vs 12c's benign_night train census (before the Pi exclusion; 12c did not exclude): IPv4 "
              f"{c['ipv4_here']:,} here vs {c['ipv4_12c']:,}; non-TCP/UDP {c['in_scope_here']:,} vs "
              f"{c['in_scope_12c']:,} -> {'MATCH' if c['match'] else 'DIFFER'}", ""]

    L += ["## 1. Per session", ""]
    for sp in SPLITS:
        L += [f"### {sp}", ""]
        L += md_table([r for r in per if r["split"] == sp],
                      ["session", "mode", "ipv4_packets", "excluded_packets", "excluded_in_scope", "kept_packets",
                       "in_scope_packets", "in_scope_by_proto", "phone_in_scope", "windows_10s",
                       "late_10s", "first_packet_utc", "last_packet_utc", "runtime_s"]) + [""]
    L += ["Excluded packets (attacker / testbed-Pi MAC, every capture) by reason, protocol mix and MAC:", ""]
    L += md_table([r for r in per if r["excluded_packets"]],
                  ["session", "split", "excluded_packets", "excluded_by_reason", "excluded_by_proto",
                   "excluded_by_mac"]) + [""]
    L += ["Per capture: " + "; ".join(f"{s['session']} gap dropped {sum(s['gap_dropped'].values()):,}, non-IPv4 "
                                      f"{s['reader_counts'].get('non_ipv4', 0):,}, tshark+loop {fnum(s['tshark_s'], 0)} s"
                                      for s in M["session_meta"]), ""]

    cols = ["proto_class", "proto", "dst_scope", "nonempty_windows", "max_packets", "p99", "p99_9", "max_rate_pps",
            "windows_at_max", "max_keys", "max_senders", "max_receivers", "max_session", "max_window_start_utc"]
    L += ["## 2. Per level x proto (10 s windows)", "",
          "dst_scope: all = pooled; unicast; mcast_bcast = multicast 224.0.0.0/4 + broadcast (flagged separately). "
          f"windows_at_max = windows that reach the max; up to {MAX_TIES} distinct keys are listed (' | '-separated, "
          "same order in every max_* column). Devices from the MACs seen on the key's packets (07 device_table "
          "mapping).", ""]
    for sp in SPLITS:
        for lv in LEVELS:
            L += [f"### {sp} -- {lv}", ""]
            L += md_table([r for r in mx if r["split"] == sp and r["level"] == lv], cols) + [""]

    L += ["## 3. Phones / laptops (randomised MAC, role excluded) -- share of each max", "",
          "Phones stay IN the calibration. max_phone_packets = their packets in the max window(s); max_without_phone = "
          "the max over all windows after removing their packets.", ""]
    L += md_table([r for r in mx if r["dst_scope"] == "all" and r["proto"] == "all"],
                  ["split", "level", "proto_class", "max_packets", "max_phone_packets", "max_without_phone"]) + [""]

    L += ["## Sensitivity: 1 s / 10 s / 60 s windows (all destinations)", "",
          "max_rate_vs_10s = max rate at this window / max rate at 10 s (short windows catch bursts; long ones average).",
          ""]
    for sp in SPLITS:
        L += [f"### {sp}", ""]
        L += md_table([r for r in sens if r["split"] == sp],
                      ["level", "proto_class", "window_s", "nonempty_windows", "max_packets", "p99", "p99_9",
                       "max_rate_pps", "max_rate_vs_10s", "max_keys", "max_senders"]) + [""]

    g = P["gre_design"]
    L += ["## 4. Proposed thresholds (packets per 10 s window; alert iff packets > threshold)", "",
          "threshold = int(margin x TRAIN max), all destination kinds pooled. DEFAULT = every non-TCP/UDP proto other "
          "than ICMP / IGMP (incl. GRE), floored: T = max(raw, ICMP threshold of the same level and margin); raw_ = "
          "before the floor (equal to T for ICMP / IGMP). Val exceedances are counted at T.", "",
          f"**Note: {DEFAULT_FLOOR_NOTE}.**", ""]
    rows = []
    for lv in LEVELS:
        for cls in CLASSES:
            b = P["basis"][lv][cls]
            r = {"level": lv, "class": cls, "train_max": b["train_max"], "train_p99_9": b["train_p99_9"],
                 "val_max": b["val_max"], "val_over_train_max": b["val_over_train_max"]}
            for m in MARGINS:
                e = P["margins"][f"{m}x"]["val_exceedances"][lv][cls]
                r[f"raw_{m}x"] = P["margins"][f"{m}x"]["thresholds_raw"][lv][cls]
                r[f"T_{m}x"] = P["margins"][f"{m}x"]["thresholds"][lv][cls]
                r[f"val_exc_{m}x"] = f"{e['windows']}{'+' if e['windows_is_lower_bound'] else ''} windows / " \
                                     f"{e['distinct_keys']} keys"
            rows.append(r)
    L += md_table(rows, ["level", "class", "train_max", "train_p99_9", "val_max", "val_over_train_max",
                         *[c for m in MARGINS for c in (f"raw_{m}x", f"T_{m}x", f"val_exc_{m}x")]]) + [""]
    per_proto = {lv: P["basis"][lv]["DEFAULT"]["per_proto_train_max"] for lv in LEVELS}
    L += ["DEFAULT train max per proto: " + "; ".join(
        f"{lv}: {', '.join(f'{p} {n:,}' for p, n in d.items()) or 'no packets'}" for lv, d in per_proto.items()), ""]
    L += ["### Val exceedances (the honesty check), by key / device", ""]
    any_exc = False
    for m in MARGINS:
        for lv in LEVELS:
            for cls in CLASSES:
                e = P["margins"][f"{m}x"]["val_exceedances"][lv][cls]
                if e["windows"]:
                    any_exc = True
                    L += [f"**{m}x {lv} {cls}** (threshold {P['margins'][f'{m}x']['thresholds'][lv][cls]:,}): "
                          f"{e['windows']}{'+' if e['windows_is_lower_bound'] else ''} windows, "
                          f"{e['distinct_keys']} keys", ""]
                    L += md_table(e["top"], ["session", "key", "packets", "window_start_utc", "senders", "receivers",
                                             "dst_kind", "phone_packets"]) + [""]
    if not any_exc:
        L += ["No val window exceeds any proposed threshold at any margin.", ""]
    L += [f"### GRE flood level vs the DEFAULT thresholds -- {g['label']}", "",
          f"12b pilot (base part, sha256 `{g['pcap_sha256'][:16]}...`): {g['method']} GRE streams {g['streams']}: "
          f"min {fnum(g['stream_min_10s'], 0)} / median {fnum(g['stream_median_10s'], 0)} packets per 10 s; GRE victims "
          f"{len(g['victims'])}: min {fnum(g['victim_min_10s'], 0)} / median {fnum(g['victim_median_10s'], 0)}.", ""]
    rows = []
    for m in MARGINS:
        mm = P["margins"][f"{m}x"]
        T, R, f = mm["thresholds"], mm["thresholds_raw"], mm["gre_design_factor"]
        rows.append({"margin": f"{m}x", "raw_stream_DEFAULT": R[STREAM]["DEFAULT"], "T_stream_DEFAULT": T[STREAM]["DEFAULT"],
                     "GRE_stream_min / T": f["stream_min"], "GRE_stream_median / T": f["stream_median"],
                     "raw_victim_DEFAULT": R[VICTIM]["DEFAULT"], "T_victim_DEFAULT": T[VICTIM]["DEFAULT"],
                     "GRE_victim_min / T": f["victim_min"], "GRE_victim_median / T": f["victim_median"]})
    L += md_table(rows, ["margin", "raw_stream_DEFAULT", "T_stream_DEFAULT", "GRE_stream_min / T",
                         "GRE_stream_median / T", "raw_victim_DEFAULT", "T_victim_DEFAULT", "GRE_victim_min / T",
                         "GRE_victim_median / T"], 1)
    L += ["", "Factors use the floored T. N/A = T is 0 (only if the ICMP floor is 0 too): any packet alerts.", ""]

    L += ["## 5. Recommendation (proposal only -- you decide)", "", P["recommendation"]["text"], "",
          f"Rule: {P['recommendation']['rule']}. All three margins are in rate_guard_thresholds_proposed.json as "
          "RateGuard keyword arguments.", ""]

    L += ["## Top keys (10 s, top 5 per split x level x class; full list in calib_top_keys.csv)", ""]
    L += md_table([r for r in tops if r["rank"] <= 5],
                  ["split", "level", "proto_class", "rank", "session", "key", "max_packets_10s", "max_window_start_utc",
                   "nonempty_windows", "packets_total", "phone_packets_in_max", "senders", "receivers"]) + [""]
    L += ["## Outputs", "", "summary.md, calib_per_session.csv, calib_max_by_level_proto.csv, calib_top_keys.csv, "
          "calib_sensitivity_windows.csv, rate_guard_thresholds_proposed.json, run_meta.json", ""]
    (out / "summary.md").write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- main

def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.13_calib.lock for the whole run (released by the kernel on exit)."""
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
                    help=f"pipeline test on {', '.join(DRY_SESSIONS)} only -> results/step13/dry_run")
    ap.add_argument("--sessions", nargs="+", default=None, help="subset of the train / val sessions (testing)")
    ap.add_argument("--out-dir", type=Path, default=None, help="default results/step13 (dry run: .../dry_run)")
    args = ap.parse_args()
    t0 = time.monotonic()
    if args.dry_run and args.sessions is None:
        args.sessions = DRY_SESSIONS
    out = args.out_dir or (OUT / "dry_run" if args.dry_run else OUT)
    out = out if out.is_absolute() else REPO_ROOT / out
    dry = bool(args.dry_run or args.sessions)
    lock = run_lock(out)
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...  {LABEL}  -> {out}")
    M = {"label": LABEL, "script": SCRIPT, "code_sha256": CODE_SHA256, "rate_guard_sha256": sha256_file(RATE_GUARD),
         "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "argv": sys.argv, "dry_run": dry,
         "git_head": subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True,
                                    text=True).stdout.strip(),
         "tshark_version": subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.split("\n")[0],
         "windows_s": list(WINDOWS), "design_window_s": DESIGN_W, "margins": list(MARGINS),
         "attacker_macs": {"exact": list(ATTACKER_MACS.exact), "prefixes": list(ATTACKER_MACS.prefixes)},
         "never_opened": "test sessions DDoS-SYN_Flood10 / 15, Mirai-udpplain24; test_only BenignTraffic1-3; greeth "
                         "parts base / 9 / 18 / 27 / 28; test.parquet"}
    S_list = check_inputs(args.sessions, M)
    M["sessions"] = [S["session"] for S in S_list]
    dev = m07a.Devices(DEVICE_TABLE)
    M["device_table_attacker_rows"] = dev.safety_check()
    book = MacBook(dev)
    agg = Agg(book)
    gre = gre_design()

    per, metas, gchecks = [], [], []
    for S in S_list:
        R = run_session(S, agg, book)
        per += R["rows"]
        metas.append(R["meta"])
        gchecks += R["checks"]
    M["session_meta"], M["guard_checks"] = metas, gchecks

    if BENIGN_SESSION in M["sessions"] and STEP12C_META.is_file():
        bp = read_json(STEP12C_META).get("benign_packet_census") or {}
        r = next(r for r in per if r["session"] == BENIGN_SESSION and r["split"] == "train")
        if bp:
            here = r["in_scope_packets"] + r["excluded_in_scope"]      # 12c did not exclude Pi packets
            M["cross_check_12c"] = {"ipv4_here": r["ipv4_packets"], "ipv4_12c": bp["ipv4_packets"],
                                    "in_scope_here": here, "in_scope_12c": bp["non_tcp_udp_packets"],
                                    "match": r["ipv4_packets"] == bp["ipv4_packets"]
                                    and here == bp["non_tcp_udp_packets"],
                                    "note": "12c: same capture and cut, 02's lean dissector set, filter ip && not 6/17, "
                                            "no Pi exclusion; counts here are before the exclusion"}
            log(f"cross-check vs 12c benign_night train census: {M['cross_check_12c']}")

    log("tables + proposal ...")
    mx, sens, tops = max_rows(agg), sens_rows(agg), top_key_rows(agg)
    P = proposal(agg, gre)
    pd.DataFrame(per).to_csv(out / "calib_per_session.csv", index=False, lineterminator="\n")
    pd.DataFrame(mx).to_csv(out / "calib_max_by_level_proto.csv", index=False, lineterminator="\n")
    pd.DataFrame(tops).to_csv(out / "calib_top_keys.csv", index=False, lineterminator="\n")
    pd.DataFrame(sens).to_csv(out / "calib_sensitivity_windows.csv", index=False, lineterminator="\n")
    write_json(out / "rate_guard_thresholds_proposed.json", {"dry_run": dry, **P})
    M["val_heap"] = {"keep_per_level_proto": VAL_KEEP, "dropped": {f"{k[0]} {k[1]}": v for k, v in agg.val_dropped.items()}}
    M["peak_rss"] = peak_rss()
    M["runtime_s"] = round(time.monotonic() - t0, 1)
    write_json(out / "run_meta.json", M)
    write_summary(out, M, per, mx, sens, tops, P, dry)
    log(P["recommendation"]["text"])
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
