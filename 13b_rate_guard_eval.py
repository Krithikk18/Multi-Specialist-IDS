#!/usr/bin/env python
"""13b_rate_guard_eval.py -- evaluate the FROZEN rate guard (config/rate_guard_v1.json) on Mirai greeth_flood captures.

Captures (nothing else is opened; guard() refuses every other name)
  Mirai-greeth_flood.pcap     DESIGN data (already used in 12b / 12c) -- reported in its own section
  Mirai-greeth_flood9.pcap    VALIDATION (first touch)
  Mirai-greeth_flood18.pcap   VALIDATION (first touch)
  Parts 27 / 28 (RESERVED fresh test) are never opened, read, hashed, copied or listed; test.parquet is never opened.

Guards (abort on failure), before any pcap byte is read
  - config/rate_guard_v1.json is tracked in git and its blob == HEAD's blob (unchanged vs HEAD)
  - sha256(rate_guard.py) == rate_guard_sha256 recorded in results/step13/run_meta.json
  then, before any tshark: sha256 of every capture used == its entry in config/sha256_greeth.txt.

Packets  13_rate_guard_calibrate.tshark_ipv4_packets() imported unchanged: outer-header fields (-E occurrence=f), IPv4
         only, no protocol filter (GRE stays outer proto 47), one tshark at a time, streamed line by line.
Guard    one RateGuard(**config args, proto keys -> int) per capture, every IPv4 packet in file order (TCP / UDP =
         clock ticks), flush() at the end of the capture. No packet is excluded: the guard sees what it would see live.
Truth    attacker packet = outer eth.src in config ATTACKER_MACS. Per in-scope (non-TCP/UDP) key, at both guard
         levels: packets, packets with an attacker MAC as eth.src / eth.dst, first / last ts, MACs seen. GRE streams =
         stream keys (src, dst, 47) with attacker-sent packets; attacked victim keys = (dst, 47) receiving attacker GRE.
         Victim device = 07a's Devices.dest_class of the eth.dst carrying most of the attacker GRE, group from
         config/groupings/behaviour_k2.json (as 12b). Attack windows = guard-aligned 10 s windows
         (floor(ts / window_s)) holding >= 1 attacker GRE packet of that key.
Classes  attack = stream key with attacker-sent packets / victim key receiving attacker GRE; benign = key with NO
         attacker-MAC packet (eth.src or eth.dst); other = everything else (e.g. a victim key receiving attacker ICMP,
         a stream towards an attacker).
Criteria (pre-declared, fixed before this run)
  C1 every attacked victim key (dst, 47) raises a victim-level alert, and every GRE attacker stream with >= 1,000
     packets raises a stream-level alert
  C2 first alert for each attacked victim key <= 20 s after that victim's first attacker GRE packet; alert time =
     the capture ts of the clock tick that closed the window (the packet whose update() returned it; window_end if
     flush() emitted it)
  C3 0 alerts on benign keys
  Reported without criteria: share of attack windows alerted, alerts per hour on benign keys, alerts on attacker keys
  that are not GRE.

Outputs -> results/step13b/ (--dry-run: results/step13b/dry_run, base part only): summary.md, alerts.csv,
ground_truth_streams.csv, latency.csv, run_meta.json. The log goes to stdout (... > <out-dir>/run.log).
One run at a time: an exclusive flock on <out-dir>/.13b_eval.lock.

Exit status: 0 ok, 1 bad input / guard or check failed / another run active, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import resource
import shutil
import subprocess
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

from config.config import ATTACKER_MACS, CACHE_DIR, CONFIG_DIR, DATA_RAW, DEVICE_TABLE, REPO_ROOT, RESULTS_DIR, sha256_file
from rate_guard import STREAM, TCP_UDP, VICTIM, RateGuard, proto_name


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m07a = _load("attack_coverage", "07a_attack_coverage.py")   # Devices (07's device_table mapping + safety check)
m13 = _load("rate_guard_calibrate", "13_rate_guard_calibrate.py")   # tshark_ipv4_packets, used unchanged

SCRIPT = "13b_rate_guard_eval.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
CONFIG_REL = "config/rate_guard_v1.json"
CONFIG_JSON = REPO_ROOT / CONFIG_REL
RATE_GUARD = REPO_ROOT / "rate_guard.py"
CALIB = REPO_ROOT / "13_rate_guard_calibrate.py"
STEP13_META = RESULTS_DIR / "step13" / "run_meta.json"
SHA_FILE = CONFIG_DIR / "sha256_greeth.txt"
K2_JSON = CONFIG_DIR / "groupings" / "behaviour_k2.json"
SRC_DIR = DATA_RAW / "ciciot2023" / "Mirai" / "Mirai-greeth_flood"
CACHE = CACHE_DIR / "greeth_eval"
PILOT_COPY = CACHE_DIR / "pilot_greeth" / "Mirai-greeth_flood.pcap"   # 12b's verified cached copy of the base part
OUT = RESULTS_DIR / "step13b"
RUN_LOCK = ".13b_eval.lock"
MIN_FREE_GB = 10.0

BASE = "Mirai-greeth_flood.pcap"
PARTS = {BASE: "DESIGN DATA", "Mirai-greeth_flood9.pcap": "VALIDATION", "Mirai-greeth_flood18.pcap": "VALIDATION"}
DRY_PARTS = [BASE]
GRE = 47
C1_MIN_STREAM_PACKETS = 1_000
C2_MAX_LATENCY_S = 20.0
MAC_KEEP = 6                 # MACs remembered per key and side for the device labels
KEY_CAP = 1_000_000          # in-scope keys per level and capture; more -> STOP (memory)
CRITERIA = {
    "C1": "every attacked victim key (dst_ip, 47) raises a victim-level alert, and every GRE attacker stream with "
          f">= {C1_MIN_STREAM_PACKETS:,} packets raises a stream-level alert",
    "C2": f"first alert for each attacked victim key <= {C2_MAX_LATENCY_S:.0f} s after that victim's first attacker "
          "GRE packet",
    "C3": "0 alerts on keys with NO attacker-MAC packets (benign keys)",
}


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
    """Every capture path goes through here: only the base part and parts 9 / 18."""
    if Path(p).name not in PARTS:
        fatal(f"refusing to touch {p}: only {', '.join(PARTS)} may be used")
    return Path(p)


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True)


def utc(epoch: float | None) -> str:
    if epoch is None or not math.isfinite(epoch):
        return ""
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fnum(v, nd: int = 1) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, float):
        return "inf" if math.isinf(v) else f"{v:,.{nd}f}"
    return f"{v:,}" if isinstance(v, int) else str(v)


def md_table(rows: list[dict], cols: list[str], nd: int = 1) -> list[str]:
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(r.get(c, "") if isinstance(r.get(c, ""), str) else fnum(r.get(c), nd) for c in cols)
            + " |" for r in rows]
    return out


def peak_rss() -> dict:
    return {"python_self_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
            "tshark_max_mb": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024, 1)}


# --------------------------------------------------------------------------- guards + staging

def check_frozen(M: dict) -> dict:
    """Config tracked + unchanged vs HEAD, rate_guard.py == the step13 run; returns RateGuard kwargs."""
    if git("ls-files", "--error-unmatch", CONFIG_REL).returncode != 0:
        fatal(f"{CONFIG_REL} is not tracked in git")
    head_blob = git("rev-parse", f"HEAD:{CONFIG_REL}").stdout.strip()
    work_blob = git("hash-object", CONFIG_REL).stdout.strip()
    if not head_blob or head_blob != work_blob:
        fatal(f"{CONFIG_REL} differs from HEAD (blob {work_blob} vs HEAD {head_blob})")
    want = read_json(STEP13_META)["rate_guard_sha256"]
    got = sha256_file(RATE_GUARD)
    if got != want:
        fatal(f"rate_guard.py sha256 {got} != {STEP13_META.relative_to(REPO_ROOT)} rate_guard_sha256 {want}")
    calib_sha = sha256_file(CALIB)
    C = read_json(CONFIG_JSON)
    args = dict(C["args"])
    for k in ("stream_proto_thresholds", "victim_proto_thresholds"):
        args[k] = {int(p): t for p, t in args[k].items()}
    M["frozen"] = {"config": CONFIG_REL, "config_sha256": sha256_file(CONFIG_JSON), "config_git_blob": head_blob,
                   "config_version": C.get("version"), "config_unchanged_vs_head": True,
                   "rate_guard_sha256": got, "rate_guard_sha256_step13": want, "rate_guard_match": True,
                   "calibrate_sha256": calib_sha,
                   "calibrate_sha256_step13": read_json(STEP13_META)["code_sha256"],
                   "rate_guard_kwargs": {k: ({str(p): t for p, t in v.items()} if isinstance(v, dict) else v)
                                         for k, v in args.items()}}
    log(f"guards ok: {CONFIG_REL} blob {head_blob[:12]} == HEAD; rate_guard.py sha256 {got[:16]}... == step13; "
        f"13 reader sha256 {calib_sha[:16]}... ({'==' if calib_sha == M['frozen']['calibrate_sha256_step13'] else '!='}"
        " step13)")
    return args


def expected_shas() -> dict[str, str]:
    out = {}
    for line in SHA_FILE.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") in PARTS:
            out[parts[1].lstrip("*")] = parts[0].lower()
    return out


def stage(names: list[str], M: dict) -> dict[str, Path]:
    """Copy each part to CACHE (if ~ has room), sha256 the file read == config/sha256_greeth.txt, else STOP.
    All hashes are checked before any tshark runs."""
    want = expected_shas()
    missing = [n for n in names if n not in want]
    if missing:
        fatal(f"{SHA_FILE.name} has no entry for {missing}")
    free_gb = shutil.disk_usage(Path.home()).free / 1e9
    df_h = subprocess.run(["df", "-h", str(Path.home())], capture_output=True, text=True).stdout.strip()
    log(f"df -h ~:\n{df_h}")
    M["disk"] = {"home_free_gb": round(free_gb, 1), "df_h": df_h, "min_free_gb": MIN_FREE_GB}
    out, metas = {}, []
    for n in names:
        src = guard(SRC_DIR / n)
        if not src.is_file():
            fatal(f"not found: {src}")
        t0 = time.monotonic()
        size = src.stat().st_size
        if free_gb - size / 1e9 < MIN_FREE_GB:
            pcap, how = src, f"read in place from /mnt/d ({free_gb:.1f} GB free on ~)"
        elif n == BASE and PILOT_COPY.is_file() and PILOT_COPY.stat().st_size == size:
            pcap, how = guard(PILOT_COPY), "12b cached copy reused"
        else:
            pcap = guard(CACHE / n)
            if pcap.is_file() and pcap.stat().st_size == size:
                how = "cached copy reused"
            else:
                CACHE.mkdir(parents=True, exist_ok=True)
                log(f"copying {n} ({size / 1e9:.2f} GB) -> {pcap}")
                tmp = pcap.with_name(pcap.name + ".part")
                shutil.copyfile(src, tmp)
                tmp.replace(pcap)
                how = "copied to the cache"
                free_gb -= size / 1e9
        copy_s = time.monotonic() - t0
        t1 = time.monotonic()
        got = sha256_file(pcap)
        hash_s = time.monotonic() - t1
        ok = got == want[n]
        log(f"  {n}: {how}; sha256 {got[:16]}... {'==' if ok else '!='} {SHA_FILE.name} ({hash_s:.0f} s)")
        if not ok:
            fatal(f"sha256 of {pcap} {got} != {SHA_FILE.name} entry {want[n]}; STOP")
        out[n] = pcap
        metas.append({"file": n, "role": PARTS[n], "source": str(src), "used_path": str(pcap), "how": how,
                      "size_bytes": size, "sha256": got, "sha256_expected": want[n], "sha256_match": True,
                      "copy_s": round(copy_s, 1), "sha256_s": round(hash_s, 1)})
    M["pcaps"] = metas
    return out


# --------------------------------------------------------------------------- one capture

class Key:
    """Ground truth of one in-scope guard key (stream or victim) over the whole capture."""
    __slots__ = ("n", "att_src", "att_dst", "lo", "hi", "att_lo", "att_hi", "smacs", "dmacs", "att_dmac")

    def __init__(self, ts: float):
        self.n = self.att_src = self.att_dst = 0
        self.lo = self.hi = ts
        self.att_lo, self.att_hi = math.inf, -math.inf
        self.smacs, self.dmacs = set(), set()
        self.att_dmac = Counter()            # eth.dst of attacker-sent packets (victim device)

    def add(self, ts: float, smac: str, dmac: str, a_src: bool, a_dst: bool) -> None:
        self.n += 1
        if ts < self.lo:
            self.lo = ts
        if ts > self.hi:
            self.hi = ts
        if a_src:
            self.att_src += 1
            if ts < self.att_lo:
                self.att_lo = ts
            if ts > self.att_hi:
                self.att_hi = ts
            if dmac in self.att_dmac or len(self.att_dmac) < MAC_KEEP:
                self.att_dmac[dmac] += 1
        if a_dst:
            self.att_dst += 1
        if len(self.smacs) < MAC_KEEP:
            self.smacs.add(smac)
        if len(self.dmacs) < MAC_KEEP:
            self.dmacs.add(dmac)


class Labels:
    def __init__(self, dev, k2: dict):
        self.dev, self.k2 = dev, k2
        self._c: dict[str, tuple[str, str]] = {}

    def get(self, mac: str) -> tuple[str, str]:
        """(device, k2 group / class) of a MAC, as 12b's victim table."""
        r = self._c.get(mac)
        if r is None:
            if not mac:
                r = ("(no eth)", "")
            elif not m07a.mac_is_unicast(mac):
                r = ("broadcast / multicast", "bcast")
            else:
                name, cls = self.dev.dest_class(mac)
                r = (name, self.k2.get(mac, cls))
            self._c[mac] = r
        return r

    def fmt(self, macs) -> str:
        return "; ".join(sorted({f"{self.get(m)[0]} ({self.get(m)[1]})" if self.get(m)[1] else self.get(m)[0]
                                 for m in macs})) + (" (+more)" if len(macs) >= MAC_KEEP else "")


def run_capture(name: str, pcap: Path, gargs: dict, lab: Labels) -> dict:
    t0 = time.monotonic()
    role = PARTS[name]
    log(f"== {name} ({role}): {pcap}")
    g = RateGuard(**gargs)
    w = g.window_s
    att_cache: dict[str, bool] = {}
    streams: dict[tuple, Key] = {}
    victims: dict[tuple, Key] = {}
    vwin: dict[tuple, Counter] = defaultdict(Counter)     # attacked victim key -> window -> attacker GRE packets
    swin: dict[tuple, Counter] = defaultdict(Counter)     # GRE attacker stream -> window -> packets
    alerts: list[tuple] = []                               # (Alert, emitted_ts, emitted_by)
    c, by_proto, att_proto = Counter(), Counter(), Counter()
    rc = Counter()
    t_lo, t_hi = math.inf, -math.inf

    def is_att(mac: str) -> bool:
        r = att_cache.get(mac)
        if r is None:
            r = att_cache[mac] = bool(mac) and ATTACKER_MACS.matches(mac)
        return r

    t1 = time.monotonic()
    try:
        for ts, src, dst, proto, smac, dmac in m13.tshark_ipv4_packets(pcap, None, rc):
            for a in g.update(ts, src, dst, proto, smac, dmac):
                alerts.append((a, ts, "packet"))
            c["ipv4"] += 1
            if ts < t_lo:
                t_lo = ts
            if ts > t_hi:
                t_hi = ts
            a_src, a_dst = is_att(smac), is_att(dmac)
            if a_src:
                c["attacker"] += 1
                att_proto[proto] += 1
            if proto in TCP_UDP:
                continue
            by_proto[proto] += 1
            skey, vkey = (src, dst, proto), (dst, proto)
            st = streams.get(skey)
            if st is None:
                if len(streams) >= KEY_CAP:
                    fatal(f"{name}: more than {KEY_CAP:,} stream keys; STOP")
                st = streams[skey] = Key(ts)
            st.add(ts, smac, dmac, a_src, a_dst)
            vt = victims.get(vkey)
            if vt is None:
                if len(victims) >= KEY_CAP:
                    fatal(f"{name}: more than {KEY_CAP:,} victim keys; STOP")
                vt = victims[vkey] = Key(ts)
            vt.add(ts, smac, dmac, a_src, a_dst)
            if a_src and proto == GRE:
                k = math.floor(ts / w)
                vwin[vkey][k] += 1
                swin[skey][k] += 1
            if c["ipv4"] % 1_000_000 == 0:
                log(f"  {c['ipv4']:,} IPv4 packets, {len(alerts):,} alerts, {time.monotonic() - t1:.0f} s")
    except RuntimeError as e:
        fatal(str(e))
    for a in g.flush():
        alerts.append((a, a.window_end, "flush"))
    tshark_s = time.monotonic() - t1
    gs = g.stats()

    # consistency: the guard saw every IPv4 packet; nothing late should be silently lost
    in_scope = sum(by_proto.values())
    checks = [
        {"check": f"{name}: guard packets_seen == IPv4 packets fed", "pass": gs["packets_seen"] == c["ipv4"],
         "detail": f"{gs['packets_seen']:,} vs {c['ipv4']:,}"},
        {"check": f"{name}: guard packets_in_scope == non-TCP/UDP packets", "pass": gs["packets_in_scope"] == in_scope,
         "detail": f"{gs['packets_in_scope']:,} vs {in_scope:,}"},
        {"check": f"{name}: stream / victim key totals == non-TCP/UDP packets",
         "pass": sum(k.n for k in streams.values()) == sum(k.n for k in victims.values()) == in_scope,
         "detail": f"{sum(k.n for k in streams.values()):,} / {sum(k.n for k in victims.values()):,} vs {in_scope:,}"},
        {"check": f"{name}: guard alerts == alerts collected", "pass": gs["alerts"] == len(alerts),
         "detail": f"{gs['alerts']:,} vs {len(alerts):,}"},
    ]
    if not all(x["pass"] for x in checks):
        for x in checks:
            if not x["pass"]:
                log(f"  CHECK FAIL {x['check']}: {x['detail']}")
        fatal(f"{name}: consistency checks failed")

    # ---- classify alerts
    def kclass(level: str, key: tuple, proto: int) -> str:
        K = streams[key] if level == STREAM else victims[key]
        if level == STREAM and K.att_src:
            return "attack"
        if level == VICTIM and proto == GRE and K.att_src:
            return "attack"
        return "benign" if not (K.att_src or K.att_dst) else "other"

    def victim_device(K: Key) -> tuple[str, str]:
        macs = K.att_dmac or Counter({m: 0 for m in K.dmacs})
        mac = max(sorted(macs), key=lambda m: macs[m]) if macs else ""
        return lab.get(mac)

    arows = []
    for a, ets, eby in alerts:
        key = (a.src_ip, a.dst_ip, a.proto) if a.level == STREAM else (a.dst_ip, a.proto)
        K = streams[key] if a.level == STREAM else victims[key]
        cls = kclass(a.level, key, a.proto)
        dev, grp = victim_device(victims[(a.dst_ip, a.proto)])
        att_in_win = (swin if a.level == STREAM else vwin).get(key, {}).get(round(a.window_start / w), 0)
        arows.append({
            "capture": name, "role": role, "level": a.level, "key_class": cls,
            "src_ip": a.src_ip or "", "dst_ip": a.dst_ip, "proto": a.proto, "proto_name": a.proto_name,
            "window_start": a.window_start, "window_end": a.window_end, "window_start_utc": utc(a.window_start),
            "window_end_utc": utc(a.window_end),
            "packets": a.packets, "threshold": a.threshold, "rate_pps": a.rate_pps,
            "attacker_gre_packets_in_window": att_in_win,
            "first_seen_utc": utc(a.first_seen_ts), "last_seen_utc": utc(a.last_seen_ts),
            "emitted_ts": ets, "emitted_utc": utc(ets), "emitted_by": eby,
            "key_packets_total": K.n, "key_attacker_src_packets": K.att_src, "key_attacker_dst_packets": K.att_dst,
            "dst_device": dev, "dst_group": grp, "senders": lab.fmt(K.smacs), "receivers": lab.fmt(K.dmacs),
            "alert_src_macs": " ".join(a.src_macs)})

    # ---- ground truth: GRE attacker streams, attacked victims
    first_alert: dict[tuple, dict] = {}
    alerted_win: dict[tuple, set] = defaultdict(set)
    for r in arows:
        key = (r["level"], r["src_ip"], r["dst_ip"], r["proto"])
        alerted_win[key].add(round(r["window_start"] / w))
        if key not in first_alert or r["emitted_ts"] < first_alert[key]["emitted_ts"]:
            first_alert[key] = r

    def win_stats(att: Counter, alerted: set) -> dict:
        ks = sorted(att)
        un = [k for k in ks if k not in alerted]
        edge = {ks[0], ks[-1]} if ks else set()
        return {"attack_windows": len(ks), "alerted_windows": len(ks) - len(un),
                "share_alerted": (len(ks) - len(un)) / len(ks) if ks else math.nan,
                "unalerted_windows": len(un), "unalerted_edge_windows": sum(k in edge for k in un),
                "unalerted_interior_windows": sum(k not in edge for k in un),
                "unalerted_max_attacker_packets": max((att[k] for k in un), default=0)}

    gt = []
    for (src, dst, proto), K in sorted(streams.items(), key=lambda kv: (-kv[1].att_src, kv[0])):
        if proto != GRE or not K.att_src:
            continue
        fa = first_alert.get((STREAM, src, dst, proto))
        dev, grp = victim_device(victims[(dst, proto)])
        ws = win_stats(swin[(src, dst, proto)], alerted_win[(STREAM, src, dst, proto)])
        gt.append({"capture": name, "role": role, "src_ip": src, "dst_ip": dst, "proto": proto,
                   "packets": K.n, "attacker_packets": K.att_src, "first_utc": utc(K.att_lo), "last_utc": utc(K.att_hi),
                   "duration_s": K.att_hi - K.att_lo, "attacker_macs": lab.fmt(K.smacs),
                   "src_mac_list": " ".join(sorted(K.smacs)), "victim_device": dev, "victim_group": grp,
                   "c1_in_scope": K.att_src >= C1_MIN_STREAM_PACKETS, "stream_alerted": fa is not None,
                   "stream_alert_windows": len(alerted_win[(STREAM, src, dst, proto)]),
                   "first_stream_alert_window_utc": fa["window_start_utc"] if fa else "",
                   "first_stream_alert_latency_s": fa["emitted_ts"] - K.att_lo if fa else math.nan, **ws})

    lat = []
    for (dst, proto), K in sorted(victims.items(), key=lambda kv: (-kv[1].att_src, kv[0])):
        if proto != GRE or not K.att_src:
            continue
        fa = first_alert.get((VICTIM, "", dst, proto))
        dev, grp = victim_device(K)
        vw = win_stats(vwin[(dst, proto)], alerted_win[(VICTIM, "", dst, proto)])
        union = alerted_win[(VICTIM, "", dst, proto)] | {k for (lv, s, d, p), ks in alerted_win.items()
                                                          if lv == STREAM and d == dst and p == proto
                                                          and streams[(s, d, p)].att_src for k in ks}
        uw = win_stats(vwin[(dst, proto)], union)
        latency = fa["emitted_ts"] - K.att_lo if fa else math.inf
        lat.append({"capture": name, "role": role, "dst_ip": dst, "proto": proto, "victim_device": dev,
                    "victim_group": grp, "attacker_gre_packets": K.att_src, "packets_total": K.n,
                    "attacker_streams": sum(1 for (s, d, p), S in streams.items() if d == dst and p == proto
                                            and S.att_src),
                    "first_attacker_gre_utc": utc(K.att_lo), "last_attacker_gre_utc": utc(K.att_hi),
                    "first_alert_window_start_utc": fa["window_start_utc"] if fa else "",
                    "first_alert_window_end_utc": fa["window_end_utc"] if fa else "",
                    "first_alert_packets": fa["packets"] if fa else 0,
                    "first_alert_emitted_utc": fa["emitted_utc"] if fa else "",
                    "first_alert_emitted_by": fa["emitted_by"] if fa else "",
                    "latency_s": latency,
                    "latency_to_window_end_s": fa["window_end"] - K.att_lo if fa else math.inf,
                    "c2_pass": latency <= C2_MAX_LATENCY_S,
                    **{f"victim_{k}": v for k, v in vw.items()},
                    **{f"any_level_{k}": v for k, v in uw.items()}})

    # ---- criteria
    v_att = [r for r in lat]
    s_big = [r for r in gt if r["c1_in_scope"]]
    v_miss = [r["dst_ip"] for r in v_att if not r["first_alert_emitted_utc"]]
    s_miss = [f"{r['src_ip']} -> {r['dst_ip']}" for r in s_big if not r["stream_alerted"]]
    benign = [r for r in arows if r["key_class"] == "benign"]
    dur_h = (t_hi - t_lo) / 3600 if t_hi > t_lo else math.nan
    crit = {
        "C1": {"pass": bool(v_att) and not v_miss and not s_miss,
               "attacked_victim_keys": len(v_att), "victims_alerted": len(v_att) - len(v_miss),
               "victims_missed": v_miss, "gre_streams": len(gt), "gre_streams_ge_1000": len(s_big),
               "streams_alerted": len(s_big) - len(s_miss), "streams_missed": s_miss,
               "gre_streams_lt_1000_alerted": sum(r["stream_alerted"] for r in gt if not r["c1_in_scope"]),
               "note": "" if v_att else "no attacked victim key -> FAIL (nothing to detect)"},
        "C2": {"pass": bool(v_att) and all(r["c2_pass"] for r in v_att),
               "max_latency_s": max((r["latency_s"] for r in v_att), default=math.nan),
               "latencies_s": {r["dst_ip"]: r["latency_s"] for r in v_att}},
        "C3": {"pass": not benign, "benign_key_alerts": len(benign),
               "benign_keys_alerted": len({(r["level"], r["src_ip"], r["dst_ip"], r["proto"]) for r in benign})},
    }
    tot_aw = sum(r["victim_attack_windows"] for r in v_att)
    other = {
        "victim_attack_windows": tot_aw,
        "victim_alerted_windows": sum(r["victim_alerted_windows"] for r in v_att),
        "victim_share_alerted": sum(r["victim_alerted_windows"] for r in v_att) / tot_aw if tot_aw else math.nan,
        "any_level_alerted_windows": sum(r["any_level_alerted_windows"] for r in v_att),
        "any_level_share_alerted": sum(r["any_level_alerted_windows"] for r in v_att) / tot_aw if tot_aw else math.nan,
        "stream_attack_windows_ge_1000": sum(r["attack_windows"] for r in s_big),
        "stream_alerted_windows_ge_1000": sum(r["alerted_windows"] for r in s_big),
        "stream_share_alerted_ge_1000": (sum(r["alerted_windows"] for r in s_big) / sum(r["attack_windows"] for r in s_big)
                                         if sum(r["attack_windows"] for r in s_big) else math.nan),
        "benign_alerts_per_hour": len(benign) / dur_h if dur_h == dur_h and dur_h > 0 else math.nan,
        "capture_hours": dur_h,
        "attacker_non_gre_alerts": sum(1 for r in arows if r["proto"] != GRE
                                       and (r["key_attacker_src_packets"] or r["key_attacker_dst_packets"])),
        "alerts_by_class_level": {f"{k[0]} {k[1]}": v for k, v in
                                  sorted(Counter((r["key_class"], r["level"]) for r in arows).items())},
    }
    rt = time.monotonic() - t0
    log(f"  {c['ipv4']:,} IPv4, attacker {c['attacker']:,}, non-TCP/UDP {in_scope:,} "
        f"({', '.join(f'{proto_name(p)} {n:,}' for p, n in by_proto.most_common(5))}), alerts {len(arows):,} "
        f"{other['alerts_by_class_level']}, late {gs['late_packets']:,}, {tshark_s:.0f} s, rss {peak_rss()}")
    for k, v in crit.items():
        log(f"  {k} {'PASS' if v['pass'] else 'FAIL'}: { {x: y for x, y in v.items() if x != 'pass'} }")
    meta = {"capture": name, "role": role, "tshark_cmd": " ".join(m13.tshark_cmd(pcap)),
            "reader_counts": dict(rc), "ipv4_packets": c["ipv4"], "attacker_packets": c["attacker"],
            "attacker_by_proto": {str(p): n for p, n in att_proto.most_common()},
            "non_tcp_udp_by_proto": {str(p): n for p, n in by_proto.most_common()},
            "first_utc": utc(t_lo), "last_utc": utc(t_hi), "duration_s": t_hi - t_lo,
            "stream_keys": len(streams), "victim_keys": len(victims), "guard_stats": gs, "checks": checks,
            "criteria": crit, "other": other, "tshark_s": round(tshark_s, 1), "runtime_s": round(rt, 1),
            "peak_rss_after": peak_rss()}
    return {"alerts": arows, "gt": gt, "lat": lat, "meta": meta}


# --------------------------------------------------------------------------- 12b cross-check (base part)

def cross_check_12b(R: dict) -> dict:
    P = read_json(RESULTS_DIR / "step12b" / "run_meta.json")["packets"]
    ref = {(s[0], s[1]): (s[3], s[4], s[5]) for s in P["att_streams"] if str(s[2]) == str(GRE)}
    here = {(r["src_ip"], r["dst_ip"]): (r["attacker_packets"], r["first_utc"], r["last_utc"]) for r in R["gt"]}
    same = set(ref) == set(here) and all(here[k][0] == ref[k][0] and here[k][1] == utc(ref[k][1])
                                         and here[k][2] == utc(ref[k][2]) for k in ref)
    m = R["meta"]
    return {"gre_streams_12b": len(ref), "gre_streams_here": len(here), "streams_identical": same,
            "attacker_ipv4_packets_here": m["attacker_packets"], "attacker_packets_12b": P["S"]["att"],
            "gre_attacker_here": int(m["attacker_by_proto"].get(str(GRE), 0)), "gre_attacker_12b": P["S"]["gre_att"],
            "match": same and int(m["attacker_by_proto"].get(str(GRE), 0)) == P["S"]["gre_att"],
            "note": "12b: full-dissection tshark, attacker = outer eth.src in ATTACKER_MACS; here: 13's lean reader "
                    "(IPv4 only, so 12b's non-IPv4 attacker frames are not counted here)"}


# --------------------------------------------------------------------------- summary

def write_summary(out: Path, M: dict, res: list[dict], dry: bool) -> None:
    F = M["frozen"]
    kw = F["rate_guard_kwargs"]
    L = ["# Step 13b -- frozen rate guard v1 on Mirai greeth_flood (GRE flood)", ""]
    if dry:
        L += ["**DRY RUN: base part (design data) only -- pipeline test, not the evaluation.**", ""]
    L += [f"- run {M['run_utc']}, git HEAD `{M['git_head']}`, {SCRIPT} sha256 `{CODE_SHA256[:16]}...`, runtime "
          f"{fnum(M['runtime_s'], 0)} s, peak RSS python {fnum(M['peak_rss']['python_self_mb'], 0)} MB / tshark "
          f"{fnum(M['peak_rss']['tshark_max_mb'], 0)} MB",
          f"- frozen guard: `{F['config']}` (sha256 `{F['config_sha256'][:16]}...`, git blob `{F['config_git_blob'][:12]}`"
          f" == HEAD), rate_guard.py sha256 `{F['rate_guard_sha256'][:16]}...` == results/step13/run_meta.json; "
          f"window {kw['window_s']:g} s; alert iff packets > threshold: stream {kw['stream_threshold']} / victim "
          f"{kw['victim_threshold']} (DEFAULT, incl. GRE), ICMP {kw['stream_proto_thresholds']['1']} / "
          f"{kw['victim_proto_thresholds']['1']}, IGMP {kw['stream_proto_thresholds']['2']} / "
          f"{kw['victim_proto_thresholds']['2']}",
          "- captures: " + "; ".join(f"{p['file']} ({p['role']}, sha256 `{p['sha256'][:16]}...` == "
                                     f"config/sha256_greeth.txt, {p['how']})" for p in M["pcaps"]),
          "- never opened: Mirai-greeth_flood27 / 28 (reserved fresh test), test.parquet",
          "- packets: 13's tshark reader unchanged (outer header, IPv4, no protocol filter); one RateGuard per capture "
          "over every IPv4 packet in file order (TCP / UDP = clock ticks, nothing excluded), flush() at the end",
          "- attacker = outer eth.src in config ATTACKER_MACS; attack key = stream with attacker-sent packets / victim "
          "key (dst, 47) receiving attacker GRE; benign key = no attacker-MAC packet (eth.src or eth.dst) on the key; "
          "other = the rest",
          "- alert time = capture ts of the clock tick that closed the window (flush: window end); latency = alert "
          "time - the victim's first attacker GRE packet", ""]
    L += ["## Pre-declared criteria (fixed before this run)", ""] + [f"- **{k}** {v}" for k, v in CRITERIA.items()] + [""]
    rows = []
    for R in res:
        m = R["meta"]
        cr, o = m["criteria"], m["other"]
        rows.append({"capture": m["capture"], "role": m["role"],
                     **{k: "PASS" if cr[k]["pass"] else "FAIL" for k in ("C1", "C2", "C3")},
                     "victims alerted": f"{cr['C1']['victims_alerted']}/{cr['C1']['attacked_victim_keys']}",
                     "streams >= 1k alerted": f"{cr['C1']['streams_alerted']}/{cr['C1']['gre_streams_ge_1000']}",
                     "max latency s": cr["C2"]["max_latency_s"], "benign alerts": cr["C3"]["benign_key_alerts"],
                     "victim windows alerted": f"{o['victim_alerted_windows']}/{o['victim_attack_windows']}"})
    L += ["## Verdict per capture", ""]
    L += md_table(rows, ["capture", "role", "C1", "C2", "C3", "victims alerted", "streams >= 1k alerted",
                         "max latency s", "benign alerts", "victim windows alerted"]) + [""]
    sections = [("DESIGN DATA", "already used in 12b / 12c to see the attack; reported for completeness, not "
                                "evidence"),
                ("VALIDATION", "first touch of parts 9 and 18")]
    n = 0
    for role, note in sections:
        sub = [R for R in res if R["meta"]["role"] == role]
        if not sub:
            continue
        L += [f"## {role} -- {note}", ""]
        for R in sub:
            n += 1
            L += capture_section(R, n)
    if M.get("cross_check_12b"):
        c = M["cross_check_12b"]
        L += ["## Cross-check vs 12b (base part)", "",
              f"GRE attacker streams here {c['gre_streams_here']} vs 12b {c['gre_streams_12b']}, packets and first / last "
              f"identical: {c['streams_identical']}; attacker GRE packets here {c['gre_attacker_here']:,} vs 12b "
              f"{c['gre_attacker_12b']:,} -> {'MATCH' if c['match'] else 'DIFFER'}", ""]
    L += ["## Outputs", "", "summary.md, alerts.csv (every alert, classified), ground_truth_streams.csv (GRE attacker "
          "streams), latency.csv (per attacked victim key), run_meta.json", ""]
    (out / "summary.md").write_text("\n".join(L), encoding="utf-8")


def capture_section(R: dict, n: int) -> list[str]:
    m = R["meta"]
    cr, o, gs = m["criteria"], m["other"], m["guard_stats"]
    L = [f"### {n}. {m['capture']} ({m['role']})", "",
         f"- {m['ipv4_packets']:,} IPv4 packets {m['first_utc']} .. {m['last_utc']} ({m['duration_s'] / 60:.1f} min); "
         f"attacker-sent {m['attacker_packets']:,} ("
         + ", ".join(f"{m13.pname(int(p))} {v:,}" for p, v in m["attacker_by_proto"].items()) + ")",
         "- non-TCP/UDP: " + ", ".join(f"{proto_name(int(p))} {v:,}" for p, v in m["non_tcp_udp_by_proto"].items())
         + f"; keys {m['stream_keys']:,} stream / {m['victim_keys']:,} victim; guard: {gs['windows_closed']:,} windows "
         f"closed, {gs['alerts']:,} alerts, late packets {gs['late_packets']:,}, max active keys {gs['max_active_keys']:,}",
         f"- consistency checks {sum(c['pass'] for c in m['checks'])}/{len(m['checks'])} PASS; tshark + loop "
         f"{m['tshark_s']:.0f} s", ""]
    c1, c2, c3 = cr["C1"], cr["C2"], cr["C3"]
    L += [f"**C1 detection: {'PASS' if c1['pass'] else 'FAIL'}** -- attacked victim keys alerted "
          f"{c1['victims_alerted']}/{c1['attacked_victim_keys']}"
          + (f" (missed: {', '.join(c1['victims_missed'])})" if c1["victims_missed"] else "")
          + f"; GRE attacker streams >= {C1_MIN_STREAM_PACKETS:,} packets alerted {c1['streams_alerted']}/"
          f"{c1['gre_streams_ge_1000']}" + (f" (missed: {', '.join(c1['streams_missed'])})" if c1["streams_missed"] else "")
          + f"; GRE streams in total {c1['gre_streams']} ({c1['gre_streams_lt_1000_alerted']} of those under "
          f"{C1_MIN_STREAM_PACKETS:,} packets alerted){'; ' + c1['note'] if c1['note'] else ''}", "",
          f"**C2 latency: {'PASS' if c2['pass'] else 'FAIL'}** -- max {fnum(c2['max_latency_s'], 2)} s "
          f"(limit {C2_MAX_LATENCY_S:.0f} s)", "",
          f"**C3 false alerts: {'PASS' if c3['pass'] else 'FAIL'}** -- {c3['benign_key_alerts']} alerts on "
          f"{c3['benign_keys_alerted']} benign keys", ""]
    L += ["Latency per attacked victim key (victim level):", ""]
    L += md_table(R["lat"], ["dst_ip", "victim_device", "victim_group", "attacker_gre_packets", "attacker_streams",
                             "first_attacker_gre_utc", "first_alert_window_start_utc", "first_alert_packets",
                             "first_alert_emitted_utc", "latency_s", "latency_to_window_end_s"], 2) + [""]
    L += ["Attack 10 s windows alerted (reported, no criterion; edge = the key's first / last attack window, "
          "usually partial):", ""]
    L += md_table(R["lat"], ["dst_ip", "victim_attack_windows", "victim_alerted_windows", "victim_share_alerted",
                             "victim_unalerted_edge_windows", "victim_unalerted_interior_windows",
                             "victim_unalerted_max_attacker_packets", "any_level_alerted_windows",
                             "any_level_share_alerted"], 3) + [""]
    L += [f"- victim level: {o['victim_alerted_windows']}/{o['victim_attack_windows']} = "
          f"{fnum(o['victim_share_alerted'], 3)}; victim or any of its attacker streams: "
          f"{o['any_level_alerted_windows']}/{o['victim_attack_windows']} = {fnum(o['any_level_share_alerted'], 3)}; "
          f"stream level (streams >= {C1_MIN_STREAM_PACKETS:,}): {o['stream_alerted_windows_ge_1000']}/"
          f"{o['stream_attack_windows_ge_1000']} = {fnum(o['stream_share_alerted_ge_1000'], 3)}",
          f"- benign-key alerts per hour: {fnum(o['benign_alerts_per_hour'], 2)} ({c3['benign_key_alerts']} over "
          f"{fnum(o['capture_hours'], 3)} h)",
          f"- alerts on attacker keys that are not GRE: {o['attacker_non_gre_alerts']}",
          f"- alerts by class x level: {', '.join(f'{k} {v:,}' for k, v in o['alerts_by_class_level'].items()) or 'none'}",
          ""]
    L += ["GRE attacker streams (ground truth; full table in ground_truth_streams.csv):", ""]
    L += md_table(R["gt"], ["src_ip", "dst_ip", "attacker_packets", "first_utc", "last_utc", "victim_device",
                            "c1_in_scope", "stream_alerted", "attack_windows", "alerted_windows",
                            "unalerted_interior_windows", "first_stream_alert_latency_s"], 2) + [""]
    ben = [r for r in R["alerts"] if r["key_class"] == "benign"]
    L += ["Every benign-key alert:", ""]
    L += md_table(ben, ["level", "src_ip", "dst_ip", "proto_name", "packets", "threshold", "window_start_utc",
                        "senders", "receivers", "key_packets_total"]) + [""]
    ng = [r for r in R["alerts"] if r["proto"] != GRE and (r["key_attacker_src_packets"] or r["key_attacker_dst_packets"])]
    L += ["Alerts on attacker keys that are not GRE:", ""]
    L += md_table(ng, ["level", "key_class", "src_ip", "dst_ip", "proto_name", "packets", "threshold",
                       "window_start_utc", "key_attacker_src_packets", "key_attacker_dst_packets", "senders",
                       "receivers"]) + [""]
    oth = [r for r in R["alerts"] if r["key_class"] == "other" and r["proto"] == GRE]
    if oth:
        L += ["Other GRE-key alerts (key has attacker-MAC packets but is not an attack key):", ""]
        L += md_table(oth, ["level", "src_ip", "dst_ip", "packets", "window_start_utc", "senders", "receivers"]) + [""]
    return L


# --------------------------------------------------------------------------- main

def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.13b_eval.lock for the whole run (released by the kernel on exit)."""
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
                    help="pipeline test on the base part (design data) only -> results/step13b/dry_run")
    args = ap.parse_args()
    t0 = time.monotonic()
    out = OUT / "dry_run" if args.dry_run else OUT
    names = DRY_PARTS if args.dry_run else list(PARTS)
    lock = run_lock(out)
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...  -> {out}")
    M = {"script": SCRIPT, "code_sha256": CODE_SHA256,
         "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "argv": sys.argv,
         "dry_run": args.dry_run, "git_head": git("rev-parse", "HEAD").stdout.strip(),
         "tshark_version": subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.split("\n")[0],
         "criteria": CRITERIA, "captures": {n: PARTS[n] for n in names},
         "attacker_macs": {"exact": list(ATTACKER_MACS.exact), "prefixes": list(ATTACKER_MACS.prefixes)},
         "never_opened": "Mirai-greeth_flood27.pcap, Mirai-greeth_flood28.pcap (reserved fresh test); test.parquet"}
    gargs = check_frozen(M)
    dev = m07a.Devices(DEVICE_TABLE)
    M["device_table_attacker_rows"] = dev.safety_check()
    k2 = {m07a.norm_mac(m): gname for m, gname in read_json(K2_JSON)["devices"].items()}
    lab = Labels(dev, k2)
    pcaps = stage(names, M)

    res = []
    for n in names:
        res.append(run_capture(n, pcaps[n], gargs, lab))
    if BASE in names:
        M["cross_check_12b"] = cross_check_12b(res[names.index(BASE)])
        log(f"cross-check vs 12b: {M['cross_check_12b']}")
    M["per_capture"] = [R["meta"] for R in res]
    M["verdict"] = {R["meta"]["capture"]: {k: R["meta"]["criteria"][k]["pass"] for k in ("C1", "C2", "C3")}
                    for R in res}

    alerts = pd.DataFrame([r for R in res for r in R["alerts"]])
    alerts.to_csv(out / "alerts.csv", index=False, lineterminator="\n")
    pd.DataFrame([r for R in res for r in R["gt"]]).to_csv(out / "ground_truth_streams.csv", index=False,
                                                           lineterminator="\n")
    pd.DataFrame([r for R in res for r in R["lat"]]).to_csv(out / "latency.csv", index=False, lineterminator="\n")
    M["peak_rss"] = peak_rss()
    M["runtime_s"] = round(time.monotonic() - t0, 1)
    write_json(out / "run_meta.json", M)
    write_summary(out, M, res, args.dry_run)
    for n, v in M["verdict"].items():
        log(f"{n} ({PARTS[n]}): " + ", ".join(f"{k} {'PASS' if p else 'FAIL'}" for k, p in v.items()))
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
