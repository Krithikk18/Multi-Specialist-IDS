#!/usr/bin/env python
"""07a_attack_coverage.py -- which smart-home devices do the attackers actually hit?

For each CICIoT2023 attack pcap: stream tshark packet fields once (TZ=UTC, chunked), find
the packets SENT by attacker MACs (config.config.ATTACKER_MACS: the testbed Raspberry Pis),
map each destination MAC to a device and its behaviour group (config/device_table.csv),
and decide whether the attack covers both G1 and G2 with at least --min-victims victims.
No CICFlowMeter. Read-only with respect to config/ and data/.

The testbed Pis also talk to some devices NORMALLY (the benign capture has ~35 attacker-MAC
packets/min, e.g. a Pi holding a Cast connection to the Google Nest Mini). So "any packet from
an attacker MAC" is not an attack. A benign --control capture is REQUIRED and every
(attacker MAC -> destination MAC) pair is judged against it:

  victim rule  pair rate (packets / capture minute) > --rate-k x the same pair's control
               rate (control packets floored at 1, so a pair absent from control has a
               finite ratio), OR the pair uses >= --min-new-services services never seen for
               that pair in control. A device is a victim if any of its pairs qualifies;
               reason = rate / new_service / both.
  service      (ip.proto, service port). service port = min(src port, dst port) for TCP/UDP,
               which is the server side for requests AND replies (a raw dst port would make
               every reply to a device's ephemeral port look new); no port for other
               protocols (ICMP errors quote inner UDP/TCP headers, whose ports are ignored).
  bursts       (report only) minutes where attacker packets/min > --rate-k x the control mean
               attacker packets/min, merged across gaps <= 2 minutes; overall and per MAC
               (per MAC uses the same overall threshold).

Scaling (tens of millions of attacker packets)
  tshark       only frame/eth/ip/arp/tcp/udp/icmp/ipv6/vlan dissectors, no TCP sequence
               analysis / reassembly, session state reset every 200k packets (-M). Field
               output is byte-identical to full dissection on the benign pcap; tshark RSS
               3.3 GB -> 0.19 GB there, and 0.43 GB on a 3M-packet spoofed SYN flood (every
               packet a new conversation; -M 1M gave 1.5 GB). tests/make_stress_flood.py.
  streaming    each chunk is reduced into bounded aggregates and discarded; no per-packet
               lists. Per (attacker MAC, destination): packets, first/last, protocol counts,
               dst ports (capped at 2,000 + overflow flag) and services UNSEEN in control
               (tested against the control set as packets stream, capped at 2,000 + overflow
               flag, so the cap can never hide a new service behind already-known ones).
               "2000+" in a CSV means the cap was hit.
  cross-check  ip.dst that needs no map (non-IPv4, external, multicast, broadcast) is counted
               on the fly. LAN ip.dst is kept as (ip.dst, eth.dst, minute) counts and
               resolved at the end, because a time-aware map window spans first..last
               sighting and can depend on packets after the lookup time. The key count grows
               with distinct targets x minutes, not packets (cap 500k keys, overflow counted).
  spoofing     exact distinct ip.src up to 100,000, then HyperLogLog (2^14 registers, 64-bit
               pandas hash, ~0.8% standard error); the top-10 table then only counts IPs
               already tracked. Collisions: every attacker ip.src is tested against the real
               device IPs from this pcap's map (exactly, at the end, while exact; against the
               device IPs known so far, per chunk, after the switch).
  control      cached in <out-dir>/control_baseline.json and reused when its SHA256 matches.
  resumable    one pcap at a time; <stem>_victims.csv, <stem>_pairs.csv, then <stem>_stats.json
               (the completion marker) are written as each finishes; coverage_summary.csv and
               coverage_report.md are rebuilt from every *_stats.json in --out-dir after each
               pcap. --skip-done skips a pcap whose stats JSON has the same SHA256 and the same
               completion key (K, min new services, control SHA256, device_table SHA256,
               stats version); otherwise it re-runs, and the report marks every stats file
               whose key differs from the current run as STALE (with the differing keys).
  memory       peak RSS (getrusage: this process and the largest child, i.e. tshark) is
               printed after each pcap and at the end. ru_maxrss is a high-water mark, so the
               per-pcap value is the peak so far.

Per pcap also: source-MAC census (top 30, tagged), broadcast/multicast destinations, IP/MAC
cross-check (time-aware IP->MAC map built FROM THIS PCAP with 02_mac_ip_map.py's approach,
sender evidence only -- ip.src and ARP sender, LAN scope, unicast MAC -- from NON-attacker
senders so spoofed packets cannot vouch for themselves), attack window, background share,
and everything per attacker MAC (packets, victims, bursts; a Pi that never attacks shows up).

Outputs (--out-dir): control_baseline.json, sha256.txt, <stem>_victims.csv, <stem>_pairs.csv,
<stem>_stats.json, coverage_summary.csv (group rows + burst rows), coverage_report.md,
attack_rate_<stem>.png, attack_rate_<control stem>_control.png

--devices overrides config/device_table.csv (e.g. to test a modified table); its SHA256 is
part of the completion key.

Exit status: 0 ok, 1 bad input / safety failure / no --control, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gc
import importlib.util
import ipaddress as ipa
import json
import math
import os
import resource
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

from config.config import ATTACKER_MACS, CACHE_DIR, DEVICE_TABLE, NETWORK, REPO_ROOT, RESULTS_DIR

# Reuse 02's helpers so MACs / IP scope / hashing behave identically across steps.
_spec = importlib.util.spec_from_file_location("mac_ip_map", REPO_ROOT / "02_mac_ip_map.py")
m02 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m02)
log, fatal, norm_mac, mac_is_unicast = m02.log, m02.fatal, m02.norm_mac, m02.mac_is_unicast
ip_scope, sha256, utc, pct, md_table = m02.ip_scope, m02.sha256, m02.utc, m02.pct, m02.md_table

FIELDS = ["frame.time_epoch", "eth.src", "eth.dst", "ip.src", "ip.dst", "ip.proto",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags",
          "arp.src.hw_mac", "arp.src.proto_ipv4"]
COLS = ["t", "esrc", "edst", "ipsrc", "ipdst", "proto", "tsport", "tport", "usport", "uport",
        "tflags", "amac", "aip"]
TSHARK_PROTOCOLS = "frame,eth,ethertype,ip,arp,tcp,udp,icmp,ipv6,vlan"
TSHARK_RESET = 200_000     # tshark -M: per-conversation state is cleared this often
CHUNK = 250_000
CAP_SET = 2_000
SPOOF_EXACT_MAX = 100_000
HLL_P = 14
XKEY_CAP = 500_000
CENSUS_CAP = 100_000
SCOPE_CACHE_MAX = 200_000
CENSUS_TOP = 30
SPOOF_THRESHOLD = 10
BURST_GAP_MIN = 2
MAP_SLACK_S = 60.0        # a (ip, mac) window counts as active up to 60 s outside its span
COVER_GROUPS = ["G1", "G2", "GEN", "gateway"]
VERDICT_GROUPS = ["G1", "G2"]
PROTO = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
TCP_FLAG_NAMES = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"),
                  (0x20, "URG")]
STATS_VERSION = 2
BASELINE_FORMAT = 1
SERVICE_DEF = "(ip.proto, min(src_port, dst_port) for TCP/UDP else none)"

# Chart tokens (dataviz reference palette, light mode).
SURFACE, TEXT1, TEXT2, GRID, SERIES1 = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e0", "#2a78d6"


def pname(p: int) -> str:
    return PROTO.get(p, "none" if p < 0 else str(p))


def svc_name(svc: tuple[int, int]) -> str:
    p, port = svc
    return pname(p) if port < 0 else f"{pname(p)}/{port}"


def capped(n: int, over: bool):
    return f"{n}+" if over else n


def peak_rss() -> dict:
    """Peak resident set size in MB (Linux ru_maxrss is in KB): self and largest child."""
    return {"self_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
            "tshark_mb": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024, 1)}


# --------------------------------------------------------------------------- devices

class Devices:
    def __init__(self, path: Path):
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        need = {"mac", "device_name", "role", "behaviour_group"}
        if need - set(df.columns):
            fatal(f"{path}: missing columns {sorted(need - set(df.columns))}")
        df["mac"] = df["mac"].map(norm_mac)
        self.df = df
        self.name = dict(zip(df["mac"], df["device_name"]))
        self.role = dict(zip(df["mac"], df["role"]))
        self.group = dict(zip(df["mac"], df["behaviour_group"]))
        gw = df.loc[df["role"] == "gateway", "mac"].tolist()
        if len(gw) != 1:
            fatal(f"{path}: expected exactly one role=gateway row, found {len(gw)}")
        self.gateway_mac = gw[0]

    def safety_check(self) -> list[dict]:
        """Attacker MACs may appear in the table only as testbed Pis; an attacker MAC on a
        smart-home / grouped / any other row would make an attacker look like a victim."""
        hits = self.df[self.df["mac"].map(ATTACKER_MACS.matches)]
        bad = hits[(hits["role"] != "testbed_pi") | (hits["behaviour_group"] != "")]
        if len(bad):
            fatal("SAFETY: attacker MACs on non-testbed device_table rows:\n"
                  + bad[["mac", "device_name", "role", "behaviour_group"]].to_string(index=False))
        return hits[["mac", "device_name", "role"]].to_dict("records")

    def tag(self, mac: str) -> str:
        """Census tag for a source MAC."""
        if ATTACKER_MACS.matches(mac):
            return "attacker"
        if mac == self.gateway_mac:
            return "gateway"
        return self.name.get(mac, "unknown")

    def dest_class(self, mac: str) -> tuple[str, str]:
        """(device name, group) for a unicast destination MAC."""
        if mac == self.gateway_mac:
            return self.name[mac], "gateway"
        if ATTACKER_MACS.matches(mac):
            return self.name.get(mac, "attacker"), "attacker"
        role = self.role.get(mac)
        if role is None:
            return "unknown", "unknown"
        if role == "iot":
            return self.name[mac], self.group[mac] or "ungrouped"
        return self.name[mac], role          # testbed_pi / unknown / excluded rows


# --------------------------------------------------------------------------- bounded state

class Pair:
    """Aggregate for one (attacker MAC, destination MAC) pair."""
    __slots__ = ("n", "lo", "hi", "protos", "dports", "dports_over", "svc", "svc_over")

    def __init__(self):
        self.n, self.lo, self.hi = 0, math.inf, -math.inf
        self.protos = Counter()
        self.dports, self.dports_over = set(), False
        self.svc, self.svc_over = Counter(), False   # control: all services; attack: new only


def capped_add(counter: Counter, key, n: int, cap: int) -> bool:
    """Add n to counter[key]; returns True (overflow) if key is new and the cap is reached."""
    if key in counter:
        counter[key] += n
        return False
    if len(counter) >= cap:
        return True
    counter[key] = n
    return False


class SourceIPs:
    """Distinct attacker ip.src: exact up to SPOOF_EXACT_MAX, then HyperLogLog."""

    def __init__(self):
        self.counts = Counter()
        self.exact = True
        self.reg = None
        self.known = None

    def _hll(self, ips) -> None:
        h = pd.util.hash_array(np.asarray(list(ips), dtype=object))      # uint64
        bucket = (h >> np.uint64(64 - HLL_P)).astype(np.int64)
        w = (h & np.uint64((1 << (64 - HLL_P)) - 1)).astype(np.float64)  # < 2^50: exact
        _, e = np.frexp(w)                                               # bit length of w
        rank = np.where(w == 0, 64 - HLL_P + 1, 64 - HLL_P - e + 1).astype(np.uint8)
        np.maximum.at(self.reg, bucket, rank)

    def update(self, vc: pd.Series) -> None:
        if self.exact:
            self.counts.update(vc.to_dict())
            if len(self.counts) > SPOOF_EXACT_MAX:
                self.exact = False
                self.reg = np.zeros(1 << HLL_P, dtype=np.uint8)
                self._hll(self.counts.keys())
                self.known = pd.Index(list(self.counts))
        else:
            for ip, n in vc[vc.index.isin(self.known)].items():
                self.counts[ip] += int(n)
            self._hll(vc.index)

    def distinct(self) -> int:
        if self.exact:
            return len(self.counts)
        m = float(1 << HLL_P)
        est = (0.7213 / (1 + 1.079 / m)) * m * m / float(np.sum(np.power(2.0, -self.reg.astype(float))))
        zeros = int(np.sum(self.reg == 0))
        if est <= 2.5 * m and zeros:
            est = m * math.log(m / zeros)
        return int(round(est))

    def method(self) -> str:
        return ("exact" if self.exact else
                f"approximate: HyperLogLog 2^{HLL_P} registers (~0.8% std error) after "
                f"{SPOOF_EXACT_MAX:,} exact; top-10 counts only for IPs tracked before the switch")


# --------------------------------------------------------------------------- extraction

def tcp_flag_name(v: str) -> str:
    try:
        x = int(v, 16)
    except ValueError:
        return "?"
    names = [n for b, n in TCP_FLAG_NAMES if x & b]
    return "+".join(names) or "none"


def tshark_cmd(pcap: Path) -> list[str]:
    cmd = ["tshark", "-n", "-M", str(TSHARK_RESET), "--disable-all-protocols",
           "--enable-protocol", TSHARK_PROTOCOLS,
           "-o", "tcp.analyze_sequence_numbers:FALSE", "-o", "tcp.desegment_tcp_streams:FALSE",
           "-r", str(pcap), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
           "-E", "quote=n"]
    for f in FIELDS:
        cmd += ["-e", f]
    return cmd


def analyse(pcap: Path, dev: Devices, C: dict | None = None) -> dict:
    """One streaming tshark pass. C = control baseline (None while building the control):
    with C, each pair's services are tested against the control set as they stream."""
    cmd = tshark_cmd(pcap)
    log(f"  tshark: {' '.join(cmd)}")
    env = {**os.environ, "TZ": "UTC"}
    bcast = {ipa.ip_network(n).broadcast_address for n in NETWORK.subnets}

    att_cache: dict[str, bool] = {}
    scope_cache: dict[str, str | None] = {}
    S = {"packets": 0, "background": 0, "att_src": 0, "att_dst": 0, "t_min": None, "t_max": None,
         "att_first": None, "att_last": None}
    census, per_min, tflags, proto_all = Counter(), Counter(), Counter(), Counter()
    flags = {"census_overflow": 0, "xkey_overflow_packets": 0}
    pairs: dict[tuple[str, str], Pair] = {}
    ips = SourceIPs()
    xkey, xout = Counter(), Counter()
    mapev = {}                       # (ip, mac) -> [first, last, n]
    seen_dev_ips, seen_lan_ips = set(), set()
    stream_coll = {"dev_ips": set(), "dev_packets": 0, "lan_ips": set()}
    empty: frozenset = frozenset()

    def is_att(series: pd.Series) -> pd.Series:
        for m in pd.unique(series):
            if m not in att_cache:
                att_cache[m] = bool(m) and ATTACKER_MACS.matches(m)
        return series.map(att_cache)

    def scope(ip: str) -> str | None:
        why = scope_cache.get(ip, "?")
        if why == "?":
            if len(scope_cache) > SCOPE_CACHE_MAX:
                scope_cache.clear()
            a, why = ip_scope(ip)
            scope_cache[ip] = why
        return why

    def add_ev(df: pd.DataFrame, ipcol: str, maccol: str) -> None:
        g = df.groupby([ipcol, maccol])["t"].agg(["min", "max", "size"])
        for (ip, mac), (lo, hi, n) in g.iterrows():
            r = mapev.get((ip, mac))
            if r is None:
                mapev[(ip, mac)] = [lo, hi, int(n)]
                if mac_is_unicast(mac):
                    a, why = ip_scope(ip)
                    if why is None and a not in bcast:
                        seen_lan_ips.add(ip)
                        if dev.role.get(mac) == "iot":
                            seen_dev_ips.add(ip)
            else:
                r[0], r[1], r[2] = min(r[0], lo), max(r[1], hi), r[2] + int(n)

    def mn(a, b):
        return b if a is None else min(a, b)

    def mx(a, b):
        return b if a is None else max(a, b)

    def num(s: pd.Series) -> pd.Series:
        return pd.to_numeric(s, errors="coerce")

    t0 = time.monotonic()
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, env=env)
        reader = pd.read_csv(proc.stdout, sep="\t", header=None, names=COLS, dtype=str,
                             keep_default_na=False, quoting=csv.QUOTE_NONE,
                             chunksize=CHUNK, engine="c")
        for c in reader:
            c["t"] = num(c["t"])
            c = c[c["t"].notna()]
            if c.empty:
                continue
            a_src, a_dst = is_att(c["esrc"]), is_att(c["edst"])
            S["packets"] += len(c)
            S["background"] += int((~a_src & ~a_dst).sum())
            S["att_src"] += int(a_src.sum())
            S["att_dst"] += int(a_dst.sum())
            S["t_min"], S["t_max"] = mn(S["t_min"], c["t"].min()), mx(S["t_max"], c["t"].max())
            for m, n in c["esrc"].value_counts().items():
                if capped_add(census, m, int(n), CENSUS_CAP):
                    flags["census_overflow"] += int(n)

            # map evidence: sender side only, non-attacker senders
            ok = ~a_src & (c["esrc"] != "") & (c["ipsrc"] != "")
            if ok.any():
                add_ev(c[ok], "ipsrc", "esrc")
            arp = (c["amac"] != "") & (c["aip"] != "")
            if arp.any():
                ar = c[arp]
                ar = ar[~is_att(ar["amac"])]
                if len(ar):
                    add_ev(ar, "aip", "amac")

            a = c[a_src]
            del c
            if a.empty:
                continue
            S["att_first"], S["att_last"] = mn(S["att_first"], a["t"].min()), mx(S["att_last"], a["t"].max())
            minute = (a["t"] // 60).astype("int64")
            per_min.update(pd.DataFrame({"m": a["esrc"], "t": minute}).value_counts().to_dict())
            vc_ip = a.loc[a["ipsrc"] != "", "ipsrc"].value_counts()
            ips.update(vc_ip)
            if not ips.exact:            # streaming collision test once exact counts are gone
                hit = vc_ip[vc_ip.index.isin(seen_dev_ips)]
                stream_coll["dev_ips"].update(hit.index)
                stream_coll["dev_packets"] += int(hit.sum())
                stream_coll["lan_ips"].update(vc_ip.index[vc_ip.index.isin(seen_lan_ips)])
            tflags.update(a.loc[a["tflags"] != "", "tflags"].value_counts().to_dict())
            pn = num(a["proto"]).fillna(-1).astype("int64")
            proto_all.update(pn.value_counts().to_dict())
            # ports only for TCP / UDP (ICMP errors carry the quoted inner header's ports)
            dport = num(a["tport"]).where(pn == 6, num(a["uport"]).where(pn == 17))
            sport = num(a["tsport"]).where(pn == 6, num(a["usport"]).where(pn == 17))
            svc = pd.Series(np.fmin(sport.to_numpy(), dport.to_numpy()), index=a.index)
            svc = svc.fillna(-1).astype("int64")

            g = a.groupby(["esrc", "edst"])["t"].agg(["size", "min", "max"])
            for key, (n, lo, hi) in g.iterrows():
                P = pairs.get(key)
                if P is None:
                    P = pairs[key] = Pair()
                P.n += int(n)
                P.lo, P.hi = min(P.lo, lo), max(P.hi, hi)
            for (s, d, p), n in pd.DataFrame({"s": a["esrc"], "d": a["edst"], "p": pn}) \
                    .value_counts().items():
                pairs[(s, d)].protos[int(p)] += int(n)
            for (s, d, p, q), n in pd.DataFrame({"s": a["esrc"], "d": a["edst"], "p": pn,
                                                 "q": svc}).value_counts().items():
                P, key = pairs[(s, d)], (int(p), int(q))
                if C is not None:
                    if (s, d) in C["over"] or key in C["svc"].get((s, d), empty):
                        continue
                if capped_add(P.svc, key, int(n), CAP_SET):
                    P.svc_over = True
            dp = pd.DataFrame({"s": a["esrc"], "d": a["edst"], "x": dport}).dropna()
            for key, ports in dp.groupby(["s", "d"])["x"].unique().items():
                P = pairs[key]
                for x in ports:
                    x = int(x)
                    if x in P.dports:
                        continue
                    if len(P.dports) >= CAP_SET:
                        P.dports_over = True
                        break
                    P.dports.add(x)
            # cross-check: resolve what needs no map now; keep LAN ip.dst for the end
            for (ip, e, m), n in pd.DataFrame({"i": a["ipdst"], "e": a["edst"], "m": minute}) \
                    .value_counts().items():
                n = int(n)
                if not ip:
                    xout["no_ip_dst (non-IPv4)"] += n
                    continue
                why = scope(ip)
                if why:
                    kind = "external ip.dst" if why == "not_lan_scope" else f"{why} ip.dst"
                    xout[kind + (" via gateway MAC" if e == dev.gateway_mac else "")] += n
                elif (ip, e, int(m)) in xkey or len(xkey) < XKEY_CAP:
                    xkey[(ip, e, int(m))] += n
                else:
                    xout["lan ip.dst unresolved (key cap)"] += n
                    flags["xkey_overflow_packets"] += n
            del a
            el = time.monotonic() - t0
            log(f"    {S['packets']:>11,} packets  {el:7.1f} s  attacker {S['att_src']:,}  "
                f"pairs {len(pairs):,}  lan-keys {len(xkey):,}")
        rc = proc.wait()
        errf.seek(0)
        err = errf.read().decode(errors="replace").strip()
    err = "\n".join(l for l in err.splitlines() if l.strip() != "resetting session.")
    if rc != 0:
        fatal(f"tshark exited {rc} on {pcap}: {err[-2000:]}")
    if S["packets"] == 0:
        fatal(f"tshark produced no packets for {pcap}")
    S["tshark_seconds"] = round(time.monotonic() - t0, 1)
    S["minutes"] = max((S["t_max"] - S["t_min"]) / 60.0, 1 / 60)
    log(f"  done: {S['packets']:,} packets in {S['tshark_seconds']} s")
    return {"S": S, "census": census, "per_min": per_min, "ips": ips, "stream_coll": stream_coll,
            "tflags": tflags, "proto_all": proto_all, "pairs": pairs, "xkey": xkey,
            "xout": xout, "mapev": mapev, "flags": flags}


# --------------------------------------------------------------------------- control baseline

def baseline_from(R: dict, pcap: Path, digest: str, dev: Devices) -> dict:
    return {"format": BASELINE_FORMAT, "service_definition": SERVICE_DEF, "pcap": str(pcap),
            "sha256": digest, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "packets": R["S"]["packets"], "minutes": R["S"]["minutes"], "att_src": R["S"]["att_src"],
            "census": [{"rank": i + 1, "eth_src": m, "tag": dev.tag(m), "packets": n,
                        "pct": pct(n, R["S"]["packets"])}
                       for i, (m, n) in enumerate(R["census"].most_common(CENSUS_TOP))],
            "pairs": {f"{s}|{d}": {"packets": P.n, "services": sorted([list(k) for k in P.svc]),
                                   "overflow": P.svc_over}
                      for (s, d), P in R["pairs"].items()},
            "per_min": {f"{m}|{t}": n for (m, t), n in R["per_min"].items()}}


def control_view(B: dict) -> dict:
    """In-memory form of a baseline for the victim rule."""
    pairs, svc, over = {}, {}, set()
    for k, v in B["pairs"].items():
        s, d = k.split("|")
        pairs[(s, d)] = v["packets"]
        svc[(s, d)] = frozenset(tuple(x) for x in v["services"])
        if v["overflow"]:
            over.add((s, d))
    per_min = Counter()
    for k, n in B["per_min"].items():
        m, t = k.split("|")
        per_min[(m, int(t))] = n
    return {"S": {"packets": B["packets"], "minutes": B["minutes"], "att_src": B["att_src"]},
            "pairs": pairs, "svc": svc, "over": over, "per_min": per_min, "B": B}


# --------------------------------------------------------------------------- IP -> MAC map

def build_map(mapev: dict) -> dict:
    """ip -> sorted [(first, last, mac, n)] after 02's filters (LAN scope, unicast MAC,
    not a subnet broadcast)."""
    bcast = {ipa.ip_network(n).broadcast_address for n in NETWORK.subnets}
    out = defaultdict(list)
    for (ip, mac), (lo, hi, n) in mapev.items():
        if not mac_is_unicast(mac):
            continue
        a, why = ip_scope(ip)
        if why or a in bcast:
            continue
        out[ip].append((lo, hi, mac, n))
    return {ip: sorted(v) for ip, v in out.items()}


def lookup(ipmap: dict, ip: str, t: float) -> tuple[str, str | None]:
    """('mapped', mac) | ('ambiguous', None) | ('unmapped_at_time', None) | ('unmapped', None)."""
    wins = ipmap.get(ip)
    if not wins:
        return "unmapped", None
    macs = {m for lo, hi, m, _ in wins if lo - MAP_SLACK_S <= t <= hi + MAP_SLACK_S}
    if len(macs) == 1:
        return "mapped", macs.pop()
    return ("ambiguous", None) if macs else ("unmapped_at_time", None)


def cross_check(R: dict, ipmap: dict, dev: Devices) -> dict:
    """attacker ip.dst -> map -> device vs eth.dst -> device (packet counts). Non-map outcomes
    were counted while streaming; LAN ip.dst keys are resolved here."""
    out, pairs = Counter(R["xout"]), Counter()
    for (ip, edst, minute), n in R["xkey"].items():
        if not mac_is_unicast(edst):
            out["lan ip.dst, non-unicast eth.dst"] += n
            continue
        status, mac = lookup(ipmap, ip, minute * 60 + 30)
        if status != "mapped":
            out[f"lan ip.dst {status}"] += n
        elif mac == edst:
            out["agree"] += n
        else:
            out["DISAGREE"] += n
            pairs[(ip, dev.tag(mac), dev.tag(edst))] += n
    top = [{"ip_dst": ip, "map_device": md, "eth_dst_device": ed, "packets": n}
           for (ip, md, ed), n in pairs.most_common(10)]
    return {"outcomes": dict(out.most_common()), "disagree": out.get("DISAGREE", 0),
            "top_disagreements": top}


# --------------------------------------------------------------------------- victim rule

def judge_pairs(R: dict, C: dict, dev: Devices, k: float, min_new: int) -> list[dict]:
    """Every attacker -> unicast destination pair, judged against the control capture."""
    rows = []
    for (am, dm), P in R["pairs"].items():
        if not mac_is_unicast(dm):
            continue
        name, group = dev.dest_class(dm)
        cn = C["pairs"].get((am, dm), 0)
        ratio = (P.n / R["S"]["minutes"]) / (max(cn, 1) / C["S"]["minutes"])
        if (am, dm) in C["over"]:
            n_new, new_txt = 0, f"(control service set hit the {CAP_SET} cap: not tested)"
        else:
            n_new = len(P.svc)
            new_txt = ";".join(f"{svc_name(s)}:{c}" for s, c in
                               sorted(P.svc.items(), key=lambda kv: -kv[1])[:8])
        is_rate, is_new = ratio > k, n_new >= min_new
        reason = ("both" if is_rate and is_new else "rate" if is_rate
                  else "new_service" if is_new else "")
        rows.append({"attacker_mac": am, "mac": dm, "device": name, "group": group,
                     "attack_packets": P.n, "control_packets": cn, "rate_ratio": round(ratio, 2),
                     "new_service_pairs": capped(n_new, P.svc_over), "new_services": new_txt,
                     "victim": bool(reason), "reason": reason,
                     "first_ts": utc(P.lo), "last_ts": utc(P.hi),
                     "distinct_dst_ports": capped(len(P.dports), P.dports_over),
                     "_n_new": n_new, "_new_over": P.svc_over})
    rows.sort(key=lambda r: (not r["victim"], -r["attack_packets"]))
    return rows


def victims_from_pairs(pairs: list[dict], R: dict) -> list[dict]:
    """One row per victim device, aggregated over its QUALIFYING pairs only."""
    by = defaultdict(list)
    for p in pairs:
        if p["victim"]:
            by[p["mac"]].append(p)
    rows = []
    for mac, ps in by.items():
        protos, ports, over = Counter(), set(), False
        for p in ps:
            P = R["pairs"][(p["attacker_mac"], mac)]
            protos.update(P.protos)
            ports |= P.dports
            over |= P.dports_over
        reasons = {p["reason"] for p in ps}
        reason = ("both" if "both" in reasons or {"rate", "new_service"} <= reasons
                  else reasons.pop())
        rows.append({"mac": mac, "device": ps[0]["device"], "group": ps[0]["group"],
                     "attack_packets": sum(p["attack_packets"] for p in ps),
                     "first_ts": min(p["first_ts"] for p in ps),
                     "last_ts": max(p["last_ts"] for p in ps),
                     "distinct_dst_ports": capped(len(ports), over),
                     "protocols": ";".join(f"{pname(pr)}:{c}" for pr, c in protos.most_common()),
                     "reason": reason, "rate_ratio": max(p["rate_ratio"] for p in ps),
                     "new_service_pairs": capped(sum(p["_n_new"] for p in ps),
                                                 any(p["_new_over"] for p in ps)),
                     "attacker_macs": ";".join(sorted(p["attacker_mac"] for p in ps))})
    rows.sort(key=lambda r: (-r["attack_packets"], r["mac"]))
    return rows


def bursts(per_min: dict[int, int], threshold: float) -> list[dict]:
    """Minutes with packets > threshold, merged across gaps <= BURST_GAP_MIN minutes."""
    hot = sorted(m for m, n in per_min.items() if n > threshold)
    wins = []
    for m in hot:
        if wins and m - wins[-1][1] <= BURST_GAP_MIN + 1:
            wins[-1][1] = m
        else:
            wins.append([m, m])
    return [{"start": utc(lo * 60), "end": utc((hi + 1) * 60), "minutes": hi - lo + 1,
             "packets": sum(per_min.get(x, 0) for x in range(lo, hi + 1)),
             "peak_per_min": max(per_min.get(x, 0) for x in range(lo, hi + 1))}
            for lo, hi in wins]


def per_minute(per_min_mac: Counter, mac: str | None = None) -> Counter:
    out = Counter()
    for (m, minute), n in per_min_mac.items():
        if mac is None or m == mac:
            out[minute] += n
    return out


# --------------------------------------------------------------------------- per-pcap summary

def summarise(pcap: Path, R: dict, C: dict, dev: Devices, att_rows: list[dict],
              k: float, min_new: int) -> dict:
    S = R["S"]
    ipmap = build_map(R["mapev"])
    census = [{"rank": i + 1, "eth_src": m, "tag": dev.tag(m), "packets": n,
               "pct": pct(n, S["packets"])}
              for i, (m, n) in enumerate(R["census"].most_common(CENSUS_TOP))]
    bm = Counter()
    for (am, dm), P in R["pairs"].items():
        if not mac_is_unicast(dm):
            bm["broadcast" if dm == "ff:ff:ff:ff:ff:ff" else "multicast"] += P.n
    pairs = judge_pairs(R, C, dev, k, min_new)
    victims = victims_from_pairs(pairs, R)
    cover = []
    for g in COVER_GROUPS:
        sel = [r for r in victims if r["group"] == g]
        cover.append({"pcap": pcap.stem, "group": g, "n_victims": len(sel),
                      "attack_packets": sum(r["attack_packets"] for r in sel),
                      "window_start": min((r["first_ts"] for r in sel), default=""),
                      "window_end": max((r["last_ts"] for r in sel), default="")})
    # bursts: overall and per attacker MAC, against the control mean
    c_min = C["S"]["minutes"]
    thr_all = k * C["S"]["att_src"] / c_min
    burst_all = bursts(per_minute(R["per_min"]), thr_all)
    macs = sorted({r["mac"] for r in att_rows} | {m for m, _ in R["per_min"]}
                  | {m for m, _ in C["per_min"]})
    att_ctl, att_now = Counter(), Counter()
    for (m, _), n in C["per_min"].items():
        att_ctl[m] += n
    for (m, _), n in R["per_min"].items():
        att_now[m] += n
    per_mac = []
    for m in macs:
        # same threshold as overall: a per-MAC control mean is ~0 for sparse Pis, which
        # would turn every single packet into a "burst"
        vic = Counter(v["group"] for v in victims if m in v["attacker_macs"].split(";"))
        bw = bursts(per_minute(R["per_min"], m), thr_all)
        per_mac.append({"attacker_mac": m, "device": dev.name.get(m, "not in device_table"),
                        "packets": att_now[m], "pkt_per_min": round(att_now[m] / S["minutes"], 2),
                        "control_pkt_per_min": round(att_ctl[m] / c_min, 2),
                        "victims": sum(vic.values()),
                        "victims_by_group": ", ".join(f"{g} {n}" for g, n in sorted(vic.items())) or "-",
                        "burst_windows": len(bw),
                        "bursts": "; ".join(f"{b['start'][11:19]}-{b['end'][11:19]} "
                                            f"({b['packets']:,} pkts)" for b in bw) or "-"})
    # spoofing: exact while the exact set lasted, else streaming tests + tracked IPs
    dev_ips = {ip for ip, w in ipmap.items()
               if any(dev.role.get(m) == "iot" for _, _, m, _ in w)}
    ips, sc = R["ips"], R["stream_coll"]
    keys = set(ips.counts)
    if ips.exact:
        coll_dev, coll_lan = keys & dev_ips, keys & set(ipmap)
        dev_pkts = sum(ips.counts[i] for i in coll_dev)
    else:
        coll_dev = sc["dev_ips"] | (keys & dev_ips)
        coll_lan = sc["lan_ips"] | (keys & set(ipmap))
        dev_pkts = sc["dev_packets"] + sum(ips.counts[i] for i in (keys & dev_ips))
    n_ips = ips.distinct()
    spoof = {"distinct_ip_src": n_ips, "distinct_method": ips.method(),
             "flag": n_ips > SPOOF_THRESHOLD,
             "collide_with_device_ips": len(coll_dev),
             "collide_with_any_lan_host_ip": len(coll_lan),
             "packets_from_device_ips": dev_pkts,
             "top_ip_src": [{"ip_src": ip, "packets": n, "is_device_ip": ip in dev_ips}
                            for ip, n in ips.counts.most_common(10)]}
    att = S["att_src"]
    pm = per_minute(R["per_min"])
    win = {"first_utc": utc(S["att_first"]) if att else "",
           "last_utc": utc(S["att_last"]) if att else "", "active_minutes": len(pm),
           "pkts_per_min_over_capture": round(att / S["minutes"], 2),
           "pkts_per_min_over_active_minutes": round(att / len(pm), 2) if att else 0.0,
           "peak_pkts_per_min": max(pm.values(), default=0)}
    flags = Counter()
    for v, n in R["tflags"].items():
        flags[tcp_flag_name(v)] += n
    for p in pairs:
        p.pop("_n_new"), p.pop("_new_over")
    return {"pcap": str(pcap), "stem": pcap.stem, "S": S, "census": census, "pairs": pairs,
            "victims": victims, "bcast_mcast": dict(bm), "cover": cover, "spoof": spoof,
            "window": win, "xcheck": cross_check(R, ipmap, dev),
            "per_min": {str(m): n for m, n in sorted(pm.items())},
            "burst_threshold": round(thr_all, 2), "bursts": burst_all, "per_mac": per_mac,
            "capture": {"first_utc": utc(S["t_min"]), "last_utc": utc(S["t_max"]),
                        "minutes": round(S["minutes"], 2)},
            "tcp_flags": dict(flags.most_common(8)),
            "protocols": {pname(p): n for p, n in R["proto_all"].most_common()},
            "background_pct": pct(S["background"], S["packets"]),
            "gateway_ip_macs": sorted({m for _, _, m, _ in ipmap.get(NETWORK.gateway_ip, [])}),
            "caps": {**R["flags"], "pairs_with_dport_cap": sum(P.dports_over for P in R["pairs"].values()),
                     "pairs_with_new_service_cap": sum(P.svc_over for P in R["pairs"].values()),
                     "lan_xcheck_keys": len(R["xkey"])}}


def verdicts(P: dict, min_v: int) -> tuple[dict, str]:
    n = {c["group"]: c["n_victims"] for c in P["cover"]}
    v = {g: ("PASS" if n.get(g, 0) >= min_v else "FAIL") for g in VERDICT_GROUPS + ["GEN"]}
    g1, g2 = v["G1"] == "PASS", v["G2"] == "PASS"
    return v, "BOTH" if g1 and g2 else "G1-only" if g1 else "G2-only" if g2 else "NONE"


def plot_rate(stem: str, pm: Counter, threshold: float, out: Path, name: str, label: str) -> Path:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    path = out / name
    fig, ax = plt.subplots(figsize=(8, 3), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    if pm:
        lo, hi = min(pm), max(pm)
        mins = list(range(lo, hi + 1))
        x = [dt.datetime.fromtimestamp(m * 60, tz=dt.timezone.utc) for m in mins]
        y = [pm.get(m, 0) for m in mins]
        ax.fill_between(x, y, color=SERIES1, alpha=0.12, linewidth=0, step="post")
        ax.step(x, y, where="post", color=SERIES1, linewidth=2)
        ax.axhline(threshold, color=TEXT2, linewidth=1, linestyle=(0, (4, 3)))
        ax.annotate(f"burst threshold {threshold:,.0f}/min", (1, threshold),
                    xycoords=("axes fraction", "data"), xytext=(-4, 4),
                    textcoords="offset points", ha="right", va="bottom", fontsize=8, color=TEXT2)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=dt.timezone.utc))
    else:
        ax.text(0.5, 0.5, "no attacker-MAC packets", transform=ax.transAxes, ha="center",
                va="center", color=TEXT2)
    ax.set_title(f"Attacker packets per minute — {stem} ({label})", color=TEXT1,
                 fontsize=10, loc="left")
    ax.set_xlabel("time (UTC)", color=TEXT2, fontsize=9)
    ax.set_ylabel("packets / minute", color=TEXT2, fontsize=9)
    ax.set_ylim(bottom=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=TEXT2, labelsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    return path


# --------------------------------------------------------------------------- outputs

VICTIM_COLS = ["mac", "device", "group", "attack_packets", "first_ts", "last_ts",
               "distinct_dst_ports", "protocols", "reason", "rate_ratio", "new_service_pairs",
               "attacker_macs"]
PAIR_COLS = ["attacker_mac", "mac", "device", "group", "attack_packets", "control_packets",
             "rate_ratio", "new_service_pairs", "new_services", "victim", "reason", "first_ts",
             "last_ts", "distinct_dst_ports"]


def write_csv(path: Path, rows: list[dict], cols: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_json(path: Path, obj) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=lambda o: o.item() if hasattr(o, "item")
                              else str(o)) + "\n", encoding="utf-8")
    tmp.replace(path)


def census_md(rows: list[dict]) -> list[str]:
    return [f"Source-MAC census (top {CENSUS_TOP}):", ""] + md_table(
        rows, ["rank", "eth_src", "tag", "packets", "pct"])


def pcap_md(P: dict, min_v: int) -> list[str]:
    S, sp, w, x = P["S"], P["spoof"], P["window"], P["xcheck"]
    v, overall = verdicts(P, min_v)
    L = [f"- file: `{P['pcap']}`",
         f"- rule parameters: {P['params']}; run {P['run_utc']}; peak RSS so far "
         f"{P['peak_rss']['self_mb']:,} MB (python), {P['peak_rss']['tshark_mb']:,} MB (tshark)",
         f"- packets: {S['packets']:,}; capture {P['capture']['first_utc']} -> "
         f"{P['capture']['last_utc']} ({P['capture']['minutes']} min); tshark+aggregation "
         f"{S['tshark_seconds']} s",
         f"- attacker-MAC packets: sent {S['att_src']:,} ({pct(S['att_src'], S['packets'])}%), "
         f"received {S['att_dst']:,}",
         f"- **background share** (neither from nor to an attacker MAC): {P['background_pct']}%",
         f"- attacker packets span {w['first_utc'] or '-'} -> {w['last_utc'] or '-'}; "
         f"{w['active_minutes']} active minutes; {w['pkts_per_min_over_capture']:,} pkt/min over "
         f"the capture, peak {w['peak_pkts_per_min']:,}",
         f"- attacker protocols: {P['protocols']}; TCP flags: {P['tcp_flags']}",
         f"- broadcast / multicast destinations of attacker packets (never victims): "
         f"{P['bcast_mcast'] or 'none'}",
         f"- gateway {NETWORK.gateway_ip} seen with MAC(s) {P['gateway_ip_macs'] or '-'} "
         f"(table gateway MAC is used for 'gateway')",
         f"- caps: {P['caps']}", "",
         f"**Coverage (min victims {min_v}):** overall **{overall}**", ""]
    L += md_table([{**c, "verdict": v.get(c["group"], "-")} for c in P["cover"]],
                  ["group", "n_victims", "attack_packets", "window_start", "window_end", "verdict"])
    L += ["", f"**Burst windows** (report only; attacker packets/min > {P['burst_threshold']:,} "
          f"= K x control mean, gaps <= {BURST_GAP_MIN} min merged): {len(P['bursts'])}", ""]
    L += md_table(P["bursts"], ["start", "end", "minutes", "packets", "peak_per_min"])
    L += ["", "**Per attacker MAC:**", ""]
    L += md_table(P["per_mac"], ["attacker_mac", "device", "packets", "pkt_per_min",
                                 "control_pkt_per_min", "victims", "victims_by_group",
                                 "burst_windows", "bursts"])
    L += ["", f"**Victims ({len(P['victims'])}):**", ""]
    L += md_table(P["victims"], ["mac", "device", "group", "attack_packets", "reason",
                                 "rate_ratio", "new_service_pairs", "distinct_dst_ports",
                                 "protocols", "attacker_macs"])
    L += ["", "**All attacker -> unicast destination pairs** (control comparison):", ""]
    L += md_table(P["pairs"], ["attacker_mac", "device", "group", "attack_packets",
                               "control_packets", "rate_ratio", "new_service_pairs",
                               "new_services", "reason"])
    L += ["", f"**Spoofing:** {sp['distinct_ip_src']:,} distinct ip.src on attacker-MAC packets "
          f"({sp['distinct_method']}) -> "
          f"{'**SPOOFED SOURCES**' if sp['flag'] else 'not spoofed'} (threshold > {SPOOF_THRESHOLD}); "
          f"{sp['collide_with_device_ips']:,} are real smart-home device IPs in this pcap's map "
          f"({sp['packets_from_device_ips']:,} packets), "
          f"{sp['collide_with_any_lan_host_ip']:,} are any LAN host IP.", ""]
    L += md_table(sp["top_ip_src"], ["ip_src", "packets", "is_device_ip"])
    L += ["", f"**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): "
          f"**{x['disagree']:,} disagreeing packets**", ""]
    L += md_table([{"outcome": k, "packets": n} for k, n in x["outcomes"].items()],
                  ["outcome", "packets"])
    if x["top_disagreements"]:
        L += ["", "Top disagreements:", ""]
        L += md_table(x["top_disagreements"], ["ip_dst", "map_device", "eth_dst_device", "packets"])
    return L + [""] + census_md(P["census"])


def stale_keys(old: dict, params: dict) -> list[str]:
    """Completion-key entries that differ between a stats file and the current run."""
    return sorted(k for k in set(old) | set(params) if old.get(k) != params.get(k))


def rebuild(out: Path, B: dict, params: dict, min_v: int, att_rows: list[dict],
            devices: Path) -> list[dict]:
    """coverage_summary.csv, coverage_report.md, sha256.txt from every *_stats.json in out."""
    stats = []
    for f in sorted(out.glob("*_stats.json")):
        try:
            P = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log(f"  [warn] skipping unreadable {f.name}: {e}")
            continue
        if P.get("stats_version") == STATS_VERSION:
            stats.append(P)
    summ = []
    for P in stats:
        summ += P["cover"]
        summ += [{"pcap": P["stem"], "group": "burst", "n_victims": "",
                  "attack_packets": b["packets"], "window_start": b["start"],
                  "window_end": b["end"]} for b in P["bursts"]]
    write_csv(out / "coverage_summary.csv", summ,
              ["pcap", "group", "n_victims", "attack_packets", "window_start", "window_end"])
    (out / "sha256.txt").write_text(
        f"{B['sha256']}  {B['pcap']}\n" + "".join(f"{P['sha256']}  {P['pcap']}\n" for P in stats),
        encoding="utf-8")
    c_rate = round(B["att_src"] / B["minutes"], 2)
    c_thr = params["rate_k"] * B["att_src"] / B["minutes"]
    ov = []
    for P in stats:
        v, overall = verdicts(P, min_v)
        n = {c["group"]: c["n_victims"] for c in P["cover"]}
        ov.append({"pcap": P["stem"], "G1": f"{n['G1']} {v['G1']}", "G2": f"{n['G2']} {v['G2']}",
                   "GEN": n["GEN"], "gateway": n["gateway"], "overall": overall,
                   "attacker_pkts": P["S"]["att_src"],
                   "pkt_per_min": P["window"]["pkts_per_min_over_capture"],
                   "x_control": round(P["window"]["pkts_per_min_over_capture"] / c_rate, 1)
                   if c_rate else "-",
                   "bursts": len(P["bursts"]), "spoofed": "yes" if P["spoof"]["flag"] else "no",
                   "ip_mac_disagree": P["xcheck"]["disagree"], "background_pct": P["background_pct"],
                   "params": ("current" if P["params"] == params else
                              "STALE: " + ", ".join(stale_keys(P["params"], params)))})
    L = ["# Step 7a -- attack coverage (attacker MAC -> victim device -> behaviour group)", "",
         f"- rebuilt: {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')} from "
         f"{len(stats)} per-pcap stats file(s) in `{out}`",
         f"- attacker MACs: exact {list(ATTACKER_MACS.exact)}, prefixes "
         f"{list(ATTACKER_MACS.prefixes)}; device table `{devices}` (sha256 "
         f"`{params['device_table_sha256']}`) "
         f"({len(att_rows)} testbed-Pi rows match, safety check passed)",
         f"- victim rule (per attacker MAC -> device pair vs control `{B['pcap']}`): rate > "
         f"{params['rate_k']:g} x control rate (control packets floored at 1) OR >= "
         f"{params['min_new_services']} new {SERVICE_DEF} pair(s)",
         f"- min victims per group: {min_v}; spoofing flag: > {SPOOF_THRESHOLD} distinct ip.src; "
         "tshark env TZ=UTC; params=STALE rows were computed with a different completion key (rule parameters / control / device_table) -- re-run them", "",
         "## Overview", ""]
    L += md_table(ov, list(ov[0].keys()) if ov else ["pcap"])
    L += ["", f"## Control: {Path(B['pcap']).stem}", "",
          f"- packets {B['packets']:,}; {B['minutes']:.1f} min; attacker-MAC packets "
          f"{B['att_src']:,} = **{c_rate} pkt/min** (burst threshold {c_thr:,.1f} pkt/min); "
          f"sha256 `{B['sha256']}`; baseline built {B['created_utc']}", ""]
    L += census_md(B["census"])
    for P in stats:
        L += ["", f"## Attack: {P['stem']}", "", f"- sha256: `{P['sha256']}`",
              f"- rate plot: `{P['png']}`"]
        L += pcap_md(P, min_v)
    (out / "coverage_report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    return ov


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pcap", type=Path, nargs="+", required=True,
                    help=f"attack pcaps (must be under CACHE_DIR = {CACHE_DIR})")
    ap.add_argument("--control", type=Path, default=None,
                    help="benign pcap (under CACHE_DIR); REQUIRED: the victim rule needs it")
    ap.add_argument("--min-victims", type=int, default=2)
    ap.add_argument("--rate-k", type=float, default=10.0,
                    help="pair is a victim if its rate > K x its control rate (default 10)")
    ap.add_argument("--min-new-services", type=int, default=1,
                    help="... or if it uses >= N services unseen in control (default 1)")
    ap.add_argument("--out-dir", type=Path, default=RESULTS_DIR / "step7" / "coverage")
    ap.add_argument("--skip-done", action="store_true",
                    help="skip pcaps whose <stem>_stats.json has the same pcap SHA256 and "
                         "completion key (rule params, control and device_table SHA256)")
    ap.add_argument("--devices", type=Path, default=DEVICE_TABLE,
                    help=f"device table (default {DEVICE_TABLE})")
    args = ap.parse_args()

    if args.control is None:
        fatal("--control is required: the victim rule compares every attacker -> device pair "
              "with a benign baseline (e.g. --control ~/lgids_cache/BenignTraffic.pcap)")
    if shutil.which("tshark") is None:
        fatal("tshark not found on PATH")
    if args.min_victims < 1 or args.rate_k <= 0 or args.min_new_services < 1:
        fatal("--min-victims and --min-new-services must be >= 1, --rate-k > 0")
    cache = CACHE_DIR.resolve()
    for p in args.pcap + [args.control]:
        if not p.is_file():
            fatal(f"pcap not found: {p}")
        if not p.resolve().is_relative_to(cache):
            fatal(f"{p} is not under CACHE_DIR ({cache}); copy it to the cache first "
                  "(reading pcaps from /mnt/d is slow)")
    stems = [p.stem for p in args.pcap]
    if len(set(stems)) != len(stems):
        fatal(f"attack pcap stems must be unique (outputs are named by stem): {stems}")
    out = args.out_dir if args.out_dir.is_absolute() else REPO_ROOT / args.out_dir
    for forbidden in (REPO_ROOT / "config", REPO_ROOT / "data"):
        if out.resolve().is_relative_to(forbidden.resolve()):
            fatal(f"--out-dir must not be under {forbidden}")
    out.mkdir(parents=True, exist_ok=True)

    if not args.devices.is_file():
        fatal(f"device table not found: {args.devices}")
    dev = Devices(args.devices)
    dev_sha = sha256(args.devices)
    log(f"device table {args.devices} sha256 {dev_sha}")
    att_rows = dev.safety_check()
    log(f"safety check OK: {len(att_rows)} device_table rows match ATTACKER_MACS, all "
        f"role=testbed_pi, none grouped (exact {list(ATTACKER_MACS.exact)}, prefixes "
        f"{list(ATTACKER_MACS.prefixes)})")

    # ---- control baseline (cached by SHA256)
    log(f"\n=== control: {args.control}")
    c_sha = sha256(args.control, args.control.name)
    bpath = out / "control_baseline.json"
    B = None
    if bpath.is_file():
        try:
            old = json.loads(bpath.read_text(encoding="utf-8"))
            if (old.get("sha256") == c_sha and old.get("format") == BASELINE_FORMAT
                    and old.get("service_definition") == SERVICE_DEF):
                B = old
                log(f"  reusing {bpath.name} (sha256 {c_sha[:16]}... matches)")
            else:
                log(f"  {bpath.name} is for another control / format; rebuilding")
        except (OSError, json.JSONDecodeError):
            log(f"  {bpath.name} unreadable; rebuilding")
    if B is None:
        R = analyse(args.control, dev)
        B = baseline_from(R, args.control, c_sha, dev)
        write_json(bpath, B)
        del R
        gc.collect()
        log(f"  wrote {bpath.name}")
    C = control_view(B)
    c_rate = B["att_src"] / B["minutes"]
    c_thr = args.rate_k * c_rate
    log(f"  control attacker-MAC rate {c_rate:.2f} pkt/min over {B['minutes']:.1f} min "
        f"-> burst threshold {c_thr:,.1f} pkt/min (K={args.rate_k:g}); peak RSS {peak_rss()}")
    c_stem = Path(B["pcap"]).stem
    plot_rate(c_stem, per_minute(C["per_min"]), c_thr, out, f"attack_rate_{c_stem}_control.png",
              "control")
    params = {"rate_k": args.rate_k, "min_new_services": args.min_new_services,
              "control_sha256": c_sha, "device_table_sha256": dev_sha,
              "stats_version": STATS_VERSION}

    # ---- attack pcaps, one at a time
    for i, p in enumerate(args.pcap, 1):
        log(f"\n=== attack {i}/{len(args.pcap)}: {p}")
        digest = sha256(p, p.name)
        spath = out / f"{p.stem}_stats.json"
        if args.skip_done and spath.is_file():
            try:
                old = json.loads(spath.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                old = {}
            if old.get("sha256") == digest and old.get("params") == params:
                log(f"  --skip-done: {spath.name} matches pcap sha256 and completion key; skipped")
                continue
            diff = (["pcap sha256"] if old.get("sha256") != digest else []) + \
                stale_keys(old.get("params", {}), params)
            log(f"  --skip-done: {spath.name} differs in {', '.join(diff)}; re-running")
        t0 = time.monotonic()
        R = analyse(p, dev, C)
        P = summarise(p, R, C, dev, att_rows, args.rate_k, args.min_new_services)
        del R
        gc.collect()
        P.update({"stats_version": STATS_VERSION, "sha256": digest, "params": params,
                  "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                  "png": f"attack_rate_{p.stem}.png"})
        log(f"\n  Source-MAC census, top {CENSUS_TOP} ({P['stem']}):")
        for r in P["census"]:
            log(f"    {r['rank']:>2}. {r['eth_src']}  {r['packets']:>11,}  {r['pct']:>7.3f}%  {r['tag']}")
        write_csv(out / f"{P['stem']}_victims.csv", P["victims"], VICTIM_COLS)
        write_csv(out / f"{P['stem']}_pairs.csv", P["pairs"], PAIR_COLS)
        plot_rate(P["stem"], Counter({int(m): n for m, n in P["per_min"].items()}),
                  P["burst_threshold"], out, P["png"], "attack")
        P["peak_rss"] = peak_rss()
        write_json(spath, P)          # completion marker: written last
        rebuild(out, B, params, args.min_victims, att_rows, args.devices)
        log(f"  finished {p.name} in {time.monotonic() - t0:.1f} s; peak RSS so far: "
            f"python {P['peak_rss']['self_mb']:,} MB, tshark {P['peak_rss']['tshark_mb']:,} MB")

    ov = rebuild(out, B, params, args.min_victims, att_rows, args.devices)

    # compact console summary (all stats files in out-dir)
    log("\n" + "=" * 118)
    log(f"COVERAGE SUMMARY  min victims {args.min_victims}, K={args.rate_k:g}, "
        f"min new services {args.min_new_services}, control {c_stem} "
        f"({c_rate:.2f} attacker pkt/min)   out: {out}")
    log(f"{'pcap':<30} {'G1':>7} {'G2':>7} {'GEN':>4} {'gw':>3}  {'overall':<8} {'att_pkts':>11} "
        f"{'pkt/min':>10} {'x_ctl':>7} {'bursts':>6} {'spoof':>5} {'ip/mac≠':>7} {'bg%':>7} params")
    for r in ov:
        log(f"{r['pcap'][:30]:<30} {r['G1']:>7} {r['G2']:>7} {r['GEN']:>4} {r['gateway']:>3}  "
            f"{r['overall']:<8} {r['attacker_pkts']:>11,} {r['pkt_per_min']:>10,} "
            f"{r['x_control']:>7} {r['bursts']:>6} {r['spoofed']:>5} {r['ip_mac_disagree']:>7,} "
            f"{r['background_pct']:>7} {r['params']}")
    for f in sorted(out.glob("*_stats.json")):
        P = json.loads(f.read_text(encoding="utf-8"))
        if P.get("stats_version") != STATS_VERSION:
            continue
        log(f"  {P['stem']}: victims " + (", ".join(f"{v['device']} ({v['group']}, {v['reason']})"
                                                   for v in P["victims"]) or "none"))
        for m in P["per_mac"]:
            if m["packets"]:
                log(f"    {m['attacker_mac']}  {m['packets']:>11,} pkts  victims {m['victims']} "
                    f"[{m['victims_by_group']}]  bursts {m['burst_windows']}")
        silent = [m["attacker_mac"] for m in P["per_mac"] if not m["packets"]]
        if silent:
            log(f"    silent attacker MACs: {len(silent)} ({', '.join(silent)})")
    rss = peak_rss()
    log(f"peak RSS: python {rss['self_mb']:,} MB, tshark {rss['tshark_mb']:,} MB")
    log("=" * 118)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
