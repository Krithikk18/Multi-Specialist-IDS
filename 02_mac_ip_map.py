#!/usr/bin/env python
"""02_mac_ip_map.py -- time-aware LAN IP -> MAC -> device map from the raw benign pcap.

CICFlowMeter flows only carry IP addresses. To tag flows with devices later, this script
learns which MAC (and therefore which device in the device table) used each LAN IP, and
when. It reads the pcap once with tshark, never modifies inputs, and writes:

  config/ip_mac_map.csv                one row per (ip, mac) with time window + evidence
  results/step5/ip_mac_map_report.md   human-readable report
  results/step5/ip_mac_map_report.json same data, machine-readable

Evidence for a (mac, ip) pair comes from three places in every packet:
  src : (eth.src, ip.src | ipv6.src)
  dst : (eth.dst, ip.dst | ipv6.dst)          only when eth.dst is unicast
  arp : (arp.src.hw_mac, arp.src.proto_ipv4)

Only LAN-scope IPs are kept (IPv4 private / 169.254 link-local, IPv6 fe80::/10 / fc00::/7).
Rationale: on a LAN capture every packet to or from an external (internet) IP carries the
GATEWAY's MAC on the LAN side, so mapping external IPs would label every internet server as
"the gateway". Unspecified, multicast, limited-broadcast and subnet-broadcast addresses and
non-unicast / all-zero MACs are dropped too: they do not identify a single host.

Exit status is non-zero only for fatal errors (missing input, tshark failure, cache
verification failure).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress as ipa
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
GATEWAY_MAC = "3c:18:a0:41:c3:a0"
EXPECTED_PACKETS = 3_664_164
PROGRESS_EVERY = 500_000

TSHARK_FIELDS = ["frame.time_epoch", "eth.src", "eth.dst", "ip.src", "ip.dst",
                 "ipv6.src", "ipv6.dst", "arp.src.hw_mac", "arp.src.proto_ipv4"]
EVIDENCE = ("src", "dst", "arp")

# Lean tshark (same flags as 07a_attack_coverage.py): only the dissectors the fields need, no TCP
# sequence analysis / reassembly, and per-conversation state reset every TSHARK_RESET packets.
# Without -M, tshark's state grows with every conversation: 5.2 GB RSS on a 3M-packet SYN flood,
# ~47 GB projected for a 26.7M-packet part. Field output is unchanged on the benign pcap
# (02's map and 04's tagged flows are byte-identical with and without these flags).
TSHARK_PROTOCOLS = "frame,eth,ethertype,ip,arp,tcp,udp,icmp,ipv6,vlan"
TSHARK_RESET = 200_000
TSHARK_LEAN = ["-M", str(TSHARK_RESET), "--disable-all-protocols", "--enable-protocol",
               TSHARK_PROTOCOLS, "-o", "tcp.analyze_sequence_numbers:FALSE",
               "-o", "tcp.desegment_tcp_streams:FALSE"]

LAN_V4 = [ipa.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                       "169.254.0.0/16")]
LAN_V6 = [ipa.ip_network(n) for n in ("fe80::/10", "fc00::/7")]

# Logical column -> accepted spellings after normalisation (lower-case alphanumerics only).
DEVICE_COLS = {
    "mac": ["mac", "macaddress", "ethmac", "hwaddr"],
    "device_name": ["devicename", "device", "name"],
    "category": ["category", "papercategory", "devicecategory", "class"],
    "role": ["role", "type", "devicetype", "roletype", "devicerole"],
}
FLOW_COLS = {"src_ip": ["srcip", "sourceip"], "dst_ip": ["dstip", "destinationip"]}

# device_table role -> coverage bucket
ROLE_BUCKET = {"iot": "smart-home", "gateway": "gateway", "testbed_pi": "testbed",
               "excluded": "phone", "unknown": "unknown", "unlisted": "unlisted"}
BUCKETS = ["smart-home", "gateway", "testbed", "phone", "unknown", "unlisted", "unmapped"]


# --------------------------------------------------------------------------- helpers

def log(msg: str) -> None:
    print(msg, flush=True)


def fatal(msg: str) -> None:
    print(f"FATAL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def norm(name: str) -> str:
    return re.sub(r"[^0-9a-z]", "", name.lower())


def match_columns(header: list[str], wanted: dict[str, list[str]], what: str) -> dict[str, str]:
    lookup = {norm(h): h for h in header}
    out, missing = {}, []
    for key, aliases in wanted.items():
        hit = next((lookup[a] for a in aliases if a in lookup), None)
        if hit is None:
            missing.append(f"{key} (tried {aliases})")
        else:
            out[key] = hit
    if missing:
        fatal(f"{what}: cannot match columns {missing} in header {header}")
    return out


def norm_mac(mac: str) -> str:
    hexd = re.sub(r"[^0-9a-f]", "", str(mac).strip().lower())
    if len(hexd) != 12:
        return str(mac).strip().lower()
    return ":".join(hexd[i:i + 2] for i in range(0, 12, 2))


def mac_is_unicast(mac: str) -> bool:
    try:
        return int(mac[:2], 16) & 1 == 0 and mac != "00:00:00:00:00:00"
    except ValueError:
        return False


def sha256(path: Path, label: str = "", chunk: int = 16 << 20) -> str:
    h, done, size = hashlib.sha256(), 0, path.stat().st_size
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
            done += len(block)
            if label and done % (512 << 20) < chunk:
                log(f"  hashing {label}: {done / 2**30:.2f} / {size / 2**30:.2f} GiB")
    return h.hexdigest()


def utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat(timespec="microseconds")


def pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 3) if d else 0.0


# --------------------------------------------------------------------------- step 0: cache

def ensure_cached(src: Path, cache_dir: Path, rehash: bool) -> tuple[Path, dict]:
    """Copy the pcap to fast WSL ext4 storage once; verify the copy's SHA256 equals the
    original's. The original's hash is remembered in a sidecar keyed on its size + mtime,
    so later runs do not have to re-read 1.9 GB over /mnt/d (use --rehash-source to force)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    dst = cache_dir / src.name
    sidecar = cache_dir / f"{src.name}.sha256.json"
    st = src.stat()
    ident = {"source": str(src.resolve()), "size": st.st_size, "mtime_ns": st.st_mtime_ns}

    src_hash, how = None, None
    if sidecar.exists() and not rehash:
        side = json.loads(sidecar.read_text())
        if all(side.get(k) == v for k, v in ident.items()):
            src_hash, how = side["sha256"], "sidecar (source size+mtime unchanged)"

    if dst.exists() and dst.stat().st_size == st.st_size:
        if src_hash is None:
            log("Hashing original pcap on /mnt/d (slow) ...")
            src_hash, how = sha256(src, "original"), "re-hashed original"
        log("Verifying cached copy ...")
        cache_hash = sha256(dst, "cache")
        if cache_hash == src_hash:
            sidecar.write_text(json.dumps({**ident, "sha256": src_hash}, indent=2))
            return dst, {"cached_path": str(dst), "action": "reused existing cache",
                         "source_hash_from": how, "sha256": src_hash, "verified": True}
        log("Cached copy does not match original -> re-copying")

    log(f"Copying pcap to cache {dst} (hashing the original on the fly) ...")
    tmp = dst.with_name(dst.name + ".part")
    h, done, chunk = hashlib.sha256(), 0, 16 << 20
    with open(src, "rb") as fi, open(tmp, "wb") as fo:
        while block := fi.read(chunk):
            h.update(block)
            fo.write(block)
            done += len(block)
            if done % (256 << 20) < chunk:
                log(f"  copied {done / 2**30:.2f} / {st.st_size / 2**30:.2f} GiB")
    src_hash = h.hexdigest()
    os.replace(tmp, dst)
    log("Verifying cached copy ...")
    cache_hash = sha256(dst, "cache")
    if cache_hash != src_hash:
        fatal(f"cache verification failed: original {src_hash} != cache {cache_hash}")
    sidecar.write_text(json.dumps({**ident, "sha256": src_hash}, indent=2))
    return dst, {"cached_path": str(dst), "action": "copied", "source_hash_from":
                 "hashed during copy", "sha256": src_hash, "verified": True}


# --------------------------------------------------------------------------- step 1: extract

def extract(pcap: Path) -> tuple[dict, dict]:
    """Single streaming tshark pass. Returns
    agg[(mac, ip)] = [first, last, n_src, n_dst, n_arp] and packet-level stats."""
    cmd = ["tshark", "-n", *TSHARK_LEAN, "-r", str(pcap), "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=f"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    log("Running: " + " ".join(cmd))

    agg: dict[tuple[str, str], list] = {}
    unicast_cache: dict[str, bool] = {}
    stats = Counter()
    nf = len(TSHARK_FIELDS)

    def add(mac: str, ip: str, which: int, t: float) -> None:
        rec = agg.get((mac, ip))
        if rec is None:
            agg[(mac, ip)] = rec = [t, t, 0, 0, 0]
        elif t < rec[0]:
            rec[0] = t
        elif t > rec[1]:
            rec[1] = t
        rec[2 + which] += 1

    t0 = time.monotonic()
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf,
                                text=True, bufsize=1 << 20)
        for line in proc.stdout:
            p = line.rstrip("\n").split("\t")
            if len(p) < nf:
                p += [""] * (nf - len(p))
            stats["packets"] += 1
            t = float(p[0]) if p[0] else 0.0
            esrc, edst, ip4s, ip4d, ip6s, ip6d, amac, aip = p[1:9]
            srcip, dstip = ip4s or ip6s, ip4d or ip6d

            if not esrc:
                stats["no_ethernet"] += 1
            if ip4s:
                stats["ipv4"] += 1
            elif ip6s:
                stats["ipv6"] += 1
            elif amac:
                stats["arp"] += 1
            else:
                stats["other_non_ip"] += 1

            if esrc and srcip:
                add(esrc, srcip, 0, t)
            if edst and dstip:
                uni = unicast_cache.get(edst)
                if uni is None:
                    uni = unicast_cache[edst] = mac_is_unicast(edst)
                if uni:
                    add(edst, dstip, 1, t)
                else:
                    stats["dst_skipped_non_unicast_mac"] += 1
            if amac and aip:
                add(amac, aip, 2, t)

            if stats["packets"] % PROGRESS_EVERY == 0:
                el = time.monotonic() - t0
                log(f"  {stats['packets']:>9,} packets  {el:6.1f} s  "
                    f"({stats['packets'] / el:,.0f} pkt/s)  pairs={len(agg):,}")
        rc = proc.wait()
        errf.seek(0)
        err = errf.read().decode(errors="replace").strip()
    err = "\n".join(l for l in err.splitlines() if l.strip() != "resetting session.")
    if rc != 0:
        fatal(f"tshark exited with {rc}: {err[-2000:]}")
    stats["tshark_seconds"] = round(time.monotonic() - t0, 1)
    stats["tshark_stderr"] = err[-2000:]
    log(f"  done: {stats['packets']:,} packets in {stats['tshark_seconds']} s, "
        f"{len(agg):,} raw (mac, ip) pairs")
    return agg, dict(stats)


# --------------------------------------------------------------------------- filtering

def ip_scope(ip: str) -> tuple[ipa._BaseAddress | None, str | None]:
    """Return (address, rejection reason or None) ignoring subnet broadcast."""
    try:
        a = ipa.ip_address(ip)
    except ValueError:
        return None, "invalid_ip"
    if a.is_unspecified:
        return a, "unspecified"
    if a.is_multicast:
        return a, "multicast"
    if a.version == 4 and a == ipa.IPv4Address("255.255.255.255"):
        return a, "limited_broadcast"
    nets = LAN_V4 if a.version == 4 else LAN_V6
    if not any(a in n for n in nets):
        return a, "not_lan_scope"
    return a, None


def infer_subnets(agg: dict) -> tuple[list[dict], set]:
    """Assume /24 LANs: group private IPv4 seen as a *source* (src/arp evidence from a
    unicast MAC) by /24. Each /24's .255 is treated as its subnet broadcast address."""
    per24: dict[ipa.IPv4Network, dict] = defaultdict(lambda: {"hosts": set(), "packets": 0})
    for (mac, ip), rec in agg.items():
        if rec[2] + rec[4] == 0 or not mac_is_unicast(mac):
            continue
        a, why = ip_scope(ip)
        if why or a.version != 4 or a in LAN_V4[3]:
            continue
        net = ipa.ip_network(f"{ip}/24", strict=False)
        per24[net]["hosts"].add(a)
        per24[net]["packets"] += rec[2] + rec[4]
    subnets, bcast = [], {ipa.IPv4Address("169.254.255.255")}
    for net, d in sorted(per24.items(), key=lambda kv: -kv[1]["packets"]):
        hosts = sorted(d["hosts"])
        # tightest prefix covering all observed hosts (informational)
        span = int(hosts[0]) ^ int(hosts[-1])
        tight = 32 - span.bit_length()
        subnets.append({"subnet": str(net), "broadcast": str(net.broadcast_address),
                        "hosts_seen": len(hosts), "source_evidence_packets": d["packets"],
                        "host_range": f"{hosts[0]} - {hosts[-1]}",
                        "tightest_covering_prefix": f"/{tight}"})
        bcast.add(net.broadcast_address)
    return subnets, bcast


def filter_pairs(agg: dict, bcast: set) -> tuple[dict, dict]:
    kept, rej_pairs, rej_pkts = {}, Counter(), Counter()
    scope_cache: dict[str, tuple] = {}
    for (mac, ip), rec in agg.items():
        n = rec[2] + rec[3] + rec[4]
        if not mac_is_unicast(mac):
            why = "mac_zero" if mac == "00:00:00:00:00:00" else "mac_not_unicast"
        else:
            if ip not in scope_cache:
                scope_cache[ip] = ip_scope(ip)
            a, why = scope_cache[ip]
            if why is None and a in bcast:
                why = "subnet_broadcast"
        if why:
            rej_pairs[why] += 1
            rej_pkts[why] += n
        else:
            kept[(mac, ip)] = rec
    return kept, {"pairs": dict(rej_pairs), "evidence_packets": dict(rej_pkts)}


# --------------------------------------------------------------------------- device table

def load_devices(path: Path) -> tuple[pd.DataFrame, dict]:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    cols = match_columns(list(df.columns), DEVICE_COLS, f"device table {path}")
    dev = pd.DataFrame({k: df[v].str.strip() for k, v in cols.items()})
    dev["mac"] = dev["mac"].map(norm_mac)
    dev["role"] = dev["role"].str.lower()
    dups = dev["mac"][dev["mac"].duplicated()].tolist()
    if dups:
        log(f"WARNING: duplicate MACs in device table (first kept): {dups}")
        dev = dev.drop_duplicates("mac")
    return dev, cols


# --------------------------------------------------------------------------- step 3: checks

def overlaps(a: dict, b: dict) -> bool:
    return a["first_seen_epoch"] <= b["last_seen_epoch"] and b["first_seen_epoch"] <= a["last_seen_epoch"]


def time_checks(m: pd.DataFrame, dev: pd.DataFrame) -> dict:
    flags = defaultdict(set)
    ip_conflicts = []
    for ip, g in m.groupby("ip", sort=False):
        if len(g) < 2:
            continue
        rows = g.sort_values("first_seen_epoch").to_dict("records")
        any_overlap = False
        for i, r in enumerate(rows):
            ov = any(overlaps(r, o) for j, o in enumerate(rows) if j != i)
            any_overlap |= ov
            flags[r["_idx"]].add("ip_multi_mac_overlapping" if ov else "ip_multi_mac_sequential")
        ip_conflicts.append({
            "ip": ip, "classification": "OVERLAPPING" if any_overlap else "SEQUENTIAL",
            "macs": [{"mac": r["mac"], "device_name": r["device_name"], "role": r["role"],
                      "first_seen_utc": r["first_seen_utc"], "last_seen_utc": r["last_seen_utc"],
                      "packets": r["packets"], "evidence_src": r["evidence_src"],
                      "evidence_dst": r["evidence_dst"], "evidence_arp": r["evidence_arp"]}
                     for r in rows]})

    mac_multi = []
    for mac, g in m.groupby("mac", sort=False):
        if len(g) < 2:
            continue
        v4 = g[g["ip_version"] == 4]
        if len(v4) > 1:
            for idx in v4["_idx"]:
                flags[idx].add("mac_multi_ipv4")
        mac_multi.append({
            "mac": mac, "device_name": g["device_name"].iloc[0], "role": g["role"].iloc[0],
            "n_ipv4": int(len(v4)), "n_ipv6": int((g["ip_version"] == 6).sum()),
            "flag_multiple_ipv4": bool(len(v4) > 1),
            "ips": [{"ip": r["ip"], "ip_version": r["ip_version"],
                     "first_seen_utc": r["first_seen_utc"], "last_seen_utc": r["last_seen_utc"],
                     "packets": r["packets"]}
                    for r in g.sort_values("first_seen_epoch").to_dict("records")]})

    gw = m[m["mac"] == GATEWAY_MAC]
    gateway = [{"ip": r["ip"], "ip_version": r["ip_version"], "packets": r["packets"],
                "first_seen_utc": r["first_seen_utc"], "last_seen_utc": r["last_seen_utc"]}
               for r in gw.sort_values("packets", ascending=False).to_dict("records")]

    mapped_macs = set(m["mac"])
    no_ip = dev[~dev["mac"].isin(mapped_macs)]
    unlisted = m[m["role"] == "unlisted"]
    return {
        "flags": flags,
        "ip_multi_mac": ip_conflicts,
        "ip_multi_mac_sequential": sum(c["classification"] == "SEQUENTIAL" for c in ip_conflicts),
        "ip_multi_mac_overlapping": sum(c["classification"] == "OVERLAPPING" for c in ip_conflicts),
        "mac_multi_ip": mac_multi,
        "mac_multi_ipv4_count": sum(x["flag_multiple_ipv4"] for x in mac_multi),
        "gateway_mac": GATEWAY_MAC, "gateway_ips": gateway,
        "devices_without_lan_ip": no_ip[["mac", "device_name", "category", "role"]].to_dict("records"),
        "lan_ips_with_unlisted_mac": unlisted[["ip", "mac", "packets", "first_seen_utc",
                                               "last_seen_utc", "evidence_src", "evidence_dst",
                                               "evidence_arp"]].to_dict("records"),
    }


# --------------------------------------------------------------------------- step 4: coverage

def coverage(flows_path: Path, m: pd.DataFrame, bcast: set) -> dict:
    header = pd.read_csv(flows_path, nrows=0).columns.tolist()
    cols = match_columns(header, FLOW_COLS, f"flows {flows_path}")
    f = pd.read_csv(flows_path, usecols=list(cols.values()), dtype=str)
    src, dst = f[cols["src_ip"]].str.strip(), f[cols["dst_ip"]].str.strip()
    n = len(f)

    # IP-only preview (no time window): an IP with several MACs -> the one with most packets.
    best = m.sort_values("packets", ascending=False).drop_duplicates("ip")
    ip_bucket = dict(zip(best["ip"], best["role"].map(lambda r: ROLE_BUCKET.get(r, "unknown"))))
    conflicted = set(m.loc[m["ip"].duplicated(keep=False), "ip"])
    sb = src.map(ip_bucket).fillna("unmapped")
    db = dst.map(ip_bucket).fillna("unmapped")

    sh_s, sh_d = sb == "smart-home", db == "smart-home"
    smart = {"flows": n,
             "src_smart_home": int(sh_s.sum()), "src_smart_home_pct": pct(sh_s.sum(), n),
             "dst_smart_home": int(sh_d.sum()), "dst_smart_home_pct": pct(sh_d.sum(), n),
             "either_smart_home": int((sh_s | sh_d).sum()),
             "either_smart_home_pct": pct((sh_s | sh_d).sum(), n),
             "neither_smart_home": int((~(sh_s | sh_d)).sum()),
             "neither_smart_home_pct": pct((~(sh_s | sh_d)).sum(), n)}
    by_role = {}
    for b in BUCKETS:
        s_, d_ = sb == b, db == b
        by_role[b] = {"src": int(s_.sum()), "src_pct": pct(s_.sum(), n),
                      "dst": int(d_.sum()), "dst_pct": pct(d_.sum(), n),
                      "either": int((s_ | d_).sum()), "either_pct": pct((s_ | d_).sum(), n)}

    mapped = set(m["ip"])
    cache: dict[str, bool] = {}

    def lan_unmapped(ip: str) -> bool:
        if ip not in cache:
            a, why = ip_scope(ip)
            cache[ip] = why is None and a not in bcast and ip not in mapped
        return cache[ip]

    both = pd.concat([src, dst.where(dst != src)]).dropna()
    both = both[both.map(lan_unmapped)]
    top = both.value_counts().head(10)
    return {"flow_columns": cols, "smart_home": smart, "by_role": by_role,
            "flows_touching_multi_mac_ip": int((src.isin(conflicted) | dst.isin(conflicted)).sum()),
            "lan_scope_unmapped_distinct_ips": int(both.nunique()),
            "top10_lan_scope_unmapped": [{"ip": ip, "flows": int(c)} for ip, c in top.items()]}


# --------------------------------------------------------------------------- reporting

def md_table(rows: list[dict], cols: list[str]) -> list[str]:
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(f"{r.get(c, ''):,}" if isinstance(r.get(c), int)
                                      and not isinstance(r.get(c), bool) else str(r.get(c, ""))
                                      for c in cols) + " |")
    return out


def write_md(path: Path, rep: dict) -> None:
    L = ["# LAN IP -> MAC -> device map report", ""]
    L += [f"- **{k}**: {v}" for k, v in rep["meta"].items()]
    s = rep["summary"]
    L += ["", "## Summary", ""] + [f"- **{k}**: {v}" for k, v in s.items()]
    L += ["", "## Packet stats (tshark pass)", ""]
    L += [f"- **{k}**: {v:,}" if isinstance(v, int) else f"- **{k}**: {v}"
          for k, v in rep["packet_stats"].items() if k != "tshark_stderr"]
    if rep["packet_stats"].get("tshark_stderr"):
        L += ["", "tshark stderr:", "", "```", rep["packet_stats"]["tshark_stderr"], "```"]
    L += ["", "## Inferred subnet(s)", "", rep["subnet_assumption"], ""]
    L += md_table(rep["subnets"], ["subnet", "broadcast", "hosts_seen", "host_range",
                                   "tightest_covering_prefix", "source_evidence_packets"])
    L += ["", "## Filtering (raw pairs dropped)", ""]
    rows = [{"reason": k, "pairs": v, "evidence_packets": rep["filtering"]["evidence_packets"][k]}
            for k, v in sorted(rep["filtering"]["pairs"].items())]
    L += md_table(rows, ["reason", "pairs", "evidence_packets"])

    c = rep["checks"]
    L += ["", f"## Gateway ({c['gateway_mac']}) LAN IPs", ""]
    L += md_table(c["gateway_ips"], ["ip", "ip_version", "packets", "first_seen_utc", "last_seen_utc"])
    L += ["", f"## IPs with more than one MAC ({c['ip_multi_mac_sequential']} sequential, "
          f"{c['ip_multi_mac_overlapping']} overlapping)", ""]
    if not c["ip_multi_mac"]:
        L += ["_none_"]
    for x in c["ip_multi_mac"]:
        L += ["", f"### {x['ip']} -- {x['classification']}", ""]
        L += md_table(x["macs"], ["mac", "device_name", "role", "first_seen_utc", "last_seen_utc",
                                  "packets", "evidence_src", "evidence_dst", "evidence_arp"])
    L += ["", f"## MACs with more than one IP ({c['mac_multi_ipv4_count']} flagged with >1 IPv4)", ""]
    if not c["mac_multi_ip"]:
        L += ["_none_"]
    for x in c["mac_multi_ip"]:
        flag = " **FLAG: multiple IPv4**" if x["flag_multiple_ipv4"] else ""
        L += ["", f"### {x['mac']} ({x['device_name']}, {x['role']}) -- "
              f"{x['n_ipv4']} IPv4 / {x['n_ipv6']} IPv6{flag}", ""]
        L += md_table(x["ips"], ["ip", "ip_version", "first_seen_utc", "last_seen_utc", "packets"])
    L += ["", f"## Device-table entries with NO LAN IP ({len(c['devices_without_lan_ip'])})", ""]
    L += md_table(c["devices_without_lan_ip"], ["mac", "device_name", "category", "role"])
    L += ["", f"## LAN IPs whose MAC is not in the device table ({len(c['lan_ips_with_unlisted_mac'])})", ""]
    L += md_table(c["lan_ips_with_unlisted_mac"], ["ip", "mac", "packets", "first_seen_utc",
                                                   "last_seen_utc", "evidence_src", "evidence_dst",
                                                   "evidence_arp"])
    cov = rep["coverage"]
    L += ["", "## Flow coverage preview (IP-only lookup, no time window)", "",
          "An IP with several MACs is resolved to its highest-packet MAC for this preview; "
          f"{cov['flows_touching_multi_mac_ip']:,} flows touch such an IP.", ""]
    L += [f"- **{k}**: {v:,}" if isinstance(v, int) else f"- **{k}**: {v}"
          for k, v in cov["smart_home"].items()]
    L += ["", "### By role (unmapped = IP not in the map, e.g. internet hosts)", ""]
    L += md_table([{"role": k, **v} for k, v in cov["by_role"].items()],
                  ["role", "src", "src_pct", "dst", "dst_pct", "either", "either_pct"])
    L += ["", f"### Top 10 LAN-scope flow IPs NOT in the map "
          f"({cov['lan_scope_unmapped_distinct_ips']} distinct)", ""]
    L += md_table(cov["top10_lan_scope_unmapped"], ["ip", "flows"])
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- main

def main() -> None:
    t_start = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pcap", type=Path, default=ROOT / "data/raw/ciciot2023/benign/BenignTraffic.pcap")
    ap.add_argument("--devices", type=Path, default=ROOT / "config/device_table.csv")
    ap.add_argument("--flows", type=Path,
                    default=ROOT / "data/interim/flows/benign/BenignTraffic.pcap_Flow__singlepkt.csv")
    ap.add_argument("--out-map", type=Path, default=ROOT / "config/ip_mac_map.csv")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "results/step5")
    ap.add_argument("--cache-dir", type=Path, default=Path("~/lgids_cache"))
    ap.add_argument("--rehash-source", action="store_true",
                    help="re-hash the original pcap even if the cache sidecar matches")
    args = ap.parse_args()
    args.cache_dir = args.cache_dir.expanduser()

    for p in (args.pcap, args.devices, args.flows):
        if not p.exists():
            fatal(f"input not found: {p}")
    if shutil.which("tshark") is None:
        fatal("tshark not found on PATH")
    tshark_ver = subprocess.run(["tshark", "--version"], capture_output=True,
                                text=True).stdout.splitlines()[0]

    dev, dev_cols = load_devices(args.devices)
    log(f"Device table: {len(dev)} MACs; columns matched: {dev_cols}")
    n_smart = int((dev["role"] == "iot").sum())

    # Step 0 + 1
    cached, cache_info = ensure_cached(args.pcap, args.cache_dir, args.rehash_source)
    agg, pstats = extract(cached)

    subnets, bcast = infer_subnets(agg)
    kept, rejected = filter_pairs(agg, bcast)
    log(f"Kept {len(kept):,} LAN (mac, ip) pairs; dropped {sum(rejected['pairs'].values()):,}")

    # Step 2: build map + join device table
    rows = []
    for (mac, ip), (first, last, ns, nd, na) in kept.items():
        a = ipa.ip_address(ip)
        rows.append({"ip": ip, "ip_version": a.version, "mac": mac,
                     "first_seen_epoch": first, "last_seen_epoch": last,
                     "first_seen_utc": utc(first), "last_seen_utc": utc(last),
                     "packets": ns + nd + na, "evidence_src": ns, "evidence_dst": nd,
                     "evidence_arp": na, "_sort": (a.version, int(a), first)})
    m = pd.DataFrame(rows).sort_values("_sort").drop(columns="_sort").reset_index(drop=True)
    m = m.merge(dev[["mac", "device_name", "category", "role"]], on="mac", how="left")
    m["role"] = m["role"].fillna("unlisted")
    m[["device_name", "category"]] = m[["device_name", "category"]].fillna("")
    m["_idx"] = m.index

    # Step 3
    checks = time_checks(m, dev)
    flags = checks.pop("flags")
    m["conflict_flag"] = m["_idx"].map(lambda i: ";".join(sorted(flags.get(i, ()))))
    out_cols = ["ip", "ip_version", "mac", "device_name", "category", "role",
                "first_seen_epoch", "last_seen_epoch", "first_seen_utc", "last_seen_utc",
                "packets", "evidence_src", "evidence_dst", "evidence_arp", "conflict_flag"]
    args.out_map.parent.mkdir(parents=True, exist_ok=True)
    m[out_cols].to_csv(args.out_map, index=False, float_format="%.6f", quoting=csv.QUOTE_MINIMAL)

    # Step 4
    log("Computing flow coverage preview ...")
    cov = coverage(args.flows, m, bcast)

    smart_mapped = sorted(set(m.loc[m["role"] == "iot", "mac"]))
    gw_v4 = [g["ip"] for g in checks["gateway_ips"] if g["ip_version"] == 4]
    runtime = round(time.monotonic() - t_start, 1)
    summary = {
        "map_rows": len(m), "map_rows_ipv4": int((m["ip_version"] == 4).sum()),
        "map_rows_ipv6": int((m["ip_version"] == 6).sum()),
        "distinct_ips": int(m["ip"].nunique()), "distinct_macs": int(m["mac"].nunique()),
        "smart_home_devices_mapped": f"{len(smart_mapped)}/{n_smart}",
        "listed_devices_mapped": f"{int(dev['mac'].isin(m['mac']).sum())}/{len(dev)}",
        "ip_conflicts_sequential": checks["ip_multi_mac_sequential"],
        "ip_conflicts_overlapping": checks["ip_multi_mac_overlapping"],
        "macs_with_multiple_ipv4": checks["mac_multi_ipv4_count"],
        "gateway_ipv4": ", ".join(gw_v4) or "NOT FOUND",
        "unmapped_listed_devices": len(checks["devices_without_lan_ip"]),
        "lan_ips_with_unlisted_mac": len(checks["lan_ips_with_unlisted_mac"]),
        "flows_either_end_smart_home_pct": cov["smart_home"]["either_smart_home_pct"],
        "runtime_s": runtime,
    }
    meta = {
        "run_timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "pcap": str(args.pcap), "pcap_sha256": cache_info["sha256"], "pcap_cache": cache_info,
        "devices": str(args.devices), "devices_sha256": sha256(args.devices),
        "flows": str(args.flows), "flows_sha256": sha256(args.flows),
        "out_map": str(args.out_map), "tshark_version": tshark_ver,
        "packets_processed": pstats["packets"], "packets_expected": EXPECTED_PACKETS,
        "runtime_s": runtime, "python": platform.python_version(), "pandas": pd.__version__,
    }
    rep = {"meta": meta, "summary": summary, "packet_stats": pstats,
           "subnet_assumption": ("Subnets inferred as the /24 networks containing private IPv4 "
                                 "addresses seen as a SOURCE (eth.src/ip.src or ARP sender) with "
                                 "a unicast MAC; the /24's .255 (plus 169.254.255.255) is "
                                 "treated as subnet broadcast and excluded."),
           "subnets": subnets, "filtering": rejected, "device_columns": dev_cols,
           "checks": checks, "coverage": cov}

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "ip_mac_map_report.json").write_text(
        json.dumps(rep, indent=2, default=str), encoding="utf-8")
    write_md(args.out_dir / "ip_mac_map_report.md", rep)

    # Terminal summary
    no_ip = checks["devices_without_lan_ip"]
    sh = cov["smart_home"]
    log("\n================ SUMMARY ================")
    log(f"packets processed      : {pstats['packets']:,} (expected {EXPECTED_PACKETS:,})")
    log(f"subnet(s) inferred     : {', '.join(s['subnet'] for s in subnets) or 'none'}")
    log(f"map rows               : {summary['map_rows']} "
        f"(IPv4 {summary['map_rows_ipv4']} / IPv6 {summary['map_rows_ipv6']})")
    log(f"smart-home mapped      : {summary['smart_home_devices_mapped']}  "
        f"(all listed: {summary['listed_devices_mapped']})")
    log(f"IP conflicts           : {summary['ip_conflicts_sequential']} sequential / "
        f"{summary['ip_conflicts_overlapping']} overlapping")
    log(f"MACs with >1 IPv4      : {summary['macs_with_multiple_ipv4']}")
    log(f"gateway LAN IP(s)      : {', '.join(g['ip'] for g in checks['gateway_ips']) or 'NOT FOUND'}")
    log(f"unmapped listed devices: {len(no_ip)}")
    for d in no_ip:
        log(f"    {d['mac']}  {d['device_name']}  [{d['role']}]")
    log(f"unlisted-MAC LAN IPs   : {summary['lan_ips_with_unlisted_mac']}")
    log(f"flow coverage          : src smart-home {sh['src_smart_home_pct']}% | "
        f"dst {sh['dst_smart_home_pct']}% | either {sh['either_smart_home_pct']}% | "
        f"neither {sh['neither_smart_home_pct']}%")
    log("  by role (either end) : " + ", ".join(
        f"{k} {v['either_pct']}%" for k, v in cov["by_role"].items()))
    log(f"runtime                : {runtime} s (tshark {pstats['tshark_seconds']} s)")
    log(f"\nwrote {args.out_map}\n      {args.out_dir / 'ip_mac_map_report.md'}\n"
        f"      {args.out_dir / 'ip_mac_map_report.json'}")


if __name__ == "__main__":
    main()
