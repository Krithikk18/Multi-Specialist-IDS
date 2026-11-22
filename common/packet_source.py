"""common/packet_source.py -- split-confined packet reader (Phase 3 rate guard and pcap flow path). TRAIN / VAL only.

    for ts, src_ip, dst_ip, proto, src_mac, dst_mac in session_packets(cfg, "Recon-PortScan", "val"): ...
    src = PacketSource(cfg, "val")                    # every session's val packets, merged on the event clock
    write_slice(cfg, "Recon-PortScan", "val", out_pcap)   # a val-window pcap + <out>.slice.json manifest

Reader: classic pcap (any byte order, us / ns timestamps); Ethernet II, 802.1Q / 802.1ad tags skipped; IPv4 outer
header only (like V1's tshark reader 13_rate_guard_calibrate.tshark_ipv4_packets: same tuple, same order; non-IPv4
frames counted and skipped; MACs lower-case "aa:bb:..", IPs dotted). Standard library only.

Split confinement (docs/V2_PREREG_PHASE3.md, results/phase3/discovery.md): the dataset's split definition (sha256
checked) gives per session the cut labels and boundaries; a packet's split = labels[bisect_right(boundaries, ts)]
(08's rule on packet time). Sessions whose mode is test / test_only are refused, split "test" is refused, and reading
STOPS at the first packet at or after the first boundary that leads into a label that is neither the wanted split
nor an earlier one (for a time_split capture: the start of gap@val|test), so no test-window packet is ever read.
Every capture's sha256 is checked against its record (config/config.py DATASET / config/attack_set.json).
"""

from __future__ import annotations

import bisect
import hashlib
import heapq
import json
import mmap
import socket
import struct
from collections import Counter
from pathlib import Path

from common import phase3_config as C

MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
         b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
VLAN = (0x8100, 0x88A8)
IPV4 = 0x0800
SPLIT_ORDER = ("train", "gap@train|val", "val", "gap@val|test", "test")
_SHA_DONE: dict = {}


class PacketSourceError(RuntimeError):
    pass


def _mac(b: bytes, cache: dict) -> str:
    s = cache.get(b)
    if s is None:
        s = cache[b] = b.hex(":")
    return s


def _ip(b: bytes, cache: dict) -> str:
    s = cache.get(b)
    if s is None:
        s = cache[b] = socket.inet_ntoa(b)
    return s


def iter_pcap(path: Path, counts: Counter | None = None, stop_at: float | None = None, raw: bool = False,
              start_at: float | None = None):
    """Yield (ts, src_ip, dst_ip, proto, src_mac, dst_mac) per IPv4 packet in file order; raw=True yields
    (ts, record_header_bytes, frame_bytes) for every frame instead. Stops BEFORE the first frame with ts >= stop_at;
    frames with ts < start_at are skipped on their record header alone (never parsed; counted)."""
    c = counts if counts is not None else Counter()
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if len(mm) < 24 or mm[:4] not in MAGIC:
            raise PacketSourceError(f"{path}: not a classic pcap file")
        bo, unit = MAGIC[mm[:4]]
        linktype = struct.unpack_from(bo + "I", mm, 20)[0]
        if linktype != 1:
            raise PacketSourceError(f"{path}: link type {linktype}, only Ethernet (1) is supported")
        rec = struct.Struct(bo + "IIII")
        off, n = 24, len(mm)
        macs, ips = {}, {}
        while off + 16 <= n:
            s, frac, incl, _orig = rec.unpack_from(mm, off)
            ts = s + frac * unit
            if stop_at is not None and ts >= stop_at:
                c["stopped_at_cut"] = 1
                break
            start, off = off + 16, off + 16 + incl
            if off > n:
                c["truncated_tail"] += 1
                break
            c["frames"] += 1
            if start_at is not None and ts < start_at:
                c["skipped_before_start"] += 1
                continue
            if raw:
                yield ts, mm[start - 16:start], mm[start:off]
                continue
            if incl < 14:
                c["short_frames"] += 1
                continue
            et = (mm[start + 12] << 8) | mm[start + 13]
            l3 = start + 14
            while et in VLAN and l3 + 4 <= off:
                et = (mm[l3 + 2] << 8) | mm[l3 + 3]
                l3 += 4
            if et != IPV4 or l3 + 20 > off:
                c["non_ipv4"] += 1
                continue
            yield (ts, _ip(mm[l3 + 12:l3 + 16], ips), _ip(mm[l3 + 16:l3 + 20], ips), mm[l3 + 9],
                   _mac(mm[start + 6:start + 12], macs), _mac(mm[start:start + 6], macs))


# --------------------------------------------------------------------------- sessions and cuts
def split_definition(cfg: dict) -> dict:
    p = C.expand(cfg["packets"]["split_definition"])
    D = json.loads(p.read_text(encoding="utf-8"))
    body = {k: v for k, v in D.items() if k not in ("sha256", "sha256_of")}
    got = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if got != D.get("sha256"):
        raise PacketSourceError(f"{p}: canonical sha256 {got} != its sha256 field {D.get('sha256')}")
    return D


def sha256_file(p: Path) -> str:
    key = (str(p), Path(p).stat().st_size, Path(p).stat().st_mtime_ns)
    if key not in _SHA_DONE:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for b in iter(lambda: fh.read(1 << 22), b""):
                h.update(b)
        _SHA_DONE[key] = h.hexdigest()
    return _SHA_DONE[key]


def capture_of(cfg: dict, session: str) -> tuple[Path, str]:
    """(pcap path, expected sha256) of a session, from config/config.py DATASET (benign) or the attack set."""
    from config.config import DATASET, REPO_ROOT
    pk = cfg["packets"]
    if session == pk["benign_session"]:
        return C.expand(pk["benign_pcap"]), DATASET.benign_pcap_sha256
    aset = json.loads((REPO_ROOT / pk["attack_set"]).read_text(encoding="utf-8"))
    hits = [e for e in aset["pcaps"] if Path(e["path"]).stem == session]
    if len(hits) != 1:
        raise PacketSourceError(f"session {session!r}: {len(hits)} attack-set entries")
    return C.expand(pk["attack_pcap_root"]) / hits[0]["path"], hits[0]["sha256"]


def session_plan(cfg: dict, session: str, split: str) -> dict:
    """Cut labels / boundaries of a session, the stop time (first boundary into a later split) and the pcap."""
    C.refuse_test(split, f"(packets of {session})")
    D = split_definition(cfg)
    S_ = D["sessions"].get(session)
    if S_ is None:
        raise PacketSourceError(f"session {session!r} not in the split definition")
    if S_["mode"] in ("test", "test_only"):
        raise C.TestSplitRefused(f"session {session!r} is a {S_['mode']} session")
    labels, bounds = S_["labels"], [float(b) for b in S_["boundaries_epoch"]]
    if split not in labels:
        raise PacketSourceError(f"session {session!r} has no {split} part ({labels})")
    allowed = set(SPLIT_ORDER[:SPLIT_ORDER.index(split) + 1])
    stop = None
    for i, lab in enumerate(labels):
        if lab not in allowed:
            stop = bounds[i - 1]
            break
    pcap, sha = capture_of(cfg, session)
    if "test" in pcap.name.lower():
        raise C.TestSplitRefused(f"refused capture {pcap}")
    i = labels.index(split)
    start = bounds[i - 1] if i > 0 else None                          # first instant of the wanted split
    return {"session": session, "split": split, "mode": S_["mode"], "labels": labels, "bounds": bounds, "stop": stop,
            "start": start, "pcap": pcap, "sha256": sha}


def session_packets(cfg: dict, session: str, split: str, counts: Counter | None = None, verify_sha: bool = True):
    """The `split` packets of one session, in file order (packets of other splits are counted and skipped)."""
    P = session_plan(cfg, session, split)
    c = counts if counts is not None else Counter()
    if verify_sha:
        got = sha256_file(P["pcap"])
        if got != P["sha256"]:
            raise PacketSourceError(f"{P['pcap']}: sha256 {got} != record {P['sha256']}")
    labels, bounds = P["labels"], P["bounds"]
    for pkt in iter_pcap(P["pcap"], c, stop_at=P["stop"], start_at=P["start"]):
        lab = labels[bisect.bisect_right(bounds, pkt[0])]
        if lab == split:
            c["kept"] += 1
            yield pkt
        else:
            c[f"skipped_{lab}"] += 1


def sessions_with(cfg: dict, split: str) -> list[str]:
    D = split_definition(cfg)
    return [s for s, v in D["sessions"].items() if v["mode"] not in ("test", "test_only") and split in v["labels"]]


class PacketSource:
    """Every session's `split` packets merged in time order (heap merge; sessions are separate captures)."""

    def __init__(self, cfg: dict, split: str, sessions: list[str] | None = None, verify_sha: bool = True):
        C.refuse_test(split, "(PacketSource)")
        self.cfg, self.split, self.verify = cfg, split, verify_sha
        self.sessions = sessions if sessions is not None else sessions_with(cfg, split)
        self.counts = {s: Counter() for s in self.sessions}
        self.plans = {s: session_plan(cfg, s, split) for s in self.sessions}

    def __iter__(self):
        gens = [session_packets(self.cfg, s, self.split, self.counts[s], self.verify) for s in self.sessions]
        return heapq.merge(*gens, key=lambda p: p[0])

    def describe(self) -> dict:
        return {"split": self.split, "sessions": {s: {"pcap": str(p["pcap"]), "sha256": p["sha256"], "stop": p["stop"],
                                                      "counts": dict(self.counts[s])} for s, p in self.plans.items()}}


def write_slice(cfg: dict, session: str, split: str, out: Path, t0: float | None = None, t1: float | None = None,
                max_packets: int | None = None) -> dict:
    """Every frame of the session's `split` window (optionally [t0, t1), first max_packets) -> a new pcap, plus
    <out>.slice.json (split, session, source sha256, window, counts). Refuses an existing target."""
    out = Path(out)
    man_p = out.with_suffix(out.suffix + ".slice.json")
    if out.exists() or man_p.exists():
        raise PacketSourceError(f"{out} or its manifest exists (never overwritten)")
    P = session_plan(cfg, session, split)
    got = sha256_file(P["pcap"])
    if got != P["sha256"]:
        raise PacketSourceError(f"{P['pcap']}: sha256 {got} != record {P['sha256']}")
    c = Counter()
    labels, bounds = P["labels"], P["bounds"]
    n, first, last = 0, None, None
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(P["pcap"], "rb") as fh:
        gh = fh.read(24)
    with open(out, "xb") as o:
        o.write(gh)
        for ts, rh, fr in iter_pcap(P["pcap"], c, stop_at=P["stop"], raw=True):
            if labels[bisect.bisect_right(bounds, ts)] != split or (t0 is not None and ts < t0):
                continue
            if t1 is not None and ts >= t1:
                break
            o.write(rh)
            o.write(fr)
            n += 1
            first = ts if first is None else first
            last = ts
            if max_packets is not None and n >= max_packets:
                break
    man = {"split": split, "session": session, "source_pcap": str(P["pcap"]), "source_sha256": got, "labels": labels,
           "boundaries_epoch": bounds, "stop": P["stop"], "window": [t0, t1], "max_packets": max_packets,
           "frames_written": n, "first_ts": first, "last_ts": last, "reader_counts": dict(c),
           "pcap_sha256": sha256_file(out)}
    man_p.write_text(json.dumps(man, indent=1) + "\n", encoding="utf-8")
    return man
