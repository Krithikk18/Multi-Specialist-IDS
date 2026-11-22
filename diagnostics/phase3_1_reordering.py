#!/usr/bin/env python
"""diagnostics/phase3_1_reordering.py -- Phase 3.1 PART E (READ-ONLY): packet reordering in the captures.

For every train / val capture (common/packet_source.session_plan: test sessions refused, reading stops at the first
frame of a later split, capture sha256 checked), in file order:
  inversions   a frame whose timestamp is earlier than the previous frame's (magnitude = previous - this; also the
               distance below the running maximum), broken down by capture, protocol, TCP flags of the inverted frame,
               source / destination host (inventory device, attack source, other); frames of the train and val
               windows are counted (gap frames keep the file-order chain but are not counted)
  handshakes   a SYN (SYN set, ACK clear) A -> B paired with B's first SYN/ACK or RST(/ACK) back on the same 4-tuple
               (pending tables pruned after 10 s of capture time); share where the responder's frame is timestamped
               BEFORE the SYN, per responder device and class (class = the capture's attack class when the client is an
               attack source, else benign); mapped onto the dataset's R3 flips and the diag_03 H1 shape per capture x
               device
  capture      file format (pcapng interface ids if any), timestamp resolution (header magic; share of timestamps on a
               whole millisecond), duplicate frames (identical bytes within 1 ms)
Attack-source identity = V1 step 13 / D74 (evaluation-only); inventory = device_table owner-role MACs.
Outputs: results/phase3_1/reordering/ (summary.md for a networking reader, reordering.json, run_manifest.json,
run_meta.json, run.log, figures/).
"""

from __future__ import annotations

import argparse
import bisect
import socket
import struct
import sys
import traceback
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import packet_source as PK  # noqa: E402
from common import phase2_data as D  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import phase3_config as C3  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402
from diagnostics import orient_r4_common as Q  # noqa: E402

SCRIPT = "diagnostics/phase3_1_reordering.py"
PENDING_S, DUP_S, PRUNE_EVERY = 10.0, 0.001, 200_000
COUNTED = ("train", "val")
PROTO = {6: "TCP", 17: "UDP", 1: "ICMP"}


def pins() -> dict:
    return {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH), ("config/class_map.json", S.CLASS_MAP_PATH))}


def flags_str(f: int) -> str:
    s = "".join(ch for bit, ch in ((0x02, "S"), (0x10, "A"), (0x04, "R"), (0x01, "F"), (0x08, "P"), (0x20, "U")) if f & bit)
    return s or "none"


class Hosts:
    def __init__(self, truth: Q.Truth):
        self.t = truth
        self._c: dict = {}

    def kind(self, mac: str) -> str:
        k = self._c.get(mac)
        if k is None:
            if self.t.hosts.is_attacker(mac):
                k = "attack source"
            elif mac in self.t.inventory:
                k = "inventory device"
            elif mac == "ff:ff:ff:ff:ff:ff" or (len(mac) == 17 and int(mac[:2], 16) & 1):
                k = "broadcast / multicast"
            elif mac in self.t.hosts.book.dev.name:
                k = "other listed host"
            else:
                k = "unlisted host"
            self._c[mac] = k
        return k

    def name(self, mac: str) -> str:
        return self.t.hosts.book.dev.name.get(mac, mac)


def frames(plan: dict, counts: Counter):
    """(label, ts, frame bytes) of every frame from the capture start up to the plan's stop (raw reader)."""
    labels, bounds = plan["labels"], plan["bounds"]
    for ts, _rh, fr in PK.iter_pcap(plan["pcap"], counts, stop_at=plan["stop"], raw=True):
        yield labels[bisect.bisect_right(bounds, ts)], ts, fr


def parse(fr: bytes):
    """(src_mac, dst_mac, proto, sip, dip, sport, dport, tcp_flags) or None for non-IPv4."""
    if len(fr) < 14:
        return None
    et = (fr[12] << 8) | fr[13]
    l3 = 14
    while et in (0x8100, 0x88A8) and l3 + 4 <= len(fr):
        et = (fr[l3 + 2] << 8) | fr[l3 + 3]
        l3 += 4
    if et != 0x0800 or l3 + 20 > len(fr):
        return None
    ihl = (fr[l3] & 0x0F) * 4
    proto = fr[l3 + 9]
    sip, dip = fr[l3 + 12:l3 + 16], fr[l3 + 16:l3 + 20]
    l4 = l3 + ihl
    sp = dp = -1
    fl = -1
    if proto in (6, 17) and l4 + 4 <= len(fr):
        sp, dp = struct.unpack_from("!HH", fr, l4)
        if proto == 6 and l4 + 14 <= len(fr):
            fl = fr[l4 + 13]
    return fr[6:12], fr[0:6], proto, sip, dip, sp, dp, fl


def scan_capture(cfg3: dict, sess: str, hosts: Hosts, att_class: str, log) -> dict:
    labs = PK.split_definition(cfg3)["sessions"][sess]["labels"]
    plan = PK.session_plan(cfg3, sess, "val" if "val" in labs else "train")
    got = PK.sha256_file(plan["pcap"])
    if got != plan["sha256"]:
        raise RuntimeError(f"{plan['pcap']}: sha256 {got} != record")
    with open(plan["pcap"], "rb") as fh:
        head = fh.read(24)
    fmt = "pcapng" if head[:4] == b"\x0a\x0d\x0d\x0a" else "pcap"
    res = "ns" if head[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else "us"
    cnt = Counter()
    st = {"frames": Counter(), "inv": Counter(), "inv_by_proto": Counter(), "all_by_proto": Counter(),
          "inv_by_flags": Counter(), "all_by_flags": Counter(), "inv_by_src": Counter(), "all_by_src": Counter(),
          "inv_by_dst": Counter(), "all_by_dst": Counter(), "dup": 0, "ms_whole": 0, "non_ipv4": 0}
    mag, below = [], []
    syn_p, rsp_p = {}, {}
    hs = Counter()                                           # (responder device, class, type, responder_first) -> n
    hs_cell = Counter()                                      # (responder mac, type, responder_first) -> n (attack-source clients)
    unpaired = Counter()
    dups: dict = {}
    prev = None
    runmax = -np.inf
    mac_cache: dict = {}

    def m(b):
        s = mac_cache.get(b)
        if s is None:
            s = mac_cache[b] = b.hex(":")
        return s

    n = 0
    for lab, ts, fr in frames(plan, cnt):
        n += 1
        if prev is not None and lab in COUNTED:
            p = parse(fr)
            proto = "non-IPv4" if p is None else PROTO.get(p[2], "other IP")
            fls = flags_str(p[7]) if (p is not None and p[7] >= 0) else "-"
            sk = hosts.kind(m(p[0])) if p is not None else "-"
            dk = hosts.kind(m(p[1])) if p is not None else "-"
            st["frames"][lab] += 1
            st["all_by_proto"][proto] += 1
            st["all_by_src"][sk] += 1
            st["all_by_dst"][dk] += 1
            if p is not None and p[2] == 6:
                st["all_by_flags"][fls] += 1
            if ts < prev:
                st["inv"][lab] += 1
                mag.append(prev - ts)
                below.append(runmax - ts)
                st["inv_by_proto"][proto] += 1
                st["inv_by_src"][sk] += 1
                st["inv_by_dst"][dk] += 1
                if p is not None and p[2] == 6:
                    st["inv_by_flags"][fls] += 1
            if round(ts * 1e6) % 1000 == 0:
                st["ms_whole"] += 1
            h = hash(fr)
            t0 = dups.get(h)
            if t0 is not None and abs(ts - t0) <= DUP_S:
                st["dup"] += 1
            dups[h] = ts
            if p is None:
                st["non_ipv4"] += 1
            elif p[2] == 6 and p[7] >= 0:
                f = p[7]
                src_mac, dst_mac = m(p[0]), m(p[1])
                if f & 0x02 and not f & 0x10:                                  # SYN
                    k = (p[3], p[5], p[4], p[6])
                    r = rsp_p.pop(k, None)
                    if r is not None:
                        _pair(hs, hs_cell, hosts, att_class, src_mac, r[1], r[2], r[0] < ts)
                    elif k not in syn_p:
                        syn_p[k] = (ts, src_mac)
                elif (f & 0x02 and f & 0x10) or f & 0x04:                      # SYN/ACK or RST(/ACK)
                    typ = "SYN/ACK" if f & 0x02 else ("RST/ACK" if f & 0x10 else "RST")
                    k = (p[4], p[6], p[3], p[5])
                    s_ = syn_p.pop(k, None)
                    if s_ is not None:
                        _pair(hs, hs_cell, hosts, att_class, s_[1], src_mac, typ, ts < s_[0])
                    elif k not in rsp_p:
                        rsp_p[k] = (ts, src_mac, typ)
        prev = ts
        runmax = max(runmax, ts)
        if n % PRUNE_EVERY == 0:
            lim = ts - PENDING_S
            for d_, slot in ((syn_p, "syn_unanswered"), (rsp_p, "responder_unmatched")):
                old = [k for k, v in d_.items() if v[0] < lim]
                unpaired[slot] += len(old)
                for k in old:
                    del d_[k]
            dups = {k: v for k, v in dups.items() if v >= ts - 1.0}
    unpaired["syn_unanswered"] += len(syn_p)
    unpaired["responder_unmatched"] += len(rsp_p)
    mag = np.asarray(mag, float)
    below = np.asarray(below, float)
    q = lambda a: ({k: float(np.quantile(a, x)) for k, x in (("p50", .5), ("p90", .9), ("p99", .99), ("max", 1.0))}  # noqa: E731
                   if len(a) else {})
    nfr = sum(st["frames"].values())
    ninv = sum(st["inv"].values())
    log(f"  {sess}: {nfr:,} frames counted, {ninv:,} inversions ({100 * ninv / max(nfr, 1):.3f} %), "
        f"{sum(hs.values()):,} handshakes, duplicates {st['dup']:,}")
    hist = np.histogram(np.log10(np.maximum(mag, 1e-7)), bins=np.arange(-7, 2.01, 0.25))[0].tolist() if len(mag) else []
    return {"session": sess, "pcap": str(plan["pcap"]), "format": fmt, "timestamp_resolution": res,
            "mode": plan["mode"], "labels": plan["labels"], "reader": dict(cnt),
            "frames": dict(st["frames"]), "inversions": dict(st["inv"]), "inversion_rate": ninv / max(nfr, 1),
            "magnitude_s": q(mag), "below_running_max_s": q(below), "magnitude_log10_hist": hist,
            "inv_by_proto": dict(st["inv_by_proto"]), "all_by_proto": dict(st["all_by_proto"]),
            "inv_by_flags": dict(st["inv_by_flags"]), "all_by_flags": dict(st["all_by_flags"]),
            "inv_by_src": dict(st["inv_by_src"]), "all_by_src": dict(st["all_by_src"]),
            "inv_by_dst": dict(st["inv_by_dst"]), "all_by_dst": dict(st["all_by_dst"]),
            "duplicates_within_1ms": st["dup"], "share_ts_on_whole_ms": st["ms_whole"] / max(nfr, 1),
            "non_ipv4": st["non_ipv4"], "handshakes": [{"device": k[0], "class": k[1], "type": k[2], "responder_first": k[3],
                                                        "n": v} for k, v in hs.items()],
            "handshake_cells": [{"mac": k[0], "type": k[1], "responder_first": k[2], "n": v} for k, v in hs_cell.items()],
            "unpaired": dict(unpaired), "attack_class": att_class}


def _pair(hs, hs_cell, hosts, att_class, client_mac, resp_mac, typ, responder_first) -> None:
    cls = att_class if hosts.kind(client_mac) == "attack source" else "benign"
    dev = hosts.name(resp_mac) if hosts.kind(resp_mac) == "inventory device" else hosts.kind(resp_mac)
    hs[(dev, cls, typ, bool(responder_first))] += 1
    if cls != "benign":
        hs_cell[(resp_mac, typ, bool(responder_first))] += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="the smallest capture only")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()
    cfg = load_phase2_config(REPO_ROOT / "config" / "v2_phase2_v2_1.json")
    cfg["_results_root"] = str(RESULTS_DIR / "phase3_1")
    cfg3 = C3.load_phase3_config()
    S.verify_v2_lock(strict=True)
    p0 = pins()
    names = list(S.load_class_map().names)
    ctx = R.start_run("reordering", "diag", SCRIPT, cfg, args.dry_run, args.run_id)
    ctx.log(f"  [start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    M = R.base_manifest(ctx, SCRIPT, ["common/packet_source.py", "diagnostics/orient_r4_common.py", "config/v2_phase3.json"])
    M.update({"pins_before": p0, "read_only": True})
    ok, out = False, {}
    try:
        truth = Q.Truth()
        hosts = Hosts(truth)
        sessions = sorted(set(PK.sessions_with(cfg3, "train")) | set(PK.sessions_with(cfg3, "val")))
        # the capture's attack class and the dataset side (R3 flips, H1 shape) per session x device, from v2_1 flows
        cols = Q.RULE_COLUMNS + ["session", "label_id", "device_mac", "src_mac", "dst_mac", "orientation_flipped", "group"]
        fl = pd.concat([D.load_split(cfg, s, cols) for s in ("train", "val")], ignore_index=True)
        M["inputs"] = {s: D.verify_split_file(cfg, s) for s in ("train", "val")} | {"test_read": False}
        att_class = {}
        for s, g in fl.groupby("session"):
            a = g.loc[g["label_id"] != 0, "label_id"]
            att_class[s] = names[int(a.mode().iloc[0])] if len(a) else names[0]
        y = fl["label_id"].to_numpy()
        T = truth.labels(fl["src_mac"].astype(str).to_numpy(), fl["dst_mac"].astype(str).to_numpy(),
                         pd.to_numeric(fl[Q.PROTO]).to_numpy(), y)
        flipped = fl["orientation_flipped"].to_numpy(bool)
        h1 = T["REV"] & ~flipped & (pd.to_numeric(fl[Q.BIW]).to_numpy() == 0)
        tcp_att = (pd.to_numeric(fl[Q.PROTO]).to_numpy() == Q.TCP) & (y != 0)
        ds = pd.DataFrame({"session": fl["session"], "mac": fl["device_mac"].astype(str), "tcp_attack": tcp_att,
                           "r3_flip": flipped & tcp_att, "h1_shape": h1}).groupby(["session", "mac"]).sum()
        del fl
        if args.dry_run:
            sessions = [min(sessions, key=lambda s: PK.session_plan(cfg3, s, "val" if "val" in PK.split_definition(cfg3)
                                                                     ["sessions"][s]["labels"] else "train")["pcap"].stat().st_size)]
        caps = []
        for s in sessions:
            caps.append(scan_capture(cfg3, s, hosts, att_class.get(s, names[0]), ctx.log))
        out["captures"] = caps
        # mapping onto R3 / H1 per capture x device (attack-source handshakes only)
        rows = []
        for c in caps:
            cell = defaultdict(Counter)
            for h in c["handshake_cells"]:
                cell[h["mac"]][(h["type"], h["responder_first"])] += h["n"]
            for mac, cc in cell.items():
                n_ra = sum(v for (t, _), v in cc.items() if t != "SYN/ACK")
                n_sa = sum(v for (t, _), v in cc.items() if t == "SYN/ACK")
                key = (c["session"], mac)
                dsr = ds.loc[key] if key in ds.index else None
                rows.append({"session": c["session"], "device": hosts.name(mac), "mac": mac,
                             "rst_handshakes": n_ra, "rst_responder_first": sum(v for (t, f), v in cc.items() if t != "SYN/ACK" and f),
                             "synack_handshakes": n_sa, "synack_responder_first": cc[("SYN/ACK", True)],
                             "dataset_tcp_attack_flows": int(dsr["tcp_attack"]) if dsr is not None else 0,
                             "dataset_r3_flips": int(dsr["r3_flip"]) if dsr is not None else 0,
                             "dataset_h1_shape": int(dsr["h1_shape"]) if dsr is not None else 0})
        out["map_r3_h1"] = rows
        from scipy.stats import spearmanr
        Mx = pd.DataFrame(rows)
        if len(Mx) > 2:
            Mx = Mx[Mx["dataset_tcp_attack_flows"] > 0]
            with np.errstate(invalid="ignore", divide="ignore"):
                a1 = Mx["rst_responder_first"] / Mx["rst_handshakes"].replace(0, np.nan)
                b1 = Mx["dataset_r3_flips"] / Mx["dataset_tcp_attack_flows"]
                a2 = Mx["synack_responder_first"] / Mx["synack_handshakes"].replace(0, np.nan)
                b2 = Mx["dataset_h1_shape"] / Mx["dataset_tcp_attack_flows"]
            k1, k2 = a1.notna(), a2.notna()
            out["map_spearman"] = {"rst_first_vs_r3_flip_share": float(spearmanr(a1[k1], b1[k1]).statistic) if k1.sum() > 2 else None,
                                   "synack_first_vs_h1_share": float(spearmanr(a2[k2], b2[k2]).statistic) if k2.sum() > 2 else None,
                                   "cells": int(len(Mx))}
        R.write_json(ctx.partial / "reordering.json", out)
        R.write_json(ctx.res / "reordering.json", out)
        figs = [fig_rates(ctx.fig / "inversion_rate_per_capture.png", caps),
                fig_mag(ctx.fig / "inversion_magnitude.png", caps),
                fig_hs(ctx.fig / "responder_before_syn.png", caps)]
        M["figures"] = [str(Path(f).relative_to(ctx.res)) for f in figs]
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = pins()
    R.add_check(ctx, M, "config.py / class_map.json unchanged", M["pins_after"] == p0, str(M["pins_after"]))
    ctx.log(f"  [end] config.py {M['pins_after']['config/config.py']}; class_map.json {M['pins_after']['config/class_map.json']}")
    ok = ok and M["pins_after"] == p0
    write_summary(ctx.res / "summary.md", M, out, ok)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def _pct(a, b):
    return f"{100 * a / b:.3f} %" if b else "-"


def write_summary(path, M, out, ok) -> None:
    L = [f"# Packet reordering in the training / validation captures -- {'PASS' if ok else 'FAIL'}"
         + (" (DRY RUN)" if M["dry_run"] else ""), "",
         "Written for network engineers. Read-only measurement of the capture files the IDS was trained and validated on "
         "(train and validation time windows only; the held-out test window is never read). \"File order\" = the order "
         "frames are stored in the .pcap; \"inversion\" = a frame whose timestamp is EARLIER than the frame stored just "
         "before it. Host roles: \"inventory device\" = a smart-home device in the testbed inventory; \"attack source\" = "
         "the testbed attack machines.", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```"]
        path.write_text("\n".join(L) + "\n", encoding="utf-8")
        return
    caps = out["captures"]
    L += ["## 1. How often frames are out of timestamp order", "",
          "| capture | format / timestamp unit | frames (train + val windows) | inversions | rate | median / p99 / max size "
          "(ms) | median / p99 behind the latest timestamp so far (ms) |", "|---|---|---|---|---|---|---|"]
    for c in caps:
        nf, ni = sum(c["frames"].values()), sum(c["inversions"].values())
        mg, bl = c["magnitude_s"], c["below_running_max_s"]
        L.append(f"| {c['session']} | {c['format']} / {c['timestamp_resolution']} | {nf:,} | {ni:,} | {_pct(ni, nf)} | "
                 + (f"{1e3 * mg['p50']:.3f} / {1e3 * mg['p99']:.3f} / {1e3 * mg['max']:.1f}" if mg else "-") + " | "
                 + (f"{1e3 * bl['p50']:.3f} / {1e3 * bl['p99']:.3f}" if bl else "-") + " |")
    agg = lambda k: sum((Counter(c[k]) for c in caps), Counter())  # noqa: E731
    for title, ik, ak in (("protocol", "inv_by_proto", "all_by_proto"), ("TCP flags of the inverted frame", "inv_by_flags", "all_by_flags"),
                          ("source host", "inv_by_src", "all_by_src"), ("destination host", "inv_by_dst", "all_by_dst")):
        I, A = agg(ik), agg(ak)
        L += ["", f"Inversions by {title} (all captures):", "", "| value | inverted frames | all frames | rate |", "|---|---|---|---|"]
        L += [f"| {k} | {v:,} | {A.get(k, 0):,} | {_pct(v, A.get(k, 0))} |" for k, v in I.most_common(12)]
    L += ["", "## 2. TCP handshakes: is the reply stamped before the SYN?", "",
          "A SYN from A to B is paired with B's first SYN/ACK or RST back on the same address / port pair (within 10 s). "
          "\"Reply first\" = the reply's timestamp is earlier than the SYN's. Class = the capture's attack type when A is an "
          "attack source, otherwise benign.", "",
          "| responder | class | reply type | handshakes | reply first | share |", "|---|---|---|---|---|---|"]
    H = defaultdict(lambda: [0, 0])
    for c in caps:
        for h in c["handshakes"]:
            k = (h["device"], h["class"], h["type"])
            H[k][0] += h["n"]
            H[k][1] += h["n"] if h["responder_first"] else 0
    for k, (n, f) in sorted(H.items(), key=lambda kv: -kv[1][1])[:40]:
        L.append(f"| {k[0]} | {k[1]} | {k[2]} | {n:,} | {f:,} | {_pct(f, n)} |")
    ms = out.get("map_spearman") or {}
    L += ["", "How this lines up with the two reversed-flow patterns the IDS sees (per capture x device, attack-source "
          "handshakes; dataset = the sampled flow rows): RST-type reply first <-> rows the R3 rule flips; SYN/ACK reply "
          f"first <-> the diag_03 'H1' shape. Spearman over {ms.get('cells', 0)} cells: RST-first share vs R3-flip share "
          f"{_r(ms.get('rst_first_vs_r3_flip_share'))}; SYN/ACK-first share vs H1 share {_r(ms.get('synack_first_vs_h1_share'))}.", "",
          "| capture | device | RST replies | first | SYN/ACK replies | first | dataset TCP attack flows | R3 flips | H1 shape |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(out["map_r3_h1"], key=lambda r: -(r["rst_responder_first"] + r["synack_responder_first"]))[:30]:
        L.append(f"| {r['session']} | {r['device']} | {r['rst_handshakes']:,} | {r['rst_responder_first']:,} | "
                 f"{r['synack_handshakes']:,} | {r['synack_responder_first']:,} | {r['dataset_tcp_attack_flows']:,} | "
                 f"{r['dataset_r3_flips']:,} | {r['dataset_h1_shape']:,} |")
    L += ["", "## 3. Signs of a merged or multi-interface capture", "",
          "| capture | file format | interface ids | timestamp unit (header) | share of timestamps on a whole ms | duplicate "
          "frames within 1 ms | non-IPv4 frames | unpaired SYN / reply |", "|---|---|---|---|---|---|---|---|"]
    for c in caps:
        nf = sum(c["frames"].values())
        L.append(f"| {c['session']} | {c['format']} | {'none (classic pcap has no interface ids)' if c['format'] == 'pcap' else 'see pcapng'} | "
                 f"{c['timestamp_resolution']} | {100 * c['share_ts_on_whole_ms']:.2f} % | {c['duplicates_within_1ms']:,} "
                 f"({_pct(c['duplicates_within_1ms'], nf)}) | {c['non_ipv4']:,} | {c['unpaired'].get('syn_unanswered', 0):,} / "
                 f"{c['unpaired'].get('responder_unmatched', 0):,} |")
    L += ["", "## Figures", ""] + [f"- `{f}`" for f in M.get("figures", [])]
    L += ["", "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M["checks"]]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def _r(x):
    return "n/a" if x is None or not np.isfinite(x) else f"{x:+.2f}"


def fig_rates(path, caps):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, ax = plt.subplots(figsize=(7.2, 0.45 * len(caps) + 1.4))
    v = [100 * c["inversion_rate"] for c in caps]
    y = np.arange(len(caps))
    ax.barh(y, v, color=PS.CATEGORICAL[0], height=0.6)
    for yy, x, c in zip(y, v, caps):
        ax.text(x, yy, f" {x:.3f} % ({sum(c['inversions'].values()):,} of {sum(c['frames'].values()):,})", va="center", fontsize=7)
    ax.set_yticks(y, [c["session"] for c in caps], fontsize=8)
    ax.invert_yaxis()
    ax.set_xlim(0, max(v + [0.01]) * 1.6)
    ax.set_xlabel("% of frames stamped earlier than the frame before them in the file")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_title("Timestamp inversions per capture (train + val windows)", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_mag(path, caps):
    import matplotlib.pyplot as plt
    PS.apply()
    edges = np.arange(-7, 2.01, 0.25)
    mid = 10 ** ((edges[:-1] + edges[1:]) / 2) * 1e3
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    for k, c in enumerate(caps):
        h = np.asarray(c["magnitude_log10_hist"], float)
        if h.sum():
            ax.plot(mid, h / h.sum(), marker="o", ms=3, lw=1.2, color=PS.CATEGORICAL[k % len(PS.CATEGORICAL)], label=c["session"])
    ax.set_xscale("log")
    ax.set_xlabel("how much earlier than the previous frame (ms, log)")
    ax.set_ylabel("share of inversions")
    if ax.get_legend_handles_labels()[0]:
        ax.legend(frameon=False, fontsize=7)
    else:
        ax.text(0.5, 0.5, "no timestamp inversions in any capture", transform=ax.transAxes, ha="center", color=PS.TEXT2)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_title("Size of timestamp inversions per capture", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_hs(path, caps):
    import matplotlib.pyplot as plt
    PS.apply()
    H = defaultdict(lambda: [0, 0])
    for c in caps:
        for h in c["handshakes"]:
            k = (h["class"], h["type"])
            H[k][0] += h["n"]
            H[k][1] += h["n"] if h["responder_first"] else 0
    keys = sorted(H, key=lambda k: (k[0], k[1]))
    fig, ax = plt.subplots(figsize=(7.2, 0.42 * len(keys) + 1.4))
    y = np.arange(len(keys))
    v = [100 * H[k][1] / H[k][0] if H[k][0] else 0 for k in keys]
    ax.barh(y, v, color=PS.CATEGORICAL[1], height=0.6)
    for yy, x, k in zip(y, v, keys):
        ax.text(x, yy, f" {x:.2f} % ({H[k][1]:,} of {H[k][0]:,})", va="center", fontsize=7)
    ax.set_yticks(y, [f"{a} / {b}" for a, b in keys], fontsize=8)
    ax.invert_yaxis()
    ax.set_xlim(0, max(v + [1]) * 1.5)
    ax.set_xlabel("% of handshakes whose reply is stamped before the SYN")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_title("Reply-before-SYN by class / reply type (all train + val captures)", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


if __name__ == "__main__":
    sys.exit(main())
