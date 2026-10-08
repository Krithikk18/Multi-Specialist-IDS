#!/usr/bin/env python
"""04_tag_flows.py -- tag every CICFlowMeter flow with the device on each side and one owner.

Inputs (never modified):
  flows    CICFlowMeter CSV (84 columns)
  map      config/ip_mac_map.csv from 02_mac_ip_map.py (ip, mac, first/last_seen_epoch, ...)
  devices  config/device_table.csv
  pcap     cached copy in ~/lgids_cache (verified against 02's saved SHA256), used only to
           resolve IP-conflict flows

Outputs:
  <out>                              all 84 original columns, unchanged and in order, plus
                                     src_mac, src_device, src_role, dst_mac, dst_device, dst_role,
                                     owner_mac, owner_device, owner_category, owner_rule,
                                     owner_status, owner_resolution, ambiguous_reason,
                                     exclude_reason
  <out-dir>/tag_report.md / .json    integrity checks + tagging statistics

Endpoint lookup (Src IP and Dst IP separately, first match wins):
  multicast / 255.255.255.255 / subnet broadcast  -> role "broadcast"
  0.0.0.0 / ::                                    -> role "unspecified"
  not LAN-scope (same definition as 02)           -> role "external"
  LAN-scope: map rows for this IP whose [first_seen - tol, last_seen + tol] contains the flow
  start (flow Timestamp, truncated to whole seconds, hence the 1 s default tolerance):
      one distinct MAC  -> that MAC's device-table role (iot, gateway, testbed_pi, ...)
      several MACs      -> role "ambiguous" (all candidates recorded, ';'-joined)
      none              -> role "lan_unmapped"

Conflict resolution (default on, --no-resolve-conflicts skips it): IPs flagged
ip_multi_mac_overlapping in the map are extracted from the pcap in one tshark pass (filter:
conflict IP and time within the overlap window +/- 2 s, extended to the end of the latest
ambiguous flow). Packets are matched to ambiguous TCP/UDP flows in time
(flow start - 1 s .. start + Flow Duration + 1 s). Per flow, the set of matched conflict-side
MACs decides: exactly one -> that endpoint is resolved; several -> "both_macs_in_flow";
none -> "no_packet_match" (includes protocol-0 flows, which have no ports).

  --conflict-rule sender_mac (default)
    Only packets SENT by the conflict IP count; their MAC is eth.src. (A packet's eth.dst
    only reflects the sender's ARP cache, which during an ARP-level IP clash points at one
    host regardless of who the conversation belongs to.) Key: (conflict IP, peer IP,
    conflict-side port, peer port, protocol) -- independent of which side CICFlowMeter
    called Src. ICMP error packets (ip.proto 1) that carry an inner UDP/TCP header are
    matched the way CICFlowMeter reads them: outer IPs, inner ports as given (inner src port
    = conflict-side port), protocol of the inner header.
  --conflict-rule legacy
    Packet MAC = eth.src if ip.src is the conflict IP, else eth.dst if ip.dst is the conflict
    IP and eth.dst is unicast. Key: (sorted IP pair, sorted port pair, protocol); TCP/UDP
    packets only.

exclude_reason (blank = usable for training; at most one reason per flow):
  ip_conflict_unresolved  owner_status is still "ambiguous" after conflict resolution
  invalid_parse           owner_status "invalid_parse" (see Ownership)
  ip_clash_artifact       owner_resolution "pcap_packet_mac" (sender_mac rule) AND the flow
                          matched >= 1 packet sent by the conflict IP AND every such packet is
                          an ICMP destination-unreachable error (ip.proto 1, icmp.type 3, any
                          code). These are the resolved host's replies to traffic that was
                          meant for the other host sharing the IP (here: the Yi camera
                          rejecting DNS answers to Unknown's queries). Owner fields are kept;
                          the flow is only flagged. Not evaluated under the legacy rule.

Ownership (smart-home = device-table role "iot"; gateway, testbed Pis, phone and unknown
MACs are never owners):
  either side ambiguous      -> ambiguous, rule ip_conflict
  both sides smart-home      -> Src side,  rule device_device_initiator
  exactly one smart-home     -> that side, rule device_side
  both external, Protocol 0  -> invalid_parse, rule invalid_parse:external-external-proto0
                                (non-IP frames CICFlowMeter misread as IP)
  otherwise                  -> unowned,   rule no_device:<src_role>-<dst_role>

Exit status is non-zero if an input is missing, the pcap cache fails verification, or any
integrity check fails.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import importlib.util
import io
import ipaddress as ipa
import json
import platform
import subprocess
import sys
import time
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
EXPECTED_FLOW_COLS = 84
TS_FORMAT = "%d/%m/%Y %I:%M:%S %p"
LOW_FLOW_THRESHOLD = 100
SMART_HOME_ROLE = "iot"
PORT_PROTOS = (6, 17)
TSHARK_PAD_S = 2.0
INVALID_PARSE_RULE = "invalid_parse:external-external-proto0"

TAG_COLS = ["src_mac", "src_device", "src_role", "dst_mac", "dst_device", "dst_role",
            "owner_mac", "owner_device", "owner_category", "owner_rule", "owner_status",
            "owner_resolution", "ambiguous_reason", "exclude_reason"]
ICMP_DEST_UNREACH = 3
CONFLICT_RULES = ("sender_mac", "legacy")
PKT_FIELDS = ["frame.time_epoch", "eth.src", "eth.dst", "ip.src", "ip.dst", "ip.proto",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "icmp.type",
              "icmp.code"]

# Reuse 02's LAN-scope definition and helpers so both steps classify IPs identically.
_spec = importlib.util.spec_from_file_location("mac_ip_map", ROOT / "02_mac_ip_map.py")
m02 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m02)
log, fatal, pct, norm_mac, sha256 = m02.log, m02.fatal, m02.pct, m02.norm_mac, m02.sha256


# --------------------------------------------------------------------------- loading

def load_devices(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    cols = m02.match_columns(list(df.columns), m02.DEVICE_COLS, f"device table {path}")
    dev = pd.DataFrame({k: df[v].str.strip() for k, v in cols.items()})
    dev["mac"] = dev["mac"].map(norm_mac)
    dev["role"] = dev["role"].str.lower()
    dups = dev["mac"][dev["mac"].duplicated()].tolist()
    if dups:
        fatal(f"duplicate MACs in device table: {dups}")
    return dev


def norm_ip(ip: str) -> str:
    try:
        return str(ipa.ip_address(ip.strip()))
    except ValueError:
        return ip.strip()


def load_map(path: Path) -> pd.DataFrame:
    m = pd.read_csv(path, dtype={"ip": str, "mac": str, "conflict_flag": str},
                    keep_default_na=False)
    need = {"ip", "mac", "first_seen_epoch", "last_seen_epoch", "conflict_flag"}
    if not need <= set(m.columns):
        fatal(f"map {path} lacks columns {sorted(need - set(m.columns))}")
    m["ip"] = m["ip"].map(norm_ip)
    m["mac"] = m["mac"].map(norm_mac)
    return m[["ip", "mac", "first_seen_epoch", "last_seen_epoch", "conflict_flag"]]


def find_conflicts(m: pd.DataFrame, dev: pd.DataFrame) -> list[dict]:
    """IPs the map flags ip_multi_mac_overlapping, with the span where >= 2 MAC windows overlap."""
    names = dict(zip(dev["mac"], dev["device_name"]))
    out = []
    flagged = m[m["conflict_flag"].str.contains("ip_multi_mac_overlapping", regex=False)]
    for ip, g in flagged.groupby("ip", sort=True):
        rows = g.to_dict("records")
        ov = [(max(a["first_seen_epoch"], b["first_seen_epoch"]),
               min(a["last_seen_epoch"], b["last_seen_epoch"]))
              for a, b in combinations(rows, 2)]
        ov = [(lo, hi) for lo, hi in ov if lo <= hi]
        if not ov:
            continue
        macs = sorted(g["mac"].unique())
        out.append({"ip": ip, "macs": macs, "devices": [names.get(x, "?") for x in macs],
                    "overlap_start": min(lo for lo, _ in ov), "overlap_end": max(hi for _, hi in ov)})
    return out


# --------------------------------------------------------------------------- endpoint lookup

def ip_class(ip: str, bcast: set) -> str:
    """broadcast | unspecified | external | invalid | lan (lan = needs map lookup)."""
    a, why = m02.ip_scope(ip)
    if why == "invalid_ip":
        return "invalid"
    if why in ("multicast", "limited_broadcast") or a in bcast:
        return "broadcast"
    if why == "unspecified":
        return "unspecified"
    if why == "not_lan_scope":
        return "external"
    return "lan"


def set_device(side: pd.DataFrame, rows: pd.Index, macs: pd.Series, dev: pd.DataFrame) -> None:
    d = dev.set_index("mac")
    side.loc[rows, "mac"] = macs
    side.loc[rows, "device"] = macs.map(d["device_name"]).fillna("")
    side.loc[rows, "category"] = macs.map(d["category"]).fillna("")
    side.loc[rows, "role"] = macs.map(d["role"]).fillna("unlisted")


def resolve_side(ips: pd.Series, t: pd.Series, m: pd.DataFrame, dev: pd.DataFrame,
                 bcast: set, tol: float) -> pd.DataFrame:
    """Vectorised lookup for one side. Each LAN endpoint is joined to every map row of its
    IP (<= a handful per IP), kept if the time window matches, then grouped back per flow;
    unlike merge_asof this sees *all* windows, so overlapping claims are detected."""
    nip = ips.map(norm_ip)
    cls = nip.map({u: ip_class(u, bcast) for u in nip.unique()})
    out = pd.DataFrame({"ip": nip, "mac": "", "device": "", "role": cls, "category": ""},
                       index=ips.index)

    lan = pd.DataFrame({"ip": nip[cls == "lan"], "t": t[cls == "lan"]})
    lan["row"] = lan.index
    j = lan.merge(m[["ip", "mac", "first_seen_epoch", "last_seen_epoch"]], on="ip", how="inner")
    j = j[(j["t"] >= j["first_seen_epoch"] - tol) & (j["t"] <= j["last_seen_epoch"] + tol)]
    j = j.drop_duplicates(["row", "mac"]).sort_values(["row", "mac"])
    cands = j.groupby("row")["mac"].agg(list)

    out.loc[cls == "lan", "role"] = "lan_unmapped"
    one = cands[cands.str.len() == 1].str[0]
    many = cands[cands.str.len() > 1]
    set_device(out, one.index, one, dev)

    names = dict(zip(dev["mac"], dev["device_name"]))
    out.loc[many.index, "mac"] = many.str.join(";")
    out.loc[many.index, "device"] = many.map(lambda ms: ";".join(names.get(x, "?") for x in ms))
    out.loc[many.index, "role"] = "ambiguous"
    return out


# --------------------------------------------------------------------------- conflict resolution

def verify_cache(pcap_src: Path, cache_dir: Path) -> tuple[Path, dict]:
    """Check the cached pcap against the SHA256 that 02 saved in its sidecar."""
    cached = cache_dir / pcap_src.name
    sidecar = cache_dir / f"{pcap_src.name}.sha256.json"
    if not cached.exists() or not sidecar.exists():
        fatal(f"cached pcap or sidecar missing in {cache_dir} (run 02_mac_ip_map.py first)")
    side = json.loads(sidecar.read_text())
    info = {"cached_path": str(cached), "saved_sha256": side["sha256"]}
    if pcap_src.exists():
        st = pcap_src.stat()
        info["source_unchanged_since_hash"] = (st.st_size == side.get("size")
                                               and st.st_mtime_ns == side.get("mtime_ns"))
        if not info["source_unchanged_since_hash"]:
            log("WARNING: original pcap size/mtime differ from the sidecar; re-run 02 to re-cache")
    log("Verifying cached pcap SHA256 ...")
    info["cache_sha256"] = sha256(cached, "cache")
    info["verified"] = info["cache_sha256"] == side["sha256"]
    if not info["verified"]:
        fatal(f"cached pcap hash {info['cache_sha256']} != saved {side['sha256']}")
    return cached, info


def extract_conflict_packets(pcap: Path, conflicts: list[dict]) -> tuple[pd.DataFrame, dict]:
    clauses = [f"(ip.addr == {c['ip']} && frame.time_epoch >= {c['tshark_lo']:.6f} "
               f"&& frame.time_epoch <= {c['tshark_hi']:.6f})" for c in conflicts]
    cmd = ["tshark", "-n", "-r", str(pcap), "-Y", " || ".join(clauses), "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=f"]
    for fld in PKT_FIELDS:
        cmd += ["-e", fld]
    log("Running: " + " ".join(cmd))
    t0 = time.monotonic()
    r = subprocess.run(cmd, capture_output=True, text=True)
    secs = round(time.monotonic() - t0, 1)
    if r.returncode != 0:
        fatal(f"tshark exited with {r.returncode}: {r.stderr[-2000:]}")
    if r.stdout.strip():
        pk = pd.read_csv(io.StringIO(r.stdout), sep="\t", header=None, names=PKT_FIELDS,
                         dtype=str, keep_default_na=False, quoting=csv.QUOTE_NONE)
    else:
        pk = pd.DataFrame(columns=PKT_FIELDS, dtype=str)
    log(f"  {len(pk):,} packets in {secs} s")
    return pk, {"display_filter": " || ".join(clauses), "packets_extracted": len(pk),
                "tshark_seconds": secs, "tshark_stderr": r.stderr.strip()[-2000:]}


def prep_packets(pk: pd.DataFrame) -> pd.DataFrame:
    """Numeric time/protocol/ports. With tshark occurrence=f the tcp/udp ports of an ICMP error
    packet come from its inner (quoted) header, since the outer packet has none."""
    pk = pk.copy()
    pk["t"] = pd.to_numeric(pk["frame.time_epoch"], errors="coerce")
    pk["proto"] = pd.to_numeric(pk["ip.proto"], errors="coerce")
    tcp, udp = pk["tcp.srcport"] != "", pk["udp.srcport"] != ""
    pk["sp"] = pd.to_numeric(pk["tcp.srcport"].where(tcp, pk["udp.srcport"]), errors="coerce")
    pk["dp"] = pd.to_numeric(pk["tcp.dstport"].where(tcp, pk["udp.dstport"]), errors="coerce")
    pk["inner_proto"] = np.where(tcp, 6, np.where(udp, 17, -1))
    pk["icmp_type"] = pd.to_numeric(pk["icmp.type"], errors="coerce")
    pk["is_icmp_inner"] = (pk["proto"] == 1) & (pk["inner_proto"] > 0)
    pk["is_unreach"] = (pk["proto"] == 1) & (pk["icmp_type"] == ICMP_DEST_UNREACH)
    return pk


def match_packets_sender(pk: pd.DataFrame, flows: pd.DataFrame,
                         conflicts: list[dict]) -> tuple[pd.Series, pd.Series, dict]:
    """sender_mac rule. Returns per-flow sorted MAC lists, per-flow 'all matched packets are
    ICMP destination-unreachable' flags, and stats."""
    st = {"rule": "sender_mac"}
    pk = prep_packets(pk)
    cand = {x for c in conflicts for x in c["macs"]}
    pk["cip"] = ""
    for c in conflicts:
        hit = pk["t"].between(c["tshark_lo"], c["tshark_hi"]) & (pk["ip.src"] == c["ip"])
        pk.loc[hit, "cip"] = c["ip"]
    pk = pk[pk["cip"] != ""].copy()
    pk["cmac"] = pk["eth.src"].map(norm_mac)
    st["packets_sent_by_conflict_ip"] = len(pk)
    st["packets_sent_mac_counts"] = pk["cmac"].value_counts().to_dict()
    st["packets_non_candidate_mac"] = int((~pk["cmac"].isin(cand)).sum())
    st["packets_icmp_with_inner_header"] = int(pk["is_icmp_inner"].sum())
    st["packets_icmp_dest_unreachable"] = int(pk["is_unreach"].sum())
    st["packets_icmp_dest_unreachable_by_mac"] = pk.loc[pk["is_unreach"], "cmac"].value_counts().to_dict()
    # effective protocol as CICFlowMeter sees it: native TCP/UDP, or the inner header of ICMP
    pk["eproto"] = np.where(pk["proto"].isin(PORT_PROTOS), pk["proto"],
                            np.where(pk["is_icmp_inner"], pk["inner_proto"], -1))
    usable = (pk["cmac"].isin(cand) & pk["eproto"].isin(PORT_PROTOS)
              & pk["sp"].notna() & pk["dp"].notna())
    pk = pk[usable]
    st["packets_usable"] = len(pk)
    pkk = pd.DataFrame({"cip": pk["cip"], "peer": pk["ip.dst"], "cport": pk["sp"].astype("int64"),
                        "pport": pk["dp"].astype("int64"), "proto": pk["eproto"].astype("int64"),
                        "t": pk["t"], "cmac": pk["cmac"], "unreach": pk["is_unreach"],
                        "pid": pk.index})

    fl = flows[flows["proto"].isin(PORT_PROTOS)]
    src = (fl["cside"] == "src").to_numpy()
    flk = pd.DataFrame({"cip": np.where(src, fl["sip"], fl["dip"]),
                        "peer": np.where(src, fl["dip"], fl["sip"]),
                        "cport": np.where(src, fl["sport"], fl["dport"]).astype("int64"),
                        "pport": np.where(src, fl["dport"], fl["sport"]).astype("int64"),
                        "proto": fl["proto"].astype("int64").to_numpy(),
                        "lo": fl["lo"].to_numpy(), "hi": fl["hi"].to_numpy(), "row": fl.index})
    j = flk.merge(pkk, on=["cip", "peer", "cport", "pport", "proto"], how="inner")
    st["join_rows_before_time_filter"] = len(j)
    j = j[(j["t"] >= j["lo"]) & (j["t"] <= j["hi"])]
    st["packet_flow_matches"] = len(j)
    st["packets_matched_to_any_flow"] = int(j["pid"].nunique())
    g = j.groupby("row")
    macs = g["cmac"].agg(lambda x: sorted(set(x)))
    unreach_all = g["unreach"].all()
    st["flows_with_matched_packets"] = len(macs)
    st["flows_mixed_unreach_and_other"] = int((g["unreach"].any() & ~unreach_all).sum())
    return macs, unreach_all, st


def match_packets_legacy(pk: pd.DataFrame, flows: pd.DataFrame,
                         conflicts: list[dict]) -> tuple[pd.Series, pd.Series, dict]:
    """legacy rule. Returns per-flow sorted lists of conflict-side candidate MACs seen in its
    packets; the ICMP-unreachable flags are empty (ICMP packets are not matched)."""
    st = {"rule": "legacy"}
    pk = prep_packets(pk)
    uni = {x: m02.mac_is_unicast(x) for x in pk["eth.dst"].unique()}
    pk["cmac"] = ""
    for c in conflicts:
        in_win = pk["t"].between(c["tshark_lo"], c["tshark_hi"])
        is_src = in_win & (pk["ip.src"] == c["ip"]) & (pk["cmac"] == "")
        is_dst = (in_win & ~is_src & (pk["ip.dst"] == c["ip"]) & (pk["cmac"] == "")
                  & pk["eth.dst"].map(uni))
        pk.loc[is_src, "cmac"] = pk.loc[is_src, "eth.src"].map(norm_mac)
        pk.loc[is_dst, "cmac"] = pk.loc[is_dst, "eth.dst"].map(norm_mac)
    cand = {x for c in conflicts for x in c["macs"]}
    st["packets_with_conflict_side_mac"] = int((pk["cmac"] != "").sum())
    st["packets_conflict_side_mac_counts"] = pk.loc[pk["cmac"] != "", "cmac"].value_counts().to_dict()
    st["packets_non_candidate_mac"] = int(((pk["cmac"] != "") & ~pk["cmac"].isin(cand)).sum())
    usable = (pk["cmac"].isin(cand) & pk["proto"].isin(PORT_PROTOS)
              & pk["sp"].notna() & pk["dp"].notna())
    pk = pk[usable]
    st["packets_usable"] = len(pk)

    def keyed(df, a, b, pa, pb, proto):
        x, y = df[a].astype(str).to_numpy(), df[b].astype(str).to_numpy()
        u, v = df[pa].astype("int64").to_numpy(), df[pb].astype("int64").to_numpy()
        return pd.DataFrame({"ia": np.where(x <= y, x, y), "ib": np.where(x <= y, y, x),
                             "pa": np.minimum(u, v), "pb": np.maximum(u, v),
                             "proto": df[proto].astype("int64").to_numpy()}, index=df.index)

    pkk = keyed(pk, "ip.src", "ip.dst", "sp", "dp", "proto")
    pkk["t"], pkk["cmac"], pkk["pid"] = pk["t"], pk["cmac"], pk.index
    fl = flows[flows["proto"].isin(PORT_PROTOS)]
    flk = keyed(fl, "sip", "dip", "sport", "dport", "proto")
    flk["lo"], flk["hi"], flk["row"] = fl["lo"], fl["hi"], fl.index
    j = flk.merge(pkk, on=["ia", "ib", "pa", "pb", "proto"], how="inner")
    st["join_rows_before_time_filter"] = len(j)
    j = j[(j["t"] >= j["lo"]) & (j["t"] <= j["hi"])]
    st["packet_flow_matches"] = len(j)
    st["packets_matched_to_any_flow"] = int(j["pid"].nunique())
    macs = j.groupby("row")["cmac"].agg(lambda x: sorted(set(x)))
    st["flows_with_matched_packets"] = len(macs)
    return macs, pd.Series(dtype=bool), st


# --------------------------------------------------------------------------- ownership

def assign_owner(s: pd.DataFrame, d: pd.DataFrame, proto: pd.Series) -> pd.DataFrame:
    s_sh, d_sh = s["role"] == SMART_HOME_ROLE, d["role"] == SMART_HOME_ROLE
    amb = (s["role"] == "ambiguous") | (d["role"] == "ambiguous")
    own = pd.DataFrame({"owner_mac": "", "owner_device": "", "owner_category": "",
                        "owner_rule": "no_device:" + s["role"] + "-" + d["role"],
                        "owner_status": "unowned"}, index=s.index)

    take_src = ~amb & s_sh                 # both smart-home -> initiator (Src) side
    take_dst = ~amb & ~s_sh & d_sh
    for mask, side in ((take_src, s), (take_dst, d)):
        own.loc[mask, "owner_mac"] = side.loc[mask, "mac"]
        own.loc[mask, "owner_device"] = side.loc[mask, "device"]
        own.loc[mask, "owner_category"] = side.loc[mask, "category"]
        own.loc[mask, "owner_status"] = "owned"
    own.loc[take_src & d_sh, "owner_rule"] = "device_device_initiator"
    own.loc[take_src & ~d_sh, "owner_rule"] = "device_side"
    own.loc[take_dst, "owner_rule"] = "device_side"
    own.loc[amb, "owner_rule"] = "ip_conflict"
    own.loc[amb, "owner_status"] = "ambiguous"

    invalid = (s["role"] == "external") & (d["role"] == "external") & (proto == 0)
    own.loc[invalid, "owner_rule"] = INVALID_PARSE_RULE
    own.loc[invalid, "owner_status"] = "invalid_parse"
    return own


# --------------------------------------------------------------------------- integrity

def integrity(flows_path: Path, out_path: Path, orig_cols: list[str], n_in: int,
              sha_before: str) -> dict:
    """Re-read both files from disk and compare the original columns: exact text equality,
    plus a parsed NaN-aware comparison (NaN == NaN) of the values pandas infers."""
    res = {"input_rows": n_in}
    out_cols = pd.read_csv(out_path, nrows=0).columns.tolist()
    res["output_columns"] = len(out_cols)
    res["original_columns_in_order"] = out_cols[:len(orig_cols)] == orig_cols
    res["tag_columns_appended"] = out_cols[len(orig_cols):] == TAG_COLS

    a = pd.read_csv(flows_path, dtype=str, keep_default_na=False)
    b = pd.read_csv(out_path, dtype=str, keep_default_na=False, usecols=orig_cols)[orig_cols]
    res["output_rows"] = len(b)
    res["row_count_equal"] = len(a) == len(b) == n_in
    text_diff = {c: int((a[c] != b[c]).sum()) for c in orig_cols} \
        if len(a) == len(b) else {"<row count>": abs(len(a) - len(b))}
    res["text_mismatch_cells"] = sum(text_diff.values())
    res["text_mismatch_by_column"] = {k: v for k, v in text_diff.items() if v}
    del a, b

    a = pd.read_csv(flows_path, low_memory=False)
    b = pd.read_csv(out_path, usecols=orig_cols, low_memory=False)[orig_cols]
    val_diff = {}
    if len(a) == len(b):
        for c in orig_cols:
            x, y = a[c], b[c]
            same = (x.eq(y) | (x.isna() & y.isna())).fillna(False).astype(bool)
            val_diff[c] = int((~same).sum())
    else:
        val_diff["<row count>"] = abs(len(a) - len(b))
    res["value_mismatch_cells_nan_aware"] = sum(val_diff.values())
    res["value_mismatch_by_column"] = {k: v for k, v in val_diff.items() if v}
    res["nan_cells_input"] = int(a.isna().sum().sum())

    res["input_sha256_before"] = sha_before
    res["input_sha256_after"] = sha256(flows_path)
    res["input_sha256_unchanged"] = res["input_sha256_before"] == res["input_sha256_after"]

    res["PASS"] = bool(res["row_count_equal"] and res["original_columns_in_order"]
                       and res["tag_columns_appended"] and res["text_mismatch_cells"] == 0
                       and res["value_mismatch_cells_nan_aware"] == 0
                       and res["input_sha256_unchanged"]
                       and len(orig_cols) == EXPECTED_FLOW_COLS)
    return res


# --------------------------------------------------------------------------- statistics

def vc(s: pd.Series, n: int) -> list[dict]:
    c = s.value_counts()
    return [{"value": k, "flows": int(v), "pct": pct(v, n)} for k, v in c.items()]


def utc_s(epoch) -> str:
    return dt.datetime.fromtimestamp(float(epoch), tz=dt.timezone.utc).isoformat()


def build_stats(f: pd.DataFrame, t: pd.Series, dev: pd.DataFrame) -> dict:
    n = len(f)
    st = {"flows": n, "by_owner_status": vc(f["owner_status"], n),
          "by_owner_rule": vc(f["owner_rule"], n),
          "by_owner_resolution": vc(f["owner_resolution"], n),
          "by_exclude_reason": vc(f["exclude_reason"].replace("", "(blank = usable)"), n)}

    # lan_unmapped: every case
    cases = []
    for side in ("src", "dst"):
        hit = f[f[f"{side}_role"] == "lan_unmapped"]
        cases += [{"side": side, "ip": r[f"{'Src' if side == 'src' else 'Dst'} IP"],
                   "flow_id": r["Flow ID"], "timestamp": r["Timestamp"]}
                  for _, r in hit.iterrows()]
    st["lan_unmapped_endpoints"] = len(cases)
    st["lan_unmapped_cases"] = cases

    # ambiguous (after resolution)
    amb = f["owner_status"] == "ambiguous"
    ips = pd.concat([f.loc[amb & (f["src_role"] == "ambiguous"), "Src IP"],
                     f.loc[amb & (f["dst_role"] == "ambiguous"), "Dst IP"]])
    by_ip = []
    for ip in sorted(ips.unique()):
        s_hit = (f["Src IP"] == ip) & (f["src_role"] == "ambiguous")
        d_hit = (f["Dst IP"] == ip) & (f["dst_role"] == "ambiguous")
        rows = s_hit | d_hit
        cand = set(";".join(pd.concat([f.loc[s_hit, "src_mac"], f.loc[d_hit, "dst_mac"]])
                            .unique()).split(";"))
        by_ip.append({"ip": ip, "flows": int(rows.sum()), "candidate_macs": sorted(cand),
                      "first_flow_utc": utc_s(t[rows].min()), "last_flow_utc": utc_s(t[rows].max())})
    st["ambiguous_flows"] = int(amb.sum())
    st["ambiguous_by_ip"] = by_ip

    # flows per smart-home owner device (all smart-home devices, incl. zero)
    sh = dev[dev["role"] == SMART_HOME_ROLE]
    owned = f.loc[f["owner_status"] == "owned"]
    rule_cnt = owned.groupby(["owner_mac", "owner_rule"]).size().to_dict()
    usable_cnt = owned.loc[owned["exclude_reason"] == "", "owner_mac"].value_counts()
    per_dev = []
    for _, r in sh.iterrows():
        ds = int(rule_cnt.get((r["mac"], "device_side"), 0))
        ddi = int(rule_cnt.get((r["mac"], "device_device_initiator"), 0))
        per_dev.append({"owner_mac": r["mac"], "owner_device": r["device_name"],
                        "owner_category": r["category"], "flows": ds + ddi,
                        "usable": int(usable_cnt.get(r["mac"], 0)),
                        "device_side": ds, "device_device_initiator": ddi,
                        "low_flag": ds + ddi < LOW_FLOW_THRESHOLD})
    per_dev.sort(key=lambda x: (-x["flows"], x["owner_device"]))
    st["smart_home_devices"] = len(sh)
    st["owner_devices_with_flows"] = int(sum(x["flows"] > 0 for x in per_dev))
    st["flows_per_owner_device"] = per_dev
    st["low_flow_devices"] = [x for x in per_dev if x["low_flag"]]

    # device-device pairs
    dd = f[f["owner_rule"] == "device_device_initiator"]
    pairs = dd.groupby(["src_device", "dst_device"]).size().sort_values(ascending=False)
    st["device_device_flows"] = len(dd)
    st["device_device_distinct_pairs"] = int(len(pairs))
    st["device_device_top10"] = [{"src_device": s, "dst_device": d, "flows": int(v)}
                                 for (s, d), v in pairs.head(10).items()]

    # Protocol 0
    p0 = f[pd.to_numeric(f["Protocol"], errors="coerce") == 0]
    st["protocol0_flows"] = len(p0)
    od = p0["owner_device"].where(p0["owner_status"] == "owned",
                                  "(" + p0["owner_status"] + ")")
    st["protocol0_by_owner_device"] = [{"owner_device": k, "flows": int(v)}
                                       for k, v in od.value_counts().items()]
    st["protocol0_by_roles"] = [{"src_role": s, "dst_role": d, "flows": int(v)} for (s, d), v in
                                p0.groupby(["src_role", "dst_role"]).size()
                                .sort_values(ascending=False).items()]

    # unowned
    un = f[f["owner_status"] == "unowned"]
    st["unowned_flows"] = len(un)
    st["unowned_by_rule"] = vc(un["owner_rule"], n)

    # invalid parse
    inv = f[f["owner_status"] == "invalid_parse"]
    st["invalid_parse_flows"] = len(inv)
    st["invalid_parse_ip_counts"] = pd.concat([inv["Src IP"], inv["Dst IP"]]).value_counts() \
        .head(10).to_dict()
    st["invalid_parse_examples"] = inv[["Flow ID", "Src IP", "Dst IP", "Protocol", "Timestamp",
                                        "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
                                        "Total Length of Fwd Packet"]].head(10).to_dict("records")

    # endpoint roles (context)
    st["src_role_counts"] = vc(f["src_role"], n)
    st["dst_role_counts"] = vc(f["dst_role"], n)
    return st


def ambiguity_expectations(s: pd.DataFrame, d: pd.DataFrame, t: pd.Series,
                           conflicts: list[dict], tol: float, lan_unmapped: int) -> dict:
    """Checked on the IP/time lookup *before* pcap resolution."""
    exp = {"lan_unmapped_is_zero": lan_unmapped == 0}
    win = {c["ip"]: (c["overlap_start"] - tol, c["overlap_end"] + tol) for c in conflicts}
    amb_ips = set(s.loc[s["role"] == "ambiguous", "ip"]) | set(d.loc[d["role"] == "ambiguous", "ip"])
    exp["ambiguous_ips"] = sorted(amb_ips)
    exp["ambiguous_ips_all_map_conflicts"] = amb_ips <= set(win)
    inside = True
    for ip in amb_ips & set(win):
        rows = ((s["ip"] == ip) & (s["role"] == "ambiguous")) | ((d["ip"] == ip) & (d["role"] == "ambiguous"))
        lo, hi = win[ip]
        inside &= bool(t[rows].min() >= lo and t[rows].max() <= hi)
    exp["ambiguous_within_overlap_window"] = inside
    return exp


# --------------------------------------------------------------------------- reporting

def md_table(rows: list[dict], cols: list[str]) -> list[str]:
    return m02.md_table(rows, cols)


def write_md(path: Path, rep: dict) -> None:
    st, ig, cr = rep["stats"], rep["integrity"], rep["conflict_resolution"]
    L = ["# Step 5 -- flow tagging report", ""]
    L += [f"- **{k}**: {v}" for k, v in rep["meta"].items()]
    L += ["", f"## Integrity: **{'PASS' if ig['PASS'] else 'FAIL'}**", ""]
    L += [f"- **{k}**: {v}" for k, v in ig.items() if k != "PASS"]
    L += ["", "## Expectations (IP/time lookup, before pcap resolution)", ""]
    L += [f"- **{k}**: {v}" for k, v in rep["expectations"].items()]
    L += ["", "## Rules", "", rep["rules"], ""]
    L += ["## By owner_status", ""] + md_table(st["by_owner_status"], ["value", "flows", "pct"])
    L += ["", "## By owner_rule", ""] + md_table(st["by_owner_rule"], ["value", "flows", "pct"])
    L += ["", "## By owner_resolution", ""]
    L += md_table(st["by_owner_resolution"], ["value", "flows", "pct"])
    L += ["", "## By exclude_reason", ""]
    L += md_table(st["by_exclude_reason"], ["value", "flows", "pct"])

    L += ["", f"## Conflict resolution (rule: {cr.get('rule')})", ""]
    if not cr.get("enabled"):
        L += [f"_skipped: {cr.get('skipped_reason', '--no-resolve-conflicts')}_"]
    else:
        L += [f"- **ambiguous flows before -> after**: {cr['ambiguous_before']:,} -> "
              f"{cr['ambiguous_after']:,} ({cr['resolved_flows']:,} resolved)",
              f"- **ip_clash_artifact flows**: {cr['ip_clash_artifacts']:,} ("
              + (", ".join(f"{x['device']} {x['flows']:,}" for x in cr["ip_clash_artifacts_by_device"])
                 or "none") + ")",
              f"- **packets extracted**: {cr['packets_extracted']:,}",
              *[f"- **{k}**: {v}" for k, v in cr["match"].items()],
              f"- **tshark runtime**: {cr['tshark_seconds']} s",
              f"- **pcap verified**: {cr['pcap']['verified']} ({cr['pcap']['cache_sha256']})",
              f"- **display filter**: `{cr['display_filter']}`", "", "### Conflicts found in map", ""]
        L += md_table([{**c, "macs": ", ".join(c["macs"]), "devices": ", ".join(c["devices"]),
                        "overlap": f"{utc_s(c['overlap_start'])} .. {utc_s(c['overlap_end'])}",
                        "tshark_window": f"{utc_s(c['tshark_lo'])} .. {utc_s(c['tshark_hi'])}"}
                       for c in cr["conflicts"]],
                      ["ip", "macs", "devices", "overlap", "tshark_window"])
        L += ["", "### Resolved to", ""]
        L += md_table(cr["resolved_to"], ["mac", "device", "role", "flows"])
        L += ["", "### Resolved flows -- resulting ownership", ""]
        L += md_table(cr["resolved_ownership"], ["owner_status", "owner_rule", "flows"])
        L += ["", "### Still ambiguous by reason", ""]
        L += md_table(cr["still_ambiguous_by_reason"], ["ambiguous_reason", "protocol", "flows"])
        L += ["", "### Owned flows per candidate device: before resolution -> after "
              "(total / usable = exclude_reason blank)", ""]
        L += md_table(cr["owned_before_after"], ["mac", "device", "before", "after", "after_usable"])

    L += ["", f"## Invalid parse: {st['invalid_parse_flows']:,} flows", "",
          f"Rule `{INVALID_PARSE_RULE}`: both endpoints external and Protocol 0 "
          "(non-IP frames misread as IP). Most frequent addresses: "
          + ", ".join(f"{k} ({v})" for k, v in st["invalid_parse_ip_counts"].items()), ""]
    L += md_table(st["invalid_parse_examples"],
                  ["Flow ID", "Src IP", "Dst IP", "Protocol", "Timestamp", "Flow Duration",
                   "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet"])

    L += ["", f"## lan_unmapped endpoints: {st['lan_unmapped_endpoints']}", ""]
    L += md_table(st["lan_unmapped_cases"], ["side", "ip", "flow_id", "timestamp"])
    L += ["", f"## Ambiguous flows remaining: {st['ambiguous_flows']:,}", ""]
    L += md_table([{**x, "candidate_macs": ", ".join(x["candidate_macs"])}
                   for x in st["ambiguous_by_ip"]],
                  ["ip", "flows", "candidate_macs", "first_flow_utc", "last_flow_utc"])
    L += ["", f"## Flows per smart-home owner device ({st['owner_devices_with_flows']}/"
          f"{st['smart_home_devices']} own >= 1 flow; LOW = < {LOW_FLOW_THRESHOLD})", ""]
    L += md_table([{**x, "low_flag": "LOW" if x["low_flag"] else ""}
                   for x in st["flows_per_owner_device"]],
                  ["owner_device", "owner_mac", "owner_category", "flows", "usable",
                   "device_side", "device_device_initiator", "low_flag"])
    L += ["", f"## Device-device flows: {st['device_device_flows']:,} "
          f"({st['device_device_distinct_pairs']} distinct pairs) -- top 10", ""]
    L += md_table(st["device_device_top10"], ["src_device", "dst_device", "flows"])
    L += ["", f"## Protocol-0 flows: {st['protocol0_flows']:,}", "", "### By owner device", ""]
    L += md_table(st["protocol0_by_owner_device"], ["owner_device", "flows"])
    L += ["", "### By (src_role, dst_role)", ""]
    L += md_table(st["protocol0_by_roles"], ["src_role", "dst_role", "flows"])
    L += ["", f"## Unowned flows: {st['unowned_flows']:,} -- by rule", ""]
    L += md_table(st["unowned_by_rule"], ["value", "flows", "pct"])
    L += ["", "## Endpoint roles", "", "### Src", ""]
    L += md_table(st["src_role_counts"], ["value", "flows", "pct"])
    L += ["", "### Dst", ""] + md_table(st["dst_role_counts"], ["value", "flows", "pct"])
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def print_summary(rep: dict) -> None:
    st, ig, ex, cr = rep["stats"], rep["integrity"], rep["expectations"], rep["conflict_resolution"]
    log("\n================ STEP 5 TAG SUMMARY ================")
    log(f"integrity              : {'PASS' if ig['PASS'] else 'FAIL'}  rows {ig['input_rows']:,} -> "
        f"{ig['output_rows']:,} | text diffs {ig['text_mismatch_cells']} | "
        f"NaN-aware value diffs {ig['value_mismatch_cells_nan_aware']} | "
        f"cols {ig['output_columns']} = {EXPECTED_FLOW_COLS} + {len(TAG_COLS)} | "
        f"input sha256 unchanged {ig['input_sha256_unchanged']}")
    log(f"expectations           : lan_unmapped 0 {ex['lan_unmapped_is_zero']} | ambiguous IPs "
        f"{ex['ambiguous_ips']} all map conflicts {ex['ambiguous_ips_all_map_conflicts']} | "
        f"inside overlap {ex['ambiguous_within_overlap_window']}")
    log("owner_status           : " + " | ".join(
        f"{x['value']} {x['flows']:,} ({x['pct']}%)" for x in st["by_owner_status"]))
    log("owner_rule             :")
    for x in st["by_owner_rule"]:
        log(f"    {x['value']:<40} {x['flows']:>8,}  {x['pct']:>7}%")
    log("owner_resolution       : " + " | ".join(
        f"{x['value']} {x['flows']:,}" for x in st["by_owner_resolution"]))
    if cr.get("enabled"):
        log(f"conflict resolution    : rule {cr['rule']} | ambiguous {cr['ambiguous_before']:,} -> "
            f"{cr['ambiguous_after']:,} | packets {cr['packets_extracted']:,} | "
            f"tshark {cr['tshark_seconds']} s")
        log("    resolved to        : " + ", ".join(
            f"{x['device']} ({x['mac']}) {x['flows']:,}" for x in cr["resolved_to"]))
        log("    still ambiguous    : " + (", ".join(
            f"{x['ambiguous_reason']}/proto {x['protocol']} {x['flows']:,}"
            for x in cr["still_ambiguous_by_reason"]) or "none"))
        log(f"    ip_clash_artifact  : {cr['ip_clash_artifacts']:,} (" + (", ".join(
            f"{x['device']} {x['flows']:,}" for x in cr["ip_clash_artifacts_by_device"]) or "none")
            + f"); mixed unreach+other flows: {cr['match'].get('flows_mixed_unreach_and_other', 'n/a')}")
        for x in cr["owned_before_after"]:
            log(f"    owned by {x['device']:<22}: before {x['before']:,} -> after {x['after']:,} "
                f"(usable {x['after_usable']:,})")
    else:
        log(f"conflict resolution    : skipped ({cr.get('skipped_reason')})")
    log("exclude_reason         : " + " | ".join(
        f"{x['value']} {x['flows']:,}" for x in st["by_exclude_reason"]))
    low = st["low_flow_devices"]
    log(f"devices < {LOW_FLOW_THRESHOLD} owned     : " + (", ".join(
        f"{x['owner_device']} {x['flows']}" for x in low) or "none")
        + f"  ({st['owner_devices_with_flows']}/{st['smart_home_devices']} own >= 1 flow)")


# --------------------------------------------------------------------------- main

def main() -> None:
    t_start = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--flows", type=Path,
                    default=ROOT / "data/interim/flows/benign/BenignTraffic.pcap_Flow__singlepkt.csv")
    ap.add_argument("--map", type=Path, default=ROOT / "config/ip_mac_map.csv")
    ap.add_argument("--devices", type=Path, default=ROOT / "config/device_table.csv")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "data/interim/flows/benign/benign_flows_tagged.csv")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "results/step5")
    ap.add_argument("--pcap", type=Path, default=ROOT / "data/raw/ciciot2023/benign/BenignTraffic.pcap",
                    help="original pcap (only its name and size/mtime are used; the cache is read)")
    ap.add_argument("--cache-dir", type=Path, default=Path("~/lgids_cache"))
    ap.add_argument("--no-resolve-conflicts", action="store_true",
                    help="skip resolving IP-conflict flows from pcap packet MACs")
    ap.add_argument("--conflict-rule", choices=CONFLICT_RULES, default="sender_mac",
                    help="packet-to-flow matching rule for conflict resolution (see docstring)")
    ap.add_argument("--subnets", nargs="+", default=["192.168.137.0/24", "10.22.22.0/24"],
                    help="LAN subnets whose broadcast address is role 'broadcast'")
    ap.add_argument("--tolerance", type=float, default=1.0,
                    help="seconds added to each side of a map window and of a flow's packet "
                         "window (flow timestamps are truncated to whole seconds)")
    args = ap.parse_args()
    args.cache_dir = args.cache_dir.expanduser()

    for p in (args.flows, args.map, args.devices):
        if not p.exists():
            fatal(f"input not found: {p}")
    if args.out.resolve() in {args.flows.resolve(), args.map.resolve(), args.devices.resolve(),
                              args.pcap.resolve()}:
        fatal("--out must not overwrite an input file")

    # 02 also treats 169.254.255.255 as broadcast; keep the definitions identical.
    bcast = {ipa.ip_network(s).broadcast_address for s in args.subnets}
    bcast.add(ipa.IPv4Address("169.254.255.255"))

    dev = load_devices(args.devices)
    m = load_map(args.map)
    conflicts = find_conflicts(m, dev)
    log(f"Device table: {len(dev)} MACs ({int((dev['role'] == SMART_HOME_ROLE).sum())} smart-home); "
        f"map: {len(m)} rows")
    log(f"Overlapping IP conflicts in map: {len(conflicts)}")
    for c in conflicts:
        log(f"  {c['ip']}: {', '.join(f'{x} ({n})' for x, n in zip(c['macs'], c['devices']))}  "
            f"overlap {utc_s(c['overlap_start'])} .. {utc_s(c['overlap_end'])}")

    log(f"Reading flows {args.flows} ...")
    flows_sha_before = sha256(args.flows)
    f = pd.read_csv(args.flows, dtype=str, keep_default_na=False)
    orig_cols = list(f.columns)
    if len(orig_cols) != EXPECTED_FLOW_COLS:
        fatal(f"expected {EXPECTED_FLOW_COLS} flow columns, found {len(orig_cols)}")
    for c in ("Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp",
              "Flow Duration"):
        if c not in orig_cols:
            fatal(f"flows lack column {c!r}")
    clash = set(TAG_COLS) & set(orig_cols)
    if clash:
        fatal(f"flows already contain tag columns {sorted(clash)}")
    n_in = len(f)
    log(f"  {n_in:,} flows x {len(orig_cols)} columns")

    ts = pd.to_datetime(f["Timestamp"], format=TS_FORMAT, utc=True, errors="coerce")
    if ts.isna().any():
        bad = f.loc[ts.isna(), "Timestamp"].head(5).tolist()
        fatal(f"{int(ts.isna().sum())} unparseable Timestamps, e.g. {bad}")
    # resolution-independent (pandas may parse to s/us/ns)
    t = ((ts - pd.Timestamp(0, tz="UTC")) // pd.Timedelta(seconds=1)).astype("int64")
    proto = pd.to_numeric(f["Protocol"], errors="coerce")

    log("Resolving endpoints (IP + time) ...")
    s = resolve_side(f["Src IP"], t, m, dev, bcast, args.tolerance)
    d = resolve_side(f["Dst IP"], t, m, dev, bcast, args.tolerance)
    lan_unmapped = int((s["role"] == "lan_unmapped").sum() + (d["role"] == "lan_unmapped").sum())
    exp = ambiguity_expectations(s, d, t, conflicts, args.tolerance, lan_unmapped)
    own_before = assign_owner(s, d, proto)

    amb_mask = (s["role"] == "ambiguous") | (d["role"] == "ambiguous")
    resolution = pd.Series("ip_time", index=f.index)
    reason = pd.Series("", index=f.index)
    resolved_mac = pd.Series(dtype=str)
    artifact = pd.Series(False, index=f.index)
    cr: dict = {"enabled": not args.no_resolve_conflicts and bool(conflicts) and bool(amb_mask.any()),
                "rule": args.conflict_rule}
    if args.no_resolve_conflicts:
        cr["skipped_reason"] = "--no-resolve-conflicts"
    elif not cr["enabled"]:
        cr["skipped_reason"] = "no overlapping conflicts / no ambiguous flows"

    if cr["enabled"]:
        fl = pd.DataFrame({"sip": s["ip"], "dip": d["ip"],
                           "sport": pd.to_numeric(f["Src Port"], errors="coerce"),
                           "dport": pd.to_numeric(f["Dst Port"], errors="coerce"),
                           "proto": proto, "lo": t - args.tolerance,
                           "hi": t + pd.to_numeric(f["Flow Duration"], errors="coerce").fillna(0) / 1e6
                                 + args.tolerance,
                           "cside": np.where(s["role"] == "ambiguous", "src", "dst")})[amb_mask]
        # tshark window: overlap +/- 2 s, extended to cover the end of the latest ambiguous flow
        for c in conflicts:
            on_ip = (fl["sip"] == c["ip"]) | (fl["dip"] == c["ip"])
            c["tshark_lo"] = min(c["overlap_start"] - TSHARK_PAD_S,
                                 float(fl.loc[on_ip, "lo"].min()) if on_ip.any() else float("inf"))
            c["tshark_hi"] = max(c["overlap_end"] + TSHARK_PAD_S,
                                 float(fl.loc[on_ip, "hi"].max()) if on_ip.any() else float("-inf"))
            if ":" in c["ip"]:
                log(f"WARNING: IPv6 conflict {c['ip']} not supported by the packet pass; left ambiguous")
        v4 = [c for c in conflicts if ":" not in c["ip"]]

        cached, pinfo = verify_cache(args.pcap, args.cache_dir)
        pk, xinfo = extract_conflict_packets(cached, v4)
        matcher = match_packets_sender if args.conflict_rule == "sender_mac" else match_packets_legacy
        log(f"Matching packets to ambiguous flows (rule: {args.conflict_rule}) ...")
        macs, unreach_all, mst = matcher(pk, fl.dropna(subset=["sport", "dport", "proto"]), v4)

        one = macs[macs.str.len() == 1].str[0]
        art = unreach_all.reindex(one.index).fillna(False).astype(bool)   # empty under legacy
        artifact[art[art].index] = True
        both = macs[macs.str.len() > 1].index
        for side in (s, d):
            rows = one.index[side.loc[one.index, "role"] == "ambiguous"]
            set_device(side, rows, one.loc[rows], dev)
        resolution[amb_mask] = "unresolved"
        resolution[one.index] = "pcap_packet_mac"
        reason[amb_mask] = "no_packet_match"
        reason[both] = "both_macs_in_flow"
        reason[one.index] = ""
        resolved_mac = one
        cr.update({"pcap": pinfo, "conflicts": conflicts, **xinfo, "match": mst})
    elif amb_mask.any():
        resolution[amb_mask] = "unresolved"
        reason[amb_mask] = "not_attempted"

    own = assign_owner(s, d, proto)
    still = own["owner_status"] == "ambiguous"
    exclude = pd.Series("", index=f.index)
    exclude[still] = "ip_conflict_unresolved"
    exclude[own["owner_status"] == "invalid_parse"] = "invalid_parse"
    exclude[artifact] = "ip_clash_artifact"
    usable = exclude == ""
    if cr["enabled"]:
        resolved = resolution == "pcap_packet_mac"
        names, roles = dict(zip(dev["mac"], dev["device_name"])), dict(zip(dev["mac"], dev["role"]))
        cand = sorted({x for c in conflicts for x in c["macs"]})
        cr.update({
            "ambiguous_before": int(amb_mask.sum()), "ambiguous_after": int(still.sum()),
            "resolved_flows": int(resolved.sum()),
            "resolved_to": [{"mac": k, "device": names.get(k, "?"), "role": roles.get(k, "unlisted"),
                             "flows": int(v)} for k, v in resolved_mac.value_counts().items()],
            "resolved_ownership": [{"owner_status": a, "owner_rule": b, "flows": int(v)} for (a, b), v in
                                   own[resolved].groupby(["owner_status", "owner_rule"]).size()
                                   .sort_values(ascending=False).items()],
            "still_ambiguous_by_reason": [{"ambiguous_reason": a, "protocol": int(p), "flows": int(v)}
                                          for (a, p), v in pd.DataFrame({"r": reason[still],
                                                                         "p": proto[still]})
                                          .groupby(["r", "p"]).size().items()],
            "ip_clash_artifacts": int(artifact.sum()),
            "ip_clash_artifacts_by_device": [{"mac": k, "device": names.get(k, "?"), "flows": int(v)}
                                             for k, v in resolved_mac[artifact.reindex(
                                                 resolved_mac.index)].value_counts().items()],
            "owned_before_after": [{"mac": x, "device": names.get(x, "?"),
                                    "before": int(((own_before["owner_status"] == "owned")
                                                   & (own_before["owner_mac"] == x)).sum()),
                                    "after": int(((own["owner_status"] == "owned")
                                                  & (own["owner_mac"] == x)).sum()),
                                    "after_usable": int(((own["owner_status"] == "owned")
                                                         & (own["owner_mac"] == x) & usable).sum())}
                                   for x in cand],
        })
    else:
        cr.update({"ambiguous_before": int(amb_mask.sum()), "ambiguous_after": int(still.sum())})

    tags = pd.DataFrame({"src_mac": s["mac"], "src_device": s["device"], "src_role": s["role"],
                         "dst_mac": d["mac"], "dst_device": d["device"], "dst_role": d["role"],
                         **{c: own[c] for c in own.columns},
                         "owner_resolution": resolution, "ambiguous_reason": reason,
                         "exclude_reason": exclude})[TAG_COLS]
    out = pd.concat([f, tags], axis=1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    log(f"Writing {args.out} ...")
    out.to_csv(args.out, index=False, lineterminator="\n")

    log("Integrity checks (re-reading input and output from disk) ...")
    ig = integrity(args.flows, args.out, orig_cols, n_in, flows_sha_before)
    st = build_stats(out, t, dev)

    runtime = round(time.monotonic() - t_start, 1)
    rep = {
        "meta": {"run_timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                 "flows": str(args.flows), "flows_sha256": flows_sha_before,
                 "map": str(args.map), "map_sha256": sha256(args.map),
                 "devices": str(args.devices), "devices_sha256": sha256(args.devices),
                 "out": str(args.out), "out_sha256": sha256(args.out),
                 "subnet_broadcasts": sorted(str(b) for b in bcast),
                 "window_tolerance_s": args.tolerance, "timestamp_format": TS_FORMAT + " (UTC)",
                 "resolve_conflicts": not args.no_resolve_conflicts,
                 "conflict_rule": args.conflict_rule,
                 "runtime_s": runtime, "python": platform.python_version(),
                 "pandas": pd.__version__},
        "rules": ("Endpoint: broadcast (multicast/255.255.255.255/subnet .255) > unspecified "
                  "> external (not LAN-scope, as in 02) > LAN map lookup with window "
                  f"[first_seen-{args.tolerance:g}s, last_seen+{args.tolerance:g}s] "
                  "(1 MAC -> device role, >1 -> ambiguous, 0 -> lan_unmapped). Ambiguous "
                  "TCP/UDP flows are then resolved from pcap packets, time window "
                  "start-1s .. start+duration+1s, exactly one MAC -> resolved. "
                  + ("Rule sender_mac: only packets sent by the conflict IP (MAC = eth.src); key "
                     "(conflict IP, peer IP, conflict-side port, peer port, protocol); ICMP errors "
                     "matched via their inner UDP/TCP header. "
                     if args.conflict_rule == "sender_mac" else
                     "Rule legacy: MAC = eth.src if sender else unicast eth.dst; key (sorted IP "
                     "pair, sorted port pair, protocol); TCP/UDP packets only. ")
                  + "Owner: ambiguous side -> ip_conflict; both "
                  "smart-home -> Src (device_device_initiator); one smart-home -> that side "
                  "(device_side); both external + Protocol 0 -> invalid_parse; else unowned "
                  "(no_device:<src_role>-<dst_role>). Smart-home = device-table role 'iot'. "
                  "exclude_reason: ip_conflict_unresolved (still ambiguous), invalid_parse, "
                  "ip_clash_artifact (pcap-resolved flow whose matched conflict-IP-sent packets "
                  "are all ICMP destination-unreachable; owner kept); blank = usable."),
        "integrity": ig, "expectations": exp, "conflict_resolution": cr, "stats": st,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "tag_report.json").write_text(json.dumps(rep, indent=2, default=str),
                                                  encoding="utf-8")
    write_md(args.out_dir / "tag_report.md", rep)

    print_summary(rep)
    log(f"runtime                : {runtime} s")
    log(f"\nwrote {args.out}\n      {args.out_dir / 'tag_report.md'}\n"
        f"      {args.out_dir / 'tag_report.json'}")
    if not ig["PASS"]:
        print("\n!!!!!!!! INTEGRITY FAIL -- tagged output does not preserve the input !!!!!!!!\n"
              + json.dumps(ig, indent=2, default=str), file=sys.stderr, flush=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
