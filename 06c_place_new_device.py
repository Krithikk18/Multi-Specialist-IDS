#!/usr/bin/env python
"""06c_place_new_device.py -- place a device that is absent from the benign capture into a
LOCKED behaviour group (config/behaviour_groups.json v1.0). No re-clustering.

Pipeline (every step reuses the existing scripts' functions):
  1  flows    extraction/run_cicflowmeter.py (locked jar, singlepkt, TZ=UTC) into
              data/interim/flows/attack/<pcap_stem>/ (skipped when the CSV and its .meta.json
              sidecar match the pcap SHA256 and the locked jar); then 03b_check_flows.py,
              abort on exit 1 / 2. (03b's packet-total check compares against the given
              pcap's own capinfos packet count.)
  2  map      02_mac_ip_map.py functions (extract -> infer_subnets -> filter_pairs ->
              time_checks) on THIS pcap -> data/interim/maps/<pcap_stem>_ip_mac_map.csv.
              config/ip_mac_map.csv is never written.
  3  tag      04_tag_flows.py functions in 04's order (resolve_side, assign_owner, pcap-based
              IP-conflict resolution, exclude reasons) with device_table + the new MAC as an
              in-memory extra row (role "iot", the role 04/05 treat as smart-home; no group).
  4  filter   owned by --mac, owner_status == "owned", exclude_reason == "", and the other
              endpoint not an ATTACKER_MACS MAC; counts reported at each step.
  5  features 05_profile_devices.py: load_flows, orient, build_fingerprints. Normalisation is
              05's: only log_flows_per_hour depends on time, = usable flows / capture hours,
              capture hours = first..last Timestamp over ALL flows in the input CSV; the other
              features are per-flow distributions/shares (gap_cv is scale-free).
              Sensitivity (report only): the same fingerprint on the largest contiguous capture
              segment (flow gaps > 10 min split segments), because a gappy capture inflates
              the denominator of log_flows_per_hour and the inter-flow gaps behind gap_cv.
  6  place    locked scaler (clip +-3), distance to every centroid (NaN features skipped, x
              sqrt(n/observed)), stored rule: < min_flows -> GEN; nearest centroid; distance >
              that group's max member distance -> GEN.
  7  report   <out-dir>/<label>.md / .json; context: locked scaled distances of the existing
              Amazon / Google speakers to the same centroids.
  8  --apply  only then: timestamped backup of device_table.csv into --out-dir, add the row
              (behaviour_group = decision, group_confidence low, placement_source =
              --source-label, note); add column placement_source if missing (existing grouped
              rows: "benign_cluster_v1.0"). behaviour_groups.json is never modified.

Self-test (--validate-device NAME [NAME ...], with --pcap the benign pcap): each named device is
removed from the table and re-added as the in-memory extra device, then must reproduce its 05
fingerprint (results/step6/device_fingerprints.csv, |diff| <= 1e-6), its scaled cluster input
(results/step6/cluster_input.csv) and its locked group. The extracted flow CSV and the map are
compared with the existing benign CSV / config/ip_mac_map.csv and reused when byte-identical.

Exit status: 0 ok, 1 bad input or validation failure, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import importlib.util
import ipaddress as ipa
import json
import math
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import (ATTACKER_MACS, BEHAVIOUR_GROUPS, DATASET, DATA_INTERIM, DEVICE_TABLE,
                           EXTRACTOR, FLOWS_DIR, IP_MAC_MAP, NETWORK, REPO_ROOT, RESULTS_DIR)


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m02 = _load("mac_ip_map", "02_mac_ip_map.py")
m04 = _load("tag_flows", "04_tag_flows.py")
m05 = _load("profile_devices", "05_profile_devices.py")
log, fatal, sha256, norm_mac, md_table = m02.log, m02.fatal, m02.sha256, m02.norm_mac, m02.md_table

WRAPPER = REPO_ROOT / "extraction" / "run_cicflowmeter.py"
CHECK_FLOWS = REPO_ROOT / "03b_check_flows.py"
LOCKED_FP = RESULTS_DIR / "step6" / "device_fingerprints.csv"
LOCKED_CI = RESULTS_DIR / "step6" / "cluster_input.csv"
BENIGN_FLOWS = FLOWS_DIR / "benign" / f"{DATASET.benign_pcap}_Flow__{EXTRACTOR.build}.csv"
BENIGN_TAGGED = FLOWS_DIR / "benign" / "benign_flows_tagged.csv"
MAP_COLS = ["ip", "ip_version", "mac", "device_name", "category", "role",
            "first_seen_epoch", "last_seen_epoch", "first_seen_utc", "last_seen_utc",
            "packets", "evidence_src", "evidence_dst", "evidence_arp", "conflict_flag"]
CONTEXT_DEVICES = ["Amazon Alexa Echo Dot 1", "Amazon Alexa Echo Dot 2", "Amazon Alexa Echo Studio",
                   "Amazon Echo Show", "Google Nest Mini Speaker"]
SEGMENT_GAP_S = 600
TOL = 1e-6
NEW_CATEGORY = "Unidentified (Amazon)"
EXISTING_SOURCE = "benign_cluster_v1.0"


# --------------------------------------------------------------------------- 1. flows

def run(cmd: list, what: str) -> subprocess.CompletedProcess:
    log(f"  $ {' '.join(str(c) for c in cmd)}")
    r = subprocess.run([str(c) for c in cmd], cwd=REPO_ROOT, capture_output=True, text=True)
    return r


def extract_flows(pcap: Path, pcap_sha: str, out_dir: Path) -> tuple[Path, dict]:
    csv_path = out_dir / f"{pcap.name}_Flow__{EXTRACTOR.build}.csv"
    meta_path = csv_path.with_name(csv_path.name + ".meta.json")
    if csv_path.is_file() and meta_path.is_file():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if (meta.get("input_pcap_sha256") == pcap_sha and meta.get("jar_sha256") == EXTRACTOR.jar_sha256
                and meta.get("build") == EXTRACTOR.build):
            log(f"  reusing {csv_path} (meta sidecar matches pcap and locked jar)")
            return csv_path, {"action": "reused", "csv": str(csv_path), "meta": meta}
    out_dir.mkdir(parents=True, exist_ok=True)
    r = run([sys.executable, WRAPPER, "--pcap", pcap, "--out-dir", out_dir, "--build",
             EXTRACTOR.build, "--suffix", EXTRACTOR.build, "--timeout", "7200"], "extraction")
    if r.returncode != 0 or not csv_path.is_file() or not meta_path.is_file():
        fatal(f"extraction failed (exit {r.returncode}):\n{(r.stdout + r.stderr)[-3000:]}")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    log(f"  extracted {meta['row_count']:,} flows -> {csv_path}")
    return csv_path, {"action": "extracted", "csv": str(csv_path), "meta": meta}


def check_flows(csv_path: Path, pcap: Path, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    jpath = out_dir / f"{csv_path.stem}_check.json"
    r = run([sys.executable, CHECK_FLOWS, "--csv", csv_path, "--pcap", pcap, "--out-dir", out_dir,
             "--json", jpath], "03b")
    if r.returncode in (1, 2):
        fatal(f"03b_check_flows.py exit {r.returncode} on {csv_path}:\n{(r.stdout + r.stderr)[-3000:]}")
    if r.returncode != 0:
        fatal(f"03b_check_flows.py unexpected exit {r.returncode}")
    j = json.loads(jpath.read_text(encoding="utf-8"))
    log(f"  03b: overall {j['overall_status']} (exit 0)")
    return {"overall": j["overall_status"], "json": str(jpath),
            "checks": {k: v["status"] for k, v in j["checks"].items()}}


# --------------------------------------------------------------------------- 2. map

def build_map(pcap: Path, dev02: pd.DataFrame, out_csv: Path) -> dict:
    """02's main, steps 1-3, on this pcap; writes the map CSV exactly as 02 does."""
    if out_csv.resolve() == IP_MAC_MAP.resolve():
        fatal("refusing to overwrite config/ip_mac_map.csv")
    agg, pstats = m02.extract(pcap)
    subnets, bcast = m02.infer_subnets(agg)
    kept, rejected = m02.filter_pairs(agg, bcast)
    rows = []
    for (mac, ip), (first, last, ns, nd, na) in kept.items():
        a = ipa.ip_address(ip)
        rows.append({"ip": ip, "ip_version": a.version, "mac": mac,
                     "first_seen_epoch": first, "last_seen_epoch": last,
                     "first_seen_utc": m02.utc(first), "last_seen_utc": m02.utc(last),
                     "packets": ns + nd + na, "evidence_src": ns, "evidence_dst": nd,
                     "evidence_arp": na, "_sort": (a.version, int(a), first)})
    m = pd.DataFrame(rows).sort_values("_sort").drop(columns="_sort").reset_index(drop=True)
    m = m.merge(dev02[["mac", "device_name", "category", "role"]], on="mac", how="left")
    m["role"] = m["role"].fillna("unlisted")
    m[["device_name", "category"]] = m[["device_name", "category"]].fillna("")
    m["_idx"] = m.index
    checks = m02.time_checks(m, dev02)
    flags = checks.pop("flags")
    m["conflict_flag"] = m["_idx"].map(lambda i: ";".join(sorted(flags.get(i, ()))))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    m[MAP_COLS].to_csv(out_csv, index=False, float_format="%.6f", quoting=csv.QUOTE_MINIMAL)
    log(f"  map: {len(m):,} rows -> {out_csv}")
    return {"csv": str(out_csv), "rows": len(m), "packets": pstats["packets"],
            "subnets": [s["subnet"] for s in subnets],
            "ip_conflicts_overlapping": checks["ip_multi_mac_overlapping"],
            "ip_conflicts_sequential": checks["ip_multi_mac_sequential"]}


# --------------------------------------------------------------------------- 3. tag

def tag_flows(flows_csv: Path, map_csv: Path, dev: pd.DataFrame, pcap: Path, out_csv: Path) -> dict:
    """04's main (endpoint lookup, ownership, conflict resolution, exclude reasons), same order
    and defaults (sender_mac rule, 1 s tolerance), with 04's functions."""
    tol = 1.0
    bcast = {ipa.ip_network(s).broadcast_address for s in NETWORK.subnets}
    bcast.add(ipa.IPv4Address("169.254.255.255"))
    m = m04.load_map(map_csv)
    conflicts = m04.find_conflicts(m, dev)
    f = pd.read_csv(flows_csv, dtype=str, keep_default_na=False)
    orig_cols = list(f.columns)
    if len(orig_cols) != m04.EXPECTED_FLOW_COLS:
        fatal(f"expected {m04.EXPECTED_FLOW_COLS} flow columns, found {len(orig_cols)}")
    if set(m04.TAG_COLS) & set(orig_cols):
        fatal("flows already contain tag columns")
    ts = pd.to_datetime(f["Timestamp"], format=m04.TS_FORMAT, utc=True, errors="coerce")
    if ts.isna().any():
        fatal(f"{int(ts.isna().sum())} unparseable Timestamps in {flows_csv}")
    t = ((ts - pd.Timestamp(0, tz="UTC")) // pd.Timedelta(seconds=1)).astype("int64")
    proto = pd.to_numeric(f["Protocol"], errors="coerce")
    s = m04.resolve_side(f["Src IP"], t, m, dev, bcast, tol)
    d = m04.resolve_side(f["Dst IP"], t, m, dev, bcast, tol)

    amb_mask = (s["role"] == "ambiguous") | (d["role"] == "ambiguous")
    resolution = pd.Series("ip_time", index=f.index)
    reason = pd.Series("", index=f.index)
    artifact = pd.Series(False, index=f.index)
    info = {"conflicts": len(conflicts), "ambiguous_before": int(amb_mask.sum())}
    if conflicts and amb_mask.any():
        fl = pd.DataFrame({"sip": s["ip"], "dip": d["ip"],
                           "sport": pd.to_numeric(f["Src Port"], errors="coerce"),
                           "dport": pd.to_numeric(f["Dst Port"], errors="coerce"),
                           "proto": proto, "lo": t - tol,
                           "hi": t + pd.to_numeric(f["Flow Duration"], errors="coerce").fillna(0) / 1e6
                                 + tol,
                           "cside": np.where(s["role"] == "ambiguous", "src", "dst")})[amb_mask]
        for c in conflicts:
            on_ip = (fl["sip"] == c["ip"]) | (fl["dip"] == c["ip"])
            c["tshark_lo"] = min(c["overlap_start"] - m04.TSHARK_PAD_S,
                                 float(fl.loc[on_ip, "lo"].min()) if on_ip.any() else float("inf"))
            c["tshark_hi"] = max(c["overlap_end"] + m04.TSHARK_PAD_S,
                                 float(fl.loc[on_ip, "hi"].max()) if on_ip.any() else float("-inf"))
        v4 = [c for c in conflicts if ":" not in c["ip"]]
        pk, _ = m04.extract_conflict_packets(pcap, v4)
        macs, unreach_all, _ = m04.match_packets_sender(pk, fl.dropna(subset=["sport", "dport", "proto"]), v4)
        one = macs[macs.str.len() == 1].str[0]
        art = unreach_all.reindex(one.index).fillna(False).astype(bool)
        artifact[art[art].index] = True
        both = macs[macs.str.len() > 1].index
        for side in (s, d):
            rows = one.index[side.loc[one.index, "role"] == "ambiguous"]
            m04.set_device(side, rows, one.loc[rows], dev)
        resolution[amb_mask] = "unresolved"
        resolution[one.index] = "pcap_packet_mac"
        reason[amb_mask] = "no_packet_match"
        reason[both] = "both_macs_in_flow"
        reason[one.index] = ""
        info["resolved_flows"] = int(len(one))
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
    out = pd.concat([f, tags], axis=1)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_csv, index=False, lineterminator="\n")
    info.update({"flows": len(out), "ambiguous_after": int((own["owner_status"] == "ambiguous").sum()),
                 "tagged_csv": str(out_csv)})
    log(f"  tagged {len(out):,} flows -> {out_csv}")
    return info


# --------------------------------------------------------------------------- 4-6. filter, fingerprint, place

def segments(ts: pd.Series) -> list[tuple[pd.Timestamp, pd.Timestamp, int]]:
    t = ts.dropna().sort_values().reset_index(drop=True)
    if t.empty:
        return []
    cut = np.where(t.diff().dt.total_seconds().to_numpy()[1:] > SEGMENT_GAP_S)[0] + 1
    bounds = [0, *cut.tolist(), len(t)]
    return [(t[a], t[b - 1], b - a) for a, b in zip(bounds[:-1], bounds[1:])]


def fingerprint(f5: pd.DataFrame, mac: str, home: dict, min_flows: int,
                window: tuple | None = None) -> tuple[dict, dict]:
    """Filters (step 4) + 05's fingerprint. window=(lo, hi) restricts flows AND the capture span."""
    f = f5 if window is None else f5[(f5["ts"] >= window[0]) & (f5["ts"] <= window[1])]
    near = (f["src_mac"] == mac) | (f["dst_mac"] == mac)
    owned = (f["owner_status"] == "owned") & (f["owner_mac"] == mac)
    clean = owned & (f["exclude_reason"] == "")
    other = np.where(f["owner_mac"] == f["src_mac"], f["dst_mac"], f["src_mac"])
    att = pd.Series([any(ATTACKER_MACS.matches(x) for x in str(o).split(";") if x) for o in other],
                    index=f.index)
    keep = clean & ~att
    counts = {"all_flows_in_capture": len(f), "device_on_either_side": int(near.sum()),
              "owned_by_device": int(owned.sum()), "owned_and_exclude_reason_blank": int(clean.sum()),
              "dropped_other_endpoint_attacker": int((clean & att).sum()),
              "usable_for_fingerprint": int(keep.sum())}
    all_ts = f["ts"].dropna()
    hours = (all_ts.max() - all_ts.min()).total_seconds() / 3600.0
    u = f[keep]
    o = m05.orient(u)
    fp = m05.build_fingerprints(u, o, pd.DataFrame([home]), hours, min_flows).iloc[0].to_dict()
    fp["capture_hours"] = round(hours, 4)
    return fp, counts


def scale(fp: dict, lock: dict) -> dict:
    return {k: float(np.clip((fp[k] - p["median"]) / p["scale"], -p["clip"], p["clip"]))
            if pd.notna(fp[k]) else float("nan") for k, p in lock["scaler"].items()}


def distance(z: dict, cent: list[float], kept: list[str]) -> float:
    v = np.array([z[k] for k in kept], dtype=float)
    c = np.array(cent, dtype=float)
    ok = ~np.isnan(v)
    return float(np.linalg.norm(v[ok] - c[ok]) * math.sqrt(len(v) / ok.sum()))


def place(z: dict, flows: int, lock: dict) -> dict:
    kept = lock["kept_features"]
    ds = {g: distance(z, c, kept) for g, c in lock["centroids_scaled"].items()}
    near = min(ds, key=ds.get)
    mx = {g: s["max_member_distance"] for g, s in lock["spread"].items()}
    if flows < lock["min_flows"]:
        dec, why = "GEN", f"min_flows gate ({flows} < {lock['min_flows']})"
    elif ds[near] > mx[near]:
        dec, why = "GEN", f"beyond {near} max spread ({ds[near]:.3f} > {mx[near]:.3f})"
    else:
        dec, why = near, f"nearest centroid {near} within its max spread ({ds[near]:.3f} <= {mx[near]:.3f})"
    return {"decision": dec, "reason": why, "nearest": near,
            "distance": {g: round(v, 4) for g, v in ds.items()},
            "ratio_to_max_spread": {g: round(ds[g] / mx[g], 3) for g in ds},
            "ratio_to_median_spread": {g: round(ds[g] / lock["spread"][g]["median_member_distance"], 3)
                                       for g in ds}}


def context(lock: dict) -> list[dict]:
    ci = pd.read_csv(LOCKED_CI)
    tab = pd.read_csv(DEVICE_TABLE, dtype=str, keep_default_na=False)
    grp = dict(zip(tab["device_name"], tab["behaviour_group"]))
    rows = []
    for name in CONTEXT_DEVICES:
        r = ci[ci["device_name"] == name]
        if r.empty:
            continue
        r = r.iloc[0]
        z = {k: float(r[k]) for k in lock["kept_features"]}
        p = place(z, int(r["usable_flows"]), lock)
        rows.append({"device": name, "locked_group": grp.get(name, ""), "usable_flows": int(r["usable_flows"]),
                     "d_G1": p["distance"]["G1"], "d_G2": p["distance"]["G2"],
                     "d_G1/max": p["ratio_to_max_spread"]["G1"], "d_G2/max": p["ratio_to_max_spread"]["G2"]})
    return rows


# --------------------------------------------------------------------------- devices

def fmt(v) -> str:
    return "NaN" if v is None or (isinstance(v, float) and math.isnan(v)) else f"{v:.6g}"


# --------------------------------------------------------------------------- reports

def feature_rows(fp: dict, z: dict, kept: list[str], extra: dict | None = None) -> list[dict]:
    rows = []
    for k in kept:
        r = {"feature": k, "raw": fmt(fp[k]), "scaled": fmt(z[k])}
        if extra:
            r.update({c: fmt(v[k]) for c, v in extra.items()})
        rows.append(r)
    return rows


def write_report(out: Path, label: str, R: dict, lock: dict) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    jpath, mpath = out / f"{label}.json", out / f"{label}.md"
    jpath.write_text(json.dumps(R, indent=2, default=lambda o: o.item() if hasattr(o, "item")
                                else str(o)) + "\n", encoding="utf-8")
    P, S = R["placement"], R.get("sensitivity")
    L = [f"# 06c -- new-device placement: {R['device']['name']} ({R['device']['mac']})", "",
         f"- mode: **{R['mode']}**; run {R['run_utc']}; groups `{BEHAVIOUR_GROUPS}` v{lock['version']} "
         "(locked, not modified)",
         f"- pcap: `{R['pcap']['path']}` sha256 `{R['pcap']['sha256']}`",
         f"- flows: {R['flows']['action']} `{R['flows']['csv']}`; 03b overall **{R['check']['overall']}** "
         f"{R['check']['checks']}",
         f"- map: `{R['map']['csv']}` ({R['map']['rows']} rows, {R['map']['ip_conflicts_overlapping']} "
         f"overlapping IP conflicts); tagging: {R['tag']}",
         f"- device IP(s) in this pcap's map: {R['device'].get('ips_in_map') or 'none'}", "",
         "## Normalisation (05)", "", R["normalisation"], "",
         "## Flow counts per filter step", ""]
    L += md_table([{"step": k, "flows": v} for k, v in R["counts"].items()], ["step", "flows"])
    L += ["", f"## Features (capture hours {R['fingerprint']['capture_hours']}, usable flows "
          f"{R['fingerprint']['usable_flows']})", ""]
    L += md_table(R["feature_table"], list(R["feature_table"][0].keys()))
    L += ["", "## Placement (locked rule)", "",
          f"- distance to G1 centroid **{P['distance']['G1']}** (ratio to G1 max spread "
          f"{P['ratio_to_max_spread']['G1']}, to median {P['ratio_to_median_spread']['G1']})",
          f"- distance to G2 centroid **{P['distance']['G2']}** (ratio to G2 max spread "
          f"{P['ratio_to_max_spread']['G2']}, to median {P['ratio_to_median_spread']['G2']})",
          f"- max spreads: G1 {lock['spread']['G1']['max_member_distance']}, "
          f"G2 {lock['spread']['G2']['max_member_distance']}",
          f"- **decision: {P['decision']}** -- {P['reason']}"]
    if S:
        L += ["", "## Sensitivity: largest contiguous capture segment (report only)", "",
              f"- capture segments (flow gaps > {SEGMENT_GAP_S} s split): "
              + "; ".join(f"{a} -> {b} ({n:,} flows)" for a, b, n in R["capture_segments"]),
              f"- segment {S['window'][0]} -> {S['window'][1]}: capture hours "
              f"{S['fingerprint']['capture_hours']}, usable flows {S['fingerprint']['usable_flows']}",
              f"- distances G1 {S['placement']['distance']['G1']} / G2 {S['placement']['distance']['G2']}; "
              f"ratio to max spread G1 {S['placement']['ratio_to_max_spread']['G1']} / "
              f"G2 {S['placement']['ratio_to_max_spread']['G2']} -> **{S['placement']['decision']}** "
              f"({S['placement']['reason']})"]
    if R.get("validation"):
        L += ["", "## Self-test", ""]
        L += md_table([R["validation"]], list(R["validation"].keys()))
    L += ["", "## Context: locked fingerprints of existing speakers (benign capture)", ""]
    L += md_table(R["context"], list(R["context"][0].keys()) if R["context"] else ["device"])
    if R.get("apply"):
        L += ["", "## Applied", "", f"- {R['apply']}"]
    mpath.write_text("\n".join(L) + "\n", encoding="utf-8")
    return mpath, jpath


# --------------------------------------------------------------------------- apply

def apply_row(mac: str, name: str, decision: str, label: str, lock: dict, out: Path, note: str) -> str:
    tab = pd.read_csv(DEVICE_TABLE, dtype=str, keep_default_na=False)
    if (tab["mac"].map(norm_mac) == mac).any():
        fatal(f"{mac} is already in {DEVICE_TABLE}")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = out / f"device_table_backup_{stamp}.csv"
    shutil.copy2(DEVICE_TABLE, backup)
    if "placement_source" not in tab.columns:
        tab["placement_source"] = np.where(tab["behaviour_group"] != "", EXISTING_SOURCE, "")
    row = {c: "" for c in tab.columns}
    row.update({"mac": mac, "device_name": name, "paper_category": NEW_CATEGORY,
                "role": m04.SMART_HOME_ROLE, "vendor_family": "Amazon", "include_in_grouping": "no",
                "behaviour_group": decision, "behaviour_group_label": lock["labels"].get(decision, ""),
                "group_confidence": "low", "placement_source": label, "notes": note})
    tab = pd.concat([tab, pd.DataFrame([row])], ignore_index=True)
    tab.to_csv(DEVICE_TABLE, index=False, lineterminator="\n")
    return f"added {mac} as {decision} to {DEVICE_TABLE}; backup {backup}"


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mac", default=None)
    ap.add_argument("--name", default="Unidentified Amazon device (1c:12:b0)")
    ap.add_argument("--pcap", type=Path, required=True)
    ap.add_argument("--source-label", default="bruteforce_background")
    ap.add_argument("--apply", action="store_true", help="write the row to device_table.csv")
    ap.add_argument("--note", default="", help="extra text appended to the row's notes (--apply)")
    ap.add_argument("--validate-device", nargs="+", default=None, metavar="NAME",
                    help="self-test: re-derive these known devices as if new")
    ap.add_argument("--out-dir", type=Path, default=RESULTS_DIR / "step7" / "new_device")
    args = ap.parse_args()
    t0 = time.monotonic()
    out = args.out_dir if args.out_dir.is_absolute() else REPO_ROOT / args.out_dir
    if not args.pcap.is_file():
        fatal(f"pcap not found: {args.pcap}")
    if args.validate_device and args.apply:
        fatal("--apply cannot be combined with --validate-device")
    lock = json.loads(BEHAVIOUR_GROUPS.read_text(encoding="utf-8"))
    lock_sha = sha256(BEHAVIOUR_GROUPS)
    table = pd.read_csv(DEVICE_TABLE, dtype=str, keep_default_na=False)
    table["mac"] = table["mac"].map(norm_mac)

    if args.validate_device:
        targets = []
        for nm in args.validate_device:
            r = table[table["device_name"] == nm]
            if len(r) != 1:
                fatal(f"--validate-device {nm!r}: {len(r)} matching device_table rows")
            r = r.iloc[0]
            targets.append({"mac": r["mac"], "name": nm, "category": r["paper_category"],
                            "locked_group": r["behaviour_group"]})
        mode = "self-test"
    else:
        if not args.mac:
            fatal("--mac is required (or use --validate-device)")
        mac = norm_mac(args.mac)
        if (table["mac"] == mac).any():
            fatal(f"{mac} is already in device_table.csv; this script places NEW devices")
        if ATTACKER_MACS.matches(mac):
            fatal(f"{mac} matches ATTACKER_MACS")
        targets = [{"mac": mac, "name": args.name, "category": NEW_CATEGORY, "locked_group": None}]
        mode = "dry run" if not args.apply else "apply"

    log(f"=== {mode}: {args.pcap}")
    pcap_sha = sha256(args.pcap, args.pcap.name)
    stem = args.pcap.stem
    is_benign = pcap_sha == DATASET.benign_pcap_sha256
    if args.validate_device and not is_benign:
        fatal("--validate-device needs the benign pcap (its locked fingerprints come from it)")

    # 1. flows (+03b)
    log("[1] flows")
    if args.validate_device:
        fdir = out / "selftest" / "flows"
        csv_new, finfo = extract_flows(args.pcap, pcap_sha, fdir)
        same = BENIGN_FLOWS.is_file() and sha256(csv_new) == sha256(BENIGN_FLOWS)
        finfo["identical_to_existing_benign_csv"] = same
        if same:
            finfo["csv"] = str(BENIGN_FLOWS)
            log(f"  extracted CSV is byte-identical to {BENIGN_FLOWS}; using it")
        flows_csv = Path(finfo["csv"])
    else:
        flows_csv, finfo = extract_flows(args.pcap, pcap_sha, FLOWS_DIR / "attack" / stem)
    chk = check_flows(flows_csv, args.pcap, out / "flow_check")

    # devices: every target is the in-memory extra row
    d04 = m04.load_devices(DEVICE_TABLE)
    d02, _ = m02.load_devices(DEVICE_TABLE)
    for tg in targets:
        d04, d02 = (pd.concat([x[x["mac"] != tg["mac"]], pd.DataFrame([{
            "mac": tg["mac"], "device_name": tg["name"], "category": tg["category"],
            "role": m04.SMART_HOME_ROLE}])], ignore_index=True) for x in (d04, d02))

    # 2. map
    log("[2] IP->MAC map from this pcap (02)")
    if args.validate_device:
        map_csv = out / "selftest" / f"{stem}_ip_mac_map.csv"
        minfo = build_map(args.pcap, d02, map_csv)
        same = sha256(map_csv) == sha256(IP_MAC_MAP)
        minfo["identical_to_config_ip_mac_map"] = same
        if same:
            minfo["csv"] = str(IP_MAC_MAP)
            log(f"  map is byte-identical to {IP_MAC_MAP}; using it")
        map_csv = Path(minfo["csv"])
    else:
        map_csv = DATA_INTERIM / "maps" / f"{stem}_ip_mac_map.csv"
        minfo = build_map(args.pcap, d02, map_csv)

    # 3. tag
    log("[3] tag flows (04)")
    tagged = (out / "selftest" / f"{stem}_tagged.csv" if args.validate_device
              else FLOWS_DIR / "attack" / stem / f"{flows_csv.stem}_tagged_newdev.csv")
    tinfo = tag_flows(flows_csv, map_csv, d04, args.pcap, tagged)
    if args.validate_device and BENIGN_TAGGED.is_file():
        tinfo["identical_to_existing_benign_tagged_csv"] = sha256(tagged) == sha256(BENIGN_TAGGED)
        log(f"  tagged CSV identical to {BENIGN_TAGGED.name}: "
            f"{tinfo['identical_to_existing_benign_tagged_csv']}")

    # 4-6
    log("[4-6] filter, fingerprint (05), place (locked rule)")
    f5, _, _ = m05.load_flows(tagged)
    segs = segments(f5["ts"])
    mp = m04.load_map(map_csv)
    locked_fp = pd.read_csv(LOCKED_FP).set_index("mac")
    locked_ci = pd.read_csv(LOCKED_CI).set_index("mac")
    kept = lock["kept_features"]
    ctx = context(lock)
    norm_txt = ("05 time-normalises only `log_flows_per_hour` = usable flows / capture hours, where "
                "capture hours = first..last Timestamp over ALL flows in the input CSV (every device "
                "shares one window); all other features are per-flow distributions or shares, and "
                "gap_cv is scale-free. 06c applies exactly this to the pcap's flow CSV.")
    failures = []
    for tg in targets:
        mac = tg["mac"]
        home = {"mac": mac, "device_name": tg["name"], "category": tg["category"], "vendor_family": ""}
        fp, counts = fingerprint(f5, mac, home, lock["min_flows"])
        z = scale(fp, lock)
        P = place(z, int(fp["usable_flows"]), lock)
        R = {"mode": mode, "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "device": {"mac": mac, "name": tg["name"],
                        "ips_in_map": sorted(mp.loc[mp["mac"] == mac, "ip"].unique().tolist())},
             "pcap": {"path": str(args.pcap), "sha256": pcap_sha},
             "behaviour_groups": {"path": str(BEHAVIOUR_GROUPS), "sha256": lock_sha,
                                  "version": lock["version"]},
             "flows": finfo, "check": chk, "map": minfo, "tag": tinfo, "normalisation": norm_txt,
             "counts": counts, "fingerprint": fp, "scaled": z, "placement": P, "context": ctx,
             "capture_segments": [(str(a), str(b), n) for a, b, n in segs]}
        extra = None
        if args.validate_device:
            lf, lc = locked_fp.loc[mac], locked_ci.loc[mac]
            feats = m05.FEATURES
            dr = {k: (abs(fp[k] - lf[k]) if pd.notna(fp[k]) and pd.notna(lf[k])
                      else (0.0 if pd.isna(fp[k]) and pd.isna(lf[k]) else math.inf)) for k in feats}
            dz = {k: (abs(z[k] - lc[k]) if pd.notna(z[k]) and pd.notna(lc[k])
                      else (0.0 if pd.isna(z[k]) and pd.isna(lc[k]) else math.inf)) for k in kept}
            ok_raw, ok_z = max(dr.values()) <= TOL, max(dz.values()) <= TOL
            ok_n = int(fp["usable_flows"]) == int(lf["usable_flows"])
            ok_g = P["decision"] == tg["locked_group"]
            R["validation"] = {"device": tg["name"], "usable_flows": f"{fp['usable_flows']} vs locked {lf['usable_flows']}",
                               "max_abs_diff_raw_15": f"{max(dr.values()):.2e}",
                               "max_abs_diff_scaled_14": f"{max(dz.values()):.2e}",
                               "decision": P["decision"], "locked_group": tg["locked_group"],
                               "PASS": ok_raw and ok_z and ok_n and ok_g}
            if not R["validation"]["PASS"]:
                failures.append(tg["name"])
                R["validation"]["diffs"] = {k: v for k, v in {**dr, **dz}.items() if v > TOL}
            extra = {"locked_raw": {k: lf[k] for k in kept}, "locked_scaled": {k: lc[k] for k in kept}}
        else:
            big = max(segs, key=lambda s: s[2]) if segs else None
            if big is not None and len(segs) > 1:
                sfp, scount = fingerprint(f5, mac, home, lock["min_flows"], (big[0], big[1]))
                sz = scale(sfp, lock)
                R["sensitivity"] = {"window": (str(big[0]), str(big[1])), "fingerprint": sfp,
                                    "counts": scount, "scaled": sz,
                                    "placement": place(sz, int(sfp["usable_flows"]), lock)}
                extra = {"raw_segment": sfp, "scaled_segment": sz}
        R["feature_table"] = feature_rows(fp, z, kept, extra)
        if args.apply:
            note = (f"placed by 06c from {args.pcap.name} ({args.source_label}); "
                    f"{fp['usable_flows']} usable flows; {P['reason']}; d(G1)={P['distance']['G1']}, "
                    f"d(G2)={P['distance']['G2']}" + (f"; {args.note}" if args.note else ""))
            R["apply"] = apply_row(mac, tg["name"], P["decision"], args.source_label, lock, out, note)
            log(f"  {R['apply']}")
        label = (f"selftest_{tg['name'].replace(' ', '_')}" if args.validate_device
                 else f"{args.source_label}_{mac.replace(':', '')}")
        mpath, _ = write_report(out, label, R, lock)
        log(f"  {tg['name']}: {fp['usable_flows']} usable flows; d(G1)={P['distance']['G1']} "
            f"d(G2)={P['distance']['G2']} -> {P['decision']} ({P['reason']})"
            + (f"; self-test {'PASS' if R['validation']['PASS'] else 'FAIL'}" if args.validate_device else ""))
        log(f"  report: {mpath}")

    if sha256(BEHAVIOUR_GROUPS) != lock_sha:
        fatal("behaviour_groups.json changed during the run")
    log(f"runtime {time.monotonic() - t0:.1f} s")
    if failures:
        log(f"VALIDATION FAILED: {failures}")
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
