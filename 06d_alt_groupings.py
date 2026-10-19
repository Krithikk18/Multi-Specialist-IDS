#!/usr/bin/env python
"""06d_alt_groupings.py -- alternative device groupings for the Step 9 split-strategy comparison
(global / device category / behaviour clustering k = 2, 3, 4) and their train / val coverage.
No model training. config/behaviour_groups.json (v1.0) and every file verify_lock() checks are
read only; the run fails if any of them changes.

Inputs (read-only)
  config/device_table.csv                       device set, category, v1.0 groups
  config/behaviour_groups.json                  v1.0 lock (scaler, centroids, spread, source sha256)
  results/step6/device_fingerprints.csv, kept_features.txt, cluster_input.csv, groups_k{2,3,4}.csv
  results/step7/new_device/<06c report>.json    scaled fingerprint of the 06c-placed Amazon device
  results/step8/manifest_v1.json                08's active segments + cut points (FP/hour hours)
  ~/lgids_cache/datasets/v1/{train,val}.parquet metadata columns only; test.parquet is never opened
  05 / 06 / 06c / 08 scripts are imported, so scaling, Ward, placement and the hours rule are theirs.

Rules (CONFIG below)
  devices    device_table rows with include_in_grouping == "yes". Differences against the v1.0
             groups (device_table behaviour_group, and the 05 fingerprint set) are reported.
  GEN        usable benign flows < min_flows (100) -> GEN (scored by the global model), as in v1.0.
  behaviour  06's method on 05's fingerprints: robust scaler fit on the high-confidence devices
             (06.fit_scaler), clip +-3, Ward / Euclidean, groups numbered G1..Gk along the
             dendrogram leaves (06.relabel_by_leaf_order). Only k changes between k2 / k3 / k4.
             Known high-confidence devices keep their Ward group (as 06b did for v1.0).
             behaviour_k2 must reproduce v1.0 exactly (scaler, cluster input, memberships, centroids,
             spread, Amazon placement, the parquet group column); otherwise the run STOPS before
             writing anything and prints the differences.
  category   device_table paper_category as is (the table has no device_category column; 08 writes
             paper_category to the parquet as device_category). Categories with < 2 devices or no
             train attack rows are listed in summary.md, never merged here.
  global     every device -> GLOBAL.
  new device the 06c-placed Amazon device (1c:12:b0:9b:0c:ec, include_in_grouping "no") is placed in
             every non-global strategy with 06c's rule (06c.place: min_flows gate -> nearest centroid
             -> beyond that group's max member distance -> GEN) on that strategy's centroids (category:
             mean cluster-input z of each category's high-confidence members), flagged low_confidence.

Outputs
  config/groupings/<strategy>.json      device MAC -> group + version, method, k, inputs sha256,
                                        seed, created timestamp (MACs lowercase colon-separated, the
                                        device_table / 02 norm_mac format)
  results/step9/groupings/coverage.csv  per strategy x group: devices, train / val benign + rows per
                                        attack family, val active benign hours (08 rule), flags
  results/step9/groupings/summary.md    checks, coverage, category merge candidates, k3 / k4 vs v1.0
                                        crosstabs. Facts only, no recommendation.
  Flags: NO_ATTACK_<family> (0 train rows of the family), LOW_N_<family> (1..low_n-1 train rows),
  TINY_GROUP (< tiny_devices devices or < tiny_benign_train benign train rows).

Exit status: 0 ok, 1 bad input / check failed (k2 reproduction included), 2 unexpected exception.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from config.config import (BEHAVIOUR_GROUPS, CACHE_DIR, CONFIG_DIR, DEVICE_TABLE, EXTRACTOR, GROUPS,
                           IP_MAC_MAP, REPO_ROOT, RESULTS_DIR, LockError, verify_lock)

S6 = RESULTS_DIR / "step6"

# --------------------------------------------------------------------------- CONFIG

CONFIG = {
    "strategies": ["global", "category", "behaviour_k2", "behaviour_k3", "behaviour_k4"],
    "version": "alt-1",
    "base_lock_version": GROUPS.version,
    "seed": 42,                       # 06's seed (Ward itself is deterministic)
    "min_flows": 100,                 # GEN rule, = behaviour_groups.json min_flows
    "gen_label": "GEN",
    "global_label": "GLOBAL",
    "include_column": "include_in_grouping",
    "include_value": "yes",
    "category_column": "paper_category",
    "new_device_mac": "1c:12:b0:9b:0c:ec",
    "new_device_report": RESULTS_DIR / "step7" / "new_device" / "bruteforce_background_1c12b09b0cec.json",
    "low_n": 50,
    "tiny_devices": 2,
    "tiny_benign_train": 1000,
    "splits": ["train", "val"],       # test is never opened
    "datasets_dir": CACHE_DIR / "datasets" / "v1",
    "manifest": RESULTS_DIR / "step8" / "manifest_v1.json",
    "out_config": CONFIG_DIR / "groupings",
    "out_results": RESULTS_DIR / "step9" / "groupings",
    "tol": 1e-6,
}
INPUTS = {"device_table.csv": DEVICE_TABLE, "behaviour_groups.json": BEHAVIOUR_GROUPS,
          "fingerprints": S6 / "device_fingerprints.csv", "kept_features": S6 / "kept_features.txt",
          "cluster_input": S6 / "cluster_input.csv", "groups_k2": S6 / "groups_k2.csv",
          "groups_k3": S6 / "groups_k3.csv", "groups_k4": S6 / "groups_k4.csv",
          "05_profile_devices.py": REPO_ROOT / "05_profile_devices.py",
          "06_form_groups.py": REPO_ROOT / "06_form_groups.py",
          "06c_place_new_device.py": REPO_ROOT / "06c_place_new_device.py",
          "06c_report": CONFIG["new_device_report"], "manifest_v1.json": CONFIG["manifest"],
          "06d_alt_groupings.py": Path(__file__).resolve()}
# Files verify_lock() checks: never an output, and their sha256 must not change during the run.
PROTECTED = [EXTRACTOR.jar_path, EXTRACTOR.patch_path, EXTRACTOR.patch_sweeper_path, DEVICE_TABLE,
             IP_MAC_MAP, BEHAVIOUR_GROUPS]
META_COLS = ["y", "attack_family", "group", "device", "session", "start_ts"]


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m06 = _load("form_groups", "06_form_groups.py")
m06c = _load("place_new_device", "06c_place_new_device.py")
m08 = _load("build_datasets", "08_build_datasets.py")
m02 = m08.m02
log, fatal, md_table, norm_mac = m02.log, m02.fatal, m02.md_table, m02.norm_mac


def guard_read(path: Path) -> Path:
    """06d never opens the test split: every file read goes through here."""
    if "test" in str(path).lower():
        raise AssertionError(f"06d must not read {path} (path contains 'test')")
    return path


def sha256(path: Path) -> str:
    return m02.sha256(guard_read(path))


def read_json(path: Path) -> dict:
    return json.loads(guard_read(path).read_text(encoding="utf-8"))


def guard_write(path: Path) -> Path:
    if any(path.resolve() == p.resolve() for p in PROTECTED):
        raise AssertionError(f"refusing to write {path}: verify_lock() checks it")
    return path


# --------------------------------------------------------------------------- grouping

def centroids(Z: np.ndarray, labels: np.ndarray) -> tuple[dict, dict]:
    """Per group: mean of the members' z, and the members' distances to it (median / max / n)."""
    cents, spread = {}, {}
    for g in sorted(set(labels), key=str):
        m = labels == g
        c = Z[m].mean(axis=0)
        d = np.linalg.norm(Z[m] - c, axis=1)
        cents[g] = c
        spread[g] = {"median_member_distance": float(np.median(d)), "max_member_distance": float(d.max()),
                     "n_members": int(m.sum())}
    return cents, spread


def place_new(z: dict, flows: int, kept: list[str], cents: dict, spread: dict) -> dict:
    """06c's stored rule on this strategy's centroids."""
    lockish = {"kept_features": kept, "min_flows": CONFIG["min_flows"],
               "centroids_scaled": {g: [float(v) for v in c] for g, c in cents.items()}, "spread": spread}
    return m06c.place(z, flows, lockish)


def nearest_vs_ward(Z: np.ndarray, labels: np.ndarray, cents: dict) -> list[int]:
    """Indices of members whose nearest centroid is not their Ward group (06b's boundary cases)."""
    gs = list(cents)
    C = np.array([cents[g] for g in gs])
    near = np.array(gs, dtype=object)[np.argmin(np.linalg.norm(Z[:, None, :] - C[None], axis=2), axis=1)]
    return [int(i) for i in np.flatnonzero(near != labels)]


# --------------------------------------------------------------------------- coverage

def segments_and_cuts(M: dict) -> dict:
    out = {}
    for sess, c in M["session_cuts"].items():
        seg = np.array([[pd.Timestamp(a).timestamp(), pd.Timestamp(b).timestamp()]
                        for a, b in c["active_segments_utc"]], dtype=float)
        out[sess] = (seg, (c["boundaries_epoch"], c["splits"]))
    return out

def val_hours(SC: dict, benign: pd.DataFrame) -> float:
    """08's benign_hours rule (val) on the benign flow starts in `benign` (columns session, start_ts)."""
    tot = 0.0
    for sess, (seg, cuts) in SC.items():
        t = benign.loc[benign["session"] == sess, "start_ts"].to_numpy(dtype=float)
        tot += m08.benign_hours(seg, t, cuts)["val"]
    return tot


def coverage_rows(strategy: str, mapping: dict, info: dict, meta: dict, families: list[str], SC: dict,
                  name_of: dict) -> list[dict]:
    tr, va = meta["train"], meta["val"]
    both = pd.concat([tr, va], ignore_index=True)
    groups = sorted(set(mapping.values()), key=lambda g: (g == CONFIG["gen_label"], str(g)))
    rows = []
    for g in groups:
        macs = [m for m, x in mapping.items() if x == g]
        r = {"strategy": strategy, "group": g, "n_devices": len(macs),
             "n_low_confidence": sum(info[m]["confidence"] != "high" for m in macs),
             "scored_by": CONFIG["global_label"] if g == CONFIG["gen_label"] else g}
        for sp, d in (("train", tr), ("val", va)):
            dg = d[d["group_alt"] == g]
            r[f"{sp}_benign"] = int((dg["y"] == 0).sum())
            for f in families:
                r[f"{sp}_{f}"] = int(((dg["y"] == 1) & (dg["attack_family"] == f)).sum())
        r["val_active_benign_hours"] = round(val_hours(SC, both[(both["y"] == 0) & (both["group_alt"] == g)]), 6)
        r["val_active_benign_hours_valonly_starts"] = round(
            val_hours(SC, va[(va["y"] == 0) & (va["group_alt"] == g)]), 6)
        flags = [f"NO_ATTACK_{f}" for f in families if r[f"train_{f}"] == 0]
        flags += [f"LOW_N_{f}" for f in families if 0 < r[f"train_{f}"] < CONFIG["low_n"]]
        if r["n_devices"] < CONFIG["tiny_devices"] or r["train_benign"] < CONFIG["tiny_benign_train"]:
            flags.append("TINY_GROUP")
        r["flags"] = ";".join(flags)
        r["devices"] = "; ".join(sorted(name_of[m] for m in macs))
        rows.append(r)
    return rows


# --------------------------------------------------------------------------- main

def main() -> int:
    t0 = dt.datetime.now(dt.timezone.utc)
    try:
        lock_res = verify_lock(strict=True)
    except LockError as e:
        fatal(str(e))
    for p in INPUTS.values():
        if not guard_read(p).is_file():
            fatal(f"missing input {p}")
    prot0 = {str(p): sha256(p) for p in PROTECTED}
    shas = {k: sha256(p) for k, p in INPUTS.items()}
    lock = read_json(BEHAVIOUR_GROUPS)
    tol, gen, glob_ = CONFIG["tol"], CONFIG["gen_label"], CONFIG["global_label"]
    checks: dict[str, bool] = {}       # k2 reproduction: any False -> STOP
    diffs: dict[str, object] = {}
    xchecks: dict[str, bool] = {}      # other hard checks

    # ---- inputs are the ones v1.0 was locked from
    for k, s in lock["source_sha256"].items():
        name = k if k in shas else None
        if name:
            checks[f"input {k} sha256 == behaviour_groups.json source_sha256"] = shas[name] == s
            if shas[name] != s:
                diffs[f"sha256 {k}"] = {"now": shas[name], "lock": s}

    # ---- device set
    tab = pd.read_csv(guard_read(DEVICE_TABLE), dtype=str, keep_default_na=False)
    tab["mac"] = tab["mac"].map(norm_mac)
    inc = tab[tab[CONFIG["include_column"]] == CONFIG["include_value"]]
    v10 = tab[tab["behaviour_group"] != ""]
    fp = pd.read_csv(guard_read(INPUTS["fingerprints"]))
    fp["vendor_family"] = fp["vendor_family"].fillna("")
    fp["mac"] = fp["mac"].map(norm_mac)
    A, B, F = set(inc["mac"]), set(v10["mac"]), set(fp["mac"])
    name_of = dict(zip(tab["mac"], tab["device_name"]))
    nm = lambda s: sorted(f"{name_of.get(m, '?')} ({m})" for m in s)  # noqa: E731
    devset = {"include_yes": len(A), "v10_behaviour_group_set": len(B), "fingerprints_05": len(F),
              "v10_grouped_but_include_not_yes": nm(B - A), "include_yes_but_no_v10_group": nm(A - B),
              "fingerprinted_but_include_not_yes": nm(F - A), "include_yes_but_not_fingerprinted": nm(A - F),
              "role_iot_but_include_not_yes": nm(set(tab.loc[tab["role"] == "iot", "mac"]) - A),
              "include_yes_but_role_not_iot": nm(A - set(tab.loc[tab["role"] == "iot", "mac"]))}
    if A - F:
        fatal(f"include_in_grouping == yes devices without a 05 fingerprint: {nm(A - F)}")
    new_mac = CONFIG["new_device_mac"]
    if new_mac in A:
        fatal(f"{new_mac} has include_in_grouping == yes; this script expects it to be the 06c-placed device")
    if new_mac not in set(tab["mac"]):
        fatal(f"{new_mac} not in device_table")
    fp = fp[fp["mac"].isin(A)].reset_index(drop=True)
    kept = [l.strip() for l in guard_read(INPUTS["kept_features"]).read_text(encoding="utf-8").splitlines()
            if l.strip()]
    if kept != lock["kept_features"]:
        fatal("kept_features.txt != behaviour_groups.json kept_features")
    cat_of = dict(zip(tab["mac"], tab[CONFIG["category_column"]]))
    cat_mismatch = [f"{r.device_name}: 05 {r.category!r} vs table {cat_of[r.mac]!r}"
                    for r in fp.itertuples() if r.category != cat_of[r.mac]]
    hi_mask = (fp["usable_flows"] >= CONFIG["min_flows"]).to_numpy()
    xchecks["GEN rule (usable flows < min_flows) == 05 confidence 'low'"] = bool(
        (~hi_mask == (fp["confidence"] == "low").to_numpy()).all())
    xchecks["min_flows == behaviour_groups.json min_flows"] = CONFIG["min_flows"] == lock["min_flows"]

    # ---- scaler + cluster input (06's code)
    hi = fp[hi_mask].reset_index(drop=True)
    params = m06.fit_scaler(hi, kept)
    sdiff = {k: max(abs(params[k]["median"] - lock["scaler"][k]["median"]),
                    abs(params[k]["scale"] - lock["scaler"][k]["scale"])) for k in kept}
    stype = [k for k in kept if params[k]["scale_type"] != lock["scaler"][k]["scale_type"]]
    checks["scaler == behaviour_groups.json scaler (1e-9, same scale types)"] = max(sdiff.values()) <= 1e-9 \
        and not stype
    if not checks["scaler == behaviour_groups.json scaler (1e-9, same scale types)"]:
        diffs["scaler"] = {"max_abs_diff": sdiff, "scale_type_differs": stype}
    Zdf = m06.apply_scaler(fp, params)[kept]
    ci = pd.read_csv(guard_read(INPUTS["cluster_input"]))
    ci["mac"] = ci["mac"].map(norm_mac)
    ci = ci.set_index("mac").loc[fp["mac"]]
    zd = float(np.nanmax(np.abs(Zdf.to_numpy() - ci[kept].to_numpy())))
    checks["cluster input == results/step6/cluster_input.csv (1e-6, same NaN cells)"] = bool(
        zd <= tol and (Zdf.isna().to_numpy() == ci[kept].isna().to_numpy()).all())
    if not checks["cluster input == results/step6/cluster_input.csv (1e-6, same NaN cells)"]:
        diffs["cluster_input_max_abs_diff"] = zd
    Zall = Zdf.to_numpy(dtype=float)
    X = Zall[hi_mask]
    if np.isnan(X).any():
        fatal("NaN in high-confidence cluster input")
    hi_macs = fp.loc[hi_mask, "mac"].tolist()
    low_macs = fp.loc[~hi_mask, "mac"].tolist()
    flows_of = dict(zip(fp["mac"], fp["usable_flows"].astype(int)))

    # ---- the 06c device
    R = read_json(CONFIG["new_device_report"])
    if norm_mac(R["device"]["mac"]) != new_mac:
        fatal(f"{CONFIG['new_device_report'].name} is for {R['device']['mac']}, not {new_mac}")
    xchecks["06c report used this behaviour_groups.json (sha256)"] = \
        R["behaviour_groups"]["sha256"] == shas["behaviour_groups.json"]
    z_new = {k: float(R["scaled"][k]) if R["scaled"][k] is not None else float("nan") for k in kept}
    flows_new = int(R["fingerprint"]["usable_flows"])
    new_row = tab[tab["mac"] == new_mac].iloc[0]

    # ---- Ward (06's code) and the behaviour strategies
    Zl = m06.ward(X)
    leaves = m06.dendrogram(Zl, no_plot=True)["leaves"]
    tab_group = dict(zip(tab["mac"], tab["behaviour_group"]))
    tab_k4 = dict(zip(tab["mac"], tab["group_k4"]))
    S: dict[str, dict] = {}
    for strat in CONFIG["strategies"]:
        if not strat.startswith("behaviour_k"):
            continue
        k = int(strat.rsplit("k", 1)[1])
        lab = np.array([f"G{g}" for g in m06.relabel_by_leaf_order(m06.cut(Zl, k), leaves)], dtype=object)
        cents, spread = centroids(X, lab)
        mapping = {m: g for m, g in zip(hi_macs, lab)}
        mapping.update({m: gen for m in low_macs})
        P = place_new(z_new, flows_new, kept, cents, spread)
        mapping[new_mac] = P["decision"]
        bnd = nearest_vs_ward(X, lab, cents)
        S[strat] = {"k": k, "mapping": mapping, "cents": cents, "spread": spread, "placement": P,
                    "boundary": [name_of[hi_macs[i]] for i in bnd]}
        g6 = pd.read_csv(guard_read(INPUTS[f"groups_k{k}"])) if f"groups_k{k}" in INPUTS else None
        if g6 is not None:
            g6["mac"] = g6["mac"].map(norm_mac)
            g6h = dict(zip(g6.loc[g6["confidence"] == "high", "mac"], g6.loc[g6["confidence"] == "high", "group"]))
            ok = g6h == {m: mapping[m] for m in hi_macs}
            if k == 2:
                checks["k2 Ward memberships == results/step6/groups_k2.csv (high confidence)"] = ok
            else:
                xchecks[f"k{k} Ward memberships == results/step6/groups_k{k}.csv (high confidence)"] = ok
            if not ok:
                diffs[f"groups_k{k}"] = {name_of[m]: (g6h.get(m), mapping[m]) for m in hi_macs
                                         if g6h.get(m) != mapping[m]}
        if k == 4:
            ok = all(tab_k4[m] == mapping[m] for m in A)
            xchecks["k4 memberships == device_table group_k4 (include_in_grouping == yes)"] = ok
            if not ok:
                diffs["device_table group_k4"] = {name_of[m]: (tab_k4[m], mapping[m]) for m in A
                                                  if tab_k4[m] != mapping[m]}

    # ---- k2 == v1.0
    if "behaviour_k2" not in S:
        fatal("behaviour_k2 is the consistency check for the method and must be in CONFIG strategies")
    k2 = S["behaviour_k2"]
    mm = {name_of[m]: (tab_group[m], g) for m, g in k2["mapping"].items() if tab_group[m] != g}
    checks["k2 memberships == device_table behaviour_group (all 55 + the 06c device)"] = not mm
    if mm:
        diffs["memberships (device_table, k2)"] = mm
    cd = {g: float(np.max(np.abs(np.round(k2["cents"][g], 6) - np.array(lock["centroids_scaled"][g]))))
          for g in lock["centroids_scaled"]} if set(k2["cents"]) == set(lock["centroids_scaled"]) else None
    checks["k2 centroids == behaviour_groups.json centroids_scaled (1e-6)"] = cd is not None and \
        max(cd.values()) <= tol
    if not checks["k2 centroids == behaviour_groups.json centroids_scaled (1e-6)"]:
        diffs["centroids"] = cd
    sp_d = {g: {q: abs(k2["spread"][g][q] - lock["spread"][g][q]) for q in lock["spread"][g]}
            for g in lock["spread"] if g in k2["spread"]}
    checks["k2 spread (median / max member distance, n) == behaviour_groups.json spread (1e-6)"] = bool(
        set(sp_d) == set(lock["spread"]) and all(v <= tol for d in sp_d.values() for v in d.values()))
    if not checks["k2 spread (median / max member distance, n) == behaviour_groups.json spread (1e-6)"]:
        diffs["spread"] = sp_d
    Pk2 = k2["placement"]
    ok = (Pk2["decision"] == R["placement"]["decision"] == new_row["behaviour_group"]
          and all(abs(Pk2["distance"][g] - R["placement"]["distance"][g]) <= 1e-4 for g in R["placement"]["distance"]))
    checks["k2 06c placement of the Amazon device == 06c report + device_table (decision, distances 1e-4)"] = ok
    if not ok:
        diffs["06c placement"] = {"k2": Pk2, "report": R["placement"], "table": new_row["behaviour_group"]}
    if not all(checks.values()):
        log("\nk2 REPRODUCTION FAILED -- STOP (nothing written). Differences:")
        for k, v in checks.items():
            log(f"  {'PASS' if v else 'FAIL'}  {k}")
        log(json.dumps(diffs, indent=2, default=str))
        return 1
    log("k2 reproduces v1.0: " + "; ".join(k for k in checks))

    # ---- category + global
    cat_lab = np.array([cat_of[m] for m in hi_macs], dtype=object)
    ccents, cspread = centroids(X, cat_lab)
    cmap = {m: cat_of[m] for m in hi_macs}
    cmap.update({m: gen for m in low_macs})
    cP = place_new(z_new, flows_new, kept, ccents, cspread)
    cmap[new_mac] = cP["decision"]
    S["category"] = {"k": len(ccents), "mapping": cmap, "cents": ccents, "spread": cspread, "placement": cP,
                     "boundary": [name_of[hi_macs[i]] for i in nearest_vs_ward(X, cat_lab, ccents)]}
    S["global"] = {"k": 1, "mapping": {m: glob_ for m in [*A, new_mac]}, "placement": None}

    info = {m: {"device_name": name_of[m], "category": cat_of[m], "usable_flows_benign": flows_of.get(m),
                "confidence": "high" if m in set(hi_macs) else "low"} for m in [*A, new_mac]}
    info[new_mac]["usable_flows_06c"] = flows_new

    # ---- datasets (train / val only)
    meta = {}
    for sp in CONFIG["splits"]:
        assert sp != "test"
        d = pq.read_table(guard_read(CONFIG["datasets_dir"] / f"{sp}.parquet"), columns=META_COLS).to_pandas()
        d["attack_family"] = d["attack_family"].fillna("").astype(str)
        d["device"] = d["device"].fillna("").astype(str)
        d["session"] = d["session"].astype(str)
        meta[sp] = d
    iot = tab[tab["role"] == "iot"]
    if iot["device_name"].duplicated().any():
        fatal("duplicate smart-home device names in device_table")
    mac_by_name = dict(zip(iot["device_name"], iot["mac"]))
    for sp, d in meta.items():
        unk = sorted(set(d["device"]) - set(mac_by_name))
        if unk:
            fatal(f"{sp}.parquet devices not in device_table (role iot): {unk}")
        d["mac"] = d["device"].map(mac_by_name)
        out = sorted(set(d["mac"]) - set(info))
        if out:
            fatal(f"{sp}.parquet devices outside the grouped set: {nm(out)}")
        grp_ok = bool((d["group"].astype(str).to_numpy() == d["mac"].map(k2["mapping"]).to_numpy()).all())
        xchecks[f"{sp}.parquet group column == behaviour_k2 mapping (every row)"] = grp_ok
    M = read_json(CONFIG["manifest"])
    SC = segments_and_cuts(M)
    families = sorted({f for d in meta.values() for f in d.loc[d["y"] == 1, "attack_family"].unique()})
    attack_set = sorted({p["family"] for p in read_json(CONFIG_DIR / "attack_set.json")["pcaps"]})
    xchecks["attack families in train / val == attack_set.json"] = families == attack_set
    families = attack_set

    cov = []
    for strat in CONFIG["strategies"]:
        mapping = S[strat]["mapping"]
        for d in meta.values():
            d["group_alt"] = d["mac"].map(mapping)
            if d["group_alt"].isna().any():
                fatal(f"{strat}: unmapped rows")
        rows = coverage_rows(strat, mapping, info, meta, families, SC, name_of)
        for sp in CONFIG["splits"]:
            xchecks[f"{strat}: {sp} rows over groups == {sp}.parquet rows"] = \
                sum(r[f"{sp}_benign"] + sum(r[f"{sp}_{f}"] for f in families) for r in rows) == len(meta[sp])
        cov += rows
    man_val = float(M["benign_active_hours"]["per_split"]["val"])
    gh = [r for r in cov if r["strategy"] == "global"][0]["val_active_benign_hours"]
    xchecks[f"GLOBAL val active benign hours {gh:.4f} == manifest per_split.val {man_val:.4f} (1e-3)"] = \
        abs(gh - man_val) <= 1e-3
    cov_df = pd.DataFrame(cov)

    # ---- outputs
    if not all(xchecks.values()):
        for k, v in xchecks.items():
            log(f"  {'PASS' if v else 'FAIL'}  {k}")
        log(json.dumps(diffs, indent=2, default=str))
        fatal("a consistency check failed; nothing written")
    created = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    combined = hashlib.sha256("\n".join(f"{k} {v}" for k, v in sorted(shas.items())).encode()).hexdigest()
    method = {
        "global": {"rule": "every device -> GLOBAL"},
        "category": {"rule": f"device_table {CONFIG['category_column']} as is; usable benign flows < "
                             f"{CONFIG['min_flows']} -> GEN; categories are not merged",
                     "new_device": "06c rule on category centroids = mean cluster-input z of each category's "
                                   "high-confidence members (06 scaler, clip 3)"},
    }
    CONFIG["out_config"].mkdir(parents=True, exist_ok=True)
    CONFIG["out_results"].mkdir(parents=True, exist_ok=True)
    order = {m: i for i, m in enumerate(tab["mac"])}
    for strat in CONFIG["strategies"]:
        s = S[strat]
        mth = method.get(strat) or {
            "linkage": "Ward", "metric": "Euclidean", "fit_on": "high-confidence devices only",
            "features": "results/step6/kept_features.txt (14) of 05_profile_devices.py fingerprints",
            "scaler": "06_form_groups.fit_scaler (median / IQR, p95-p5 fallback), clip +-3 -- identical to "
                      "behaviour_groups.json scaler",
            "labels": "G1..Gk in order of first appearance along the dendrogram leaves (06)",
            "known_devices": "high-confidence devices keep their Ward group",
            "new_device": "06c rule on this k's centroids / max member distances"}
        mth = {**mth, "gen_rule": f"usable benign flows < {CONFIG['min_flows']} -> {gen} (scored by the "
                                  f"{glob_} model)" if strat != "global" else "n/a (all GLOBAL)"}
        mapping = dict(sorted(s["mapping"].items(), key=lambda kv: order[kv[0]]))
        J = {"strategy": strat, "version": CONFIG["version"],
             "derived_from": f"behaviour_groups.json v{lock['version']} (sha256 {shas['behaviour_groups.json']})",
             "method": mth, "k": s["k"], "seed": CONFIG["seed"], "created_utc": created,
             "inputs_sha256": combined, "inputs": {k: {"path": str(INPUTS[k]), "sha256": v} for k, v in shas.items()},
             "mac_format": "lowercase, colon-separated (device_table.csv / 02 norm_mac)",
             "groups": sorted(set(mapping.values()), key=str),
             "devices": mapping,
             "low_confidence": {m: {"device_name": name_of[m],
                                    "reason": ("06c-placed device (not in the benign capture); "
                                               f"{s['placement']['reason']}" if m == new_mac and s["placement"]
                                               else "06c-placed device" if m == new_mac
                                               else f"usable benign flows {flows_of[m]} < {CONFIG['min_flows']}")}
                                for m in mapping if info[m]["confidence"] != "high"},
             "device_info": {m: info[m] for m in mapping}}
        if s.get("cents") is not None:
            J["centroids_scaled"] = {g: [round(float(v), 6) for v in c] for g, c in s["cents"].items()}
            J["spread"] = {g: {q: (round(v, 6) if isinstance(v, float) else v) for q, v in d.items()}
                           for g, d in s["spread"].items()}
            J["new_device_placement"] = {"mac": new_mac, **s["placement"]}
        p = guard_write(CONFIG["out_config"] / f"{strat}.json")
        p.write_text(json.dumps(J, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    cov_df.to_csv(guard_write(CONFIG["out_results"] / "coverage.csv"), index=False, lineterminator="\n")

    # ---- summary.md
    fam_cols = [f"train_{f}" for f in families]
    L = ["# 06d -- alternative groupings: coverage (train / val only)", "",
         f"- run {created}; version {CONFIG['version']}; derived from behaviour_groups.json v{lock['version']}",
         f"- verify_lock(): {'OK' if lock_res['ok'] else 'FAILED'} at start and end; protected files unchanged",
         f"- inputs sha256 (combined) `{combined}`; datasets `{CONFIG['datasets_dir']}` train + val "
         "(test.parquet never opened)",
         f"- strategies: {', '.join(CONFIG['strategies'])}; groupings in `config/groupings/<strategy>.json`",
         "- facts only; no recommendation", "",
         "## Device set", "",
         f"Filter: device_table `{CONFIG['include_column']} == \"{CONFIG['include_value']}\"` -> {len(A)} devices. "
         f"v1.0 groups (device_table behaviour_group set): {len(B)} devices; 05 fingerprints: {len(F)}.", ""]
    L += [f"- **{k}**: {v if not isinstance(v, list) else ('; '.join(v) or 'none')}" for k, v in devset.items()]
    L += [f"- category column: `{CONFIG['category_column']}` (no `device_category` column in device_table; "
          "08 copies paper_category into the parquet's device_category)",
          f"- 05 category vs table {CONFIG['category_column']} mismatches: {'; '.join(cat_mismatch) or 'none'}",
          f"- GEN (usable benign flows < {CONFIG['min_flows']}): " + "; ".join(
              f"{name_of[m]} ({flows_of[m]})" for m in low_macs), ""]
    L += ["## k2 reproduction of v1.0: **PASS**", ""]
    L += [f"- PASS -- {k}" for k in checks]
    L += ["", "## Other checks: **PASS**", ""] + [f"- PASS -- {k}" for k in xchecks]
    L += ["", "## 06c-placed Amazon device (1c:12:b0:9b:0c:ec), per strategy", "",
          f"Scaled fingerprint from `{CONFIG['new_device_report'].relative_to(REPO_ROOT)}` ({flows_new} usable "
          f"flows); rule = 06c.place. device_table {CONFIG['category_column']}: "
          f"{new_row[CONFIG['category_column']]!r} (as-is it would be a 1-device category).", ""]
    prow = []
    for strat in CONFIG["strategies"]:
        P = S[strat]["placement"]
        if P is None:
            prow.append({"strategy": strat, "decision": glob_, "reason": "all devices GLOBAL"})
            continue
        near = P["nearest"]
        two = sorted(P["distance"], key=P["distance"].get)[:2]
        prow.append({"strategy": strat, "decision": P["decision"], "nearest": near,
                     "d_nearest": P["distance"][near], "max_spread_nearest":
                         round(S[strat]["spread"][near]["max_member_distance"], 4),
                     "ratio_to_max": P["ratio_to_max_spread"][near],
                     "second": two[1] if len(two) > 1 else "", "d_second": P["distance"][two[1]] if len(two) > 1 else "",
                     "reason": P["reason"]})
    L += md_table(prow, ["strategy", "decision", "nearest", "d_nearest", "max_spread_nearest", "ratio_to_max",
                         "second", "d_second", "reason"])
    L += ["", "## Coverage per strategy x group", "",
          "Rows are the v1.0 dataset rows regrouped. 08's caps were drawn per v1.0 cap key (train benign "
          "per device: unaffected by regrouping; attack per (v1.0 group, family, split): the alternative groups "
          "inherit that sample). Val hours: 08's benign_hours rule on the manifest's active segments / cut "
          "points and the group's benign flow starts in train + val (09's denominator); `valonly` uses val "
          "starts only. Flags: NO_ATTACK_<family> = 0 train rows; LOW_N_<family> = 1.."
          f"{CONFIG['low_n'] - 1} train rows; TINY_GROUP = < {CONFIG['tiny_devices']} devices or < "
          f"{CONFIG['tiny_benign_train']:,} benign train rows. GEN is scored by the GLOBAL model.", ""]
    ccols = ["group", "n_devices", "n_low_confidence", "train_benign", *fam_cols, "val_benign",
             *[f"val_{f}" for f in families], "val_active_benign_hours", "val_active_benign_hours_valonly_starts",
             "flags"]
    for strat in CONFIG["strategies"]:
        sub = cov_df[cov_df["strategy"] == strat].copy()
        for c in ("val_active_benign_hours", "val_active_benign_hours_valonly_starts"):
            sub[c] = sub[c].map(lambda v: f"{v:.4f}")
        L += [f"### {strat} (k = {S[strat]['k']})", ""]
        L += md_table([{k: (int(v) if isinstance(v, (np.integer,)) else v) for k, v in r.items()}
                       for r in sub.to_dict("records")], ccols)
        if strat.startswith("behaviour_k") and S[strat].get("boundary"):
            L += ["", f"High-confidence devices whose nearest centroid is not their own group (they keep their "
                      f"Ward group; 06b's boundary cases): {'; '.join(sorted(S[strat]['boundary']))}"]
        L += [""]
    hv = cov_df["val_active_benign_hours"]
    if hv.nunique() == 1:
        L += [f"Val active benign hours are {hv.iloc[0]:.4f} h for every group: 08's active segments are "
              "capture-level, and every group has >= 1 benign flow start in each segment that overlaps a val "
              "window.", ""]
    L += ["## Val coverage (facts; not flags)", "",
          "Families with val attack rows but 0 train rows in the group:", ""]
    vo = [{"strategy": r["strategy"], "group": r["group"], "family": f, "val_rows": int(r[f"val_{f}"])}
          for _, r in cov_df.iterrows() for f in families if r[f"train_{f}"] == 0 and r[f"val_{f}"] > 0]
    L += md_table(vo, ["strategy", "group", "family", "val_rows"])
    L += ["", "Groups with 0 val attack rows (any family):", ""]
    na = cov_df[cov_df[[f"val_{f}" for f in families]].sum(axis=1) == 0]
    L += md_table([{"strategy": r["strategy"], "group": r["group"], "val_benign": int(r["val_benign"]),
                    "train_attack": int(sum(r[c] for c in fam_cols))} for _, r in na.iterrows()],
                  ["strategy", "group", "val_benign", "train_attack"]) + [""]
    L += ["## Category: listed for your merge decision (nothing merged)", "",
          "Categories (excluding GEN) with < 2 devices or no train attack rows:", ""]
    cc = cov_df[(cov_df["strategy"] == "category") & (cov_df["group"] != gen)]
    lst = cc[(cc["n_devices"] < 2) | (cc[fam_cols].sum(axis=1) == 0)]
    L += md_table([{"category": r["group"], "n_devices": int(r["n_devices"]),
                    "train_attack_rows": int(sum(r[c] for c in fam_cols)), "train_benign": int(r["train_benign"]),
                    "devices": r["devices"]} for _, r in lst.iterrows()],
                  ["category", "n_devices", "train_attack_rows", "train_benign", "devices"])
    if new_row[CONFIG["category_column"]] not in set(cc["group"]):
        L += ["", f"`{new_row[CONFIG['category_column']]}` (the 06c device's table category) has no device in this "
                  f"strategy: the device is placed by the 06c rule ({S['category']['placement']['decision']})."]
    L += ["", "## behaviour_k3 / behaviour_k4 vs v1.0 (device_table behaviour_group)", ""]
    for strat in [s for s in CONFIG["strategies"] if s in ("behaviour_k3", "behaviour_k4")]:
        mp = S[strat]["mapping"]
        df = pd.DataFrame({"v1.0": [tab_group[m] for m in mp], strat: list(mp.values()),
                           "device": [name_of[m] + (" †" if info[m]["confidence"] != "high" else "") for m in mp]})
        ct = pd.crosstab(df["v1.0"], df[strat])
        L += [f"### {strat}", "", "Device counts (rows v1.0, columns new):", ""]
        L += md_table([{"v1.0": i, **{c: int(ct.at[i, c]) for c in ct.columns}} for i in ct.index],
                      ["v1.0", *ct.columns])
        L += ["", "Members per cell († = low confidence):", ""]
        cells = df.groupby(["v1.0", strat])["device"].apply(lambda s: "; ".join(sorted(s))).reset_index()
        L += md_table(cells.to_dict("records"), ["v1.0", strat, "device"]) + [""]

    # ---- final protection check
    if {str(p): sha256(p) for p in PROTECTED} != prot0:
        fatal("a file verify_lock() checks changed during the run")
    try:
        verify_lock(strict=True)
    except LockError as e:
        fatal(f"verify_lock failed after the run: {e}")
    if sha256(BEHAVIOUR_GROUPS) != shas["behaviour_groups.json"]:
        fatal("behaviour_groups.json changed during the run")
    (guard_write(CONFIG["out_results"] / "summary.md")).write_text("\n".join(L) + "\n", encoding="utf-8")
    log(f"wrote {len(CONFIG['strategies'])} groupings -> {CONFIG['out_config']}; coverage + summary -> "
        f"{CONFIG['out_results']}  ({(dt.datetime.now(dt.timezone.utc) - t0).total_seconds():.1f} s)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
