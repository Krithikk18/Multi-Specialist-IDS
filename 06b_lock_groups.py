#!/usr/bin/env python
"""06b_lock_groups.py -- lock the Step 6 behaviour groups (decisions made after review).

Inputs (never modified):
  fingerprints   results/step6/device_fingerprints.csv
  kept features  results/step6/kept_features.txt
  cluster input  results/step6/cluster_input.csv
  groups         results/step6/groups_k2.csv (primary), results/step6/groups_k4.csv (comparison)
  06 script      06_form_groups.py (imported: SAME scaler fit / apply code)

Outputs:
  config/device_table.csv                     behaviour_group (G1/G2/GEN, "" for non-smart-home)
                                              + behaviour_group_label, group_confidence, group_k4
  results/step6/device_table_before_lock.csv  backup of the table before this run
  config/behaviour_groups.json                lock record used to place NEW devices
  results/step6/figures/fig2_device_fingerprints.pdf/.png   regenerated on cluster-input scaling
  results/step6/lock_report.md

Decisions (fixed here, not derived):
  primary grouping = Ward k=2; G1 "high-activity multi-peer", G2 "low-activity simple"
  placement rule (min_flows gate -> nearest centroid -> max-spread check -> else GEN) is
  applied to every low-confidence device too, with no manual exceptions (all three -> GEN).
  Known devices keep their device_table group; the rule is for NEW devices only.
  Exit 0 iff: all low-confidence devices -> GEN by rule, and high-confidence devices reproduce
  groups_k2 except exactly the EXPECTED_BOUNDARY Ward boundary cases.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("form_groups", ROOT / "06_form_groups.py")
m06 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m06)
m05 = m06.m05
log, fatal, sha256, md_table = m06.log, m06.fatal, m06.sha256, m06.md_table
plt, Patch, ListedColormap = m06.plt, m06.Patch, m06.ListedColormap

VERSION = "1.0"
K = 2
LABELS = {"G1": "high-activity multi-peer", "G2": "low-activity simple",
          "GEN": "generalist fallback"}
EXPECTED_BOUNDARY = {"Philips Hue Bridge", "Yi Indoor 2 Camera"}
MIN_FLOWS = 100
NEW_COLS = ["behaviour_group_label", "group_confidence", "group_k4"]

S6 = ROOT / "results/step6"
P = {"fingerprints": S6 / "device_fingerprints.csv", "kept_features": S6 / "kept_features.txt",
     "cluster_input": S6 / "cluster_input.csv", "groups_k2": S6 / "groups_k2.csv",
     "groups_k4": S6 / "groups_k4.csv", "06_form_groups.py": ROOT / "06_form_groups.py",
     "05_profile_devices.py": ROOT / "05_profile_devices.py"}
TABLE = ROOT / "config/device_table.csv"
BACKUP = S6 / "device_table_before_lock.csv"
LOCK = ROOT / "config/behaviour_groups.json"
REPORT = S6 / "lock_report.md"
FIGDIR = S6 / "figures"


def place(z: np.ndarray, flows: int, cents: dict, max_spread: dict) -> tuple[str, str, dict, str]:
    """Placement rule: (1) usable flows < MIN_FLOWS -> GEN; (2) nearest centroid (NaN features
    skipped, distance rescaled by sqrt(d / observed), as in 06); (3) GEN if that distance >
    the group's max member spread; else the nearest group."""
    ok = ~np.isnan(z)
    ds = {g: float(np.linalg.norm(z[ok] - c[ok]) * np.sqrt(len(z) / ok.sum()))
          for g, c in cents.items()}
    g = min(ds, key=ds.get)
    if flows < MIN_FLOWS:
        return "GEN", g, ds, f"min_flows gate ({flows} < {MIN_FLOWS})"
    if ds[g] > max_spread[g]:
        return "GEN", g, ds, f"max-spread ({ds[g]:.3f} > {max_spread[g]:.3f})"
    return g, g, ds, "nearest centroid"


def fig2_fingerprints(ci: pd.DataFrame, kept: list[str], colors: dict) -> list[str]:
    """05's fig2 (same layout, rows by category) drawn on the cluster-input scaling."""
    d = ci[ci["usable_flows"] > 0].reset_index(drop=True)
    nr, nc = len(d), len(kept)
    fig = plt.figure(figsize=(1.9 + 0.42 * nc + 1.2, 0.8 + 0.165 * nr))
    gs = fig.add_gridspec(1, 3, width_ratios=[0.035 * nc, nc, 0.06 * nc], wspace=0.03)
    axc, ax, axb = fig.add_subplot(gs[0]), fig.add_subplot(gs[1]), fig.add_subplot(gs[2])
    m = np.clip(d[kept].to_numpy(dtype=float), -m06.CLIP, m06.CLIP)
    cmap = plt.get_cmap("RdBu_r").copy()
    cmap.set_bad("#d9d9d9")
    im = ax.imshow(np.ma.masked_invalid(m), cmap=cmap, vmin=-m06.CLIP, vmax=m06.CLIP,
                   aspect="auto", interpolation="nearest")
    cats = list(dict.fromkeys(d["category"]))
    cidx = d["category"].map({c: i for i, c in enumerate(cats)}).to_numpy()[:, None]
    axc.imshow(cidx, cmap=ListedColormap([colors[c] for c in cats]), aspect="auto",
               vmin=-0.5, vmax=len(cats) - 0.5, interpolation="nearest")
    axc.set_xticks([])
    low = (d["confidence"] == "low").to_numpy()
    ylabels = [f"{n} †" if lo else n for n, lo in zip(d["device_name"], low)]
    axc.set_yticks(range(nr), ylabels, fontsize=8)
    for tl, lo in zip(axc.get_yticklabels(), low):
        if lo:
            tl.set_color("#777777")
            tl.set_fontstyle("italic")
    for i in np.where(low)[0]:
        ax.add_patch(plt.Rectangle((-0.5, i - 0.5), nc, 1, fill=False, hatch="////",
                                   edgecolor="#555555", linewidth=0, alpha=0.5))
    ax.set_yticks([])
    ax.set_xticks(range(nc), [m05.LABEL[k] for k in kept], rotation=55, ha="right",
                  rotation_mode="anchor")
    for b in np.where(d["category"].to_numpy()[1:] != d["category"].to_numpy()[:-1])[0]:
        for a in (ax, axc):
            a.axhline(b + 0.5, color="white", lw=1.2)
    for a in (ax, axc):
        a.tick_params(length=0)
        for s in a.spines.values():
            s.set_visible(False)
    cb = fig.colorbar(im, cax=axb, extend="both")
    cb.set_label(f"cluster-input z (robust, clipped ±{m06.CLIP:g})")
    hs = m05.cat_handles(colors, cats) + [
        Patch(facecolor="white", edgecolor="#555555", hatch="////", label="† low confidence"),
        Patch(facecolor="#d9d9d9", edgecolor="none", label="undefined (NaN)")]
    leg = ax.legend(handles=hs, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=3,
                    frameon=False)
    return m05.save(fig, FIGDIR, "fig2_device_fingerprints", [leg])


def main() -> None:
    for p in [*P.values(), TABLE]:
        if not p.is_file():
            fatal(f"missing input {p}")
    shas = {k: sha256(p) for k, p in P.items()}

    fp = pd.read_csv(P["fingerprints"])
    fp["vendor_family"] = fp["vendor_family"].fillna("")
    kept = [l.strip() for l in P["kept_features"].read_text(encoding="utf-8").splitlines()
            if l.strip()]
    ci = pd.read_csv(P["cluster_input"])
    g2 = pd.read_csv(P["groups_k2"])
    g4 = pd.read_csv(P["groups_k4"])
    checks = {}

    # ---- scaler (06's code, fit on high-confidence devices) and its agreement with cluster_input
    hi_mask = fp["confidence"] == "high"
    params = m06.fit_scaler(fp[hi_mask], kept)
    Z = m06.apply_scaler(fp, params)[kept]
    diff = np.nanmax(np.abs(Z.to_numpy() - ci[kept].to_numpy()))
    checks["scaler_reproduces_cluster_input (max abs diff <= 1e-6)"] = bool(
        diff <= 1e-6 and (fp["mac"] == ci["mac"]).all()
        and (Z.isna().to_numpy() == ci[kept].isna().to_numpy()).all())
    z_by_mac = dict(zip(fp["mac"], Z.to_numpy(dtype=float)))

    # ---- centroids + spread from high-confidence members of groups_k2
    hi2 = g2[g2["confidence"] == "high"]
    if set(hi2["mac"]) != set(fp.loc[hi_mask, "mac"]):
        fatal("groups_k2 high-confidence members do not match fingerprints")
    groups = [f"G{i}" for i in range(1, K + 1)]
    cents = {g: np.mean([z_by_mac[m] for m in hi2.loc[hi2["group"] == g, "mac"]], axis=0)
             for g in groups}
    dist = {m: float(np.linalg.norm(z_by_mac[m] - cents[g]))
            for m, g in zip(hi2["mac"], hi2["group"])}
    spread = {g: [dist[m] for m in hi2.loc[hi2["group"] == g, "mac"]] for g in groups}
    med_spread = {g: float(np.median(v)) for g, v in spread.items()}
    max_spread = {g: float(np.max(v)) for g, v in spread.items()}
    checks["member distances match groups_k2.distance_to_centroid (1e-4)"] = bool(all(
        abs(dist[m] - d) <= 1e-4 for m, d in zip(hi2["mac"], hi2["distance_to_centroid"])))

    # ---- verification: re-place every high-confidence device + the low-confidence ones
    flows_by_mac = dict(zip(fp["mac"], fp["usable_flows"].astype(int)))
    rows = []
    for _, r in g2.iterrows():
        rule, nearest, ds, why = place(z_by_mac[r["mac"]], flows_by_mac[r["mac"]], cents,
                                       max_spread)
        rows.append({"device": r["device"], "confidence": r["confidence"],
                     "usable_flows": flows_by_mac[r["mac"]], "groups_k2": r["group"],
                     "rule_result": rule, "rule_step": why, "nearest": nearest,
                     **{f"d_{g}": round(ds[g], 4) for g in groups},
                     "d_over_median_spread": round(ds[nearest] / med_spread[nearest], 2)})
    ver = pd.DataFrame(rows)
    vh, vl = ver[ver["confidence"] == "high"], ver[ver["confidence"] != "high"]
    n_repro = int((vh["rule_result"] == vh["groups_k2"]).sum())
    boundary = vh[vh["rule_result"] != vh["groups_k2"]]
    checks[f"all {len(vl)} low-confidence devices -> GEN by rule "
           f"({', '.join(f'{d}: {s}' for d, s in zip(vl['device'], vl['rule_step']))})"] = bool(
        (vl["rule_result"] == "GEN").all())
    checks[f"high-confidence reproduce groups_k2 {n_repro}/{len(vh)}; mismatches exactly the "
           f"Ward boundary cases {sorted(EXPECTED_BOUNDARY)}"] = (
        set(boundary["device"]) == EXPECTED_BOUNDARY)

    # ---- final membership: high-confidence = groups_k2; low-confidence = rule result (GEN)
    rule_by_mac = dict(zip(g2["mac"], ver["rule_result"]))
    conf = dict(zip(g2["mac"], np.where(g2["confidence"] == "high", "high", "low")))
    k2 = {m: (g if conf[m] == "high" else rule_by_mac[m]) for m, g in zip(g2["mac"], g2["group"])}
    k4 = {m: (g if conf[m] == "high" else rule_by_mac[m]) for m, g in zip(g4["mac"], g4["group"])}
    name = dict(zip(g2["mac"], g2["device"]))
    if set(k4) != set(k2):
        fatal("groups_k2 and groups_k4 cover different devices")

    # ---- device table
    if not BACKUP.exists():  # a rerun must never overwrite the pre-lock backup
        shutil.copy2(TABLE, BACKUP)
    before = pd.read_csv(BACKUP, dtype=str, keep_default_na=False)
    if any(c in before.columns for c in NEW_COLS):
        fatal(f"{BACKUP} is not a pre-lock table")
    dt_ = before.copy()
    iot = dt_["role"] == m05.SMART_HOME_ROLE
    if set(dt_.loc[iot, "mac"]) != set(k2) or iot.sum() != 55:
        fatal(f"smart-home rows ({iot.sum()}) do not match the 55 grouped devices")
    dt_["behaviour_group"] = np.where(iot, dt_["mac"].map(k2), "")
    dt_["behaviour_group_label"] = np.where(iot, dt_["behaviour_group"].map(LABELS), "")
    dt_["group_confidence"] = np.where(iot, dt_["mac"].map(conf), "")
    dt_["group_k4"] = np.where(iot, dt_["mac"].map(k4), "")
    dt_ = dt_.fillna("")
    dt_.to_csv(TABLE, index=False, lineterminator="\n")
    after = pd.read_csv(TABLE, dtype=str, keep_default_na=False)
    changed = {c: int((before[c] != after[c]).sum()) for c in before.columns}
    diff_summary = {"rows_before": len(before), "rows_after": len(after),
                    "columns_added": [c for c in after.columns if c not in before.columns],
                    "columns_removed": [c for c in before.columns if c not in after.columns],
                    "cells_changed_per_column": {c: n for c, n in changed.items() if n},
                    "behaviour_group_transitions": (
                        before["behaviour_group"].str.cat(after["behaviour_group"], sep=" -> ")
                        .value_counts().to_dict())}
    checks["device_table: only behaviour_group changed + 3 columns added"] = (
        list(diff_summary["cells_changed_per_column"]) == ["behaviour_group"]
        and diff_summary["columns_added"] == NEW_COLS and not diff_summary["columns_removed"]
        and len(before) == len(after))

    # ---- lock record
    lock = {
        "version": VERSION, "date": dt.date.today().isoformat(),
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "method": {"linkage": "Ward", "metric": "Euclidean",
                   "fit_on": "high-confidence devices only"},
        "k": K,
        "labels": LABELS,
        "kept_features": kept,
        "scaler": {k: {"median": p["median"], "scale": p["scale"],
                       "scale_type": p["scale_type"], "clip": m06.CLIP} for k, p in params.items()},
        "scaler_formula": "z = clip((x - median) / scale, -clip, +clip), per feature in "
                          "kept_features order; x computed with 05_profile_devices.py",
        "centroids_scaled": {g: [round(float(v), 6) for v in c] for g, c in cents.items()},
        "spread": {g: {"median_member_distance": round(med_spread[g], 6),
                       "max_member_distance": round(max_spread[g], 6),
                       "n_members": len(spread[g])} for g in groups},
        "known_devices": "Devices already in config/device_table.csv use their behaviour_group "
                         "from that table (never re-placed). The placement_rule applies to NEW "
                         "devices only.",
        "placement_rule": {
            "applies_to": "NEW devices only",
            "text": "min_flows gate -> nearest centroid -> max-spread check -> else GEN",
            "steps": [
                f"1. usable flows < min_flows ({MIN_FLOWS}) -> GEN (re-place once the device "
                "reaches min_flows)",
                "2. scale the kept features with `scaler` and find the nearest centroid",
                "3. distance > spread[nearest].max_member_distance (strictly greater) -> GEN",
                "4. else -> the nearest group"],
            "distance": "Euclidean in scaled space; NaN features skipped and the distance "
                        "multiplied by sqrt(n_features / n_observed)",
            "fallback_group": "GEN"},
        "min_flows": MIN_FLOWS,
        "manual_assignments": {},
        "source_sha256": shas,
        "verification": {"checks": checks,
                         "placement": ver.to_dict("records")},
    }

    # ---- fig2 on the cluster-input scaling
    cats = [c for c in m05.CATEGORY_ORDER if c in set(fp["category"])]
    cats += sorted(set(fp["category"]) - set(cats))
    colors = {c: m05.OKABE_ITO[i % len(m05.OKABE_ITO)] for i, c in enumerate(cats)}
    m05.setup_style()
    fig2 = fig2_fingerprints(ci, kept, colors)

    for k, p in P.items():
        checks[f"{k} unchanged"] = sha256(p) == shas[k]
    allpass = all(checks.values())
    lock["verification"]["pass"] = allpass
    LOCK.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # ---- report
    mem = pd.DataFrame({"device": [name[m] for m in k2], "mac": list(k2)})
    mem["category"] = mem["mac"].map(dict(zip(fp["mac"], fp["category"])))
    mem["group"] = mem["mac"].map(k2)
    mem["label"] = mem["group"].map(LABELS)
    mem["confidence"] = mem["mac"].map(conf)
    mem["group_k4"] = mem["mac"].map(k4)
    mem["usable_flows"] = mem["mac"].map(dict(zip(fp["mac"], fp["usable_flows"])))
    mem = mem.sort_values(["group", "category", "device"]).reset_index(drop=True)
    gsum = (mem.groupby("group").agg(devices=("device", "size"),
                                     high_conf=("confidence", lambda s: int((s == "high").sum())),
                                     low_conf=("confidence", lambda s: int((s == "low").sum())),
                                     usable_flows=("usable_flows", "sum"))
            .reset_index())
    gsum.insert(1, "label", gsum["group"].map(LABELS))

    L = ["# Step 6c -- behaviour groups LOCKED", "",
         f"- **version**: {VERSION} ({lock['date']})",
         f"- **primary grouping**: Ward (Euclidean), k = {K}, from `groups_k2.csv`; "
         "k = 4 kept as `group_k4` for comparison; `paper_category` is the category baseline",
         "- **lock record**: `config/behaviour_groups.json`",
         "- **device table**: `config/device_table.csv` (backup: "
         "`results/step6/device_table_before_lock.csv`)", "",
         f"## Verification: **{'PASS' if allpass else 'FAIL'}**", ""]
    L += [f"- {'PASS' if v else 'FAIL'} -- {k}" for k, v in checks.items()]
    L += ["", "### Placement rule (NEW devices only) re-applied to every known device", "",
          "Known devices keep their device_table group; this re-application only checks the "
          f"rule. Rule: usable flows < {MIN_FLOWS} -> GEN; else nearest centroid; GEN if "
          "distance > that group's max member distance "
          f"(G1 max {max_spread['G1']:.3f}, G2 max {max_spread['G2']:.3f}; medians "
          f"G1 {med_spread['G1']:.3f}, G2 {med_spread['G2']:.3f}).", "",
          "**Low-confidence devices (all GEN by rule):**", ""]
    L += md_table(vl.to_dict("records"), list(ver.columns))
    L += ["", f"**Ward boundary cases ({len(boundary)} of {len(vh)} high-confidence):** Ward "
          "joins clusters by minimum variance increase, not by nearest centroid, so these "
          "G1 members sit closer to the G2 centroid. They keep their Ward group (G1) in the "
          "device table; a NEW device with the same fingerprint would be placed in G2.", ""]
    L += md_table(boundary.to_dict("records"), list(ver.columns))
    L += ["", "(Full per-device table in `config/behaviour_groups.json` -> "
          "verification.placement.)", "", "## Group counts", ""]
    L += md_table(gsum.to_dict("records"), list(gsum.columns))
    L += ["", f"Total: {int(gsum['devices'].sum())} devices, "
          f"{int(gsum['usable_flows'].sum()):,} usable flows.", "",
          "## Device table diff (vs backup)", ""]
    L += [f"- rows: {diff_summary['rows_before']} -> {diff_summary['rows_after']}",
          f"- columns added: {diff_summary['columns_added']}",
          f"- columns removed: {diff_summary['columns_removed']}",
          f"- cells changed: {diff_summary['cells_changed_per_column']}",
          "- behaviour_group transitions: " + "; ".join(
              f"`{k}` x{v}" for k, v in diff_summary["behaviour_group_transitions"].items()),
          "", "## Figure change", "",
          "- **fig2_device_fingerprints** regenerated (" + ", ".join(Path(f).name for f in fig2)
          + "): now drawn on the cluster-input scaling (robust median/IQR, p95-p5 fallback "
          f"where IQR < 0.1 x (p95-p5), clipped ±{m06.CLIP:g}; identical to `cluster_input.csv`"
          " and Fig. 7). The previous fig2 used IQR-only scaling (unit fallback), so features "
          "with a near-zero IQR were not comparable with Fig. 7. Layout and row order "
          "(by category) are unchanged.", "",
          "## Final group membership", ""]
    L += md_table(mem.drop(columns=["mac"]).to_dict("records"),
                  ["device", "category", "group", "label", "confidence", "group_k4",
                   "usable_flows"])
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")

    log("table diff: " + json.dumps(diff_summary))
    for _, r in gsum.iterrows():
        log(f"{r['group']} ({r['label']}): {r['devices']} devices "
            f"({r['high_conf']} high, {r['low_conf']} low), {r['usable_flows']:,} usable flows")
    for k, v in checks.items():
        log(f"{'PASS' if v else 'FAIL'}  {k}")
    log(f"VERIFICATION: {'PASS' if allpass else 'FAIL'}")
    if not allpass:
        sys.exit(1)


if __name__ == "__main__":
    main()
