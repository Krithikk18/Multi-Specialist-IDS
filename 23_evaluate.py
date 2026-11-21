#!/usr/bin/env python
"""23_evaluate.py -- Phase 2 step 3: evaluate step 22's models on VAL only (docs/V2_PREREG_PHASE2.md section 4).

Entities
  systems  ROUTED (primary: each flow -> its group's specialist, fallback group -> GLOBAL), FLAT_GLOBAL,
           ROUTED_A1_<mode> (same routing, ablation class weights), ROUTED_A2 (fallback group -> GENSPEC),
           ROUTED_A3 (each flow -> its device category's model, else GLOBAL); scored on every val row
  models   every model id of the run on its own val set (same pooling rule as its training set)
Per entity, per subset ("all" + every group present in val), per seed: classification_metrics (P / R / F1, both
macro-F1s, weighted F1, MCC, balanced accuracy, confusion, OvR ROC- / PR-AUC, Clopper-Pearson recall CIs) and
false alarms / hour (benign predicted as any attack / benign val hours of that evaluation set, exact Poisson CI);
then mean +- 95 % t-CI over the seeds. Latency (single thread, "dev machine") and size per model id (seed 0).
Binary collapse P(attack) = 1 - P(benign) of ROUTED vs V1's frozen FINAL system (step 10 models, read-only,
sha256 == config/step10_prereg.json, V1's routing) on the same val rows.

Outputs
  ~/lgids_cache/v2/eval/<run_id>/  metrics_per_seed.json, metrics_summary.json, run_manifest.json
  results/23/  run_meta.json, run.log, summary.md, metrics_summary.json, run_manifest.json, figures/*.png
  --dry-run --train-run <dry 22 run id>: the dry-run val sample, eval_dry_run/<run_id>/, results/23/dry_run/<run_id>/
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import traceback
from pathlib import Path

import numpy as np

from common import phase2_data as D
from common import phase2_metrics as PM
from common import phase2_run as R
from common import plot_style as PS
from common import schemas as S
from common import amendment as A
from common.phase2_config import config_from_arg, expand

SCRIPT = "23_evaluate.py"
SCALARS = ["macro_f1_all", "macro_f1_nonrare", "weighted_f1", "mcc", "balanced_accuracy", "fa_per_hour"]
PERCLASS = ["precision", "recall", "f1", "roc_auc", "pr_auc"]


# --------------------------------------------------------------------------- systems
def build_systems(M22: dict, cfg: dict) -> dict:
    """name -> {"kind": "group" | "category" | "all", "map": {key: model_id}, "default": model_id, "note"}."""
    prim = M22["routing"]["primary"]
    default = M22["routing"]["default"]
    ids = {m["model_id"] for m in M22["models"]}
    fb = cfg["fallback_group"]
    out = {"ROUTED": {"kind": "group", "map": dict(prim), "default": default, "note": "primary"},
           "FLAT_GLOBAL": {"kind": "all", "map": {}, "default": default, "note": "flat multiclass baseline"}}
    primary_w = cfg["class_weights"]["primary"]
    for m in cfg["class_weights"]["ablation_modes"]:
        sw = lambda mid: mid.rsplit("__", 1)[0] + f"__{m}"  # noqa: E731
        mp = {g: sw(v) for g, v in prim.items()}
        if all(v in ids for v in mp.values()) and sw(default) in ids:
            out[f"ROUTED_A1_{m}"] = {"kind": "group", "map": mp, "default": sw(default), "note": f"A1 weights {m}"}
    gen = [s["model_id"] for s in M22["specs"] if s["config"] == "A2"]
    if gen:
        out["ROUTED_A2"] = {"kind": "group", "map": {**prim, fb: gen[0]}, "default": default,
                            "note": f"A2: {fb} -> {gen[0]}"}
    a3 = (M22.get("spec_info") or {}).get("a3") or {}
    if a3.get("category_models"):
        out["ROUTED_A3"] = {"kind": "category", "map": dict(a3["category_models"]), "default": default,
                            "note": "A3: device category -> category model, else GLOBAL"}
    for s in out.values():
        assert all(v.endswith(f"__{primary_w}") or "A1" in s["note"] for v in [s["default"], *s["map"].values()])
    return out


def route(system: dict, group: np.ndarray, category: np.ndarray | None) -> np.ndarray:
    """Model id per row (object array)."""
    if system["kind"] == "all":
        return np.full(len(group), system["default"], dtype=object)
    keys = group if system["kind"] == "group" else category
    return np.array([system["map"].get(str(k), system["default"]) for k in keys], dtype=object)


def assemble(P_by_key: dict, model_per_row: np.ndarray, seed: int) -> np.ndarray:
    """Probabilities of a routed system for one seed from the per-model predictions on every val row."""
    first = P_by_key[f"{model_per_row[0]}__s{seed}"]
    P = np.empty_like(first)
    for mid in np.unique(model_per_row):
        m = model_per_row == mid
        P[m] = P_by_key[f"{mid}__s{seed}"][m]
    return P


# --------------------------------------------------------------------------- evaluation
def evaluate_entity(y, P_seeds: dict, rows_eval: np.ndarray, subsets: dict, hours_fn, K: int, cfg: dict) -> dict:
    """Per subset: per-seed metrics + aggregate. P_seeds: seed -> probabilities over every val row."""
    lvl, mv = cfg["eval"]["ci_level"], cfg["min_val_flows"]
    out = {}
    for sname, smask in subsets.items():
        rows = rows_eval & smask
        if not rows.any():
            continue
        hours = hours_fn(rows & (y == 0))
        per_seed = {}
        for seed, P in P_seeds.items():
            r = PM.classification_metrics(y[rows], P[rows], K, mv, lvl)
            fp = int(((y[rows] == 0) & (P[rows].argmax(1) != 0)).sum())
            lo, hi = PM.garwood(fp, lvl)
            r.update({"fa_count": fp, "benign_hours": hours,
                      "fa_per_hour": fp / hours if hours > 0 else float("nan"),
                      "fa_per_hour_ci": [lo / hours, hi / hours] if hours > 0 else [None, None]})
            per_seed[seed] = r
        agg = {k: PM.t_ci([per_seed[s][k] for s in per_seed], lvl) for k in SCALARS}
        for k in PERCLASS:
            agg[k] = [PM.t_ci([per_seed[s][k][c] for s in per_seed], lvl) for c in range(K)]
        cms = [np.asarray(per_seed[s]["confusion"], float) for s in per_seed]
        with np.errstate(invalid="ignore", divide="ignore"):
            agg["confusion_norm_mean"] = np.mean([c / c.sum(1, keepdims=True) for c in cms], axis=0).tolist()
        s0 = per_seed[min(per_seed)]
        agg.update({"n": s0["n"], "support": s0["support"], "rare_classes": s0["rare_classes"],
                    "benign_hours": hours, "seed0": {"fa_count": s0["fa_count"], "fa_per_hour": s0["fa_per_hour"],
                                                     "fa_per_hour_ci": s0["fa_per_hour_ci"], "recall_cp": s0["recall_cp"],
                                                     "recall": s0["recall"]},
                    "fa_counts_per_seed": [per_seed[s]["fa_count"] for s in sorted(per_seed)]})
        out[sname] = {"aggregate": agg, "per_seed": per_seed}
    return out


def latency(booster, X: np.ndarray, cfg: dict) -> dict:
    b = booster.copy()
    b.set_param({"nthread": 1})
    ev = cfg["eval"]
    n1 = min(ev["latency_batch1_repeats"], len(X))
    b.inplace_predict(X[:1])                                          # warm-up
    t1 = []
    for i in range(n1):
        t = time.perf_counter()
        b.inplace_predict(X[i:i + 1])
        t1.append(time.perf_counter() - t)
    nb = min(ev["latency_batch"], len(X))
    tb = []
    for _ in range(ev["latency_batch_repeats"]):
        t = time.perf_counter()
        b.inplace_predict(X[:nb])
        tb.append(time.perf_counter() - t)
    return {"ms_per_flow_batch1": float(np.median(t1) * 1e3), "ms_per_flow_batch": float(np.median(tb) * 1e3 / nb),
            "batch": nb, "threads": 1, "label": "dev machine (not the Pi)"}


def v1_compare(cfg: dict, X, y, group, hours_all: float, P_routed: dict, dry: bool, ctx, M) -> dict | None:
    """V1 FINAL (frozen step 10 binary models, read-only) vs V2 ROUTED binary collapse on the same val rows."""
    import joblib
    from sklearn.metrics import average_precision_score, roc_auc_score
    pre = json.loads(S.STEP10_PREREG_PATH.read_text(encoding="utf-8"))
    vdir = expand(cfg["paths"]["v1_models_dir"])
    models = {}
    for name, rec in pre["models"].items():
        p = vdir / Path(rec["path"]).name
        if not p.is_file() or R.sha256_path(p) != rec["sha256"]:
            ctx.log(f"  V1 model {name} missing or sha256 != step10_prereg: comparison skipped")
            M["warnings"].append(f"V1 comparison skipped: {p} missing or sha256 mismatch")
            return None
        models[name] = joblib.load(p)
    g2m = pre["routing"]["group_to_model"]
    s_v1 = np.empty(len(y))
    for g in np.unique(group):
        m = group == g
        s_v1[m] = models[g2m.get(str(g), "GLOBAL")].predict_proba(X[m])[:, 1]
    yb = y != 0
    max_fp = cfg["eval"]["fp_threshold_max_fp"]

    def stats_of(s):
        thr = PM.fp_threshold(s, ~yb, max_fp)
        return {"pr_auc": float(average_precision_score(yb, s)), "roc_auc": float(roc_auc_score(yb, s)),
                "dr_at_0.5": float((s[yb] >= 0.5).mean()), "fp_at_0.5": int((s[~yb] >= 0.5).sum()),
                "fa_per_hour_at_0.5": float((s[~yb] >= 0.5).sum() / hours_all),
                f"thr_le{max_fp}fp": thr, f"dr_at_le{max_fp}fp": float((s[yb] >= thr).mean()),
                f"fp_at_le{max_fp}fp": int((s[~yb] >= thr).sum())}
    v1 = stats_of(s_v1)
    t_house = pre["systems"]["FINAL"]["thresholds"]["T_house"]
    v1["fp_at_T_house"] = int((s_v1[~yb] >= t_house).sum())
    v1["dr_at_T_house"] = float((s_v1[yb] >= t_house).mean())
    if not dry:
        R.add_check(ctx, M, "V1 FINAL reproduces its prereg val false alarms at T_house (artifacts + routing sane)",
                    v1["fp_at_T_house"] == pre["systems"]["FINAL"]["val_fp_at_T_house"],
                    f"{v1['fp_at_T_house']} vs prereg {pre['systems']['FINAL']['val_fp_at_T_house']}")
    v2 = {s: stats_of(1.0 - P[:, 0]) for s, P in P_routed.items()}
    lvl = cfg["eval"]["ci_level"]
    agg = {k: PM.t_ci([v2[s][k] for s in v2], lvl) for k in v1 if k in v2[min(v2)]}
    return {"v1_FINAL": v1, "v2_ROUTED_per_seed": v2, "v2_ROUTED": agg, "hours": hours_all,
            "v1_models": {k: pre["models"][k]["sha256"] for k in models}, "t_house": t_house,
            "note": f"thresholds at <= {max_fp} val FP are chosen and read on val (same-set, optimistic), V1's rule"}


# --------------------------------------------------------------------------- figures
def _ci_err(a):
    m = np.array([x["mean"] for x in a], float)
    lo = np.array([x["lo"] for x in a], float)
    hi = np.array([x["hi"] for x in a], float)
    return m, np.vstack([np.nan_to_num(m - lo), np.nan_to_num(hi - m)])


def figures(fig_dir: Path, E: dict, systems: dict, names: list[str], groups: list[str], lat: dict, sizes: dict,
            v1: dict | None, P0: np.ndarray, y: np.ndarray, cfg: dict) -> list[str]:
    import matplotlib.pyplot as plt
    from matplotlib.colors import Normalize
    from sklearn.metrics import precision_recall_curve
    PS.apply()
    made, K = [], len(names)
    R_ = E["ROUTED"]
    # 1 normalised confusion per group (ROUTED, mean over seeds)
    subs = [s for s in ["all", *groups] if s in R_]
    fig, axes = plt.subplots(1, len(subs), figsize=(2.9 * len(subs) + 0.6, 3.1), squeeze=False)
    for ax, s in zip(axes[0], subs):
        cmn = np.array(R_[s]["aggregate"]["confusion_norm_mean"], float)
        ax.imshow(np.nan_to_num(cmn), cmap=PS.SEQUENTIAL_CMAP, norm=Normalize(0, 1))
        for i in range(K):
            for j in range(K):
                v = cmn[i, j]
                ax.text(j, i, "n/a" if np.isnan(v) else f"{v:.3f}", ha="center", va="center", fontsize=6.5,
                        color="#ffffff" if (not np.isnan(v) and v > 0.6) else PS.TEXT1)
        ax.set_xticks(range(K), names, rotation=40, ha="right", fontsize=7)
        ax.set_yticks(range(K), names if s == subs[0] else [""] * K, fontsize=7)
        ax.set_title(f"{s} (n={R_[s]['aggregate']['n']:,})", loc="left", fontsize=8.5)
        ax.tick_params(length=0)
        for sp in ax.spines.values():
            sp.set_visible(False)
    axes[0][0].set_ylabel("true class")
    fig.suptitle("ROUTED, row-normalised confusion (val, mean over seeds; rows = true, columns = predicted)",
                 x=0.01, ha="left", y=1.02)
    made.append(PS.save(fig, fig_dir / "confusion_per_group.png"))
    # 2 per-class P / R / F1 with t-CI
    A = R_["all"]["aggregate"]
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    x, w = np.arange(K), 0.26
    for k, (met, col) in enumerate([("precision", "#3a3936"), ("recall", PS.BENIGN_GRAY), ("f1", PS.NEUTRAL_LIGHT)]):
        m, err = _ci_err(A[met])
        ax.bar(x + (k - 1) * w, np.nan_to_num(m), w * 0.92, yerr=err, color=col, label=met, capsize=2,
               error_kw={"lw": 0.8, "ecolor": PS.TEXT1})
    lab = [f"{n}\n(rare, n={A['support'][c]})" if c in A["rare_classes"] else n for c, n in enumerate(names)]
    ax.set_xticks(x, lab, fontsize=8)
    ax.set_ylim(0, 1.08)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.2))
    ax.set_title("ROUTED per-class precision / recall / F1 (val, mean +- 95 % t-CI over seeds)", loc="left")
    made.append(PS.save(fig, fig_dir / "per_class_prf.png"))
    # 3 binary collapse vs V1
    if v1:
        mets = [("pr_auc", "PR-AUC"), ("roc_auc", "ROC-AUC"), ("dr_at_0.5", "detection rate @0.5"),
                ("fa_per_hour_at_0.5", "false alarms / h @0.5")]
        # dots + CI, not bars: these values sit next to 1.0, so a bar from 0 on a truncated axis would mislead
        fig, axes = plt.subplots(1, 4, figsize=(9.6, 2.9))
        for ax, (k, t) in zip(axes, mets):
            a = v1["v2_ROUTED"][k]
            v1v = v1["v1_FINAL"][k]
            ax.plot([0], [v1v], "D", color=PS.BENIGN_GRAY, ms=7)
            ax.errorbar([1], [a["mean"]], yerr=[[np.nan_to_num(a["mean"] - a["lo"])], [np.nan_to_num(a["hi"] - a["mean"])]],
                        fmt="o", color=PS.CATEGORICAL[0], ms=7, capsize=3)
            for xi, v in ((0, v1v), (1, a["mean"])):
                ax.annotate(f"{v:.5f}" if k != "fa_per_hour_at_0.5" else f"{v:.3f}", (xi, v), xytext=(9, 0),
                            textcoords="offset points", va="center", fontsize=7)
            ax.set_xlim(-0.5, 1.9)
            ax.set_xticks([0, 1], ["V1\nFINAL", "V2\nROUTED"], fontsize=7.5)
            ax.ticklabel_format(axis="y", useOffset=False, style="plain")
            ax.yaxis.grid(True)
            ax.set_title(t, loc="left", fontsize=8.5)
            vals = [v1v, a["mean"]] + [x for x in (a["lo"], a["hi"]) if np.isfinite(x)]
            lo, hi = min(vals), max(vals)
            pad = max((hi - lo) * 0.6, 1e-4 if k != "fa_per_hour_at_0.5" else 0.1)
            ax.set_ylim(max(0.0, lo - pad), hi + pad)
        fig.subplots_adjust(top=0.78, wspace=0.55)
        fig.suptitle("Binary collapse vs V1's frozen binary system (val; V2 = 1 - P(benign), mean +- t-CI over seeds)",
                     x=0.01, ha="left", y=0.99)
        made.append(PS.save(fig, fig_dir / "binary_collapse_vs_v1.png"))
    # 4 macro-F1 dot plot, every entity
    ents = list(systems) + sorted(k for k in E if k not in systems)
    fig, ax = plt.subplots(figsize=(6.4, 0.24 * len(ents) + 1.0))
    yy = np.arange(len(ents))[::-1]
    for which, mk, col in (("macro_f1_all", "o", PS.CATEGORICAL[0]), ("macro_f1_nonrare", "D", PS.BENIGN_GRAY)):
        m = np.array([E[e]["all"]["aggregate"][which]["mean"] for e in ents], float)
        lo = np.array([E[e]["all"]["aggregate"][which]["lo"] for e in ents], float)
        hi = np.array([E[e]["all"]["aggregate"][which]["hi"] for e in ents], float)
        ax.errorbar(m, yy, xerr=[np.nan_to_num(m - lo), np.nan_to_num(hi - m)], fmt=mk, ms=4.5, color=col,
                    ecolor=col, elinewidth=1, capsize=2, label=f"macro-F1 ({which.split('_')[-1]} classes)")
    ax.set_yticks(yy, [f"{e}  [system]" if e in systems else e for e in ents], fontsize=7)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_xlabel("macro-F1 on its val set (mean +- 95 % t-CI over seeds)")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.08 * 10 / max(10, len(ents)) - 0.04), ncol=2)
    ax.set_title("Macro-F1, every system / model / ablation (val)", loc="left")
    made.append(PS.save(fig, fig_dir / "macro_f1_dotplot.png"))
    # 5 false alarms / hour
    rows = list(systems) + [m for m in sorted(E) if m not in systems and "__" in m and m.split("__")[-1] in
                            (cfg["class_weights"]["primary"],)]
    fig, ax = plt.subplots(figsize=(6.4, 0.3 * len(rows) + 1.1))
    yy = np.arange(len(rows))[::-1]
    for yi, e in zip(yy, rows):
        a = E[e]["all"]["aggregate"]
        s0 = a["seed0"]
        lo, hi = s0["fa_per_hour_ci"]
        ax.errorbar([s0["fa_per_hour"]], [yi], xerr=[[s0["fa_per_hour"] - lo], [hi - s0["fa_per_hour"]]], fmt="o",
                    color=PS.CATEGORICAL[0], ms=5, capsize=2, elinewidth=1)
        others = [c / a["benign_hours"] for c in a["fa_counts_per_seed"][1:]] if a["benign_hours"] else []
        ax.plot(others, [yi] * len(others), "|", color=PS.TEXT2, ms=8)
        ax.annotate(f"{s0['fa_count']} FP / {a['benign_hours']:.2f} h", (hi, yi), xytext=(4, 0),
                    textcoords="offset points", va="center", fontsize=7)
    ax.set_yticks(yy, rows, fontsize=7.5)
    ax.set_xlabel("false alarms / hour (seed 0, exact Poisson 95 % CI; ticks = seeds 1-4)")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_xlim(left=0)
    ax.set_title("False alarms per benign val hour", loc="left")
    made.append(PS.save(fig, fig_dir / "false_alarms_per_hour.png"))
    # 6 OvR PR curves per class (ROUTED, seed 0)
    fig, axes = plt.subplots(1, K, figsize=(2.6 * K + 0.4, 2.7), squeeze=False)
    for c, ax in enumerate(axes[0]):
        pos = y == c
        if 0 < pos.sum() < len(y):
            p, r, _ = precision_recall_curve(pos, P0[:, c])
            ax.plot(r, p, color=PS.class_color(c), lw=2)
            ax.axhline(pos.mean(), color=PS.TEXT2, lw=0.8, ls=":")
            ap = R_["all"]["per_seed"][min(R_["all"]["per_seed"])]["pr_auc"][c]
            ax.set_title(f"{names[c]} (AP {ap:.4f}, n={int(pos.sum()):,})", loc="left", fontsize=8)
        else:
            ax.set_title(f"{names[c]} (no val flows)", loc="left", fontsize=8)
        ax.set_xlim(0, 1.01)
        ax.set_ylim(0, 1.02)
        ax.set_xlabel("recall")
        ax.grid(True)
    axes[0][0].set_ylabel("precision")
    fig.suptitle("One-vs-rest PR curves, ROUTED seed 0 (val; dotted = prevalence)", x=0.01, ha="left", y=1.03)
    made.append(PS.save(fig, fig_dir / "pr_curves_per_class.png"))
    # 7 macro-F1 vs ms / flow, point size = model size
    mids = sorted(lat)
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    sz = np.array([sizes[m] for m in mids], float)
    xs = np.array([lat[m]["ms_per_flow_batch1"] for m in mids])
    ys = np.array([E[m]["all"]["aggregate"]["macro_f1_all"]["mean"] for m in mids])
    cfg_of = {m: ("primary" if m.endswith("__" + cfg["class_weights"]["primary"]) and not m.startswith(("CAT_", "GENSPEC_"))
                  else "ablation") for m in mids}
    for kind, col in (("primary", PS.CATEGORICAL[0]), ("ablation", PS.NEUTRAL_LIGHT)):
        sel = np.array([cfg_of[m] == kind for m in mids])
        ax.scatter(xs[sel], ys[sel], s=20 + 180 * sz[sel] / sz.max(), color=col, edgecolor=PS.SURFACE, lw=1,
                   label=f"{kind} models", zorder=3)
    for m, xi, yi in zip(mids, xs, ys):
        if cfg_of[m] == "primary":
            ax.annotate(m.rsplit("__", 1)[0], (xi, yi), xytext=(5, 3), textcoords="offset points", fontsize=7)
    ax.set_xlabel("ms / flow at batch 1 (1 thread, dev machine, not the Pi)")
    ax.set_ylabel("macro-F1 (own val set, mean over seeds)")
    ax.grid(True)
    ax.legend(frameon=False, loc="lower right")
    ax.set_title("Macro-F1 vs latency (point area ~ model size on disk)", loc="left")
    made.append(PS.save(fig, fig_dir / "macro_f1_vs_latency.png"))
    return made


# --------------------------------------------------------------------------- summary
def _fmt(a, d=4):
    if a is None or not np.isfinite(a.get("mean", np.nan)):
        return "n/a"
    if not np.isfinite(a.get("lo", np.nan)):
        return f"{a['mean']:.{d}f}"
    return f"{a['mean']:.{d}f} [{a['lo']:.{d}f}, {a['hi']:.{d}f}]"


def primary_selection_section(ps: dict, E: dict, names: list[str], cfg: dict) -> list[str]:
    """Amendment 1 (docs/V2_PREREG_PHASE2_AMENDMENT_1.md section 2): the table that chose the primary weighting, then
    the chosen ROUTED / FLAT_GLOBAL headline on the full val split."""
    L = ["## Primary configuration chosen by Amendment 1 (section 2)", "",
         f"- rule: ROUTED non-rare macro-F1 (5-seed mean) within {ps['tolerance']} of the best -> fewest ROUTED false "
         f"alarms (5-seed mean) -> ties: first of {ps['tie_order']}", "",
         "| weighting | ROUTED system | non-rare macro-F1 mean [t-CI] | all-class macro-F1 mean | within tolerance | "
         "false alarms per seed | mean | FA / h mean |", "|---|---|---|---|---|---|---|---|"]
    for r in ps["table"]:
        ci = r["macro_f1_nonrare_ci"]
        L.append(f"| {r['mode']} | {r['routed_system']} | {r['macro_f1_nonrare_mean']:.5f} [{ci[0]:.5f}, {ci[1]:.5f}] | "
                 f"{r['macro_f1_all_mean']:.5f} | {'yes' if r['mode'] in ps['within_tolerance'] else 'no'} | "
                 f"{r['fa_counts_per_seed']} | {r['fa_count_mean']:.1f} | {r['fa_per_hour_mean']:.3f} |")
    L += ["", f"- best non-rare macro-F1 mean {ps['best_macro_f1_nonrare_mean']:.5f}; within tolerance "
          f"{ps['within_tolerance']}; fewest mean false alarms {ps['fewest_fa_count_mean']:.1f} -> {ps['tied_on_fa']}"
          + ("; tie broken by the order" if ps["tie_break_used"] else ""),
          f"- **chosen: `{ps['chosen']}`** -> primary system `{ps['chosen_routed_system']}`, flat baseline "
          f"`{ps['chosen_flat_system']}`; 24 / 25 / 26 use the `{ps['chosen_config_label']}` models", ""]
    for sname in (ps["chosen_routed_system"], ps["chosen_flat_system"]):
        if sname not in E:
            continue
        a = E[sname]["all"]["aggregate"]
        ci = a["seed0"]["fa_per_hour_ci"]
        L += [f"### {sname} (chosen weighting) on the full val split", "",
              f"- macro-F1 all **{_fmt(a['macro_f1_all'])}**, non-rare **{_fmt(a['macro_f1_nonrare'])}**; false alarms / h "
              f"over seeds {_fmt(a['fa_per_hour'], 3)}; seed 0 {a['seed0']['fa_per_hour']:.3f} ({a['seed0']['fa_count']} FP / "
              f"{a['benign_hours']:.3f} h; Poisson 95 % CI [{ci[0]:.3f}, {ci[1]:.3f}])", "",
              "| class | val flows | precision | recall | F1 |", "|---|---|---|---|---|"]
        for c, n in enumerate(names):
            rare = " (rare)" if c in a["rare_classes"] else ""
            L.append(f"| {n}{rare} | {a['support'][c]:,} | {_fmt(a['precision'][c])} | {_fmt(a['recall'][c])} | "
                     f"{_fmt(a['f1'][c])} |")
        L += [""]
    return L


def write_summary(path: Path, M: dict, E: dict, systems: dict, names: list[str], groups: list[str], lat: dict,
                  v1: dict | None, a2: dict | None, cfg: dict) -> None:
    L = [f"# Step 23 -- evaluation (VAL only) -- {M['status']}" + (" (DRY RUN)" if M["dry_run"] else ""), "",
         f"- run `{M['run_id']}`, models from step 22 run `{M.get('train_run')}`, dataset `{M['dataset_version']}`, "
         f"config `{M['config']['sha256'][:16]}...`, prereg `{M['prereg_phase2_sha256'][:16]}...`, seeds {M['seeds']}",
         f"- val rows {M.get('n_val', 0):,}; benign val hours (all benign val flows, 08 active-segment rule) "
         f"{M.get('hours_all', float('nan')):.4f} h (V1 manifest: 1.9676 h, from all flows of the files)",
         "- CIs: mean +- 95 % t-CI over the 5 seeds unless stated; false alarms / hour: seed 0 with an exact Poisson "
         "95 % CI; rare-class recall: Clopper-Pearson 95 % (seed 0).", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("primary_selection"):
        L += primary_selection_section(M["primary_selection"], E, names, cfg)
    if "ROUTED" in E:
        A = E["ROUTED"]["all"]["aggregate"]
        L += [("## ROUTED with the originally pre-registered weighting (sqrt) on the full val split; see the Amendment 1 "
               "section above for the chosen primary" if M.get("primary_selection")
               else "## Headline: ROUTED (primary) on the full val split"), "",
              f"- macro-F1 (all classes with val flows): **{_fmt(A['macro_f1_all'])}**",
              f"- macro-F1 (non-rare classes, >= {cfg['min_val_flows']} val flows): **{_fmt(A['macro_f1_nonrare'])}**",
              f"- weighted F1 {_fmt(A['weighted_f1'])}, MCC {_fmt(A['mcc'])}, balanced accuracy {_fmt(A['balanced_accuracy'])}",
              f"- false alarms / hour (seed 0): **{A['seed0']['fa_per_hour']:.3f}** ({A['seed0']['fa_count']} FP / "
              f"{A['benign_hours']:.3f} h; Poisson 95 % CI [{A['seed0']['fa_per_hour_ci'][0]:.3f}, "
              f"{A['seed0']['fa_per_hour_ci'][1]:.3f}]); over seeds {_fmt(A['fa_per_hour'], 3)}", "",
              "| class | val flows | precision | recall | F1 | recall CP 95 % (seed 0) | ROC-AUC | PR-AUC |",
              "|---|---|---|---|---|---|---|---|"]
        for c, n in enumerate(names):
            cp = A["seed0"]["recall_cp"][c]
            rare = " (rare)" if c in A["rare_classes"] else ""
            L.append(f"| {n}{rare} | {A['support'][c]:,} | {_fmt(A['precision'][c])} | {_fmt(A['recall'][c])} | "
                     f"{_fmt(A['f1'][c])} | " + (f"[{cp[0]:.4f}, {cp[1]:.4f}]" if cp[0] is not None else "n/a")
                     + f" | {_fmt(A['roc_auc'][c])} | {_fmt(A['pr_auc'][c])} |")
        L += ["", "### ROUTED per group of the flow", "",
              "| group | rows | macro-F1 all | macro-F1 non-rare | false alarms (seed 0) | FA / h (seed 0) |", "|---|---|---|---|---|---|"]
        for g in groups:
            if g in E["ROUTED"]:
                a = E["ROUTED"][g]["aggregate"]
                L.append(f"| {g} | {a['n']:,} | {_fmt(a['macro_f1_all'])} | {_fmt(a['macro_f1_nonrare'])} | "
                         f"{a['seed0']['fa_count']} | {a['seed0']['fa_per_hour']:.3f} |")
        L += ["", "## Systems and ablations (full val; " + ("A1 used to select the primary weighting under Amendment 1, "
              "the rest reported only)" if M.get("primary_selection") else "reported, never used to select)"), "",
              "| system | note | macro-F1 all | macro-F1 non-rare | MCC | FA count seed 0 | FA / h seed 0 [Poisson CI] |",
              "|---|---|---|---|---|---|---|"]
        for s, d in systems.items():
            a = E[s]["all"]["aggregate"]
            ci = a["seed0"]["fa_per_hour_ci"]
            L.append(f"| {s} | {d['note']} | {_fmt(a['macro_f1_all'])} | {_fmt(a['macro_f1_nonrare'])} | {_fmt(a['mcc'])} | "
                     f"{a['seed0']['fa_count']} | {a['seed0']['fa_per_hour']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}] |")
    if a2:
        L += ["", f"### A2: {cfg['fallback_group']} val benign false alarms (GLOBAL vs GEN specialist)", "",
              f"- {cfg['fallback_group']} val benign flows: {a2['n_benign']:,}; their benign hours {a2['hours']:.3f} h", "",
              "| model | FP per seed | mean FP | FA / h seed 0 [Poisson CI] |", "|---|---|---|---|"]
        for k, v in a2["models"].items():
            L.append(f"| {k} | {v['fp_per_seed']} | {np.mean(v['fp_per_seed']):.1f} | {v['fa_h_seed0']:.3f} "
                     f"[{v['ci'][0]:.3f}, {v['ci'][1]:.3f}] |")
    if v1:
        L += ["", "## Binary collapse vs V1 (frozen step 10 FINAL; same val rows; read-only)", "",
              f"- {v1['note']}; V1 at its prereg T_house {v1['t_house']:.6f}: {v1['v1_FINAL']['fp_at_T_house']} FP, "
              f"DR {v1['v1_FINAL']['dr_at_T_house']:.5f}", "", "| metric | V1 FINAL | V2 ROUTED (mean [t-CI]) |", "|---|---|---|"]
        for k, v in v1["v1_FINAL"].items():
            if k in v1["v2_ROUTED"]:
                L.append(f"| {k} | {v:.6g} | {_fmt(v1['v2_ROUTED'][k], 5)} |")
    if lat:
        L += ["", "## Cost per model (seed 0; 1 thread; dev machine, NOT the Pi)", "",
              "| model | ms / flow batch 1 | ms / flow batch 1024 | size on disk (bytes) |", "|---|---|---|---|"]
        for m in sorted(lat):
            L.append(f"| {m} | {lat[m]['ms_per_flow_batch1']:.4f} | {lat[m]['ms_per_flow_batch']:.5f} | {M['sizes'][m]:,} |")
    L += ["", "## Figures", "",
          "- `figures/confusion_per_group.png` -- ROUTED row-normalised confusion matrices, all val and per group of the flow (mean over seeds).",
          "- `figures/per_class_prf.png` -- ROUTED per-class precision / recall / F1 with 95 % t-CI error bars; rare classes marked.",
          "- `figures/binary_collapse_vs_v1.png` -- V2 ROUTED as a binary detector (1 - P(benign)) vs V1's frozen binary FINAL on the same val rows.",
          "- `figures/macro_f1_dotplot.png` -- both macro-F1s with t-CIs for every system, model and ablation, each on its own val set.",
          "- `figures/false_alarms_per_hour.png` -- benign val false alarms per hour, seed 0 with exact Poisson CI, other seeds as ticks.",
          "- `figures/pr_curves_per_class.png` -- one-vs-rest PR curves per class, ROUTED seed 0, with the prevalence line.",
          "- `figures/macro_f1_vs_latency.png` -- macro-F1 vs single-flow latency per model, point area ~ size on disk.", ""]
    if M.get("warnings"):
        L += ["## Warnings / caveats", ""] + [f"- {w}" for w in M["warnings"]] + [""]
    path.write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- main
def main() -> int:
    import xgboost as xgb
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--train-run", default=None, help="step 22 run id (default: the full run in results/22)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--config", default=None, help="Phase 2 config file (default config/v2_phase2.json)")
    args = ap.parse_args()
    cfg = config_from_arg(args.config)
    S.verify_v2_lock(strict=True)
    cm = S.load_class_map()
    feats, names, K = S.feature_columns(), list(cm.names), cm.n_classes
    up = R.resolve_run("22", args.train_run, args.dry_run, R.results_root(cfg))
    ctx = R.start_run("23", "eval", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    M.update({"train_run": up["meta"]["run_id"], "train_run_manifest_sha256": up["manifest_sha256"], "warnings": []})
    ok, E, systems, lat, v1, a2, groups = False, {}, {}, {}, None, None, []
    try:
        M22 = up["manifest"]
        R.add_check(ctx, M, "step 22 run used the same config / prereg / class map / features",
                    M22["config"]["sha256"] == cfg["_sha256"] and M22["prereg_phase2_sha256"] == S.PREREG_PHASE2_SHA256
                    and M22["class_map_sha256"] == S.CLASS_MAP_SHA256 and M22["features_file_sha256"] == S.FEATURES_V1_SHA256,
                    f"config {M22['config']['sha256'][:12]}..")
        c = cfg["columns"]
        import pyarrow.parquet as pq
        has_cat = c["device_category"] in pq.read_schema(D.split_file(cfg, "val")).names
        va = D.load_split(cfg, "val", feats + [c["group"], c["label_id"], c["session"], c["start_ts"]]
                          + ([c["device_category"]] if has_cat else []), sample=args.dry_run)
        M["dataset"] = {"val_sha256": D.verify_split_file(cfg, "val"), "train_read": False}
        y = va[c["label_id"]].to_numpy(np.int64)
        grp = va[c["group"]].astype(str).to_numpy()
        cat = va[c["device_category"]].astype(str).to_numpy() if has_cat else None
        sess, ts = va[c["session"]].astype(str).to_numpy(), va[c["start_ts"]].to_numpy(np.int64)
        X = D.feature_matrix(va, feats)
        M["n_val"] = len(y)
        del va
        gap = cfg["eval"]["benign_hours_idle_gap_s"]
        hours_cache: dict = {}

        def hours_fn(benign_rows):
            k = hash(benign_rows.tobytes())
            if k not in hours_cache:
                hours_cache[k] = PM.benign_hours(sess, ts, benign_rows, gap)
            return hours_cache[k]
        M["hours_all"] = hours_fn(y == 0)
        groups = sorted(set(grp))
        boosters, P = {}, {}
        for m in M22["models"]:
            p = up["dir"] / m["file"]
            if R.sha256_path(p) != m["sha256"]:
                raise RuntimeError(f"{p}: sha256 != step 22 manifest")
            b = xgb.Booster()
            b.load_model(str(p))
            boosters[m["key"]] = b
            P[m["key"]] = b.predict(xgb.DMatrix(X))
        R.add_check(ctx, M, "every step 22 model loaded (sha256 == manifest) and scored on val", True,
                    f"{len(P)} models x {len(y):,} rows")
        systems = build_systems(M22, cfg)
        if A.active(cfg):                                                # Amendment 1: flat baseline per weighting
            ids = {m["model_id"] for m in M22["models"]}
            for wm in cfg["class_weights"]["ablation_modes"]:
                did = A.swap_weights(M22["routing"]["default"], wm)
                if did in ids:
                    systems[A.flat_name(cfg, wm)] = {"kind": "all", "map": {}, "default": did,
                                                     "note": f"flat baseline, A1 weights {wm} (Amendment 1)"}
        M["systems"] = systems
        seeds = cfg["seeds"]
        subsets = {"all": np.ones(len(y), bool), **{g: grp == g for g in groups}}
        P_routed = {}
        for sname, sd in systems.items():
            mpr = route(sd, grp, cat)
            Ps = {s: assemble(P, mpr, s) for s in seeds}
            if sname == "ROUTED":
                P_routed = Ps
            E[sname] = evaluate_entity(y, Ps, np.ones(len(y), bool), subsets, hours_fn, K, cfg)
            ctx.log(f"  system {sname:<20} macro-F1 all {E[sname]['all']['aggregate']['macro_f1_all']['mean']:.5f}")
        if A.active(cfg):
            M["primary_selection"] = A.select_primary(E, cfg)
            ps = M["primary_selection"]
            R.add_check(ctx, M, "Amendment 1 primary selection applied", ps["chosen"] in A.modes(cfg),
                        f"chosen {ps['chosen']} ({ps['chosen_routed_system']}); within tolerance {ps['within_tolerance']}; "
                        f"tied on false alarms {ps['tied_on_fa']}")
        spec_of = {s["model_id"]: s for s in M22["specs"]}
        for mid, s in spec_of.items():
            kind, val = s["subset"]
            if kind == "all":
                rows = np.ones(len(y), bool)
            else:
                col = grp if kind == "group" else cat
                rows = D.pooled_mask(y, col == str(val))
            E[mid] = evaluate_entity(y, {sd: P[f"{mid}__s{sd}"] for sd in seeds}, rows, subsets, hours_fn, K, cfg)
            ctx.log(f"  model  {mid:<28} macro-F1 all {E[mid]['all']['aggregate']['macro_f1_all']['mean']:.5f}")
        for mid in spec_of:
            lat[mid] = latency(boosters[f"{mid}__s{seeds[0]}"], X, cfg)
        M["sizes"] = {m["model_id"]: m["bytes"] for m in M22["models"] if m["seed"] == seeds[0]}
        rare_all = E["ROUTED"]["all"]["aggregate"]["rare_classes"]
        if rare_all:
            sup_all = E["ROUTED"]["all"]["aggregate"]["support"]
            rare_txt = ", ".join("%s (%d)" % (names[c], sup_all[c]) for c in rare_all)
            M["warnings"].append(f"rare classes on the full val split (< {cfg['min_val_flows']} flows): {rare_txt}")
        for g in groups:
            sup = E["ROUTED"].get(g, {}).get("aggregate", {}).get("support")
            if sup and any(v == 0 for v in sup):
                M["warnings"].append(f"group {g}: classes with 0 val flows (N/A, excluded from its macro-F1): "
                                     f"{[names[c] for c, v in enumerate(sup) if v == 0]}")
        fb = cfg["fallback_group"]
        gen_ids = [s["model_id"] for s in M22["specs"] if s["config"] == "A2"]
        if gen_ids and (grp == fb).any():
            ben = (grp == fb) & (y == 0)
            h = hours_fn(ben)
            a2 = {"n_benign": int(ben.sum()), "hours": h, "models": {}}
            for mid in (M22["routing"]["default"], gen_ids[0]):
                fps = [int((P[f"{mid}__s{sd}"][ben].argmax(1) != 0).sum()) for sd in seeds]
                lo, hi = PM.garwood(fps[0], cfg["eval"]["ci_level"])
                a2["models"][mid] = {"fp_per_seed": fps, "fa_h_seed0": fps[0] / h if h else float("nan"),
                                     "ci": [lo / h, hi / h] if h else [None, None]}
            M["a2"] = a2
        if cfg["eval"]["v1_binary_compare"]:
            v1 = v1_compare(cfg, X, y, grp, M["hours_all"], P_routed, args.dry_run, ctx, M)
            M["v1_compare"] = v1
        if M.get("warnings") is not None and not (M22.get("spec_info") or {}).get("a3", {}).get("category_models"):
            M["warnings"].append("A3 not evaluated: no category models in the step 22 run")
        summary = {ent: {s: d[s]["aggregate"] for s in d} for ent, d in E.items()}
        R.write_json(ctx.partial / "metrics_per_seed.json", {ent: {s: d[s]["per_seed"] for s in d} for ent, d in E.items()})
        R.write_json(ctx.partial / "metrics_summary.json", {"classes": names, "groups": groups, "systems": systems,
                                                            "entities": summary, "latency": lat, "sizes": M["sizes"],
                                                            "v1_compare": v1, "a2": a2, "hours_all": M["hours_all"],
                                                            **({"primary_selection": M["primary_selection"]}
                                                               if "primary_selection" in M else {})})
        shutil.copyfile(ctx.partial / "metrics_summary.json", ctx.res / "metrics_summary.json")
        M["figures"] = [str(Path(p).relative_to(ctx.res)) for p in
                        figures(ctx.fig, E, systems, names, groups, lat, M["sizes"], v1, P_routed[seeds[0]], y, cfg)]
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["status"] = "PASS" if ok else "FAIL"
    write_summary(ctx.res / "summary.md", M, E, systems, names, groups, lat, v1, a2, cfg)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
