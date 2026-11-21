#!/usr/bin/env python
"""25_explain_shap.py -- Phase 2 step 5: TreeSHAP explanations of the seed-0 primary models, VAL only
(docs/V2_PREREG_PHASE2.md section 4).

shap is not in the lgids env, so TreeSHAP comes from XGBoost itself (Booster.predict(pred_contribs=True): exact
TreeSHAP, the prompt's named fallback; docs/V2_DECISIONS.md D01). Per primary model (seed = config seeds[0]):
  sample      up to shap_per_class val flows per class from the model's own val set (seeded; all if fewer)
  values      contributions (n, K, F + 1); additivity checked: sum of contributions + bias == the model margin
  importance  mean |SHAP| per class output and feature; global = mean over class outputs
Leakage check (hard): no feature name is identifier-like (IP, MAC, port, timestamp, flow id; V1 08's IDENTITY_RE)
or a metadata column of the dataset. Flag (reported): any feature with > dominance_threshold of a model's (or a
class output's) total mean |SHAP|.

Outputs
  ~/lgids_cache/v2/shap/<run_id>/<model key>.npz (sampled rows' SHAP values, labels, row positions), shap.json
  results/25/  run_meta.json, run.log, summary.md, run_manifest.json, figures/beeswarm_<model>.png,
               figures/global_mean_abs_shap.png, figures/top20_features_by_group_heatmap.png
"""

from __future__ import annotations

import argparse
import re
import sys
import traceback
from pathlib import Path

import numpy as np

from common import phase2_data as D
from common import phase2_run as R
from common import plot_style as PS
from common import schemas as S
from common import amendment as A
from common.phase2_config import config_from_arg

SCRIPT = "25_explain_shap.py"
IDENTITY_RE = re.compile(r"(?i)\b(ip|port|mac|id)\b|timestamp|label|owner|device|group|flow id|session")  # V1 08 + session


def leakage_check(feats: list[str], metadata_cols: list[str]) -> list[str]:
    """Feature names that look like identifiers or are dataset metadata columns (empty list = clean)."""
    meta = set(metadata_cols) | set(S.ID_COLS) | set(S.MAC_COLS) | set(S.V1_META_COLS) | set(S.LABEL_COLS) | {S.SESSION_COL}
    return [f for f in feats if IDENTITY_RE.search(f) or f in meta]


def sample_per_class(y: np.ndarray, cap: int, seed: int) -> np.ndarray:
    """Ascending positions: per class min(n_c, cap) seeded-random rows."""
    rng = np.random.default_rng(seed)
    out = [np.sort(rng.permutation(np.flatnonzero(y == c))[:cap]) for c in np.unique(y)]
    return np.sort(np.concatenate(out)) if out else np.zeros(0, np.int64)


def tree_shap(booster, X: np.ndarray) -> tuple[np.ndarray, float]:
    """(contributions (n, K, F + 1), max additivity error vs the margin)."""
    import xgboost as xgb
    d = xgb.DMatrix(X)
    C = booster.predict(d, pred_contribs=True)
    if C.ndim == 2:                                                    # single output -> (n, 1, F + 1)
        C = C[:, None, :]
    margin = booster.predict(d, output_margin=True).reshape(len(X), -1)
    err = float(np.abs(C.sum(2) - margin).max()) if len(X) else 0.0
    return C, err


def importance(C: np.ndarray) -> np.ndarray:
    """mean |SHAP| per class output x feature (bias column dropped): (K, F)."""
    return np.abs(C[:, :, :-1]).mean(0)


def dominance(imp_row: np.ndarray, feats: list[str], thr: float) -> list[dict]:
    tot = imp_row.sum()
    if tot <= 0:
        return []
    share = imp_row / tot
    return [{"feature": feats[j], "share": float(share[j])} for j in np.flatnonzero(share > thr)]


# --------------------------------------------------------------------------- figures
def fig_beeswarm(path: Path, title: str, C: np.ndarray, X: np.ndarray, feats: list[str], names: list[str], top: int,
                 seed: int, max_points: int = 1500) -> None:
    import matplotlib.pyplot as plt
    from matplotlib.cm import ScalarMappable
    from matplotlib.colors import Normalize
    PS.apply()
    K = len(names)
    rng = np.random.default_rng(seed)
    rows = np.sort(rng.permutation(len(X))[:max_points])
    fig, axes = plt.subplots(1, K, figsize=(4.4 * K, 0.27 * top + 1.6), squeeze=False)
    fig.subplots_adjust(wspace=0.95)                                   # room for each panel's own feature labels
    cmap = plt.get_cmap(PS.SEQUENTIAL_CMAP)
    for c, ax in enumerate(axes[0]):
        imp = np.abs(C[:, c, :-1]).mean(0)
        order = np.argsort(imp)[::-1][:top]
        for r, j in enumerate(order[::-1]):
            v = X[rows, j]
            rank = (np.argsort(np.argsort(v)) / max(1, len(v) - 1)) if len(v) > 1 else np.zeros(len(v))
            jit = rng.uniform(-0.3, 0.3, len(rows))
            ax.scatter(C[rows, c, j], np.full(len(rows), r) + jit, c=0.15 + 0.85 * rank, cmap=cmap, vmin=0, vmax=1, s=3,
                       lw=0, rasterized=True)
        ax.axvline(0, color=PS.TEXT2, lw=0.6)
        ax.set_yticks(range(len(order)), [feats[j] for j in order[::-1]], fontsize=6.5)
        ax.set_title(f"output: {names[c]}", loc="left", fontsize=8.5)
        ax.set_xlabel("SHAP value (margin)", fontsize=8)
        ax.xaxis.grid(True)
    sm = ScalarMappable(norm=Normalize(0, 1), cmap=cmap)
    cb = fig.colorbar(sm, ax=axes[0].tolist(), fraction=0.015, pad=0.01)
    cb.set_ticks([0.15, 1.0], labels=["low", "high"])
    cb.set_label("feature value (rank within the feature)")
    cb.outline.set_visible(False)
    fig.suptitle(title, x=0.01, ha="left")
    PS.save(fig, path)


def fig_global(path: Path, imps: dict, feats: list[str], top: int) -> None:
    import matplotlib.pyplot as plt
    PS.apply()
    n = len(imps)
    fig, axes = plt.subplots(1, n, figsize=(3.6 * n, 0.24 * top + 1.2), squeeze=False)
    for ax, (mid, I) in zip(axes[0], imps.items()):
        g = I.mean(0)
        order = np.argsort(g)[::-1][:top][::-1]
        ax.barh(range(len(order)), g[order], color=PS.CATEGORICAL[0], height=0.7)
        ax.set_yticks(range(len(order)), [feats[j] for j in order], fontsize=6.5)
        ax.set_title(mid.rsplit("__", 1)[0], loc="left", fontsize=9)
        ax.set_xlabel("mean |SHAP| (mean over class outputs)", fontsize=8)
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
    fig.suptitle(f"Global feature importance, top {top} per model (val sample, seed-0 primary models)", x=0.01, ha="left")
    PS.save(fig, path)


def fig_heatmap(path: Path, imps: dict, labels: dict, feats: list[str], top: int) -> None:
    import matplotlib.pyplot as plt
    PS.apply()
    G = np.array([I.mean(0) for I in imps.values()])                  # models x F
    order = np.argsort(G.max(0))[::-1][:top]
    M = G[:, order].T                                                  # top features x models
    fig, ax = plt.subplots(figsize=(1.3 * len(imps) + 3.2, 0.26 * top + 1.2))
    im = ax.imshow(M, cmap=PS.SEQUENTIAL_CMAP, aspect="auto")
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            ax.text(j, i, f"{M[i, j]:.2f}", ha="center", va="center", fontsize=6.5,
                    color="#ffffff" if M[i, j] > 0.6 * M.max() else PS.TEXT1)
    ax.set_xticks(range(len(imps)), [labels[m] for m in imps], fontsize=8)
    ax.set_yticks(range(len(order)), [feats[j] for j in order], fontsize=7)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cb.set_label("mean |SHAP|")
    cb.outline.set_visible(False)
    ax.set_title(f"Top {top} features x group (model serving the group; mean |SHAP|)", loc="left")
    PS.save(fig, path)


# --------------------------------------------------------------------------- main
def main() -> int:
    import xgboost as xgb
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--train-run", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--config", default=None, help="Phase 2 config file (default config/v2_phase2.json)")
    ap.add_argument("--eval-run", default=None, help="step 23 run (only read under Amendment 1: the chosen weighting)")
    args = ap.parse_args()
    cfg = config_from_arg(args.config)
    S.verify_v2_lock(strict=True)
    cm = S.load_class_map()
    feats, names = S.feature_columns(), list(cm.names)
    up = R.resolve_run("22", args.train_run, args.dry_run, R.results_root(cfg))
    up23 = R.resolve_run("23", args.eval_run, args.dry_run, R.results_root(cfg)) if A.active(cfg) else None
    ch = A.chosen(cfg, up["manifest"], up23)
    ctx = R.start_run("25", "shap", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    M.update({"train_run": up["meta"]["run_id"], "train_run_manifest_sha256": up["manifest_sha256"], "warnings": [],
              "method": "xgboost Booster.predict(pred_contribs=True): exact TreeSHAP (shap library not installed; D01)"})
    if up23 is not None:
        M.update({"eval_run": up23["meta"]["run_id"], "eval_run_manifest_sha256": up23["manifest_sha256"],
                  "primary": {k: v for k, v in ch.items() if k != "selection"}})
        R.add_check(ctx, M, "step 23 run used this step 22 run", up23["manifest"]["train_run"] == up["meta"]["run_id"], "")
    ok, out, imps = False, {}, {}
    sh = cfg["shap"]
    seed0 = cfg["seeds"][0]
    try:
        M22 = up["manifest"]
        import pyarrow.parquet as pq
        meta_cols = [c for c in pq.read_schema(D.split_file(cfg, "val")).names if c not in feats]
        leaks = leakage_check(feats, meta_cols)
        R.add_check(ctx, M, "leakage: no identifier-like / metadata column in the feature set", not leaks,
                    "clean (70 features vs identifier pattern + %d metadata columns)" % len(meta_cols) if not leaks else str(leaks))
        c = cfg["columns"]
        va = D.load_split(cfg, "val", feats + [c["group"], c["label_id"]], sample=args.dry_run)
        M["dataset"] = {"val_sha256": D.verify_split_file(cfg, "val"), "train_read": False}
        y = va[c["label_id"]].to_numpy(np.int64)
        grp = va[c["group"]].astype(str).to_numpy()
        X = D.feature_matrix(va, feats)
        del va
        prim = [s for s in M22["specs"] if s["config"] == ch["config_label"]]
        serves = {}
        for g, mid in ch["routing"].items():
            serves.setdefault(mid, []).append(g)
        for s in prim:
            m = next(x for x in M22["models"] if x["model_id"] == s["model_id"] and x["seed"] == seed0)
            p = up["dir"] / m["file"]
            if R.sha256_path(p) != m["sha256"]:
                raise RuntimeError(f"{p}: sha256 != step 22 manifest")
            b = xgb.Booster()
            b.load_model(str(p))
            kind, val = s["subset"]
            rows = np.ones(len(y), bool) if kind == "all" else D.pooled_mask(y, grp == str(val))
            pos = np.flatnonzero(rows)
            pick = pos[sample_per_class(y[pos], sh["shap_per_class"], seed0)]
            C, err = tree_shap(b, X[pick])
            R.add_check(ctx, M, f"TreeSHAP additivity {m['key']}: contributions + bias == margin", err < 1e-3,
                        f"max |error| {err:.2e} over {len(pick):,} rows")
            I = importance(C)
            imps[m["key"]] = I
            dom = {"model": dominance(I.mean(0), feats, sh["dominance_threshold"]),
                   "per_class": {names[k]: dominance(I[k], feats, sh["dominance_threshold"]) for k in range(len(names))}}
            g_imp = I.mean(0)
            top = np.argsort(g_imp)[::-1][:10]
            out[m["key"]] = {"model_id": s["model_id"], "serves_groups": serves.get(s["model_id"], []),
                             "n_rows": int(len(pick)), "rows_per_class": np.bincount(y[pick], minlength=len(names)).tolist(),
                             "additivity_max_abs_error": err, "dominance": dom,
                             "top10_global": [{"feature": feats[j], "mean_abs_shap": float(g_imp[j]),
                                               "share": float(g_imp[j] / g_imp.sum())} for j in top],
                             "mean_abs_shap": {names[k]: dict(zip(feats, map(float, I[k]))) for k in range(len(names))}}
            np.savez_compressed(ctx.partial / f"{m['key']}.npz", shap=C.astype(np.float32), y=y[pick], val_rows=pick)
            flags = dom["model"] + [x for v in dom["per_class"].values() for x in v]
            if flags:
                M["warnings"].append(f"{m['key']}: feature(s) above {sh['dominance_threshold']:.0%} of total mean |SHAP|: "
                                     + "; ".join(f"{x['feature']} {x['share']:.1%}" for x in dom["model"])
                                     + ("; per class: " + "; ".join(f"{k}: {x['feature']} {x['share']:.1%}"
                                                                    for k, v in dom["per_class"].items() for x in v)
                                        if any(dom["per_class"].values()) else ""))
            ctx.log(f"  {m['key']:<24} rows {len(pick):>6,}  additivity err {err:.1e}  top {feats[top[0]]} "
                    f"({g_imp[top[0]] / g_imp.sum():.1%})")
            fig_beeswarm(ctx.fig / f"beeswarm_{s['model_id'].rsplit('__', 1)[0]}.png",
                         f"{m['key']}: TreeSHAP per class output (val sample; top {sh['beeswarm_top']} features per output)",
                         C, X[pick], feats, names, sh["beeswarm_top"], seed0)
        R.write_json(ctx.partial / "shap.json", out)
        fig_global(ctx.fig / "global_mean_abs_shap.png", imps, feats, sh["top_k_heatmap"])
        labels = {k: "/".join(out[k]["serves_groups"]) + f"\n({out[k]['model_id'].rsplit('__', 1)[0]})"
                  if out[k]["serves_groups"] else out[k]["model_id"].rsplit("__", 1)[0] for k in imps}
        fig_heatmap(ctx.fig / "top20_features_by_group_heatmap.png", imps, labels, feats, sh["top_k_heatmap"])
        M["figures"] = sorted(str(p.relative_to(ctx.res)) for p in ctx.fig.glob("*.png"))
        M["shap"] = {k: {x: v[x] for x in ("model_id", "serves_groups", "n_rows", "rows_per_class",
                                             "additivity_max_abs_error", "dominance", "top10_global")} for k, v in out.items()}
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["status"] = "PASS" if ok else "FAIL"
    L = [f"# Step 25 -- TreeSHAP explanations (VAL only) -- {M['status']}" + (" (DRY RUN)" if args.dry_run else ""), "",
         f"- run `{ctx.run_id}`, models: seed-{seed0} primary models of step 22 run `{M['train_run']}`"
         + (f" -- Amendment 1 primary weighting `{M['primary']['weights']}` ({M['primary']['source']})"
            if M.get("primary") else ""),
         f"- method: {M['method']}", f"- sample: up to {sh['shap_per_class']} val flows per class per model (seeded; all if fewer)", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    L += ["## Leakage check", ""] + [f"- {ch['check']}: **{'PASS' if ch['pass'] else 'FAIL'}** -- {ch['detail']}"
                                     for ch in M["checks"] if ch["check"].startswith(("leakage", "TreeSHAP"))] + [""]
    L += [f"## Dominance flags (> {sh['dominance_threshold']:.0%} of total mean |SHAP|)", ""]
    L += ([f"- {w}" for w in M["warnings"]] if M["warnings"] else ["- none: no single feature dominates any model or class output"]) + [""]
    for k, v in out.items():
        L += [f"## {k} (serves {', '.join(v['serves_groups']) or '-'}; {v['n_rows']:,} rows, per class {v['rows_per_class']})", "",
              "| rank | feature | mean abs SHAP | share |", "|---|---|---|---|"]
        L += [f"| {i + 1} | {t['feature']} | {t['mean_abs_shap']:.4f} | {t['share']:.1%} |" for i, t in enumerate(v["top10_global"])]
        L += [""]
    L += ["## Figures", ""]
    for f in M.get("figures", []):
        cap = ("beeswarm per class output: SHAP value per sampled flow for the top features, colour = the flow's feature value "
               "rank" if "beeswarm" in f else "global mean |SHAP| (mean over class outputs), top features per model"
               if "global" in f else "mean |SHAP| of the top features x the model serving each group (GLOBAL serves the "
               "fallback group)")
        L.append(f"- `{f}` -- {cap}.")
    (ctx.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
