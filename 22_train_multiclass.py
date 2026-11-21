#!/usr/bin/env python
"""22_train_multiclass.py -- Phase 2 step 2: train the multiclass specialists, GLOBAL and the ablation models for
every seed (docs/V2_PREREG_PHASE2.md section 2-3). TRAIN rows only (val is not even opened here).

Models (one XGBoost multi:softprob per spec x seed; num_class = len(class_map); hyperparameters from
config/v2_phase2.json = V1 step 9's XGBoost 3.4.2 defaults, tree_method hist)
  primary   SPEC_<g>   one per group in the train `group` column except the fallback group: g's benign train rows
                       + every attack train row (shared attack pool); class weights "sqrt"
            GLOBAL     every train row; class weights "sqrt" (flat baseline + runtime model of fallback flows)
  A1        the primary models with class weights "none" and "balanced"
  A2        GENSPEC    fallback group's benign train rows + every attack train row ("sqrt")
  A3        CAT_<c>    per device category (config columns.device_category, if the column exists): c's benign train
                       rows + every attack train row ("sqrt"); categories with < a3_min_benign_train benign train
                       rows get no model (routed to GLOBAL); skipped and logged when the column does not exist
Per model: class weights from that training set's own counts; a seeded stratified inner split
(inner_split_frac of the training set) for early stopping on the weighted mlogloss (never val); the saved
booster is sliced at the best iteration. A class with 0 training rows is warned about, never a crash.

Outputs
  ~/lgids_cache/v2/models/<run_id>/<model_id>__s<seed>.ubj, curves.json, run_manifest.json
  results/22/  run_meta.json, run.log, summary.md, run_manifest.json (copy),
               figures/class_counts_per_training_set.png, figures/mlogloss_curves_seed0.png
  --dry-run: seeded stratified sample (config dry_run) -> models_dry_run/<run_id>/, results/22/dry_run/<run_id>/
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import traceback
from pathlib import Path

import numpy as np

from common import phase2_data as D
from common import phase2_run as R
from common import plot_style as PS
from common import schemas as S
from common.phase2_config import config_from_arg

SCRIPT = "22_train_multiclass.py"


# --------------------------------------------------------------------------- specs
def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", str(s)).strip("_") or "x"


def build_specs(groups, categories_benign: dict | None, cfg: dict) -> tuple[list[dict], dict]:
    """Model specs (data-agnostic). groups: group value per train row; categories_benign: {category: benign train
    rows} or None if the category column is absent. Returns (specs, info)."""
    fb = cfg["fallback_group"]
    spec_groups = D.specialist_groups(groups, fb)
    primary_w = cfg["class_weights"]["primary"]
    specs, info = [], {"specialist_groups": spec_groups, "fallback_group": fb,
                       "fallback_present": fb in set(map(str, groups)), "a3": None}
    for g in spec_groups:
        specs.append({"model_id": f"SPEC_{slug(g)}__{primary_w}", "kind": "specialist", "key": g,
                      "subset": ("group", g), "weights": primary_w, "config": "primary"})
    specs.append({"model_id": f"GLOBAL__{primary_w}", "kind": "global", "key": "GLOBAL", "subset": ("all", None),
                  "weights": primary_w, "config": "primary"})
    if cfg["ablations"]["A1_class_weights"]:
        for m in cfg["class_weights"]["ablation_modes"]:
            for s in [x for x in specs if x["config"] == "primary"]:
                specs.append({**s, "model_id": s["model_id"].rsplit("__", 1)[0] + f"__{m}", "weights": m,
                              "config": f"A1_{m}"})
    if cfg["ablations"]["A2_gen_specialist"]:
        if info["fallback_present"]:
            specs.append({"model_id": f"GENSPEC_{slug(fb)}__{primary_w}", "kind": "gen_specialist", "key": fb,
                          "subset": ("group", fb), "weights": primary_w, "config": "A2"})
        else:
            info["a2_skipped"] = f"fallback group {fb!r} not in the train data"
    if cfg["ablations"]["A3_device_category"]:
        if categories_benign is None:
            info["a3"] = {"skipped": f"column {cfg['columns']['device_category']!r} not in the dataset"}
        else:
            routed, low = {}, {}
            for c, n in sorted(categories_benign.items()):
                if n >= cfg["ablations"]["a3_min_benign_train"]:
                    mid = f"CAT_{slug(c)}__{primary_w}"
                    specs.append({"model_id": mid, "kind": "category", "key": c, "subset": ("category", c),
                                  "weights": primary_w, "config": "A3"})
                    routed[c] = mid
                else:
                    low[c] = n
            info["a3"] = {"category_models": routed, "fallback_to_global": low,
                          "min_benign_train": cfg["ablations"]["a3_min_benign_train"]}
    ids = [s["model_id"] for s in specs]
    if len(set(ids)) != len(ids):
        raise ValueError(f"duplicate model ids {ids}")
    return specs, info


def subset_mask(spec: dict, label_id: np.ndarray, group: np.ndarray, category: np.ndarray | None,
                benign_id: int = 0) -> np.ndarray:
    kind, val = spec["subset"]
    if kind == "all":
        return np.ones(len(label_id), dtype=bool)
    col = group if kind == "group" else category
    return D.pooled_mask(label_id, np.asarray(col).astype(str) == str(val), benign_id)


# --------------------------------------------------------------------------- training
def train_one(X: np.ndarray, y: np.ndarray, n_classes: int, weight_mode: str, seed: int, cfg: dict,
              nthread: int | None = None) -> dict:
    """One XGBoost multi:softprob fit with class weights, a seeded stratified inner split and early stopping.
    Returns {"booster" (sliced at best iteration), "counts", "class_weights", "best_iteration", "curves", ...}."""
    import xgboost as xgb
    counts = D.class_counts(y, n_classes)
    w_class = D.class_weights(counts, weight_mode)
    fit_ix, inner_ix = D.stratified_split(y, cfg["inner_split_frac"], seed)
    w = w_class[y]
    params = {**cfg["xgb"]["params"], "num_class": n_classes, "seed": seed}
    if nthread is not None:
        params["nthread"] = nthread
    dfit = xgb.DMatrix(X[fit_ix], label=y[fit_ix], weight=w[fit_ix])
    dinn = xgb.DMatrix(X[inner_ix], label=y[inner_ix], weight=w[inner_ix])
    curves: dict = {}
    t0 = time.monotonic()
    bst = xgb.train(params, dfit, num_boost_round=cfg["xgb"]["num_boost_round"],
                    evals=[(dfit, "train"), (dinn, "inner")], evals_result=curves,
                    early_stopping_rounds=cfg["xgb"]["early_stopping_rounds"], verbose_eval=False)
    fit_s = time.monotonic() - t0
    best = int(bst.best_iteration)
    sliced = bst[: best + 1]
    return {"booster": sliced, "counts": counts.tolist(), "class_weights": w_class.tolist(),
            "zero_row_classes": [int(c) for c in np.flatnonzero(counts == 0)],
            "n_fit": int(len(fit_ix)), "n_inner": int(len(inner_ix)),
            "inner_counts": D.class_counts(y[inner_ix], n_classes).tolist(),
            "best_iteration": best, "best_score": float(bst.best_score), "rounds_run": int(bst.num_boosted_rounds()),
            "curves": {k: [float(v) for v in curves[k]["mlogloss"]] for k in ("train", "inner")},
            "fit_seconds": round(fit_s, 2), "params": params}


# --------------------------------------------------------------------------- figures + summary
def fig_class_counts(path: Path, specs: list[dict], counts: dict, names: list[str]) -> None:
    import matplotlib.pyplot as plt
    PS.apply()
    sets = [s for s in specs if s["config"] in ("primary", "A2", "A3")]
    fig, ax = plt.subplots(figsize=(max(6.4, 0.75 * len(sets) + 1.5), 3.6))
    K, w = len(names), 0.8 / len(names)
    x = np.arange(len(sets))
    for k, n in enumerate(names):
        vals = [counts[s["model_id"]][k] for s in sets]
        ax.bar(x + (k - (K - 1) / 2) * w, [v if v > 0 else np.nan for v in vals], width=w * 0.92,
               color=PS.class_color(k), label=n)
    ax.set_yscale("log")
    ax.set_xticks(x, [s["model_id"].rsplit("__", 1)[0] for s in sets], rotation=35, ha="right")
    ax.set_ylabel("training rows (log scale)")
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=K, loc="upper center", bbox_to_anchor=(0.5, 1.13))
    ax.set_title("Class counts per training set (attack bars = the shared pool)", loc="left", pad=22)
    PS.save(fig, path)


def fig_curves(path: Path, primaries: list[dict], curves: dict) -> None:
    import matplotlib.pyplot as plt
    PS.apply()
    n = len(primaries)
    fig, axes = plt.subplots(1, n, figsize=(3.0 * n + 0.6, 2.8), squeeze=False)
    for ax, s in zip(axes[0], primaries):
        c = curves[f"{s['model_id']}__s0"]
        it = np.arange(1, len(c["train"]) + 1)
        ax.plot(it, c["train"], color=PS.NEUTRAL_LIGHT, lw=2, label="train (fit part)")
        ax.plot(it, c["inner"], color=PS.CATEGORICAL[0], lw=2, label="inner split")
        ax.axvline(c["best_iteration"] + 1, color=PS.TEXT2, lw=0.8, ls=":")
        ax.set_yscale("log")
        ax.set_xlabel("boosting round")
        ax.set_title(s["model_id"].rsplit("__", 1)[0], loc="left")
        ax.yaxis.grid(True)
    axes[0][0].set_ylabel("weighted mlogloss (log)")
    axes[0][-1].legend(frameon=False, loc="upper right")
    fig.subplots_adjust(top=0.76, wspace=0.3)
    fig.suptitle("mlogloss, train vs inner early-stopping split (seed 0; dotted = best iteration)", x=0.01, y=0.99,
                 ha="left")
    PS.save(fig, path)


def write_summary(path: Path, M: dict, names: list[str]) -> None:
    L = [f"# Step 22 -- multiclass training -- {M['status']}" + (" (DRY RUN)" if M["dry_run"] else ""), "",
         f"- run `{M['run_id']}`, dataset `{M['dataset_version']}`, config sha256 `{M['config']['sha256'][:16]}...`, "
         f"prereg sha256 `{M['prereg_phase2_sha256'][:16]}...`, seeds {M['seeds']}, runtime {M.get('runtime_s')} s",
         f"- train rows used: {M.get('n_train_rows', 0):,}" + (" (dry-run sample)" if M["dry_run"] else ""),
         f"- specialist groups (from the data): {M.get('spec_info', {}).get('specialist_groups')}; fallback "
         f"`{M.get('spec_info', {}).get('fallback_group')}` -> GLOBAL", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    a3 = (M.get("spec_info") or {}).get("a3")
    if a3:
        L += [f"- A3: {a3}", ""]
    L += ["## Figures", "",
          "- `figures/class_counts_per_training_set.png` -- training rows per class for every primary / A2 / A3 "
          "training set (log scale); the attack bars are identical across sets because attacks are pooled.",
          "- `figures/mlogloss_curves_seed0.png` -- weighted mlogloss on the fit part vs the 10 % inner split per "
          "primary model (seed 0); the dotted line is the early-stopping best iteration.", ""]
    rows = []
    for mid, e in (M.get("models_summary") or {}).items():
        rows.append({"model": mid, "config": e["config"], "weights": e["weights"],
                     **{n: e["counts"][k] for k, n in enumerate(names)},
                     **{f"w_{n}": round(e["class_weights"][k], 3) for k, n in enumerate(names)},
                     "best_iter (mean, seeds)": e["best_iter_mean"], "fit s (mean)": e["fit_s_mean"]})
    if rows:
        cols = list(rows[0])
        L += ["## Models (training-set counts and class weights are seed-independent)", "",
              "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        L += ["| " + " | ".join(f"{r[c]:,}" if isinstance(r[c], int) else str(r[c]) for c in cols) + " |" for r in rows]
        L += [""]
    if M.get("warnings"):
        L += ["## Warnings", ""] + [f"- {w}" for w in M["warnings"]] + [""]
    path.write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--config", default=None, help="Phase 2 config file (default config/v2_phase2.json)")
    args = ap.parse_args()
    cfg = config_from_arg(args.config)
    S.verify_v2_lock(strict=True)
    cm = S.load_class_map()
    feats = S.feature_columns()
    names = list(cm.names)
    ctx = R.start_run("22", "models", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    M["warnings"], ok = [], False
    try:
        c = cfg["columns"]
        dm = D.load_dataset_manifest(cfg)
        M["dataset"] = {"dir": str(D.dataset_dir(cfg)), "manifest_sha256": dm["_sha256"],
                        "train_sha256": D.verify_split_file(cfg, "train"), "val_read": False}
        import pyarrow.parquet as pq
        has_cat = c["device_category"] in pq.read_schema(D.split_file(cfg, "train")).names
        cols = feats + [c["group"], c["label_id"]] + ([c["device_category"]] if has_cat else [])
        tr = D.load_split(cfg, "train", cols, sample=args.dry_run)
        M["n_train_rows"] = len(tr)
        y = tr[c["label_id"]].to_numpy(np.int64)
        grp = tr[c["group"]].astype(str).to_numpy()
        cat = tr[c["device_category"]].astype(str).to_numpy() if has_cat else None
        if y.min() < 0 or y.max() >= cm.n_classes:
            raise ValueError(f"label_id outside [0, {cm.n_classes})")
        X = D.feature_matrix(tr, feats)
        del tr
        cat_ben = ({k: int(v) for k, v in zip(*np.unique(cat[y == 0], return_counts=True))} if has_cat else None)
        specs, info = build_specs(grp, cat_ben, cfg)
        M["spec_info"] = info
        if info.get("a3", {}) and info["a3"].get("skipped"):
            M["warnings"].append(f"A3 skipped: {info['a3']['skipped']}")
        if not info["fallback_present"]:
            M["warnings"].append(f"fallback group {cfg['fallback_group']!r} not in the train data")
        M["routing"] = {"primary": {**{g: f"SPEC_{slug(g)}__{cfg['class_weights']['primary']}"
                                       for g in info["specialist_groups"]},
                                    cfg["fallback_group"]: f"GLOBAL__{cfg['class_weights']['primary']}"},
                        "default": f"GLOBAL__{cfg['class_weights']['primary']}"}
        M["specs"] = specs
        R.add_check(ctx, M, "class map / features / dataset pins", True,
                    f"{cm.n_classes} classes, {len(feats)} features, {len(specs)} specs x {len(cfg['seeds'])} seeds")
        models, curves, counts = [], {}, {}
        for s in specs:
            mask = subset_mask(s, y, grp, cat)
            Xs, ys = X[mask], y[mask]
            for seed in cfg["seeds"]:
                r = train_one(Xs, ys, cm.n_classes, s["weights"], seed, cfg)
                fname = f"{s['model_id']}__s{seed}.ubj"
                r["booster"].save_model(str(ctx.partial / fname))
                fp = ctx.partial / fname
                key = f"{s['model_id']}__s{seed}"
                curves[key] = {**r["curves"], "best_iteration": r["best_iteration"]}
                counts[s["model_id"]] = r["counts"]
                if r["zero_row_classes"]:
                    msg = (f"{key}: classes with 0 training rows {[names[k] for k in r['zero_row_classes']]} "
                           f"(num_class stays {cm.n_classes})")
                    if msg.split(":")[0].endswith("__s0"):
                        M["warnings"].append(msg.replace("__s0", ""))
                    ctx.log(f"  WARN {msg}")
                models.append({"key": key, "model_id": s["model_id"], "seed": seed, "file": fname,
                               "sha256": R.sha256_path(fp), "bytes": fp.stat().st_size, "kind": s["kind"],
                               "subset_key": s["key"], "config": s["config"], "weights": s["weights"],
                               **{k: r[k] for k in ("counts", "class_weights", "zero_row_classes", "n_fit", "n_inner",
                                                    "inner_counts", "best_iteration", "best_score", "rounds_run",
                                                    "fit_seconds")}})
                ctx.log(f"  {key:<34} rows {len(ys):>8,}  best_iter {r['best_iteration']:>3}  "
                        f"inner mlogloss {r['best_score']:.5f}  {r['fit_seconds']:6.1f} s")
        R.write_json(ctx.partial / "curves.json", curves)
        M["models"] = models
        M["models_summary"] = {}
        for s in specs:
            ms = [m for m in models if m["model_id"] == s["model_id"]]
            M["models_summary"][s["model_id"]] = {
                "config": s["config"], "weights": s["weights"], "counts": ms[0]["counts"],
                "class_weights": ms[0]["class_weights"],
                "best_iter_mean": round(float(np.mean([m["best_iteration"] for m in ms])), 1),
                "fit_s_mean": round(float(np.mean([m["fit_seconds"] for m in ms])), 1)}
        R.add_check(ctx, M, "every spec x seed trained and saved", len(models) == len(specs) * len(cfg["seeds"]),
                    f"{len(models)} models")
        fig_class_counts(ctx.fig / "class_counts_per_training_set.png", specs, counts, names)
        fig_curves(ctx.fig / "mlogloss_curves_seed0.png",
                   [s for s in specs if s["config"] == "primary"], curves)
        M["figures"] = ["figures/class_counts_per_training_set.png", "figures/mlogloss_curves_seed0.png"]
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["status"] = "PASS" if ok else "FAIL"
    write_summary(ctx.res / "summary.md", {**M, "runtime_s": round(time.monotonic() - ctx.t0, 1)}, names)
    R.finish_run(ctx, ok, M, {"n_models": len(M.get("models", []))})
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
