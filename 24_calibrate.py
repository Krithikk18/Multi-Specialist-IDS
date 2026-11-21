#!/usr/bin/env python
"""24_calibrate.py -- Phase 2 step 4 (Stage 2): temperature scaling per model, VAL only
(docs/V2_PREREG_PHASE2.md section 4).

Per model x seed of a step 22 run, on the model's own val set (same pooling rule as its training set):
  logits z = booster margin; one temperature T minimising the NLL of softmax(z / T) (bounded search on log T)
  reported   cross_fit_folds-fold stratified cross-fit (fold assignment seeded by the model seed): T fitted on the
             other folds, metrics read on the held-out fold, averaged over folds -- no row is scored by a T fitted
             on it
  deployed   T fitted on the whole val set, saved as <model key>.temperature.json (with the model file's sha256)
Metrics before (T = 1) / after: ECE (ece_bins equal-width bins; top-label and per-class one-vs-rest), Brier, NLL.

Outputs
  ~/lgids_cache/v2/calibrators/<run_id>/<model key>.temperature.json, calibration.json, run_manifest.json
  results/24/  run_meta.json, run.log, summary.md, run_manifest.json, figures/reliability_<model>.png,
               figures/ece_brier_before_after.png
  --dry-run --train-run <dry 22 run id>: the dry-run val sample, calibrators_dry_run/<run_id>/, results/24/dry_run/
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

import numpy as np

from common import phase2_data as D
from common import phase2_metrics as PM
from common import phase2_run as R
from common import plot_style as PS
from common import schemas as S
from common import amendment as A
from common.phase2_config import config_from_arg

SCRIPT = "24_calibrate.py"


def stratified_folds(y: np.ndarray, k: int, seed: int) -> np.ndarray:
    """Fold id per row: within each class, a seeded permutation dealt round-robin into k folds."""
    rng = np.random.default_rng(seed)
    f = np.empty(len(y), dtype=np.int64)
    for c in np.unique(y):
        ix = rng.permutation(np.flatnonzero(y == c))
        f[ix] = np.arange(len(ix)) % k
    return f


def calib_metrics(P: np.ndarray, y: np.ndarray, z: np.ndarray, T: float, bins: int) -> dict:
    return {"ece_top": PM.ece_top(P, y, bins), "ece_class": PM.ece_classwise(P, y, bins), "brier": PM.brier(P, y),
            "nll": PM.nll(z, y, T)}


def cross_fit(z: np.ndarray, y: np.ndarray, k: int, seed: int, bounds, bins: int) -> dict:
    """Held-out-fold metrics before / after, averaged over folds; out-of-fold calibrated probabilities."""
    folds = stratified_folds(y, k, seed)
    P_oof = np.empty((len(y), z.shape[1]))
    before, after, temps = [], [], []
    for f in range(k):
        te, tr = folds == f, folds != f
        if not te.any() or not tr.any():
            continue
        T = PM.fit_temperature(z[tr], y[tr], bounds)
        temps.append(T)
        P_oof[te] = PM.softmax(z[te], T)
        before.append(calib_metrics(PM.softmax(z[te], 1.0), y[te], z[te], 1.0, bins))
        after.append(calib_metrics(P_oof[te], y[te], z[te], T, bins))

    def avg(L):
        return {"ece_top": float(np.mean([m["ece_top"] for m in L])), "brier": float(np.mean([m["brier"] for m in L])),
                "nll": float(np.mean([m["nll"] for m in L])),
                "ece_class": np.nanmean(np.array([m["ece_class"] for m in L], float), axis=0).tolist()}
    return {"before": avg(before), "after": avg(after), "fold_temperatures": temps, "P_oof": P_oof, "folds": folds}


def fig_reliability(path: Path, title: str, P_raw: np.ndarray, P_cal: np.ndarray, y: np.ndarray, names: list[str],
                    bins: int) -> None:
    import matplotlib.pyplot as plt
    PS.apply()
    K = len(names)
    fig, axes = plt.subplots(1, K, figsize=(2.55 * K + 0.5, 2.8), squeeze=False)
    for c, ax in enumerate(axes[0]):
        ax.plot([0, 1], [0, 1], color=PS.GRID, lw=1)
        pos = (y == c).astype(float)
        if pos.any():
            for P, col, lab in ((P_raw, PS.NEUTRAL_LIGHT, "before"), (P_cal, PS.CATEGORICAL[0], "after (cross-fit)")):
                r = PM.reliability(P[:, c], pos, bins)
                ax.plot(r["conf"], r["acc"], "o-", color=col, ms=3.5, lw=1.5, label=lab)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.set_title(f"{names[c]} (n={int(pos.sum()):,})", loc="left", fontsize=8)
        ax.set_xlabel(f"predicted P({names[c]})", fontsize=8)
    axes[0][0].set_ylabel("observed frequency")
    axes[0][-1].legend(frameon=False, loc="upper left", fontsize=7)
    fig.subplots_adjust(top=0.78, wspace=0.35)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_ece_brier(path: Path, rows: list[str], agg: dict) -> None:
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator
    PS.apply()
    fig, axes = plt.subplots(1, 2, figsize=(9.0, 0.32 * len(rows) + 1.3))
    yy = np.arange(len(rows))[::-1]
    for ax, (met, lab) in zip(axes, (("ece_top", "top-label ECE"), ("brier", "Brier score"))):
        for off, when, col in ((0.18, "before", PS.NEUTRAL_LIGHT), (-0.18, "after", PS.CATEGORICAL[0])):
            a = [agg[m][when][met] for m in rows]
            m_ = np.array([x["mean"] for x in a])
            err = np.vstack([np.nan_to_num(m_ - np.array([x["lo"] for x in a])),
                             np.nan_to_num(np.array([x["hi"] for x in a]) - m_)])
            ax.barh(yy + off, m_, 0.34, xerr=err, color=col, label=when, error_kw={"lw": 0.8, "capsize": 1.5})
        ax.set_yticks(yy, rows if ax is axes[0] else [""] * len(rows), fontsize=7)
        ax.set_xlabel(f"{lab} (mean +- t-CI over seeds; cross-fit)")
        ax.xaxis.set_major_locator(MaxNLocator(4))
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
    axes[1].legend(frameon=False, loc="lower right")
    fig.subplots_adjust(top=1 - 0.45 / fig.get_figheight(), wspace=0.08)
    fig.suptitle("Calibration before / after temperature scaling (val, held-out folds)", x=0.01, ha="left", y=0.995)
    PS.save(fig, path)


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
    feats, names, K = S.feature_columns(), list(cm.names), cm.n_classes
    up = R.resolve_run("22", args.train_run, args.dry_run, R.results_root(cfg))
    up23 = R.resolve_run("23", args.eval_run, args.dry_run, R.results_root(cfg)) if A.active(cfg) else None
    ch = A.chosen(cfg, up["manifest"], up23)
    ctx = R.start_run("24", "calibrators", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    M.update({"train_run": up["meta"]["run_id"], "train_run_manifest_sha256": up["manifest_sha256"], "warnings": []})
    if up23 is not None:
        M.update({"eval_run": up23["meta"]["run_id"], "eval_run_manifest_sha256": up23["manifest_sha256"],
                  "primary": {k: v for k, v in ch.items() if k != "selection"}})
        R.add_check(ctx, M, "step 23 run used this step 22 run", up23["manifest"]["train_run"] == up["meta"]["run_id"], "")
    ok, agg, results = False, {}, {}
    ca = cfg["calibration"]
    try:
        M22 = up["manifest"]
        R.add_check(ctx, M, "step 22 run used the same config / prereg / class map / features",
                    M22["config"]["sha256"] == cfg["_sha256"] and M22["prereg_phase2_sha256"] == S.PREREG_PHASE2_SHA256
                    and M22["class_map_sha256"] == S.CLASS_MAP_SHA256, "")
        c = cfg["columns"]
        import pyarrow.parquet as pq
        has_cat = c["device_category"] in pq.read_schema(D.split_file(cfg, "val")).names
        va = D.load_split(cfg, "val", feats + [c["group"], c["label_id"]] + ([c["device_category"]] if has_cat else []),
                          sample=args.dry_run)
        M["dataset"] = {"val_sha256": D.verify_split_file(cfg, "val"), "train_read": False}
        y = va[c["label_id"]].to_numpy(np.int64)
        grp = va[c["group"]].astype(str).to_numpy()
        cat = va[c["device_category"]].astype(str).to_numpy() if has_cat else None
        X = D.feature_matrix(va, feats)
        del va
        spec_of = {s["model_id"]: s for s in M22["specs"]}
        oof_seed0 = {}
        for m in M22["models"]:
            s = spec_of[m["model_id"]]
            kind, val = s["subset"]
            rows = np.ones(len(y), bool) if kind == "all" else D.pooled_mask(y, (grp if kind == "group" else cat) == str(val))
            p = up["dir"] / m["file"]
            if R.sha256_path(p) != m["sha256"]:
                raise RuntimeError(f"{p}: sha256 != step 22 manifest")
            b = xgb.Booster()
            b.load_model(str(p))
            z = b.predict(xgb.DMatrix(X[rows]), output_margin=True).astype(np.float64)
            yr = y[rows]
            cf = cross_fit(z, yr, ca["cross_fit_folds"], m["seed"], ca["temperature_bounds"], ca["ece_bins"])
            T = PM.fit_temperature(z, yr, ca["temperature_bounds"])
            cal = {"model_key": m["key"], "model_file": m["file"], "model_sha256": m["sha256"], "train_run": up["meta"]["run_id"],
                   "method": "temperature", "temperature": T, "fitted_on": "the model's own val set (all rows)",
                   "n": int(len(yr)), "class_map_sha256": S.CLASS_MAP_SHA256, "features_file_sha256": S.FEATURES_V1_SHA256,
                   "config_sha256": cfg["_sha256"], "apply": "P = softmax(margin / temperature)"}
            R.write_json(ctx.partial / f"{m['key']}.temperature.json", cal)
            results[m["key"]] = {"model_id": m["model_id"], "seed": m["seed"], "temperature": T, "n": int(len(yr)),
                                 "fold_temperatures": cf["fold_temperatures"], "before": cf["before"], "after": cf["after"],
                                 "deployed_full_val": calib_metrics(PM.softmax(z, T), yr, z, T, ca["ece_bins"])}
            if m["seed"] == cfg["seeds"][0] and s["config"] == ch["config_label"]:
                oof_seed0[m["model_id"]] = (PM.softmax(z, 1.0), cf["P_oof"], yr)
            ctx.log(f"  {m['key']:<34} T {T:7.4f}  ECE {cf['before']['ece_top']:.5f} -> {cf['after']['ece_top']:.5f}  "
                    f"Brier {cf['before']['brier']:.6f} -> {cf['after']['brier']:.6f}")
        lvl = cfg["eval"]["ci_level"]
        for mid in spec_of:
            rs = [r for r in results.values() if r["model_id"] == mid]
            agg[mid] = {when: {k: PM.t_ci([r[when][k] for r in rs], lvl) for k in ("ece_top", "brier", "nll")}
                        for when in ("before", "after")}
            agg[mid]["temperature"] = PM.t_ci([r["temperature"] for r in rs], lvl)
            agg[mid]["config"] = spec_of[mid]["config"]
        R.write_json(ctx.partial / "calibration.json", {"per_model_seed": results, "aggregate": agg})
        R.add_check(ctx, M, "a deployment calibrator for every step 22 model", len(results) == len(M22["models"]),
                    f"{len(results)} calibrators")
        figs = []
        for mid, (Pr, Pc, yr) in oof_seed0.items():
            f = ctx.fig / f"reliability_{mid.rsplit('__', 1)[0]}.png"
            fig_reliability(f, f"{mid}, seed 0: reliability per class (one-vs-rest; val, cross-fit)", Pr, Pc, yr, names,
                            ca["ece_bins"])
            figs.append(f)
        f = ctx.fig / "ece_brier_before_after.png"
        fig_ece_brier(f, list(spec_of), agg)
        figs.append(f)
        M["figures"] = [str(p.relative_to(ctx.res)) for p in figs]
        M["calibration"] = {"aggregate": agg}
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["status"] = "PASS" if ok else "FAIL"
    L = [f"# Step 24 -- calibration (temperature scaling, VAL only) -- {M['status']}" + (" (DRY RUN)" if args.dry_run else ""), "",
         f"- run `{ctx.run_id}`, models from step 22 run `{M['train_run']}`; {ca['cross_fit_folds']}-fold stratified "
         f"cross-fit for the reported numbers (fold assignment seeded by the model seed); deployment calibrator fitted on "
         f"the whole own val set; ECE with {ca['ece_bins']} bins"]
    if M.get("primary"):
        L.append(f"- Amendment 1: primary weighting `{M['primary']['weights']}` ({M['primary']['source']}); reliability "
                 f"figures are for its `{M['primary']['config_label']}` models; every model is calibrated")
    L += [""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if agg:
        f5 = lambda a: f"{a['mean']:.5f} [{a['lo']:.5f}, {a['hi']:.5f}]" if np.isfinite(a.get("lo", np.nan)) else f"{a['mean']:.5f}"  # noqa: E731
        L += ["## Per model (mean [95 % t-CI] over seeds; held-out folds)", "",
              "| model | config | T | ECE before | ECE after | Brier before | Brier after |", "|---|---|---|---|---|---|---|"]
        for mid, a in agg.items():
            L.append(f"| {mid} | {a['config']} | {f5(a['temperature'])} | {f5(a['before']['ece_top'])} | {f5(a['after']['ece_top'])} | "
                     f"{f5(a['before']['brier'])} | {f5(a['after']['brier'])} |")
        L += ["", "## Figures", ""]
        for f in M.get("figures", []):
            cap = ("ECE (top-label) and Brier before / after per model, mean +- t-CI over seeds on held-out folds"
                   if "ece_brier" in f else "reliability diagram per class (one-vs-rest), before vs cross-fit after, seed 0")
            L.append(f"- `{f}` -- {cap}.")
    (ctx.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
