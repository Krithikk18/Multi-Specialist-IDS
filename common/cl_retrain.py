"""common/cl_retrain.py -- Phase 4 retraining (docs/V2_PREREG_PHASE4.md section 5). OFFLINE ONLY: the Pi never trains.

    r = fit(X, y, K, weights, seed, cfg2, nthread)                         # full (re)train == step 22's train_one
    r = fit(X, y, K, weights, seed, cfg2, nthread, base=booster, rounds=100)   # warm start: continue boosting

Both: class weights from this training set's own counts (common/phase2_data.class_weights), a seeded stratified inner
split (cfg2 inner_split_frac, seed = the model seed) for early stopping on the weighted mlogloss (cfg2
early_stopping_rounds), the booster saved sliced at the best iteration. The full fit is step 22's train_one with a fixed
thread count (tested identical, model bytes). Warm start passes the existing booster as xgb.train(xgb_model=...) and
adds up to `rounds` trees; XGBoost counts best_iteration over ALL trees (base included), so the slice keeps the base
trees + the best number of new ones (>= 1: early stopping compares new rounds only). The base booster is not modified.
Cost: wall-clock seconds of DMatrix construction + boosting (fixed nthread), and the process peak RSS during it
(VmHWM reset via /proc/self/clear_refs before the fit; also its increase over the RSS before the fit).
Calibration of a retrained model: one temperature fitted on its own inner split (common/phase2_metrics.fit_temperature).
"""

from __future__ import annotations

import time

import numpy as np

from common import cl_run as CR
from common import phase2_data as D
from common import phase2_metrics as PM


def fit(X: np.ndarray, y: np.ndarray, n_classes: int, weight_mode: str, seed: int, cfg2: dict, nthread: int,
        base=None, rounds: int | None = None, temperature_bounds=(0.05, 20.0)) -> dict:
    import xgboost as xgb
    y = np.asarray(y, dtype=np.int64)
    reset_ok = CR.reset_peak_rss()
    vm0 = CR.vm_status()
    t0 = time.monotonic()
    counts = D.class_counts(y, n_classes)
    w_class = D.class_weights(counts, weight_mode)
    fit_ix, inner_ix = D.stratified_split(y, cfg2["inner_split_frac"], seed)
    w = w_class[y]
    params = {**cfg2["xgb"]["params"], "num_class": n_classes, "seed": seed, "nthread": int(nthread)}
    dfit = xgb.DMatrix(X[fit_ix], label=y[fit_ix], weight=w[fit_ix])
    dinn = xgb.DMatrix(X[inner_ix], label=y[inner_ix], weight=w[inner_ix])
    curves: dict = {}
    n_base = int(base.num_boosted_rounds()) if base is not None else 0
    bst = xgb.train(params, dfit, num_boost_round=int(rounds if base is not None else cfg2["xgb"]["num_boost_round"]),
                    evals=[(dfit, "train"), (dinn, "inner")], evals_result=curves,
                    early_stopping_rounds=cfg2["xgb"]["early_stopping_rounds"], verbose_eval=False, xgb_model=base)
    best = int(bst.best_iteration)
    sliced = bst[: best + 1]
    fit_s = time.monotonic() - t0
    vm1 = CR.vm_status()
    z = sliced.predict(dinn, output_margin=True).astype(np.float64)
    T = PM.fit_temperature(z, y[inner_ix], tuple(temperature_bounds)) if len(inner_ix) else 1.0
    return {"booster": sliced, "counts": counts.tolist(), "class_weights": w_class.tolist(),
            "zero_row_classes": [int(c) for c in np.flatnonzero(counts == 0)], "n_rows": int(len(y)),
            "n_fit": int(len(fit_ix)), "n_inner": int(len(inner_ix)), "best_iteration": best,
            "best_score": float(bst.best_score), "rounds_total": int(sliced.num_boosted_rounds()),
            "base_rounds": n_base, "new_rounds": int(sliced.num_boosted_rounds()) - n_base,
            "fit_seconds": round(fit_s, 3), "params": params, "temperature": float(T),
            "temperature_fitted_on": f"inner split ({len(inner_ix):,} rows)",
            "curves": {k: [float(v) for v in curves[k]["mlogloss"]] for k in ("train", "inner")},
            "peak_rss_mb": vm1["hwm_mb"] if reset_ok else float("nan"),
            "rss_before_mb": vm0["rss_mb"], "peak_rss_increase_mb": (vm1["hwm_mb"] - vm0["rss_mb"]) if reset_ok else float("nan"),
            "peak_rss_method": "VmHWM after clear_refs reset" if reset_ok else "unavailable"}


def predict_proba(booster, X: np.ndarray, nthread: int | None = None) -> np.ndarray:
    """Step 23's path: booster.predict on a DMatrix (softprob, T = 1). argmax == argmax of the calibrated softmax."""
    import xgboost as xgb
    if nthread is not None:
        booster.set_param({"nthread": int(nthread)})
    return booster.predict(xgb.DMatrix(X))


def routed_proba(models_by_group: dict, default, X: np.ndarray, group, nthread: int | None = None) -> np.ndarray:
    """ROUTED system: rows of group g scored by models_by_group[g] (if present) else by `default`."""
    group = np.asarray(group).astype(str)
    P = None
    assign = np.array([g if g in models_by_group else "__default__" for g in group], dtype=object)
    for key in dict.fromkeys(assign.tolist()):
        ix = np.flatnonzero(assign == key)
        m = models_by_group[key] if key != "__default__" else default
        p = predict_proba(m, X[ix], nthread)
        if P is None:
            P = np.empty((len(X), p.shape[1]))
        P[ix] = p
    return P if P is not None else np.zeros((0, 0))
