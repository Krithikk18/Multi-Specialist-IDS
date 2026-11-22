"""common/shap_perturb.py -- Phase 5B Part B: does TreeSHAP's ranking drive the prediction? (docs/V2_PREREG_PHASE5B.md
section 6). Pure numpy + an XGBoost booster.

    pos = sample(pred, K, per_class_cap, benign_cap, seed)        # per predicted class, without replacement, sorted
    C = tree_shap(booster, X)                                     # (n, K, F + 1): exact TreeSHAP (XGBoost pred_contribs)
    top, bot, rnd = select(phi, k, draws, seed)                   # phi = (n, F) SHAP of each row's predicted class
    R = perturbation(booster, X, pred, T, medians, top, bot, rnd)  # drops of the predicted class's calibrated probability
    verdict(R["drop_top"] - R["drop_rand"], ev)                    # FAITHFUL iff bootstrap CI lower bound > 0

Top-k = the k largest |SHAP| (ties: lower feature index first); bottom-k = the k smallest; random-k = `draws` seeded
draws of k features outside the top-k (drops averaged over the draws). Perturbation = replace the chosen features with
the per-feature train-benign median. Probability = softmax(margin / T)[predicted class].
"""

from __future__ import annotations

import numpy as np

from common import phase2_metrics as PM
from common import zeroday_metrics as ZM

FAITHFUL, NOT_FAITHFUL = "FAITHFUL", "NOT_FAITHFUL"


def sample(pred, K: int, per_class_cap: int, benign_cap: int, seed: int, benign: int = 0) -> np.ndarray:
    pred = np.asarray(pred)
    rng = np.random.default_rng(int(seed))
    out = []
    for c in range(K):
        ix = np.flatnonzero(pred == c)
        cap = benign_cap if c == benign else per_class_cap
        if len(ix):
            out.append(np.sort(rng.choice(ix, size=min(cap, len(ix)), replace=False)))
    return np.sort(np.concatenate(out)) if out else np.zeros(0, np.int64)


def tree_shap(booster, X: np.ndarray) -> np.ndarray:
    import xgboost as xgb
    C = booster.predict(xgb.DMatrix(X), pred_contribs=True)
    return C[:, None, :] if C.ndim == 2 else C


def class_phi(C: np.ndarray, pred) -> np.ndarray:
    """(n, F): each row's SHAP values for its predicted class (bias column dropped)."""
    pred = np.asarray(pred, np.int64)
    return C[np.arange(len(pred)), pred, :-1]


def select(phi: np.ndarray, k: int, draws: int, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(top (n, k), bottom (n, k), random (draws, n, k)) feature indices."""
    a = np.abs(np.asarray(phi, float))
    n, F = a.shape
    if F < 2 * k:
        raise ValueError(f"{F} features < 2k = {2 * k}")
    top = np.argsort(-a, axis=1, kind="stable")[:, :k]                 # stable: ties -> lower feature index first
    bot = np.argsort(a, axis=1, kind="stable")[:, :k]
    rng = np.random.default_rng(int(seed))
    rnd = np.empty((draws, n, k), np.int64)
    for i in range(n):
        pool = np.setdiff1d(np.arange(F), top[i])
        for d in range(draws):
            rnd[d, i] = rng.choice(pool, size=k, replace=False)
    return top, bot, rnd


def replace(X: np.ndarray, idx: np.ndarray, medians: np.ndarray) -> np.ndarray:
    """Copy of X with X[i, idx[i]] = medians[idx[i]] for every row i."""
    Xp = np.array(X, copy=True)
    r = np.arange(len(X))[:, None]
    Xp[r, idx] = np.asarray(medians, Xp.dtype)[idx]
    return Xp


def proba(booster, X: np.ndarray, T: float) -> np.ndarray:
    import xgboost as xgb
    z = booster.predict(xgb.DMatrix(X), output_margin=True).reshape(len(X), -1).astype(np.float64)
    return PM.softmax(z, T)


def perturbation(booster, X: np.ndarray, pred, T: float, medians: np.ndarray, top, bot, rnd) -> dict:
    pred = np.asarray(pred, np.int64)
    r = np.arange(len(X))
    P0 = proba(booster, X, T)
    p0 = P0[r, pred]

    def run(idx):
        P = proba(booster, replace(X, idx, medians), T)
        return p0 - P[r, pred], P.argmax(1) != pred

    dt, ft = run(top)
    db, fb = run(bot)
    dr = np.zeros(len(X))
    fr = np.zeros(len(X))
    for d in range(len(rnd)):
        a, f = run(rnd[d])
        dr += a / len(rnd)
        fr += f / len(rnd)
    return {"p0": p0, "drop_top": dt, "drop_bottom": db, "drop_rand": dr, "flip_top": ft, "flip_bottom": fb,
            "flip_rand": fr, "argmax_consistent": bool((P0.argmax(1) == pred).all())}


def verdict(diff, ev: dict) -> dict:
    c = ZM.bootstrap_mean_ci(diff, ev["bootstrap_resamples"], ev["bootstrap_seed"], ev["ci_level"])
    return {"verdict": FAITHFUL if (c["n"] > 0 and c["lo"] > 0) else NOT_FAITHFUL, "diff": c}
