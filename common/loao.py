"""common/loao.py -- Phase 5A leave-one-attack-out Stage 1 (docs/V2_PREREG_PHASE5.md section 3). OFFLINE ONLY.

    nonrare, rare = heldout_classes(y_val, K, min_val_flows)        # attack classes by val support (Phase 2 rare rule)
    r = fit_without(X_tr, y_tr, K, k, seed, cfg2, nthread, weights)  # class k removed, contiguous local labels
    pred = predict_global(r["booster"], X_val, r["keep"], nthread)  # argmax, mapped back to class-map ids
    miss_mask(y_val, pred, k) / caught_mask(...) / outcome(...) / benign_sanity(...)

Training = the promoted Stage 1 configuration (common/cl_retrain.fit == step 22's train_one): class weights from this
training set's own counts (mode `weights`), seeded stratified inner split for early stopping, fixed nthread.
Local mapping: keep = the class-map ids != k in ascending order; local id i <-> global id keep[i]; benign (0) stays 0.
The class map is never edited. Stage 1 miss = true class k predicted benign; caught = true k predicted as another
attack (it still alerts). argmax == argmax of the calibrated softmax (a temperature does not change it).
"""

from __future__ import annotations

import numpy as np

from common import cl_retrain as RT
from common import phase2_metrics as PM

BENIGN = 0


def heldout_classes(y_val: np.ndarray, K: int, min_val_flows: int, benign: int = BENIGN) -> tuple[list[int], list[int]]:
    """(non-rare attack classes, rare attack classes): rare = < min_val_flows val flows (0 included)."""
    sup = np.bincount(np.asarray(y_val, np.int64), minlength=K)[:K]
    att = [c for c in range(K) if c != benign]
    return [c for c in att if sup[c] >= min_val_flows], [c for c in att if sup[c] < min_val_flows]


def keep_ids(K: int, k: int) -> np.ndarray:
    if not 0 <= k < K or k == BENIGN:
        raise ValueError(f"held-out class {k} must be an attack class id in [1, {K})")
    return np.array([c for c in range(K) if c != k], dtype=np.int64)


def to_local(y: np.ndarray, keep: np.ndarray) -> np.ndarray:
    lut = np.full(int(max(keep.max(), np.max(y, initial=0))) + 1, -1, dtype=np.int64)
    lut[keep] = np.arange(len(keep))
    out = lut[np.asarray(y, np.int64)]
    if (out < 0).any():
        raise ValueError(f"labels {sorted(set(np.asarray(y)[out < 0].tolist()))} are not in the kept classes {keep.tolist()}")
    return out


def to_global(pred_local: np.ndarray, keep: np.ndarray) -> np.ndarray:
    return np.asarray(keep)[np.asarray(pred_local, np.int64)]


def train_mask(y: np.ndarray, k: int) -> np.ndarray:
    return np.asarray(y) != k


def fit_without(X: np.ndarray, y: np.ndarray, K: int, k: int, seed: int, cfg2: dict, nthread: int,
                weights: str = "none") -> dict:
    keep = keep_ids(K, k)
    m = train_mask(y, k)
    yl = to_local(np.asarray(y)[m], keep)
    if (np.asarray(y)[m] == k).any():
        raise AssertionError("held-out class present in the training set")
    Xm = np.ascontiguousarray(X[m])
    r = RT.fit(Xm, yl, len(keep), weights, seed, cfg2, nthread)
    r["keep"] = keep
    r["held_out"] = int(k)
    r["train_counts_global"] = {int(c): int(n) for c, n in zip(keep, r["counts"])}
    r["n_removed"] = int((~m).sum())
    return r


def predict_global(booster, X: np.ndarray, keep: np.ndarray, nthread: int | None = None) -> np.ndarray:
    P = RT.predict_proba(booster, X, nthread)
    return to_global(P.argmax(1), keep)


def miss_mask(y: np.ndarray, pred: np.ndarray, k: int) -> np.ndarray:
    return (np.asarray(y) == k) & (np.asarray(pred) == BENIGN)


def caught_mask(y: np.ndarray, pred: np.ndarray, k: int) -> np.ndarray:
    return (np.asarray(y) == k) & (np.asarray(pred) != BENIGN)


def outcome(y: np.ndarray, pred: np.ndarray, k: int, names: list[str]) -> dict:
    """Where the val flows of held-out class k went."""
    y, pred = np.asarray(y), np.asarray(pred)
    m = y == k
    n = int(m.sum())
    as_cls = np.bincount(pred[m].astype(np.int64), minlength=len(names))[:len(names)]
    miss = int(miss_mask(y, pred, k).sum())
    caught = int(caught_mask(y, pred, k).sum())
    return {"class": names[k], "class_id": int(k), "n_val": n, "misses": miss, "caught": caught,
            "miss_share": miss / n if n else float("nan"), "caught_share": caught / n if n else float("nan"),
            "caught_as": {names[c]: int(as_cls[c]) for c in range(len(names)) if c != BENIGN and as_cls[c]},
            "predicted_as": {names[c]: int(as_cls[c]) for c in range(len(names)) if as_cls[c]}}


def benign_sanity(y: np.ndarray, pred: np.ndarray, session, start_ts, idle_gap: float, hours: float | None = None) -> dict:
    """Benign recall and flow-level false alarms (benign predicted as any attack) of a Stage 1 model on val."""
    y, pred = np.asarray(y), np.asarray(pred)
    b = y == BENIGN
    fa = int((b & (pred != BENIGN)).sum())
    h = hours if hours is not None else PM.benign_hours(np.asarray(session).astype(str), np.asarray(start_ts, np.int64),
                                                        b, idle_gap)
    return {"n_benign": int(b.sum()), "benign_recall": float((pred[b] == BENIGN).mean()) if b.any() else float("nan"),
            "fa_count": fa, "benign_hours": float(h), "fa_per_hour": fa / h if h > 0 else float("nan")}
