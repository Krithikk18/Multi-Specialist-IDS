"""common/normal_model.py -- Phase 5A models of normal traffic (docs/V2_PREREG_PHASE5.md section 4). OFFLINE ONLY.

    Z, nonfinite = prepare(X, feats)                     # V1 NaN / +-inf -> 0 policy (counted), then sign(x) log1p|x|
    A = fit_arm("PER_GROUP_NORMAL", Z, g, seed, p, global_rec=G["models"][GLOBAL_KEY])
    s, thr, key = score_arm(A, Z_val, g_val, p)          # anomaly score (higher = more anomalous), row threshold, model
    flag = s > thr

Detector: sklearn IsolationForest (n_estimators, max_samples = min(cap, n), max_features, bootstrap, random_state =
seed, fixed n_jobs; contamination unused). Anomaly score = -score_samples(x). Threshold = the threshold_quantile
(linear) of the model's anomaly scores on ALL its own training rows; flagged iff score > threshold.
Arms:
  GLOBAL_NORMAL        one model on all train-benign rows
  PER_GROUP_NORMAL     one model per group on that group's rows; a group with < min_group_benign rows -> the GLOBAL
                       model + threshold of the same seed (fallback, logged); a scoring group absent from training ->
                       the global model (logged)
  RANDOM_GROUP_NORMAL  the per-group rule on a seeded permutation of the rows' group labels (same group sizes); val
                       rows use the model keyed by their real group label (report-only control)
No class, group or feature names are used: groups come from the caller's array.
"""

from __future__ import annotations

import io
import time

import numpy as np
import pandas as pd

GLOBAL_KEY = "__global__"
GLOBAL, PER_GROUP, RANDOM_GROUP = "GLOBAL_NORMAL", "PER_GROUP_NORMAL", "RANDOM_GROUP_NORMAL"


# --------------------------------------------------------------------------- input
def signed_log1p(X) -> np.ndarray:
    """sign(x) * log1p(|x|), element-wise, float64 (odd, monotone, 0 -> 0)."""
    X = np.asarray(X, dtype=np.float64)
    return np.sign(X) * np.log1p(np.abs(X))


def nonfinite_counts(X: np.ndarray, feats: list[str]) -> dict:
    """{feature: {"nan": n, "inf": n}} for the features with any non-finite value."""
    X = np.asarray(X, dtype=np.float64)
    nan, inf = np.isnan(X).sum(0), np.isinf(X).sum(0)
    return {f: {"nan": int(nan[i]), "inf": int(inf[i])} for i, f in enumerate(feats) if nan[i] or inf[i]}


def clean(X: np.ndarray, feats: list[str]) -> np.ndarray:
    """The V1 / Stage 1 data policy (common/schemas.apply_nan_inf_policy: NaN, +-inf -> 0), imported, not re-invented."""
    from common.schemas import apply_nan_inf_policy
    df = pd.DataFrame(np.asarray(X, dtype=np.float64), columns=list(feats))
    return apply_nan_inf_policy(df, list(feats))[list(feats)].to_numpy(np.float64)


def prepare(X: np.ndarray, feats: list[str]) -> tuple[np.ndarray, dict]:
    """(transformed matrix, non-finite counts before cleaning)."""
    counts = nonfinite_counts(X, feats)
    Xc = clean(X, feats) if counts else np.asarray(X, dtype=np.float64)
    return signed_log1p(Xc), counts


# --------------------------------------------------------------------------- one detector
def make_detector(p: dict, n: int, seed: int):
    from sklearn.ensemble import IsolationForest
    return IsolationForest(n_estimators=int(p["n_estimators"]), max_samples=int(min(p["max_samples_cap"], n)),
                           max_features=float(p["max_features"]), bootstrap=bool(p["bootstrap"]),
                           random_state=int(seed), n_jobs=int(p["n_jobs"]))


def anomaly_score(model, Z: np.ndarray, chunk: int) -> np.ndarray:
    """-score_samples (higher = more anomalous), computed in row chunks (memory); float64."""
    out = np.empty(len(Z), dtype=np.float64)
    for a in range(0, len(Z), max(1, int(chunk))):
        out[a:a + chunk] = -model.score_samples(Z[a:a + chunk])
    return out


def threshold(scores: np.ndarray, q: float) -> float:
    return float(np.quantile(np.asarray(scores, dtype=np.float64), q, method="linear"))


def model_bytes(model) -> bytes:
    import joblib
    b = io.BytesIO()
    joblib.dump(model, b)
    return b.getvalue()


def fit_one(Z: np.ndarray, seed: int, p: dict, keep_scores: bool = True) -> dict:
    """Fit one detector on rows Z; threshold on its own training scores."""
    if len(Z) < 2:
        raise ValueError(f"cannot fit a model of normal on {len(Z)} rows")
    t0 = time.monotonic()
    m = make_detector(p, len(Z), seed)
    m.fit(Z)
    fit_s = time.monotonic() - t0
    s = anomaly_score(m, Z, p["score_chunk_rows"])
    thr = threshold(s, p["threshold_quantile"])
    rec = {"model": m, "threshold": thr, "n_train": int(len(Z)), "fit_seconds": round(fit_s, 4),
           "max_samples": int(min(p["max_samples_cap"], len(Z))), "seed": int(seed),
           "train_flag_rate": float((s > thr).mean())}
    if keep_scores:
        rec["train_scores"] = s
    return rec


# --------------------------------------------------------------------------- arms
def fit_groups(arm: str, g: np.ndarray, seed: int, p: dict) -> np.ndarray:
    """Group labels the arm FITS on: the real ones, or (RANDOM_GROUP) a seeded permutation of them (same sizes)."""
    g = np.asarray(g).astype(str)
    if arm == RANDOM_GROUP:
        rng = np.random.default_rng(int(p["random_group_perm_seed_base"]) + int(seed))
        return g[rng.permutation(len(g))]
    return g


def fit_arm(arm: str, Z: np.ndarray, g: np.ndarray, seed: int, p: dict, global_rec: dict | None = None,
            keep_scores: bool = True) -> dict:
    """{"arm", "seed", "models": {key: rec}, "route": {group: key}, "fallback": [{group, n}], "fit_group": array,
    "rows": {key: positions}}. Per-group arms need the same-seed GLOBAL record for fallback groups."""
    g = np.asarray(g).astype(str)
    if arm == GLOBAL:
        rec = fit_one(Z, seed, p, keep_scores)
        return {"arm": arm, "seed": int(seed), "models": {GLOBAL_KEY: rec}, "route": {x: GLOBAL_KEY for x in sorted(set(g))},
                "fallback": [], "fit_group": g, "rows": {GLOBAL_KEY: np.arange(len(g))}}
    if arm not in (PER_GROUP, RANDOM_GROUP):
        raise ValueError(f"unknown arm {arm!r}")
    fg = fit_groups(arm, g, seed, p)
    models, route, fallback, rows = {}, {}, [], {}
    for grp in sorted(set(fg.tolist())):
        ix = np.flatnonzero(fg == grp)
        if len(ix) < int(p["min_group_benign"]):
            if global_rec is None:
                raise ValueError(f"group {grp!r} ({len(ix)} rows) needs the GLOBAL fallback, none given")
            route[grp] = GLOBAL_KEY
            fallback.append({"group": grp, "n": int(len(ix))})
            continue
        models[grp] = fit_one(Z[ix], seed, p, keep_scores)
        route[grp] = grp
        rows[grp] = ix
    if fallback:
        models[GLOBAL_KEY] = global_rec
        rows[GLOBAL_KEY] = np.arange(len(g))
    return {"arm": arm, "seed": int(seed), "models": models, "route": route, "fallback": fallback, "fit_group": fg,
            "rows": rows, "global_rec": global_rec}


def route_rows(A: dict, g: np.ndarray) -> tuple[np.ndarray, list]:
    """Model key per scoring row; groups the arm never saw go to the global model (returned for logging)."""
    g = np.asarray(g).astype(str)
    unseen = sorted(set(g.tolist()) - set(A["route"]))
    key = np.array([A["route"].get(x, GLOBAL_KEY) for x in g], dtype=object)
    if unseen and GLOBAL_KEY not in A["models"]:
        if A.get("global_rec") is None:
            raise ValueError(f"groups {unseen} unseen in training and no global model to fall back to")
        A["models"][GLOBAL_KEY] = A["global_rec"]
    return key, unseen


def score_arm(A: dict, Z: np.ndarray, g: np.ndarray, p: dict) -> tuple[np.ndarray, np.ndarray, np.ndarray, list]:
    """(anomaly scores, per-row threshold, per-row model key, unseen groups) for rows Z with groups g."""
    key, unseen = route_rows(A, g)
    s = np.empty(len(Z), dtype=np.float64)
    thr = np.empty(len(Z), dtype=np.float64)
    for k in dict.fromkeys(key.tolist()):
        ix = np.flatnonzero(key == k)
        rec = A["models"][k]
        s[ix] = anomaly_score(rec["model"], Z[ix], p["score_chunk_rows"])
        thr[ix] = rec["threshold"]
    return s, thr, key, unseen


def flags(scores: np.ndarray, thr: np.ndarray) -> np.ndarray:
    return np.asarray(scores) > np.asarray(thr)


# --------------------------------------------------------------------------- checks
def threshold_check(A: dict, Z: np.ndarray, seed: int, p: dict, tc: dict) -> dict:
    """Per model of the arm (its own training rows): refit on a seeded fit_frac share, threshold there, flag rate on
    the held-out rest. Report-only (the in-sample threshold's bias)."""
    out, fl, n = {}, 0, 0
    for k, ix in A["rows"].items():
        if k == GLOBAL_KEY and A["arm"] != GLOBAL:
            continue                                                   # the fallback model is checked in its own arm
        rng = np.random.default_rng(int(tc["split_seed_base"]) + int(seed))
        perm = rng.permutation(ix)
        nf = int(round(float(tc["fit_frac"]) * len(perm)))
        fit_ix, hold_ix = np.sort(perm[:nf]), np.sort(perm[nf:])
        r = fit_one(Z[fit_ix], seed, p, keep_scores=False)
        h = anomaly_score(r["model"], Z[hold_ix], p["score_chunk_rows"])
        f = int((h > r["threshold"]).sum())
        out[k] = {"n_fit": int(len(fit_ix)), "n_held_out": int(len(hold_ix)), "threshold_fit": r["threshold"],
                  "held_out_flagged": f, "held_out_flag_rate": f / len(hold_ix) if len(hold_ix) else float("nan")}
        fl, n = fl + f, n + len(hold_ix)
    return {"per_model": out, "held_out_flagged": int(fl), "held_out_n": int(n),
            "held_out_flag_rate": fl / n if n else float("nan"), "nominal": 1.0 - float(p["threshold_quantile"])}


def summary_record(A: dict) -> dict:
    """JSON-able description of an arm fit (no model objects, no arrays)."""
    return {"arm": A["arm"], "seed": A["seed"], "route": A["route"], "fallback": A["fallback"],
            "models": {k: {kk: v for kk, v in r.items() if kk not in ("model", "train_scores")}
                       for k, r in A["models"].items()},
            "fit_group_sizes": {k: int(v) for k, v in zip(*np.unique(A["fit_group"], return_counts=True))}}
