"""common/tail_rule.py -- Phase 5B H-C3 primary model of normal: per-feature upper-tail rule with a held-out-benign
threshold (docs/V2_PREREG_PHASE5B.md section 5; D165).

    R = fit(X_benign, seed, p)                 # seeded fit / held-out split, one shared q calibrated on the held-out part
    flags = flag(X, R["t"])                    # x_j > t_j for ANY feature j (strictly greater)
    E = explain(X, R["t"], features)           # per flagged row: the features that fired and x_j / t_j
    G = fit_groups(X, groups, seed, p)         # per-group variant (report-only); small groups -> the global rule
    flags_g, key = flag_groups(G, X, groups)

Rule. Split the benign rows (seeded with the model seed; fit_share to the fit part). For a quantile level q, t_j(q) = the
q-quantile of feature j on the fit part, as an ORDER STATISTIC (numpy method "higher": t_j is an observed value), so the
flags are exactly invariant to any strictly increasing transform of the features. Calibration: the smallest q of the
pinned grid whose flag rate on the held-out part is <= target_flag_rate (the flag rate is non-increasing in q); if no q
meets the target, the largest q is used and `met` is False. No class, group or feature name is used here.
"""

from __future__ import annotations

import numpy as np

GLOBAL_KEY = "__global__"


def q_grid(p: dict) -> np.ndarray:
    """Ascending q in [lo, hi], log-spaced in (1 - q)."""
    g = p["q_grid"]
    return np.sort(1.0 - np.geomspace(1.0 - float(g["lo"]), 1.0 - float(g["hi"]), int(g["n"])))


def split(n: int, frac: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    perm = np.random.default_rng(int(seed)).permutation(n)
    k = int(round(float(frac) * n))
    return np.sort(perm[:k]), np.sort(perm[k:])


def thresholds(X: np.ndarray, q, method: str = "higher") -> np.ndarray:
    return np.quantile(np.asarray(X, dtype=np.float64), q, axis=0, method=method)


def flag(X: np.ndarray, t: np.ndarray) -> np.ndarray:
    return (np.asarray(X, dtype=np.float64) > np.asarray(t, dtype=np.float64)[None, :]).any(1)


def calibrate(Xfit: np.ndarray, Xhold: np.ndarray, grid: np.ndarray, target: float, method: str = "higher") -> dict:
    T = thresholds(Xfit, grid, method)                                 # (G, F)
    Xh = np.asarray(Xhold, dtype=np.float64)
    rates = np.array([float(flag(Xh, T[i]).mean()) if len(Xh) else 0.0 for i in range(len(grid))])
    ok = np.flatnonzero(rates <= target)
    i = int(ok[0]) if len(ok) else len(grid) - 1
    return {"q": float(grid[i]), "q_index": i, "t": T[i], "hold_rate": float(rates[i]), "met": bool(len(ok)),
            "rates": rates}


def fit(X: np.ndarray, seed: int, p: dict) -> dict:
    X = np.asarray(X, dtype=np.float64)
    fi, hi = split(len(X), p["fit_share"], seed)
    C = calibrate(X[fi], X[hi], q_grid(p), float(p["target_flag_rate"]), p["quantile_method"])
    return {"q": C["q"], "q_index": C["q_index"], "t": C["t"], "hold_rate": C["hold_rate"], "met": C["met"],
            "n_fit": int(len(fi)), "n_hold": int(len(hi)), "seed": int(seed),
            "hold_flagged": int(round(C["hold_rate"] * len(hi)))}


def explain(X: np.ndarray, t: np.ndarray, features: list[str]) -> dict:
    """Per flagged row: {"row", "fired": [(feature, x / t), ...] sorted by ratio}; and fire counts per feature."""
    X = np.asarray(X, dtype=np.float64)
    t = np.asarray(t, dtype=np.float64)
    F = X > t[None, :]
    rows = np.flatnonzero(F.any(1))
    with np.errstate(divide="ignore", invalid="ignore"):
        ratio = np.where(t[None, :] > 0, X / t[None, :], np.inf)
    out = []
    for r in rows:
        j = np.flatnonzero(F[r])
        j = j[np.argsort(-ratio[r, j], kind="stable")]
        out.append({"row": int(r), "fired": [(features[k], float(ratio[r, k])) for k in j]})
    counts = {features[k]: int(F[:, k].sum()) for k in range(F.shape[1]) if F[:, k].any()}
    return {"rows": out, "fire_counts": dict(sorted(counts.items(), key=lambda kv: -kv[1]))}


def fit_groups(X: np.ndarray, groups, seed: int, p: dict, global_rule: dict | None = None) -> dict:
    """Per-group rules (groups with >= min_group_benign rows); smaller groups use the global rule (logged)."""
    X = np.asarray(X, dtype=np.float64)
    g = np.asarray(groups).astype(str)
    G = global_rule if global_rule is not None else fit(X, seed, p)
    rules, route, fallback = {GLOBAL_KEY: G}, {}, []
    for grp in sorted(set(g.tolist())):
        ix = np.flatnonzero(g == grp)
        if len(ix) < int(p["min_group_benign"]):
            route[grp] = GLOBAL_KEY
            fallback.append({"group": grp, "n": int(len(ix))})
        else:
            rules[grp] = fit(X[ix], seed, p)
            route[grp] = grp
    return {"rules": rules, "route": route, "fallback": fallback}


def flag_groups(G: dict, X: np.ndarray, groups) -> tuple[np.ndarray, np.ndarray]:
    g = np.asarray(groups).astype(str)
    key = np.array([G["route"].get(x, GLOBAL_KEY) for x in g], dtype=object)
    out = np.zeros(len(g), bool)
    for k in dict.fromkeys(key.tolist()):
        ix = np.flatnonzero(key == k)
        out[ix] = flag(np.asarray(X)[ix], G["rules"][k]["t"])
    return out, key
