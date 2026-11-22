"""common/operator_sim.py -- the simulated operator (docs/V2_PREREG_PHASE4.md section 3). Labels come from ground truth.

    L = simulate(truth, reason, n_classes, noise=0.0, budget=None, seed=0)
    L["sel"]       ascending positions (into the queue) that were labelled
    L["label"]     the operator's class id per labelled item
    L["flipped"]   True where noise changed the label

Budget (None = unlimited = the whole queue): n_alert = round(budget x alerts / queue), n_random = budget - n_alert
(each capped at what the queue holds), each drawn uniformly without replacement within its reason.
Noise: each labelled item independently, with probability `noise`, gets a uniformly random OTHER class:
(truth + U{1, .., K-1}) mod K. One numpy default_rng(seed) stream: budget draws first (alert, then random), then noise.
"""

from __future__ import annotations

import numpy as np


def budget_split(n_alert: int, n_random: int, budget: int | None) -> tuple[int, int]:
    n = n_alert + n_random
    if budget is None or budget >= n:
        return n_alert, n_random
    ka = int(round(budget * n_alert / n)) if n else 0
    ka = min(ka, n_alert)
    kr = min(budget - ka, n_random)
    return ka, kr


def simulate(truth, reason, n_classes: int, noise: float = 0.0, budget: int | None = None, seed: int = 0) -> dict:
    truth = np.asarray(truth, dtype=np.int64)
    reason = np.asarray(reason, dtype=object)
    if len(truth) != len(reason):
        raise ValueError("truth and reason lengths differ")
    if not 0.0 <= noise < 1.0:
        raise ValueError(f"noise {noise} outside [0, 1)")
    if n_classes < 2:
        raise ValueError("need >= 2 classes")
    if len(truth) and (truth.min() < 0 or truth.max() >= n_classes):
        raise ValueError("truth ids outside [0, n_classes)")
    rng = np.random.default_rng(seed)
    ia, ir = np.flatnonzero(reason == "alert"), np.flatnonzero(reason == "random")
    ka, kr = budget_split(len(ia), len(ir), budget)
    sa = ia if ka == len(ia) else np.sort(rng.choice(ia, size=ka, replace=False))
    sr = ir if kr == len(ir) else np.sort(rng.choice(ir, size=kr, replace=False))
    sel = np.sort(np.concatenate([sa, sr]).astype(np.int64))
    lab = truth[sel].copy()
    flip = rng.random(len(sel)) < noise if noise > 0 else np.zeros(len(sel), dtype=bool)
    if flip.any():
        lab[flip] = (lab[flip] + rng.integers(1, n_classes, size=int(flip.sum()))) % n_classes
    return {"sel": sel, "label": lab, "flipped": flip, "n_alert": int(ka), "n_random": int(kr),
            "noise": float(noise), "budget": budget, "seed": int(seed)}
