"""common/review_queue.py -- the operator review queue (docs/V2_PREREG_PHASE4.md section 2).

    Q = build_queue(alert, rate, seed)          # positions + reasons over the runtime's prediction rows
    Q = build_queue(alert, 0.0, seed)           # the feedback-bias variant: alerts only

Queue = every alerted flow (reason "alert") + a seeded uniform random sample of the non-alerted flows (reason
"random") of exactly round(rate x n_non_alerted) rows (numpy default_rng(seed), without replacement). Output order =
the prediction rows' order (ascending position). Pure function of (alert flags, rate, seed).
"""

from __future__ import annotations

import numpy as np

REASONS = ("alert", "random")


def n_random(n_non_alerted: int, rate: float) -> int:
    return int(round(float(rate) * int(n_non_alerted)))


def build_queue(alert, rate: float, seed: int) -> dict:
    """{"pos": ascending row positions, "reason": "alert" / "random" per queued row, counts}."""
    alert = np.asarray(alert, dtype=bool)
    if not 0.0 <= float(rate) <= 1.0:
        raise ValueError(f"random_review_rate {rate} outside [0, 1]")
    a = np.flatnonzero(alert)
    na = np.flatnonzero(~alert)
    k = n_random(len(na), rate)
    rng = np.random.default_rng(seed)
    r = np.sort(rng.choice(na, size=k, replace=False)) if k else np.zeros(0, np.int64)
    pos = np.concatenate([a, r]).astype(np.int64)
    reason = np.array(["alert"] * len(a) + ["random"] * len(r), dtype=object)
    o = np.argsort(pos, kind="stable")
    return {"pos": pos[o], "reason": reason[o], "n_alert": int(len(a)), "n_random": int(len(r)),
            "n_non_alerted": int(len(na)), "rate": float(rate), "seed": int(seed)}
