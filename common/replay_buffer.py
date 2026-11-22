"""common/replay_buffer.py -- the fixed, seeded, stratified replay buffer (docs/V2_PREREG_PHASE4.md section 4).

    B = select(label_id, group, frac=0.25, min_class_rows=1000, seed=0)     # ascending train row positions
    B["pos"], B["strata"]                                                   # strata: per (class, group) total / kept

Rule: strata = class x group of the ORIGINAL training data (the train split the deployed model was trained on). A class
with fewer than min_class_rows train rows in total keeps ALL its rows; otherwise each of its (class, group) strata keeps
max(1, round(frac x n)) rows drawn uniformly without replacement (numpy default_rng(seed), one permutation per stratum
in sorted stratum order). One buffer, written once with a manifest; every arm that replays uses that same buffer
(a model's replay rows = the buffer rows that belong to its own training set).
"""

from __future__ import annotations

import hashlib

import numpy as np


def select(label_id, group, frac: float, min_class_rows: int, seed: int) -> dict:
    y = np.asarray(label_id, dtype=np.int64)
    g = np.asarray(group).astype(str)
    if len(y) != len(g):
        raise ValueError("label_id and group lengths differ")
    if not 0 < frac <= 1:
        raise ValueError(f"frac {frac} outside (0, 1]")
    rng = np.random.default_rng(seed)
    cls_n = {int(c): int(n) for c, n in zip(*np.unique(y, return_counts=True))}
    out, strata = [], []
    keys = sorted({(int(a), str(b)) for a, b in zip(y.tolist(), g.tolist())})
    for c, gg in keys:
        ix = np.flatnonzero((y == c) & (g == gg))
        if cls_n[c] < min_class_rows:
            k, rule = len(ix), "all (class < min_class_rows)"
        else:
            k, rule = max(1, int(round(frac * len(ix)))), f"max(1, round({frac} x n))"
        sel = ix if k == len(ix) else np.sort(rng.permutation(ix)[:k])
        out.append(sel)
        strata.append({"class_id": c, "group": gg, "n": int(len(ix)), "kept": int(k), "rule": rule})
    pos = np.sort(np.concatenate(out)).astype(np.int64) if out else np.zeros(0, np.int64)
    return {"pos": pos, "strata": strata, "frac": float(frac), "min_class_rows": int(min_class_rows), "seed": int(seed),
            "pos_sha256": hashlib.sha256(pos.tobytes()).hexdigest()}
