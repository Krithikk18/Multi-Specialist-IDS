"""tests/test_replay_buffer.py -- common/replay_buffer.py: per class x group stratum max(1, round(frac x n)) rows; every
row of a class with < min_class_rows rows; positions ascending, unique and inside their stratum; deterministic for a
seed, different for another seed; bad inputs refused. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_replay_buffer.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import replay_buffer as RB  # noqa: E402


def _data(seed=0):
    rng = np.random.default_rng(seed)
    y = np.concatenate([np.zeros(6000), np.ones(4000), np.full(95, 2), np.full(1500, 3)]).astype(int)
    g = rng.choice(["G1", "G2", "GEN"], size=len(y), p=[0.6, 0.35, 0.05])
    o = rng.permutation(len(y))
    return y[o], g[o]


def test_stratification_counts():
    y, g = _data()
    B = RB.select(y, g, 0.25, 1000, 0)
    sel_y, sel_g = y[B["pos"]], g[B["pos"]]
    for s in B["strata"]:
        n = int(((y == s["class_id"]) & (g == s["group"])).sum())
        k = int(((sel_y == s["class_id"]) & (sel_g == s["group"])).sum())
        assert s["n"] == n and s["kept"] == k
        if s["class_id"] == 2:                                     # 95 rows < 1,000: all kept
            assert k == n
        else:
            assert k == max(1, round(0.25 * n)), (s, k)


def test_small_class_kept_whole():
    y, g = _data()
    B = RB.select(y, g, 0.25, 1000, 0)
    assert set(np.flatnonzero(y == 2)) <= set(B["pos"].tolist())
    B2 = RB.select(y, g, 0.25, 50, 0)                              # threshold below 95 -> sampled
    assert int((y[B2["pos"]] == 2).sum()) < 95


def test_positions_valid_and_deterministic():
    y, g = _data()
    a, b, c = RB.select(y, g, 0.25, 1000, 0), RB.select(y, g, 0.25, 1000, 0), RB.select(y, g, 0.25, 1000, 1)
    assert (np.diff(a["pos"]) > 0).all() and a["pos"].min() >= 0 and a["pos"].max() < len(y)
    assert (a["pos"] == b["pos"]).all() and a["pos_sha256"] == b["pos_sha256"]
    assert a["pos_sha256"] != c["pos_sha256"] and len(a["pos"]) == len(c["pos"])


def test_tiny_stratum_keeps_one():
    y = np.array([0] * 2000 + [1] * 1999 + [1])
    g = np.array(["A"] * 2000 + ["A"] * 1999 + ["B"])
    B = RB.select(y, g, 0.25, 1000, 0)
    assert int(((y[B["pos"]] == 1) & (g[B["pos"]] == "B")).sum()) == 1


def test_bad_inputs():
    for args in ((np.zeros(3), np.array(["a", "b"]), 0.25), (np.zeros(3), np.array(["a"] * 3), 0.0)):
        try:
            RB.select(*args, 1000, 0)
            raise AssertionError("accepted")
        except ValueError:
            pass


def main() -> int:
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}\n{traceback.format_exc()}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
