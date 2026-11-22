"""tests/test_phase5b_tail_rule.py -- common/tail_rule.py (Phase 5B H-C3 primary detector, D165): the q grid; calibration
hits the target flag rate on the held-out rows (smallest such q); strictly-greater ties; any-feature OR logic;
monotone-transform invariance (same flags after log1p, order-statistic quantiles); seeded split determinism;
explanation output; per-group rules with fallback below min_group_benign. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_phase5b_tail_rule.py
"""

from __future__ import annotations

import copy
import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import context_config as CC  # noqa: E402
from common import tail_rule as TR  # noqa: E402

P = CC.load_phase5b_config(verify_pin=False)["tail"]


def _X(n=20000, F=6, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.poisson(5.0, size=(n, F)).astype(float)                    # count-like, many ties
    X[:, 0] = rng.lognormal(2.0, 1.0, n)                                # one continuous heavy-tailed feature
    return X


def test_q_grid():
    g = TR.q_grid(P)
    assert len(g) == P["q_grid"]["n"] >= 200 and np.all(np.diff(g) > 0)
    assert np.isclose(g[0], P["q_grid"]["lo"]) and np.isclose(g[-1], P["q_grid"]["hi"])
    assert np.allclose(np.diff(np.log(1 - g)), np.diff(np.log(1 - g))[0])   # log-spaced in 1 - q


def test_calibration_hits_target_smallest_q():
    X = _X()
    R = TR.fit(X, 0, P)
    fi, hi = TR.split(len(X), P["fit_share"], 0)
    assert R["met"] and R["hold_rate"] <= P["target_flag_rate"] and R["n_fit"] == len(fi) == 16000
    assert R["hold_rate"] == TR.flag(X[hi], R["t"]).mean()
    if R["q_index"] > 0:                                                # the next smaller q misses the target
        qprev = TR.q_grid(P)[R["q_index"] - 1]
        assert TR.flag(X[hi], TR.thresholds(X[fi], qprev)).mean() > P["target_flag_rate"]
    assert np.all(np.isin(R["t"][1:], X[fi][:, 1:]))                    # order statistic: thresholds are observed values
    p2 = copy.deepcopy(P)
    p2["target_flag_rate"] = 1e-9                                       # unreachable target -> largest q, met False
    R2 = TR.fit(X, 0, p2)
    assert not R2["met"] and R2["q_index"] == len(TR.q_grid(P)) - 1


def test_strictly_greater_and_any_feature():
    t = np.array([5.0, 10.0])
    X = np.array([[5.0, 10.0], [5.0001, 0.0], [0.0, 10.5], [6.0, 11.0], [4.0, 9.0]])
    assert TR.flag(X, t).tolist() == [False, True, True, True, False]


def test_monotone_transform_invariance():
    X = _X(seed=3)
    R = TR.fit(X, 1, P)
    Rl = TR.fit(np.log1p(X), 1, P)
    assert R["q"] == Rl["q"] and np.allclose(np.log1p(R["t"]), Rl["t"])
    Y = _X(n=5000, seed=9) * 1.5
    assert np.array_equal(TR.flag(Y, R["t"]), TR.flag(np.log1p(Y), Rl["t"]))


def test_seeded_split_determinism():
    X = _X(n=3000)
    a, b = TR.split(3000, 0.8, 7), TR.split(3000, 0.8, 7)
    assert np.array_equal(a[0], b[0]) and not np.array_equal(a[0], TR.split(3000, 0.8, 8)[0])
    assert len(np.intersect1d(*a)) == 0 and len(a[0]) + len(a[1]) == 3000
    R1, R2 = TR.fit(X, 7, P), TR.fit(X, 7, P)
    assert R1["q"] == R2["q"] and np.array_equal(R1["t"], R2["t"])


def test_explanation():
    t = np.array([5.0, 10.0, 0.0])
    X = np.array([[20.0, 11.0, 0.0], [1.0, 1.0, 0.0], [6.0, 40.0, 2.0]])
    E = TR.explain(X, t, ["a", "b", "c"])
    assert [r["row"] for r in E["rows"]] == [0, 2]
    assert E["rows"][0]["fired"] == [("a", 4.0), ("b", 1.1)]
    assert E["rows"][1]["fired"][0] == ("c", float("inf")) and E["rows"][1]["fired"][1] == ("b", 4.0)
    assert E["fire_counts"] == {"a": 2, "b": 2, "c": 1}


def test_per_group_fallback():
    rng = np.random.default_rng(0)
    X = np.r_[rng.poisson(3, (15000, 3)), rng.poisson(30, (12000, 3)), rng.poisson(5, (500, 3))].astype(float)
    g = np.array(["A"] * 15000 + ["B"] * 12000 + ["C"] * 500)
    G = TR.fit_groups(X, g, 0, P)
    assert G["route"] == {"A": "A", "B": "B", "C": TR.GLOBAL_KEY} and G["fallback"] == [{"group": "C", "n": 500}]
    assert G["rules"]["B"]["t"][0] > G["rules"]["A"]["t"][0]             # each group has its own tail
    Y = np.array([[20.0, 0, 0], [20.0, 0, 0], [20.0, 0, 0]])
    f, key = TR.flag_groups(G, Y, np.array(["A", "B", "NEW"]))
    assert f.tolist()[:2] == [True, False] and key.tolist() == ["A", "B", TR.GLOBAL_KEY]


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items(), key=lambda kv: kv[1].__code__.co_firstlineno
                                       if callable(kv[1]) and hasattr(kv[1], "__code__") else 0)
             if n.startswith("test_") and callable(f)]
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
