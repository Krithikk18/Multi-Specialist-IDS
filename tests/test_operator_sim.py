"""tests/test_operator_sim.py -- common/operator_sim.py: noise 0 = ground truth; noise flips only to OTHER classes at
about the given rate; budget keeps alert / random at their queue proportions, uniform within reason; budget >= queue =
everything; seeded; bad inputs refused. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_operator_sim.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import operator_sim as OP  # noqa: E402

K = 4


def _queue(n=20_000, seed=3):
    rng = np.random.default_rng(seed)
    truth = rng.integers(0, K, n)
    reason = np.where(rng.random(n) < 0.9, "alert", "random").astype(object)
    return truth, reason


def test_noise_zero_is_ground_truth_whole_queue():
    t, r = _queue()
    L = OP.simulate(t, r, K)
    assert (L["sel"] == np.arange(len(t))).all() and (L["label"] == t).all() and not L["flipped"].any()


def test_noise_flips_to_other_class_at_rate():
    t, r = _queue(50_000)
    L = OP.simulate(t, r, K, noise=0.02, seed=0)
    f = L["flipped"]
    assert (L["label"][f] != t[f]).all() and (L["label"][~f] == t[~f]).all()
    assert abs(f.mean() - 0.02) < 0.004, f.mean()
    other = L["label"][f]
    assert len(set(other.tolist())) == K                        # every class reachable as a flip target


def test_budget_proportions_and_uniform_within_reason():
    t, r = _queue()
    L = OP.simulate(t, r, K, budget=1000, seed=0)
    assert len(L["sel"]) == 1000
    na, nr = int((r == "alert").sum()), int((r == "random").sum())
    assert L["n_alert"] == round(1000 * na / (na + nr)) and L["n_alert"] + L["n_random"] == 1000
    rs = r[L["sel"]]
    assert int((rs == "alert").sum()) == L["n_alert"]
    assert (np.diff(L["sel"]) > 0).all()
    assert (L["label"] == t[L["sel"]]).all()


def test_budget_ge_queue_takes_all():
    t, r = _queue(500)
    assert len(OP.simulate(t, r, K, budget=500)["sel"]) == 500
    assert len(OP.simulate(t, r, K, budget=10_000)["sel"]) == 500


def test_budget_split_edge_cases():
    assert OP.budget_split(10, 0, 5) == (5, 0)
    assert OP.budget_split(0, 10, 5) == (0, 5)
    assert OP.budget_split(3, 7, None) == (3, 7)


def test_seeded():
    t, r = _queue()
    a = OP.simulate(t, r, K, noise=0.05, budget=3000, seed=7)
    b = OP.simulate(t, r, K, noise=0.05, budget=3000, seed=7)
    c = OP.simulate(t, r, K, noise=0.05, budget=3000, seed=8)
    assert (a["sel"] == b["sel"]).all() and (a["label"] == b["label"]).all()
    assert not ((a["sel"] == c["sel"]).all() and (a["label"] == c["label"]).all())


def test_bad_inputs():
    t, r = _queue(10)
    for kw in ({"noise": 1.0}, {"noise": -0.1}):
        try:
            OP.simulate(t, r, K, **kw)
            raise AssertionError(f"accepted {kw}")
        except ValueError:
            pass
    try:
        OP.simulate(np.array([0, 5]), np.array(["alert", "alert"], dtype=object), K)
        raise AssertionError("out-of-range truth accepted")
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
