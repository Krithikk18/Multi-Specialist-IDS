"""tests/test_phase2_4_calibrate.py -- Phase 2 step 4: temperature scaling, ECE / Brier / reliability and
24_calibrate.py's stratified cross-fit (no row scored by a temperature fitted on it). Synthetic data only.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_phase2_4_calibrate.py
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase2_metrics as PM  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("cal24", REPO / "24_calibrate.py")
C24 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C24)


def _synthetic(T_true=2.5, n=20000, K=4, seed=0):
    """Logits whose labels are drawn from softmax(z / T_true): the NLL-optimal temperature is ~T_true."""
    rng = np.random.default_rng(seed)
    z = rng.normal(scale=4.0, size=(n, K))
    P = PM.softmax(z, T_true)
    y = np.array([rng.choice(K, p=p) for p in P])
    return z, y


def test_fit_temperature_recovers_truth():
    z, y = _synthetic(2.5)
    T = PM.fit_temperature(z, y, (0.05, 20))
    assert abs(T - 2.5) < 0.15, T
    z2, y2 = _synthetic(0.5, seed=1)
    assert abs(PM.fit_temperature(z2, y2, (0.05, 20)) - 0.5) < 0.05


def test_temperature_one_is_identity_and_bounds_hold():
    z, y = _synthetic(1.0, n=500)
    e = np.exp(z - z.max(1, keepdims=True))
    assert np.allclose(PM.softmax(z, 1.0), e / e.sum(1, keepdims=True))
    zs = np.c_[np.full(50, 30.0), np.zeros((50, 3))]                 # perfectly separated -> T wants -> 0
    T = PM.fit_temperature(zs, np.zeros(50, int), (0.05, 20))
    assert 0.05 <= T < 0.06, T                                        # bounded search ends at the lower bound


def test_ece_and_brier_known_values():
    P = np.array([[0.9, 0.1], [0.9, 0.1], [0.6, 0.4], [0.6, 0.4], [0.6, 0.4]])
    y = np.array([0, 1, 0, 0, 1])
    # bins: confidence 0.9 (2 rows, acc 0.5), 0.6 (3 rows, acc 2/3) -> ECE = 0.4*0.4 + 0.6*(0.6-2/3 -> 0.0667)
    assert abs(PM.ece_top(P, y, 15) - (0.4 * 0.4 + 0.6 * (2 / 3 - 0.6))) < 1e-9
    assert abs(PM.brier(np.array([[1.0, 0.0], [0.5, 0.5]]), np.array([0, 1])) - (0 + 0.5) / 2) < 1e-12
    ec = PM.ece_classwise(np.array([[0.7, 0.3, 0.0]] * 4), np.array([0, 0, 0, 1]), 10)
    assert np.isnan(ec[2]) and abs(ec[0] - 0.05) < 1e-9


def test_calibration_improves_overconfident_model():
    z, y = _synthetic(3.0, seed=2)                                    # raw softmax(z) is overconfident
    cf = C24.cross_fit(z, y, 2, seed=0, bounds=(0.05, 20), bins=15)
    assert cf["after"]["ece_top"] < cf["before"]["ece_top"] * 0.5
    assert cf["after"]["nll"] < cf["before"]["nll"] and cf["after"]["brier"] < cf["before"]["brier"]
    assert all(abs(T - 3.0) < 0.3 for T in cf["fold_temperatures"])


def test_cross_fit_folds_disjoint_and_stratified():
    y = np.array([0] * 101 + [1] * 30 + [2] * 3 + [3] * 1)
    f = C24.stratified_folds(y, 2, seed=5)
    for c in range(4):
        counts = np.bincount(f[y == c], minlength=2)
        assert abs(counts[0] - counts[1]) <= 1, (c, counts)
    assert np.array_equal(f, C24.stratified_folds(y, 2, seed=5)) and not np.array_equal(f, C24.stratified_folds(y, 2, 6))
    z = np.random.default_rng(0).normal(size=(len(y), 4))
    seen = []
    orig = PM.fit_temperature

    def spy(zz, yy, b):
        seen.append(len(yy))
        return orig(zz, yy, b)
    PM.fit_temperature = spy
    try:
        C24.cross_fit(z, y, 2, 5, (0.05, 20), 15)
    finally:
        PM.fit_temperature = orig
    assert sorted(seen) == sorted([int((f != 0).sum()), int((f != 1).sum())])   # each fit excludes its scored fold


def test_nll_matches_naive_and_keeps_tiny_losses():
    z, y = _synthetic(1.0, n=300, seed=3)
    for T in (0.5, 1.0, 3.0):
        P = PM.softmax(z, T)
        assert abs(PM.nll(z, y, T) - float(-np.log(P[np.arange(len(y)), y]).mean())) < 1e-10
    zs = np.c_[np.full(3, 30.0), np.zeros((3, 3))]
    a, b = PM.nll(zs, np.zeros(3, int), 0.2), PM.nll(zs, np.zeros(3, int), 0.1)
    assert 0 < b < a < 1e-50                                          # not rounded to 0, still decreasing in T
    assert abs(PM.nll(zs, np.ones(3, int), 1.0) - (30 + np.log(1 + 3 * np.exp(-30)))) < 1e-9


def test_reliability_bins():
    r = PM.reliability(np.array([0.05, 0.06, 0.95]), np.array([0.0, 1.0, 1.0]), 10)
    assert r["n"] == [2, 1] and r["acc"] == [0.5, 1.0]


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
