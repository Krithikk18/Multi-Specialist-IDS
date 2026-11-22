"""tests/test_phase5b_perturbation.py -- common/shap_perturb.py (Phase 5B Part B): stratified sampling; top / random /
bottom selection (random never touches the top-k, seeded); median replacement; TreeSHAP of the predicted class on a tiny
XGBoost model (additivity); the perturbation drops (a model that uses only one feature: top-k removes the signal,
bottom-k does not); FAITHFUL / NOT_FAITHFUL branches; seeded determinism. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_phase5b_perturbation.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common import cl_retrain as RT  # noqa: E402
from common import shap_perturb as SP  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

CFG2 = load_phase2_config(ROOT / "config" / "v2_phase2_v2_1.json")
EVC = {"ci_level": 0.95, "bootstrap_resamples": 4000, "bootstrap_seed": 0}


def test_sample_stratified_seeded():
    pred = np.array([0] * 50 + [1] * 30 + [3] * 5)
    a = SP.sample(pred, 4, 10, 20, 0)
    b = SP.sample(pred, 4, 10, 20, 0)
    assert np.array_equal(a, b) and len(a) == 20 + 10 + 5 and np.all(np.diff(a) > 0)
    assert (pred[a] == 0).sum() == 20 and (pred[a] == 1).sum() == 10 and (pred[a] == 3).sum() == 5
    assert not np.array_equal(a, SP.sample(pred, 4, 10, 20, 1))


def test_select_top_bottom_random():
    phi = np.array([[0.1, -5.0, 0.2, 3.0, 0.0, 0.01, -0.3, 2.0, 0.05, 1.0, -0.02, 0.4]])
    top, bot, rnd = SP.select(phi, 3, 4, 0)
    assert top[0].tolist() == [1, 3, 7] and sorted(bot[0].tolist()) == [4, 5, 10]
    assert rnd.shape == (4, 1, 3) and not set(rnd.ravel().tolist()) & set(top[0].tolist())
    assert all(len(set(r[0].tolist())) == 3 for r in rnd)
    t2, b2, r2 = SP.select(phi, 3, 4, 0)
    assert np.array_equal(rnd, r2)
    tie = np.array([[1.0, 1.0, 1.0, 0.0, 0.0, 0.0]])
    assert SP.select(tie, 2, 1, 0)[0][0].tolist() == [0, 1]                # ties -> lower index first
    try:
        SP.select(np.zeros((1, 5)), 3, 1, 0)
        raise AssertionError("F < 2k accepted")
    except ValueError:
        pass


def test_replace_with_median():
    X = np.arange(12, dtype=np.float32).reshape(2, 6)
    med = np.full(6, -1.0)
    Xp = SP.replace(X, np.array([[0, 2], [5, 1]]), med)
    assert Xp[0].tolist() == [-1, 1, -1, 3, 4, 5] and Xp[1].tolist() == [6, -1, 8, 9, 10, -1]
    assert X[0, 0] == 0                                                  # input untouched


def _model():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(1500, 12)).astype(np.float32)
    y = (X[:, 0] > 0.5).astype(np.int64) + 2 * (X[:, 0] < -0.8).astype(np.int64)   # only feature 0 matters
    return RT.fit(X, y, 3, "none", 0, CFG2, 2)["booster"], X, y


def test_tree_shap_and_perturbation_drops():
    b, X, y = _model()
    P = SP.proba(b, X[:300], 1.0)
    pred = P.argmax(1)
    C = SP.tree_shap(b, X[:300])
    import xgboost as xgb
    assert C.shape == (300, 3, 13)
    assert np.abs(C.sum(2) - b.predict(xgb.DMatrix(X[:300]), output_margin=True)).max() < 1e-3
    phi = SP.class_phi(C, pred)
    top, bot, rnd = SP.select(phi, 2, 3, 0)
    assert (top[:, 0] == 0).mean() > 0.95                                # feature 0 is the top feature
    med = np.median(X[y == 0], axis=0)
    R = SP.perturbation(b, X[:300], pred, 1.0, med, top, bot, rnd)
    m = pred != 0
    assert R["argmax_consistent"]
    assert R["drop_top"][m].mean() > 0.5 and abs(R["drop_bottom"][m].mean()) < 0.05 and R["flip_top"][m].mean() > 0.9
    V = SP.verdict(R["drop_top"][m] - R["drop_rand"][m], EVC)
    assert V["verdict"] == SP.FAITHFUL
    R2 = SP.perturbation(b, X[:300], pred, 1.0, med, top, bot, rnd)
    assert np.array_equal(R["drop_rand"], R2["drop_rand"])               # deterministic


def test_verdict_branches():
    assert SP.verdict([0.3, 0.25, 0.4, 0.2], EVC)["verdict"] == SP.FAITHFUL
    assert SP.verdict([0.0, 0.0, 0.0], EVC)["verdict"] == SP.NOT_FAITHFUL          # lower bound 0, not > 0
    assert SP.verdict([0.2, -0.3, 0.1, -0.1], EVC)["verdict"] == SP.NOT_FAITHFUL
    assert SP.verdict([], EVC)["verdict"] == SP.NOT_FAITHFUL


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
