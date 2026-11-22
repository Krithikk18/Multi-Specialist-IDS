"""tests/test_phase5_loao.py -- common/loao.py (Phase 5A leave-one-attack-out Stage 1): held-out class selection by
val support (rare rule); class k fully removed from training; contiguous local remap and back; miss = true k predicted
benign; k predicted as another attack counted as caught; benign sanity (recall, FA / h); the fit is cl_retrain.fit on
the reduced set (same configuration). Synthetic data.

Plain asserts. Usage (repo root): python tests/test_phase5_loao.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common import cl_retrain as RT  # noqa: E402
from common import loao as L  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

CFG2 = load_phase2_config(ROOT / "config" / "v2_phase2_v2_1.json")
NAMES = ["benign", "a1", "a2", "a3"]
K = 4


def _data(n, seed):
    rng = np.random.default_rng(seed)
    y = rng.choice(K, size=n, p=[0.5, 0.2, 0.15, 0.15])
    X = rng.normal(size=(n, 6)).astype(np.float32)
    X[:, 0] += 3.0 * y
    X[:, 1] += 2.0 * (y == 2)
    return X, y.astype(np.int64)


def raises(fn, exc=Exception):
    try:
        fn()
    except exc:
        return True
    return False


def test_heldout_classes_rare_rule():
    y = np.array([0] * 100 + [1] * 60 + [2] * 49 + [3] * 50)
    nonrare, rare = L.heldout_classes(y, 5, 50)
    assert nonrare == [1, 3] and rare == [2, 4]                         # 4 has 0 val flows -> rare
    assert 0 not in nonrare + rare


def test_remap_contiguous_and_back():
    keep = L.keep_ids(4, 2)
    assert keep.tolist() == [0, 1, 3]
    y = np.array([0, 1, 3, 3, 0, 1])
    yl = L.to_local(y, keep)
    assert yl.tolist() == [0, 1, 2, 2, 0, 1]
    assert np.array_equal(L.to_global(yl, keep), y)
    assert raises(lambda: L.to_local(np.array([0, 2]), keep), ValueError)       # the held-out class cannot be encoded
    assert raises(lambda: L.keep_ids(4, 0), ValueError) and raises(lambda: L.keep_ids(4, 4), ValueError)
    for k in (1, 2, 3):
        kp = L.keep_ids(4, k)
        assert kp[0] == 0 and len(kp) == 3 and k not in kp


def test_class_fully_removed_from_training():
    X, y = _data(3000, 0)
    r = L.fit_without(X, y, K, 2, 0, CFG2, 2)
    assert r["n_removed"] == int((y == 2).sum()) > 0
    assert "2" not in {str(c) for c in r["train_counts_global"]} and sum(r["train_counts_global"].values()) == int((y != 2).sum())
    assert r["keep"].tolist() == [0, 1, 3] and len(r["counts"]) == 3
    assert r["booster"].num_features() == 6
    P = RT.predict_proba(r["booster"], X[:5])
    assert P.shape == (5, 3)                                            # the model knows K-1 classes only
    pred = L.predict_global(r["booster"], X, r["keep"])
    assert not (pred == 2).any() and set(pred.tolist()) <= {0, 1, 3}


def test_same_configuration_as_full_fit():
    """fit_without(k) == cl_retrain.fit on the reduced, remapped set (same weights, seed, inner split, nthread)."""
    X, y = _data(2500, 1)
    r = L.fit_without(X, y, K, 3, 4, CFG2, 2)
    m = y != 3
    ref = RT.fit(np.ascontiguousarray(X[m]), L.to_local(y[m], np.array([0, 1, 2])), 3, "none", 4, CFG2, 2)
    assert bytes(r["booster"].save_raw("ubj")) == bytes(ref["booster"].save_raw("ubj"))
    assert r["params"]["seed"] == 4 and r["params"]["nthread"] == 2 and r["params"]["num_class"] == 3


def test_miss_and_caught():
    y = np.array([0, 2, 2, 2, 2, 1, 3, 2])
    pred = np.array([0, 0, 1, 3, 0, 1, 0, 2])                          # pred 2 cannot happen under LOAO(2); counted caught
    miss = L.miss_mask(y, pred, 2)
    caught = L.caught_mask(y, pred, 2)
    assert miss.tolist() == [False, True, False, False, True, False, False, False]
    assert caught.tolist() == [False, False, True, True, False, False, False, True]
    o = L.outcome(y, pred, 2, NAMES)
    assert o["n_val"] == 5 and o["misses"] == 2 and o["caught"] == 3 and o["misses"] + o["caught"] == o["n_val"]
    assert o["caught_as"] == {"a1": 1, "a2": 1, "a3": 1} and o["predicted_as"]["benign"] == 2
    assert np.isclose(o["miss_share"], 0.4)
    assert not (miss & (y != 2)).any()                                  # a missed a3 (index 6) is not a miss of k = 2


def test_benign_sanity():
    y = np.array([0, 0, 0, 0, 1])
    pred = np.array([0, 1, 0, 0, 1])
    sess = np.array(["s"] * 5)
    ts = np.array([0, 10, 20, 30, 40])
    b = L.benign_sanity(y, pred, sess, ts, 300)
    assert b["fa_count"] == 1 and np.isclose(b["benign_recall"], 0.75) and b["n_benign"] == 4
    assert np.isclose(b["benign_hours"], 41 / 3600) and np.isclose(b["fa_per_hour"], 1 / (41 / 3600))
    assert L.benign_sanity(y, pred, sess, ts, 300, hours=2.0)["fa_per_hour"] == 0.5


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
