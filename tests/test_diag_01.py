"""tests/test_diag_01.py -- helpers of diagnostics/diag_01_portscan_synflood.py on synthetic data: row identity
(exact / 6 significant figures), conflict matrix, per-flow ceiling, causal context window, threshold choice.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_diag_01.py
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
_spec = importlib.util.spec_from_file_location("diag01", REPO / "diagnostics" / "diag_01_portscan_synflood.py")
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)


def test_round_sig():
    x = np.array([123456789.0, 0.000123456789, -98765.4321, 0.0, 1.0])
    r = G.round_sig(x, 6)
    assert np.allclose(r, [123457000.0, 0.000123457, -98765.4, 0.0, 1.0], rtol=0, atol=1e-12 * 0 + 1e-9 * np.abs(x).max())
    assert G.round_sig(np.array([1.0000004]), 6)[0] == G.round_sig(np.array([0.9999996]), 6)[0] == 1.0


def test_row_ids_exact_and_near():
    X = np.array([[1.0, 2.0], [1.0, 2.0], [-0.0, 2.0], [0.0, 2.0], [1.0000001, 2.0]], dtype=np.float32)
    e = G.row_ids(X)
    assert e[0] == e[1] and e[2] == e[3] and e[0] != e[4]           # -0.0 == 0.0; float32 1.0000001 != 1.0
    s = G.row_ids(X, 6)
    assert s[0] == s[4] and s[0] != s[2]                             # near-duplicate merged at 6 sig. fig.


def test_conflict_matrix():
    ids = np.array([0, 0, 1, 2, 2, 3])
    y = np.array([0, 1, 1, 1, 2, 2])
    P = G.presence(ids, y, 4, 3)
    M = G.conflict_matrix(ids, y, P, 3)
    assert M[0, 1] == 1.0 and M[0, 2] == 0.0                        # the one class-0 row shares id 0 with class 1
    assert abs(M[1, 0] - 1 / 3) < 1e-12 and abs(M[1, 2] - 1 / 3) < 1e-12
    assert M[2, 1] == 0.5 and np.isnan(M[1, 1])


def test_majority_and_ceiling():
    ids_tr = np.array([0, 0, 0, 1, 1])
    y_tr = np.array([2, 2, 1, 1, 1])
    lk = G.majority_label(ids_tr, y_tr, 3, 3)
    assert lk.tolist() == [2, 1, -1]
    ids_va = np.array([0, 0, 1, 2])
    y_va = np.array([1, 2, 1, 0])
    r = G.ceiling_recall(ids_va, y_va, lk, 3)
    assert r == [1.0, 0.5, 1.0]                                      # unseen id 2 counts as correct; id 0 -> class 2,
                                                                     # so class 1 = 1 of 2 (id 0 wrong, id 1 right)
    tie = G.majority_label(np.array([0, 0]), np.array([2, 1]), 1, 3)
    assert tie.tolist() == [1]                                       # ties -> lowest class id


def test_context_is_causal_and_windowed():
    src = np.array(["a", "a", "a", "a", "a", "b"])
    dst = np.array(["x", "x", "y", "x", "x", "x"])
    port = np.array([1, 2, 1, 1, 1, 1])
    t = np.array([100, 100, 105, 109, 111, 105])
    F = G.context_features(src, dst, port, t, W=10)
    assert F[0].tolist() == [0, 0, 0] and F[1].tolist() == [0, 0, 0]   # same second: nothing earlier
    assert F[2].tolist() == [2, 0, 1]                                  # sees both t=100 flows: ports {1,2}, dst {x}
    assert F[3].tolist() == [2, 1, 2]                                  # (x,1) seen once before; dst {x,y}
    assert F[4].tolist() == [1, 1, 2]                                  # window [101,111): t=100 flows dropped
    assert F[5].tolist() == [0, 0, 0]                                  # other source
    assert G.context_features(src, dst, port, t, W=2)[4].tolist() == [1, 1, 1]   # only t=109


def test_best_threshold_both_directions():
    pos, neg = np.array([10, 12, 15, 30]), np.array([1, 1, 2, 3])
    thr = G.best_threshold(pos, neg)
    assert thr["direction"] == ">=" and thr["train_bal_acc"] == 1.0 and 3 < thr["theta"] <= 10
    assert G.side(pos, thr).all() and not G.side(neg, thr).any()
    thr2 = G.best_threshold(neg, pos)
    assert thr2["direction"] == "<" and thr2["train_bal_acc"] == 1.0


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
