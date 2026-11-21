"""tests/test_phase2_5_shap.py -- Phase 2 step 5 (25_explain_shap.py): leakage check, TreeSHAP via pred_contribs
(additivity), per-class capped sampling and dominance flags. Synthetic data only.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_phase2_5_shap.py
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import schemas as S  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("shap25", REPO / "25_explain_shap.py")
X25 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(X25)


def test_leakage_check_real_features_clean():
    meta = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp", "start_ts", "src_mac", "dst_mac",
            "device", "group", "session", "label_id", "y"]
    assert X25.leakage_check(S.feature_columns(), meta) == []


def test_leakage_check_flags_identifiers():
    bad = ["Flow Duration", "Src IP", "Dst Port", "dst_mac", "Timestamp", "Flow ID", "device_mac", "session",
           "my_group_code", "Idle Mean", "Protocol"]
    got = X25.leakage_check(bad, ["start_ts"])
    assert got == ["Src IP", "Dst Port", "dst_mac", "Timestamp", "Flow ID", "device_mac", "session", "my_group_code"], got
    assert X25.leakage_check(["start_ts", "Fwd IAT Mean"], ["start_ts"]) == ["start_ts"]   # metadata column by name


def test_tree_shap_additivity_multiclass():
    import xgboost as xgb
    rng = np.random.default_rng(0)
    X = rng.normal(size=(600, 6)).astype(np.float32)
    y = (X[:, 0] > 0).astype(int) + 2 * (X[:, 1] > 1)
    b = xgb.train({"objective": "multi:softprob", "num_class": 4, "max_depth": 3, "nthread": 2, "seed": 0},
                  xgb.DMatrix(X, label=y), 20)
    C, err = X25.tree_shap(b, X[:100])
    assert C.shape == (100, 4, 7) and err < 1e-4
    I = X25.importance(C)
    assert I.shape == (4, 6) and I[:, 0].sum() > I[:, 5].sum()         # the informative feature dominates the noise


def test_sample_per_class_caps_and_keeps_rare():
    y = np.array([0] * 5000 + [1] * 30 + [2] * 3)
    ix = X25.sample_per_class(y, 2000, seed=0)
    assert np.bincount(y[ix]).tolist() == [2000, 30, 3] and (np.diff(ix) > 0).all()
    assert np.array_equal(ix, X25.sample_per_class(y, 2000, seed=0))


def test_dominance_flag():
    feats = ["a", "b", "c"]
    assert X25.dominance(np.array([6.0, 2.0, 2.0]), feats, 0.5) == [{"feature": "a", "share": 0.6}]
    assert X25.dominance(np.array([5.0, 3.0, 2.0]), feats, 0.5) == []
    assert X25.dominance(np.zeros(3), feats, 0.5) == []


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
