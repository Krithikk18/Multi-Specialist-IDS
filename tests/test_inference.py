"""tests/test_inference.py -- common/inference.py on 1,000 real val rows (v2_1_oriented, seeded sample): the row ->
vector path equals the offline feature matrix exactly; single-row scoring == batch scoring == the offline path (step
23's DMatrix predict for the class, step 24's softmax(margin / T) for the probabilities, within 1e-6); ROUTED routes
each row to its group's model; TreeSHAP top-k is ordered by |contribution| and contributions + bias == margin; the
NaN / inf policy and non-numeric refusal.

Plain asserts. Usage (repo root): python tests/test_inference.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import inference as INF  # noqa: E402
from common import model_loader as ML  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_metrics import softmax  # noqa: E402

CFG = C.load_phase3_config()
_DATA: dict = {}


def _rows():
    if not _DATA:
        from common import phase2_data as D
        from common.phase2_config import load_phase2_config
        from config.config import REPO_ROOT
        cfg2 = load_phase2_config(REPO_ROOT / CFG["phase2_config"])
        feats = S.feature_columns()
        va = D.load_split(cfg2, "val", feats + ["group"])
        idx = np.sort(np.random.default_rng(0).choice(len(va), 1000, replace=False))
        va = va.iloc[idx].reset_index(drop=True)
        _DATA["X"] = D.feature_matrix(va, feats)
        _DATA["rows"] = [{f: float(v) for f, v in zip(feats, r)} for r in va[feats].to_numpy(np.float64)]
        _DATA["group"] = va["group"].astype(str).tolist()
    return _DATA


def test_vector_equals_offline_matrix():
    d = _rows()
    inf = INF.Inference(ML.load_runtime_model(CFG), CFG)
    V = np.vstack([inf.vector(r) for r in d["rows"]])
    assert V.dtype == np.float32 and np.array_equal(V, d["X"])


def test_single_equals_batch_equals_offline_global():
    import xgboost as xgb
    d = _rows()
    rm = ML.load_runtime_model(CFG)
    inf = INF.Inference(rm, CFG)
    X = d["X"]
    mids = [rm.model_for(g) for g in d["group"]]
    zb, pb = inf.score(X, mids)
    z1 = np.vstack([inf.score(X[i:i + 1], mids[i:i + 1])[0] for i in range(len(X))])
    p1 = np.vstack([inf.score(X[i:i + 1], mids[i:i + 1])[1] for i in range(len(X))])
    assert np.max(np.abs(zb - z1)) <= 1e-6 and np.max(np.abs(pb - p1)) <= 1e-6
    m = rm.models[rm.default]
    b = m.booster
    P23 = b.predict(xgb.DMatrix(X))                                    # step 23's path (T = 1)
    Z24 = b.predict(xgb.DMatrix(X), output_margin=True).astype(np.float64)
    assert np.array_equal(P23.argmax(1), pb.argmax(1))
    assert np.max(np.abs(Z24 - zb)) <= 1e-5
    assert np.max(np.abs(softmax(Z24, m.temperature) - pb)) <= 1e-6


def test_routed_uses_each_groups_model():
    import xgboost as xgb
    d = _rows()
    rm = ML.load_runtime_model(CFG, mode="ROUTED", evaluation=True)
    inf = INF.Inference(rm, CFG)
    mids = [rm.model_for(g) for g in d["group"]]
    assert len(set(mids)) >= 2
    _, pb = inf.score(d["X"], mids)
    for mid in set(mids):
        ix = [i for i, x in enumerate(mids) if x == mid]
        m = rm.models[mid]
        z = m.booster.predict(xgb.DMatrix(d["X"][ix]), output_margin=True).astype(np.float64)
        assert np.max(np.abs(softmax(z, m.temperature) - pb[ix])) <= 1e-6, mid


def test_explain_topk_and_additivity():
    import xgboost as xgb
    d = _rows()
    rm = ML.load_runtime_model(CFG)
    inf = INF.Inference(rm, CFG)
    X = d["X"][:50]
    mids = [rm.default] * 50
    z, p = inf.score(X, mids)
    cls = p.argmax(1)
    top = inf.explain(X, mids, cls)
    full = rm.models[rm.default].booster.predict(xgb.DMatrix(X), pred_contribs=True).reshape(50, inf.K, 71)
    for i in range(50):
        assert len(top[i]) == CFG["explain"]["top_k"]
        mags = [abs(c) for _, _, c in top[i]]
        assert mags == sorted(mags, reverse=True)
        assert abs(full[i, cls[i]].sum() - z[i, cls[i]]) < 1e-3          # SHAP additivity (float32 sums)
        assert top[i][0][2] == float(full[i, cls[i], :-1][np.argmax(np.abs(full[i, cls[i], :-1]))])


def test_nan_inf_policy_and_non_numeric():
    rm = ML.load_runtime_model(CFG)
    inf = INF.Inference(rm, CFG)
    feats = S.feature_columns()
    row = {f: 1.0 for f in feats}
    row[feats[3]], row[feats[5]], row[feats[7]], row[feats[9]] = float("nan"), float("inf"), "-inf", "2.5"
    v = inf.vector(row)
    assert v[3] == 0 and v[5] == 0 and v[7] == 0 and v[9] == 2.5 and v[0] == 1.0
    row[feats[0]] = "abc"
    try:
        inf.vector(row)
        raise AssertionError("no error")
    except ValueError as e:
        assert "non-numeric" in str(e)


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
