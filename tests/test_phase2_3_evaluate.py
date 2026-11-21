"""tests/test_phase2_3_evaluate.py -- Phase 2 step 3: metric definitions (common/phase2_metrics.py) against known
values / sklearn, and 23_evaluate.py's system routing, assembly and per-subset evaluation. Synthetic data only.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_phase2_3_evaluate.py
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase2_metrics as PM  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("eval23", REPO / "23_evaluate.py")
E23 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E23)


def close(a, b, tol=1e-4):
    return abs(a - b) <= tol


def test_t_ci():
    r = PM.t_ci([1, 2, 3, 4, 5])
    half = 2.7764451 * np.std([1, 2, 3, 4, 5], ddof=1) / np.sqrt(5)
    assert close(r["mean"], 3) and close(r["hi"] - 3, half) and r["n"] == 5
    assert np.isnan(PM.t_ci([0.5])["lo"]) and PM.t_ci([np.nan, 1.0])["n"] == 1 and np.isnan(PM.t_ci([])["mean"])


def test_clopper_pearson():
    lo, hi = PM.clopper_pearson(0, 10)
    assert lo == 0 and close(hi, 1 - 0.025 ** (1 / 10))
    lo, hi = PM.clopper_pearson(17, 17)
    assert hi == 1 and close(lo, 0.025 ** (1 / 17))
    lo, hi = PM.clopper_pearson(5, 10)
    assert close(lo, 0.187086, 1e-5) and close(hi, 0.812914, 1e-5)
    assert all(np.isnan(PM.clopper_pearson(0, 0)))


def test_garwood():
    assert PM.garwood(0)[0] == 0 and close(PM.garwood(0)[1], 3.688879, 1e-5)
    lo, hi = PM.garwood(2)
    assert close(lo, 0.242209, 1e-5) and close(hi, 7.224688, 1e-5)


def test_per_class_and_macro_versions():
    y = np.array([0] * 100 + [1] * 60 + [2] * 5)                   # class 3 absent; class 2 rare (< 50)
    pred = y.copy()
    pred[:10] = 1                                                  # 10 benign -> class 1
    pred[160:162] = 0                                              # 2 of 5 class-2 missed
    P = np.eye(4)[pred] * 0.97 + 0.01
    r = PM.classification_metrics(y, P, 4, min_val_flows=50)
    assert r["support"] == [100, 60, 5, 0] and np.isnan(r["recall"][3]) and np.isnan(r["f1"][3])
    assert r["rare_classes"] == [2]
    f1 = np.array(r["f1"][:3])
    assert close(r["macro_f1_all"], f1.mean()) and close(r["macro_f1_nonrare"], f1[:2].mean())
    assert close(r["recall"][2], 0.6) and r["recall_cp"][3] == [None, None]
    from sklearn.metrics import balanced_accuracy_score, f1_score, matthews_corrcoef
    assert close(r["mcc"], matthews_corrcoef(y, pred), 1e-9)
    assert close(r["weighted_f1"], f1_score(y, pred, average="weighted"), 1e-9)
    assert close(r["balanced_accuracy"], balanced_accuracy_score(y, pred), 1e-9)
    assert np.isnan(r["roc_auc"][3]) and r["roc_auc"][0] > 0.9


def test_precision_zero_when_never_predicted():
    cm = np.array([[5, 0], [3, 0]])
    pc = PM.per_class_prf(cm)
    assert pc["precision"][1] == 0 and pc["recall"][1] == 0 and pc["f1"][1] == 0


def test_benign_hours_active_segments():
    sess = np.array(["A"] * 5 + ["B"] * 2)
    ts = np.array([0, 10, 20, 1000, 1010, 50, 60])
    ben = np.array([True, False, False, False, False, True, False])
    h = PM.benign_hours(sess, ts, ben, idle_gap=300)
    assert close(h * 3600, 21 + 11)                                 # A: [0, 21); B: [50, 61); A's 2nd segment has no benign
    ben2 = ben.copy()
    ben2[3] = True
    assert close(PM.benign_hours(sess, ts, ben2, 300) * 3600, 21 + 11 + 11)


def test_fp_threshold_v1_rule():
    s = np.array([0.9, 0.8, 0.7, 0.1, 0.95, 0.6])
    ben = np.array([True, True, True, True, False, False])
    assert PM.fp_threshold(s, ben, 2) == 0.8
    assert PM.fp_threshold(s, ben, 0) == 0.95
    assert PM.fp_threshold(np.array([0.9, 0.9]), np.array([True, True]), 1) == float("inf")


def _m22():
    models = [{"model_id": mid, "key": f"{mid}__s{s}", "seed": s} for mid in
              ["SPEC_G1__sqrt", "SPEC_G2__sqrt", "GLOBAL__sqrt", "SPEC_G1__none", "SPEC_G2__none", "GLOBAL__none",
               "SPEC_G1__balanced", "SPEC_G2__balanced", "GLOBAL__balanced", "GENSPEC_GEN__sqrt", "CAT_Cam__sqrt"]
              for s in (0, 1)]
    return {"models": models, "routing": {"primary": {"G1": "SPEC_G1__sqrt", "G2": "SPEC_G2__sqrt", "GEN": "GLOBAL__sqrt"},
                                          "default": "GLOBAL__sqrt"},
            "specs": [{"model_id": "GENSPEC_GEN__sqrt", "config": "A2"}],
            "spec_info": {"a3": {"category_models": {"Cam": "CAT_Cam__sqrt"}}}}


def test_build_systems_and_route():
    cfg = load_phase2_config()
    S = E23.build_systems(_m22(), cfg)
    assert set(S) == {"ROUTED", "FLAT_GLOBAL", "ROUTED_A1_none", "ROUTED_A1_balanced", "ROUTED_A2", "ROUTED_A3"}
    g = np.array(["G1", "G2", "GEN", "G9"])
    cat = np.array(["Cam", "Hub", "Cam", "x"])
    assert E23.route(S["ROUTED"], g, cat).tolist() == ["SPEC_G1__sqrt", "SPEC_G2__sqrt", "GLOBAL__sqrt", "GLOBAL__sqrt"]
    assert E23.route(S["ROUTED_A2"], g, cat).tolist()[2] == "GENSPEC_GEN__sqrt"
    assert E23.route(S["ROUTED_A3"], g, cat).tolist() == ["CAT_Cam__sqrt", "GLOBAL__sqrt", "CAT_Cam__sqrt", "GLOBAL__sqrt"]
    assert E23.route(S["ROUTED_A1_none"], g, cat).tolist()[0] == "SPEC_G1__none"
    assert set(E23.route(S["FLAT_GLOBAL"], g, cat)) == {"GLOBAL__sqrt"}


def test_assemble_takes_each_rows_model():
    P = {f"{m}__s0": np.full((3, 2), v) for m, v in (("A", 0.1), ("B", 0.7))}
    out = E23.assemble(P, np.array(["A", "B", "A"], dtype=object), 0)
    assert out[:, 0].tolist() == [0.1, 0.7, 0.1]


def test_evaluate_entity_subsets_and_false_alarms():
    cfg = copy.deepcopy(load_phase2_config())
    y = np.array([0, 0, 0, 1, 1, 2])
    grp = np.array(["G1", "G1", "G2", "G1", "G2", "G2"])
    P0 = np.eye(3)[[0, 1, 0, 1, 1, 2]].astype(float)               # one benign G1 row -> false alarm
    P1 = np.eye(3)[[0, 0, 0, 1, 1, 2]].astype(float)
    subsets = {"all": np.ones(6, bool), "G1": grp == "G1", "G2": grp == "G2", "EMPTY": np.zeros(6, bool)}
    out = E23.evaluate_entity(y, {0: P0, 1: P1}, np.ones(6, bool), subsets, lambda m: 2.0, 3, cfg)
    assert "EMPTY" not in out
    a = out["all"]["aggregate"]
    assert a["fa_counts_per_seed"] == [1, 0] and close(a["seed0"]["fa_per_hour"], 0.5)
    assert close(a["fa_per_hour"]["mean"], 0.25) and out["G1"]["aggregate"]["fa_counts_per_seed"] == [1, 0]
    assert out["G2"]["aggregate"]["support"] == [1, 1, 1]


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
