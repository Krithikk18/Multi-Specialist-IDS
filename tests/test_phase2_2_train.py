"""tests/test_phase2_2_train.py -- Phase 2 step 2 (22_train_multiclass.py): model specs, pooled subsets and one
seeded multiclass fit with class weights, inner-split early stopping and a 0-row class. Synthetic data only.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_phase2_2_train.py
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.phase2_config import load_phase2_config  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("train22", REPO / "22_train_multiclass.py")
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)


def _cfg(**over) -> dict:
    cfg = copy.deepcopy(load_phase2_config())
    cfg["xgb"]["num_boost_round"], cfg["xgb"]["early_stopping_rounds"] = 40, 5
    cfg["xgb"]["params"]["nthread"] = 2
    for k, v in over.items():
        cfg[k] = v
    return cfg


def _data(n=1200, seed=0, absent=(2,)):
    """4 classes on 70 features, class means separated; classes in `absent` get no rows."""
    rng = np.random.default_rng(seed)
    y = rng.choice([c for c in range(4) if c not in absent], size=n, p=None)
    X = rng.normal(size=(n, 70)).astype(np.float32)
    X[:, 0] += 3 * y
    X[:, 1] -= 2 * (y == 3)
    return X, y.astype(np.int64)


def test_build_specs_counts_and_ids():
    groups = np.array(["G1", "G2", "GEN", "G1"])
    specs, info = T.build_specs(groups, {"Camera": 500, "Hub": 50, "Light Bulb (x)": 100}, _cfg())
    ids = [s["model_id"] for s in specs]
    assert info["specialist_groups"] == ["G1", "G2"] and info["fallback_present"]
    prim = [s["model_id"] for s in specs if s["config"] == "primary"]
    assert prim == ["SPEC_G1__sqrt", "SPEC_G2__sqrt", "GLOBAL__sqrt"], prim
    assert sum(s["config"].startswith("A1_") for s in specs) == 6
    assert "SPEC_G1__none" in ids and "GLOBAL__balanced" in ids and "GENSPEC_GEN__sqrt" in ids
    assert info["a3"]["category_models"] == {"Camera": "CAT_Camera__sqrt", "Light Bulb (x)": "CAT_Light_Bulb_x__sqrt"}
    assert info["a3"]["fallback_to_global"] == {"Hub": 50}
    assert len(ids) == len(set(ids)) == 3 + 6 + 1 + 2


def test_build_specs_data_agnostic_and_skips():
    cfg = _cfg()
    specs, info = T.build_specs(["A", "B", "C"], None, cfg)              # no GEN, no category column
    assert [s["model_id"] for s in specs if s["config"] == "primary"] == ["SPEC_A__sqrt", "SPEC_B__sqrt",
                                                                          "SPEC_C__sqrt", "GLOBAL__sqrt"]
    assert "skipped" in info["a3"] and info.get("a2_skipped") and not info["fallback_present"]
    cfg["ablations"] = {**cfg["ablations"], "A1_class_weights": False, "A2_gen_specialist": False,
                        "A3_device_category": False}
    assert len(T.build_specs(["G1", "GEN"], {"x": 999}, cfg)[0]) == 2


def test_subset_mask_pools_attacks():
    y = np.array([0, 0, 0, 1, 2, 3])
    g = np.array(["G1", "G2", "GEN", "G2", "GEN", "G1"])
    cat = np.array(["Cam", "Hub", "Cam", "Hub", "Cam", "Hub"])
    spec_g1 = {"subset": ("group", "G1")}
    assert T.subset_mask(spec_g1, y, g, cat).tolist() == [True, False, False, True, True, True]
    assert T.subset_mask({"subset": ("category", "Cam")}, y, g, cat).tolist() == [True, False, True, True, True, True]
    assert T.subset_mask({"subset": ("all", None)}, y, g, cat).all()


def test_train_one_zero_row_class_and_early_stopping():
    X, y = _data()
    r = T.train_one(X, y, 4, "sqrt", seed=0, cfg=_cfg(), nthread=2)
    assert r["zero_row_classes"] == [2] and r["counts"][2] == 0
    b = r["booster"]
    assert b.num_boosted_rounds() == r["best_iteration"] + 1               # sliced at the best inner iteration
    assert len(r["curves"]["inner"]) == r["rounds_run"] == len(r["curves"]["train"])
    assert r["n_fit"] + r["n_inner"] == len(y) and r["inner_counts"][2] == 0
    import xgboost as xgb
    P = b.predict(xgb.DMatrix(X[:50]))
    assert P.shape == (50, 4) and np.allclose(P.sum(1), 1, atol=1e-5)  # num_class stays 4
    n = np.array(r["counts"], dtype=float)
    assert np.allclose(r["class_weights"], [1 if c in (0, 2) or n[c] >= n[0] else np.sqrt(n[0] / n[c])
                                            for c in range(4)])


def test_train_one_seed_determinism():
    X, y = _data(seed=1, absent=())
    cfg = _cfg()
    a = T.train_one(X, y, 4, "none", 3, cfg, nthread=2)
    b = T.train_one(X, y, 4, "none", 3, cfg, nthread=2)
    c = T.train_one(X, y, 4, "none", 4, cfg, nthread=2)
    import xgboost as xgb
    d = xgb.DMatrix(X[:100])
    assert np.array_equal(a["booster"].predict(d), b["booster"].predict(d))
    assert a["curves"]["inner"] != c["curves"]["inner"]                  # another seed -> another inner split


def test_weight_modes_reach_xgboost():
    X, y = _data(seed=2, absent=())
    keep = (y != 1) | (np.arange(len(y)) % 10 == 0)                       # make class 1 rare
    r_none = T.train_one(X[keep], y[keep], 4, "none", 0, _cfg(), nthread=2)
    r_bal = T.train_one(X[keep], y[keep], 4, "balanced", 0, _cfg(), nthread=2)
    assert r_none["class_weights"] == [1.0] * 4 and r_bal["class_weights"][1] > r_bal["class_weights"][0]


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
