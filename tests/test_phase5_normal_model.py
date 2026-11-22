"""tests/test_phase5_normal_model.py -- common/normal_model.py (Phase 5A models of normal): the signed-log transform
(sign, zero, negatives, monotone); the V1 NaN / inf policy reused and counted; threshold = the 99.9th percentile of the
model's own training scores; fallback below min_group_benign (logged) and for groups unseen in training; per-group
routing of scores; determinism per seed; score sign (higher = more anomalous); the random-group permutation keeps
group sizes; the 90/10 threshold check. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_phase5_normal_model.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import normal_model as NM  # noqa: E402

P = {"n_estimators": 50, "max_samples_cap": 256, "max_features": 1.0, "bootstrap": False, "n_jobs": 1,
     "threshold_quantile": 0.999, "quantile_method": "linear", "min_group_benign": 1000,
     "random_group_perm_seed_base": 1000, "score_chunk_rows": 700}
TC = {"fit_frac": 0.9, "split_seed_base": 2000}


def _benign(n_a=3000, n_b=1500, n_c=400, seed=0):
    rng = np.random.default_rng(seed)
    Z = np.vstack([rng.normal(0, 1, (n_a, 4)), rng.normal(3, 0.5, (n_b, 4)), rng.normal(-2, 1, (n_c, 4))])
    g = np.array(["A"] * n_a + ["B"] * n_b + ["C"] * n_c)
    return Z, g


def test_transform_sign_zero_negative_monotone():
    x = np.array([-1e9, -10.0, -1.0, -1e-6, 0.0, 1e-6, 1.0, 10.0, 1e9])
    t = NM.signed_log1p(x)
    assert t[4] == 0.0 and np.all(np.sign(t) == np.sign(x))
    assert np.allclose(t, -t[::-1])                                    # odd function
    assert np.all(np.diff(t) > 0)                                       # strictly monotone
    assert np.isclose(t[6], np.log(2.0)) and np.isclose(t[2], -np.log(2.0))
    assert t.dtype == np.float64


def test_prepare_reuses_v1_nan_inf_policy_and_counts():
    X = np.array([[1.0, np.nan], [np.inf, 2.0], [-np.inf, 3.0]], dtype=np.float32)
    Z, c = NM.prepare(X, ["f1", "f2"])
    assert c == {"f1": {"nan": 0, "inf": 2}, "f2": {"nan": 1, "inf": 0}}, c
    assert np.isfinite(Z).all() and Z[1, 0] == 0.0 and Z[2, 0] == 0.0 and Z[0, 1] == 0.0
    Z2, c2 = NM.prepare(np.ones((2, 2)), ["a", "b"])
    assert c2 == {} and np.allclose(Z2, np.log(2.0))


def test_score_sign_higher_is_more_anomalous():
    Z, _ = _benign()
    r = NM.fit_one(Z[:3000], 0, P)
    s_in = NM.anomaly_score(r["model"], np.zeros((5, 4)), 100)
    s_out = NM.anomaly_score(r["model"], np.full((5, 4), 25.0), 100)
    assert (s_out > s_in).all() and (s_in > 0).all()
    assert np.allclose(NM.anomaly_score(r["model"], Z[:50], 7), -r["model"].score_samples(Z[:50]))   # chunking


def test_threshold_is_own_train_quantile():
    Z, _ = _benign()
    r = NM.fit_one(Z, 3, P)
    s = NM.anomaly_score(r["model"], Z, 10_000)
    assert r["threshold"] == float(np.quantile(s, 0.999, method="linear"))
    assert np.array_equal(r["train_scores"], s)
    assert (s > r["threshold"]).sum() <= int(np.ceil(0.001 * len(s))) + 1
    assert r["max_samples"] == 256 and r["n_train"] == len(Z)
    small = NM.fit_one(Z[:100], 0, P)
    assert small["max_samples"] == 100 and small["model"].max_samples_ == 100


def test_fallback_below_min_group_benign():
    Z, g = _benign()
    G = NM.fit_arm(NM.GLOBAL, Z, g, 0, P)
    A = NM.fit_arm(NM.PER_GROUP, Z, g, 0, P, global_rec=G["models"][NM.GLOBAL_KEY])
    assert A["fallback"] == [{"group": "C", "n": 400}], A["fallback"]
    assert A["route"] == {"A": "A", "B": "B", "C": NM.GLOBAL_KEY}
    assert A["models"][NM.GLOBAL_KEY] is G["models"][NM.GLOBAL_KEY]
    assert A["models"]["A"]["n_train"] == 3000 and A["models"]["B"]["n_train"] == 1500
    raised = False
    try:
        NM.fit_arm(NM.PER_GROUP, Z, g, 0, P)                            # no global given -> refuses
    except ValueError:
        raised = True
    assert raised


def test_per_group_routing_of_scores():
    Z, g = _benign()
    G = NM.fit_arm(NM.GLOBAL, Z, g, 0, P)
    A = NM.fit_arm(NM.PER_GROUP, Z, g, 0, P, global_rec=G["models"][NM.GLOBAL_KEY])
    rng = np.random.default_rng(5)
    Zv = rng.normal(0, 2, (60, 4))
    gv = np.array(["A"] * 20 + ["B"] * 20 + ["C"] * 10 + ["NEW"] * 10)
    s, thr, key, unseen = NM.score_arm(A, Zv, gv, P)
    assert unseen == ["NEW"]
    assert list(key[:20]) == ["A"] * 20 and list(key[20:40]) == ["B"] * 20
    assert list(key[40:]) == [NM.GLOBAL_KEY] * 20                       # fallback group and unseen group -> global
    assert np.allclose(s[:20], NM.anomaly_score(A["models"]["A"]["model"], Zv[:20], 100))
    assert np.allclose(s[20:40], NM.anomaly_score(A["models"]["B"]["model"], Zv[20:40], 100))
    assert np.allclose(s[40:], NM.anomaly_score(G["models"][NM.GLOBAL_KEY]["model"], Zv[40:], 100))
    assert (thr[:20] == A["models"]["A"]["threshold"]).all() and (thr[40:] == G["models"][NM.GLOBAL_KEY]["threshold"]).all()
    assert np.array_equal(NM.flags(s, thr), s > thr)
    sg, tg, kg, _ = NM.score_arm(G, Zv, gv, P)                          # global arm: one model for every row
    assert set(kg.tolist()) == {NM.GLOBAL_KEY} and len(set(tg.tolist())) == 1


def test_determinism_per_seed():
    Z, g = _benign()
    a = NM.fit_one(Z, 7, P)
    b = NM.fit_one(Z, 7, P)
    c = NM.fit_one(Z, 8, P)
    assert np.array_equal(a["train_scores"], b["train_scores"]) and a["threshold"] == b["threshold"]
    assert not np.array_equal(a["train_scores"], c["train_scores"])
    assert NM.model_bytes(a["model"]) == NM.model_bytes(b["model"])


def test_random_group_permutation_keeps_sizes():
    Z, g = _benign()
    f1 = NM.fit_groups(NM.RANDOM_GROUP, g, 0, P)
    f2 = NM.fit_groups(NM.RANDOM_GROUP, g, 0, P)
    f3 = NM.fit_groups(NM.RANDOM_GROUP, g, 1, P)
    assert np.array_equal(f1, f2) and not np.array_equal(f1, f3)
    assert sorted(np.unique(f1, return_counts=True)[1].tolist()) == sorted(np.unique(g, return_counts=True)[1].tolist())
    assert (f1 != g).mean() > 0.3                                       # actually permuted
    assert np.array_equal(NM.fit_groups(NM.PER_GROUP, g, 0, P), g)
    G = NM.fit_arm(NM.GLOBAL, Z, g, 0, P)
    R = NM.fit_arm(NM.RANDOM_GROUP, Z, g, 0, P, global_rec=G["models"][NM.GLOBAL_KEY])
    assert R["fallback"] == [{"group": "C", "n": 400}] and R["models"]["A"]["n_train"] == 3000


def test_threshold_check_reports_held_out_rate():
    Z, g = _benign()
    G = NM.fit_arm(NM.GLOBAL, Z, g, 0, P)
    A = NM.fit_arm(NM.PER_GROUP, Z, g, 0, P, global_rec=G["models"][NM.GLOBAL_KEY])
    T = NM.threshold_check(A, Z, 0, P, TC)
    assert set(T["per_model"]) == {"A", "B"}                            # the fallback global is checked in its own arm
    assert T["per_model"]["A"]["n_fit"] == 2700 and T["per_model"]["A"]["n_held_out"] == 300
    assert T["held_out_n"] == 300 + 150 and 0 <= T["held_out_flag_rate"] <= 1 and np.isclose(T["nominal"], 0.001)
    T2 = NM.threshold_check(A, Z, 0, P, TC)
    assert T == T2                                                      # seeded
    TG = NM.threshold_check(G, Z, 0, P, TC)
    assert set(TG["per_model"]) == {NM.GLOBAL_KEY} and TG["held_out_n"] == len(Z) - int(round(0.9 * len(Z)))


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
