"""tests/test_phase5b_eval.py -- common/phase5b_eval.py (Phase 5B verdict rules): flip agreement; every branch of
H-C1 (holds; all-flows CI touches 0; benign fails), H-C2 (holds; context loses as much; per-class independence),
H-C3 (holds; recall CI below the bar; FA above the reference; no eligible pair; rare / small pairs excluded),
non-inferiority (pass; macro-F1 CI below the margin; FA median above the margin; boundary); FA/h + counts.

Plain asserts. Usage (repo root): python tests/test_phase5b_eval.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase5b_eval as EV  # noqa: E402

EVC = {"ci_level": 0.95, "bootstrap_resamples": 4000, "bootstrap_seed": 0}
NI = {"macro_f1_margin": 0.002, "fa_count_margin": 2}
ZD = {"min_misses": 30, "recall_lo_min": 0.5}


def test_flip_agreement():
    p = np.array([0, 1, 2, 3, 0, 0])
    q = np.array([0, 1, 0, 3, 0, 1])
    assert EV.flip_agreement(p, q) == 4 / 6
    assert EV.flip_agreement(p, q, p == 0) == 2 / 3
    assert EV.flip_agreement(p, p) == 1.0 and np.isnan(EV.flip_agreement(p, q, np.zeros(6, bool)))


def test_h_c1_branches():
    g = [0.990, 0.991, 0.989, 0.990, 0.992]
    up = [x + 0.005 for x in g]
    assert EV.h_c1(up, g, up, g, EVC)["verdict"] == EV.HOLDS
    noisy = [x + d for x, d in zip(g, (0.004, -0.004, 0.003, -0.003, 0.0))]
    R = EV.h_c1(noisy, g, up, g, EVC)
    assert R["verdict"] == EV.NOT_HOLDS and not R["all_ok"] and R["benign_ok"]
    R = EV.h_c1(up, g, g, g, EVC)                                       # benign unchanged -> lower bound 0, not > 0
    assert R["verdict"] == EV.NOT_HOLDS and R["all_ok"] and not R["benign_ok"]


def test_h_c2_branches():
    rec = {"GLOBAL": [0.999] * 5, "GLOBAL_NOFP": [0.98, 0.985, 0.982, 0.981, 0.984],
           "GLOBAL_CTX": [0.999] * 5, "GLOBAL_CTX_NOFP": [0.998, 0.997, 0.998, 0.999, 0.998]}
    R = EV.h_c2(rec, EVC)
    assert R["verdict"] == EV.HOLDS and np.allclose(R["delta_flow"], np.array(rec["GLOBAL_NOFP"]) - 0.999)
    rec2 = dict(rec, GLOBAL_CTX_NOFP=list(rec["GLOBAL_NOFP"]))           # context loses exactly as much
    assert EV.h_c2(rec2, EVC)["verdict"] == EV.NOT_HOLDS
    rec3 = dict(rec, GLOBAL_CTX_NOFP=[0.97] * 5)                         # context loses more
    assert EV.h_c2(rec3, EVC)["verdict"] == EV.NOT_HOLDS and EV.h_c2(rec3, EVC)["diff"]["hi"] < 0


def _pairs(rec, n_miss=100, classes=(1, 3), seeds=range(5)):
    return [{"k": k, "s": s, "n_miss": n_miss, "recall": rec + 0.01 * (s - 2)} for k in classes for s in seeds]


def test_h_c3_branches():
    fa_ok = [5.0, 6.0, 5.5, 6.2, 5.8]
    R = EV.h_c3(_pairs(0.8), fa_ok, 18.0, ZD, EVC, [1, 3])
    assert R["verdict"] == EV.HOLDS and R["recall_ok"] and R["fa_ok"] and R["recall"]["n"] == 10
    R = EV.h_c3(_pairs(0.45), fa_ok, 18.0, ZD, EVC, [1, 3])
    assert R["verdict"] == EV.NOT_HOLDS and not R["recall_ok"] and "lower bound" in R["reason"]
    R = EV.h_c3(_pairs(0.8), [17.0, 19.5, 18.4, 18.0, 17.9], 18.0, ZD, EVC, [1, 3])
    assert R["verdict"] == EV.NOT_HOLDS and R["recall_ok"] and not R["fa_ok"]
    R = EV.h_c3(_pairs(0.9, n_miss=10), fa_ok, 18.0, ZD, EVC, [1, 3])
    assert R["verdict"] == EV.NOT_HOLDS and R["recall"]["n"] == 0 and "no eligible pair" in R["reason"]
    mixed = _pairs(0.8) + _pairs(0.0, classes=(2,))                       # class 2 (rare) excluded from the verdict
    assert EV.h_c3(mixed, fa_ok, 18.0, ZD, EVC, [1, 3])["recall"]["n"] == 10
    nan = _pairs(0.8) + [{"k": 1, "s": 9, "n_miss": 50, "recall": float("nan")}]
    assert EV.h_c3(nan, fa_ok, 18.0, ZD, EVC, [1, 3])["recall"]["n"] == 10


def test_noninferiority_branches():
    g = [0.9978, 0.9975, 0.9980, 0.9977, 0.9979]
    R = EV.noninferiority([x + 0.0005 for x in g], g, [3, 2, 2, 1, 3], [2, 2, 2, 1, 3], NI, EVC)
    assert R["status"] == EV.PASS and R["fa_count_diff_median"] == 0
    R = EV.noninferiority([x - 0.004 for x in g], g, [2] * 5, [2] * 5, NI, EVC)
    assert R["status"] == EV.FAIL and not R["macro_f1_ok"]
    R = EV.noninferiority(g, g, [5, 6, 2, 7, 5], [2, 2, 2, 2, 2], NI, EVC)
    assert R["status"] == EV.FAIL and R["macro_f1_ok"] and not R["fa_ok"] and R["fa_count_diff_median"] == 3
    R = EV.noninferiority(g, g, [4, 4, 4, 2, 2], [2] * 5, NI, EVC)        # median exactly 2 -> passes (<=)
    assert R["fa_ok"] and R["status"] == EV.PASS


def test_eval_arm_fa_counts_hours():
    y = np.array([0, 0, 0, 1, 1, 0])
    pred = np.array([0, 1, 0, 1, 0, 3])
    sess = np.array(["s"] * 6)
    ts = np.array([0, 10, 20, 30, 40, 50])
    E = EV.eval_arm(y, pred, 4, [0, 1], sess, ts, 300)
    assert E["fa_count"] == 2 and np.isclose(E["benign_hours"], 51 / 3600)
    assert np.isclose(E["fa_per_hour"] * E["benign_hours"], E["fa_count"])
    assert E["recall"][1] == 0.5 and np.isnan(E["recall"][2])


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
