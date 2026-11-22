"""tests/test_cl_gate.py -- common/cl_gate.py: each gate condition fails on its own ((i) recall, (ii) non-rare
macro-F1, (iii) FA/h); limits are inclusive; rare classes are never gated; eval_set metrics (macro-F1 over non-rare,
FA/h with the active-segment hours); the Amendment 2 section 4 rule (lower / equal + cheaper / affected-group cases);
the poisoning verdict; poison targets and label flips. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_cl_gate.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import cl_gate as CG  # noqa: E402

G = {"min_val_flows": 50, "max_recall_drop": 0.01, "max_macro_f1_drop": 0.002, "max_fa_per_h_rise": 0.5}
VC = {"forgetting_equal_tol": 0.002, "time_ratio": 2.0, "affected_group_tol": 0.005}


def _E(recall, f1nr=0.99, fa=1.0, support=(1000, 1000, 10, 1000)):
    return {"recall": list(recall), "macro_f1_nonrare": f1nr, "fa_per_hour": fa, "support": list(support)}


NONRARE = [0, 1, 3]


def test_all_hold_pass():
    g = CG.gate(_E([1, .99, .5, .98]), _E([1, .99, .9, .98]), NONRARE, G)
    assert g["pass"] and g["status"] == "PASS" and g["rare_not_gated"] == [2]


def test_i_recall_drop_fails():
    g = CG.gate(_E([1, .975, .9, .98]), _E([1, .99, .9, .98]), NONRARE, G)
    assert not g["pass"] and not g["conditions"]["i_recall"]["pass"] and 1 in g["conditions"]["i_recall"]["failing"]
    assert g["conditions"]["ii_macro_f1_nonrare"]["pass"] and g["conditions"]["iii_fa_per_hour"]["pass"]


def test_i_limit_inclusive():
    g = CG.gate(_E([1, .9805, .9, .98]), _E([1, .99, .9, .98]), NONRARE, G)
    assert g["conditions"]["i_recall"]["pass"] and g["pass"]
    g2 = CG.gate(_E([1, .9795, .9, .98]), _E([1, .99, .9, .98]), NONRARE, G)
    assert not g2["conditions"]["i_recall"]["pass"]


def test_ii_macro_f1_fails():
    g = CG.gate(_E([1, .99, .9, .98], f1nr=0.9875), _E([1, .99, .9, .98], f1nr=0.99), NONRARE, G)
    assert not g["pass"] and not g["conditions"]["ii_macro_f1_nonrare"]["pass"] and g["conditions"]["i_recall"]["pass"]
    g2 = CG.gate(_E([1, .99, .9, .98], f1nr=0.9885), _E([1, .99, .9, .98], f1nr=0.99), NONRARE, G)
    assert g2["conditions"]["ii_macro_f1_nonrare"]["pass"]


def test_iii_fa_fails():
    g = CG.gate(_E([1, .99, .9, .98], fa=1.6), _E([1, .99, .9, .98], fa=1.0), NONRARE, G)
    assert not g["pass"] and not g["conditions"]["iii_fa_per_hour"]["pass"]
    assert CG.gate(_E([1, .99, .9, .98], fa=1.5), _E([1, .99, .9, .98], fa=1.0), NONRARE, G)["pass"]


def test_rare_class_not_gated():
    g = CG.gate(_E([1, .99, 0.0, .98]), _E([1, .99, 1.0, .98]), NONRARE, G)
    assert g["pass"] and 2 not in g["conditions"]["i_recall"]["drops"]


def test_nonrare_and_eval_set():
    y = np.array([0] * 60 + [1] * 60 + [2] * 5)
    assert CG.nonrare_classes(y, 4, 50) == [0, 1]
    pred = y.copy()
    pred[:3] = 1                                                    # 3 false alarms
    pred[60:66] = 0                                                 # 6 misses of class 1
    sess = np.array(["s"] * len(y))
    t = np.arange(len(y)) * 10                                      # one active segment of (124 * 10 + 1) s
    E = CG.eval_set(y, pred, 4, [0, 1], sess, t, 300)
    assert E["fa_count"] == 3 and abs(E["benign_hours"] - 1241 / 3600) < 1e-12
    assert abs(E["fa_per_hour"] - 3 / (1241 / 3600)) < 1e-9
    assert abs(E["recall"][1] - 54 / 60) < 1e-12 and np.isnan(E["recall"][3])
    f1 = np.array(E["f1"])
    assert abs(E["macro_f1_nonrare"] - f1[[0, 1]].mean()) < 1e-12 and E["nonrare"] == [0, 1]
    assert abs(E["macro_f1_all"] - f1[[0, 1, 2]].mean()) < 1e-12


def test_verdict_lower_wins():
    V = CG.verdict_a2s4([0, 0, 0, 0, 0], [.01, .012, .009, .011, .01], [.99] * 5, [.99] * 5, [10] * 5, [10] * 5, VC)
    assert V["forgetting_lower"] and V["wins"]


def test_verdict_equal_needs_cost():
    z = [0.0] * 5
    gl = [.0005, -.0003, .0001, .0002, 0]
    V = CG.verdict_a2s4(z, gl, [.99] * 5, [.99] * 5, [10] * 5, [12] * 5, VC)
    assert V["forgetting_equal_within_tol"] and not V["time_cheaper"] and not V["wins"]
    V2 = CG.verdict_a2s4(z, gl, [.99] * 5, [.99] * 5, [5] * 5, [10] * 5, VC)
    assert V2["time_cheaper"] and V2["wins"]


def test_verdict_affected_group_blocks():
    V = CG.verdict_a2s4([0] * 5, [.01, .012, .009, .011, .01], [.98] * 5, [.99] * 5, [5] * 5, [10] * 5, VC)
    assert V["forgetting_lower"] and not V["affected_group_ok"] and not V["wins"]


def test_verdict_zero_vs_zero_not_lower():
    V = CG.verdict_a2s4([0] * 5, [0] * 5, [.99] * 5, [.99] * 5, [10] * 5, [10.5] * 5, VC)
    assert not V["forgetting_lower"] and V["forgetting_equal_within_tol"] and not V["wins"]


def test_poisoning_verdict():
    assert CG.poisoning_verdict(True, True) == "CAUGHT_BY_VALIDATOR"
    assert CG.poisoning_verdict(False, False) == "CAUGHT_BY_GATE"
    assert CG.poisoning_verdict(False, True) == "NOT_CAUGHT"


def test_poison_targets_and_flip():
    lab = np.array([0] * 10 + [1] * 50 + [2] * 3 + [3] * 20)
    t = CG.poison_targets(lab, 4, nonrare=[0, 1, 3])
    assert t["p1"] == 1 and t["p2"] == 3                            # class 2 is rare -> not the P2 target
    new, fl = CG.flip_labels(lab, 1, 0, 0.10, 0)
    assert fl.sum() == 5 and (new[fl] == 0).all() and (lab[fl] == 1).all() and (new[~fl] == lab[~fl]).all()
    new2, fl2 = CG.flip_labels(lab, 3, 0, 1.0, 0)
    assert fl2.sum() == 20 and not (new2 == 3).any()


def main() -> int:
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]
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
