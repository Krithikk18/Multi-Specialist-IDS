"""tests/test_phase5_zeroday_metrics.py -- common/zeroday_metrics.py (Phase 5A verdict): miss-recall; paired difference;
bootstrap reproducible with its seed (and a known case); eligibility (< min_misses excluded); every verdict branch
(win; recall CI touches 0; FA upper CI > 0.5; insufficient support: no eligible pair / one class only); the CONFLICT
guard (prereg vs Amendment 2 literal reading); kill-rule line text for both outcomes; FA / h and counts consistent.

Plain asserts. Usage (repo root): python tests/test_phase5_zeroday_metrics.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import zeroday_metrics as ZM  # noqa: E402

EV = {"min_misses": 30, "ci_level": 0.95, "bootstrap_resamples": 10000, "bootstrap_seed": 0, "fa_margin_per_h": 0.5,
      "min_support_classes": 2}
G, PG = ZM.A_GLOBAL, ZM.A_PER_GROUP
SEEDS = [0, 1, 2, 3, 4]


def _pairs(d_by_class: dict, n_miss=500, base=0.5, jitter=0.01):
    out = []
    for k, d in d_by_class.items():
        for s in SEEDS:
            j = jitter * (s - 2)
            out.append({"k": k, "s": s, "n_miss": n_miss if not callable(n_miss) else n_miss(k, s),
                        "recall": {G: base, PG: base + d + j}})
    return out


def _fa(diffs, base=10.0):
    return {G: {s: base for s in SEEDS}, PG: {s: base + d for s, d in zip(SEEDS, diffs)}}


def test_miss_recall():
    r = ZM.miss_recall(np.array([1, 0, 1, 1, 0], bool), np.array([1, 1, 0, 1, 0], bool))
    assert r == {"flagged": 2, "n": 3, "recall": 2 / 3}
    assert np.isnan(ZM.miss_recall(np.ones(3, bool), np.zeros(3, bool))["recall"])


def test_bootstrap_reproducible_and_correct():
    v = np.arange(10.0)
    a = ZM.bootstrap_mean_ci(v, 10000, 0)
    b = ZM.bootstrap_mean_ci(v, 10000, 0)
    c = ZM.bootstrap_mean_ci(v, 10000, 1)
    assert a == b and a != c and a["mean"] == 4.5 and a["lo"] < 4.5 < a["hi"]
    rng = np.random.default_rng(0)
    means = v[rng.integers(0, 10, size=(10000, 10))].mean(1)
    assert np.isclose(a["lo"], np.percentile(means, 2.5)) and np.isclose(a["hi"], np.percentile(means, 97.5))
    const = ZM.bootstrap_mean_ci([0.2] * 5, 1000, 0)
    assert const["lo"] == const["hi"] == 0.2
    assert ZM.bootstrap_mean_ci([], 100, 0)["n"] == 0


def test_paired_difference_and_eligibility():
    pairs = _pairs({1: 0.1, 3: 0.2}, n_miss=lambda k, s: 29 if (k == 3 and s == 4) else 100)
    T = ZM.paired_test(pairs, _fa([0] * 5), EV, G, PG, [1, 3], EV["min_misses"])
    assert T["n_pairs"] == 9 and all(p["n_miss"] >= 30 for p in T["pairs_used"])
    assert not any(p["k"] == 3 and p["s"] == 4 for p in T["pairs_used"])
    assert np.allclose(sorted(T["d"]), sorted(p["recall"][PG] - p["recall"][G] for p in pairs
                                              if not (p["k"] == 3 and p["s"] == 4)))
    tab = ZM.eligibility_table(pairs, [1, 3], 30)
    assert tab == {1: {"pairs": 5, "eligible": 5}, 3: {"pairs": 5, "eligible": 4}}


def test_verdict_win():
    V = ZM.verdict(_pairs({1: 0.10, 3: 0.20}), _fa([0.1, 0.0, -0.1, 0.2, 0.0]), EV, [1, 3], [1, 3])
    assert V["verdict"] == ZM.WIN and V["agree"], V["prereg"]["reason"]
    assert V["prereg"]["a_recall_ci_above_0"] and V["prereg"]["b_fa_ci_within_margin"]
    assert ZM.kill_line(V["verdict"], ZM.NO_WIN) == ZM.KILL_NOT


def test_verdict_recall_ci_touches_zero():
    V = ZM.verdict(_pairs({1: 0.0, 3: 0.0}, jitter=0.05), _fa([0] * 5), EV, [1, 3], [1, 3])
    assert V["prereg"]["ci_d"]["lo"] <= 0 <= V["prereg"]["ci_d"]["hi"]
    assert V["verdict"] == ZM.NO_WIN and "(a) fails" in V["prereg"]["reason"]
    assert ZM.kill_line(V["verdict"], ZM.NO_WIN) == ZM.KILL_FIRES


def test_verdict_fa_upper_ci_above_margin():
    V = ZM.verdict(_pairs({1: 0.3, 3: 0.3}), _fa([0.4, 0.6, 0.5, 0.7, 0.55]), EV, [1, 3], [1, 3])
    assert V["prereg"]["a_recall_ci_above_0"] and V["prereg"]["ci_fa"]["hi"] > 0.5
    assert V["verdict"] == ZM.NO_WIN and "(b) fails" in V["prereg"]["reason"]
    # exactly at the margin passes (<=)
    V2 = ZM.verdict(_pairs({1: 0.3, 3: 0.3}), _fa([0.5] * 5), EV, [1, 3], [1, 3])
    assert V2["prereg"]["ci_fa"]["hi"] == 0.5 and V2["verdict"] == ZM.WIN


def test_verdict_insufficient_support_no_pairs():
    V = ZM.verdict(_pairs({1: 0.3, 3: 0.3}, n_miss=10), _fa([0] * 5), EV, [1, 3], [1, 3])
    assert V["prereg"]["verdict"] == ZM.NO_WIN and "no eligible pair" in V["prereg"]["reason"]
    # the literal reading (>= 1 miss) would see a win -> CONFLICT, no verdict declared
    assert V["literal"]["verdict"] == ZM.WIN and V["verdict"] == ZM.CONFLICT and not V["agree"]
    assert ZM.kill_line(V["verdict"], ZM.NO_WIN) == ZM.KILL_CONFLICT
    V0 = ZM.verdict(_pairs({1: 0.3, 3: 0.3}, n_miss=0), _fa([0] * 5), EV, [1, 3], [1, 3])
    for p in V0["prereg"], V0["literal"]:
        assert p["n_pairs"] == 0 and p["verdict"] == ZM.NO_WIN
    assert V0["verdict"] == ZM.NO_WIN and V0["agree"]


def test_verdict_insufficient_support_one_class():
    pairs = _pairs({1: 0.3, 3: 0.3}, n_miss=lambda k, s: 100 if k == 1 else 5)
    V = ZM.verdict(pairs, _fa([0] * 5), EV, [1, 3], [1, 3])
    assert V["prereg"]["support_classes"] == [1] and "insufficient support" in V["prereg"]["reason"]
    assert V["prereg"]["verdict"] == ZM.NO_WIN and V["literal"]["verdict"] == ZM.WIN and V["verdict"] == ZM.CONFLICT
    # if the literal reading also fails, both agree on DOES_NOT_WIN
    pairs2 = _pairs({1: -0.1, 3: -0.1}, n_miss=lambda k, s: 100 if k == 1 else 5)
    V2 = ZM.verdict(pairs2, _fa([0] * 5), EV, [1, 3], [1, 3])
    assert V2["verdict"] == ZM.NO_WIN and V2["agree"]


def test_rare_class_only_in_literal_reading():
    pairs = _pairs({1: 0.0, 3: 0.0}, jitter=0.05) + _pairs({2: 0.9}, n_miss=10)
    V = ZM.verdict(pairs, _fa([0] * 5), EV, [1, 3], [1, 3, 2])
    assert {p["k"] for p in V["prereg"]["pairs_used"]} == {1, 3}
    assert {p["k"] for p in V["literal"]["pairs_used"]} == {1, 2, 3}


def test_kill_line_text():
    assert ZM.kill_line(ZM.NO_WIN, ZM.NO_WIN) == "Kill rule §5 FIRES: routing is operational only; no novelty claim."
    assert ZM.kill_line(ZM.WIN, ZM.NO_WIN) == ("Kill rule §5 does not fire: the routing novelty claim rests on the "
                                               "zero-day result (§3) alone.")
    try:
        ZM.kill_line("MAYBE", ZM.NO_WIN)
        raise AssertionError("unknown verdict accepted")
    except ValueError:
        pass


def test_fa_rate_counts_consistent():
    flag = np.array([1, 1, 0, 1, 0, 0], bool)
    ben = np.array([1, 0, 1, 1, 1, 0], bool)
    r = ZM.fa_rate(flag, ben, 2.0)
    assert r["fa_count"] == 2 and r["n_benign"] == 4 and r["fa_per_hour"] == 1.0 and r["flag_rate"] == 0.5
    assert np.isclose(r["fa_per_hour"] * r["benign_hours"], r["fa_count"])
    assert np.isnan(ZM.fa_rate(flag, ben, 0.0)["fa_per_hour"])


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
