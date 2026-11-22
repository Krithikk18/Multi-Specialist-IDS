"""tests/test_phase5_end_to_end.py -- the Phase 5A path end to end on tiny synthetic datasets (no project data, temp dirs):
36 core (LOAO Stage 1 retrains, misses) -> 37 core (models of normal, three arms, threshold + determinism checks) -> 38
core (miss-recall, paired CIs, FA / h, verdict, kill-rule line) -> figures + phase summary render.

Case 1 -- two groups whose benign differ; each of two held-out attacks sits on the OTHER group's benign region (plus a
          feature that is constant in benign, so a model of normal cannot see it): Stage 1 trained without the attack
          calls it benign, the global model of normal sees "normal" traffic, the per-group model of the attack's own group
          flags it -> PER_GROUP_WINS (both readings agree), random-group control does not win.
Case 2 -- the two groups' benign are identical (three clusters each); the held-out attacks sit in the gaps between
          benign clusters (inside the benign range), so both arms flag the misses alike -> d ~ 0 -> DOES_NOT_WIN, kill
          rule fires. (Attacks placed OUTSIDE the benign range are a different story: an isolation tree scores them like
          the most extreme training rows, and smaller per-group training sets then flag more of them even when the
          groups are identical -- the effect the RANDOM_GROUP control exists to expose; D-log.)

Plain asserts. Usage (repo root): python tests/test_phase5_end_to_end.py
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common import normal_model as NM  # noqa: E402
from common import zeroday_config as ZC  # noqa: E402
from common import zeroday_metrics as ZM  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

CFG2 = load_phase2_config(ROOT / "config" / "v2_phase2_v2_1.json")
NAMES = ["benign", "a1", "a2", "a3"]
FEATS = [f"f{i}" for i in range(7)]
SEEDS = [0, 1, 2]


def _script(fname: str, modname: str):
    spec = importlib.util.spec_from_file_location(modname, ROOT / fname)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


S36, S37, S38 = (_script("36_loao_stage1.py", "s36"), _script("37_fit_normal_models.py", "s37"),
                 _script("38_zeroday_eval.py", "s38"))


def _cfg5():
    c = copy.deepcopy(ZC.load_phase5_config(verify_pin=False))
    c["loao"]["nthread"] = 2
    c["normal_model"].update({"n_estimators": 100, "n_jobs": 1, "min_group_benign": 300, "score_chunk_rows": 2000})
    c["eval"].update({"bootstrap_resamples": 2000, "single_flow_timing_calls": 3, "score_hist_bins": 30})
    return c


def _raw(z):
    """Raw feature values whose signed log1p is z (heavy-tailed raw scale, like flow counters)."""
    return (np.sign(z) * np.expm1(np.abs(z))).astype(np.float32)


def _make(case: int, n_scale: int, seed: int):
    rng = np.random.default_rng(seed)
    nb, na = 3 * n_scale, n_scale
    rows, y, g = [], [], []

    def add(n, center, cls, grp, extra=None):
        z = rng.normal(0, 0.4, (n, 7))
        z[:, :5] += center
        z[:, 5:] = 0.0
        if extra is not None:
            z[:, extra[0]] = extra[1]
        rows.append(z)
        y.extend([cls] * n)
        g.extend([grp] * n)

    if case == 1:
        add(nb, 0.0, 0, "gA")
        add(nb, 4.0, 0, "gB")
        add(na, 4.0, 1, "gA", (5, 2.0))             # a1: group A rows that look like B's benign
        add(na, np.array([-6, 0, 0, 0, 0.0]), 2, "gA")   # a2: far outside both groups (both arms flag)
        add(na, 0.0, 3, "gB", (6, 2.0))             # a3: group B rows that look like A's benign
    else:
        for grp in ("gA", "gB"):                     # identical benign in both groups: clusters at 0, 6, 12
            for c in (0.0, 6.0, 12.0):
                add(nb // 3, c, 0, grp)
        add(na, 3.0, 1, "gA")                        # a1: in the gap 0..6 (inside the benign range: both arms isolate it)
        add(na, 9.0, 2, "gB")                        # a2: in the gap 6..12
        add(na, 3.0, 3, "gA", (6, 2.0))              # a3: a1's region + a benign-constant feature (Stage 1 calls it a1)
    Z = np.vstack(rows)
    return _raw(Z), np.array(y, np.int64), np.array(g)


def _run(case: int):
    cfg5 = _cfg5()
    Xtr, ytr, gtr = _make(case, 400, 1)
    Xva, yva, gva = _make(case, 150, 2)
    sess = np.array(["s1"] * len(yva))
    ts = np.sort(np.random.default_rng(3).integers(0, 360_000, len(yva)))   # ~100 h, one active segment
    quiet = (lambda *_a, **_k: None)
    o36 = S36.core(Xtr, ytr, Xva, yva, sess, ts, NAMES, cfg5, CFG2, SEEDS, quiet)
    b = ytr == 0
    Z, nonfinite = NM.prepare(Xtr[b], FEATS)
    assert nonfinite == {}
    o37 = S37.core(Z, gtr[b], cfg5, SEEDS, quiet)
    Zva, _ = NM.prepare(Xva, FEATS)
    tscores = {k: S37.owner_scores(A, len(Z)) for k, A in o37["fits"].items()}
    E, SC = S38.core(yva, gva, sess, ts, Zva, o36["pairs"], o36["preds"], o37["fits"], NAMES, cfg5, o36["nonrare"],
                     o36["rare"], SEEDS, o36["benign_hours"], quiet, tscores, gtr[b])
    return cfg5, o36, o37, E, SC


def _render(E, o36, o37):
    d = Path(tempfile.mkdtemp(prefix="p5_e2e_"))
    TC = {a: {r["seed"]: r["threshold_check"]["held_out_flag_rate"] for r in o37["records"] if r["arm"] == a}
          for a in S38.ARMS}
    E = {**E, "loao": {"pairs": o36["pairs"], "control": {"skipped": "test"}, "classes": {}}}
    figs = S38.make_figures(d / "figures", E, TC)
    assert len(figs) == 7, figs
    txt = S38.phase_summary(E, {"loao": E["loao"], "normal": o37["records"], "runs": {"36": "t", "37": "t", "38": "t"},
                                "figures": figs, "rare_rule": 50, "determinism": {"x": True}, "sizes": {a: 0 for a in S38.ARMS}})
    assert E["kill_line"] in txt and E["verdict"]["verdict"] in txt
    return txt


def test_case1_per_group_beats_global():
    cfg5, o36, o37, E, SC = _run(1)
    assert o36["nonrare"] == [1, 2, 3] and o36["rare"] == []
    assert len(o36["pairs"]) == 3 * len(SEEDS)
    p1 = [p for p in E["pairs"] if p["k"] == 1]
    assert all(p["n_miss"] >= 0.9 * p["n_val"] for p in p1), [(p["n_miss"], p["n_val"]) for p in p1]   # Stage 1 misses a1
    assert all(p["recall"][ZM.A_PER_GROUP] > 0.9 and p["recall"][ZM.A_GLOBAL] < 0.2 for p in p1), \
        [p["recall"] for p in p1]
    assert all(p["eligible"] for p in E["pairs"] if p["n_miss"] >= 30)
    V = E["verdict"]
    assert V["verdict"] == ZM.WIN and V["agree"], (V["prereg"]["reason"], V["literal"]["reason"], V["prereg"]["ci_d"],
                                                   V["prereg"]["ci_fa"])
    assert V["prereg"]["ci_d"]["lo"] > 0 and V["prereg"]["ci_fa"]["hi"] <= 0.5
    assert E["kill_line"] == ZM.KILL_NOT
    assert E["random_control"]["prereg"]["verdict"] == ZM.NO_WIN       # random groups mix both benign clusters
    for a in S38.ARMS:                                                  # FA counts and hours consistent
        for s in SEEDS:
            f = E["fa"][a][str(s)]
            assert np.isclose(f["fa_per_hour"] * f["benign_hours"], f["fa_count"])
    assert all(v["identical"] for v in o37["determinism"].values())
    assert all(r["fallback"] == [] for r in o37["records"])
    assert set(SC) == {(a, s) for a in S38.ARMS for s in SEEDS}
    _render(E, o36, o37)


def test_case2_identical_groups_does_not_win():
    cfg5, o36, o37, E, SC = _run(2)
    el = [p for p in E["pairs"] if p["eligible"]]
    assert {p["k"] for p in el} >= {1, 2}, [(p["class"], p["s"], p["n_miss"]) for p in E["pairs"]]
    assert all(abs(p["recall"][ZM.A_PER_GROUP] - p["recall"][ZM.A_GLOBAL]) <= 0.02 for p in el), \
        [(p["class"], p["recall"]) for p in el]
    V = E["verdict"]
    assert V["verdict"] == ZM.NO_WIN and V["agree"] and not V["prereg"]["a_recall_ci_above_0"], V["prereg"]["reason"]
    assert E["kill_line"] == ZM.KILL_FIRES == "Kill rule §5 FIRES: routing is operational only; no novelty claim."
    txt = _render(E, o36, o37)
    assert "operational feature only" in txt


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
