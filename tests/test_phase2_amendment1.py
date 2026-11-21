"""tests/test_phase2_amendment1.py -- Phase 2 closeout plumbing: the v2_1 config (optional keys, results folder),
backwards compatibility of config/v2_phase2.json, and Amendment 1's primary-selection rule (common/amendment.py).

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_phase2_amendment1.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from common import amendment as A  # noqa: E402
from common import phase2_config as C  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import schemas as S  # noqa: E402
from config.config import RESULTS_DIR  # noqa: E402

V21 = REPO / "config" / "v2_phase2_v2_1.json"


def _tmp(obj) -> Path:
    p = Path(tempfile.mkdtemp(prefix="test_amend1_")) / "cfg.json"
    p.write_bytes((json.dumps(obj, indent=1) + "\n").encode("utf-8"))
    return p


def _raises(fn, exc=Exception, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or match in str(e)
    return False


def test_old_config_unchanged_behaviour():
    cfg = C.load_phase2_config()
    assert "_results_root" not in cfg and not A.active(cfg)
    assert R.results_root(cfg) == RESULTS_DIR
    d = Path(tempfile.mkdtemp(prefix="test_amend1_run_"))
    c2 = copy.deepcopy(cfg)
    c2["paths"]["cache_root"], c2["_results_root"] = str(d / "cache"), str(d / "results")
    ctx = R.start_run("97", "models", "x.py", c2, dry_run=True, run_id="T1")
    M = R.base_manifest(ctx, "22_train_multiclass.py")
    assert M["config"]["path"] == "config/v2_phase2.json"
    assert list(M["code_sha256"]) == ["22_train_multiclass.py", *R.COMMON_CODE]          # same files as before
    assert "prereg_amendments" not in M and "orientation" not in M
    R.finish_run(ctx, True, M)
    assert C.config_from_arg(None)["_sha256"] == cfg["_sha256"]


def test_v2_1_config_loads_and_differs_only_where_intended():
    cfg = C.config_from_arg(str(V21))
    assert cfg["dataset_version"] == "v2_1_oriented" and A.active(cfg)
    assert Path(cfg["_results_root"]) == RESULTS_DIR / "v2_1" == R.results_root(cfg)
    a, b = json.loads(C.CONFIG_PATH.read_bytes()), json.loads(V21.read_bytes())
    diff = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    assert diff == ["dataset_version", "note", "orientation", "prereg_amendments", "primary_selection", "results_subdir"]
    assert b"\r" not in V21.read_bytes()
    assert cfg["prereg_amendments"] == ["docs/V2_PREREG_PHASE2_AMENDMENT_1.md"]
    assert R.sha256_path(REPO / cfg["prereg_amendments"][0]) == S.PREREG_PHASE2_AMENDMENT_1_SHA256
    assert R.sha256_path(REPO / cfg["orientation"]["map"]) == S.ORIENTATION_MAP_SHA256


def test_optional_keys_validated():
    base = json.loads(V21.read_bytes())
    for key, bad, msg in (("results_subdir", "../escape", "results_subdir"),
                          ("prereg_amendments", ["docs/NO_SUCH_FILE.md"], "prereg_amendments"),
                          ("orientation", {"map": "config/none.json", "rule": "R3"}, "orientation"),
                          ("primary_selection", {"rule": "x", "tolerance": -1, "tie_order": ["none"]}, "tolerance"),
                          ("primary_selection", {"rule": "x", "tolerance": 0.005, "tie_order": ["equal"]}, "tie_order")):
        c = copy.deepcopy(base)
        c[key] = bad
        assert _raises(lambda: C.load_phase2_config(_tmp(c)), C.ConfigError, msg), key


def _row(m, f1, fa):
    return {"mode": m, "macro_f1_nonrare_mean": f1, "fa_count_mean": fa}


def test_decide_rule():
    order = ["none", "sqrt", "balanced"]
    d = A.decide([_row("none", 0.990, 12.0), _row("sqrt", 0.996, 8.0), _row("balanced", 0.993, 5.0)], 0.005, order)
    assert d["within_tolerance"] == ["sqrt", "balanced"] and d["chosen"] == "balanced"   # none is 0.006 below
    d = A.decide([_row("none", 0.996, 6.0), _row("sqrt", 0.996, 6.0), _row("balanced", 0.995, 9.0)], 0.005, order)
    assert d["tied_on_fa"] == ["none", "sqrt"] and d["chosen"] == "none" and d["tie_break_used"]
    d = A.decide([_row("none", 0.980, 1.0), _row("sqrt", 0.996, 6.0), _row("balanced", 0.995, 6.0)], 0.005, order)
    assert d["chosen"] == "sqrt" and d["tied_on_fa"] == ["sqrt", "balanced"]          # none out; first in order
    d = A.decide([_row("none", 0.9950, 4.0), _row("sqrt", 1.0, 9.0)], 0.005, order)
    assert d["chosen"] == "none"                                                       # exactly at the tolerance edge


def test_select_primary_and_chosen():
    cfg = C.config_from_arg(str(V21))
    agg = lambda f1, fas: {"all": {"aggregate": {"macro_f1_nonrare": {"mean": f1, "lo": f1 - .001, "hi": f1 + .001},  # noqa: E731
                                                  "macro_f1_all": {"mean": f1 - .1}, "fa_counts_per_seed": fas,
                                                  "fa_per_hour": {"mean": sum(fas) / len(fas) / 2}}}}
    E = {"ROUTED": agg(0.997, [8, 9, 8, 9, 8]), "ROUTED_A1_none": agg(0.996, [3, 3, 4, 3, 3]),
         "ROUTED_A1_balanced": agg(0.990, [1, 1, 1, 1, 1]), "FLAT_GLOBAL": agg(0.99, [5] * 5),
         "FLAT_GLOBAL_A1_none": agg(0.99, [5] * 5)}
    ps = A.select_primary(E, cfg)
    assert ps["chosen"] == "none" and ps["chosen_routed_system"] == "ROUTED_A1_none"
    assert ps["chosen_flat_system"] == "FLAT_GLOBAL_A1_none" and ps["chosen_config_label"] == "A1_none"
    assert [r["mode"] for r in ps["table"]] == ["sqrt", "none", "balanced"]
    M22 = {"routing": {"primary": {"G1": "SPEC_G1__sqrt", "G2": "SPEC_G2__sqrt", "GEN": "GLOBAL__sqrt"},
                       "default": "GLOBAL__sqrt"}}
    up23 = {"manifest": {"primary_selection": ps}, "meta": {"run_id": "R23"}}
    ch = A.chosen(cfg, M22, up23)
    assert ch["routing"] == {"G1": "SPEC_G1__none", "G2": "SPEC_G2__none", "GEN": "GLOBAL__none"}
    assert ch["default"] == "GLOBAL__none" and ch["config_label"] == "A1_none"
    old = A.chosen(C.load_phase2_config(), M22, None)
    assert old["config_label"] == "primary" and old["routing"] == M22["routing"]["primary"]
    assert _raises(lambda: A.chosen(cfg, M22, None), RuntimeError, "primary_selection")


def test_scripts_take_config_option():
    for s in ("22_train_multiclass.py", "23_evaluate.py", "24_calibrate.py", "25_explain_shap.py", "26_model_registry.py"):
        src = (REPO / s).read_text(encoding="utf-8")
        assert '"--config"' in src and "config_from_arg(" in src and "load_phase2_config()" not in src, s
        assert "R.resolve_run(" not in src or "R.results_root(cfg)" in src, s


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
