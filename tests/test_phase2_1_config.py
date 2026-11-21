"""tests/test_phase2_1_config.py -- Phase 2 step 1: config loader / validation, the train/val-only data door,
the pre-registered training-set rules, and the run plumbing. Synthetic data and temp dirs only.

Plain asserts, no pytest fixtures or imports, so the file also runs without pytest.
Usage (repo root): python tests/test_phase2_1_config.py
"""

from __future__ import annotations

import copy
import json
import re
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase2_config as C  # noqa: E402
from common import phase2_data as D  # noqa: E402
from common import phase2_run as R  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
PHASE2_SCRIPTS = ["22_train_multiclass.py", "23_evaluate.py", "24_calibrate.py", "25_explain_shap.py",
                  "26_model_registry.py"]


def _raises(fn, exc=Exception, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or re.search(match, str(e)) is not None
    return False


def _tmp(data: bytes, name: str = "v2_phase2.json") -> Path:
    p = Path(tempfile.mkdtemp(prefix="test_p2_")) / name
    p.write_bytes(data)
    return p


def _cfg_raw() -> dict:
    return json.loads(C.CONFIG_PATH.read_bytes())


# --------------------------------------------------------------------------- config
def test_real_config_valid():
    cfg = C.load_phase2_config()
    assert cfg["seeds"] == [0, 1, 2, 3, 4] and cfg["min_val_flows"] == 50
    assert cfg["xgb"]["params"]["tree_method"] == "hist" and "num_class" not in cfg["xgb"]["params"]
    assert len(cfg["_sha256"]) == 64 and cfg["class_weights"]["primary"] == "sqrt"


def test_config_rejections():
    cases = [
        (lambda c: c.__setitem__("seeds", [0, 0]), "seeds"),
        (lambda c: c.__setitem__("seeds", []), "seeds"),
        (lambda c: c.__setitem__("min_val_flows", 0), "min_val_flows"),
        (lambda c: c.__setitem__("inner_split_frac", 0.9), "inner_split_frac"),
        (lambda c: c["xgb"]["params"].__setitem__("num_class", 4), "num_class"),
        (lambda c: c["xgb"]["params"].__setitem__("objective", "binary:logistic"), "objective"),
        (lambda c: c["class_weights"].__setitem__("primary", "inverse"), "class_weights.primary"),
        (lambda c: c["class_weights"].__setitem__("ablation_modes", ["sqrt"]), "ablation_modes"),
        (lambda c: c["calibration"].__setitem__("temperature_bounds", [2, 3]), "temperature_bounds"),
        (lambda c: c["registry"].__setitem__("states", ["candidate", "promoted"]), "registry.states"),
        (lambda c: c["registry"].__setitem__("register_seed", 9), "register_seed"),
        (lambda c: c.pop("fallback_group"), "fallback_group"),
        (lambda c: c["paths"].pop("keys_dir"), "keys_dir"),
    ]
    for mutate, field in cases:
        c = _cfg_raw()
        mutate(c)
        p = _tmp(json.dumps(c).encode())
        assert _raises(lambda: C.load_phase2_config(p), C.ConfigError, re.escape(field)), field


def test_config_collects_all_errors():
    c = _cfg_raw()
    c["seeds"], c["min_val_flows"] = [], -1
    p = _tmp(json.dumps(c).encode())
    try:
        C.load_phase2_config(p)
    except C.ConfigError as e:
        assert "seeds" in str(e) and "min_val_flows" in str(e)
    else:
        raise AssertionError("no error")


def test_config_crlf_and_bad_json():
    assert _raises(lambda: C.load_phase2_config(_tmp(C.CONFIG_PATH.read_bytes().replace(b"\n", b"\r\n"))), C.ConfigError, "CR")
    assert _raises(lambda: C.load_phase2_config(_tmp(b"{not json")), C.ConfigError, "JSON")


# --------------------------------------------------------------------------- test-split guard
def test_load_split_refuses_test():
    cfg = C.load_phase2_config()
    for bad in ("test", "TEST", "holdout", ""):
        assert _raises(lambda: D.load_split(cfg, bad), D.TestSplitAccessError), bad
        assert _raises(lambda: D.split_file(cfg, bad), D.TestSplitAccessError), bad
    assert _raises(lambda: D._refuse_test("val", Path("/x/test.parquet")), D.TestSplitAccessError)
    assert D.split_file(cfg, "val").name == "val.parquet"


def test_phase2_scripts_never_name_the_test_file():
    """Static guard over every Phase 2 script present: data only via load_split, never a test path."""
    for s in PHASE2_SCRIPTS:
        p = REPO / s
        if not p.is_file():
            continue
        src = p.read_text(encoding="utf-8")
        assert "test.parquet" not in src, s
        assert not re.search(r"load_split\([^)]*['\"]test['\"]", src), s
        assert "read_table(" not in src or s == "26_model_registry.py", f"{s}: data must go through load_split"


# --------------------------------------------------------------------------- training-set rules
def test_pooled_mask():
    y = np.array([0, 0, 1, 2, 0, 3])
    g = np.array(["G1", "G2", "G2", "G1", "GEN", "GEN"])
    assert D.pooled_mask(y, g == "G1").tolist() == [True, False, True, True, False, True]
    assert D.pooled_mask(y, g == "GEN").tolist() == [False, False, True, True, True, True]


def test_class_weights():
    counts = np.array([100, 25, 0, 400])
    w = D.class_weights(counts, "sqrt")
    assert np.allclose(w, [1, 2.0, 1, 1]), w                          # sqrt(100/25)=2; absent -> 1; n_c >= n_b -> 1
    assert np.allclose(D.class_weights(counts, "none"), 1)
    b = D.class_weights(counts, "balanced")
    assert np.allclose(b, [525 / 300, 525 / 75, 1, 525 / 1200]), b    # N / (K_present * n_c), K_present = 3
    assert _raises(lambda: D.class_weights(counts, "inverse"), ValueError)


def test_stratified_split():
    y = np.array([0] * 100 + [1] * 30 + [2] * 3 + [3] * 1)
    fit, inner = D.stratified_split(y, 0.10, seed=7)
    assert len(np.intersect1d(fit, inner)) == 0 and len(fit) + len(inner) == len(y)
    assert np.bincount(y[inner], minlength=4).tolist() == [10, 3, 0, 0]
    f2, i2 = D.stratified_split(y, 0.10, seed=7)
    assert np.array_equal(inner, i2)                                  # deterministic per seed
    assert not np.array_equal(inner, D.stratified_split(y, 0.10, seed=8)[1])
    assert (np.diff(fit) > 0).all() and (np.diff(inner) > 0).all()


def test_stratified_sample():
    s = np.array(["a"] * 200 + ["b"] * 5 + ["c"] * 1)
    ix = D.stratified_sample(s, 0.05, seed=0)
    got = {k: int((s[ix] == k).sum()) for k in "abc"}
    assert got == {"a": 10, "b": 1, "c": 1}, got                        # every stratum kept (>= 1)
    assert np.array_equal(ix, D.stratified_sample(s, 0.05, seed=0)) and (np.diff(ix) > 0).all()


def test_specialist_groups():
    assert D.specialist_groups(["G2", "GEN", "G1", "G1"], "GEN") == ["G1", "G2"]
    assert D.specialist_groups(["A", "B", "C"], "GEN") == ["A", "B", "C"]   # data-agnostic


# --------------------------------------------------------------------------- run plumbing
def _tmp_cfg() -> dict:
    cfg = copy.deepcopy(C.load_phase2_config())
    d = Path(tempfile.mkdtemp(prefix="test_p2_run_"))
    cfg["paths"]["cache_root"] = str(d / "cache")
    cfg["_results_root"] = str(d / "results")
    return cfg


def test_run_lifecycle_and_refusal():
    cfg = _tmp_cfg()
    ctx = R.start_run("99", "models", "x.py", cfg, dry_run=False, run_id="20990101T000000Z")
    M = R.base_manifest(ctx, "22_train_multiclass.py")
    (ctx.partial / "artifact.bin").write_bytes(b"x")
    R.finish_run(ctx, True, M)
    assert (ctx.final / "artifact.bin").is_file() and (ctx.res / "run_meta.json").is_file()
    meta = json.loads((ctx.res / "run_meta.json").read_text())
    assert meta["status"] == "PASS" and meta["config_sha256"] == cfg["_sha256"] and "git" not in json.dumps(meta["checks"])
    assert _raises(lambda: R.start_run("99", "models", "x.py", cfg, False, "20990101T000000Z"), R.RunRefused, "exist")
    up = R.resolve_run("99", None, False, cfg["_results_root"])
    assert up["meta"]["run_id"] == "20990101T000000Z" and up["dir"] == ctx.final
    assert _raises(lambda: R.resolve_run("99", "OTHER", False, cfg["_results_root"]), R.RunRefused, "asked for")
    assert _raises(lambda: R.resolve_run("99", None, True, cfg["_results_root"]), R.RunRefused, "dry run id")
    m = ctx.final / "run_manifest.json"
    m.chmod(0o644)
    with open(m, "ab") as fh:                                        # tamper with the upstream manifest
        fh.write(b" ")
    assert _raises(lambda: R.resolve_run("99", None, False, cfg["_results_root"]), R.RunRefused, "sha256")


def test_failed_run_kept_not_deleted():
    cfg = _tmp_cfg()
    ctx = R.start_run("98", "models", "x.py", cfg, dry_run=True, run_id="R1")
    (ctx.partial / "half.bin").write_bytes(b"y")
    R.finish_run(ctx, False, R.base_manifest(ctx, "22_train_multiclass.py"))
    failed = ctx.root / "R1.FAILED"
    assert (failed / "half.bin").is_file() and (failed / "run_manifest.json").is_file() and not ctx.final.exists()
    assert json.loads((ctx.res / "run_meta.json").read_text())["status"] == "FAIL"


def test_run_id_validation():
    assert _raises(lambda: R.start_run("97", "models", "x.py", _tmp_cfg(), False, "../evil"), R.RunRefused, "run id")


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
