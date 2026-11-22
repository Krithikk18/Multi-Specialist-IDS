"""tests/test_model_loader.py -- common/model_loader.py (DFD P4): a tampered model, a wrong class-map / features /
orientation-map hash, an unpromoted entry, a missing public key, a non-zero seed outside evaluation, and a bad
routing set are all refused; candidate entries load only in evaluation mode; routing comes from serves_groups.
Synthetic signed registry in a temp dir (tiny XGBoost model), plus read-only checks on the real registry.

Plain asserts. Usage (repo root): python tests/test_model_loader.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import model_loader as ML  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import registry as REG  # noqa: E402
from common import schemas as S  # noqa: E402

_CACHE: dict = {}


def _raises(fn, exc=Exception, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or match.lower() in str(e).lower()
    return False


def _model_files(d: Path) -> tuple[Path, Path]:
    if "files" not in _CACHE:
        import xgboost as xgb
        rng = np.random.default_rng(0)
        X = rng.normal(size=(400, 70)).astype(np.float32)
        y = rng.integers(0, 4, 400)
        b = xgb.train({"objective": "multi:softprob", "num_class": 4, "max_depth": 2, "nthread": 1},
                      xgb.DMatrix(X, label=y), num_boost_round=3)
        d.mkdir(parents=True, exist_ok=True)
        mf, cf = d / "m.ubj", d / "cal.json"
        b.save_model(str(mf))
        cf.write_text(json.dumps({"temperature": 1.5}), encoding="utf-8")
        _CACHE["files"] = (mf, cf)
    return _CACHE["files"]


def _fields(model_id: str, kind: str, serves: list, **over) -> dict:
    f = {"model_id": model_id, "model_key": model_id + "__s0", "seed": 0, "kind": kind, "serves_groups": serves,
         "class_names": list(S.load_class_map().names), "class_map_sha256": S.CLASS_MAP_SHA256,
         "features_file_sha256": S.FEATURES_V1_SHA256, "orientation_map_sha256": S.ORIENTATION_MAP_SHA256,
         "train_run": "synthetic"}
    f.update(over)
    return {k: v for k, v in f.items() if v is not None}


def _registry(entries: dict) -> tuple[Path, Path, bytes]:
    """entries: entry_id -> (fields, final state). Returns (root, keys_dir, secret)."""
    base = Path(tempfile.mkdtemp(prefix="p3ml_"))
    keys, root = base / "keys", base / "registry"
    sk, _ = REG.ensure_keys(keys)
    mf, cf = _model_files(base / "src")
    for eid, (fields, state) in entries.items():
        d = REG.register(root, eid, mf, cf, fields, sk)
        for st in ("approved", "promoted"):
            if REG.STATES.index(st) <= REG.STATES.index(state):
                REG.transition(d, st, sk, by="test")
    return root, keys, sk


def _cfg(mode_entries: dict) -> dict:
    cfg = copy.deepcopy(C.load_phase3_config())
    for mode, ents in mode_entries.items():
        cfg["models"][mode]["entries"] = ents
    return cfg


def test_promoted_global_loads_and_candidate_refused():
    root, keys, _ = _registry({"G_prom": (_fields("GLOBAL__x", "global", ["GEN"]), "promoted"),
                               "G_cand": (_fields("GLOBAL__y", "global", ["GEN"]), "candidate")})
    rm = ML.load_runtime_model(_cfg({"GLOBAL": ["G_prom"]}), root=root, keys_dir=keys)
    assert rm.mode == "GLOBAL" and rm.default == "GLOBAL__x" and rm.routing == {} and not rm.evaluation_only
    assert rm.model_for("anything") == "GLOBAL__x" and rm.models["GLOBAL__x"].temperature == 1.5
    cfg = _cfg({"GLOBAL": ["G_cand"]})
    assert _raises(lambda: ML.load_runtime_model(cfg, root=root, keys_dir=keys), exc=ML.ModelLoadRefused, match="promoted")
    rm2 = ML.load_runtime_model(cfg, root=root, keys_dir=keys, evaluation=True)
    assert rm2.evaluation_only and rm2.models["GLOBAL__y"].state == "candidate"


def test_tampered_model_refused():
    root, keys, _ = _registry({"G": (_fields("GLOBAL__x", "global", ["GEN"]), "promoted")})
    p = root / "G" / "model.ubj"
    raw = bytearray(p.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    p.write_bytes(bytes(raw))
    assert _raises(lambda: ML.load_runtime_model(_cfg({"GLOBAL": ["G"]}), root=root, keys_dir=keys),
                   exc=ML.ModelLoadRefused, match="sha256")


def test_wrong_class_map_features_or_orientation_refused():
    bad = "0" * 64
    root, keys, _ = _registry({
        "CM": (_fields("GLOBAL__a", "global", ["GEN"], class_map_sha256=bad), "promoted"),
        "FE": (_fields("GLOBAL__b", "global", ["GEN"], features_file_sha256=bad), "promoted"),
        "OR": (_fields("GLOBAL__c", "global", ["GEN"], orientation_map_sha256=bad), "promoted"),
        "NO": (_fields("GLOBAL__d", "global", ["GEN"], orientation_map_sha256=None), "promoted"),
        "CN": (_fields("GLOBAL__e", "global", ["GEN"], class_names=["benign", "x", "y", "z"]), "promoted")})
    for eid, frag in (("CM", "class map"), ("FE", "features"), ("OR", "orientation_map"), ("NO", "orientation_map"),
                      ("CN", "class_names")):
        assert _raises(lambda: ML.load_runtime_model(_cfg({"GLOBAL": [eid]}), root=root, keys_dir=keys,
                                                     evaluation=True), exc=ML.ModelLoadRefused, match=frag), eid


def test_routed_routing_from_serves_groups_and_bad_sets_refused():
    root, keys, _ = _registry({"S1": (_fields("SPEC_A", "specialist", ["GA"]), "promoted"),
                               "S2": (_fields("SPEC_B", "specialist", ["GB"]), "candidate"),
                               "GL": (_fields("GLOBAL__x", "global", ["GEN"]), "promoted"),
                               "GL2": (_fields("GLOBAL__z", "global", ["GEN"]), "promoted")})
    cfg = _cfg({"ROUTED": ["S1", "S2", "GL"]})
    assert _raises(lambda: ML.load_runtime_model(cfg, mode="ROUTED", root=root, keys_dir=keys), exc=ML.ModelLoadRefused)
    rm = ML.load_runtime_model(cfg, mode="ROUTED", root=root, keys_dir=keys, evaluation=True)
    assert rm.routing == {"GA": "SPEC_A", "GB": "SPEC_B"} and rm.default == "GLOBAL__x"
    assert rm.model_for("GB") == "SPEC_B" and rm.model_for("other") == "GLOBAL__x"
    two = _cfg({"ROUTED": ["S1", "GL", "GL2"]})
    assert _raises(lambda: ML.load_runtime_model(two, mode="ROUTED", root=root, keys_dir=keys, evaluation=True),
                   exc=ML.ModelLoadRefused, match="exactly one")
    assert _raises(lambda: ML.load_runtime_model(_cfg({"GLOBAL": ["S1", "GL"]}), root=root, keys_dir=keys),
                   exc=ML.ModelLoadRefused, match="exactly one entry")


def test_missing_key_and_seed_outside_evaluation_refused():
    root, keys, _ = _registry({"G": (_fields("GLOBAL__x", "global", ["GEN"]), "promoted")})
    cfg = _cfg({"GLOBAL": ["G"]})
    assert _raises(lambda: ML.load_runtime_model(cfg, root=root, keys_dir=keys.parent / "nokeys"),
                   exc=ML.ModelLoadRefused, match="public key")
    assert not (keys.parent / "nokeys").exists()                       # the loader never creates keys
    assert _raises(lambda: ML.load_runtime_model(cfg, seed=2, root=root, keys_dir=keys), exc=ML.ModelLoadRefused,
                   match="evaluation")
    assert _raises(lambda: ML.load_runtime_model(cfg, seed=99, evaluation=True, root=root, keys_dir=keys),
                   exc=ML.ModelLoadRefused)


def test_real_registry_promoted_global_and_routed_evaluation():
    cfg = C.load_phase3_config()
    rm = ML.load_runtime_model(cfg)                                    # deployment path: promoted only
    m = rm.models[rm.default]
    assert rm.mode == "GLOBAL" and m.state == "promoted" and abs(m.temperature - 1.4231229528557798) < 1e-12
    assert m.model_sha256.startswith("a0b0afc91a469ef3")
    assert _raises(lambda: ML.load_runtime_model(cfg, mode="ROUTED"), exc=ML.ModelLoadRefused, match="promoted")
    rr = ML.load_runtime_model(cfg, mode="ROUTED", evaluation=True)
    assert set(rr.routing) == {"G1", "G2"} and rr.default == rm.default and rr.evaluation_only


def test_real_seed_load_from_step22():
    cfg = C.load_phase3_config()
    rm = ML.load_runtime_model(cfg, seed=3, evaluation=True)
    m = rm.models[rm.default]
    assert m.seed == 3 and m.source.startswith("step22:") and m.state.startswith("unregistered")
    rr = ML.load_runtime_model(cfg, mode="ROUTED", seed=3, evaluation=True)
    assert set(rr.routing) == {"G1", "G2"} and all(x.seed == 3 for x in rr.models.values())


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
