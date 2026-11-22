"""common/cl_config.py -- load and validate config/v2_phase4.json (Phase 4 continual-learning loop, offline).

    cfg = load_phase4_config()                 # pinned bytes (V2_PHASE4_CONFIG_SHA256, LF only) + validation
    cfg = load_phase4_config(path, verify_pin=False)   # tests only; marked cfg["_pinned"] = False

Every Phase 4 parameter lives in this one pinned file (docs/V2_PREREG_PHASE4.md fixes the rules that use them).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from config.config import CONFIG_DIR, REPO_ROOT
from common import schemas as S

CONFIG_PATH = CONFIG_DIR / "v2_phase4.json"


class ConfigError(ValueError):
    pass


def expand(p: str) -> Path:
    return Path(p).expanduser()


def _num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _frac(x, lo_open: bool = True) -> bool:
    return _num(x) and (0 < x if lo_open else 0 <= x) and x <= 1


def validate(cfg: dict) -> list[str]:
    E: list[str] = []

    def need(cond, msg):
        if not cond:
            E.append(msg)

    def sec(name):
        v = cfg.get(name)
        if not isinstance(v, dict):
            E.append(f"missing section {name}")
            return {}
        return v

    need(_int(cfg.get("version")), "version must be an int")
    for k in ("phase2_config", "phase3_config"):
        need(isinstance(cfg.get(k), str) and (REPO_ROOT / cfg.get(k, "")).is_file(), f"{k} must be an existing repo file")
    de = sec("deployed")
    for k in ("entry", "model_id", "weights", "train_run", "calib_run"):
        need(isinstance(de.get(k), str) and de.get(k), f"deployed.{k} must be a non-empty string")
    sp = sec("split")
    need(sp.get("parts") == ["val_A", "val_B"], "split.parts must be ['val_A', 'val_B']")
    need(isinstance(sp.get("time_column"), str) and sp.get("time_column"), "split.time_column must be set")
    qu = sec("queue")
    need(_frac(qu.get("random_review_rate"), lo_open=False), "queue.random_review_rate must be in [0, 1]")
    need(_int(qu.get("seed")), "queue.seed must be an int")
    op = sec("operator")
    need(isinstance(op.get("operator_id"), str) and op.get("operator_id"), "operator.operator_id must be set")
    need(_int(op.get("seed")), "operator.seed must be an int")

    def labeller(d, where):
        need(isinstance(d, dict) and _num(d.get("noise")) and 0 <= d.get("noise", -1) < 1, f"{where}.noise in [0, 1)")
        b = (d or {}).get("budget")
        need(b is None or (_int(b) and b >= 1), f"{where}.budget must be null or an int >= 1")

    labeller(op.get("primary"), "operator.primary")
    sw = op.get("sweeps")
    need(isinstance(sw, list), "operator.sweeps must be a list")
    names = []
    for i, s in enumerate(sw if isinstance(sw, list) else []):
        labeller(s, f"operator.sweeps[{i}]")
        names.append((s or {}).get("name"))
        need(isinstance((s or {}).get("name"), str) and s.get("name"), f"operator.sweeps[{i}].name must be set")
    need(len(names) == len(set(names)), "operator.sweeps names must be unique")
    va = sec("validator")
    need(_frac(va.get("confident_pmax")), "validator.confident_pmax must be in (0, 1]")
    need(_frac(va.get("max_confident_disagreement"), lo_open=False), "validator.max_confident_disagreement in [0, 1]")
    rp = sec("replay")
    need(_frac(rp.get("frac")), "replay.frac must be in (0, 1]")
    need(_int(rp.get("min_class_rows")) and rp.get("min_class_rows", -1) >= 0, "replay.min_class_rows int >= 0")
    need(_int(rp.get("seed")), "replay.seed must be an int")
    rt = sec("retrain")
    need(isinstance(rt.get("seeds"), list) and rt.get("seeds") and all(_int(s) and s >= 0 for s in rt.get("seeds", [])),
         "retrain.seeds must be a non-empty list of ints >= 0")
    need(rt.get("weights") in ("none", "sqrt", "balanced"), "retrain.weights must be none / sqrt / balanced")
    need(_int(rt.get("warm_start_rounds")) and rt.get("warm_start_rounds", 0) >= 1, "retrain.warm_start_rounds int >= 1")
    need(_int(rt.get("nthread")) and rt.get("nthread", 0) >= 1, "retrain.nthread must be a fixed int >= 1")
    tb = rt.get("temperature_bounds")
    need(isinstance(tb, list) and len(tb) == 2 and all(_num(x) and x > 0 for x in tb) and tb[0] < tb[1],
         "retrain.temperature_bounds must be [lo, hi], 0 < lo < hi")
    s2 = sec("s2")
    need(isinstance(s2.get("label_group"), str) and s2.get("label_group"), "s2.label_group must be set")
    ga = sec("gate")
    need(_int(ga.get("min_val_flows")) and ga.get("min_val_flows", 0) >= 1, "gate.min_val_flows int >= 1")
    for k in ("max_recall_drop", "max_macro_f1_drop", "max_fa_per_h_rise"):
        need(_num(ga.get(k)) and ga.get(k, -1) >= 0, f"gate.{k} must be >= 0")
    ve = sec("verdict")
    for k in ("forgetting_equal_tol", "time_ratio", "affected_group_tol"):
        need(_num(ve.get(k)) and ve.get(k, -1) >= 0, f"verdict.{k} must be >= 0")
    po = sec("poisoning")
    need(_frac(po.get("p1_flip_frac")) and _frac(po.get("p2_flip_frac")), "poisoning flip fractions in (0, 1]")
    need(_int(po.get("seed")), "poisoning.seed must be an int")
    ev = sec("eval")
    need(_num(ev.get("ci_level")) and 0 < ev.get("ci_level", 0) < 1, "eval.ci_level in (0, 1)")
    need(_num(ev.get("benign_hours_idle_gap_s")) and ev.get("benign_hours_idle_gap_s", 0) > 0, "eval idle gap > 0")
    pa = sec("paths")
    for k in ("cache_root", "operator_keys_dir", "registry_root", "registry_keys_dir", "results"):
        need(isinstance(pa.get(k), str) and pa.get(k), f"paths.{k} must be a non-empty string")
    return E


def load_phase4_config(path: Path = CONFIG_PATH, verify_pin: bool = True) -> dict:
    path = Path(path)
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ConfigError(f"{path}: CR bytes (the pin is over LF bytes)")
    sha = hashlib.sha256(raw).hexdigest()
    if verify_pin and sha != S.V2_PHASE4_CONFIG_SHA256:
        raise ConfigError(f"{path}: sha256 {sha} != pinned V2_PHASE4_CONFIG_SHA256 {S.V2_PHASE4_CONFIG_SHA256}")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: not valid JSON: {e}") from None
    errs = validate(cfg) if isinstance(cfg, dict) else ["top level must be an object"]
    if errs:
        raise ConfigError(f"{path}: " + "; ".join(errs))
    cfg["_sha256"], cfg["_path"], cfg["_pinned"] = sha, str(path), sha == S.V2_PHASE4_CONFIG_SHA256
    return cfg
