"""common/zeroday_config.py -- load and validate config/v2_phase5.json (Phase 5A zero-day test, offline).

    cfg = load_phase5_config()                         # pinned bytes (V2_PHASE5_CONFIG_SHA256, LF only) + validation
    cfg = load_phase5_config(path, verify_pin=False)   # tests only; marked cfg["_pinned"] = False

Every Phase 5A parameter lives in this one pinned file (docs/V2_PREREG_PHASE5.md fixes the rules that use them).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from config.config import CONFIG_DIR, REPO_ROOT
from common import schemas as S

CONFIG_PATH = CONFIG_DIR / "v2_phase5.json"
ARMS = ("GLOBAL_NORMAL", "PER_GROUP_NORMAL", "RANDOM_GROUP_NORMAL")
VERDICT_ARMS = ("GLOBAL_NORMAL", "PER_GROUP_NORMAL")
VERDICTS = ("PER_GROUP_WINS", "DOES_NOT_WIN")


class ConfigError(ValueError):
    pass


def expand(p: str) -> Path:
    return Path(p).expanduser()


def _num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _seeds(x) -> bool:
    return isinstance(x, list) and bool(x) and all(_int(s) and s >= 0 for s in x) and len(set(x)) == len(x)


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
    need(isinstance(cfg.get("phase2_config"), str) and (REPO_ROOT / cfg.get("phase2_config", "")).is_file(),
         "phase2_config must be an existing repo file")
    de = sec("deployed")
    for k in ("entry", "model_id", "weights", "train_run"):
        need(isinstance(de.get(k), str) and de.get(k), f"deployed.{k} must be a non-empty string")
    pf = sec("pinned_facts")
    need(pf.get("amendment2_s4_phase4") in VERDICTS, f"pinned_facts.amendment2_s4_phase4 must be one of {VERDICTS}")
    lo = sec("loao")
    need(_seeds(lo.get("seeds")), "loao.seeds must be a non-empty list of distinct ints >= 0")
    need(lo.get("weights") in ("none", "sqrt", "balanced"), "loao.weights must be none / sqrt / balanced")
    need(lo.get("weights") == de.get("weights"), "loao.weights must equal deployed.weights (the promoted configuration)")
    need(_int(lo.get("nthread")) and lo.get("nthread", 0) >= 1, "loao.nthread must be a fixed int >= 1")
    need(_int(lo.get("rare_min_val_flows")) and lo.get("rare_min_val_flows", 0) >= 1, "loao.rare_min_val_flows int >= 1")
    need(isinstance(lo.get("rare_classes_report_only"), bool), "loao.rare_classes_report_only must be a bool")
    need(_int(lo.get("control_full_refit_seed")) and lo.get("control_full_refit_seed", -1) >= 0,
         "loao.control_full_refit_seed must be an int >= 0")
    nm = sec("normal_model")
    need(nm.get("arms") == list(ARMS), f"normal_model.arms must be {list(ARMS)}")
    need(nm.get("verdict_arms") == list(VERDICT_ARMS), f"normal_model.verdict_arms must be {list(VERDICT_ARMS)}")
    need(_seeds(nm.get("seeds")), "normal_model.seeds must be a non-empty list of distinct ints >= 0")
    need(nm.get("transform") == "signed_log1p", "normal_model.transform must be signed_log1p")
    for k in ("n_estimators", "max_samples_cap", "n_jobs", "min_group_benign", "score_chunk_rows"):
        need(_int(nm.get(k)) and nm.get(k, 0) >= 1, f"normal_model.{k} must be an int >= 1")
    need(_num(nm.get("max_features")) and 0 < nm.get("max_features", 0) <= 1, "normal_model.max_features in (0, 1]")
    need(isinstance(nm.get("bootstrap"), bool), "normal_model.bootstrap must be a bool")
    need(_num(nm.get("threshold_quantile")) and 0 < nm.get("threshold_quantile", 0) < 1,
         "normal_model.threshold_quantile in (0, 1)")
    need(nm.get("quantile_method") == "linear", "normal_model.quantile_method must be linear")
    need(_int(nm.get("random_group_perm_seed_base")), "normal_model.random_group_perm_seed_base must be an int")
    tc = sec("threshold_check")
    need(_num(tc.get("fit_frac")) and 0 < tc.get("fit_frac", 0) < 1, "threshold_check.fit_frac in (0, 1)")
    need(_int(tc.get("split_seed_base")), "threshold_check.split_seed_base must be an int")
    ev = sec("eval")
    for k in ("min_misses", "bootstrap_resamples", "min_support_classes", "single_flow_timing_calls", "score_hist_bins"):
        need(_int(ev.get(k)) and ev.get(k, 0) >= 1, f"eval.{k} must be an int >= 1")
    need(_int(ev.get("bootstrap_seed")), "eval.bootstrap_seed must be an int")
    need(_num(ev.get("ci_level")) and 0 < ev.get("ci_level", 0) < 1, "eval.ci_level in (0, 1)")
    need(_num(ev.get("fa_margin_per_h")) and ev.get("fa_margin_per_h", -1) >= 0, "eval.fa_margin_per_h >= 0")
    need(_num(ev.get("benign_hours_idle_gap_s")) and ev.get("benign_hours_idle_gap_s", 0) > 0, "eval idle gap > 0")
    pa = sec("paths")
    for k in ("cache_root", "registry_root", "results"):
        need(isinstance(pa.get(k), str) and pa.get(k), f"paths.{k} must be a non-empty string")
    return E


def load_phase5_config(path: Path = CONFIG_PATH, verify_pin: bool = True) -> dict:
    path = Path(path)
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ConfigError(f"{path}: CR bytes (the pin is over LF bytes)")
    sha = hashlib.sha256(raw).hexdigest()
    if verify_pin and sha != S.V2_PHASE5_CONFIG_SHA256:
        raise ConfigError(f"{path}: sha256 {sha} != pinned V2_PHASE5_CONFIG_SHA256 {S.V2_PHASE5_CONFIG_SHA256}")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: not valid JSON: {e}") from None
    errs = validate(cfg) if isinstance(cfg, dict) else ["top level must be an object"]
    if errs:
        raise ConfigError(f"{path}: " + "; ".join(errs))
    cfg["_sha256"], cfg["_path"], cfg["_pinned"] = sha, str(path), sha == S.V2_PHASE5_CONFIG_SHA256
    return cfg
