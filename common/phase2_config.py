"""common/phase2_config.py -- load and validate config/v2_phase2.json (Phase 2 tunables).

    cfg = load_phase2_config()          # dict + cfg["_sha256"] (file bytes) + cfg["_path"]
    p = expand(cfg["paths"]["cache_root"])

Validation collects every problem and raises one ConfigError listing them all. num_class is never configured:
it is len(config/class_map.json) at run time. The file must be LF-only (its sha256 is recorded per run).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from config.config import CONFIG_DIR, REPO_ROOT, RESULTS_DIR

CONFIG_PATH = CONFIG_DIR / "v2_phase2.json"
WEIGHT_MODES = ("none", "sqrt", "balanced")
STATES = ["candidate", "approved", "promoted"]
REQUIRED_PATHS = ("datasets_root", "cache_root", "registry_root", "keys_dir", "v1_models_dir")
REQUIRED_COLUMNS = ("group", "label_id", "session", "start_ts", "device_category")


class ConfigError(ValueError):
    pass


def expand(p: str) -> Path:
    return Path(p).expanduser()


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def validate(cfg: dict) -> list[str]:
    """All problems of a parsed config (empty list = valid)."""
    E: list[str] = []

    def need(cond: bool, msg: str) -> None:
        if not cond:
            E.append(msg)

    def get(*keys, default=None):
        d = cfg
        for k in keys:
            if not isinstance(d, dict) or k not in d:
                E.append(f"missing {'.'.join(keys)}")
                return default
            d = d[k]
        return d

    need(_is_int(get("version")), "version must be an int")
    dv = get("dataset_version", default="")
    need(isinstance(dv, str) and dv != "", "dataset_version must be a non-empty string")
    paths = get("paths", default={}) or {}
    for k in REQUIRED_PATHS:
        need(isinstance(paths.get(k), str) and paths.get(k), f"paths.{k} must be a non-empty string")
    cols = get("columns", default={}) or {}
    for k in REQUIRED_COLUMNS:
        need(isinstance(cols.get(k), str) and cols.get(k), f"columns.{k} must be a non-empty string")
    fb = get("fallback_group", default="")
    need(isinstance(fb, str) and fb != "", "fallback_group must be a non-empty string")
    seeds = get("seeds", default=[])
    need(isinstance(seeds, list) and len(seeds) > 0 and all(_is_int(s) and s >= 0 for s in seeds)
         and len(set(seeds)) == len(seeds), "seeds must be a non-empty list of unique ints >= 0")
    mv = get("min_val_flows")
    need(_is_int(mv) and mv >= 1, "min_val_flows must be an int >= 1")
    f = get("inner_split_frac")
    need(_is_num(f) and 0 < f <= 0.5, "inner_split_frac must be in (0, 0.5]")
    dr = get("dry_run", default={}) or {}
    need(_is_num(dr.get("frac")) and 0 < dr.get("frac", 0) < 1, "dry_run.frac must be in (0, 1)")
    need(_is_int(dr.get("seed")), "dry_run.seed must be an int")
    cw = get("class_weights", default={}) or {}
    need(cw.get("primary") in WEIGHT_MODES, f"class_weights.primary must be one of {WEIGHT_MODES}")
    am = cw.get("ablation_modes", [])
    need(isinstance(am, list) and all(m in WEIGHT_MODES for m in am) and cw.get("primary") not in am,
         "class_weights.ablation_modes must list weight modes other than the primary")
    x = get("xgb", default={}) or {}
    P = x.get("params", {}) if isinstance(x, dict) else {}
    need(P.get("objective") == "multi:softprob", "xgb.params.objective must be multi:softprob")
    need(P.get("tree_method") == "hist", "xgb.params.tree_method must be hist")
    need("num_class" not in P, "xgb.params.num_class must not be set (it is len(class_map))")
    need(_is_num(P.get("eta")) and P.get("eta", 0) > 0, "xgb.params.eta must be > 0")
    need(_is_int(P.get("max_depth")) and P.get("max_depth", 0) >= 1, "xgb.params.max_depth must be an int >= 1")
    need(_is_int(x.get("num_boost_round")) and x.get("num_boost_round", 0) >= 1, "xgb.num_boost_round must be an int >= 1")
    need(_is_int(x.get("early_stopping_rounds")) and x.get("early_stopping_rounds", 0) >= 1,
         "xgb.early_stopping_rounds must be an int >= 1")
    ab = get("ablations", default={}) or {}
    for k in ("A1_class_weights", "A2_gen_specialist", "A3_device_category"):
        need(isinstance(ab.get(k), bool), f"ablations.{k} must be a bool")
    need(_is_int(ab.get("a3_min_benign_train")) and ab.get("a3_min_benign_train", -1) >= 0,
         "ablations.a3_min_benign_train must be an int >= 0")
    ev = get("eval", default={}) or {}
    need(_is_num(ev.get("ci_level")) and 0 < ev.get("ci_level", 0) < 1, "eval.ci_level must be in (0, 1)")
    need(_is_num(ev.get("benign_hours_idle_gap_s")) and ev.get("benign_hours_idle_gap_s", 0) > 0,
         "eval.benign_hours_idle_gap_s must be > 0")
    for k in ("fp_threshold_max_fp", "latency_batch1_repeats", "latency_batch", "latency_batch_repeats"):
        need(_is_int(ev.get(k)) and ev.get(k, -1) >= (0 if k == "fp_threshold_max_fp" else 1), f"eval.{k} must be an int")
    need(isinstance(ev.get("v1_binary_compare"), bool), "eval.v1_binary_compare must be a bool")
    ca = get("calibration", default={}) or {}
    need(_is_int(ca.get("cross_fit_folds")) and ca.get("cross_fit_folds", 0) >= 2, "calibration.cross_fit_folds must be >= 2")
    need(_is_int(ca.get("ece_bins")) and ca.get("ece_bins", 0) >= 2, "calibration.ece_bins must be >= 2")
    tb = ca.get("temperature_bounds", [])
    need(isinstance(tb, list) and len(tb) == 2 and all(_is_num(v) for v in tb) and 0 < tb[0] < 1 < tb[1],
         "calibration.temperature_bounds must be [lo, hi] with 0 < lo < 1 < hi")
    sh = get("shap", default={}) or {}
    for k in ("shap_per_class", "top_k_heatmap", "beeswarm_top"):
        need(_is_int(sh.get(k)) and sh.get(k, 0) >= 1, f"shap.{k} must be an int >= 1")
    need(_is_num(sh.get("dominance_threshold")) and 0 < sh.get("dominance_threshold", 0) <= 1,
         "shap.dominance_threshold must be in (0, 1]")
    rg = get("registry", default={}) or {}
    need(rg.get("states") == STATES, f"registry.states must be exactly {STATES}")
    need(_is_int(rg.get("register_seed")) and isinstance(seeds, list) and rg.get("register_seed") in seeds,
         "registry.register_seed must be one of the seeds")
    # optional keys (Phase 2 closeout, docs/V2_DECISIONS.md D39+): absent in config/v2_phase2.json -> no effect
    if "results_subdir" in cfg:
        rs = cfg["results_subdir"]
        need(isinstance(rs, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", rs) is not None and rs not in (".", ".."),
             "results_subdir must be a plain folder name")
    if "prereg_amendments" in cfg:
        am = cfg["prereg_amendments"]
        need(isinstance(am, list) and all(isinstance(a, str) and (REPO_ROOT / a).is_file() for a in am),
             "prereg_amendments must list existing repo-relative files")
    if "orientation" in cfg:
        o = cfg["orientation"]
        need(isinstance(o, dict) and isinstance(o.get("map"), str) and (REPO_ROOT / o.get("map", "")).is_file()
             and isinstance(o.get("rule"), str), "orientation must be {map: existing repo-relative file, rule: str}")
    if "primary_selection" in cfg:
        p = cfg["primary_selection"]
        ok = isinstance(p, dict)
        need(ok and isinstance(p.get("rule"), str), "primary_selection.rule must be a string")
        need(ok and _is_num(p.get("tolerance")) and p.get("tolerance", -1) >= 0, "primary_selection.tolerance must be >= 0")
        to = p.get("tie_order") if ok else None
        need(isinstance(to, list) and len(to) > 0 and all(m in WEIGHT_MODES for m in to),
             f"primary_selection.tie_order must list weight modes from {WEIGHT_MODES}")
        need(isinstance(cw.get("ablation_modes"), list) and len(cw.get("ablation_modes", [])) > 0,
             "primary_selection needs class_weights.ablation_modes")
    return E


def load_phase2_config(path: Path = CONFIG_PATH) -> dict:
    path = Path(path)
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ConfigError(f"{path}: CR bytes (CRLF); the recorded sha256 is over LF bytes")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: not valid JSON: {e}") from None
    if not isinstance(cfg, dict):
        raise ConfigError(f"{path}: top level must be an object")
    errs = validate(cfg)
    if errs:
        raise ConfigError(f"{path}: " + "; ".join(errs))
    cfg["_sha256"] = hashlib.sha256(raw).hexdigest()
    cfg["_path"] = str(path)
    if "results_subdir" in cfg:                                        # results/<subdir>/<step>/ (D40)
        cfg["_results_root"] = str(RESULTS_DIR / cfg["results_subdir"])
    return cfg


def config_from_arg(path: str | None) -> dict:
    """`--config` option of the Phase 2 scripts: None -> config/v2_phase2.json (unchanged default)."""
    return load_phase2_config(Path(path)) if path else load_phase2_config()
