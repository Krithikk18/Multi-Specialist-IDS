"""common/context_config.py -- load and validate config/v2_phase5b.json (Phase 5B, offline) and its feature list.

    cfg = load_phase5b_config()                         # pinned bytes (V2_PHASE5B_CONFIG_SHA256, LF only) + validation
    cfg = load_phase5b_config(path, verify_pin=False)   # tests only
    names = context_feature_names(cfg)                  # the 44 names, generated from the config (fixed order)
    F = load_feature_list()                             # config/features_v2_2_context.json, pinned (70 + 44)
    F = build_feature_list(cfg)                         # what that file must contain (used to write / check it)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from config.config import CONFIG_DIR, REPO_ROOT
from common import schemas as S

CONFIG_PATH = CONFIG_DIR / "v2_phase5b.json"
FEATURE_LIST_PATH = CONFIG_DIR / "features_v2_2_context.json"
HOST_STATS = ("n_flows", "n_peers", "n_port_pairs", "sum_pkts", "sum_bytes", "share_short", "share_syn_no_ack")
PAIR_STATS = HOST_STATS + ("mean_duration",)
COLUMN_KEYS = ("src_ip", "dst_ip", "src_port", "dst_port", "flow_id", "start", "duration", "fwd_pkts", "bwd_pkts",
               "fwd_bytes", "bwd_bytes", "syn", "ack", "session", "split", "row", "label_id", "group")
ARMS = ("GLOBAL", "GLOBAL_CTX", "CTX_ONLY", "GLOBAL_NOFP", "GLOBAL_CTX_NOFP")


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

    def need(c, m):
        if not c:
            E.append(m)

    def sec(n):
        v = cfg.get(n)
        if not isinstance(v, dict):
            E.append(f"missing section {n}")
            return {}
        return v

    need(_int(cfg.get("version")), "version must be an int")
    for k in ("phase2_config", "phase5_config", "feature_list"):
        need(isinstance(cfg.get(k), str) and bool(cfg.get(k)), f"{k} must be a path string")
    for k in ("phase2_config", "phase5_config"):
        need((REPO_ROOT / cfg.get(k, "")).is_file(), f"{k} must be an existing repo file")
    for k in ("source_dataset", "dataset_version"):
        need(isinstance(cfg.get(k), str) and bool(cfg.get(k)), f"{k} must be set")
    need(cfg.get("source_dataset") != cfg.get("dataset_version"), "dataset_version must differ from source_dataset")
    de = sec("deployed")
    for k in ("entry", "model_id", "weights", "train_run"):
        need(isinstance(de.get(k), str) and bool(de.get(k)), f"deployed.{k} must be set")
    co = sec("columns")
    for k in COLUMN_KEYS:
        need(isinstance(co.get(k), str) and bool(co.get(k)), f"columns.{k} must be a column name")
    for k in ("start_unit_us", "duration_unit_us"):
        need(_int(co.get(k)) and co.get(k, 0) >= 1, f"columns.{k} must be an int >= 1 (integer microseconds)")
    cx = sec("context")
    w = cx.get("windows_s")
    need(isinstance(w, list) and bool(w) and all(_int(x) and x > 0 for x in w) and w == sorted(set(w)),
         "context.windows_s must be ascending distinct positive ints")
    for k in ("short_flow_max_pkts", "max_tracked_hosts", "max_tracked_pairs"):
        need(_int(cx.get(k)) and cx.get(k, 0) >= 1, f"context.{k} must be an int >= 1")
    need(cx.get("host_stats") == list(HOST_STATS), f"context.host_stats must be {list(HOST_STATS)}")
    need(cx.get("pair_stats") == list(PAIR_STATS), f"context.pair_stats must be {list(PAIR_STATS)}")
    need(cx.get("combine") == ["max", "min"], "context.combine must be ['max', 'min']")
    need(isinstance(cx.get("prefix"), str) and bool(cx.get("prefix")), "context.prefix must be set")
    need(isinstance(cx.get("warmup_column"), str) and bool(cx.get("warmup_column")), "context.warmup_column must be set")
    need(cx.get("segment_keys") == ["session", "split"], "context.segment_keys must be ['session', 'split'] (column keys)")
    rc = sec("reference_check")
    need(_int(rc.get("slice_rows")) and rc.get("slice_rows", 0) >= 10, "reference_check.slice_rows int >= 10")
    need(_int(rc.get("seed")), "reference_check.seed must be an int")
    st = sec("stage1")
    need(_seeds(st.get("seeds")), "stage1.seeds must be distinct ints >= 0")
    need(st.get("weights") == de.get("weights"), "stage1.weights must equal deployed.weights")
    need(_int(st.get("nthread")) and st.get("nthread", 0) >= 1, "stage1.nthread must be a fixed int >= 1")
    need(st.get("arms") == list(ARMS), f"stage1.arms must be {list(ARMS)}")
    need(st.get("reused_arms") == ["GLOBAL"], "stage1.reused_arms must be ['GLOBAL']")
    fp = st.get("fingerprint_features")
    need(isinstance(fp, list) and bool(fp) and all(isinstance(x, str) for x in fp), "stage1.fingerprint_features list")
    need(isinstance(st.get("fingerprint_source"), str) and (REPO_ROOT / st.get("fingerprint_source", "")).is_file(),
         "stage1.fingerprint_source must be an existing repo file")
    need(isinstance(st.get("h_c2_class"), str) and bool(st.get("h_c2_class")), "stage1.h_c2_class must name a class")
    ni = sec("noninferiority")
    need(_num(ni.get("macro_f1_margin")) and ni.get("macro_f1_margin", -1) >= 0, "noninferiority.macro_f1_margin >= 0")
    need(_num(ni.get("fa_count_margin")) and ni.get("fa_count_margin", -1) >= 0, "noninferiority.fa_count_margin >= 0")
    ev = sec("eval")
    need(_num(ev.get("ci_level")) and 0 < ev.get("ci_level", 0) < 1, "eval.ci_level in (0, 1)")
    for k in ("bootstrap_resamples", "min_val_flows", "contamination_window_s"):
        need(_int(ev.get(k)) and ev.get(k, 0) >= 1, f"eval.{k} int >= 1")
    need(_int(ev.get("bootstrap_seed")), "eval.bootstrap_seed int")
    need(_num(ev.get("benign_hours_idle_gap_s")) and ev.get("benign_hours_idle_gap_s", 0) > 0, "eval idle gap > 0")
    fl = sec("flip")
    for k in ("reversal_source", "reversal_hypothesis", "incidents_source"):
        need(isinstance(fl.get(k), str) and bool(fl.get(k)), f"flip.{k} must be set")
    zd = sec("zeroday")
    pr = zd.get("phase5a_runs")
    need(isinstance(pr, dict) and set(pr) == {"36", "37", "38"}, "zeroday.phase5a_runs must name steps 36, 37, 38")
    need(_int(zd.get("min_misses")) and zd.get("min_misses", 0) >= 1, "zeroday.min_misses int >= 1")
    need(_num(zd.get("recall_lo_min")) and 0 < zd.get("recall_lo_min", 0) <= 1, "zeroday.recall_lo_min in (0, 1]")
    need(_seeds(zd.get("seeds")), "zeroday.seeds")
    need(zd.get("primary_arm") == "CTX_TAIL_GLOBAL", "zeroday.primary_arm must be CTX_TAIL_GLOBAL (D165)")
    need(zd.get("report_only_arms") == ["CTX_IF_GLOBAL", "CTX_TAIL_PER_GROUP", "FLOWCTX_TAIL_GLOBAL"],
         "zeroday.report_only_arms must be ['CTX_IF_GLOBAL', 'CTX_TAIL_PER_GROUP', 'FLOWCTX_TAIL_GLOBAL']")
    tl = sec("tail")
    need(_num(tl.get("fit_share")) and 0 < tl.get("fit_share", 0) < 1, "tail.fit_share in (0, 1)")
    qg = tl.get("q_grid") or {}
    need(_num(qg.get("lo")) and _num(qg.get("hi")) and 0 < qg.get("lo", 0) < qg.get("hi", 0) < 1,
         "tail.q_grid lo < hi in (0, 1)")
    need(_int(qg.get("n")) and qg.get("n", 0) >= 200, "tail.q_grid.n int >= 200")
    need(_num(tl.get("target_flag_rate")) and 0 < tl.get("target_flag_rate", 0) < 1, "tail.target_flag_rate in (0, 1)")
    need(tl.get("quantile_method") == "higher", "tail.quantile_method must be 'higher' (order statistic)")
    need(_int(tl.get("min_group_benign")) and tl.get("min_group_benign", 0) >= 1, "tail.min_group_benign int >= 1")
    sh = sec("shap")
    need(sh.get("models") == ["GLOBAL", "GLOBAL_CTX"], "shap.models must be ['GLOBAL', 'GLOBAL_CTX']")
    for k in ("per_class_cap", "benign_cap", "k", "random_draws"):
        need(_int(sh.get(k)) and sh.get(k, 0) >= 1, f"shap.{k} int >= 1")
    for k in ("seed_model", "sample_seed", "random_seed"):
        need(_int(sh.get(k)), f"shap.{k} int")
    tb = sh.get("temperature_bounds")
    need(isinstance(tb, list) and len(tb) == 2 and all(_num(x) and x > 0 for x in tb) and tb[0] < tb[1],
         "shap.temperature_bounds [lo, hi]")
    pa = sec("paths")
    for k in ("cache_root", "datasets_root", "registry_root", "results"):
        need(isinstance(pa.get(k), str) and bool(pa.get(k)), f"paths.{k} must be set")
    need(_num(pa.get("min_free_gb")) and pa.get("min_free_gb", 0) > 0, "paths.min_free_gb > 0")
    return E


def load_phase5b_config(path: Path = CONFIG_PATH, verify_pin: bool = True) -> dict:
    path = Path(path)
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ConfigError(f"{path}: CR bytes (the pin is over LF bytes)")
    sha = hashlib.sha256(raw).hexdigest()
    if verify_pin and sha != S.V2_PHASE5B_CONFIG_SHA256:
        raise ConfigError(f"{path}: sha256 {sha} != pinned V2_PHASE5B_CONFIG_SHA256 {S.V2_PHASE5B_CONFIG_SHA256}")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: not valid JSON: {e}") from None
    errs = validate(cfg) if isinstance(cfg, dict) else ["top level must be an object"]
    if errs:
        raise ConfigError(f"{path}: " + "; ".join(errs))
    cfg["_sha256"], cfg["_path"], cfg["_pinned"] = sha, str(path), sha == S.V2_PHASE5B_CONFIG_SHA256
    return cfg


def context_feature_names(cfg: dict) -> list[str]:
    """<prefix>_<hostmax|hostmin|pair>_<stat>_<w>s, per window: host stats (max then min), then pair stats."""
    cx = cfg["context"]
    out = []
    for w in cx["windows_s"]:
        for comb in cx["combine"]:
            out += [f"{cx['prefix']}_host{comb}_{s}_{w}s" for s in cx["host_stats"]]
        out += [f"{cx['prefix']}_pair_{s}_{w}s" for s in cx["pair_stats"]]
    return out


def build_feature_list(cfg: dict) -> dict:
    flow = S.feature_columns()
    ctx = context_feature_names(cfg)
    feats = flow + ctx
    return {"version": 1, "dataset_version": cfg["dataset_version"], "n_features": len(feats), "n_flow": len(flow),
            "n_context": len(ctx), "features": feats, "context_features": ctx,
            "flow_features_file_sha256": S.FEATURES_V1_SHA256, "flow_features_list_sha256": S.FEATURES_V1_LIST_SHA256,
            "sha256": hashlib.sha256(json.dumps(feats, separators=(",", ":")).encode("utf-8")).hexdigest(),
            "note": "70 V1 flow features (config/features_v1.json order) then the 44 context features generated from "
                    "config/v2_phase5b.json by common/context_config.context_feature_names; ctx_warmup is metadata, "
                    "never a model feature"}


def load_feature_list(path: Path = FEATURE_LIST_PATH, expected_sha256: str | None = None) -> dict:
    path = Path(path)
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ConfigError(f"{path}: CR bytes")
    want = expected_sha256 if expected_sha256 is not None else S.FEATURES_V2_2_CONTEXT_SHA256
    got = hashlib.sha256(raw).hexdigest()
    if got != want:
        raise ConfigError(f"{path}: sha256 {got} != pinned {want}")
    F = json.loads(raw)
    lsha = hashlib.sha256(json.dumps(F["features"], separators=(",", ":")).encode("utf-8")).hexdigest()
    if lsha != F["sha256"] or len(F["features"]) != F["n_features"] or len(set(F["features"])) != len(F["features"]):
        raise ConfigError(f"{path}: list hash / count / uniqueness check failed")
    return F
