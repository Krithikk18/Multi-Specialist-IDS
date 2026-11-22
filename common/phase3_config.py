"""common/phase3_config.py -- load and validate config/v2_phase3.json (Phase 3 streaming runtime).

    cfg = load_phase3_config()                       # pinned bytes (DFD P5) + validation; refuses split == test
    run_cfg = with_overrides(cfg, mode="ROUTED", speed="10x", batch_max_flows=16)
    speed_factor("10x") -> 10.0 ; speed_factor("max") -> None

Integrity (DFD P5): the default config file must match common/schemas.V2_PHASE3_CONFIG_SHA256 byte for byte (LF
only); config/v2_phase3_1.json (Phase 3.1) must match V2_PHASE3_1_CONFIG_SHA256; any other file is checked against the
Phase 3 pin, so it is accepted only with verify_pin=False (tests) and is then marked "_pinned": False.
Phase 3.1 optional keys (validated only when present; absent = Phase 3 behaviour): predictions_chunk_rows /
predictions_chunk_seconds (chunked prediction writing), routing.ip_mac_source ({source kind: static | learned |
learned_then_static}), routing.mac_learner (gateway / flap parameters), packets.open_sequentially (bool).
Phase 3.2 optional keys (config/v2_phase3_2.json, pinned as V2_PHASE3_2_CONFIG_SHA256): routing.mac_learner.
gateway_warmup_s (>= 0 s of event time) and routing.mac_learner.inventory_gateway_roles (non-empty list of role
names): the unexpected_gateway health event (common/mac_learner.py); predictions, alerts and incidents unchanged.
Only operational fields may be overridden for one run (mode, source.speed, batch.max_flows, source.slice_minutes,
rate_guard.enabled, the evaluation seed); every override is listed in cfg["_overrides"] for the run manifest.
Policy, routing, rate-guard rule and paths can only change by editing (and re-pinning) the file.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

from config.config import CONFIG_DIR, REPO_ROOT
from common import schemas as S

CONFIG_PATH = CONFIG_DIR / "v2_phase3.json"
CONFIG_PATH_3_1 = CONFIG_DIR / "v2_phase3_1.json"
CONFIG_PATH_3_2 = CONFIG_DIR / "v2_phase3_2.json"
IP_MAC_SOURCES = ("static", "learned", "learned_then_static")
LEARNER_KEYS = ("gateway_distinct_ip_threshold", "gateway_window_s", "flap_count", "flap_window_s")
MODES = ("GLOBAL", "ROUTED")
SOURCE_KINDS = ("csv_replay", "cicfm_pcap")
ALLOWED_SPLITS = ("train", "val")
OVERFLOW = ("block", "drop")
SEVERITY_LEVELS = ["High", "Medium", "Low"]
STATES = ("candidate", "approved", "promoted")
OVERRIDABLE = ("mode", "speed", "batch_max_flows", "slice_minutes", "rate_guard_enabled", "seed")


class ConfigError(ValueError):
    pass


class TestSplitRefused(RuntimeError):
    """Phase 3 never reads the test split (docs/V2_PREREG_PHASE3.md)."""


def expand(p: str) -> Path:
    return Path(p).expanduser()


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def speed_factor(speed: str) -> float | None:
    """'max' -> None (no pacing); '<f>x' -> f (event seconds per wall second)."""
    if speed == "max":
        return None
    m = re.fullmatch(r"(\d+(?:\.\d+)?)x", str(speed))
    if not m or float(m.group(1)) <= 0:
        raise ConfigError(f"speed must be 'max' or '<factor>x' with factor > 0, got {speed!r}")
    return float(m.group(1))


def refuse_test(split: str, where: str = "") -> None:
    if split not in ALLOWED_SPLITS:
        raise TestSplitRefused(f"Phase 3 reads train / val only; refused split={split!r} {where}".strip())


def validate(cfg: dict) -> list[str]:
    E: list[str] = []

    def need(cond, msg):
        if not cond:
            E.append(msg)

    def sec(name) -> dict:
        v = cfg.get(name)
        if not isinstance(v, dict):
            E.append(f"missing section {name}")
            return {}
        return v

    need(_is_int(cfg.get("version")), "version must be an int")
    need(isinstance(cfg.get("phase2_config"), str) and (REPO_ROOT / cfg.get("phase2_config", "")).is_file(),
         "phase2_config must be an existing repo-relative file")
    need(cfg.get("mode") in MODES, f"mode must be one of {MODES}")
    mo = sec("models")
    for m in MODES:
        ents = (mo.get(m) or {}).get("entries")
        need(isinstance(ents, list) and ents and all(isinstance(e, str) and e for e in ents),
             f"models.{m}.entries must be a non-empty list of entry ids")
    need(isinstance(mo.get("registry_root"), str) and isinstance(mo.get("registry_keys_dir"), str),
         "models.registry_root / registry_keys_dir must be strings")
    ev = mo.get("evaluation") or {}
    need(isinstance(ev.get("allow_states"), list) and set(ev.get("allow_states", [])) <= set(STATES),
         f"models.evaluation.allow_states must be a subset of {STATES}")
    need(isinstance(ev.get("seeds"), list) and all(_is_int(s) and s >= 0 for s in ev.get("seeds", [])),
         "models.evaluation.seeds must be a list of ints >= 0")
    for k in ("train_run", "calib_run", "weights"):
        need(isinstance(ev.get(k), str) and ev.get(k), f"models.evaluation.{k} must be a non-empty string")
    so = sec("source")
    need(so.get("kind") in SOURCE_KINDS, f"source.kind must be one of {SOURCE_KINDS}")
    need(so.get("split") in ALLOWED_SPLITS, f"source.split must be one of {ALLOWED_SPLITS} (never test)")
    for k in ("replay_phase2_config",):
        need(isinstance(so.get(k), str) and (REPO_ROOT / so.get(k, "")).is_file(), f"source.{k} must be an existing file")
    for k in ("replay_dataset_version", "reference_dataset_version"):
        need(isinstance(so.get(k), str) and so.get(k), f"source.{k} must be a non-empty string")
    try:
        speed_factor(so.get("speed", ""))
    except ConfigError as e:
        E.append(f"source.{e}")
    need(_is_num(so.get("slice_minutes")) and so.get("slice_minutes", 0) > 0, "source.slice_minutes must be > 0")
    need(_is_num(so.get("tick_s")) and so.get("tick_s", 0) > 0, "source.tick_s must be > 0")
    ps = sec("pcap_source")
    need(ps.get("split") in ALLOWED_SPLITS, f"pcap_source.split must be one of {ALLOWED_SPLITS} (never test)")
    need(_is_num(ps.get("flow_timeout_s")) and ps.get("flow_timeout_s", 0) > 0, "pcap_source.flow_timeout_s must be > 0")
    tol = ps.get("match_tolerance") or {}
    need(_is_num(tol.get("abs")) and _is_num(tol.get("rel")), "pcap_source.match_tolerance needs abs / rel numbers")
    ba = sec("batch")
    need(_is_int(ba.get("max_flows")) and ba.get("max_flows", 0) >= 1, "batch.max_flows must be an int >= 1")
    need(_is_num(ba.get("max_event_s")) and ba.get("max_event_s", 0) > 0, "batch.max_event_s must be > 0")
    qu = sec("queue")
    need(_is_int(qu.get("max_items")) and qu.get("max_items", 0) >= 1, "queue.max_items must be an int >= 1")
    for k in ("overflow_max_speed", "overflow_paced"):
        need(qu.get(k) in OVERFLOW, f"queue.{k} must be one of {OVERFLOW}")
    fe = sec("features")
    need(fe.get("dtype") == "float32", "features.dtype must be float32 (training dtype)")
    need(_is_num(fe.get("nan_inf_to")), "features.nan_inf_to must be a number")
    ex = sec("explain")
    need(_is_int(ex.get("top_k")) and ex.get("top_k", 0) >= 1, "explain.top_k must be an int >= 1")
    po = sec("policy")
    need(_is_num(po.get("confidence_threshold")) and 0 < po.get("confidence_threshold", 0) <= 1,
         "policy.confidence_threshold must be in (0, 1]")
    for k in ("aggregation_window_s", "cooldown_s"):
        need(_is_num(po.get(k)) and po.get(k, -1) >= 0, f"policy.{k} must be >= 0")
    need(po.get("severity_levels") == SEVERITY_LEVELS, f"policy.severity_levels must be exactly {SEVERITY_LEVELS}")
    need(po.get("severity_default") in SEVERITY_LEVELS, "policy.severity_default must be High / Medium / Low")
    sv = po.get("severity")
    need(isinstance(sv, dict) and all(v in SEVERITY_LEVELS for v in sv.values()),
         "policy.severity values must be High / Medium / Low")
    need(isinstance(po.get("rate_guard_class"), str) and po.get("rate_guard_class"), "policy.rate_guard_class must be set")
    ep = sec("episodes")
    need(_is_num(ep.get("gap_s")) and ep.get("gap_s", 0) > 0, "episodes.gap_s must be > 0")
    need(_is_num(ep.get("detect_slack_s")) and ep.get("detect_slack_s", -1) >= 0, "episodes.detect_slack_s must be >= 0")
    ro = sec("routing")
    for k in ("inventory", "groups", "ip_mac_map"):
        need(isinstance(ro.get(k), str) and (REPO_ROOT / ro.get(k, "")).is_file(), f"routing.{k} must be an existing file")
    for k in ("mac_column", "name_column", "role_column", "group_column", "fallback_group", "unknown_device"):
        need(isinstance(ro.get(k), str) and ro.get(k), f"routing.{k} must be a non-empty string")
    need(isinstance(ro.get("owner_roles"), list) and ro.get("owner_roles"), "routing.owner_roles must be a non-empty list")
    need(_is_num(ro.get("ip_map_tolerance_s")) and ro.get("ip_map_tolerance_s", -1) >= 0, "routing.ip_map_tolerance_s >= 0")
    rg = sec("rate_guard")
    need(isinstance(rg.get("enabled"), bool), "rate_guard.enabled must be a bool")
    need(_is_num(rg.get("window_s")) and rg.get("window_s", 0) > 0, "rate_guard.window_s must be > 0")
    need(_is_int(rg.get("consecutive")) and rg.get("consecutive", 0) >= 1, "rate_guard.consecutive must be an int >= 1")
    need(_is_num(rg.get("multiplier")) and rg.get("multiplier", 0) > 0, "rate_guard.multiplier must be > 0")
    fam = rg.get("families")
    need(isinstance(fam, dict) and fam and all(isinstance(v, list) and all(_is_int(p) for p in v) for v in fam.values()),
         "rate_guard.families must map names to lists of IP protocol numbers")
    if isinstance(fam, dict):
        allp = [p for v in fam.values() if isinstance(v, list) for p in v]
        need(len(allp) == len(set(allp)), "rate_guard.families: a protocol is in two families")
    need(isinstance(rg.get("other_family"), str) and rg.get("other_family") not in (fam or {}),
         "rate_guard.other_family must be a name not in families")
    need(_is_int(rg.get("min_train_windows")) and rg.get("min_train_windows", 0) >= 1, "rate_guard.min_train_windows >= 1")
    need(isinstance(rg.get("v1_config"), str) and (REPO_ROOT / rg.get("v1_config", "")).is_file(),
         "rate_guard.v1_config must be an existing file")
    need(isinstance(rg.get("fit_dir"), str), "rate_guard.fit_dir must be a string")
    pk = sec("packets")
    for k in ("split_definition", "attack_set", "attack_pcap_root", "benign_session", "benign_pcap"):
        need(isinstance(pk.get(k), str) and pk.get(k), f"packets.{k} must be a non-empty string")
    pa = sec("paths")
    for k in ("runtime_root", "runtime_keys_dir", "results", "outbox"):
        need(isinstance(pa.get(k), str) and pa.get(k), f"paths.{k} must be a non-empty string")
    sw = sec("sweeps")
    need(isinstance(sw.get("confidence_threshold"), list) and all(_is_num(x) and 0 < x <= 1 for x in sw.get("confidence_threshold", [])),
         "sweeps.confidence_threshold must be a list in (0, 1]")
    need(isinstance(sw.get("aggregation_window_s"), list) and all(_is_num(x) and x > 0 for x in sw.get("aggregation_window_s", [])),
         "sweeps.aggregation_window_s must be a list of numbers > 0")
    bm = sec("benchmark")
    need(isinstance(bm.get("batch_sizes"), list) and all(_is_int(x) and x >= 1 for x in bm.get("batch_sizes", [])),
         "benchmark.batch_sizes must be ints >= 1")
    need(isinstance(bm.get("speeds"), list), "benchmark.speeds must be a list")
    for s in bm.get("speeds", []) if isinstance(bm.get("speeds"), list) else []:
        try:
            speed_factor(s)
        except ConfigError as e:
            E.append(f"benchmark.speeds: {e}")
    ev2 = sec("eval")
    need(_is_num(ev2.get("ci_level")) and 0 < ev2.get("ci_level", 0) < 1, "eval.ci_level must be in (0, 1)")
    need(_is_int(ev2.get("bootstrap")) and ev2.get("bootstrap", 0) >= 100, "eval.bootstrap must be an int >= 100")
    need(_is_int(ev2.get("bootstrap_seed")), "eval.bootstrap_seed must be an int")
    need(_is_num(ev2.get("benign_hours_idle_gap_s")) and ev2.get("benign_hours_idle_gap_s", 0) > 0,
         "eval.benign_hours_idle_gap_s must be > 0")
    # ---- Phase 3.1 optional keys
    if "predictions_chunk_rows" in cfg or "predictions_chunk_seconds" in cfg:
        need(_is_int(cfg.get("predictions_chunk_rows")) and cfg.get("predictions_chunk_rows", 0) >= 1,
             "predictions_chunk_rows must be an int >= 1 (set together with predictions_chunk_seconds)")
        need(_is_num(cfg.get("predictions_chunk_seconds")) and cfg.get("predictions_chunk_seconds", 0) > 0,
             "predictions_chunk_seconds must be > 0 (set together with predictions_chunk_rows)")
    if "ip_mac_source" in ro:
        im = ro.get("ip_mac_source")
        need(isinstance(im, dict) and im and set(im) <= set(SOURCE_KINDS) and all(v in IP_MAC_SOURCES for v in im.values()),
             f"routing.ip_mac_source must map source kinds {SOURCE_KINDS} to one of {IP_MAC_SOURCES}")
    if "mac_learner" in ro:
        ml = ro.get("mac_learner") or {}
        need(isinstance(ml, dict) and all(_is_num(ml.get(k)) and ml.get(k, 0) > 0 for k in LEARNER_KEYS)
             and _is_int(ml.get("gateway_distinct_ip_threshold")) and _is_int(ml.get("flap_count")),
             f"routing.mac_learner needs {LEARNER_KEYS} > 0 (threshold and flap_count ints)")
    if "open_sequentially" in pk:
        need(isinstance(pk.get("open_sequentially"), bool), "packets.open_sequentially must be a bool")
    ml2 = ro.get("mac_learner") if isinstance(ro.get("mac_learner"), dict) else {}
    if "gateway_warmup_s" in ml2:                                    # Phase 3.2
        need(_is_num(ml2.get("gateway_warmup_s")) and ml2.get("gateway_warmup_s", -1) >= 0,
             "routing.mac_learner.gateway_warmup_s must be a number >= 0")
    if "inventory_gateway_roles" in ml2:
        gr = ml2.get("inventory_gateway_roles")
        need(isinstance(gr, list) and bool(gr) and all(isinstance(x, str) and x.strip() for x in gr),
             "routing.mac_learner.inventory_gateway_roles must be a non-empty list of role names")
    return E


def pin_for(path: Path) -> str:
    """The pinned sha256 a config file must match (Phase 3.1 / 3.2 files -> their own pins; anything else -> the
    Phase 3 pin)."""
    try:
        rp = Path(path).resolve()
        if rp == CONFIG_PATH_3_1.resolve():
            return S.V2_PHASE3_1_CONFIG_SHA256
        if rp == CONFIG_PATH_3_2.resolve():
            return S.V2_PHASE3_2_CONFIG_SHA256
    except OSError:
        pass
    return S.V2_PHASE3_CONFIG_SHA256


def pin_name(want: str) -> str:
    for n in ("V2_PHASE3_1_CONFIG_SHA256", "V2_PHASE3_2_CONFIG_SHA256"):
        if want == getattr(S, n, None):
            return n
    return "V2_PHASE3_CONFIG_SHA256"


def ip_mac_source(cfg: dict, source_kind: str) -> str:
    """How rows without MAC columns are routed for this source kind: static (Phase 3) unless the config says otherwise."""
    return ((cfg.get("routing") or {}).get("ip_mac_source") or {}).get(source_kind, "static")


def load_phase3_config(path: Path = CONFIG_PATH, verify_pin: bool = True) -> dict:
    """Parse + validate. verify_pin: the bytes must equal the pinned config (DFD P5). Refuses split == test."""
    path = Path(path)
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ConfigError(f"{path}: CR bytes (the pin is over LF bytes)")
    sha = hashlib.sha256(raw).hexdigest()
    want = pin_for(path)
    if verify_pin and sha != want:
        name = pin_name(want)
        raise ConfigError(f"{path}: sha256 {sha} != pinned {name} {want} "
                          f"(policy config edited? DFD P5 integrity check failed)")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: not valid JSON: {e}") from None
    if not isinstance(cfg, dict):
        raise ConfigError(f"{path}: top level must be an object")
    for where in ("source", "pcap_source"):                          # explicit, before generic validation
        sp = (cfg.get(where) or {}).get("split")
        if sp is not None:
            refuse_test(sp, f"({where}.split in {path.name})")
    errs = validate(cfg)
    if errs:
        raise ConfigError(f"{path}: " + "; ".join(errs))
    cfg["_sha256"], cfg["_path"], cfg["_pinned"] = sha, str(path), sha == want
    cfg["_overrides"] = {}
    return cfg


def with_overrides(cfg: dict, **kw) -> dict:
    """A copy with operational overrides (OVERRIDABLE); None values are ignored. Re-validated."""
    bad = [k for k in kw if k not in OVERRIDABLE]
    if bad:
        raise ConfigError(f"not overridable: {bad} (allowed {OVERRIDABLE}; policy fields need a re-pinned config)")
    out = copy.deepcopy(cfg)
    ov = dict(out.get("_overrides") or {})
    for k, v in kw.items():
        if v is None:
            continue
        if k == "mode":
            out["mode"] = v
        elif k == "speed":
            out["source"]["speed"] = v
        elif k == "batch_max_flows":
            out["batch"]["max_flows"] = v
        elif k == "slice_minutes":
            out["source"]["slice_minutes"] = v
        elif k == "rate_guard_enabled":
            out["rate_guard"]["enabled"] = bool(v)
        elif k == "seed":
            if v not in out["models"]["evaluation"]["seeds"]:
                raise ConfigError(f"seed {v} not in models.evaluation.seeds")
            out["_seed"] = v
        ov[k] = v
    errs = validate(out)
    if errs:
        raise ConfigError("override makes the config invalid: " + "; ".join(errs))
    out["_overrides"] = ov
    return out
