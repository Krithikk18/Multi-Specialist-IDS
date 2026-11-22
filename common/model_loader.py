"""common/model_loader.py -- Phase 3 model loading (DFD P4): only signed, pinned, promoted models reach the runtime.

    rm = load_runtime_model(cfg)                                   # deployment: cfg mode, promoted entries only
    rm = load_runtime_model(cfg, mode="ROUTED", evaluation=True)   # comparison run (candidate entries allowed)
    rm = load_runtime_model(cfg, seed=3, evaluation=True)          # seed 3: step 22 / 24 files, evaluation only
    mid = rm.model_for(group); m = rm.models[mid]                  # m.booster, m.temperature

Every registry entry is checked by common/registry.load_model (Ed25519 manifest signature, file sha256s, runtime
class_map.json / features_v1.json file hashes, signed state log, state allowed) and then against the V2 pins:
class_map_sha256 == CLASS_MAP_SHA256, features_file_sha256 == FEATURES_V1_SHA256, orientation_map_sha256 ==
ORIENTATION_MAP_SHA256 (an entry without it is refused: the runtime normalises flows with that map), class names ==
the class map, and the runtime orientation map file == its pin. Any failure raises ModelLoadRefused (fail closed).

Routing comes from the entries' own manifests: a non-global entry serves its `serves_groups`; exactly one entry of
kind "global" is the default (every group without its own model). GLOBAL mode = that one entry for every group.

Evaluation-only loads (never a deployment path, flagged in RuntimeModel.evaluation_only):
  seed 0  the same registry entries with the config's evaluation allow_states (e.g. candidate specialists).
  seed s  the seed-0 entries name the model ids; their seed-s boosters come from the step 22 run (sha256 == its
          sha256-checked manifest) and temperatures from the step 24 run (calibrator's model_sha256 == the file).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from common import registry as REG
from common import schemas as S
from common.phase3_config import expand

DEPLOY_STATES = ("promoted",)


class ModelLoadRefused(RuntimeError):
    pass


@dataclass
class LoadedModel:
    model_id: str
    seed: int
    booster: object
    temperature: float
    model_sha256: str
    source: str                     # registry entry id, or "step22:<run>/<file>"
    state: str
    kind: str
    serves_groups: list


@dataclass
class RuntimeModel:
    mode: str
    seed: int
    models: dict
    routing: dict
    default: str
    class_names: list
    evaluation_only: bool
    provenance: list = field(default_factory=list)

    def model_for(self, group: str) -> str:
        return self.routing.get(group, self.default)

    def describe(self) -> dict:
        return {"mode": self.mode, "seed": self.seed, "evaluation_only": self.evaluation_only,
                "routing": dict(self.routing), "default": self.default,
                "models": {k: {"source": m.source, "state": m.state, "model_sha256": m.model_sha256,
                               "temperature": m.temperature, "kind": m.kind, "serves_groups": m.serves_groups}
                           for k, m in self.models.items()}, "provenance": self.provenance}


def public_key(keys_dir: Path) -> bytes:
    """The registry public key (never creates keys: a runtime must not mint a signing key)."""
    p = Path(keys_dir).expanduser() / f"{REG.KEY_NAME}.pub"
    if not p.is_file():
        raise ModelLoadRefused(f"registry public key {p} not found")
    return bytes.fromhex(p.read_text(encoding="ascii").strip())


def check_pins(M: dict, where: str) -> None:
    problems = []
    if M.get("class_map_sha256") != S.CLASS_MAP_SHA256:
        problems.append(f"class_map_sha256 {M.get('class_map_sha256')} != pin {S.CLASS_MAP_SHA256}")
    if M.get("features_file_sha256") != S.FEATURES_V1_SHA256:
        problems.append(f"features_file_sha256 {M.get('features_file_sha256')} != pin {S.FEATURES_V1_SHA256}")
    if M.get("orientation_map_sha256") != S.ORIENTATION_MAP_SHA256:
        problems.append(f"orientation_map_sha256 {M.get('orientation_map_sha256')} != pin {S.ORIENTATION_MAP_SHA256} "
                        f"(the runtime normalises flows with the pinned map)")
    names = list(S.load_class_map().names)
    if "class_names" in M and list(M["class_names"]) != names:
        problems.append(f"class_names {M['class_names']} != class map {names}")
    if REG.sha256_file(S.ORIENTATION_MAP_PATH) != S.ORIENTATION_MAP_SHA256:
        problems.append("runtime config/orientation_map.json sha256 != pin")
    if problems:
        raise ModelLoadRefused(f"{where}: " + "; ".join(problems))


def load_entry(root: Path, entry_id: str, public: bytes, allow_states=DEPLOY_STATES) -> tuple[LoadedModel, dict]:
    d = Path(root).expanduser() / entry_id
    if not d.is_dir():
        raise ModelLoadRefused(f"registry entry {d} not found")
    try:
        L = REG.load_model(d, public, S.CLASS_MAP_PATH, S.FEATURES_PATH, allow_states=tuple(allow_states))
    except REG.RegistryRefused as e:
        raise ModelLoadRefused(f"{entry_id}: {e}") from None
    M = L["manifest"]
    check_pins(M, entry_id)
    m = LoadedModel(model_id=M["model_id"], seed=int(M["seed"]), booster=L["booster"], temperature=float(L["temperature"]),
                    model_sha256=M["files"]["model.ubj"], source=entry_id, state=L["state"], kind=M["kind"],
                    serves_groups=list(M.get("serves_groups") or []))
    return m, M


def _routing(models: list[LoadedModel], mode: str) -> tuple[dict, str]:
    glob = [m for m in models if m.kind == "global"]
    if len(glob) != 1:
        raise ModelLoadRefused(f"{mode}: need exactly one entry of kind 'global', got {[m.model_id for m in glob]}")
    if mode == "GLOBAL":
        if len(models) != 1:
            raise ModelLoadRefused(f"GLOBAL mode takes exactly one entry, got {[m.model_id for m in models]}")
        return {}, glob[0].model_id
    routing = {}
    for m in models:
        if m.kind == "global":
            continue
        for g in m.serves_groups:
            if g in routing:
                raise ModelLoadRefused(f"group {g} served by two entries ({routing[g]}, {m.model_id})")
            routing[g] = m.model_id
    if not routing:
        raise ModelLoadRefused("ROUTED mode without any group specialist")
    return routing, glob[0].model_id


def _seed_models(cfg: dict, seed: int, seed0: list[tuple[LoadedModel, dict]]) -> list[LoadedModel]:
    """Seed-s boosters of the seed-0 entries' model ids, from the step 22 / 24 runs named in the config."""
    import xgboost as xgb
    from common import phase2_run as R
    from common.phase2_config import load_phase2_config
    from config.config import REPO_ROOT
    ev = cfg["models"]["evaluation"]
    cfg2 = load_phase2_config(REPO_ROOT / cfg["phase2_config"])
    up22 = R.resolve_run("22", ev["train_run"], False, R.results_root(cfg2))
    up24 = R.resolve_run("24", ev["calib_run"], False, R.results_root(cfg2))
    M22 = up22["manifest"]
    if up24["manifest"]["train_run"] != ev["train_run"]:
        raise ModelLoadRefused(f"step 24 run {ev['calib_run']} calibrated {up24['manifest']['train_run']}, not {ev['train_run']}")
    check_pins({"class_map_sha256": M22["class_map_sha256"], "features_file_sha256": M22["features_file_sha256"],
                "orientation_map_sha256": (M22.get("orientation") or {}).get("map_sha256")}, f"step 22 run {ev['train_run']}")
    out = []
    for m0, M0 in seed0:
        if M0.get("train_run") != ev["train_run"]:
            raise ModelLoadRefused(f"{m0.source}: train_run {M0.get('train_run')} != evaluation.train_run {ev['train_run']}")
        rec = [x for x in M22["models"] if x["model_id"] == m0.model_id and x["seed"] == seed]
        if len(rec) != 1:
            raise ModelLoadRefused(f"step 22 run has {len(rec)} models {m0.model_id} seed {seed}")
        rec = rec[0]
        f = up22["dir"] / rec["file"]
        if REG.sha256_file(f) != rec["sha256"]:
            raise ModelLoadRefused(f"{f}: sha256 != step 22 manifest")
        cal = json.loads((up24["dir"] / f"{rec['key']}.temperature.json").read_text(encoding="utf-8"))
        if cal["model_sha256"] != rec["sha256"]:
            raise ModelLoadRefused(f"{rec['key']}: calibrator model_sha256 != model file")
        b = xgb.Booster()
        b.load_model(str(f))
        out.append(LoadedModel(model_id=m0.model_id, seed=seed, booster=b, temperature=float(cal["temperature"]),
                               model_sha256=rec["sha256"], source=f"step22:{ev['train_run']}/{rec['file']}",
                               state="unregistered (evaluation only)", kind=m0.kind, serves_groups=m0.serves_groups))
    return out


def load_runtime_model(cfg: dict, mode: str | None = None, seed: int | None = None, evaluation: bool = False,
                       root: Path | None = None, keys_dir: Path | None = None) -> RuntimeModel:
    mode = mode or cfg["mode"]
    seed = 0 if seed is None else int(seed)
    if mode not in ("GLOBAL", "ROUTED"):
        raise ModelLoadRefused(f"unknown mode {mode!r}")
    if not evaluation and seed != 0:
        raise ModelLoadRefused("a non-zero seed is an evaluation-only load (evaluation=True)")
    if evaluation and seed not in cfg["models"]["evaluation"]["seeds"]:
        raise ModelLoadRefused(f"seed {seed} not in models.evaluation.seeds")
    states = tuple(cfg["models"]["evaluation"]["allow_states"]) if evaluation else DEPLOY_STATES
    root = expand(str(root or cfg["models"]["registry_root"]))
    pub = public_key(keys_dir or expand(cfg["models"]["registry_keys_dir"]))
    loaded = [load_entry(root, e, pub, states) for e in cfg["models"][mode]["entries"]]
    seeds0 = {m.seed for m, _ in loaded}
    if seeds0 != {0}:
        raise ModelLoadRefused(f"registry entries must be the seed-0 models, got seeds {sorted(seeds0)}")
    models = [m for m, _ in loaded] if seed == 0 else _seed_models(cfg, seed, loaded)
    routing, default = _routing(models, mode)
    prov = [{"entry": m.source, "state": m.state, "model_id": m.model_id, "seed": m.seed, "model_sha256": m.model_sha256,
             "temperature": m.temperature} for m in models]
    return RuntimeModel(mode=mode, seed=seed, models={m.model_id: m for m in models}, routing=routing, default=default,
                        class_names=list(S.load_class_map().names), evaluation_only=bool(evaluation), provenance=prov)
