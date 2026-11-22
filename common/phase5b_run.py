"""common/phase5b_run.py -- run plumbing for the Phase 5B scripts (39-44): common/zeroday_run.ZRun with results under
results/phase5b/, cache under ~/lgids_cache/v2/phase5b[_dry_run]/<kind>/<run_id>/, lock files .phase5b_<step>.lock, and
a manifest that records the Phase 5B config and pins.

    run = P5BRun("39", "39_build_context_dataset.py", cfg5b, dry_run, run_id)
    up = resolve("39", run_id=None, dry_run=False)
"""

from __future__ import annotations

import sys
from pathlib import Path

from config.config import RESULTS_DIR
from common import zeroday_run as ZR
from common.zeroday_run import RunRefused, code_sha256, lock_banner, now_utc, sha256_bytes, sha256_path, write_json  # noqa: F401

PHASE5B_RESULTS = RESULTS_DIR / "phase5b"
COMMON5B = ["common/schemas.py", "common/context_config.py", "common/context_features.py", "common/phase5b_run.py",
            "common/phase5b_eval.py", "common/shap_perturb.py", "common/tail_rule.py", "common/zeroday_run.py", "common/zeroday_metrics.py",
            "common/normal_model.py", "common/loao.py", "common/cl_retrain.py", "common/cl_gate.py", "common/orientation.py",
            "common/phase2_data.py", "common/phase2_metrics.py", "config/v2_phase5b.json", "config/features_v2_2_context.json",
            "config/v2_phase5.json", "config/v2_phase2_v2_1.json", "config/class_map.json", "config/features_v1.json",
            "config/orientation_map.json", "docs/V2_PREREG_PHASE5B.md"]


class P5BRun(ZR.ZRun):
    def __init__(self, step: str, script: str, cfg: dict, dry_run: bool, run_id: str | None = None,
                 rerun_tag: str | None = None, results_root: Path | None = None, cache_root: Path | None = None):
        super().__init__(step, script, cfg, dry_run, run_id, rerun_tag, results_root or PHASE5B_RESULTS, cache_root,
                         lock_prefix="phase5b")

    def base_manifest(self, extra_code: list[str] | None = None) -> dict:
        from common import schemas as S
        return {"run_id": self.run_id, "step": self.step, "script": self.script, "created_utc": now_utc(),
                "dry_run": self.dry, "rerun_tag": self.rerun_tag, "results_dir": str(self.res), "cache_root": str(self.cache),
                "argv": [self.script, *sys.argv[1:]], "status": "RUNNING",
                "config": {"path": "config/v2_phase5b.json", "sha256": self.cfg["_sha256"], "pinned": self.cfg.get("_pinned")},
                "pins": {"prereg_phase5b": S.PREREG_PHASE5B_SHA256, "phase5b_config": S.V2_PHASE5B_CONFIG_SHA256,
                         "features_v2_2_context": S.FEATURES_V2_2_CONTEXT_SHA256, "class_map": S.CLASS_MAP_SHA256,
                         "features": S.FEATURES_V1_SHA256, "orientation_map": S.ORIENTATION_MAP_SHA256,
                         "phase5_config": S.V2_PHASE5_CONFIG_SHA256},
                "code_sha256": code_sha256(list(dict.fromkeys([self.script, *COMMON5B, *(extra_code or [])]))),
                "git": "not recorded (no git commands); code identified by code_sha256",
                "registry": "not touched (Phase 5B registers nothing)", "checks": []}


def resolve(step: str, run_id: str | None = None, dry_run: bool = False, rerun_tag: str | None = None) -> dict:
    return ZR.resolve(step, run_id, dry_run, rerun_tag, results_root=PHASE5B_RESULTS)


_VERIFIED: dict = {}


def load_ctx_split(up39: dict, split: str, columns: list[str] | None = None):
    """A v2_2_context split written by step 39 (train / val only; file sha256 == the step 39 manifest, once per process)."""
    import pyarrow.parquet as pq
    if split not in ("train", "val"):
        raise RunRefused(f"Phase 5B reads train / val only; refused split {split!r}")
    rec = up39["manifest"]["dataset"]["files"][split]
    p = Path(rec["path"])
    if "test" in p.name.lower():
        raise RunRefused(f"refused path {p}")
    if str(p) not in _VERIFIED:
        if sha256_path(p) != rec["file_sha256"]:
            raise RunRefused(f"{p}: sha256 != step 39 manifest")
        _VERIFIED[str(p)] = rec["file_sha256"]
    cols = None if columns is None else list(dict.fromkeys(columns))
    return pq.read_table(p, columns=cols).to_pandas()
