"""common/zeroday_run.py -- run plumbing for the Phase 5A scripts (36-38); the Phase 4 conventions (common/cl_run.py):

    run = ZRun("36", "36_loao_stage1.py", cfg5, dry_run, run_id)   # refuses existing targets, flock, run.log
    d = run.cache_dir("loao")            # <cache_root>[_dry_run]/loao/<run_id>/ (refused if it exists)
    run.log("..."); run.check(M, name, ok, detail, warn=False)
    lock_banner(run, M, "start")         # verify_v2_lock (strict) + sha256 of config.py / class_map.json
    run.finish(ok, M)                    # run_manifest.json + run_meta.json in the results dir
    up = resolve("36", run_id=None, dry_run=False)   # an upstream run (manifest sha256 re-checked, status PASS)

Results: results/phase5a/<step>/ (full; refused if it holds run_meta / run.log / summary / manifest),
results/phase5a/<step>/dry_run/<run_id>/ (git-ignored), results/phase5a/<step>/<rerun_tag>/ for a re-run.
Cache dirs are never overwritten. No git calls (code identified by code_sha256). No registry access.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
import sys
import time
from pathlib import Path

from config.config import RESULTS_DIR
from common.cl_run import (RunRefused, code_sha256, dumps, lock_banner, new_run_id, now_utc,  # noqa: F401
                           sha256_bytes, sha256_path, write_json)

PHASE5_RESULTS = RESULTS_DIR / "phase5a"
COMMON5 = ["common/schemas.py", "common/zeroday_config.py", "common/zeroday_run.py", "common/loao.py",
           "common/normal_model.py", "common/zeroday_metrics.py", "common/cl_retrain.py", "common/cl_run.py",
           "common/phase2_data.py", "common/phase2_metrics.py", "config/v2_phase5.json", "config/v2_phase2_v2_1.json",
           "config/class_map.json", "config/features_v1.json", "docs/V2_PREREG_PHASE5.md",
           "docs/V2_PREREG_PHASE2_AMENDMENT_2.md"]


class ZRun:
    def __init__(self, step: str, script: str, cfg: dict, dry_run: bool, run_id: str | None = None,
                 rerun_tag: str | None = None, results_root: Path | None = None, cache_root: Path | None = None):
        self.step, self.script, self.cfg, self.dry = step, script, cfg, dry_run
        self.run_id = run_id or new_run_id()
        for name, v in (("run id", self.run_id), ("rerun tag", rerun_tag)):
            if v is not None and not re.fullmatch(r"[A-Za-z0-9_.-]+", v):
                raise RunRefused(f"{name} {v!r}: letters, digits, _ . - only")
        self.rerun_tag = rerun_tag
        base = Path(results_root or PHASE5_RESULTS) / step
        self.res_root = Path(results_root or PHASE5_RESULTS)
        self.res = base / "dry_run" / self.run_id if dry_run else (base / rerun_tag if rerun_tag else base)
        self.fig = self.res / "figures"
        for p in (self.res / "run_meta.json", self.res / "run.log", self.res / "summary.md", self.res / "run_manifest.json"):
            if p.exists():
                raise RunRefused(f"{p} exists (never overwritten; use --dry-run, another run id or --rerun-tag)")
        cr = Path(cache_root) if cache_root is not None else Path(cfg["paths"]["cache_root"]).expanduser()
        self.cache = cr.with_name(cr.name + "_dry_run") if dry_run else cr
        self.res.mkdir(parents=True, exist_ok=True)
        self.cache.mkdir(parents=True, exist_ok=True)
        self._lock = open(self.cache / f".phase5a_{step}.lock", "a+", encoding="utf-8")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RunRefused(f"another step {step} run holds the lock") from None
        self._log = open(self.res / "run.log", "x", encoding="utf-8")
        self.t0 = time.monotonic()
        self.log(f"{script}  pid {os.getpid()}  run_id {self.run_id}  dry_run={dry_run}  argv {' '.join(sys.argv[1:])}")

    def cache_dir(self, kind: str) -> Path:
        d = self.cache / kind / self.run_id
        d.mkdir(parents=True, exist_ok=False)
        return d

    def log(self, msg: str) -> None:
        line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')}  {msg}"
        print(line, flush=True)
        self._log.write(line + "\n")
        self._log.flush()

    def check(self, M: dict, name: str, ok: bool, detail: str = "", warn: bool = False) -> bool:
        M.setdefault("checks", []).append({"check": name, "pass": bool(ok), "detail": detail,
                                           "level": "warn" if warn else "hard"})
        self.log(f"  {'PASS' if ok else ('WARN' if warn else 'FAIL')}  {name}  {detail}")
        return bool(ok)

    def base_manifest(self, extra_code: list[str] | None = None) -> dict:
        from common import schemas as S
        return {"run_id": self.run_id, "step": self.step, "script": self.script, "created_utc": now_utc(),
                "dry_run": self.dry, "rerun_tag": self.rerun_tag, "results_dir": str(self.res), "cache_root": str(self.cache),
                "argv": [self.script, *sys.argv[1:]], "status": "RUNNING",
                "config": {"path": "config/v2_phase5.json", "sha256": self.cfg["_sha256"], "pinned": self.cfg.get("_pinned")},
                "pins": {"prereg_phase5": S.PREREG_PHASE5_SHA256, "phase5_config": S.V2_PHASE5_CONFIG_SHA256,
                         "class_map": S.CLASS_MAP_SHA256, "features": S.FEATURES_V1_SHA256,
                         "orientation_map": S.ORIENTATION_MAP_SHA256, "amendment_2": S.PREREG_PHASE2_AMENDMENT_2_SHA256},
                "code_sha256": code_sha256(list(dict.fromkeys([self.script, *COMMON5, *(extra_code or [])]))),
                "git": "not recorded (no git commands); code identified by code_sha256",
                "registry": "not touched (Phase 5A registers nothing)", "checks": []}

    def finish(self, ok: bool, M: dict, extra: dict | None = None) -> str:
        M["status"] = "PASS" if ok else "FAIL"
        M["runtime_s"] = round(time.monotonic() - self.t0, 1)
        try:
            import resource
            M["peak_rss_mb"] = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
        except Exception:                                              # noqa: BLE001
            M["peak_rss_mb"] = None
        sha = write_json(self.res / "run_manifest.json", M)
        write_json(self.res / "run_meta.json", {"script": self.script, "step": self.step, "run_id": self.run_id,
                                                "status": M["status"], "dry_run": self.dry, "rerun_tag": self.rerun_tag,
                                                "run_utc": M["created_utc"], "run_manifest_sha256": sha,
                                                "config_sha256": self.cfg["_sha256"], "runtime_s": M["runtime_s"],
                                                "peak_rss_mb": M["peak_rss_mb"], **(extra or {})})
        self.log(f"{M['status']}  -> {self.res}  ({M['runtime_s']} s)")
        self._log.close()
        self._lock.close()
        return sha


def resolve(step: str, run_id: str | None = None, dry_run: bool = False, rerun_tag: str | None = None,
            results_root: Path | None = None) -> dict:
    """An upstream Phase 5A run's run_meta + manifest (manifest sha256 re-checked, status PASS)."""
    base = Path(results_root or PHASE5_RESULTS) / step
    if dry_run:
        if not run_id:
            raise RunRefused(f"--dry-run needs the upstream step {step} dry run id")
        meta_p = base / "dry_run" / run_id / "run_meta.json"
    else:
        meta_p = base / rerun_tag / "run_meta.json" if rerun_tag else base / "run_meta.json"
    if not meta_p.is_file():
        raise RunRefused(f"no upstream run_meta {meta_p}")
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    if run_id and meta["run_id"] != run_id:
        raise RunRefused(f"{meta_p} is run {meta['run_id']}, asked for {run_id}")
    man_p = meta_p.with_name("run_manifest.json")
    if sha256_path(man_p) != meta["run_manifest_sha256"] or meta["status"] != "PASS" or bool(meta["dry_run"]) != bool(dry_run):
        raise RunRefused(f"{man_p}: sha256 mismatch, status {meta['status']} or dry_run {meta['dry_run']}")
    return {"meta": meta, "manifest": json.loads(man_p.read_text(encoding="utf-8")), "dir": meta_p.parent,
            "manifest_sha256": meta["run_manifest_sha256"]}
