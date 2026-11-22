"""common/phase3_run.py -- run plumbing for the Phase 3 scripts (27-30), Phase 1 / 2 conventions:

    run = Run("28", "28_run_stream.py", cfg, dry_run, run_id)   # refuses existing targets, flock, run.log
    run.log("..."); run.check(M, name, ok, detail)
    run.finish(ok, M)                                          # run_manifest.json + run_meta.json (results dir)
    lock_banner(run)                                           # guard 7: verify_v2_lock + sha256 of config.py / class_map

Results: results/phase3/<step>/ (full; refused if it holds a run_meta.json), results/phase3/<step>/dry_run/<run_id>/
(gitignored by results/**/dry_run/). Cache dirs are created by the scripts (never overwritten). No git calls.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from config.config import REPO_ROOT, RESULTS_DIR

PHASE3_RESULTS = RESULTS_DIR / "phase3"
COMMON3 = ["common/schemas.py", "common/phase3_config.py", "common/phase3_run.py", "common/model_loader.py",
           "common/flow_source.py", "common/routing.py", "common/inference.py", "common/policy.py",
           "common/packet_source.py", "common/rate_guard_v2.py", "common/alert_log.py", "common/runtime.py",
           "common/orientation.py", "common/registry.py", "common/phase2_metrics.py", "config/v2_phase3.json",
           "config/class_map.json", "config/features_v1.json", "config/orientation_map.json", "docs/V2_PREREG_PHASE3.md",
           "docs/V2_PREREG_PHASE2_AMENDMENT_2.md", "rate_guard.py", "config/rate_guard_v1.json"]


class RunRefused(RuntimeError):
    pass


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def new_run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def code_sha256(files: list[str]) -> dict:
    return {f: (sha256_path(REPO_ROOT / f) if (REPO_ROOT / f).is_file() else None) for f in files}


def write_json(p: Path, obj) -> str:
    data = (json.dumps(obj, indent=1, default=_default) + "\n").encode("utf-8")
    with open(p, "xb") as fh:
        fh.write(data)
    return hashlib.sha256(data).hexdigest()


def _default(o):
    if hasattr(o, "item"):
        return o.item()
    if hasattr(o, "tolist"):
        return o.tolist()
    if isinstance(o, (set, tuple)):
        return list(o)
    return str(o)


class Run:
    def __init__(self, step: str, script: str, cfg: dict, dry_run: bool, run_id: str | None = None,
                 rerun_tag: str | None = None):
        self.step, self.script, self.cfg, self.dry = step, script, cfg, dry_run
        self.run_id = run_id or new_run_id()
        base = PHASE3_RESULTS / step
        if rerun_tag is not None and not re.fullmatch(r"[A-Za-z0-9_.-]+", rerun_tag):
            raise RunRefused(f"rerun tag {rerun_tag!r}: letters, digits, _ . - only")
        self.rerun_tag = rerun_tag
        # a re-run of a full run goes to results/phase3/<step>/<tag>/; the earlier (e.g. killed) run stays in place
        self.res = base / "dry_run" / self.run_id if dry_run else (base / rerun_tag if rerun_tag else base)
        self.fig = self.res / "figures"
        for p in (self.res / "run_meta.json", self.res / "run.log", self.res / "summary.md"):
            if p.exists():
                raise RunRefused(f"{p} exists (never overwritten; move it or use --dry-run / another run id)")
        self.res.mkdir(parents=True, exist_ok=True)
        lockdir = Path.home() / "lgids_cache" / "v2"
        lockdir.mkdir(parents=True, exist_ok=True)
        self._lock = open(lockdir / f".phase3_{step}.lock", "a+", encoding="utf-8")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RunRefused(f"another step {step} run holds the lock") from None
        self._log = open(self.res / "run.log", "x", encoding="utf-8")
        self.t0 = time.monotonic()
        self.log(f"{script}  pid {os.getpid()}  run_id {self.run_id}  dry_run={dry_run}  argv {' '.join(sys.argv[1:])}")

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
                "dry_run": self.dry, "rerun_tag": self.rerun_tag, "results_dir": str(self.res), "argv": [self.script, *sys.argv[1:]], "status": "RUNNING",
                "config": {"path": "config/v2_phase3.json", "sha256": self.cfg["_sha256"], "pinned": self.cfg["_pinned"],
                           "overrides": self.cfg.get("_overrides", {})},
                "pins": {"class_map": S.CLASS_MAP_SHA256, "features": S.FEATURES_V1_SHA256,
                         "orientation_map": S.ORIENTATION_MAP_SHA256, "prereg_phase3": S.PREREG_PHASE3_SHA256,
                         "amendment_2": S.PREREG_PHASE2_AMENDMENT_2_SHA256},
                "code_sha256": code_sha256([self.script, *COMMON3, *(extra_code or [])]),
                "git": "not recorded (no git commands); code identified by code_sha256", "checks": []}

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
                                                "status": M["status"], "dry_run": self.dry, "run_utc": M["created_utc"],
                                                "run_manifest_sha256": sha, "config_sha256": self.cfg["_sha256"],
                                                "runtime_s": M["runtime_s"], "peak_rss_mb": M["peak_rss_mb"],
                                                **(extra or {})})
        self.log(f"{M['status']}  -> {self.res}  ({M['runtime_s']} s)")
        self._log.close()
        self._lock.close()
        return sha


def resolve(step: str, run_id: str | None = None, dry_run: bool = False, rerun_tag: str | None = None) -> dict:
    """An upstream Phase 3 run's run_meta + manifest (manifest sha256 re-checked); rerun_tag = its results subfolder."""
    base = PHASE3_RESULTS / step
    meta_p = (base / "dry_run" / run_id / "run_meta.json") if dry_run else \
        (base / rerun_tag / "run_meta.json" if rerun_tag else base / "run_meta.json")
    if not meta_p.is_file():
        raise RunRefused(f"no upstream run_meta {meta_p}")
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    if run_id and meta["run_id"] != run_id:
        raise RunRefused(f"{meta_p} is run {meta['run_id']}, asked for {run_id}")
    man_p = meta_p.with_name("run_manifest.json")
    if sha256_path(man_p) != meta["run_manifest_sha256"] or meta["status"] != "PASS":
        raise RunRefused(f"{man_p}: sha256 mismatch or status {meta['status']}")
    return {"meta": meta, "manifest": json.loads(man_p.read_text(encoding="utf-8")), "dir": meta_p.parent}


def lock_banner(run: Run, M: dict, when: str) -> dict:
    """Guard 7: verify_v2_lock (strict) + the sha256 of config/config.py and class_map.json, logged and recorded."""
    from common import schemas as S
    S.verify_v2_lock(strict=True)
    sh = {"config/config.py": sha256_path(S.CONFIG_PY_PATH), "config/class_map.json": sha256_path(S.CLASS_MAP_PATH)}
    run.log(f"  [{when}] verify_v2_lock OK; config.py {sh['config/config.py']}; class_map.json {sh['config/class_map.json']}")
    M.setdefault("lock", {})[when] = sh
    return sh
