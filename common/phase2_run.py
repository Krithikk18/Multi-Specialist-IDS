"""common/phase2_run.py -- run plumbing shared by the Phase 2 scripts (22-26), Phase 1 conventions:

  start_run(step, kind, cfg, dry_run, run_id)  refuses existing targets, flock on the cache root, opens run.log,
                                               creates <cache>/<kind>[_dry_run]/.<run_id>.partial
  finish_run(ctx, ok, manifest, meta_extra)    manifest -> partial dir, rename to <run_id> (or <run_id>.FAILED:
                                               nothing is ever deleted), copy to results, run_meta.json
  resolve_run(step, run_id, dry_run)           an upstream run's run_meta + manifest (sha256-checked)
  code_sha256(files)                           sha256 of every code / config file used (no git: Phase 2 guard)
Results: results/<step>/ (full; refused if it exists), results/<step>/dry_run/<run_id>/ (gitignored).
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

from config.config import REPO_ROOT, RESULTS_DIR
from common.phase2_config import expand

COMMON_CODE = ["common/__init__.py", "common/schemas.py", "common/plot_style.py", "common/phase2_config.py",
               "common/phase2_data.py", "common/phase2_run.py", "common/phase2_metrics.py", "common/registry.py",
               "config/class_map.json", "config/features_v1.json", "config/v2_phase2.json", "docs/V2_PREREG_PHASE2.md"]


class RunRefused(RuntimeError):
    pass


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def new_run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def code_sha256(files: list[str]) -> dict:
    return {f: (sha256_path(REPO_ROOT / f) if (REPO_ROOT / f).is_file() else None) for f in files}


def write_json(p: Path, obj) -> str:
    """Write once (refuses to overwrite); returns the file's sha256."""
    data = (json.dumps(obj, indent=1, default=str) + "\n").encode("utf-8")
    with open(p, "xb") as fh:
        fh.write(data)
    return sha256_bytes(data)


def canon_sha256(obj) -> str:
    return sha256_bytes(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))


class Ctx:
    """One run: paths, log, lock."""

    def __init__(self, step: str, kind: str, script: str, cfg: dict, dry_run: bool, run_id: str | None):
        self.step, self.kind, self.script, self.cfg, self.dry_run = step, kind, script, cfg, dry_run
        self.run_id = run_id or new_run_id()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.run_id):
            raise RunRefused(f"run id {self.run_id!r}: letters, digits, _ . - only")
        self.root = expand(cfg["paths"]["cache_root"]) / (f"{kind}_dry_run" if dry_run else kind)
        self.final = self.root / self.run_id
        self.partial = self.root / f".{self.run_id}.partial"
        res_root = Path(cfg.get("_results_root", RESULTS_DIR))          # tests point this at a temp dir
        self.res = res_root / step / "dry_run" / self.run_id if dry_run else res_root / step
        self.fig = self.res / "figures"
        self._log = None
        self._lock = None
        self.t0 = None

    def log(self, msg: str) -> None:
        line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')}  {msg}"
        print(line, flush=True)
        if self._log is not None:
            self._log.write(line + "\n")
            self._log.flush()


def start_run(step: str, kind: str, script: str, cfg: dict, dry_run: bool, run_id: str | None = None) -> Ctx:
    import time
    ctx = Ctx(step, kind, script, cfg, dry_run, run_id)
    targets = [ctx.final, ctx.partial, ctx.root / f"{ctx.run_id}.FAILED"] + \
              [ctx.res / x for x in ("run_meta.json", "run.log", "summary.md", "run_manifest.json", "figures")]
    existing = [str(p) for p in targets if p.exists()]
    if existing:
        raise RunRefused(f"target path(s) already exist {existing} (never overwritten; use another run id or move them)")
    ctx.root.mkdir(parents=True, exist_ok=True)
    fh = open(ctx.root / f".{step}.lock", "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        raise RunRefused(f"another step {step} run holds {ctx.root / f'.{step}.lock'}") from None
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {now_utc()} argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    ctx._lock = fh
    ctx.res.mkdir(parents=True, exist_ok=True)
    ctx._log = open(ctx.res / "run.log", "x", encoding="utf-8")
    ctx.partial.mkdir()
    ctx.t0 = time.monotonic()
    ctx.log(f"{script}  pid {os.getpid()}  run_id {ctx.run_id}  dry_run={dry_run}  -> {ctx.final}")
    return ctx


def results_root(cfg: dict) -> Path:
    """Where this config's runs live: results/ (default) or results/<results_subdir>/ (D40)."""
    return Path(cfg.get("_results_root", RESULTS_DIR))


def _config_rel(cfg: dict) -> str:
    p = Path(cfg.get("_path", "config/v2_phase2.json"))
    try:
        return p.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(p)


def base_manifest(ctx: Ctx, script_file: str, extra_code: list[str] | None = None) -> dict:
    from common import schemas as S
    cfg_rel = _config_rel(ctx.cfg)
    amend = list(ctx.cfg.get("prereg_amendments") or [])
    opt = (["common/amendment.py"] if ctx.cfg.get("primary_selection") else []) + \
          (["common/orientation.py", ctx.cfg["orientation"]["map"]] if ctx.cfg.get("orientation") else [])
    extra = list(dict.fromkeys(f for f in [cfg_rel, *amend, *opt, *(extra_code or [])] if f not in COMMON_CODE))
    M = {"run_id": ctx.run_id, "step": ctx.step, "created_utc": now_utc(), "script": script_file,
         "dry_run": ctx.dry_run, "argv": [script_file, *sys.argv[1:]], "status": "RUNNING",
         "config": {"path": cfg_rel, "sha256": ctx.cfg["_sha256"]},
         "prereg_phase2_sha256": S.PREREG_PHASE2_SHA256, "class_map_sha256": S.CLASS_MAP_SHA256,
         "features_file_sha256": S.FEATURES_V1_SHA256, "dataset_version": ctx.cfg["dataset_version"],
         "seeds": ctx.cfg["seeds"], "code_sha256": code_sha256([script_file, *COMMON_CODE, *extra]),
         "git": "not recorded (Phase 2 guard: no git commands); code identified by code_sha256",
         "checks": []}
    if amend:
        M["prereg_amendments"] = {a: (sha256_path(REPO_ROOT / a) if (REPO_ROOT / a).is_file() else None) for a in amend}
    if ctx.cfg.get("orientation"):
        M["orientation"] = {**ctx.cfg["orientation"], "map_sha256": sha256_path(REPO_ROOT / ctx.cfg["orientation"]["map"])}
    return M


def finish_run(ctx: Ctx, ok: bool, M: dict, meta_extra: dict | None = None) -> str:
    """Write the manifest, publish the cache dir (<run_id> or <run_id>.FAILED), copy to results, run_meta.json."""
    import time
    M["status"] = "PASS" if ok else "FAIL"
    M["runtime_s"] = round(time.monotonic() - ctx.t0, 1)
    try:
        import resource
        M["peak_rss_mb"] = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    except Exception:                                                  # noqa: BLE001
        M["peak_rss_mb"] = None
    man_sha = write_json(ctx.partial / "run_manifest.json", M)
    dest = ctx.final if ok else ctx.root / f"{ctx.run_id}.FAILED"
    ctx.partial.rename(dest)
    shutil.copyfile(dest / "run_manifest.json", ctx.res / "run_manifest.json")
    meta = {"script": M["script"], "step": ctx.step, "run_id": ctx.run_id, "status": M["status"],
            "dry_run": ctx.dry_run, "run_utc": M["created_utc"], "argv": M["argv"], "cache_dir": str(dest),
            "run_manifest_sha256": man_sha, "config_sha256": ctx.cfg["_sha256"],
            "prereg_phase2_sha256": M["prereg_phase2_sha256"], "code_sha256": M["code_sha256"],
            "checks": M["checks"], "runtime_s": M["runtime_s"], "peak_rss_mb": M["peak_rss_mb"], **(meta_extra or {})}
    write_json(ctx.res / "run_meta.json", meta)
    ctx.log(f"{M['status']}  -> {dest}  |  {ctx.res}  ({M['runtime_s']} s)")
    ctx._log.close()
    ctx._lock.close()
    return man_sha


def add_check(ctx: Ctx, M: dict, name: str, ok: bool, detail: str = "", warn: bool = False) -> bool:
    M["checks"].append({"check": name, "pass": bool(ok), "detail": detail, "level": "warn" if warn else "hard"})
    ctx.log(f"  {'PASS' if ok else ('WARN' if warn else 'FAIL')}  {name}  {detail}")
    return bool(ok)


def resolve_run(step: str, run_id: str | None, dry_run: bool, results_root: Path = RESULTS_DIR) -> dict:
    """run_meta.json of an upstream run (full: results/<step>/; dry: results/<step>/dry_run/<run_id>/) and its
    manifest from the cache dir, with the manifest sha256 checked against run_meta."""
    results_root = Path(results_root)
    if dry_run:
        if not run_id:
            raise RunRefused(f"--dry-run needs the upstream step {step} dry run id")
        meta_p = results_root / step / "dry_run" / run_id / "run_meta.json"
    else:
        meta_p = results_root / step / "run_meta.json"
    if not meta_p.is_file():
        raise RunRefused(f"no upstream run_meta {meta_p}")
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    if run_id and meta["run_id"] != run_id:
        raise RunRefused(f"{meta_p} is run {meta['run_id']}, asked for {run_id}")
    if meta["status"] != "PASS" or bool(meta["dry_run"]) != bool(dry_run):
        raise RunRefused(f"upstream {step} run {meta['run_id']}: status {meta['status']}, dry_run {meta['dry_run']}")
    man_p = Path(meta["cache_dir"]) / "run_manifest.json"
    if sha256_path(man_p) != meta["run_manifest_sha256"]:
        raise RunRefused(f"{man_p}: sha256 != {meta_p} record")
    return {"meta": meta, "manifest": json.loads(man_p.read_text(encoding="utf-8")), "dir": Path(meta["cache_dir"]),
            "manifest_sha256": meta["run_manifest_sha256"]}
