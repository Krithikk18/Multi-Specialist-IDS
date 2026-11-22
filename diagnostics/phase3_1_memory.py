#!/usr/bin/env python
"""diagnostics/phase3_1_memory.py -- Phase 3.1 PART A check (2): flow-path memory, before vs after chunked writing.

One process runs the flow path (GLOBAL s0, CSV replay of full val at max speed, no packet path) --runs times in a row
and records the process RSS after each run (after gc), the process peak (ru_maxrss) and each run's own RSS samples.
Run once with config/v2_phase3.json ("before": predictions and latencies buffered until the end of a run, the Phase 3
code path) and once with config/v2_phase3_1.json ("after": chunked prediction parts, compact latency buffers), each in
its own process. Runtime run folders: ~/lgids_cache/v2/runtime_mem31/<run_id>_<label>_r<k>/ (new folders only).
Output: results/phase3_1/memory/<label>_<run_id>.json (refused if it exists).
"""

from __future__ import annotations

import argparse
import datetime as dt
import gc
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402
from common import alert_log as AL  # noqa: E402
from common import flow_source as FS  # noqa: E402
from common import model_loader as ML  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import phase3_run as R3  # noqa: E402
from common import schemas as S  # noqa: E402
from common.runtime import Runtime, peak_rss_mb, rss_mb  # noqa: E402


def pins() -> dict:
    return {"config/config.py": R3.sha256_path(S.CONFIG_PY_PATH), "config/class_map.json": R3.sha256_path(S.CLASS_MAP_PATH)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--dry-run", action="store_true", help="the 5 % val sample")
    ap.add_argument("--malloc-trim", action="store_true", help="after each run also call glibc malloc_trim(0): tells a "
                    "real leak (RSS keeps growing) from memory the allocator keeps after free (RSS drops back)")
    args = ap.parse_args()
    S.verify_v2_lock(strict=True)
    p0 = pins()
    print(f"[start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}",
          flush=True)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = RESULTS_DIR / "phase3_1" / "memory" / ("dry_run" if args.dry_run else "")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_p = out_dir / f"{args.label}_{run_id}.json"
    if out_p.exists():
        raise SystemExit(f"{out_p} exists")
    cfg = C.load_phase3_config(Path(args.config))
    rcfg = C.with_overrides(cfg, mode="GLOBAL", seed=0, rate_guard_enabled=False)
    secret, _ = AL.ensure_runtime_keys(C.expand(cfg["paths"]["runtime_keys_dir"]), REPO_ROOT)
    root = C.expand(cfg["paths"]["runtime_root"]).parent / ("runtime_mem31_dry_run" if args.dry_run else "runtime_mem31")
    res = {"label": args.label, "malloc_trim": bool(args.malloc_trim), "config": args.config, "config_sha256": cfg["_sha256"], "pinned": cfg["_pinned"],
           "chunked": cfg.get("predictions_chunk_rows") is not None, "run_id": run_id, "rss_start_mb": rss_mb(),
           "runs": []}
    rm = ML.load_runtime_model(rcfg, mode="GLOBAL", seed=0, evaluation=False)
    res["rss_after_model_load_mb"] = rss_mb()
    for k in range(args.runs):
        d = root / f"{run_id}_{args.label}_r{k}"
        d.mkdir(parents=True, exist_ok=False)
        src = FS.CsvReplaySource(rcfg, sample=args.dry_run)
        rt = Runtime(rcfg, rm, d, secret, store_features=False)
        summ = rt.run(src, None, info=getattr(src, "info", {}))
        in_run = max((x[1] for x in rt.rss), default=float("nan"))
        del rt, src
        gc.collect()
        if args.malloc_trim:
            import ctypes
            ctypes.CDLL("libc.so.6").malloc_trim(0)
        r = {"k": k, "run_dir": str(d), "flows": summ["counts"].get("flows_scored", 0), "wall_s": summ["wall_s"],
             "predictions": summ.get("predictions"), "in_run_rss_max_mb": in_run, "rss_after_run_mb": rss_mb(),
             "process_peak_rss_mb": peak_rss_mb()}
        res["runs"].append(r)
        print(f"  run {k}: {r['flows']:,} flows in {r['wall_s']:.1f} s; in-run RSS max {in_run:.0f} MB; after run "
              f"{r['rss_after_run_mb']:.0f} MB; process peak {r['process_peak_rss_mb']:.0f} MB", flush=True)
    a = [r["rss_after_run_mb"] for r in res["runs"]]
    res["per_run_growth_mb"] = [b - a_ for a_, b in zip(a, a[1:])]
    res["process_peak_rss_mb"] = peak_rss_mb()
    p1 = pins()
    res["lock"] = {"start": p0, "end": p1}
    S.verify_v2_lock(strict=True)
    out_p.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    print(f"[end] verify_v2_lock OK; config.py {p1['config/config.py']}; class_map.json {p1['config/class_map.json']}; "
          f"-> {out_p}", flush=True)
    return 0 if p0 == p1 else 1


if __name__ == "__main__":
    sys.exit(main())
