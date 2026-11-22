#!/usr/bin/env python
"""diagnostics/phase3_2_memory_soak.py -- Phase 3.2 PART A: memory soak test (leak vs allocator fragmentation).

Rule (fixed by the Phase 3.2 prompt before any number): 10 consecutive full-val flow-path runs in ONE process (GLOBAL
s0, CSV replay at max speed, config/v2_phase3_1.json, no packet path, gc + glibc malloc_trim(0) after each run). Fit
RSS-after-run against the run number for runs 4-10 (ordinary least squares, two-sided 95 % t CI, n - 2 = 5 df):
    LEAK     iff slope > 5 MB / run AND the CI's lower bound > 0
    PLATEAU  otherwise (fragmentation / allocator caching, not a leak)
Also recorded per run (evidence, not part of the rule): glibc mallinfo2 (heap bytes in use / free / mmapped), the
number of gc-tracked Python objects, the in-run RSS maximum, the process peak, and whether the run's predictions equal
the Phase 3.1 parity run's GLOBAL s0 predictions row for row (every column).
--tracemalloc: a SECOND soak (only if the first says LEAK) that takes tracemalloc snapshots after run 2 and run 10 and
lists the top allocation-site differences (tracemalloc inflates RSS, so it is never the measured soak).
Runtime run folders: ~/lgids_cache/v2/runtime_mem32[_dry_run]/<run_id>_r<k>/ (new folders only).
Outputs: results/phase3_2/memory/ soak.json, summary.md, figures/rss_per_run.png, run.log (refused if they exist);
--dry-run: the 5 % val sample, 4 runs, results/phase3_2/memory/dry_run/<run_id>/.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import gc
import json
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402
from common import alert_log as AL  # noqa: E402
from common import flow_source as FS  # noqa: E402
from common import model_loader as ML  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import phase3_run as R3  # noqa: E402
from common import predictions_io as PIO  # noqa: E402
from common import schemas as S  # noqa: E402
from common.runtime import Runtime, peak_rss_mb, rss_mb  # noqa: E402

SCRIPT = "diagnostics/phase3_2_memory_soak.py"
CONFIG = "config/v2_phase3_1.json"
RULE = {"fit_runs": [4, 10], "slope_mb_per_run_gt": 5.0, "ci_level": 0.95,
        "leak_iff": "slope > 5 MB/run AND the 95 % CI lower bound > 0", "otherwise": "PLATEAU"}
PARITY_REF = "results/phase3/28/phase3_1_parity"          # Phase 3.1 parity re-run (run 20261122T072459Z)


def pins() -> dict:
    return {"config/config.py": R3.sha256_path(S.CONFIG_PY_PATH), "config/class_map.json": R3.sha256_path(S.CLASS_MAP_PATH)}


class _MallInfo2(ctypes.Structure):
    _fields_ = [(n, ctypes.c_size_t) for n in ("arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks",
                                                 "uordblks", "fordblks", "keepcost")]


_LIBC = ctypes.CDLL("libc.so.6")


def mallinfo_mb() -> dict:
    """glibc mallinfo2: heap (sbrk + arenas) bytes in use / free, mmapped bytes; MB. {} when unavailable."""
    try:
        f = _LIBC.mallinfo2
    except AttributeError:
        return {}
    f.restype = _MallInfo2
    m = f()
    mb = 1024.0 * 1024.0
    return {"heap_total_mb": m.arena / mb, "in_use_mb": m.uordblks / mb, "free_in_heap_mb": m.fordblks / mb,
            "mmapped_mb": m.hblkhd / mb, "top_releasable_mb": m.keepcost / mb}


def arrow_pool_mb() -> dict:
    """pyarrow's own memory pool (jemalloc / mimalloc: invisible to mallinfo2); MB. Read-only, never released here."""
    try:
        import pyarrow as pa
        p = pa.default_memory_pool()
        return {"backend": p.backend_name, "allocated_mb": p.bytes_allocated() / 2 ** 20, "max_mb": p.max_memory() / 2 ** 20}
    except Exception:                                                  # noqa: BLE001
        return {}


def ols_fit(x: list, y: list, level: float) -> dict:
    from scipy import stats
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    sxx = sum((a - mx) ** 2 for a in x)
    b = sum((a - mx) * (c - my) for a, c in zip(x, y)) / sxx
    a0 = my - b * mx
    res = [c - (a0 + b * a) for a, c in zip(x, y)]
    s2 = sum(r * r for r in res) / (n - 2)
    se = math.sqrt(s2 / sxx)
    tq = float(stats.t.ppf(0.5 + level / 2, n - 2))
    return {"n": n, "df": n - 2, "slope_mb_per_run": b, "intercept_mb": a0, "se": se, "t_quantile": tq,
            "ci": [b - tq * se, b + tq * se], "residual_sd_mb": math.sqrt(s2)}


def verdict(fit: dict) -> str:
    return "LEAK" if (fit["slope_mb_per_run"] > RULE["slope_mb_per_run_gt"] and fit["ci"][0] > 0) else "PLATEAU"


def parity_reference(dry: bool):
    if dry:
        return None, None
    runs = json.loads((REPO_ROOT / PARITY_REF / "runs.json").read_text(encoding="utf-8"))
    d = Path(runs["GLOBAL_s0"]["dir"])
    return d, PIO.read_predictions(d)


def figure(out: Path, res: dict, name: str = "rss_per_run.png", legend_loc: str = "lower right") -> str:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    PS.apply()
    runs = res["runs"]
    x = [r["run"] for r in runs]
    y = [r["rss_after_run_mb"] for r in runs]
    f = res["fit"]
    lo, hi = RULE["fit_runs"]
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    ax.plot(x, y, "o-", color=PS.CATEGORICAL[0], lw=1.2, ms=5, label="RSS after run (gc + malloc_trim)")
    iu = [r.get("malloc", {}).get("in_use_mb") for r in runs]
    if all(v is not None for v in iu):
        ax.plot(x, iu, "s--", color=PS.CATEGORICAL[2], lw=1.0, ms=4, label="glibc heap in use (mallinfo2)")
    xs = [lo + (hi - lo) * k / 50 for k in range(51)]
    b, a0, se, tq = f["slope_mb_per_run"], f["intercept_mb"], f["se"], f["t_quantile"]
    mx = sum(range(lo, hi + 1)) / (hi - lo + 1)
    sxx = sum((k - mx) ** 2 for k in range(lo, hi + 1))
    n = hi - lo + 1
    band = [tq * f["residual_sd_mb"] * math.sqrt(1 / n + (v - mx) ** 2 / sxx) for v in xs]
    yl = [a0 + b * v for v in xs]
    ax.plot(xs, yl, color=PS.CATEGORICAL[1], lw=1.6,
            label=f"OLS fit runs {lo}-{hi}: {b:+.2f} MB/run [{f['ci'][0]:+.2f}, {f['ci'][1]:+.2f}]")
    ax.fill_between(xs, [m - w for m, w in zip(yl, band)], [m + w for m, w in zip(yl, band)], color=PS.CATEGORICAL[1],
                    alpha=0.15, lw=0, label="95 % CI of the fitted line")
    ax.axvspan(0.5, lo - 0.5, color="0.5", alpha=0.08, lw=0)
    ax.text(0.6, ax.get_ylim()[1], "  warm-up runs (not fitted)", va="top", fontsize=7, color="0.35")
    ax.set_xticks(x)
    ax.set_xlabel("consecutive full-val run in one process")
    ax.set_ylabel("MB")
    ax.set_title(f"Memory soak, GLOBAL s0 flow path, 10 x 157,558 flows -- verdict {res['verdict']}", loc="left",
                 fontsize=9)
    ax.legend(fontsize=7, loc=legend_loc, frameon=False)
    p = out / "figures" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    return str(PS.save(fig, p))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true", help="the 5 % val sample, 4 runs")
    ap.add_argument("--tracemalloc", action="store_true", help="second soak: snapshots after run 2 and run 10")
    ap.add_argument("--tag", default="", help="results subfolder for a second (tracemalloc / post-fix) soak")
    ap.add_argument("--replot", default=None, help="soak.json: re-draw its figure as figures/rss_per_run_fixed.png "
                    "(legend moved off the data; numbers unchanged; refuses an existing target)")
    args = ap.parse_args()
    S.verify_v2_lock(strict=True)
    p0 = pins()
    print(f"[start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}",
          flush=True)
    if args.replot:
        sj = Path(args.replot)
        tgt = sj.parent / "figures" / "rss_per_run_fixed.png"
        if tgt.exists():
            raise SystemExit(f"{tgt} exists (never overwritten)")
        print(figure(sj.parent, json.loads(sj.read_text(encoding="utf-8")), "rss_per_run_fixed.png", "center right"))
        S.verify_v2_lock(strict=True)
        p1 = pins()
        print(f"[end] verify_v2_lock OK; config.py {p1['config/config.py']}; class_map.json {p1['config/class_map.json']}")
        return 0 if p0 == p1 else 1
    runs_n = 4 if args.dry_run else args.runs
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = RESULTS_DIR / "phase3_2" / "memory"
    out = base / "dry_run" / run_id if args.dry_run else (base / args.tag if args.tag else base)
    for p in (out / "soak.json", out / "summary.md", out / "run.log"):
        if p.exists():
            raise SystemExit(f"{p} exists (never overwritten)")
    out.mkdir(parents=True, exist_ok=True)
    logf = open(out / "run.log", "x", encoding="utf-8")

    def log(msg: str) -> None:
        line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')}  {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
        logf.flush()

    log(f"{SCRIPT} run_id {run_id} dry_run={args.dry_run} runs={runs_n} tracemalloc={args.tracemalloc} argv {sys.argv[1:]}")
    log(f"[start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    log(f"rule (fixed before any number): {RULE}")
    cfg = C.load_phase3_config(REPO_ROOT / CONFIG)
    rcfg = C.with_overrides(cfg, mode="GLOBAL", seed=0, rate_guard_enabled=False)
    secret, _ = AL.ensure_runtime_keys(C.expand(cfg["paths"]["runtime_keys_dir"]), REPO_ROOT)
    root = C.expand(cfg["paths"]["runtime_root"]).parent / ("runtime_mem32_dry_run" if args.dry_run else "runtime_mem32")
    ref_dir, Pref = parity_reference(args.dry_run)
    if ref_dir is not None:
        log(f"parity reference: {ref_dir} ({len(Pref):,} rows, layout {PIO.layout(ref_dir)})")
    tm = None
    if args.tracemalloc:
        import tracemalloc as tm
        tm.start(25)
    res = {"script": SCRIPT, "run_id": run_id, "dry_run": args.dry_run, "config": CONFIG, "config_sha256": cfg["_sha256"],
           "pinned": cfg["_pinned"], "rule": RULE, "tracemalloc": bool(args.tracemalloc), "rss_start_mb": rss_mb(),
           "code_sha256": R3.code_sha256([SCRIPT, "common/runtime.py", "common/flow_source.py", "common/predictions_io.py",
                                          "common/inference.py", "common/policy.py", "common/routing.py",
                                          "common/alert_log.py", "common/model_loader.py", "common/mac_learner.py"]),
           "parity_reference": str(ref_dir) if ref_dir else None, "runs": []}
    rm = ML.load_runtime_model(rcfg, mode="GLOBAL", seed=0, evaluation=False)
    gc.collect()
    _LIBC.malloc_trim(0)
    res["rss_after_model_load_mb"] = rss_mb()
    res["malloc_after_model_load"] = mallinfo_mb()
    snaps = {}
    for k in range(runs_n):
        d = root / f"{run_id}{('_' + args.tag) if args.tag else ''}_r{k + 1}"
        d.mkdir(parents=True, exist_ok=False)
        src = FS.CsvReplaySource(rcfg, sample=args.dry_run)
        rt = Runtime(rcfg, rm, d, secret, store_features=False)
        summ = rt.run(src, None, info=getattr(src, "info", {}))
        in_run = max((x[1] for x in rt.rss), default=float("nan"))
        del rt, src
        gc.collect()
        rss_pre_trim = rss_mb()
        mi_pre = mallinfo_mb()
        _LIBC.malloc_trim(0)
        r = {"run": k + 1, "run_dir": str(d), "flows": summ["counts"].get("flows_scored", 0), "wall_s": summ["wall_s"],
             "in_run_rss_max_mb": in_run, "rss_before_trim_mb": rss_pre_trim, "rss_after_run_mb": rss_mb(),
             "malloc_before_trim": mi_pre, "malloc": mallinfo_mb(), "arrow_pool": arrow_pool_mb(),
             "gc_objects": len(gc.get_objects()),
             "process_peak_rss_mb": peak_rss_mb()}
        if Pref is not None:
            t0 = time.monotonic()
            Pn = PIO.read_predictions(d)
            r["predictions_equal_phase3_1"] = bool(list(Pn.columns) == list(Pref.columns) and len(Pn) == len(Pref)
                                                   and Pn.equals(Pref))
            del Pn
            gc.collect()
            _LIBC.malloc_trim(0)
            r["compare_s"] = time.monotonic() - t0
            r["rss_after_compare_mb"] = rss_mb()
        if tm is not None and (k + 1) in (2, runs_n):
            snaps[k + 1] = tm.take_snapshot()
            r["tracemalloc_traced_mb"] = tm.get_traced_memory()[0] / 2 ** 20
        res["runs"].append(r)
        log(f"  run {k + 1}: {r['flows']:,} flows in {r['wall_s']:.1f} s; in-run RSS max {in_run:.0f} MB; after run "
            f"{r['rss_after_run_mb']:.1f} MB (before trim {rss_pre_trim:.1f}); heap in use "
            f"{r['malloc'].get('in_use_mb', float('nan')):.1f} MB, free in heap {r['malloc'].get('free_in_heap_mb', float('nan')):.1f} MB, "
            f"mmapped {r['malloc'].get('mmapped_mb', float('nan')):.1f} MB; arrow pool "
            f"{r['arrow_pool'].get('allocated_mb', float('nan')):.1f} MB; gc objects {r['gc_objects']:,}; "
            f"predictions == Phase 3.1: {r.get('predictions_equal_phase3_1', '-')}")
    lo, hi = RULE["fit_runs"] if not args.dry_run else (2, runs_n)
    sel = [r for r in res["runs"] if lo <= r["run"] <= hi]
    res["fit"] = ols_fit([r["run"] for r in sel], [r["rss_after_run_mb"] for r in sel], RULE["ci_level"])
    res["fit"]["runs"] = [lo, hi]
    res["verdict"] = verdict(res["fit"])
    iu = [r["malloc"].get("in_use_mb") for r in sel]
    if all(v is not None for v in iu):
        res["fit_heap_in_use"] = ols_fit([r["run"] for r in sel], iu, RULE["ci_level"])
    res["fit_gc_objects"] = ols_fit([r["run"] for r in sel], [r["gc_objects"] for r in sel], RULE["ci_level"])
    a = [r["rss_after_run_mb"] for r in res["runs"]]
    res["per_run_growth_mb"] = [b - a_ for a_, b in zip(a, a[1:])]
    res["process_peak_rss_mb"] = peak_rss_mb()
    f = res["fit"]
    log(f"fit runs {lo}-{hi}: slope {f['slope_mb_per_run']:+.3f} MB/run, 95 % CI [{f['ci'][0]:+.3f}, {f['ci'][1]:+.3f}] "
        f"-> VERDICT {res['verdict']}")
    if snaps:
        k2, k10 = sorted(snaps)
        st = snaps[k10].compare_to(snaps[k2], "traceback")
        res["tracemalloc_top"] = [{"size_diff_kb": s.size_diff / 1024, "count_diff": s.count_diff,
                                   "traceback": [f"{fr.filename}:{fr.lineno}" for fr in s.traceback][-8:]}
                                  for s in st[:25]]
        res["tracemalloc_total_diff_mb"] = sum(s.size_diff for s in st) / 2 ** 20
        for s in st[:10]:
            log(f"  tracemalloc {s.size_diff / 1024:+.0f} kB ({s.count_diff:+d}): {s.traceback[-1]}")
    try:
        res["figure"] = str(Path(figure(out, res)).relative_to(REPO_ROOT))
    except Exception as e:                                             # noqa: BLE001
        res["figure_error"] = repr(e)
        log(f"figure error: {e!r}")
    S.verify_v2_lock(strict=True)
    p1 = pins()
    res["lock"] = {"start": p0, "end": p1}
    R3.write_json(out / "soak.json", res)
    write_summary(out, res)
    log(f"[end] verify_v2_lock OK; config.py {p1['config/config.py']}; class_map.json {p1['config/class_map.json']} -> {out}")
    logf.close()
    return 0 if p0 == p1 else 1


def write_summary(out: Path, res: dict) -> None:
    f = res["fit"]
    lo, hi = f["runs"]
    L = [f"# Phase 3.2 Part A -- memory soak -- {res['verdict']}" + (" (DRY RUN)" if res["dry_run"] else ""), "",
         f"Run `{res['run_id']}`; `{res['config']}` (sha256 `{res['config_sha256'][:16]}...`, pinned {res['pinned']}); "
         f"GLOBAL s0, CSV replay of full val at max speed, no packet path; {len(res['runs'])} consecutive runs in one "
         "process; gc + `malloc_trim(0)` after each run.", "",
         "**Rule (fixed before any number):** fit RSS-after-run against run number for runs 4-10 (OLS, 95 % t CI). "
         "LEAK iff slope > 5 MB/run AND the CI lies entirely above 0; otherwise PLATEAU (fragmentation / allocator "
         "caching, not a leak).", "",
         f"**Fit runs {lo}-{hi}: slope {f['slope_mb_per_run']:+.2f} MB/run, 95 % CI [{f['ci'][0]:+.2f}, "
         f"{f['ci'][1]:+.2f}] (df {f['df']}) -> VERDICT {res['verdict']}.**", "",
         "| run | flows | wall s | in-run RSS max MB | RSS before trim MB | RSS after run MB | glibc heap in use MB | "
         "free in heap MB | mmapped MB | arrow pool MB | gc objects | predictions == Phase 3.1 |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in res["runs"]:
        m = r.get("malloc", {})
        L.append(f"| {r['run']} | {r['flows']:,} | {r['wall_s']:.1f} | {r['in_run_rss_max_mb']:.0f} | "
                 f"{r['rss_before_trim_mb']:.1f} | {r['rss_after_run_mb']:.1f} | {m.get('in_use_mb', float('nan')):.1f} | "
                 f"{m.get('free_in_heap_mb', float('nan')):.1f} | {m.get('mmapped_mb', float('nan')):.1f} | "
                 f"{r.get('arrow_pool', {}).get('allocated_mb', float('nan')):.1f} | "
                 f"{r['gc_objects']:,} | {r.get('predictions_equal_phase3_1', '-')} |")
    L += ["", f"- RSS after model load: {res['rss_after_model_load_mb']:.1f} MB; process peak "
          f"{res['process_peak_rss_mb']:.0f} MB; per-run growth (MB): "
          + ", ".join(f"{g:+.1f}" for g in res["per_run_growth_mb"])]
    if res.get("fit_heap_in_use"):
        h = res["fit_heap_in_use"]
        L.append(f"- evidence (not part of the rule): glibc heap in use, runs {lo}-{hi}: {h['slope_mb_per_run']:+.2f} "
                 f"MB/run [{h['ci'][0]:+.2f}, {h['ci'][1]:+.2f}]")
    g = res["fit_gc_objects"]
    L.append(f"- evidence: gc-tracked Python objects, runs {lo}-{hi}: {g['slope_mb_per_run']:+.1f} objects/run "
             f"[{g['ci'][0]:+.1f}, {g['ci'][1]:+.1f}]")
    if res.get("parity_reference"):
        L.append(f"- every run's predictions vs the Phase 3.1 parity run GLOBAL s0 (`{res['parity_reference']}`), row "
                 f"for row, every column: {all(r.get('predictions_equal_phase3_1') for r in res['runs'])}")
    if res.get("tracemalloc_top"):
        L += ["", "## tracemalloc: run 10 - run 2, top sites", ""]
        L += [f"- {t['size_diff_kb']:+.0f} kB ({t['count_diff']:+d} blocks): `{t['traceback'][-1]}`"
              for t in res["tracemalloc_top"][:15]]
    if res.get("figure"):
        L += ["", f"Figure: `{res['figure']}`"]
    L += ["", f"Lock: config.py `{res['lock']['end']['config/config.py']}`, class_map.json "
          f"`{res['lock']['end']['config/class_map.json']}` (start == end: {res['lock']['start'] == res['lock']['end']})"]
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
