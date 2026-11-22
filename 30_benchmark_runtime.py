#!/usr/bin/env python
"""30_benchmark_runtime.py -- Phase 3 step G: runtime benchmark on the DEV MACHINE (docs/V2_PREREG_PHASE3.md section 7;
report-only, Pi budgets come later).

Runs (GLOBAL, the promoted model; runtime run folders ~/lgids_cache/v2/runtime/<run_id>_BENCH_<tag>/):
  batch sizes {1, 16, 64, 256} at speed max on the full val replay (flow path; lossless back-pressure)
  speed 1x and 10x on the busiest 10-minute val slice (by emission time), batch 64 (paced: the drop policy applies,
  drops / backlog recorded)
Per run: per-stage latency p50 / p95 / p99 (route, normalise, features: per flow; predict, calibrate, SHAP-on-alert,
policy, log: per batch and per flow), end-to-end (dequeue -> decision) and queue wait, flows / s, peak RSS, RSS over
time. Plus: the packet path alone (reader; reader + rate guard v2 + V1 rule) on all val packets, packets / s; the
CICFlowMeter extraction speed from step 28's pcap path. Machine info: CPU model, cores, RAM, OS, Python / XGBoost /
numpy versions.
Outputs: results/phase3/30/ summary.md, benchmark.json, run_manifest.json, run_meta.json, run.log, figures/
{stage_latency_box, throughput, rss_over_time}.png. --dry-run: 5 % val sample, batch sizes {1, 64}, a 1-minute slice.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import traceback
from pathlib import Path

import numpy as np

from config.config import REPO_ROOT
from common import alert_log as AL
from common import flow_source as FS
from common import model_loader as ML
from common import packet_source as PK
from common import phase3_config as C
from common import phase3_run as R3
from common import plot_style as PS
from common import rate_guard_v2 as RG
from common.routing import Router
from common.runtime import STAGES, Runtime

SCRIPT = "30_benchmark_runtime.py"
FLOW_STAGES = ("route", "normalise", "features")
BATCH_STAGES = ("predict", "calibrate", "shap", "policy", "log")


def machine() -> dict:
    import numpy
    import xgboost
    info = {"os": platform.platform(), "python": platform.python_version(), "xgboost": xgboost.__version__,
            "numpy": numpy.__version__, "logical_cpus": None, "cpu_model": None, "ram_gb": None,
            "note": "dev machine (WSL2 on Windows); not the Pi"}
    try:
        cpu = Path("/proc/cpuinfo").read_text()
        info["cpu_model"] = next(l.split(":", 1)[1].strip() for l in cpu.splitlines() if l.startswith("model name"))
        info["logical_cpus"] = sum(1 for l in cpu.splitlines() if l.startswith("processor"))
        mem = Path("/proc/meminfo").read_text()
        info["ram_gb"] = round(int(next(l.split()[1] for l in mem.splitlines() if l.startswith("MemTotal"))) / 1024 ** 2, 1)
    except (OSError, StopIteration):
        pass
    return info


def q(a, scale=1.0) -> dict:
    a = np.asarray(a, float) * scale
    if not len(a):
        return {"p50": None, "p95": None, "p99": None, "n": 0}
    return {"p50": float(np.quantile(a, .5)), "p95": float(np.quantile(a, .95)), "p99": float(np.quantile(a, .99)),
            "n": int(len(a))}


def bench_run(cfg, run, tag: str, batch: int, speed: str, dry: bool, secret: bytes, event_slice=None) -> dict:
    rcfg = C.with_overrides(cfg, batch_max_flows=batch, speed=speed, rate_guard_enabled=False)
    root = C.expand(cfg["paths"]["runtime_root"])
    root = root.with_name(root.name + "_dry_run") if dry else root
    d = root / f"{run.run_id}_BENCH_{tag}"
    d.mkdir(parents=True, exist_ok=False)
    rm = ML.load_runtime_model(rcfg)
    src = FS.CsvReplaySource(rcfg, sample=dry, event_slice=event_slice)
    rt = Runtime(rcfg, rm, d, secret, router=Router(rcfg))
    s = rt.run(src, None, info=src.info)
    L = np.load(d / "latency.npz")
    lat_us = {st: q(L[f"flow_{st}"], 1e-3) for st in STAGES}
    lat_b_us = {st: q(L[f"batch_{st}"], 1e-3) for st in BATCH_STAGES}
    shap_alert = L["batch_shap"][L["batch_shap"] > 0]
    out = {"tag": tag, "batch": batch, "speed": speed, "dir": str(d), "flows": s["counts"].get("flows_scored", 0),
           "offered": len(src), "wall_s": s["wall_s"], "flows_per_s": s["flows_per_s"], "dropped": s["counts"].get("dropped", 0),
           "backlog_peak": s["counts"].get("backlog_peak", 0), "peak_rss_mb": s["peak_rss_mb"],
           "event_span_s": (src.info["event_span"][1] - src.info["event_span"][0]) if src.info.get("event_span") else None,
           "lat_us_per_flow": lat_us, "lat_us_per_batch": lat_b_us,
           "shap_us_per_batch_with_alerts": q(shap_alert, 1e-3), "e2e_ms": q(L["e2e_s"], 1e3),
           "queue_wait_ms": q(L["queue_wait_s"], 1e3), "mean_batch": float(np.mean(L["batch_sizes"])) if len(L["batch_sizes"]) else 0,
           "rss": json.loads((d / "rss.json").read_text())}
    R3.write_json(d / "manifest.json", {k: v for k, v in out.items() if k != "rss"} | {"summary": s, "model": rm.describe(),
                                                                                       "config_overrides": rcfg["_overrides"]})
    run.log(f"  {tag}: {out['flows']:,}/{out['offered']:,} flows in {out['wall_s']:.1f} s = {out['flows_per_s']:,.0f} flows/s; "
            f"dropped {out['dropped']}, backlog peak {out['backlog_peak']}, e2e p50 {out['e2e_ms']['p50']:.2f} ms, "
            f"peak RSS {out['peak_rss_mb']:.0f} MB")
    return out


def packet_bench(cfg, dry: bool) -> dict:
    sessions = ["Recon-PortScan"] if dry else None
    t0 = time.monotonic()
    n = sum(1 for _ in PK.PacketSource(cfg, "val", sessions=sessions))
    t_read = time.monotonic() - t0
    router = Router(cfg)
    T, TM = RG.load_thresholds(cfg)
    r = cfg["rate_guard"]
    g2 = RG.RateGuardV2(router, T["thresholds"], r["families"], r["other_family"], r["window_s"], r["consecutive"],
                        fallback_group=router.fallback)
    v1 = RG.V1Guard(cfg)
    t0 = time.monotonic()
    n2 = 0
    for p in PK.PacketSource(cfg, "val", sessions=sessions):
        g2.update(*p)
        v1.update(*p)
        n2 += 1
    g2.flush()
    v1.flush()
    t_all = time.monotonic() - t0
    return {"packets": n, "reader_s": t_read, "reader_pps": n / t_read, "reader_plus_guards_s": t_all,
            "reader_plus_guards_pps": n2 / t_all, "note": "includes the captures' sha256 check (first pass only) and "
                                                          "skipping the train part of each capture on record headers"}


def figures(run, B: list) -> list:
    import matplotlib.pyplot as plt
    PS.apply()
    out = []
    bs = [b for b in B if b["speed"] == "max"]
    fig, ax = plt.subplots(figsize=(9.0, 3.4))
    pos, data, cols, ticks = [], [], [], []
    for k, st in enumerate(STAGES):
        for j, b in enumerate(bs):
            L = np.load(Path(b["dir"]) / "latency.npz")
            a = L[f"flow_{st}"] / 1e3
            a = a[a > 0] if st == "shap" else a
            data.append(a if len(a) else np.array([np.nan]))
            pos.append(k * (len(bs) + 1) + j)
            cols.append(PS.CATEGORICAL[j % len(PS.CATEGORICAL)])
        ticks.append(k * (len(bs) + 1) + (len(bs) - 1) / 2)
    bp = ax.boxplot(data, positions=pos, widths=0.7, showfliers=False, whis=(1, 99), patch_artist=True)
    for p, c in zip(bp["boxes"], cols):
        p.set_facecolor(c)
        p.set_alpha(0.75)
    for m in bp["medians"]:
        m.set_color(PS.TEXT1)
    ax.set_yscale("log")
    ax.set_xticks(ticks, [s if s not in BATCH_STAGES else f"{s}\n(per flow)" for s in STAGES], fontsize=8)
    ax.set_ylabel("microseconds (log)")
    ax.yaxis.grid(True)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=PS.CATEGORICAL[j], alpha=0.75, label=f"batch {b['batch']}") for j, b in enumerate(bs)],
              frameon=False, fontsize=7.5, ncol=len(bs), loc="upper left")
    ax.set_title("Per-stage latency, speed max (box = p25-p75, whiskers p1-p99; batch stages amortised per flow; "
                 "SHAP only for batches with alerts)", loc="left", fontsize=8.5)
    out.append(PS.save(fig, run.fig / "stage_latency_box.png"))
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 3.0))
    ax = axes[0]
    x = [b["batch"] for b in bs]
    y = [b["flows_per_s"] for b in bs]
    ax.plot(x, y, "o-", color=PS.CATEGORICAL[0])
    for xx, yy in zip(x, y):
        ax.annotate(f"{yy:,.0f}", (xx, yy), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=7)
    ax.set_xscale("log", base=2)
    ax.set_xticks(x, [str(v) for v in x])
    ax.set_xlabel("micro-batch size (speed max, full val)")
    ax.set_ylabel("flows / s")
    ax.set_ylim(0, max(y) * 1.2)
    ax.yaxis.grid(True)
    ax = axes[1]
    ps = [b for b in B if b["speed"] != "max"] + [b for b in bs if b["batch"] == 64]
    labels = [f"{b['speed']}\nbatch {b['batch']}" for b in ps]
    ax.bar(range(len(ps)), [b["flows_per_s"] for b in ps], color=PS.NEUTRAL_LIGHT)
    for i, b in enumerate(ps):
        ax.text(i, b["flows_per_s"], f"{b['flows_per_s']:,.0f}/s\ndropped {b['dropped']}\nbacklog {b['backlog_peak']}",
                ha="center", va="bottom", fontsize=6.5)
    ax.set_xticks(range(len(ps)), labels, fontsize=7.5)
    ax.set_ylim(0, max(b["flows_per_s"] for b in ps) * 1.45)
    ax.set_ylabel("flows / s processed")
    ax.yaxis.grid(True)
    ax.set_title("paced replay (offered rate = replay rate) vs max", loc="left", fontsize=8.5)
    axes[0].set_title("throughput vs batch size", loc="left", fontsize=8.5)
    fig.tight_layout()
    out.append(PS.save(fig, run.fig / "throughput.png"))
    fig, ax = plt.subplots(figsize=(7.0, 3.0))
    for j, b in enumerate(B):
        r = np.array([(t, m) for t, m, _, _ in b["rss"]], float)
        if len(r):
            ax.plot(r[:, 0] - r[0, 0], r[:, 1], color=PS.CATEGORICAL[j % len(PS.CATEGORICAL)], lw=1.2,
                    label=f"{b['tag']} (peak {b['peak_rss_mb']:.0f} MB)")
    ax.set_xlabel("wall seconds since run start")
    ax.set_ylabel("RSS (MB)")
    ax.yaxis.grid(True)
    ax.legend(frameon=False, fontsize=6.5, loc="center left", bbox_to_anchor=(1.0, 0.5))
    ax.set_title("Resident memory over time per benchmark run (process RSS; peak = process high-water mark)",
                 loc="left", fontsize=8.5)
    out.append(PS.save(fig, run.fig / "rss_over_time.png"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--run28-tag", default=None, help="results subfolder of the step 28 re-run (CICFlowMeter speed)")
    args = ap.parse_args()
    cfg = C.load_phase3_config()
    run = R3.Run("30", SCRIPT, cfg, args.dry_run, args.run_id)
    M = run.base_manifest()
    R3.lock_banner(run, M, "start")
    ok = False
    try:
        M["machine"] = machine()
        run.log(f"  machine: {M['machine']}")
        secret, _ = AL.ensure_runtime_keys(C.expand(cfg["paths"]["runtime_keys_dir"]), REPO_ROOT)
        bm = cfg["benchmark"]
        batches = [1, 64] if args.dry_run else bm["batch_sizes"]
        B = [bench_run(cfg, run, f"max_b{b}", b, "max", args.dry_run, secret) for b in batches]
        probe = FS.CsvReplaySource(cfg, sample=args.dry_run)
        minutes = 1.0 if args.dry_run else cfg["source"]["slice_minutes"]
        sl = probe.busiest_window(minutes)
        M["slice"] = {"minutes": minutes, "event_window": sl, "rule": "the window with the most flows by emission time"}
        del probe
        for sp in [s for s in bm["speeds"] if s != "max"]:
            B.append(bench_run(cfg, run, f"{sp}_b64", 64, sp, args.dry_run, secret, event_slice=sl))
        M["runs"] = [{k: v for k, v in b.items() if k != "rss"} for b in B]
        M["packets"] = packet_bench(cfg, args.dry_run)
        run.log(f"  packet path: {M['packets']['packets']:,} packets, reader {M['packets']['reader_pps']:,.0f} pps, "
                f"reader + guards {M['packets']['reader_plus_guards_pps']:,.0f} pps")
        try:
            up = R3.resolve("28", rerun_tag=args.run28_tag)
            pc = up["manifest"].get("pcap_path") or {}
            M["cicflowmeter"] = {"frames": pc.get("slice", {}).get("frames_written"), "wall_s": pc.get("cfm", {}).get("wall_s"),
                                 "frames_per_s_incl_jvm": pc.get("frames_per_s_incl_jvm"), "flows": pc.get("csv_rows"),
                                 "source": f"step 28 run {up['meta']['run_id']} pcap path"}
        except R3.RunRefused as e:
            M["cicflowmeter"] = {"note": f"not available: {e}"}
        M["figures"] = [str(Path(f).relative_to(run.res)) for f in figures(run, B)]
        R3.write_json(run.res / "benchmark.json", {k: M[k] for k in ("machine", "slice", "runs", "packets", "cicflowmeter")})
        R3.lock_banner(run, M, "end")
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def write_summary(run, M: dict, dry: bool) -> None:
    L = [f"# Step 30 -- runtime benchmark (dev machine, report-only) -- {'FAIL' if M.get('error') else 'PASS'}"
         + (" (DRY RUN)" if dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    m = M.get("machine")
    if m:
        L += [f"- machine: {m['cpu_model']}, {m['logical_cpus']} logical CPUs, {m['ram_gb']} GB RAM, {m['os']}; Python "
              f"{m['python']}, XGBoost {m['xgboost']}, numpy {m['numpy']} ({m['note']})",
              "- GLOBAL (promoted model), boosters single-threaded, flow path only (packet path benchmarked separately); "
              "batch-stage latencies are per batch and amortised per flow", ""]
    if M.get("runs"):
        L += ["## Throughput", "", "| run | batch | speed | flows | wall s | flows / s | dropped | backlog peak | e2e p50 / p95 / "
              "p99 ms | queue wait p95 ms | peak RSS MB |", "|---|---|---|---|---|---|---|---|---|---|---|"]
        for b in M["runs"]:
            e = b["e2e_ms"]
            L.append(f"| {b['tag']} | {b['batch']} | {b['speed']} | {b['flows']:,} / {b['offered']:,} | {b['wall_s']:.1f} | "
                     f"{b['flows_per_s']:,.0f} | {b['dropped']} | {b['backlog_peak']:,} | {e['p50']:.2f} / {e['p95']:.2f} / "
                     f"{e['p99']:.2f} | {b['queue_wait_ms']['p95']:.2f} | {b['peak_rss_mb']:.0f} |")
        L += ["", "## Per-stage latency (microseconds per flow; p50 / p95 / p99)", "",
              "| run | " + " | ".join(STAGES) + " |", "|---|" + "---|" * len(STAGES)]
        for b in M["runs"]:
            L.append(f"| {b['tag']} | " + " | ".join(
                f"{b['lat_us_per_flow'][s]['p50']:.1f} / {b['lat_us_per_flow'][s]['p95']:.1f} / {b['lat_us_per_flow'][s]['p99']:.1f}"
                if b["lat_us_per_flow"][s]["n"] else "-" for s in STAGES) + " |")
        L += ["", "Per batch (microseconds; p50 / p95 / p99): " + "; ".join(
            f"{b['tag']}: predict {b['lat_us_per_batch']['predict']['p50']:.0f}/{b['lat_us_per_batch']['predict']['p95']:.0f}/"
            f"{b['lat_us_per_batch']['predict']['p99']:.0f}, SHAP (batches with alerts) "
            f"{b['shap_us_per_batch_with_alerts']['p50'] or 0:.0f}/{b['shap_us_per_batch_with_alerts']['p95'] or 0:.0f}"
            for b in M["runs"])]
        s = M["slice"]
        L += ["", f"- paced runs replay the busiest {s['minutes']:g}-minute val slice (event window {s['event_window'][0]:.0f}"
              f" .. {s['event_window'][1]:.0f}); at 1x the offered rate is the capture's own flow rate (val is a capped "
              "sample, so this is a lower bound of the real rate)"]
    p = M.get("packets")
    if p:
        L += ["", "## Packet path", "", f"- {p['packets']:,} val packets: reader {p['reader_pps']:,.0f} packets/s; reader + "
              f"rate guard v2 + V1 rule {p['reader_plus_guards_pps']:,.0f} packets/s ({p['note']})"]
    c = M.get("cicflowmeter")
    if c and c.get("frames"):
        L += [f"- CICFlowMeter (locked jar, offline mode): {c['frames']:,} frames -> {c['flows']:,} flows in {c['wall_s']:.1f} s "
              f"wall = {c['frames_per_s_incl_jvm']:,.0f} frames/s incl. JVM start ({c['source']})"]
    if M.get("figures"):
        L += ["", "## Figures", ""] + [f"- `{f}`" for f in M["figures"]]
    L += ["", "Dev-machine numbers only; Pi budgets are set when the hardware arrives (docs/V2_PREREG_PHASE3.md section 7)."]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
