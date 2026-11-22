#!/usr/bin/env python
"""27_fit_rate_guard.py -- Phase 3 step D: fit the rate guard v2 thresholds on TRAIN BENIGN packets only
(docs/V2_PREREG_PHASE3.md section 6).

Packets: the train window of every train / time_split capture (common/packet_source.session_packets, split "train":
08's cut rule on packet time, reading stops at the end of train; test sessions refused; capture sha256 checked).
Train benign = packets with no attacker / testbed-Pi MAC as eth.src or eth.dst (V1 step 13's exclusion, its MacBook
imported read-only). Counted: per capture one RateGuardV2 in record mode (1 s windows; packets INTO each protected
device, per protocol family; no window spans two captures).
Rule: threshold[group][family] = multiplier x max packets in a 1 s window into one device of that group; a (group,
family) with < min_train_windows non-empty windows takes the fallback group's threshold for that family, else the
threshold pooled over all groups. Every group label x family gets a value. Check: zero train-benign windows above
their threshold (by construction).
Outputs: <rate_guard.fit_dir>/thresholds.json + manifest.json (rule, input hashes, per group x family max / threshold /
n windows / source; thresholds_sha256 -- the runtime refuses a thresholds file that does not match); results/phase3/27/
summary.md, run_manifest.json, run_meta.json, run.log, figures/train_benign_rates.png. --dry-run: Recon-PortScan
only, <fit_dir>_dry_run/<run_id>/, results/phase3/27/dry_run/<run_id>/.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import shutil
import sys
import traceback
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from config.config import DEVICE_TABLE, REPO_ROOT
from common import packet_source as PK
from common import phase3_config as C
from common import phase3_run as R3
from common import plot_style as PS
from common.rate_guard_v2 import RateGuardV2
from common.routing import Router

SCRIPT = "27_fit_rate_guard.py"
DRY_SESSIONS = ["Recon-PortScan"]


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fit_thresholds(stats: dict, labels: list, families: list, fallback: str, mult: float, min_w: int) -> tuple[dict, dict]:
    """stats[(group, family)] = {"max", "n"} -> (thresholds {g: {f: int}}, source {g: {f: str}}). Pure (tested via 29)."""
    T, src = {}, {}
    pooled = {f: max([v["max"] for (g, ff), v in stats.items() if ff == f] or [0]) for f in families}
    for g in labels:
        T[g], src[g] = {}, {}
        for f in families:
            s = stats.get((g, f))
            fb = stats.get((fallback, f))
            if s and s["n"] >= min_w:
                T[g][f], src[g][f] = int(math.ceil(mult * s["max"])), "own"
            elif fb and fb["n"] >= min_w:
                T[g][f], src[g][f] = int(math.ceil(mult * fb["max"])), f"fallback:{fallback}"
            else:
                T[g][f], src[g][f] = int(math.ceil(mult * pooled[f])), "pooled"
    return T, src


def figure(path: Path, hist: dict, stats: dict, T: dict, src: dict, labels: list, families: list, w: float) -> None:
    import matplotlib.pyplot as plt
    PS.apply()
    fig, axes = plt.subplots(len(labels), len(families), figsize=(3.2 * len(families), 1.9 * len(labels)), squeeze=False)
    for i, g in enumerate(labels):
        for j, f in enumerate(families):
            ax = axes[i][j]
            h = hist.get((g, f), Counter())
            if h:
                vals = np.array(sorted(h))
                cnt = np.array([h[v] for v in vals])
                bins = np.unique(np.round(np.logspace(0, math.log10(max(vals.max(), T[g][f]) * 1.2), 30)))
                ax.hist(vals, bins=bins, weights=cnt, color=PS.NEUTRAL_LIGHT, edgecolor=PS.TEXT2, linewidth=0.3)
                ax.set_yscale("log")
                ax.axvline(stats[(g, f)]["max"], color=PS.TEXT2, lw=1, ls=":")
            else:
                ax.text(0.5, 0.5, "no train-benign packets", transform=ax.transAxes, ha="center", va="center",
                        color=PS.TEXT2, fontsize=8)
            ax.axvline(T[g][f], color=PS.CATEGORICAL[1], lw=1.4)
            ax.set_xscale("log")
            n = stats.get((g, f), {}).get("n", 0)
            ax.set_title(f"{g} / {f}  (n={n:,} windows)", loc="left", fontsize=8)
            ax.text(0.98, 0.95, f"threshold {T[g][f]:,}\n({src[g][f]})", transform=ax.transAxes, ha="right", va="top",
                    fontsize=7, color=PS.CATEGORICAL[1], bbox={"facecolor": PS.SURFACE, "edgecolor": "none", "pad": 1})
            if i == len(labels) - 1:
                ax.set_xlabel(f"packets per {w:g} s window into one device (log)", fontsize=8)
            if j == 0:
                ax.set_ylabel("windows (log)", fontsize=8)
    fig.suptitle("Rate guard v2: train-benign 1 s rates per group x protocol family (dotted = max, solid = threshold "
                 "= 2 x max)", x=0.01, ha="left", y=1.0, fontsize=9)
    fig.tight_layout()
    PS.save(fig, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()
    cfg = C.load_phase3_config()
    run = R3.Run("27", SCRIPT, cfg, args.dry_run, args.run_id)
    M = run.base_manifest(["07a_attack_coverage.py", "13_rate_guard_calibrate.py", "config/device_table.csv",
                           "config/behaviour_groups.json"])
    R3.lock_banner(run, M, "start")
    rg = cfg["rate_guard"]
    fit = C.expand(rg["fit_dir"])
    out = (fit.with_name(fit.name + "_dry_run") / run.run_id) if args.dry_run else fit
    partial = out.with_name("." + out.name + ".partial")
    ok = False
    try:
        if out.exists() or partial.exists():
            raise R3.RunRefused(f"{out} (or its .partial) exists: thresholds are never overwritten")
        partial.mkdir(parents=True)
        MIN_W[0] = rg["min_train_windows"]
        m13 = _load("rate_guard_calibrate", "13_rate_guard_calibrate.py")
        book = m13.MacBook(m13.m07a.Devices(DEVICE_TABLE))
        router = Router(cfg)
        labels = router.groups()
        families = list(rg["families"]) + [rg["other_family"]]
        sessions = DRY_SESSIONS if args.dry_run else PK.sessions_with(cfg, "train")
        big = {g: {f: 10 ** 15 for f in families} for g in labels}
        stats: dict = {}
        hist: dict = defaultdict(Counter)
        argmax: dict = {}
        excl, per = Counter(), {}
        for s in sessions:
            c = Counter()
            g = RateGuardV2(router, big, rg["families"], rg["other_family"], rg["window_s"], rg["consecutive"],
                            record=True, fallback_group=router.fallback)
            run.log(f"== {s}: {PK.session_plan(cfg, s, 'train')['pcap']}")
            for ts, si, di, pr, sm, dm in PK.session_packets(cfg, s, "train", c):
                es, ed = book.get(sm)[0], book.get(dm)[0]
                if es or ed:
                    excl[f"eth.src {es}" if es else f"eth.dst {ed}"] += 1
                    c["excluded"] += 1
                    continue
                g.update(ts, si, di, pr, sm, dm)
                if len(g.records) > 200_000:
                    for r in g.records:
                        _acc(r, stats, hist, argmax, s)
                    g.records = []
            g.flush()
            for r in g.records:
                _acc(r, stats, hist, argmax, s)
            per[s] = {"reader": dict(c), "guard": dict(g.stats), "pcap_sha256": PK.session_plan(cfg, s, "train")["sha256"]}
            run.log(f"   kept {c['kept']:,} train packets, excluded {c['excluded']:,}, counted {g.stats['counted']:,}, "
                    f"windows {g.stats['windows_closed']:,}")
        T, src = fit_thresholds(stats, labels, families, router.fallback, rg["multiplier"], rg["min_train_windows"])
        small = {k: v for k, v in SMALL.items() if v is not None}
        over_own = sum(n for (gg, f), h in hist.items() for v, n in h.items() if v > T[gg][f] and src[gg][f] == "own")
        run.check(M, "zero train-benign windows above an own-data threshold (by construction)", over_own == 0,
                  f"{over_own} windows over")
        fb_over = {f"{gg}|{f}": {"windows_over": sum(n for v, n in h.items() if v > T[gg][f]),
                                 "alerts": _streak_alerts(small.get((gg, f), []), T[gg][f], rg["consecutive"], rg["window_s"])}
                   for (gg, f), h in hist.items() if src[gg][f] != "own"}
        n_fb = sum(v["windows_over"] for v in fb_over.values())
        run.check(M, "train-benign windows above a fallback / pooled threshold (groups with < min windows; report-only)",
                  n_fb == 0, json.dumps(fb_over), warn=True)
        M["fallback_train_benign_over"] = fb_over
        run.check(M, "every group label x family has a threshold", all(f in T[gg] for gg in labels for f in families),
                  f"{len(labels)} groups x {len(families)} families")
        for gg in labels:
            run.log("  " + gg + ": " + ", ".join(f"{f} {T[gg][f]} ({src[gg][f]})" for f in families))
        thr = {"version": 1, "rule": {"window_s": rg["window_s"], "multiplier": rg["multiplier"],
                                      "consecutive": rg["consecutive"], "families": rg["families"],
                                      "other_family": rg["other_family"], "min_train_windows": rg["min_train_windows"],
                                      "statement": "threshold[group][family] = multiplier x max packets in one window into "
                                                   "one device of the group, train benign (no attacker / testbed-Pi MAC "
                                                   "on either side); alert iff count > threshold for `consecutive` "
                                                   "windows in a row", "fallback_group": router.fallback},
               "thresholds": T, "source": src, "dry_run": args.dry_run}
        tp = partial / "thresholds.json"
        tsha = R3.write_json(tp, thr)
        stat_rows = {f"{gg}|{f}": {**stats.get((gg, f), {"max": 0, "n": 0}), "threshold": T[gg][f], "source": src[gg][f],
                                   "max_at": argmax.get((gg, f))} for gg in labels for f in families}
        man = {"status": "PASS" if all(c["pass"] for c in M["checks"] if c["level"] == "hard") else "FAIL",
               "run_id": run.run_id, "fallback_train_benign_over": fb_over,
               "thresholds_sha256": tsha, "rule": thr["rule"], "sessions": per, "exclusion": dict(excl),
               "per_group_family": stat_rows, "inputs_sha256": {
                   "split_definition": PK.split_definition(cfg)["sha256"],
                   "config/device_table.csv": R3.sha256_path(DEVICE_TABLE),
                   "config/behaviour_groups.json": R3.sha256_path(REPO_ROOT / cfg["routing"]["groups"]),
                   "config/v2_phase3.json": cfg["_sha256"]}, "dry_run": args.dry_run}
        R3.write_json(partial / "manifest.json", man)
        partial.rename(out)
        M.update({"fit_dir": str(out), "thresholds_sha256": tsha, "thresholds": T, "source": src, "sessions": per,
                  "exclusion": dict(excl), "per_group_family": stat_rows})
        shutil.copyfile(out / "manifest.json", run.res / "fit_manifest.json")
        shutil.copyfile(out / "thresholds.json", run.res / "thresholds.json")
        f = run.fig / "train_benign_rates.png"
        figure(f, hist, stats, T, src, labels, families, rg["window_s"])
        M["figures"] = [str(f.relative_to(run.res))]
        R3.lock_banner(run, M, "end")
        ok = man["status"] == "PASS"
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def _streak_alerts(recs: list, thr: int, k: int, w: float) -> int:
    """Alerts the rule would raise on these (device, window_start, count) records (streaks of consecutive windows)."""
    by = defaultdict(list)
    for dev, start, n in recs:
        by[dev].append((start, n))
    alerts = 0
    for v in by.values():
        run, prev = 0, None
        for start, n in sorted(v):
            run = (run + 1 if prev is not None and abs(start - prev - w) < 1e-9 else 1) if n > thr else 0
            prev = start
            alerts += run >= k
    return alerts


SMALL: dict = {}
MIN_W = [0]


def _acc(r, stats, hist, argmax, session) -> None:
    start, dev, grp, fam, n = r
    k = (grp, fam)
    s = stats.setdefault(k, {"max": 0, "n": 0})
    s["n"] += 1
    hist[k][n] += 1
    if SMALL.get(k, []) is not None:                                 # keep records only while the key is small
        SMALL.setdefault(k, []).append((dev, start, n))
        if s["n"] >= MIN_W[0]:
            SMALL[k] = None
    if n > s["max"]:
        s["max"] = n
        argmax[k] = {"count": n, "window_start": start, "device": dev, "session": session}


def write_summary(run, M: dict, dry: bool) -> None:
    L = [f"# Step 27 -- rate guard v2 thresholds (train benign) -- {M['status'] if M.get('status') != 'RUNNING' else ('PASS' if not M.get('error') else 'FAIL')}"
         + (" (DRY RUN)" if dry else ""), "",
         f"- run `{run.run_id}`; rule: threshold = {run.cfg['rate_guard']['multiplier']} x max train-benign packets per "
         f"{run.cfg['rate_guard']['window_s']:g} s window into one device of the group, per protocol family; alert after "
         f"{run.cfg['rate_guard']['consecutive']} consecutive windows above it; < {run.cfg['rate_guard']['min_train_windows']} "
         f"non-empty windows -> fallback group, else pooled", "- packets: train windows of the train / time_split captures "
         "only (reading stops at the end of train); attacker / testbed-Pi MAC packets excluded (V1 step 13's rule)", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("per_group_family"):
        L += [f"- thresholds file `{M['fit_dir']}/thresholds.json`, sha256 `{M['thresholds_sha256']}`", "",
              "## Per group x family", "", "| group | family | non-empty windows | max | threshold | source | max at |",
              "|---|---|---|---|---|---|---|"]
        for k, v in M["per_group_family"].items():
            g, f = k.split("|")
            at = v.get("max_at") or {}
            L.append(f"| {g} | {f} | {v['n']:,} | {v['max']:,} | {v['threshold']:,} | {v['source']} | "
                     f"{at.get('session', '-')} {at.get('device', '')} |")
        L += ["", "## Captures", "", "| session | train packets kept | excluded (attacker / Pi) | counted (protected dst) |",
              "|---|---|---|---|"]
        for s, v in M["sessions"].items():
            L.append(f"| {s} | {v['reader'].get('kept', 0):,} | {v['reader'].get('excluded', 0):,} | "
                     f"{v['guard'].get('counted', 0):,} |")
        L += ["", "## Figures", "", "- `figures/train_benign_rates.png` -- per group x family, the train-benign 1 s rate "
              "distribution (log x, log y) with the max (dotted) and the threshold (solid)."]
    L += ["", "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
