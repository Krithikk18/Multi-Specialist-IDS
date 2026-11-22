#!/usr/bin/env python
"""38_zeroday_eval.py -- Phase 5A steps D-F (docs/V2_PREREG_PHASE5.md sections 5-6): zero-day evaluation, the
Amendment 2 section 3 verdict, the section 5 kill-rule line, figures and the phase summary.
OFFLINE: val only (+ the step 36 / 37 outputs); never test; nothing registered; the runtime is not touched.

Unit = (held-out class k, seed s): both arms use their seed-s models of normal (step 37) and the miss set of LOAO(k, s)
(step 36). Primary: miss-recall per arm, d = PER_GROUP - GLOBAL, eligibility (n_miss >= min_misses), 95 % percentile
bootstrap over pairs; FA / h on val benign (Phases 3-4 benign hours), PER_GROUP - GLOBAL over seeds, bootstrap CI;
verdict under the prereg reading and the Amendment 2 literal reading (CONFLICT if they differ); the kill-rule line.
Report-only: detector alone on all k flows, combined system (Stage 1 alert OR flag) recall + FA, RANDOM_GROUP vs
GLOBAL, val-benign flag rates per arm / group (drift), per-group miss-recall, scoring cost and model sizes.
Outputs: <cache>/eval/<run>/ (val scores per arm x seed, .npy), results/phase5a/38/ (eval.json, summary.md, figures/,
run_manifest.json, run_meta.json, run.log); full runs also write results/phase5a/summary.md + results/phase5a/figures/
(refused if they exist). --dry-run: needs --loao-run and --normal-run dry run ids.
--replot TAG: re-draw the figures + phase summary from results/phase5a/38/eval.json into results/phase5a/TAG/.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import traceback
from pathlib import Path

import numpy as np

from config.config import REPO_ROOT
from common import normal_model as NM
from common import phase2_data as D
from common import schemas as S
from common import zeroday_config as ZC
from common import zeroday_metrics as ZM
from common import zeroday_run as ZR
from common.phase2_config import load_phase2_config

SCRIPT = "38_zeroday_eval.py"
ARMS = (NM.GLOBAL, NM.PER_GROUP, NM.RANDOM_GROUP)
SHORT = {NM.GLOBAL: "GLOBAL", NM.PER_GROUP: "PER_GROUP", NM.RANDOM_GROUP: "RANDOM_GROUP"}


# =========================================================================== core (arrays in, JSON-able dict out)
def _f(x):
    return float(x) if x is not None and np.isfinite(x) else None


def core(yva, gva, sess, ts, Zva, loao_pairs: list[dict], preds: dict, fits: dict, names: list[str], cfg5: dict,
         nonrare: list[int], rare: list[int], seeds: list[int], hours: float, log=print, train_scores: dict | None = None,
         train_groups=None) -> tuple[dict, dict]:
    """(E, scores): E = every number of the evaluation (JSON-able); scores = {(arm, s): val anomaly scores}."""
    p, ev = cfg5["normal_model"], cfg5["eval"]
    yva, gva = np.asarray(yva, np.int64), np.asarray(gva).astype(str)
    benign = yva == 0
    groups = sorted(set(gva.tolist()))
    SC, FL, TH, cost = {}, {}, {}, {a: {"batch_us_per_flow": {}, "unseen_groups": {}} for a in ARMS}
    for s in seeds:
        for a in ARMS:
            t0 = time.perf_counter()
            sc, thr, key, unseen = NM.score_arm(fits[(a, s)], Zva, gva, p)
            dt = time.perf_counter() - t0
            SC[(a, s)], TH[(a, s)], FL[(a, s)] = sc, thr, NM.flags(sc, thr)
            cost[a]["batch_us_per_flow"][str(s)] = 1e6 * dt / max(1, len(Zva))
            cost[a]["unseen_groups"][str(s)] = unseen
            log(f"  scored val {a:<20} s{s}: {len(Zva):,} flows in {dt:.1f} s ({cost[a]['batch_us_per_flow'][str(s)]:.1f} us/flow)"
                f"; val benign flagged {int((FL[(a, s)] & benign).sum())} / {int(benign.sum()):,}"
                + (f"; unseen groups -> global {unseen}" if unseen else ""))
    # ---- single-flow cost (first seed; the first n val rows, one call each)
    nc = min(int(ev["single_flow_timing_calls"]), len(Zva))
    for a in ARMS:
        A = fits[(a, seeds[0])]
        t = []
        for i in range(nc):
            t0 = time.perf_counter()
            NM.score_arm(A, Zva[i:i + 1], gva[i:i + 1], p)
            t.append(time.perf_counter() - t0)
        cost[a]["single_flow_us_median"] = float(1e6 * np.median(t)) if t else None
        cost[a]["single_flow_calls"] = nc
        cost[a]["n_jobs"] = p["n_jobs"]
    # ---- false alarms (detector alone on val benign) + drift per group
    fa, fa_h, drift = {}, {}, {}
    for a in ARMS:
        fa[a], fa_h[a], drift[a] = {}, {}, {}
        for s in seeds:
            r = ZM.fa_rate(FL[(a, s)], benign, hours)
            fa[a][str(s)] = r
            fa_h[a][s] = r["fa_per_hour"]
            drift[a][str(s)] = {g: {"flagged": int((FL[(a, s)] & benign & (gva == g)).sum()),
                                    "n_benign": int((benign & (gva == g)).sum()),
                                    "flag_rate": _f((FL[(a, s)] & benign & (gva == g)).sum() / max(1, (benign & (gva == g)).sum()))
                                    if (benign & (gva == g)).any() else None} for g in groups}
    # ---- pairs
    pairs, vpairs = [], []
    for lp in loao_pairs:
        k, s = int(lp["k"]), int(lp["s"])
        pred = np.asarray(preds[(k, s)])
        miss = (yva == k) & (pred == 0)
        isk = yva == k
        st1_alert = pred != 0
        rec = {"k": k, "class": names[k], "s": s, "rare": k in rare, "n_val": int(isk.sum()), "n_miss": int(miss.sum()),
               "n_caught": int((isk & st1_alert).sum()), "eligible": bool(k in nonrare and miss.sum() >= ev["min_misses"]),
               "recall": {}, "flagged": {}, "detector_alone": {}, "combined": {}, "combined_fa": {}, "per_group": {},
               "predicted_as": {names[c]: int(n) for c, n in enumerate(np.bincount(pred[isk], minlength=len(names))) if n}}
        st1_fa = int((benign & st1_alert).sum())
        rec["stage1_fa"] = {"fa_count": st1_fa, "fa_per_hour": st1_fa / hours if hours > 0 else None}
        for a in ARMS:
            f = FL[(a, s)]
            mr = ZM.miss_recall(f, miss)
            rec["recall"][a], rec["flagged"][a] = mr["recall"], mr["flagged"]
            rec["detector_alone"][a] = _f(f[isk].mean()) if isk.any() else None
            comb = st1_alert | f
            rec["combined"][a] = _f(comb[isk].mean()) if isk.any() else None
            c = int((benign & comb).sum())
            rec["combined_fa"][a] = {"fa_count": c, "fa_per_hour": c / hours if hours > 0 else None}
            rec["per_group"][a] = {g: {"n_miss": int((miss & (gva == g)).sum()),
                                       "recall": _f((f & miss & (gva == g)).sum() / (miss & (gva == g)).sum())}
                                   for g in groups if (miss & (gva == g)).any()}
        pairs.append(rec)
        vpairs.append({"k": k, "s": s, "n_miss": rec["n_miss"], "recall": dict(rec["recall"])})
    V = ZM.verdict(vpairs, fa_h, ev, nonrare, nonrare + rare, ZM.A_GLOBAL, ZM.A_PER_GROUP)
    RC = ZM.verdict(vpairs, fa_h, ev, nonrare, nonrare + rare, ZM.A_GLOBAL, ZM.A_RANDOM)
    s4 = cfg5["pinned_facts"]["amendment2_s4_phase4"]
    kill = ZM.kill_line(V["verdict"], s4)
    # ---- histograms for the score-distribution figure (first seed, verdict arms)
    hist = None
    if train_scores is not None and train_groups is not None:
        tg = np.asarray(train_groups).astype(str)
        s0 = seeds[0]
        allv = np.concatenate([SC[(a, s0)] for a in (NM.GLOBAL, NM.PER_GROUP)] +
                              [train_scores[(a, s0)] for a in (NM.GLOBAL, NM.PER_GROUP)])
        allv = allv[np.isfinite(allv) & (allv > 0)]
        edges = np.geomspace(allv.min() * 0.98, allv.max() * 1.02, int(ev["score_hist_bins"]) + 1)
        hist = {"edges": edges.tolist(), "seed": s0, "arms": {}}
        for a in (NM.GLOBAL, NM.PER_GROUP):
            hist["arms"][a] = {}
            for g in groups:
                vb = SC[(a, s0)][benign & (gva == g)]
                tb = train_scores[(a, s0)][tg == g]
                thr = TH[(a, s0)][gva == g]
                H = {"train_benign": np.histogram(tb, edges)[0].tolist(), "n_train_benign": int(len(tb)),
                     "val_benign": np.histogram(vb, edges)[0].tolist(), "n_val_benign": int(len(vb)),
                     "threshold": _f(thr[0]) if len(thr) else None, "misses": {}}
                for k in nonrare:
                    pr = np.asarray(preds[(k, s0)])
                    mm = (yva == k) & (pr == 0) & (gva == g)
                    if mm.any():
                        H["misses"][names[k]] = {"counts": np.histogram(SC[(a, s0)][mm], edges)[0].tolist(), "n": int(mm.sum())}
                hist["arms"][a][g] = H
    E = {"seeds": seeds, "groups": groups, "names": names, "nonrare": nonrare, "rare": rare, "benign_hours": hours,
         "n_val": int(len(yva)), "n_val_benign": int(benign.sum()), "pairs": pairs, "fa": fa, "drift": drift,
         "verdict": V, "random_control": RC, "s4_phase4": s4, "kill_line": kill,
         "eligibility": ZM.eligibility_table(vpairs, nonrare + rare, ev["min_misses"]), "cost": cost, "hist": hist,
         "nominal_flag_rate": 1.0 - float(p["threshold_quantile"]), "eval_params": ev}
    return E, SC


# =========================================================================== IO: load step 36 / 37 outputs
def load_loao(up36: dict, n_val: int) -> tuple[dict, dict]:
    M = up36["manifest"]
    d = Path(M["dir"])
    preds = {}
    for p in M["pairs"]:
        f = d / p["pred_file"]
        if ZR.sha256_path(f) != p["pred_sha256"]:
            raise RuntimeError(f"{f}: sha256 != step 36 manifest")
        a = np.load(f)
        if len(a) != n_val:
            raise RuntimeError(f"{f}: {len(a)} rows != val {n_val}")
        preds[(int(p["k"]), int(p["s"]))] = a.astype(np.int64)
    return M, preds


def load_fits(up37: dict) -> tuple[dict, dict, np.ndarray, dict]:
    import joblib
    man_p = Path(up37["manifest"]["models_dir"]) / "manifest.json"
    if ZR.sha256_path(man_p) != up37["manifest"]["models_manifest_sha256"]:
        raise RuntimeError(f"{man_p}: sha256 != step 37 run manifest")
    man = json.loads(man_p.read_text(encoding="utf-8"))
    d = Path(man["dir"])
    sha = man["files_sha256"]

    def load(fn):
        if ZR.sha256_path(d / fn) != sha[fn]:
            raise RuntimeError(f"{d / fn}: sha256 != step 37 manifest")
        return joblib.load(d / fn) if fn.endswith(".joblib") else np.load(d / fn)

    recs = {(r["arm"], int(r["seed"])): r for r in man["records"]}
    glob = {}
    for (a, s), r in recs.items():
        if a == NM.GLOBAL:
            k = NM.GLOBAL_KEY
            glob[s] = {"model": load(r["files"][k]["file"]), "threshold": r["models"][k]["threshold"],
                       "n_train": r["models"][k]["n_train"]}
    fits, tscores = {}, {}
    for (a, s), r in recs.items():
        models = {}
        for k, m in r["models"].items():
            models[k] = glob[s] if k == NM.GLOBAL_KEY else {"model": load(r["files"][k]["file"]), "threshold": m["threshold"],
                                                            "n_train": m["n_train"]}
        fits[(a, s)] = {"arm": a, "seed": s, "models": models, "route": r["route"], "global_rec": glob[s],
                        "fallback": r["fallback"]}
        tscores[(a, s)] = load(r["train_scores_file"])
    return fits, tscores, load("train_groups.npy").astype(str), man


# =========================================================================== figures
def _pal():
    from common import plot_style as PS
    return {NM.GLOBAL: PS.CATEGORICAL[0], NM.PER_GROUP: PS.CATEGORICAL[1], NM.RANDOM_GROUP: PS.NEUTRAL_LIGHT}


def fig_pipeline(path: Path, E: dict) -> None:
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    from common import plot_style as PS
    fig, ax = plt.subplots(figsize=(10.5, 4.6))
    ax.set_xlim(0, 10.5)
    ax.set_ylim(0, 4.6)
    ax.axis("off")

    def box(x, y, w, h, title, body, fc):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.04,rounding_size=0.08", fc=fc, ec=PS.TEXT2, lw=0.8))
        ax.text(x + w / 2, y + h - 0.2, title, ha="center", va="top", fontsize=9, weight="bold")
        ax.text(x + w / 2, y + h - 0.5, body, ha="center", va="top", fontsize=7.6, color=PS.TEXT2, linespacing=1.35)

    def arrow(x0, y0, x1, y1, label=None, dy=0.13):
        ax.annotate("", (x1, y1), (x0, y0), arrowprops=dict(arrowstyle="-|>", color=PS.TEXT2, lw=0.9))
        if label:
            ax.text((x0 + x1) / 2, (y0 + y1) / 2 + dy, label, ha="center", va="bottom", fontsize=7.2, color=PS.TEXT2)

    box(0.1, 2.75, 2.5, 1.7, "train (all classes)", "minus held-out class k\n(every row of k removed;\nlabels remapped 0..K-2)",
        "#eef3fb")
    box(3.3, 2.75, 2.6, 1.7, "LOAO Stage 1", "XGBoost GLOBAL, weights none\nearly stop on 10 % inner split\n"
        f"seeds {E['seeds'][0]}..{E['seeds'][-1]} (fitted on train)", "#eef3fb")
    box(6.6, 2.75, 3.8, 1.7, "val flows of class k", "argmax != benign -> caught by Stage 1\n"
        "argmax == benign -> Stage 1 MISS\n(miss set depends on k and seed)", "#eef3fb")
    box(0.1, 0.15, 2.5, 1.9, "train benign only", "sign(x) log1p|x| on the\n70 pinned features\n(no attack row, no val row)",
        "#fdf0ea")
    box(3.3, 0.15, 2.6, 1.9, "model of normal", "GLOBAL_NORMAL: 1 IF (all benign)\nPER_GROUP_NORMAL: 1 IF / group\n"
        "threshold = 99.9th pct of\nits own train-benign scores", "#fdf0ea")
    box(6.6, 0.15, 3.8, 1.9, "flag + miss-recall", "flag iff score > threshold\nmiss-recall = flagged misses / misses\n"
        "d = PER_GROUP - GLOBAL, bootstrap CI\nFA/h on val benign (both arms)", "#f3f3f1")
    arrow(2.6, 3.6, 3.3, 3.6, "fit")
    arrow(5.9, 3.6, 6.6, 3.6, "predict")
    arrow(2.6, 1.1, 3.3, 1.1, "fit")
    arrow(5.9, 1.1, 6.6, 1.1, "score")
    arrow(8.5, 2.75, 8.5, 2.05, None)
    ax.text(8.6, 2.4, "misses", ha="left", va="center", fontsize=7.2, color=PS.TEXT2)
    PS.save(fig, path)


def fig_where(path: Path, E: dict) -> None:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    names = E["names"]
    ks = E["nonrare"] + E["rare"]
    fig, ax = plt.subplots(figsize=(1.9 + 1.5 * len(ks), 3.6))
    for xi, k in enumerate(ks):
        P = [p for p in E["pairs"] if p["k"] == k]
        shares = np.zeros(len(names))
        for p in P:
            shares += np.array([p["predicted_as"].get(n, 0) for n in names], float) / max(1, p["n_val"])
        shares /= max(1, len(P))
        bottom = 0.0
        for c in range(len(names)):
            if shares[c] <= 0:
                continue
            ax.bar(xi, shares[c], 0.6, bottom=bottom, color=PS.class_color(c), edgecolor=PS.SURFACE, lw=0.6,
                   label=("predicted " + names[c] + (" (Stage 1 miss)" if c == 0 else "")))
            if shares[c] >= 0.04:
                ax.text(xi, bottom + shares[c] / 2, f"{100 * shares[c]:.1f} %", ha="center", va="center", fontsize=7.5,
                        color="white" if c == 0 else PS.TEXT1)
            bottom += shares[c]
    ax.set_xticks(range(len(ks)))
    ax.set_xticklabels([f"{names[k]}\n(n={E['pairs'][[p['k'] for p in E['pairs']].index(k)]['n_val']:,})"
                        + ("\nrare: report-only" if k in E["rare"] else "") for k in ks], fontsize=8)
    ax.set_ylabel("share of held-out val flows (5-seed mean)")
    ax.set_ylim(0, 1.0)
    ax.set_xlabel("held-out class k (LOAO Stage 1 trained without k)")
    h, lab = ax.get_legend_handles_labels()
    uniq = dict(zip(lab, h))
    ax.legend(uniq.values(), uniq.keys(), loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False)
    PS.save(fig, path)


def fig_recall(path: Path, E: dict) -> None:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    pal, names = _pal(), E["names"]
    ks = E["nonrare"]
    fig, axes = plt.subplots(1, len(ks), figsize=(3.6 * len(ks) + 1.6, 3.7), squeeze=False, sharey=True)
    for ax, k in zip(axes[0], ks):
        P = [p for p in E["pairs"] if p["k"] == k]
        for p in P:
            r = [p["recall"][a] for a in ARMS]
            if not all(x is not None and np.isfinite(x) for x in r[:2]):
                continue
            ls = "-" if p["eligible"] else ":"
            ax.plot([0, 1], r[:2], ls, color=PS.TEXT2, lw=0.8, alpha=0.7, zorder=1)
            for xi, a in enumerate(ARMS):
                if r[xi] is None or not np.isfinite(r[xi]):
                    continue
                ax.scatter(xi, r[xi], s=26, color=pal[a], edgecolor=PS.TEXT2 if a == NM.RANDOM_GROUP else "none",
                           facecolor=pal[a] if p["eligible"] else "none", lw=0.8, zorder=2)
        ax.set_xticks([0, 1, 2])
        ax.set_xticklabels(["GLOBAL", "PER_GROUP", "RANDOM_GROUP\n(control)"], fontsize=8)
        ax.set_xlim(-0.4, 2.4)
        el = sum(p["eligible"] for p in P)
        ax.set_title(f"held out: {names[k]}  ({el}/{len(P)} pairs eligible)", fontsize=9)
        ax.grid(axis="y")
    axes[0][0].set_ylabel("miss-recall (share of Stage 1 misses flagged)")
    axes[0][0].set_ylim(-0.03, 1.03)
    from matplotlib.lines import Line2D
    hl = [Line2D([], [], color=PS.TEXT2, lw=0.8, label="one seed (paired)"),
          Line2D([], [], color=PS.TEXT2, lw=0.8, ls=":", label="ineligible pair (< min misses)")]
    axes[0][-1].legend(handles=hl, loc="upper left", bbox_to_anchor=(1.02, 1.0), frameon=False)
    PS.save(fig, path)


def fig_verdict(path: Path, E: dict) -> None:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    V = E["verdict"]["prereg"]
    RC = E["random_control"]["prereg"]
    pal = _pal()
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 3.6))
    for yi, (T, lab, col) in enumerate(((V, "PER_GROUP - GLOBAL\n(verdict)", pal[NM.PER_GROUP]),
                                        (RC, "RANDOM_GROUP - GLOBAL\n(control)", PS.TEXT2))):
        y = 1 - yi
        if T["ci_d"]["n"]:
            a1.errorbar(T["ci_d"]["mean"], y, xerr=[[T["ci_d"]["mean"] - T["ci_d"]["lo"]], [T["ci_d"]["hi"] - T["ci_d"]["mean"]]],
                        fmt="o", color=col, capsize=4, lw=1.4, ms=6, zorder=3)
            a1.scatter(T["d"], [y - 0.18] * len(T["d"]), s=12, color=col, alpha=0.6, zorder=2)
            a1.text(T["ci_d"]["mean"], y + 0.16, f"{T['ci_d']['mean']:+.3f} [{T['ci_d']['lo']:+.3f}, {T['ci_d']['hi']:+.3f}]",
                    ha="center", va="bottom", fontsize=7.5)
        else:
            a1.text(0, y, "no eligible pair", ha="center", va="center", fontsize=8)
        if T["ci_fa"]["n"]:
            a2.errorbar(T["ci_fa"]["mean"], y, xerr=[[T["ci_fa"]["mean"] - T["ci_fa"]["lo"]], [T["ci_fa"]["hi"] - T["ci_fa"]["mean"]]],
                        fmt="o", color=col, capsize=4, lw=1.4, ms=6, zorder=3)
            a2.scatter(T["fa_diff"], [y - 0.18] * len(T["fa_diff"]), s=12, color=col, alpha=0.6, zorder=2)
            a2.text(T["ci_fa"]["mean"], y + 0.16, f"{T['ci_fa']['mean']:+.2f} [{T['ci_fa']['lo']:+.2f}, {T['ci_fa']['hi']:+.2f}]",
                    ha="center", va="bottom", fontsize=7.5)
    for ax in (a1, a2):
        ax.set_yticks([1, 0])
        ax.set_ylim(-0.6, 1.6)
    a1.set_yticklabels(["PER_GROUP - GLOBAL\n(verdict)", "RANDOM_GROUP - GLOBAL\n(control)"], fontsize=8)
    a2.set_yticklabels([])
    a1.axvline(0, color=PS.TEXT1, lw=0.8, ls="--")
    a2.axvline(E["eval_params"]["fa_margin_per_h"], color=PS.TEXT1, lw=0.8, ls="--")
    a2.axvline(0, color=PS.GRID, lw=0.8)
    a1.set_xlabel("(a) miss-recall difference, mean + 95 % bootstrap CI\n(needs lower bound > 0; dots = eligible pairs)")
    a2.set_xlabel(f"(b) FA/h difference on val benign, mean + 95 % CI\n(needs upper bound <= {E['eval_params']['fa_margin_per_h']}; "
                  "dots = seeds)")
    for ax in (a1, a2):
        lo, hi = ax.get_xlim()
        pad = 0.3 * (hi - lo)
        ax.set_xlim(lo - pad, hi + pad)
        from matplotlib.ticker import MaxNLocator
        ax.xaxis.set_major_locator(MaxNLocator(5))                     # no crowded tick labels
    fig.suptitle(f"Amendment 2 §3 verdict: {E['verdict']['verdict']}", fontsize=10)
    PS.save(fig, path)


def fig_fa(path: Path, E: dict) -> None:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    pal = _pal()
    seeds = E["seeds"]
    w = 0.26
    fig, ax = plt.subplots(figsize=(1.6 + 1.25 * len(seeds), 3.7))
    top = max(E["fa"][a][str(s)]["fa_per_hour"] for a in ARMS for s in seeds)
    for ai, a in enumerate(ARMS):
        xs = np.arange(len(seeds)) + (ai - 1) * w
        v = [E["fa"][a][str(s)]["fa_per_hour"] for s in seeds]
        ax.bar(xs, v, w * 0.95, color=pal[a], label=SHORT[a] + (" (control)" if a == NM.RANDOM_GROUP else ""))
        for x, s, h in zip(xs, seeds, v):
            ax.text(x, h + 0.015 * max(top, 1e-9), f"{E['fa'][a][str(s)]['fa_count']}", ha="center", va="bottom", fontsize=6.8,
                    rotation=90)
    ax.set_xticks(range(len(seeds)))
    ax.set_xticklabels([f"seed {s}" for s in seeds])
    ax.set_ylabel(f"val benign false alarms / h\n(benign hours {E['benign_hours']:.3f}; numbers = flagged flows)")
    ax.set_ylim(0, top * 1.22 if top > 0 else 1)
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False)
    PS.save(fig, path)


def fig_scores(path: Path, E: dict) -> None:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    H = E["hist"]
    if not H:
        return
    edges = np.asarray(H["edges"])
    mids = np.sqrt(edges[:-1] * edges[1:])
    arms = list(H["arms"])
    groups = E["groups"]
    fig, axes = plt.subplots(len(arms), len(groups), figsize=(3.3 * len(groups) + 1.8, 2.6 * len(arms)), squeeze=False,
                             sharex=True)
    names = E["names"]
    for i, a in enumerate(arms):
        for j, g in enumerate(groups):
            ax = axes[i][j]
            h = H["arms"][a][g]

            def dens(c):
                c = np.asarray(c, float)
                return c / c.sum() if c.sum() else c

            if h["n_train_benign"]:
                ax.step(mids, dens(h["train_benign"]), where="mid", color=PS.BENIGN_GRAY, lw=1.2, label="train benign")
            if h["n_val_benign"]:
                ax.step(mids, dens(h["val_benign"]), where="mid", color=PS.TEXT1, lw=0.9, ls="--", label="val benign")
            for kn, m in h["misses"].items():
                ax.step(mids, dens(m["counts"]), where="mid", color=PS.class_color(names.index(kn)), lw=1.1,
                        label=f"val misses: {kn}")
            if h["threshold"] is not None:
                ax.axvline(h["threshold"], color=PS.CATEGORICAL[4], lw=1.0, label="threshold")
            ax.set_xscale("log")
            ax.set_title(f"{SHORT[a]} | group {g}", fontsize=8.5)
            info = f"n train {h['n_train_benign']:,}\nn val benign {h['n_val_benign']:,}" + \
                "".join(f"\nmisses {kn} {m['n']:,}" for kn, m in h["misses"].items())
            ax.text(0.02, 0.97, info, transform=ax.transAxes, ha="left", va="top", fontsize=6.5, color=PS.TEXT2)
            if j == 0:
                ax.set_ylabel("share of flows per bin")
            if i == len(arms) - 1:
                ax.set_xlabel("anomaly score (log)")
    hs, ls = [], []
    for row in axes:
        for ax in row:
            for hh, ll in zip(*ax.get_legend_handles_labels()):
                if ll not in ls:
                    hs.append(hh)
                    ls.append(ll)
    fig.legend(hs, ls, loc="center left", bbox_to_anchor=(1.0, 0.5), frameon=False)
    fig.suptitle(f"anomaly-score distributions, seed {H['seed']}", fontsize=10)
    fig.tight_layout()
    PS.save(fig, path)


def fig_threshold(path: Path, E: dict, TC: dict) -> None:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    pal = _pal()
    fig, ax = plt.subplots(figsize=(6.6, 3.6))
    for ai, a in enumerate(ARMS):
        hv = [TC[a][s] for s in sorted(TC[a])]
        vb = [E["fa"][a][str(s)]["flag_rate"] for s in E["seeds"]]
        x = np.full(len(hv), ai) + np.linspace(-0.12, 0.12, len(hv)) - 0.18
        ax.scatter(x, hv, s=24, color=pal[a], zorder=3, label="train held-out 10 %" if ai == 0 else None)
        x2 = np.full(len(vb), ai) + np.linspace(-0.12, 0.12, len(vb)) + 0.18
        ax.scatter(x2, vb, s=24, facecolor="none", edgecolor=pal[a] if a != NM.RANDOM_GROUP else PS.TEXT2, lw=1.0, zorder=3,
                   label="val benign (drift, report-only)" if ai == 0 else None)
    ax.axhline(E["nominal_flag_rate"], color=PS.TEXT1, lw=0.8, ls="--", label=f"nominal {E['nominal_flag_rate']:.3%}")
    ax.set_yscale("symlog", linthresh=1e-4)                          # symlog: a 0 flag rate stays visible
    top = max([E["nominal_flag_rate"]] + [v for a in ARMS for v in TC[a].values()] +
              [E["fa"][a][str(s)]["flag_rate"] for a in ARMS for s in E["seeds"]])
    ax.set_ylim(-0.2e-4, top * 2.0)                                    # headroom: no clipped markers
    ax.set_xticks(range(len(ARMS)))
    ax.set_xticklabels([SHORT[a] for a in ARMS])
    ax.set_xlim(-0.6, len(ARMS) - 0.4)
    ax.set_ylabel("flag rate (symlog; linear below 1e-4)")
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False)
    ax.set_title("threshold check: refit on 90 % of train benign, flag rate on the other 10 %", fontsize=9)
    PS.save(fig, path)


def make_figures(figdir: Path, E: dict, TC: dict) -> list[str]:
    from common import plot_style as PS
    PS.apply()
    figdir.mkdir(parents=True, exist_ok=True)
    out = []
    for fn, f in (("1_pipeline.png", lambda p: fig_pipeline(p, E)), ("2_where_heldout_flows_go.png", lambda p: fig_where(p, E)),
                  ("3_miss_recall_pairs.png", lambda p: fig_recall(p, E)), ("4_verdict_cis.png", lambda p: fig_verdict(p, E)),
                  ("5_false_alarms.png", lambda p: fig_fa(p, E)), ("6_score_distributions.png", lambda p: fig_scores(p, E)),
                  ("7_threshold_check.png", lambda p: fig_threshold(p, E, TC))):
        f(figdir / fn)
        if (figdir / fn).exists():
            out.append(fn)
    return out


# =========================================================================== summary
def _ci(c: dict, f: str = "{:+.4f}") -> str:
    if not c or not c.get("n"):
        return "n/a"
    return f"{f.format(c['mean'])} [{f.format(c['lo'])}, {f.format(c['hi'])}] (n={c['n']})"


def phase_summary(E: dict, X: dict) -> str:
    """results/phase5a/summary.md. X = {"loao": step 36 json, "normal": step 37 records, "runs": ids, "figures": [...]}."""
    names, V = E["names"], E["verdict"]
    P, Lt, RC = V["prereg"], V["literal"], E["random_control"]["prereg"]
    lo = X["loao"]
    L = ["# LG-IDS V2 Phase 5A -- zero-day test (leave-one-attack-out + model of normal, per-group vs global)", "",
         f"Runs: step 36 `{X['runs']['36']}`, step 37 `{X['runs']['37']}`, step 38 `{X['runs']['38']}`. Offline, train + val "
         "only (full val); nothing registered, runtime untouched. Pre-registration `docs/V2_PREREG_PHASE5.md`.", "",
         "## Headline", "",
         f"- **Amendment 2 §3 verdict: {V['verdict']}** -- prereg reading: {P['verdict']} ({P['reason']}); Amendment 2 "
         f"literal reading: {Lt['verdict']} ({Lt['reason']}); readings agree: {V['agree']}.",
         f"- (a) miss-recall difference PER_GROUP - GLOBAL, mean [95 % bootstrap CI] over {P['n_pairs']} eligible pairs: "
         f"{_ci(P['ci_d'])}; t-interval (report-only) {_ci(P['t_d'])}.",
         f"- (b) FA/h difference PER_GROUP - GLOBAL over {P['ci_fa']['n']} seeds: {_ci(P['ci_fa'], '{:+.3f}')} "
         f"(margin {V['fa_margin_per_h']} / h).",
         f"- Phase 4 §4 (pinned): {E['s4_phase4']}.", "", "**" + E["kill_line"] + "**", "",
         "## Held-out classes and Stage 1 misses", "",
         f"- verdict classes (>= {X['rare_rule']} val flows): {', '.join(names[k] for k in E['nonrare'])}; rare, report-only: "
         f"{', '.join(names[k] for k in E['rare']) or 'none'}. Val benign hours {E['benign_hours']:.3f}.", "",
         "| held out | seed | val k flows | Stage 1 misses | caught as another attack | eligible | miss-recall GLOBAL | "
         "PER_GROUP | RANDOM_GROUP | d |", "|---|---|---|---|---|---|---|---|---|---|"]
    lp = {(p["k"], p["s"]): p for p in lo["pairs"]}
    for p in E["pairs"]:
        r = p["recall"]
        fmt = (lambda x: f"{x:.4f}" if x is not None and np.isfinite(x) else "n/a")
        d = r[NM.PER_GROUP] - r[NM.GLOBAL] if np.isfinite(r[NM.GLOBAL]) and np.isfinite(r[NM.PER_GROUP]) else float("nan")
        L.append(f"| {p['class']}{' (rare)' if p['rare'] else ''} | {p['s']} | {p['n_val']:,} | {p['n_miss']:,} | "
                 f"{p['n_caught']:,} {lp[(p['k'], p['s'])]['caught_as']} | {'yes' if p['eligible'] else 'no'} | "
                 f"{fmt(r[NM.GLOBAL])} | {fmt(r[NM.PER_GROUP])} | {fmt(r[NM.RANDOM_GROUP])} | {fmt(d) if np.isfinite(d) else 'n/a'} |")
    L += ["", "Eligible pairs per class: " + ", ".join(f"{names[int(k)]} {v['eligible']}/{v['pairs']}" for k, v in E["eligibility"].items()),
          "", "LOAO Stage 1 benign sanity (val): " + "; ".join(
              f"{p['class']} s{p['s']}: benign recall {p['sanity']['benign_recall']:.5f}, FA {p['sanity']['fa_count']} "
              f"({p['sanity']['fa_per_hour']:.3f}/h)" for p in lo["pairs"]), "",
          f"Control (report-only): full refit with this code vs the step 22 deployed model: {lo['control']}", "",
          "## False alarms on val benign (detector alone)", "",
          "| arm | seed | flagged flows | val benign flows | benign hours | FA/h | flag rate |", "|---|---|---|---|---|---|---|"]
    for a in ARMS:
        for s in E["seeds"]:
            f = E["fa"][a][str(s)]
            L.append(f"| {a} | {s} | {f['fa_count']} | {f['n_benign']:,} | {f['benign_hours']:.3f} | {f['fa_per_hour']:.3f} | "
                     f"{f['flag_rate']:.5f} |")
    L += ["", "## Models of normal", "",
          "| arm | seed | models: n train benign / threshold | fallback | 90/10 held-out flag rate |", "|---|---|---|---|---|"]
    for r in X["normal"]:
        ms = "; ".join(f"{k}: {m['n_train']:,} / {m['threshold']:.5f}" for k, m in r["models"].items())
        L.append(f"| {r['arm']} | {r['seed']} | {ms} | {r['fallback'] or '-'} | {r['threshold_check']['held_out_flag_rate']:.5f} |")
    L += ["", f"Determinism (seed-0 refit, identical scores): {X['determinism']}", "",
          "## Report-only", "",
          f"- **RANDOM_GROUP vs GLOBAL** (same paired analysis): recall d {_ci(RC['ci_d'])}; FA/h d {_ci(RC['ci_fa'], '{:+.3f}')}; "
          f"(a) {RC['a_recall_ci_above_0']}, (b) {RC['b_fa_ci_within_margin']} -> would 'win': "
          f"{E['random_control']['prereg']['verdict'] == ZM.WIN}.",
          "- detector alone on ALL val flows of k (5-seed mean): " + "; ".join(
              f"{names[k]}: " + ", ".join(f"{SHORT[a]} {np.mean([p['detector_alone'][a] for p in E['pairs'] if p['k'] == k]):.4f}"
                                         for a in ARMS) for k in E["nonrare"] + E["rare"]),
          "- combined system (Stage 1 alert OR flag) recall on k (5-seed mean): " + "; ".join(
              f"{names[k]}: " + ", ".join(f"{SHORT[a]} {np.mean([p['combined'][a] for p in E['pairs'] if p['k'] == k]):.4f}"
                                         for a in ARMS) for k in E["nonrare"] + E["rare"]),
          "- combined FA/h on val benign (5-seed mean; LOAO Stage 1 FA + detector FA): " + "; ".join(
              f"{names[k]}: Stage 1 alone {np.mean([p['stage1_fa']['fa_per_hour'] for p in E['pairs'] if p['k'] == k]):.2f}, " +
              ", ".join(f"{SHORT[a]} {np.mean([p['combined_fa'][a]['fa_per_hour'] for p in E['pairs'] if p['k'] == k]):.2f} "
                        f"({np.mean([p['combined_fa'][a]['fa_count'] for p in E['pairs'] if p['k'] == k]):.1f} flows)"
                        for a in ARMS) for k in E["nonrare"]),
          f"- drift: val-benign flag rate per arm x group, 5-seed mean, nominal {E['nominal_flag_rate']:.4f}: " + "; ".join(
              f"{SHORT[a]} " + ", ".join(f"{g} {np.mean([E['drift'][a][str(s)][g]['flag_rate'] or 0 for s in E['seeds']]):.5f}"
                                        for g in E["groups"]) for a in ARMS),
          "- per-group miss-recall (seed-mean over pairs with misses in the group): " + "; ".join(
              f"{names[k]} {g}: " + ", ".join(
                  f"{SHORT[a]} {np.nanmean([p['per_group'][a][g]['recall'] for p in E['pairs'] if p['k'] == k and g in p['per_group'][a]]):.4f}"
                  for a in ARMS)
              for k in E["nonrare"] for g in E["groups"] if any(g in p["per_group"][NM.GLOBAL] for p in E["pairs"] if p["k"] == k)),
          "- scoring cost (n_jobs %d): " % E["cost"][NM.GLOBAL]["n_jobs"] + "; ".join(
              f"{SHORT[a]} batch {np.mean(list(E['cost'][a]['batch_us_per_flow'].values())):.1f} us/flow, single flow "
              f"{E['cost'][a]['single_flow_us_median']:.0f} us (median of {E['cost'][a]['single_flow_calls']})" for a in ARMS),
          "- model sizes on disk (seed 0): " + "; ".join(f"{SHORT[a]} {v / 1024:.0f} KB" for a, v in X["sizes"].items()), "",
          "## Limitations (stated in the prereg before any result)", "",
          f"1. Only {len(E['nonrare'])} held-out classes enter the verdict, all floods / scans; the CI covers seed noise, not attack variety.",
          "2. Isolation Forest is strong on globally extreme points and weak on local anomalies inside dense benign regions; "
          "the test says nothing about stealthy attacks.",
          "3. Flow level only; in the deployed hybrid the rate guard would likely catch these floods anyway.",
          "4. val is not fully held out (Phase 2 selection, Amendment 2, the deployed temperature; Phase 4 disclosure).",
          "5. The model of normal is benign-only: the same fitted models score every held-out class; only the miss set changes.",
          "6. The bootstrap treats (class, seed) pairs as independent although they share seeds and classes.", "",
          "## What this means for the paper", ""]
    if V["verdict"] == ZM.NO_WIN:
        L.append("Neither pre-registered routing test favours per-group models (Phase 4 §4 DOES_NOT_WIN, Phase 5A §3 "
                 "DOES_NOT_WIN), so under Amendment 2 §5 routing is reported as an **operational feature only**: it gives "
                 "per-device and per-group incident keys and false-alarm rates, the runtime routing is exact (Phase 3 "
                 "parity 100 %), and passive IP->MAC learning keeps it exact on pcap input (Phase 3.1, 100 %). The paper "
                 "makes no novelty claim for per-group modelling; its contribution must rest elsewhere (the pre-registered, "
                 "reproducible V1 -> V2 pipeline, the signed model / label lifecycle, the hybrid rate guard + flow "
                 "classifier, and the honest negative routing results themselves). The zero-day numbers remain useful as "
                 "a description of what a benign-only detector adds to a LOAO Stage 1 on these floods and scans.")
    elif V["verdict"] == ZM.WIN:
        L.append("The zero-day test favours per-group models of normal, so under Amendment 2 §5 the routing novelty claim "
                 "is limited to that stage: per-group benign models flag more of the attacks a Stage 1 trained without "
                 "them misses, at a false-alarm cost within the pre-registered margin. Scope: "
                 f"{len(E['nonrare'])} held-out flood / scan classes, Isolation Forest only, flow level, val evidence; the "
                 "random-group control must be read with it (if it also wins, the gain is from training-set size, not device "
                 "structure). Continual learning (Phase 4) gives no routing advantage.")
    else:
        L.append("The two readings of Amendment 2 §3 disagree (CONFLICT), so no verdict is declared and Phase 5A stops for a "
                 "human decision (see the headline).")
    L += ["", "## Figures", ""] + [f"- `figures/{f}`" for f in X["figures"]]
    return "\n".join(L) + "\n"


# =========================================================================== main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    ap.add_argument("--loao-run", default=None, help="step 36 run id (default: the full run in results/phase5a/36/)")
    ap.add_argument("--normal-run", default=None, help="step 37 run id (default: the full run in results/phase5a/37/)")
    ap.add_argument("--replot", default=None, metavar="TAG", help="re-draw figures + summary from results/phase5a/38/eval.json")
    args = ap.parse_args()
    cfg5 = ZC.load_phase5_config()
    if args.replot:
        return replot(cfg5, args.replot)
    up36 = ZR.resolve("36", args.loao_run, args.dry_run)
    up37 = ZR.resolve("37", args.normal_run, args.dry_run)
    phase_dir = ZR.PHASE5_RESULTS
    if not args.dry_run and not args.rerun_tag:
        for p in (phase_dir / "summary.md", phase_dir / "figures"):
            if p.exists():
                raise ZR.RunRefused(f"{p} exists (never overwritten; use --rerun-tag or --replot)")
    run = ZR.ZRun("38", SCRIPT, cfg5, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/phase2_config.py", "common/plot_style.py"])
    ZR.lock_banner(run, M, "start")
    M.update({"loao_run": up36["meta"]["run_id"], "normal_run": up37["meta"]["run_id"]})
    ok = False
    try:
        cm = S.load_class_map()
        names = list(cm.names)
        feats = S.feature_columns()
        cfg2 = load_phase2_config(REPO_ROOT / cfg5["phase2_config"])
        va = D.load_split(cfg2, "val", feats + ["label_id", "group", "session", "row_in_file", "start_ts"], sample=args.dry_run)
        uid = (va["session"].astype(str) + ":" + va["row_in_file"].astype(str)).tolist()
        M36, preds = load_loao(up36, len(va))
        run.check(M, "val rows / order == step 36's (uid sha256)", ZR.sha256_bytes("\n".join(uid).encode("utf-8")) ==
                  M36["data"]["val_uid_sha256"], f"{len(uid):,} rows")
        fits, tscores, tgroups, man37 = load_fits(up37)
        run.check(M, "step 37 trained on the same train file", man37["data"]["train_sha256"] == D.verify_split_file(cfg2, "train"), "")
        seeds = sorted({s for (_, s) in fits} & {int(p["s"]) for p in M36["pairs"]})
        run.check(M, "step 36 and step 37 seeds match", seeds == sorted({int(p["s"]) for p in M36["pairs"]}) ==
                  sorted({s for (_, s) in fits}), f"{seeds}")
        X = D.feature_matrix(va, feats)
        Zva, nonfinite = NM.prepare(X, feats)
        del X
        yva = va["label_id"].to_numpy(np.int64)
        gva = va["group"].astype(str).to_numpy()
        sess = va["session"].astype(str).to_numpy()
        ts = va["start_ts"].to_numpy(np.int64)
        del va
        hours = M36["benign_hours"]
        M["data"] = {"val_rows": int(len(yva)), "val_sha256": D.verify_split_file(cfg2, "val"),
                     "nonfinite_before_cleaning": nonfinite, "seeds": seeds, "benign_hours": hours}
        nonrare, rare = M36["classes"]["nonrare_ids"], M36["classes"]["rare_ids"]
        E, SC = core(yva, gva, sess, ts, Zva, M36["pairs"], preds, fits, names, cfg5, nonrare, rare, seeds, hours, run.log,
                     tscores, tgroups)
        sdir = run.cache_dir("eval")
        files = {}
        for (a, s), v in SC.items():
            fn = f"{a}__s{s}.val_scores.npy"
            np.save(sdir / fn, v.astype(np.float64))
            files[fn] = ZR.sha256_path(sdir / fn)
        ZR.write_json(sdir / "manifest.json", {"files_sha256": files, "run_id": run.run_id})
        M["scores_dir"] = str(sdir)
        TC = {a: {int(r["seed"]): r["threshold_check"]["held_out_flag_rate"] for r in man37["records"] if r["arm"] == a}
              for a in ARMS}
        sizes = {}
        for a in ARMS:
            r = next(r for r in man37["records"] if r["arm"] == a and int(r["seed"]) == seeds[0])
            g0 = next(r for r in man37["records"] if r["arm"] == NM.GLOBAL and int(r["seed"]) == seeds[0])
            sizes[a] = sum((r["files"][k].get("size_bytes") or g0["files"][NM.GLOBAL_KEY]["size_bytes"]) for k in r["files"])
        E["threshold_check"] = TC
        E["sizes_bytes"] = sizes
        E["normal_records"] = man37["records"]
        E["determinism"] = {a: v["identical"] for a, v in man37["determinism"].items()}
        E["runs"] = {"36": up36["meta"]["run_id"], "37": up37["meta"]["run_id"], "38": run.run_id}
        E["loao"] = {"pairs": M36["pairs"], "control": M36["control"], "classes": M36["classes"]}
        E["rare_rule"] = cfg5["loao"]["rare_min_val_flows"]
        ZR.write_json(run.res / "eval.json", E)
        V = E["verdict"]
        run.log(f"  VERDICT (Amendment 2 §3): {V['verdict']}  | prereg {V['prereg']['verdict']} ({V['prereg']['reason']})"
                f"  | literal {V['literal']['verdict']} ({V['literal']['reason']})")
        run.log(f"  (a) d = {_ci(V['prereg']['ci_d'])}   (b) FA/h d = {_ci(V['prereg']['ci_fa'], '{:+.3f}')}")
        run.log(f"  {E['kill_line']}")
        print(E["kill_line"], flush=True)
        M["verdict"] = {"status": V["verdict"], "prereg": V["prereg"]["verdict"], "literal": V["literal"]["verdict"],
                        "kill_line": E["kill_line"], "ci_d": V["prereg"]["ci_d"], "ci_fa": V["prereg"]["ci_fa"]}
        run.check(M, "verdict declared (the two readings of Amendment 2 §3 agree)", V["verdict"] != ZM.CONFLICT,
                  f"{V['verdict']}")
        figs = make_figures(run.fig, E, TC)
        run.log(f"  figures: {figs}")
        Xs = {"loao": E["loao"], "normal": man37["records"], "runs": E["runs"], "figures": figs, "rare_rule": E["rare_rule"],
              "determinism": E["determinism"], "sizes": sizes}
        txt = phase_summary(E, Xs)
        (run.res / "phase_summary.md").write_text(txt, encoding="utf-8")
        if not args.dry_run and not args.rerun_tag:
            (phase_dir / "summary.md").write_text(txt, encoding="utf-8")
            shutil.copytree(run.fig, phase_dir / "figures")
            run.log(f"  phase summary -> {phase_dir / 'summary.md'}, figures -> {phase_dir / 'figures'}")
        ZR.lock_banner(run, M, "end")
        ok = all(c["pass"] for c in M["checks"] if c["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def replot(cfg5: dict, tag: str) -> int:
    src = ZR.PHASE5_RESULTS / "38" / "eval.json"
    out = ZR.PHASE5_RESULTS / tag
    if out.exists():
        raise ZR.RunRefused(f"{out} exists (never overwritten)")
    E = json.loads(src.read_text(encoding="utf-8"))
    TC = {a: {int(s): v for s, v in d.items()} for a, d in E["threshold_check"].items()}
    out.mkdir(parents=True)
    figs = make_figures(out / "figures", E, TC)
    Xs = {"loao": E["loao"], "normal": E["normal_records"], "runs": E["runs"], "figures": figs, "rare_rule": E["rare_rule"],
          "determinism": E["determinism"], "sizes": E["sizes_bytes"]}
    (out / "summary.md").write_text(phase_summary(E, Xs), encoding="utf-8")
    (out / "replot_meta.json").write_text(json.dumps({"source": str(src), "source_sha256": ZR.sha256_path(src),
                                                      "created_utc": ZR.now_utc(), "figures": figs}, indent=1) + "\n",
                                          encoding="utf-8")
    print(f"replot -> {out} ({figs})")
    return 0


def write_summary(run, M: dict, dry: bool) -> None:
    st = "PASS" if all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") and not M.get("error") else "FAIL"
    L = [f"# Step 38 -- zero-day evaluation + verdict -- {st}" + (" (DRY RUN)" if dry else ""), "",
         f"- step 36 run `{M.get('loao_run')}`, step 37 run `{M.get('normal_run')}`; the full write-up is "
         "`phase_summary.md` (and results/phase5a/summary.md for the full run)", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("verdict"):
        v = M["verdict"]
        L += [f"- **verdict {v['status']}** (prereg {v['prereg']}, literal {v['literal']}); d {_ci(v['ci_d'])}; "
              f"FA/h d {_ci(v['ci_fa'], '{:+.3f}')}", f"- {v['kill_line']}", ""]
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
