#!/usr/bin/env python
"""44_phase5b_report.py -- Phase 5B step G: figures + results/phase5b/summary.md from the json outputs of steps 39-43
(no data is read; nothing is recomputed except display CIs). Full run: results/phase5b/44/ + results/phase5b/summary.md
and results/phase5b/figures/ (refused if they exist; re-render with --rerun-tag). --dry-run needs the dry run ids.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import traceback
from pathlib import Path

import numpy as np

from common import context_config as CC
from common import phase2_metrics as PM
from common import phase5b_run as PR

SCRIPT = "44_phase5b_report.py"
ARMS = ("GLOBAL", "GLOBAL_CTX", "CTX_ONLY", "GLOBAL_NOFP", "GLOBAL_CTX_NOFP")


def _pal():
    from common import plot_style as PS
    return {"GLOBAL": PS.CATEGORICAL[0], "GLOBAL_CTX": PS.CATEGORICAL[1], "CTX_ONLY": PS.CATEGORICAL[2],
            "GLOBAL_NOFP": PS.CATEGORICAL[6], "GLOBAL_CTX_NOFP": PS.CATEGORICAL[4]}


def tci(v):
    t = PM.t_ci([x for x in v if x is not None and np.isfinite(x)], 0.95)
    return t["mean"], (t["mean"] - t["lo"]) if np.isfinite(t["lo"]) else 0.0, (t["hi"] - t["mean"]) if np.isfinite(t["hi"]) else 0.0


def fig1(path, cfg):
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    from common import plot_style as PS
    fig, ax = plt.subplots(figsize=(11, 5.2))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 5.2)
    ax.axis("off")

    def box(x, y, w, h, t, body, fc):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.04,rounding_size=0.08", fc=fc, ec=PS.TEXT2, lw=0.8))
        ax.text(x + w / 2, y + h - 0.18, t, ha="center", va="top", fontsize=9, weight="bold")
        ax.text(x + w / 2, y + h - 0.48, body, ha="center", va="top", fontsize=7.4, color=PS.TEXT2, linespacing=1.35)

    def arr(x0, y0, x1, y1):
        ax.annotate("", (x1, y1), (x0, y0), arrowprops=dict(arrowstyle="-|>", color=PS.TEXT2, lw=0.9))

    w = cfg["context"]["windows_s"]
    box(0.1, 1.6, 2.4, 1.7, "flow f (ends at t)", "endpoints A, B (IP)\nports {pA, pB} unordered\npkts, bytes: fwd + bwd\n"
        "SYN / ACK counts\n(both directions)", "#eef3fb")
    box(3.2, 3.1, 2.8, 1.5, "host A window state", "every flow with A as either end\nt_end in [t - w, t)  (f excluded)",
        "#fdf0ea")
    box(3.2, 1.65, 2.8, 1.25, "host B window state", "same 7 statistics", "#fdf0ea")
    box(3.2, 0.1, 2.8, 1.35, "pair {A, B} window state", "7 statistics + mean duration", "#fdf0ea")
    box(6.7, 1.9, 2.0, 2.2, "combine", "max(h(A), h(B))\nmin(h(A), h(B))\n(symmetric in A, B)", "#f3f3f1")
    box(9.2, 1.1, 1.7, 2.6, f"{len(CC.context_feature_names(cfg))} features",
        f"(7 x 2 + 8)\nx {len(w)} windows\n({', '.join(str(x) for x in w)} s)\nsame for a\nswapped flow", "#f3f3f1")
    arr(2.5, 2.6, 3.2, 3.8)
    arr(2.5, 2.45, 3.2, 2.3)
    arr(2.5, 2.3, 3.2, 0.8)
    arr(6.0, 3.8, 6.7, 3.3)
    arr(6.0, 2.3, 6.7, 2.6)
    arr(6.0, 0.8, 9.2, 1.6)
    arr(8.7, 3.0, 9.2, 2.6)
    ax.text(5.5, 5.12, "causal: only flows that ENDED strictly before f, within w; state reset per (session, split); "
            "bounded keys (LRU eviction)", ha="center", va="top", fontsize=7.6, color=PS.TEXT2)
    PS.save(fig, path)


def fig2(path, FS, names):
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    top = FS["top"]
    n = len(top)
    cols = 3
    rows = int(np.ceil(n / cols))
    fig, axes = plt.subplots(rows, cols, figsize=(3.6 * cols + 1.8, 2.5 * rows), squeeze=False)
    for i, f in enumerate(top):
        ax = axes[i // cols][i % cols]
        H = FS["hist"][f]
        e = np.asarray(H["edges_log10_1p"])
        mid = (e[:-1] + e[1:]) / 2
        for nm, cnt in H["counts"].items():
            c = np.asarray(cnt, float)
            ax.step(mid, c / max(1, c.sum()), where="mid", color=PS.class_color(names.index(nm)), lw=1.1, label=nm)
        ax.set_title(f.replace("ctx_", ""), fontsize=8)
        ax.set_xlabel("log10(1 + value)", fontsize=8)
        if i % cols == 0:
            ax.set_ylabel("share per bin")
    for j in range(n, rows * cols):
        axes[j // cols][j % cols].axis("off")
    h, l_ = axes[0][0].get_legend_handles_labels()
    fig.legend(h, l_, loc="center left", bbox_to_anchor=(1.0, 0.5), frameon=False, title="train flows")
    fig.suptitle("most separating context features (train): distribution per class", fontsize=10)
    fig.tight_layout()
    PS.save(fig, path)


def fig3(path, S40):
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    pal, names = _pal(), S40["names"]
    A = S40["all"]
    cls = [n for n in names if A["GLOBAL"]["support"][n]]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 3.9), gridspec_kw={"width_ratios": [1.6, 1]})
    w = 0.15
    for ai, a in enumerate(S40["arms"]):
        xs = np.arange(len(cls)) + (ai - 2) * w
        m = [tci(A[a]["recall"][n]) for n in cls]
        a1.errorbar(xs, [x[0] for x in m], yerr=[[x[1] for x in m], [x[2] for x in m]], fmt="o", ms=4, capsize=2,
                    color=pal[a], label=a)
    a1.set_xticks(range(len(cls)))
    a1.set_xticklabels([f"{n}\n(n={A['GLOBAL']['support'][n]:,})" for n in cls], fontsize=8)
    a1.set_ylabel("val recall (5-seed mean, 95 % t-CI)")
    a1.legend(loc="lower left", fontsize=7.5, frameon=False, ncol=2)
    seeds = S40["seeds"]
    w2 = 0.8 / len(S40["arms"])
    top = max(max(A[a]["fa_per_hour"]) for a in S40["arms"])
    for ai, a in enumerate(S40["arms"]):
        xs = np.arange(len(seeds)) + (ai - (len(S40["arms"]) - 1) / 2) * w2
        a2.bar(xs, A[a]["fa_per_hour"], w2 * 0.95, color=pal[a])
        for x, v, cnt in zip(xs, A[a]["fa_per_hour"], A[a]["fa_count"]):
            a2.text(x, v + 0.02 * max(top, 1e-9), str(cnt), ha="center", va="bottom", fontsize=6.5)
    a2.set_xticks(range(len(seeds)))
    a2.set_xticklabels([f"s{s}" for s in seeds])
    a2.set_ylim(0, max(top, 1e-9) * 1.25)
    a2.set_ylabel(f"val FA / h (numbers = FA flows;\nbenign hours {A['GLOBAL']['benign_hours']:.2f})")
    fig.tight_layout()
    PS.save(fig, path)


def fig4(path, O41):
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    pal = _pal()
    arms, seeds = O41["arms"], O41["seeds"]
    AG = O41["agreement"]
    names = O41["names"]                                                # benign is already the "TCP benign" column
    cats = ["tcp", "tcp_benign"] + [c for c in next(iter(AG.values()))["per_class"] if c != names[0]] + ["non_tcp"]
    has_rr = bool(O41["real_reversals"].get("arms"))
    fig, axes = plt.subplots(1, 2 if has_rr else 1, figsize=(12.5 if has_rr else 8, 3.9), squeeze=False,
                             gridspec_kw={"width_ratios": [1.7, 1] if has_rr else [1]})
    ax = axes[0][0]
    w = 0.8 / len(arms)
    for ai, a in enumerate(arms):
        vals = []
        for cname in cats:
            v = [AG[f"{a}|{s}"][cname] if cname in ("tcp", "tcp_benign", "non_tcp") else AG[f"{a}|{s}"]["per_class"][cname]
                 for s in seeds]
            vals.append(tci(v))
        xs = np.arange(len(cats)) + (ai - (len(arms) - 1) / 2) * w
        ax.errorbar(xs, [1 - v[0] for v in vals], yerr=[[v[2] for v in vals], [v[1] for v in vals]], fmt="o", ms=4,
                    capsize=2, color=pal[a], label=a)
    ax.set_yscale("symlog", linthresh=1e-4)
    ax.set_ylim(-0.5e-4, None)
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels([{"tcp": "TCP", "tcp_benign": "TCP benign", "non_tcp": "non-TCP\n(not swapped)"}.get(x, f"TCP {x}")
                        for x in cats], fontsize=7.5)
    ax.set_ylabel("1 - flip agreement (symlog)\n(share of flows whose class changes)")
    ax.legend(loc="upper left", fontsize=7.5, frameon=False, ncol=2)
    ax.set_title(f"flip test (TCP flows): H-C1 {O41['h_c1']['verdict']}", fontsize=9)
    if has_rr:
        a2 = axes[0][1]
        RR = O41["real_reversals"]
        for ai, a in enumerate(arms):
            m = tci([RR["arms"][a][str(s)]["error_rate"] for s in seeds])
            a2.bar(ai, m[0], 0.7, color=pal[a])
            a2.errorbar(ai, m[0], yerr=[[m[1]], [m[2]]], color=PS.TEXT1, capsize=3, lw=0.8)
            inc = np.mean([RR["arms"][a][str(s)]["incidents_still_false"] for s in seeds])
            tot = np.mean([RR["arms"][a][str(s)]["incidents"] for s in seeds])
            a2.text(ai, m[0] + m[2] + 0.03, f"incidents {inc:.1f} / {tot:.1f}", ha="center", va="bottom", fontsize=6.5,
                    rotation=90)
        a2.set_xticks(range(len(arms)))
        a2.set_xticklabels(arms, rotation=30, ha="right", fontsize=7.5)
        a2.set_ylim(0, 1.55)
        a2.set_ylabel(f"error rate on {RR['h1_flows_in_val']} real reversed flows\n(diag_03 H1; text = incidents still "
                      "false / total, seed means)", fontsize=8.5)
    fig.tight_layout()
    PS.save(fig, path)


def fig5(path, Z):
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    pal = _pal()
    cls = list(Z["h_c2"])
    fig, ax = plt.subplots(figsize=(1.8 + 2.2 * len(cls), 3.6))
    for i, n in enumerate(cls):
        h = Z["h_c2"][n]
        for j, (key, a, lab) in enumerate((("delta_flow", "GLOBAL_NOFP", "flow only (NOFP - GLOBAL)"),
                                           ("delta_ctx", "GLOBAL_CTX_NOFP", "with context (CTX_NOFP - CTX)"))):
            m = tci(h[key])
            ax.bar(i + (j - 0.5) * 0.36, m[0], 0.34, color=pal[a], label=lab if i == 0 else None)
            ax.errorbar(i + (j - 0.5) * 0.36, m[0], yerr=[[m[1]], [m[2]]], color=PS.TEXT1, capsize=3, lw=0.8)
    ax.axhline(0, color=PS.TEXT1, lw=0.7)
    ax.set_xticks(range(len(cls)))
    ax.set_xticklabels([f"{n}\nH-C2: {Z['h_c2'][n]['verdict']}" + (" (pre-reg.)" if n == Z["h_c2_class"] else "")
                        for n in cls], fontsize=8)
    ax.set_ylabel("recall change from removing the\nfingerprint features (5-seed mean, t-CI)")
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False, fontsize=8)
    PS.save(fig, path)


def fig6(path, Z, lo_min):
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    names = Z["names"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12.5, 3.9))
    prim = Z["arms"][Z["primary_arm"]]
    cif = Z["arms"]["CTX_IF_GLOBAL"]
    ks = Z["nonrare"]
    first = (0, Z["seeds"][0])
    for i, k in enumerate(ks):
        for s in Z["seeds"]:
            r_ctx = next(p["recall"] for p in prim[str(s)]["pairs"] if p["k"] == k)
            r_if = next(p["recall"] for p in cif[str(s)]["pairs"] if p["k"] == k)
            r_5a = Z["phase5a_global_normal_recall"].get(f"{k}|{s}")
            a1.plot([i - 0.25, i, i + 0.25], [r_5a, r_if, r_ctx], "-", color=PS.GRID, lw=0.8, zorder=1)
            a1.scatter(i - 0.25, r_5a, s=20, color=PS.CATEGORICAL[0], zorder=2,
                       label="5A GLOBAL_NORMAL (IF, per-flow)" if (i, s) == first else None)
            a1.scatter(i, r_if, s=20, color=PS.NEUTRAL_LIGHT, edgecolor=PS.TEXT2, zorder=2,
                       label="CTX_IF_GLOBAL (IF, context; report-only)" if (i, s) == first else None)
            a1.scatter(i + 0.25, r_ctx, s=20, color=PS.CATEGORICAL[1], zorder=2,
                       label=f"{Z['primary_arm']} (primary)" if (i, s) == first else None)
    a1.axhline(lo_min, color=PS.TEXT2, lw=0.7, ls="--")
    a1.text(len(ks) - 0.5, lo_min + 0.01, f"H-C3 needs CI lower bound >= {lo_min}", ha="right", va="bottom", fontsize=7,
            color=PS.TEXT2)
    a1.set_xticks(range(len(ks)))
    a1.set_xticklabels([names[k] for k in ks])
    a1.set_xlim(-0.6, len(ks) - 0.4)
    a1.set_ylim(-0.03, 1.08)
    a1.set_ylabel("miss-recall per (held-out class, seed)")
    a1.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), fontsize=7.5, frameon=False, ncol=2)
    a1.set_title(f"H-C3: {Z['h_c3']['verdict']}", fontsize=9)
    H = Z["hist"]
    if H:
        e = np.asarray(H["edges"])
        mid = np.sqrt(e[:-1] * e[1:])

        def dens(c):
            c = np.asarray(c, float)
            return c / max(1, c.sum())

        a2.step(mid, dens(H["train_benign"]), where="mid", color=PS.BENIGN_GRAY, lw=1.2, label=H["train_benign_label"])
        a2.step(mid, dens(H["val_benign"]), where="mid", color=PS.TEXT1, lw=0.9, ls="--", label="val benign")
        for nm, c in H["misses"].items():
            a2.step(mid, dens(c), where="mid", color=PS.class_color(names.index(nm)), lw=1.1, label=f"Stage 1 misses: {nm}")
        a2.axvline(H["threshold"], color=PS.CATEGORICAL[4], lw=1.0, label="fires above 1")
        a2.set_xscale("log")
        a2.set_xlabel(f"{Z['primary_arm']} score {H['score']} (log), seed {H['seed']}", fontsize=8)
        a2.set_ylabel("share per bin")
        a2.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False, fontsize=7.5)
    fig.tight_layout()
    PS.save(fig, path)


def fig7(path, P43):
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    models = list(P43["models"])
    fig, axes = plt.subplots(1, len(models), figsize=(5.6 * len(models) + 1.6, 3.8), squeeze=False, sharey=True)
    cols = {"top": PS.CATEGORICAL[1], "rand": PS.NEUTRAL_LIGHT, "bottom": PS.CATEGORICAL[0]}
    for ax, a in zip(axes[0], models):
        per = P43["models"][a]["per_class"]
        cls = list(per)
        for j, (key, lab) in enumerate((("top", f"top-{P43['k']}"), ("rand", f"random-{P43['k']}"), ("bottom", f"bottom-{P43['k']}"))):
            xs = np.arange(len(cls)) + (j - 1) * 0.26
            v = [per[c][f"drop_{key}"] for c in cls]
            ax.bar(xs, v, 0.25, color=cols[key], label=lab)
        for i, c in enumerate(cls):
            ax.text(i, max(per[c]["drop_top"], per[c]["drop_rand"], per[c]["drop_bottom"]) + 0.03, per[c]["verdict"],
                    ha="center", va="bottom", fontsize=6.8, rotation=90)
        ax.set_xticks(range(len(cls)))
        ax.set_xticklabels([f"{c}\n(n={per[c]['n']:,})" for c in cls], fontsize=8)
        ax.set_title(a, fontsize=9)
        ax.axhline(0, color=PS.TEXT1, lw=0.6)
    axes[0][0].set_ylabel("mean drop of the predicted class's\ncalibrated probability")
    axes[0][0].set_ylim(None, 1.45)
    axes[0][-1].legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False)
    PS.save(fig, path)


def make_figures(figdir: Path, cfg, D_) -> list[str]:
    from common import plot_style as PS
    PS.apply()
    figdir.mkdir(parents=True, exist_ok=True)
    out = []
    for fn, f in (("1_context_construction.png", lambda p: fig1(p, cfg)),
                  ("2_context_distributions.png", lambda p: fig2(p, D_["fs"], D_["s40"]["names"])),
                  ("3_stage1_recall_fa.png", lambda p: fig3(p, D_["s40"])), ("4_flip_agreement.png", lambda p: fig4(p, D_["o41"])),
                  ("5_fingerprint_ablation.png", lambda p: fig5(p, D_["z42"])),
                  ("6_zeroday_context.png", lambda p: fig6(p, D_["z42"], cfg["zeroday"]["recall_lo_min"])),
                  ("7_shap_perturbation.png", lambda p: fig7(p, D_["p43"]))):
        f(figdir / fn)
        out.append(fn)
    return out


def _ci(c, f="{:+.4f}"):
    return f"{f.format(c['mean'])} [{f.format(c['lo'])}, {f.format(c['hi'])}]" if c and c.get("n") else "n/a"


def summary(cfg, D_, runs, figs) -> str:
    s40, o41, z42, p43, m39 = D_["s40"], D_["o41"], D_["z42"], D_["p43"], D_["m39"]
    names = s40["names"]
    NI, H1, HC2, HC3 = s40["noninferiority"], o41["h_c1"], z42["h_c2"][z42["h_c2_class"]], z42["h_c3"]
    A = s40["all"]
    L = ["# LG-IDS V2 Phase 5B -- orientation-free host / host-pair context features + TreeSHAP perturbation check", "",
         "Runs: " + ", ".join(f"step {k} `{v}`" for k, v in runs.items()) + ". Offline, train + val only; nothing registered, "
         "runtime untouched. Pre-registration `docs/V2_PREREG_PHASE5B.md`. D163 holds: no routing-novelty claim; the per-group "
         "model of normal below is report-only.", "", "## Verdicts", "",
         f"- **Non-inferiority (GLOBAL_CTX vs GLOBAL): {NI['status']}** -- non-rare macro-F1 difference "
         f"{_ci(NI['macro_f1_diff'], '{:+.5f}')} (needs lower bound > -{NI['macro_f1_margin']}); FA-count differences per seed "
         f"{NI['fa_count_diffs']} (median {NI['fa_count_diff_median']:+.1f}, needs <= {NI['fa_count_margin']}). Warm-up flows "
         f"excluded: {s40['noninferiority_no_warmup']['status']}.",
         f"- **H-C1 (orientation robustness, TCP flows): {H1['verdict']}** -- flip agreement GLOBAL_CTX - GLOBAL: TCP flows "
         f"{_ci(H1['all'], '{:+.6f}')}, TCP benign {_ci(H1['benign'], '{:+.6f}')} (non-TCP flows are not swapped: agreement "
         "1 by construction, not evidence).",
         f"- **H-C2 (fingerprint independence, {z42['h_c2_class']}): {HC2['verdict']}** -- Δ_flow {np.mean(HC2['delta_flow']):+.4f}, "
         f"Δ_ctx {np.mean(HC2['delta_ctx']):+.4f}, Δ_ctx - Δ_flow {_ci(HC2['diff'])}.",
         f"- **H-C3 (zero-day with context; primary {z42['primary_arm']}, D165): {HC3['verdict']}** -- {HC3['reason']}; "
         f"miss-recall {_ci(HC3['recall'])} over {HC3['recall']['n']} eligible pairs; FA/h {_ci(HC3['fa'], '{:.3f}')} vs "
         f"Phase 5A GLOBAL_NORMAL {HC3['fa_ref']:.3f}. Same rule applied to the report-only arms (never the verdict): " +
         "; ".join(f"{a} {H['verdict']} (miss-recall {_ci(H['recall'])}, FA/h {_ci(H['fa'], '{:.2f}')})"
                   for a, H in z42["h_c3_rule_on_report_only_arms"].items()) + ".",
         "- **Part B (TreeSHAP perturbation)**: " + "; ".join(
             f"{a}: " + ", ".join(f"{k} {v['verdict']}" for k, v in R["per_class"].items()) for a, R in p43["models"].items()) + ".",
         "", "## Dataset v2_2_context", ""]
    for s, f in m39["dataset"]["files"].items():
        L.append(f"- {s}: {f['rows']:,} rows; evictions host {f['evictions']['host']}, pair {f['evictions']['pair']}; warm-up "
                 f"{f['warmup']:,} ({f['warmup_share']:.4f})")
    rc, vc = m39["reference_check"], m39["val_cost"]
    L += [f"- real-data reference check: {rc['rows']:,}-flow val slice of segment {rc['segment']}: streaming == naive "
          f"**{rc['equal']}** ({rc['mismatches']} mismatches)",
          f"- val compute cost (dev machine, pure Python): {vc['us_per_flow']:.1f} us/flow; peak state per segment "
          f"{vc['peak_hosts']} hosts, {vc['peak_pairs']} pairs, {vc['peak_events']:,} window events", "",
          "## Stage 1 arms (val, 5 seeds)", "",
          "| arm | " + " | ".join(f"recall {n}" for n in names) + " | macro-F1 non-rare | FA per seed | FA/h |", "|---" * (len(names) + 4) + "|"]
    for a in s40["arms"]:
        r = A[a]
        L.append(f"| {a} | " + " | ".join(f"{np.mean(r['recall'][n]):.4f}" if r["support"][n] else "n/a" for n in names)
                 + f" | {np.mean(r['macro_f1_nonrare']):.5f} | {r['fa_count']} | {np.mean(r['fa_per_hour']):.2f} |")
    L += ["", "Differences vs GLOBAL (mean [95 % bootstrap CI over seeds]): " + "; ".join(
        f"{a}: macro-F1 {_ci(A[a]['vs_global']['macro_f1_nonrare'], '{:+.5f}')}, FA count "
        f"{_ci(A[a]['vs_global']['fa_count'], '{:+.1f}')}" for a in s40["arms"] if a != "GLOBAL"), "",
        "## Orientation, real reversals, contamination", "",
        f"- flip: {o41['flip']['swapped_by_guard']:,} of {o41['flip']['rows']:,} val flows swapped (the normaliser's TCP guard; "
        f"{o41['flip']['not_swapped_non_tcp']:,} non-TCP unchanged); context identical after the flip (checked).",
        "- flip agreement (5-seed mean, TCP / TCP benign): " + "; ".join(
            f"{a} {np.mean([o41['agreement'][f'{a}|{s}']['tcp'] for s in o41['seeds']]):.6f} / "
            f"{np.mean([o41['agreement'][f'{a}|{s}']['tcp_benign'] for s in o41['seeds']]):.6f}" for a in o41["arms"])]
    RR = o41["real_reversals"]
    if RR.get("arms"):
        L.append(f"- real reversals ({RR['h1_flows_in_val']} diag_03 H1 flows): error rate (5-seed mean) and diag_03 incidents "
                 "still false: " + "; ".join(
                     f"{a} {np.mean([RR['arms'][a][str(s)]['error_rate'] for s in o41['seeds']]):.3f}, "
                     f"{np.mean([RR['arms'][a][str(s)]['incidents_still_false'] for s in o41['seeds']]):.1f} / "
                     f"{np.mean([RR['arms'][a][str(s)]['incidents'] for s in o41['seeds']]):.1f}" for a in o41["arms"]))
    else:
        L.append("- real reversals: no saved diag_03 list (skipped)")
    CT = o41["contamination"]
    L += [f"- contamination: {CT['contaminated']:,} of {CT['n_benign']:,} val benign flows ({CT['share']:.4f}) had an attack flow "
          f"on one of their hosts in the previous {CT['window_s']} s. FA on contaminated / clean benign (5-seed mean): " + "; ".join(
              f"{a} {np.mean([CT['arms'][a][str(s)]['contaminated']['fa_count'] for s in o41['seeds']]):.1f} / "
              f"{np.mean([CT['arms'][a][str(s)]['clean']['fa_count'] for s in o41['seeds']]):.1f}" for a in o41["arms"]), "",
          "## Fingerprint ablation (H-C2, every class)", ""]
    for n, h in z42["h_c2"].items():
        L.append(f"- {n}{' (rare)' if h['rare'] else ''}: Δ_flow {np.mean(h['delta_flow']):+.4f}, Δ_ctx {np.mean(h['delta_ctx']):+.4f}, "
                 f"Δ_ctx - Δ_flow {_ci(h['diff'])} -> {h['verdict']}")
    L += ["", "## Zero-day with context (H-C3 and report-only arms)", ""]
    for a, per in z42["arms"].items():
        rs = {}
        for s, v in per.items():
            for p in v["pairs"]:
                rs.setdefault(p["class"], []).append(p["recall"])
        fa = [v["fa"]["fa_count"] for v in per.values()]
        role = " (primary)" if a == z42["primary_arm"] else (" (report-only; not a routing claim, D163)"
                                                              if "PER_GROUP" in a else " (report-only)")
        L.append(f"- {a}{role}: miss-recall "
                 + ", ".join(f"{n} {np.mean(v):.4f}" for n, v in rs.items()) + f"; FA per seed {fa} "
                 f"({np.mean([v['fa']['fa_per_hour'] for v in per.values()]):.2f}/h); detector alone "
                 + ", ".join(f"{p['class']} {np.mean([q['detector_alone'] for v in per.values() for q in v['pairs'] if q['class'] == p['class']]):.4f}"
                             for p in next(iter(per.values()))["pairs"]))
    OOR = z42["out_of_range"]
    L += ["", "- out-of-range diagnostic (share with >= 1 context feature above the train-benign maximum): " + ", ".join(
        f"{k} {v:.4f}" for k, v in OOR.items() if k != "misses") + "; Stage 1 misses (class|seed): " + ", ".join(
        f"{k} {v:.3f}" for k, v in OOR["misses"].items()),
        "- CTX_TAIL_GLOBAL calibration per seed (q, held-out flag rate): " + "; ".join(
            f"s{s} {r[z42['primary_arm']]['q']:.6f} / {r[z42['primary_arm']]['hold_rate']:.5f}" for s, r in z42["rules"].items()),
        "- top firing context features of CTX_TAIL_GLOBAL (seed 0, per true class): "
        + str(z42["arms"][z42["primary_arm"]][str(z42["seeds"][0])].get("top_firing_features"))]
    L += ["", "## TreeSHAP perturbation (Part B)", "",
          "| model | predicted class | n | drop top-k | random-k | bottom-k | top - random [CI] | verdict | context SHAP share | "
          "fingerprint in top-k |", "|---" * 10 + "|"]
    for a, R in p43["models"].items():
        for k, v in R["per_class"].items():
            L.append(f"| {a} | {k} | {v['n']:,} | {v['drop_top']:.4f} | {v['drop_rand']:.4f} | {v['drop_bottom']:.4f} | "
                     f"{_ci(v['diff'])} | {v['verdict']} | {v['ctx_shap_share']:.3f} | {v['fingerprint_in_topk']:.3f} |")
    L += ["", f"Disclosure: {p43['disclosure']}.", "", "## Cost on the dev machine", "",
          f"- context features: {vc['us_per_flow']:.1f} us/flow (pure Python streaming), peak state {vc['peak_hosts']} hosts / "
          f"{vc['peak_pairs']} pairs / {vc['peak_events']:,} window events per segment",
          f"- CTX_TAIL model of normal: {len(D_['fs']['per_feature'])} thresholds (one float per context feature) and an "
          "any-feature comparison per flow; no model file",
          "", "## Limitations (stated in the prereg before any result)", "",
          "1. Same CICIoT2023 testbed: few hosts, attackers are testbed Pis.", "2. val is not fully held out.",
          "3. Context features may partly re-encode what the packet-level rate guard sees (not compared here).",
          "4. Held-out classes are still only floods and scans.",
          "5. Benign flows of a host under attack inherit attack-looking context (measured above, not fixed).",
          "6. 1-second start resolution: sub-second order comes from durations.",
          "7. CTX_TAIL only sees attacks that push some context feature above the benign tail; low-and-slow attacks inside "
          "the benign range are invisible to it; contaminated benign flows raise false alarms (measured).",
          "8. H-C1 is a TCP result (the normaliser swaps TCP flows only).", "",
          "## What this means", ""]
    L += [interpret(D_), "", "## What a runtime stage would need (not built here)", "",
          "- the same `common/context_features.ContextState` fed flow by flow at flow end (it already is streaming and bounded); "
          "per-capture / per-interface segmentation and a policy for state across restarts;",
          "- a cost budget: the Python implementation measured above would need to be vectorised or ported for the Pi;",
          "- eviction monitoring (spoofed floods can exhaust the key caps) and a decision on warm-up behaviour after start;",
          "- re-validation of parity (offline == streaming) exactly as Phase 3 did for the flow path.", "",
          "## Figures", ""] + [f"- `figures/{f}`" for f in figs]
    return "\n".join(L) + "\n"


def interpret(D_) -> str:
    s40, o41, z42 = D_["s40"], D_["o41"], D_["z42"]
    H1, HC2, HC3 = o41["h_c1"]["verdict"], z42["h_c2"][z42["h_c2_class"]]["verdict"], z42["h_c3"]["verdict"]
    RR = o41["real_reversals"]
    seeds = o41["seeds"]
    t = []
    if RR.get("arms"):
        eg = np.mean([RR["arms"]["GLOBAL"][str(s)]["error_rate"] for s in seeds])
        ec = np.mean([RR["arms"]["GLOBAL_CTX"][str(s)]["error_rate"] for s in seeds])
        eo = np.mean([RR["arms"]["CTX_ONLY"][str(s)]["error_rate"] for s in seeds])
        t.append(f"**H1 limitation (SYN/ACK-first reversals).** H-C1 {H1}. On the real reversed flows behind diag_03's "
                 f"misclassified incidents the error rate is {eg:.3f} for GLOBAL, {ec:.3f} for GLOBAL_CTX and {eo:.3f} for "
                 "CTX_ONLY. " + ("Adding context reduces these errors." if ec < eg else "Adding context to the flow features does "
                                 "not reduce these errors: the flow features still dominate the decision on these flows."))
    t.append(f"**Scanner-shortcut finding (Phase 3.1 C).** H-C2 {HC2}: with context features the model "
             + ("loses less" if HC2 == "HOLDS" else "does not reliably lose less")
             + f" {z42['h_c2_class']} recall when the fingerprint features are removed.")
    side = z42["h_c3_rule_on_report_only_arms"]
    t.append(f"**Phase 5A floor effect.** H-C3 {HC3}: the benign-only upper-tail rule on the context features "
             + ("catches at least half of what the 70-feature Stage 1 misses within the false-alarm budget, so volume / fan-out "
                "context carries the anomaly signal that per-flow features lacked."
                if HC3 == "HOLDS" else f"does not meet the pre-registered bar ({z42['h_c3']['reason']}); see the per-class "
                "miss-recall and false alarms above for how far it moved from the 5A floor.")
             + f" The 5A IsolationForest recipe on the same context features (CTX_IF_GLOBAL, report-only) gives "
               f"{side['CTX_IF_GLOBAL']['verdict']} with miss-recall {side['CTX_IF_GLOBAL']['recall']['mean']:.4f}, which "
               "shows how much of the outcome is the detector rather than the features.")
    t.append(f"**Non-inferiority** of GLOBAL_CTX: {s40['noninferiority']['status']}.")
    return "\n\n".join(t)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    for s in ("39", "40", "41", "42", "43"):
        ap.add_argument(f"--run-{s}", default=None)
    args = ap.parse_args()
    cfg = CC.load_phase5b_config()
    ups = {s: PR.resolve(s, getattr(args, f"run_{s}"), args.dry_run) for s in ("39", "40", "41", "42", "43")}
    phase = PR.PHASE5B_RESULTS
    if not args.dry_run and not args.rerun_tag:
        for p in (phase / "summary.md", phase / "figures"):
            if p.exists():
                raise PR.RunRefused(f"{p} exists (never overwritten; use --rerun-tag)")
    run = PR.P5BRun("44", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/plot_style.py"])
    PR.lock_banner(run, M, "start")
    ok = False
    try:
        rd = lambda s, f: json.loads((ups[s]["dir"] / f).read_text(encoding="utf-8"))  # noqa: E731
        D_ = {"m39": ups["39"]["manifest"], "fs": rd("39", "feature_summary.json"), "s40": rd("40", "stage1.json"),
              "o41": rd("41", "orientation.json"), "z42": rd("42", "zeroday.json"), "p43": rd("43", "perturbation.json")}
        runs = {s: u["meta"]["run_id"] for s, u in ups.items()}
        runs["44"] = run.run_id
        M["inputs"] = {s: {"run_id": u["meta"]["run_id"], "manifest_sha256": u["manifest_sha256"]} for s, u in ups.items()}
        figs = make_figures(run.fig, cfg, D_)
        txt = summary(cfg, D_, runs, figs)
        (run.res / "phase_summary.md").write_text(txt, encoding="utf-8")
        if not args.dry_run and not args.rerun_tag:
            (phase / "summary.md").write_text(txt, encoding="utf-8")
            shutil.copytree(run.fig, phase / "figures")
        run.log(f"  figures {figs}")
        PR.lock_banner(run, M, "end")
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    (run.res / "summary.md").write_text(f"# Step 44 -- report -- {'PASS' if ok else 'FAIL'}\n\n" +
                                        (f"```\n{M['error']}\n```\n" if M.get("error") else "see phase_summary.md\n"),
                                        encoding="utf-8")
    run.finish(ok, M)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
