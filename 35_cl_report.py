#!/usr/bin/env python
"""35_cl_report.py -- Phase 4 step H: figures + results/phase4/summary.md from the step 31-34 runs (no data is read;
no model is scored). Figures (results/phase4/figures/, 300 dpi, common/plot_style; refused if they exist):
  split_composition.png       flows per class x group in val-A vs val-B
  recall_per_arm.png          val-B per-class recall per system (5-seed mean, 95 % t-CI), one panel per non-rare class
  forgetting.png              S2: forgetting per unlabelled group (pooled + each); S1: forgetting per class
  time_vs_macro_f1.png        retrain wall time vs val-B non-rare macro-F1 per arm
  gate_outcomes.png           gate PASS / FAIL per arm x seed (failing condition in the cell)
  poisoning.png               validator check (c) rate per batch vs its threshold + gate outcome if used anyway
  feedback_bias.png           val-A misses labelled with vs without the random sample; recall on R0's val-B misses
  loop_diagram.png            the end-to-end loop with its trust zones
--dry-run: needs --eval-run <dry step 34 run id>; writes results/phase4/35/dry_run/<run_id>/ only.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

import numpy as np

from common import cl_config as CC
from common import cl_run as CR
from common import plot_style as PS
from common import schemas as S

SCRIPT = "35_cl_report.py"
PRIMARY = ("R1", "R2", "R3", "S2_GLOBAL", "S2_SPEC")
LABEL = {"R0": "R0 no retrain (deployed)", "ROUTED_v21": "v2_1 ROUTED (reference)", "R1": "R1 full retrain",
         "R2": "R2 warm start + replay", "R3": "R3 warm start, labels only", "S2_GLOBAL": "S2-GLOBAL (G labels)",
         "S2_SPEC": "S2-specialist (ROUTED)"}


def lab(a: str, grp: str = "") -> str:
    if a in LABEL:
        return LABEL[a].replace("(G labels)", f"({grp} labels)" if grp else "(labels)").replace("specialist", f"{grp}" if grp else "spec")
    return a.replace("R2__", "R2 on ")


def ci_err(a: dict) -> tuple[float, float]:
    m, lo, hi = a["mean"], a.get("lo"), a.get("hi")
    if lo is None or hi is None or not np.isfinite(lo) or not np.isfinite(hi):
        return 0.0, 0.0
    return max(m - lo, 0.0), max(hi - m, 0.0)


def repel(ys: list, min_gap: float) -> list:
    """Label positions >= min_gap apart, as close as possible to ys (simple sweep, order kept)."""
    o = np.argsort(ys)
    pos = np.array(ys, float)[o].copy()
    for i in range(1, len(pos)):
        pos[i] = max(pos[i], pos[i - 1] + min_gap)
    shift = (pos - np.array(ys, float)[o]).mean()
    pos -= shift / 2
    for i in range(1, len(pos)):
        pos[i] = max(pos[i], pos[i - 1] + min_gap)
    out = np.empty(len(ys))
    out[o] = pos
    return out.tolist()


# --------------------------------------------------------------------------- figures
def fig_split(path, counts, names):
    import matplotlib.pyplot as plt
    groups = [g for g in counts["val_A"] if g != "_all"]
    fig, axes = plt.subplots(1, len(groups), figsize=(3.0 * len(groups) + 0.8, 2.9), sharey=True, squeeze=False)
    y = np.arange(len(names))
    for ax, g in zip(axes[0], groups):
        a = [counts["val_A"][g][n] for n in names]
        b = [counts["val_B"][g][n] for n in names]
        ax.barh(y - 0.19, [v if v else np.nan for v in a], height=0.36, color=PS.NEUTRAL_LIGHT, label="val-A (labelled)")
        ax.barh(y + 0.19, [v if v else np.nan for v in b], height=0.36, color=PS.TEXT2, label="val-B (judged)")
        ax.set_xscale("log")
        mx = max([v for v in a + b if v] or [10])
        ax.set_xlim(0.8, mx * 30)
        for yy, va_, vb in zip(y, a, b):
            ax.text(va_ * 1.15 if va_ else 1, yy - 0.19, f"{va_:,}", va="center", fontsize=7, color=PS.TEXT2)
            ax.text(vb * 1.15 if vb else 1, yy + 0.19, f"{vb:,}", va="center", fontsize=7, color=PS.TEXT1)
        ax.set_title(f"group {g}", loc="left")
        ax.set_xlabel("flows (log)")
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
    axes[0][0].set_yticks(y, names)
    axes[0][0].invert_yaxis()
    axes[0][-1].legend(frameon=False, loc="lower right", fontsize=7.5)
    fig.suptitle("Phase 4 split: val-A (operator labels) vs val-B (every model judged), flows per class x group",
                 x=0.01, ha="left", y=1.02)
    return PS.save(fig, path)


def fig_recall(path, ev, names, grp):
    import matplotlib.pyplot as plt
    T = ev["table"]
    nonrare = [names.index(n) for n in ev["nonrare"]]
    systems = ["R0", "ROUTED_v21"] + [a for a in ev["arms"]]
    fig, axes = plt.subplots(1, len(nonrare), figsize=(2.9 * len(nonrare) + 2.4, 0.32 * len(systems) + 1.3),
                             sharey=True, squeeze=False)
    y = np.arange(len(systems))
    for ax, k in zip(axes[0], nonrare):
        ms = [T[s]["all"]["recall"][k] for s in systems]
        m = np.array([a["mean"] for a in ms])
        err = np.array([ci_err(a) for a in ms]).T
        ax.errorbar(m, y, xerr=err, fmt="o", ms=4.5, color=PS.class_color(k), ecolor=PS.class_color(k), elinewidth=1.4,
                    capsize=0)
        ax.axvline(T["R0"]["all"]["recall"][k]["mean"], color=PS.TEXT2, lw=0.7, ls=":")
        lo = np.nanmin(m - err[0])
        ax.set_xlim(max(0.0, lo - (1 - lo) * 0.25 - 0.002), 1.0 + (1 - lo) * 0.05 + 0.0005)
        ax.set_title(f"{names[k]} (n = {ev['val_B']['support'][names[k]]:,})", loc="left")
        ax.set_xlabel("val-B recall")
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", labelsize=7.5)
    axes[0][0].set_yticks(y, [lab(s, grp) for s in systems], fontsize=8)
    axes[0][0].invert_yaxis()
    fig.suptitle("Per-class recall on val-B (5-seed mean, 95 % t-CI; dotted = R0). Experiment arms below the primary ones.",
                 x=0.01, ha="left", y=1.0)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_forgetting(path, ev, V, names, grp):
    import matplotlib.pyplot as plt
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10.4, 3.4), gridspec_kw={"width_ratios": [1, 1.25]})
    rows = [("pooled " + "+".join(V["other_groups"]), V["forgetting_S2_GLOBAL"], V["forgetting_S2_SPEC"])]
    for g, d in V["per_group_forgetting"].items():
        rows.append((f"group {g}", d["S2_GLOBAL"], d["S2_SPEC"]))
    ylab, vals = [], []
    for name, gl, pg in rows:
        ylab += [f"{name}: S2-GLOBAL", f"{name}: S2-{grp} (0 by construction)"]
        vals += [gl, pg]
    y = np.arange(len(vals))
    m = np.array([v["mean"] for v in vals])
    err = np.array([ci_err(v) for v in vals]).T
    a1.errorbar(m, y, xerr=err, fmt="o", ms=4.5, color=PS.TEXT1, ecolor=PS.TEXT2, capsize=0, elinewidth=1.3)
    a1.axvline(0, color=PS.TEXT2, lw=0.8)
    tol = 0.002
    a1.axvspan(-tol, tol, color=PS.GRID, zorder=0)
    span = max(np.nanmax(np.abs(m) + err.max(0)), 0.004)
    a1.set_xlim(-span * 1.3, span * 1.3)
    a1.set_yticks(y, ylab, fontsize=7.5)
    a1.invert_yaxis()
    a1.set_xlabel("forgetting = non-rare macro-F1 before - after")
    a1.set_title(f"S2: groups without labels (band = +-{tol})", loc="left", fontsize=9)
    s1 = ev["forgetting_s1"]
    arms = [a for a in ("R1", "R2", "R3") if a in s1]
    cls = list(s1[arms[0]].keys()) if arms else []
    y2, lab2, m2, e2, col = [], [], [], [], []
    i = 0
    for c in cls:
        for a in arms:
            d = s1[a][c]
            y2.append(i)
            lab2.append(f"{c}: {a}")
            m2.append(d["mean"])
            e2.append(ci_err(d))
            col.append(PS.class_color(names.index(c)))
            i += 1
        i += 0.6
    e2 = np.array(e2).T
    for yy, mm, lo, hi, cc in zip(y2, m2, e2[0], e2[1], col):
        a2.errorbar([mm], [yy], xerr=[[lo], [hi]], fmt="o", ms=4.5, color=cc, ecolor=cc, capsize=0, elinewidth=1.3)
    a2.axvline(0, color=PS.TEXT2, lw=0.8)
    span2 = max(np.nanmax(np.abs(np.array(m2)) + e2.max(0)), 0.002) if m2 else 0.01
    a2.set_xlim(-span2 * 1.3, span2 * 1.3)
    a2.set_yticks(y2, lab2, fontsize=7.5)
    a2.invert_yaxis()
    a2.set_xlabel("forgetting = F1(R0) - F1(arm), val-B")
    a2.set_title("S1: per non-rare class (positive = performance lost)", loc="left", fontsize=9)
    for ax in (a1, a2):
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", labelsize=7.5)
    fig.tight_layout(w_pad=2.5)
    return PS.save(fig, path)


def fig_time(path, ev, grp):
    """Retrain time vs val-B non-rare macro-F1 per arm, as two aligned dot panels (rows = arms; no leader lines)."""
    import matplotlib.pyplot as plt
    T = ev["table"]
    sy = ["R0"] + [a for a in PRIMARY if a in T]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(8.4, 0.42 * len(sy) + 1.3), sharey=True)
    y = np.arange(len(sy))
    for ax, key, sub, xl, fmt in ((a1, "fit_seconds", "cost", "retrain wall time, s (fixed threads)", "{:.1f} s"),
                                  (a2, "macro_f1_nonrare", "all", "val-B non-rare macro-F1", "{:.5f}")):
        vals = [T[a][sub][key] for a in sy]
        m = np.array([v["mean"] for v in vals])
        err = np.array([ci_err(v) for v in vals]).T
        ax.errorbar(m, y, xerr=err, fmt="o", ms=5, color=PS.TEXT1, ecolor=PS.NEUTRAL_LIGHT, elinewidth=1.4, capsize=0)
        hi = np.nanmax(m + err[1])
        lo = np.nanmin(m - err[0])
        pad = (hi - lo) * 0.45 if hi > lo else 1.0
        for yy, mm, e in zip(y, m, err[1]):
            ax.text(mm + e + pad * 0.06, yy - 0.28, fmt.format(mm), fontsize=7, color=PS.TEXT2, va="center")
        ax.set_xlim(lo - pad * 0.15, hi + pad)
        ax.set_xlabel(xl)
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", labelsize=7.5)
    a1.set_yticks(y, [lab(a, grp) for a in sy], fontsize=8)
    a1.invert_yaxis()
    fig.suptitle("Cost vs accuracy per arm (5-seed mean, 95 % t-CI; R0 = no retrain)", x=0.01, ha="left", y=1.0)
    fig.tight_layout(w_pad=2.0)
    return PS.save(fig, path)


def fig_gate(path, gate, ev, grp):
    import matplotlib.pyplot as plt
    seeds = ev["seeds"]
    systems = ["ROUTED_v21"] + list(ev["arms"])
    fig, ax = plt.subplots(figsize=(1.55 * len(seeds) + 2.6, 0.36 * len(systems) + 1.1))
    for i, a in enumerate(systems):
        for j, s in enumerate(seeds):
            g = gate[f"{a}|{s}"]
            ok = g["pass"]
            why = []
            C = g["conditions"]
            if not C["i_recall"]["pass"]:
                why.append("i")
            if not C["ii_macro_f1_nonrare"]["pass"]:
                why.append("ii")
            if not C["iii_fa_per_hour"]["pass"]:
                why.append("iii")
            ax.add_patch(plt.Rectangle((j + 0.04, i + 0.06), 0.92, 0.88, color=PS.GRID if ok else PS.TEXT2, lw=0))
            ax.text(j + 0.5, i + 0.5, "PASS" if ok else "FAIL " + ",".join(why), ha="center", va="center", fontsize=7.5,
                    color=PS.TEXT1 if ok else "white")
    ax.set_xlim(0, len(seeds))
    ax.set_ylim(len(systems), 0)
    ax.set_xticks(np.arange(len(seeds)) + 0.5, [f"seed {s}" for s in seeds])
    ax.set_yticks(np.arange(len(systems)) + 0.5, [lab(a, grp) for a in systems], fontsize=8)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title("Regression gate vs the deployed FLAT_GLOBAL (same seed, val-B); FAIL lists the failing condition",
                 loc="left", fontsize=9)
    return PS.save(fig, path)


def fig_poison(path, val32, poison, gate, ev, thr):
    import matplotlib.pyplot as plt
    seeds = ev["seeds"]
    keys = list(val32)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 0.34 * len(keys) + 1.6), gridspec_kw={"width_ratios": [1.4, 1]},
                                 sharey=True)
    y = np.arange(len(keys))
    r = [val32[k]["checks"]["c_confident_disagreement"].get("rate", np.nan) for k in keys]
    a1.barh(y, r, height=0.55, color=[PS.TEXT2 if val32[k]["status"] == "QUARANTINED" else PS.NEUTRAL_LIGHT for k in keys])
    a1.axvline(thr, color=PS.CATEGORICAL[1], lw=1.2)
    a1.text(thr, -0.75, f" threshold {thr:.0%}", color=PS.TEXT1, fontsize=7.5, va="center")
    for yy, v, k in zip(y, r, keys):
        a1.text(max(v, thr) + max(r) * 0.02, yy, f"{v:.2%}  {val32[k]['status']}", va="center", fontsize=7.5)
    a1.set_xlim(0, max(max(r), thr) * 1.6)
    a1.set_ylim(len(keys) - 0.4, -1.2)
    a1.set_yticks(y, keys, fontsize=8)
    a1.set_xlabel("check (c) rate: labels vs confident (p >= 0.99) predictions")
    a1.set_title("Validator per label batch (dark = quarantined)", loc="left", fontsize=9)
    pc = []
    for k in keys:
        a = "R2" if k == "primary" else f"R2__{k}"
        pc.append(sum(gate[f"{a}|{s}"]["pass"] for s in seeds) if f"{a}|{seeds[0]}" in gate else np.nan)
    a2.barh(y, pc, height=0.55, color=PS.NEUTRAL_LIGHT)
    for yy, v, k in zip(y, pc, keys):
        txt = f"{v:.0f}/{len(seeds)} PASS" + (f"  -> {poison[k]['verdict']}" if k in poison else "")
        a2.text((0 if np.isnan(v) else v) + 0.12, yy, txt, va="center", fontsize=7.5)
    a2.set_xlim(0, len(seeds) * 2.6)
    a2.set_xticks(range(len(seeds) + 1))
    a2.set_xlabel("seeds passing the gate (R2 on the batch)")
    a2.set_title("Gate if the batch were used anyway", loc="left", fontsize=9)
    for ax in (a1, a2):
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
    fig.tight_layout(w_pad=3.0)
    return PS.save(fig, path)


def fig_feedback(path, fb, names):
    import matplotlib.pyplot as plt
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.4, 2.9), gridspec_kw={"width_ratios": [1, 1.3]})
    vals = [fb["val_A_missed_attack_flows"], fb["labelled_with_random"], fb["labelled_without_random"]]
    labs = ["val-A missed attack flows", "labelled, queue with random 5 %", "labelled, alerts-only queue"]
    y = np.arange(3)
    a1.barh(y, vals, height=0.55, color=[PS.TEXT2, PS.NEUTRAL_LIGHT, PS.NEUTRAL_LIGHT])
    for yy, v in zip(y, vals):
        a1.text(v + max(vals + [1]) * 0.02, yy, f"{v:,}", va="center", fontsize=8)
    a1.set_xlim(0, max(vals + [1]) * 1.3)
    a1.set_yticks(y, labs, fontsize=8)
    a1.invert_yaxis()
    a1.set_xlabel("flows")
    a1.set_title("Missed attacks reaching the operator", loc="left", fontsize=9)
    rows = []
    for c, r in fb["recall_val_B"].items():
        rows += [(f"{c}: with random", r["recall_on_R0_misses_with_random"], names.index(c)),
                 (f"{c}: alerts only", r["recall_on_R0_misses_without_random"], names.index(c))]
    if rows:
        y2 = np.arange(len(rows))
        for yy, (_, a, k) in zip(y2, rows):
            lo, hi = ci_err(a)
            a2.errorbar([a["mean"]], [yy], xerr=[[lo], [hi]], fmt="o", ms=5, color=PS.class_color(k),
                        ecolor=PS.class_color(k), capsize=0)
        a2.set_yticks(y2, [r[0] for r in rows], fontsize=8)
        a2.invert_yaxis()
        a2.set_xlim(-0.05, 1.05)
    a2.set_xlabel("R2 recall on the val-B flows R0 misses (5-seed mean, CI)")
    a2.set_title("Does retraining fix the deployed model's misses?", loc="left", fontsize=9)
    for ax in (a1, a2):
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
    fig.tight_layout(w_pad=2.0)
    return PS.save(fig, path)


def fig_loop(path):
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    fig, ax = plt.subplots(figsize=(10.0, 6.0))
    ax.set_xlim(-4, 103)
    ax.set_ylim(0, 60)
    ax.axis("off")
    zones = [(1, 32, 30, 23, "Pi runtime (never trains)", "left"),
             (34, 32, 30, 23, "Operator (human review)", "left"),
             (1, 1, 63, 28, "Offline training host (scripts 31-34)", "right"),
             (67, 1, 32, 54, "Model registry (signed entries)", "left")]
    for x, y, w, h, t, al in zones:
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.2,rounding_size=1.2", fc=PS.SURFACE,
                                    ec=PS.TEXT2, lw=0.9, ls="--"))
        ax.text(x + 1.2 if al == "left" else x + w - 1.2, y + h - 1.4, t, fontsize=7.8, color=PS.TEXT2, va="top",
                ha=al, weight="bold")
    boxes = {"rt": (3, 34, 26, 13, "runtime: route -> normalise ->\npredict -> calibrate -> policy\n"
                                   "(loads only signed,\nPROMOTED entries)"),
             "q": (36, 41, 26, 7, "review queue (runtime predictions):\nall alerts + seeded random 5 %"),
             "op": (36, 34, 26, 5.5, "labels -> Ed25519-signed batch\n(operator key)"),
             "val": (3, 14, 18, 7, "validator: (a) sig / hash\n(b) class map\n(c) confident disagreement"),
             "tr": (23, 14, 19, 7, "retrain arms R1-R3, S2\n(+ replay buffer)"),
             "gate": (44, 14, 18, 7, "regression gate on val-B\n(i) recall (ii) F1 (iii) FA/h"),
             "rej": (44, 3, 18, 7, "REJECTED\n(logged with reason)"),
             "quar": (3, 3, 18, 7, "QUARANTINED\n(human review)"),
             "cand": (69, 12, 28, 9, "CANDIDATE entry\n(signed, tagged phase4)"),
             "prom": (69, 38, 28, 9, "PROMOTED entry\n(the deployed model)")}
    for k, (x, y, w, h, t) in boxes.items():
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=0.8",
                                    fc=PS.GRID if k not in ("rej", "quar") else PS.SURFACE, ec=PS.TEXT1, lw=0.8))
        ax.text(x + w / 2, y + h / 2, t, ha="center", va="center", fontsize=7.2)

    def pt(k, r):
        x, y, w, h, _ = boxes[k]
        return (x + w * r[0], y + h * r[1])

    def arrow(p, q):
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=9, color=PS.TEXT2, lw=0.9))

    def note(x, y, t, ha="center"):
        ax.text(x, y, t, fontsize=6.8, color=PS.TEXT2, ha=ha, va="center")

    arrow(pt("rt", (1, 0.75)), pt("q", (0, 0.5)))
    arrow(pt("q", (0.5, 0)), pt("op", (0.5, 1)))
    arrow(pt("op", (0.3, 0)), pt("val", (0.6, 1)))
    note(31, 30.4, "signed labels")
    arrow(pt("val", (1, 0.5)), pt("tr", (0, 0.5)))
    note(22, 22.4, "VALID")
    arrow(pt("val", (0.5, 0)), pt("quar", (0.5, 1)))
    note(13.5, 12, "fired", ha="left")
    arrow(pt("tr", (1, 0.5)), pt("gate", (0, 0.5)))
    arrow(pt("gate", (0.5, 0)), pt("rej", (0.5, 1)))
    note(54.5, 12, "FAIL", ha="left")
    arrow(pt("gate", (1, 0.5)), pt("cand", (0, 0.5)))
    note(53, 23.6, "PASS (seed 0) -> registry")
    arrow(pt("cand", (0.5, 1)), pt("prom", (0.5, 0)))
    note(82, 29.5, "human approve + promote\n(not in Phase 4)", ha="right")
    # promoted model -> Pi: routed around the outside of every zone (no title is crossed)
    x0, y0 = pt("prom", (1, 0.5))
    x1, y1 = pt("rt", (0, 0.5))
    ax.plot([x0, 101.5, 101.5, -2.5, -2.5], [y0, y0, 57.5, 57.5, y1], color=PS.TEXT2, lw=0.9)
    arrow((-2.5, y1), (x1, y1))
    ax.text(50, 57.5, " signed model load (promoted only) ", fontsize=6.8, color=PS.TEXT2, ha="center", va="center",
            bbox={"fc": PS.SURFACE, "ec": "none", "pad": 0.5})
    ax.set_title("LG-IDS V2 continual-learning loop and its trust zones (Phase 4 runs the offline part; the Pi never trains)",
                 loc="left", fontsize=9.5)
    return PS.save(fig, path)


# --------------------------------------------------------------------------- summary
def _f(a, fmt="{:.4f}"):
    if a is None:
        return "-"
    s = fmt.format(a["mean"])
    lo, hi = a.get("lo"), a.get("hi")
    if lo is not None and hi is not None and np.isfinite(lo) and np.isfinite(hi):
        s += " [" + fmt.format(lo) + ", " + fmt.format(hi) + "]"
    return s


def summary(ev, V, poison, fb, reg, rej, m31, m32, m33, figs, names, grp, cfg4) -> str:
    T = ev["table"]
    sp = m31["split"]
    L = ["# LG-IDS V2 Phase 4 -- continual learning loop (val only) -- summary", "",
         f"Runs: step 31 `{m31['run_id']}`, 32 `{m32['run_id']}`, 33 `{m33['run_id']}`, 34 (see results/phase4/34/). "
         f"Pre-registration `docs/V2_PREREG_PHASE4.md` sha256 `{S.PREREG_PHASE4_SHA256}`, config `config/v2_phase4.json` "
         f"sha256 `{S.V2_PHASE4_CONFIG_SHA256}`. The test split was never read. Nothing was approved or promoted.", "",
         "## Split", "",
         f"- val-A {sp['n']['val_A']:,} flows (labelled live period), val-B {sp['n']['val_B']:,} flows (judging set); "
         f"val-B support {sp['val_B_support']}; rare for the gate (< {sp['min_val_flows']}): {sp['rare_for_gate']}", "",
         "## Loop", "",
         f"- runtime on val-A: parity exact ({m31['parity'].get('class_agree', 0):,} / {m31['parity'].get('n_runtime', 0):,} "
         f"classes, max |dp| {m31['parity'].get('max_abs_dp', float('nan')):.1e}, features identical "
         f"{m31['parity'].get('features_equal_rows', 0):,})"]
    for q, mm in m31["queues"].items():
        L.append(f"- queue `{q}`: {mm['n']:,} items (alerts {mm['n_alert']:,}, random {mm['n_random']:,})")
    for k, b in m32["batches"].items():
        L.append(f"- batch `{b['batch_id']}`: {b['n']:,} labels, accuracy vs truth {b['label_accuracy_vs_truth']:.4f}, "
                 f"validator **{m32['validation'][k]['status']}** {m32['validation'][k]['fired'] or ''}")
    L += ["", "## Headline per arm (val-B, 5-seed mean [95 % t-CI])", "",
          "| system | non-rare macro-F1 | diff vs R0 | FA / h | " + " | ".join(f"recall {n}" for n in ev["nonrare"])
          + " | retrain s | peak RSS MB | gate PASS / seeds |", "|" + "---|" * (7 + len(ev["nonrare"]))]
    for a in ["R0", "ROUTED_v21"] + list(ev["arms"]):
        r = T[a]
        c = r.get("cost", {})
        L.append(f"| {lab(a, grp)} | {_f(r['all']['macro_f1_nonrare'], '{:.5f}')} | "
                 f"{_f(r['all']['vs_R0']['macro_f1_nonrare'], '{:+.5f}') if a != 'R0' else '-'} | "
                 f"{_f(r['all']['fa_per_hour'], '{:.3f}')} | "
                 + " | ".join(_f(r["all"]["recall"][names.index(n)]) for n in ev["nonrare"])
                 + f" | {_f(c.get('fit_seconds'), '{:.2f}') if c.get('fit_seconds') else '-'} | "
                 f"{_f(c.get('peak_rss_mb'), '{:.0f}') if c.get('peak_rss_mb') else '-'} | "
                 + (f"{r['gate']['pass_count']}/{r['gate']['of']}" if r.get("gate") else "deployed") + " |")
    L += ["", "## Amendment 2 section 4 verdict", "", f"**{V['verdict']}** ({V['rule']}).", "",
          f"- forgetting (non-rare macro-F1 drop on the unlabelled groups {V['other_groups']}): S2-GLOBAL "
          f"{_f(V['forgetting_S2_GLOBAL'], '{:+.5f}')}, S2-{grp} {_f(V['forgetting_S2_SPEC'], '{:+.5f}')}; "
          f"difference {_f(V['forgetting_diff_pg_minus_global'], '{:+.5f}')}",
          f"- retrain time S2-{grp} {V['time_mean_s']['per_group']:.2f} s vs S2-GLOBAL {V['time_mean_s']['global']:.2f} s "
          f"(global / per-group = {V['time_ratio_global_over_per_group']:.2f}, needs >= {cfg4['verdict']['time_ratio']})",
          f"- affected group {grp}: S2-{grp} {_f(V['affected_group_macro_f1']['S2_SPEC'], '{:.5f}')}, S2-GLOBAL "
          f"{_f(V['affected_group_macro_f1']['S2_GLOBAL'], '{:.5f}')}",
          f"- **{V['note']}**", f"- kill rule (Amendment 2 section 5): {V['kill_rule_section_5']}", "",
          "## Poisoning", ""]
    for k, p in poison.items():
        L.append(f"- {k} ({p['poison']['target_class']} -> {p['poison']['flipped_to']}, {p['poison']['n_flipped']:,} of "
                 f"{p['poison']['n_target']:,} labels): validator {p['validator']} {p['fired']}; R2 on it passes the gate in "
                 f"{p['gate_pass_count']}/{len(p['gate_if_used'])} seeds -> **{p['verdict']}**")
    if fb:
        L += ["", "## Feedback bias", "",
              f"- val-A attack flows the deployed model did not alert on: {fb['val_A_missed_attack_flows']:,} "
              f"{fb['missed_by_class']}; labelled with the random 5 %: {fb['labelled_with_random']:,}; without: "
              f"{fb['labelled_without_random']:,}"]
        for c, r in fb["recall_val_B"].items():
            L.append(f"- {c}: R2 val-B recall with random {_f(r['R2_with_random'])}, alerts only {_f(r['R2_without_random'])}; "
                     f"on R0's val-B misses: with {_f(r['recall_on_R0_misses_with_random'])}, without "
                     f"{_f(r['recall_on_R0_misses_without_random'])}")
    L += ["", "## Registry", ""] + [f"- CANDIDATE `{r['entry_id']}` ({r['arm']})" for r in reg["registered"]]
    L += [f"- REJECTED {r['arm']} seed {r['seed']}: {r['reason']}" for r in rej["rejected"]]
    L += ["", "## What Phase 4 shows, and what needs real operators", "",
          "- Shown (val, simulated operator): the loop runs end to end with the Pi runtime unchanged (exact parity); labels "
          "are signed, append-only and refused when tampered; the validator and the gate behave as pre-registered on "
          "clean, noisy, budget-limited and poisoned batches; retrained models enter the registry only as signed "
          "candidates; the cost and forgetting of each retraining strategy on this data.",
          "- Not shown: real operator accuracy, latency, fatigue or bias (labels here are ground truth, uniform noise or a "
          "designed flip); label budgets in a real SOC; drift beyond the val window (val-B is the second half of the same "
          "captures, and val was used for Phase 2 selection and the deployed temperature); a poisoning attacker who knows "
          "the validator's 0.99 / 5 % rule and stays under it; any test-split number.", "",
          "## Figures", ""] + [f"- `{f}`" for f in figs]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--eval-run", default=None)
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg4 = CC.load_phase4_config()
    up34 = CR.resolve("34", args.eval_run, args.dry_run)
    up33 = CR.resolve("33", up34["manifest"]["retrain_run"], args.dry_run)
    up32 = CR.resolve("32", up34["manifest"]["labels_run"], args.dry_run)
    up31 = CR.resolve("31", up34["manifest"]["queue_run"], args.dry_run)
    run = CR.Run("35", SCRIPT, cfg4, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest()
    CR.lock_banner(run, M, "start")
    ok = False
    try:
        PS.apply()
        names = list(S.load_class_map().names)
        rd = lambda u, f: json.loads((u["dir"] / f).read_text(encoding="utf-8"))  # noqa: E731
        ev, gate, vd = rd(up34, "eval.json"), rd(up34, "gate.json"), rd(up34, "verdict.json")
        reg, rej, val32 = rd(up34, "registry.json"), rd(up34, "rejected.json"), rd(up32, "validation.json")
        V, poison, fb = vd["amendment_2_section_4"], vd["poisoning"], vd["feedback_bias"]
        grp = V["label_group"]
        # a re-run (e.g. a figure fix) writes a complete new set under results/phase4/<tag>/; the first set is kept
        top = run.res / "phase4" if args.dry_run else (CR.PHASE4_RESULTS / args.rerun_tag if args.rerun_tag
                                                       else CR.PHASE4_RESULTS)
        figd = top / "figures"
        out = []
        out.append(fig_split(figd / "split_composition.png", ev["split_counts"], names))
        out.append(fig_recall(figd / "recall_per_arm.png", ev, names, grp))
        out.append(fig_forgetting(figd / "forgetting.png", ev, V, names, grp))
        out.append(fig_time(figd / "time_vs_macro_f1.png", ev, grp))
        out.append(fig_gate(figd / "gate_outcomes.png", gate, ev, grp))
        out.append(fig_poison(figd / "poisoning.png", val32, poison, gate, ev, cfg4["validator"]["max_confident_disagreement"]))
        if fb:
            out.append(fig_feedback(figd / "feedback_bias.png", fb, names))
        out.append(fig_loop(figd / "loop_diagram.png"))
        rel = [str(Path(p).relative_to(top)) for p in out]
        txt = summary(ev, V, poison, fb, reg, rej, up31["manifest"], up32["manifest"], up33["manifest"], rel, names, grp, cfg4)
        sp = top / "summary.md"
        with open(sp, "x", encoding="utf-8") as fh:
            fh.write(txt)
        M.update({"figures": [str(p) for p in out], "summary": str(sp), "eval_run": up34["meta"]["run_id"]})
        run.check(M, "figures + summary written (never overwritten)", True, f"{len(out)} figures -> {figd}")
        CR.lock_banner(run, M, "end")
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    (run.res / "summary.md").write_text(f"# Step 35 -- Phase 4 figures + summary -- {'PASS' if ok else 'FAIL'}\n\n"
                                        + (f"```\n{M['error']}\n```\n" if M.get("error") else
                                           f"- summary: `{M.get('summary')}`\n- figures: {M.get('figures')}\n"), encoding="utf-8")
    run.finish(ok, M)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
