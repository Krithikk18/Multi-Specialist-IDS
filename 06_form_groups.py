#!/usr/bin/env python
"""06_form_groups.py -- propose behaviour groups from device fingerprints (Step 6, part 2).

Inputs (never modified):
  fingerprints   results/step6/device_fingerprints.csv   (raw features + metadata, from 05)
  kept features  results/step6/kept_features.txt          (features retained by 05's pruning)
  flows          data/interim/flows/benign/benign_flows_tagged.csv  (bootstrap only)
  05 script      05_profile_devices.py  (imported; bootstrap fingerprints use ITS functions)

Outputs (<out-dir>):
  cluster_input.csv            metadata + final scaled, clipped cluster-input features
  groups_k{k}.csv              memberships for each candidate k
  group_report.md / .json      metrics, candidates, cross-checks, stability, profiles,
                               known-pair table, figure captions, run metadata
  figures/fig5..fig9 .pdf/.png paper figures (vector PDF + 300-dpi PNG)

Method
  Scaling   fit on high-confidence devices: z = (x - median) / IQR; if IQR < 1e-9 or
            IQR < 0.1 * (p95 - p5) the scale is (p95 - p5); if that is ~0, std. Clip +-3.
  Cluster   Ward linkage (Euclidean) over the high-confidence devices, k = k-min..k-max.
  Choose k  silhouette, Calinski-Harabasz, Davies-Bouldin, Ward merge-height gap; a k is
            feasible only if every group has >= min-group-flows usable flows. Top 3 feasible
            by mean metric rank become candidates; nothing is locked here.
  Checks    ARI vs Ward for k-means, average-linkage/correlation, Ward without
            median_packets; bootstrap over flows (fingerprints recomputed with 05's code,
            rescaled with the SAME fitted scaler); leave-one-feature-out.
  Low conf  low-confidence devices are assigned to the nearest group centroid and flagged.

config/device_table.csv is NOT touched: groups are proposed here and locked after review.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd
import scipy
import sklearn
from scipy.cluster.hierarchy import dendrogram, fcluster, linkage
from scipy.optimize import linear_sum_assignment
from scipy.spatial.distance import pdist
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import (adjusted_rand_score, calinski_harabasz_score,
                             davies_bouldin_score, silhouette_score)

ROOT = Path(__file__).resolve().parent

# Reuse 05 (and through it 02) so fingerprints, style, colours and helpers are identical.
_spec = importlib.util.spec_from_file_location("profile_devices", ROOT / "05_profile_devices.py")
m05 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m05)
log, fatal, sha256, jsonable, md_table = m05.log, m05.fatal, m05.sha256, m05.jsonable, m05.md_table
LABEL, setup_style, save, cat_handles = m05.LABEL, m05.setup_style, m05.save, m05.cat_handles
plt = m05.plt
from matplotlib.colors import ListedColormap  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

CLIP = 3.0
EPS = 1e-9
SENS_DROP = "median_packets"   # the rho = 0.89 sensitivity case from 05's pruning
LOW_FLAG = "low_confidence"
META = ["mac", "device_name", "category", "vendor_family", "usable_flows", "confidence"]

# Group colours: Paul Tol "muted" (colour-blind aware), distinct in tone from the Okabe-Ito
# category colours; fixed order, assigned by group number (never cycled past 12).
GROUP_COLOURS = ["#332288", "#88CCEE", "#117733", "#DDCC77", "#CC6677", "#44AA99",
                 "#882255", "#999933", "#AA4499", "#6699CC", "#661100", "#888888"]
CAT_MARKERS = ["o", "s", "^", "D", "v", "P", "X", "*"]

# Phrase for a group whose median z is high (+) / low (-) on a feature.
PHRASE = {
    "log_flows_per_hour": ("high flow rate", "low flow rate"),
    "log_median_bytes": ("large payloads", "small payloads"),
    "log_p90_bytes": ("large p90 flows", "small p90 flows"),
    "median_packets": ("many packets/flow", "few packets/flow"),
    "pct_single_packet": ("many single-packet flows", "few single-packet flows"),
    "log_median_duration_us": ("long flows", "short flows"),
    "upload_ratio": ("high upload ratio", "download-heavy"),
    "pct_tcp": ("TCP-heavy", "little TCP"),
    "pct_udp": ("UDP-heavy", "TCP-heavy"),
    "pct_dns": ("DNS-heavy", "little DNS"),
    "pct_discovery": ("mDNS/SSDP-heavy", "little mDNS/SSDP"),
    "gap_cv": ("bursty timing", "regular timing"),
    "pct_internet": ("Internet-facing", "mostly local"),
    "pct_device": ("talks to other devices", "few device peers"),
    "log_distinct_peers": ("many peers", "few peers"),
}
DESC_MIN_Z = 0.5

KNOWN_SETS = {
    "GoSund (4)": lambda d: d["device_name"].str.contains("GoSund", regex=False),
    "ESP plugs (4)": lambda d: d["device_name"].str.contains("ESP plug", regex=False),
    "Teckin/Yutron plugs (4)": lambda d: d["device_name"].str.contains(
        r"^(?:Teckin|Yutron) Plug", regex=True),
    "Lighting": lambda d: d["category"] == "Lighting",
    "Echo family": lambda d: d["device_name"].str.contains(r"Echo", regex=True),
    "Cameras": lambda d: d["category"] == "Camera",
}


# --------------------------------------------------------------------------- scaling

def fit_scaler(hi: pd.DataFrame, kept: list[str]) -> dict:
    params = {}
    for k in kept:
        v = hi[k].dropna()
        med = float(v.median())
        iqr = float(v.quantile(0.75) - v.quantile(0.25))
        spread = float(v.quantile(0.95) - v.quantile(0.05))
        if iqr >= EPS and iqr >= 0.1 * spread:
            kind, scale = "iqr", iqr
        elif spread >= EPS:
            kind, scale = "p95-p5", spread
        else:
            sd = float(v.std())
            kind, scale = ("std", sd) if sd >= EPS else ("unit (all zero)", 1.0)
        params[k] = {"median": med, "iqr": iqr, "p95_minus_p5": spread,
                     "scale_type": kind, "scale": scale}
    return params


def apply_scaler(df: pd.DataFrame, params: dict) -> pd.DataFrame:
    return pd.DataFrame({k: ((df[k] - p["median"]) / p["scale"]).clip(-CLIP, CLIP)
                         for k, p in params.items()}, index=df.index)


# --------------------------------------------------------------------------- clustering

def ward(X: np.ndarray) -> np.ndarray:
    return linkage(X, method="ward", metric="euclidean")


def relabel_by_leaf_order(labels: np.ndarray, leaves: list[int]) -> np.ndarray:
    """Number groups 1..k in order of first appearance along the dendrogram leaves."""
    order = {}
    for i in leaves:
        order.setdefault(labels[i], len(order) + 1)
    return np.array([order[l] for l in labels])


def cut(Z: np.ndarray, k: int) -> np.ndarray:
    return fcluster(Z, k, criterion="maxclust")


def match_stay(base: np.ndarray, other: np.ndarray) -> np.ndarray:
    """Per device: True if it stays in the cluster matched (Hungarian) to its base group."""
    bu, ou = np.unique(base), np.unique(other)
    C = np.array([[np.sum((base == b) & (other == o)) for o in ou] for b in bu])
    r, c = linear_sum_assignment(-C)
    m = {bu[i]: ou[j] for i, j in zip(r, c)}
    return np.array([m.get(b, None) == o for b, o in zip(base, other)])


def summarise(x) -> dict:
    x = np.asarray(x, dtype=float)
    return {"mean": float(x.mean()), "median": float(np.median(x)),
            "p5": float(np.percentile(x, 5)), "min": float(x.min()), "max": float(x.max())}


# --------------------------------------------------------------------------- bootstrap data

def load_usable(flows_path: Path):
    f, _, _ = m05.load_flows(flows_path)
    usable = (f["owner_status"] == "owned") & (f["exclude_reason"] == "")
    u = f[usable].copy()
    if u["ts"].isna().any():
        fatal("unparseable timestamps among usable flows")
    o = m05.orient(u)
    all_ts = f["ts"].dropna()
    hours = (all_ts.max() - all_ts.min()).total_seconds() / 3600.0
    return u, o, hours


# --------------------------------------------------------------------------- figures

def group_colour(g: int) -> str:
    return GROUP_COLOURS[(g - 1) % len(GROUP_COLOURS)]


def fig5_dendrogram(Z, names, cats, labels, k, colors, figdir):
    n = len(names)
    members = [{i} for i in range(n)]
    for a, b, *_ in Z:
        members.append(members[int(a)] | members[int(b)])

    def link_col(i):
        gs = {labels[j] for j in members[i]}
        return group_colour(gs.pop()) if len(gs) == 1 else "#555555"

    fig, ax = plt.subplots(figsize=(10.5, 4.8))
    dn = dendrogram(Z, labels=list(names), ax=ax, link_color_func=link_col, leaf_rotation=90,
                    leaf_font_size=7.5)
    h = (Z[-k, 2] + Z[-(k - 1), 2]) / 2
    ax.axhline(h, ls="--", lw=1, color="#333333")
    ax.text(ax.get_xlim()[0] + 2, h, f"cut: k = {k}", va="bottom", ha="left", fontsize=8.5,
            color="#333333")
    name_cat = dict(zip(names, cats))
    for tl in ax.get_xticklabels():
        tl.set_color(colors[name_cat[tl.get_text()]])
    ax.set_ylabel("Ward merge height (scaled feature units)")
    ax.tick_params(axis="x", length=0)
    ax.spines["bottom"].set_visible(False)
    present = [c for c in colors if c in set(cats)]
    leg1 = ax.legend(handles=cat_handles(colors, present), title="Category (leaf label)",
                     title_fontsize=8.5, loc="upper left", bbox_to_anchor=(1.01, 1.0),
                     frameon=False)
    ax.add_artist(leg1)
    gh = [Line2D([], [], color=group_colour(g), lw=2, label=f"G{g}")
          for g in range(1, k + 1)]
    gh.append(Line2D([], [], color="#555555", lw=1.5, label="above cut"))
    leg2 = ax.legend(handles=gh, title="Group (branch)", title_fontsize=8.5, loc="lower left",
                     bbox_to_anchor=(1.01, 0.0), frameon=False, ncol=2)
    return save(fig, figdir, "fig5_dendrogram", [leg1, leg2]), dn["leaves"]


def fig6_k_selection(ktab: pd.DataFrame, cands: list[int], rec: int, figdir):
    fig, axes = plt.subplots(1, 3, figsize=(8.4, 2.6), sharex=True)
    spec = [("silhouette", "silhouette (↑)"), ("calinski_harabasz", "Calinski–Harabasz (↑)"),
            ("davies_bouldin", "Davies–Bouldin (↓)")]
    for ax, (col, lab) in zip(axes, spec):
        ax.plot(ktab["k"], ktab[col], color="#999999", lw=1, zorder=1)
        fe = ktab[ktab["feasible"]]
        inf = ktab[~ktab["feasible"]]
        ax.scatter(inf["k"], inf[col], s=26, facecolor="white", edgecolor="#bbbbbb", zorder=2,
                   label="infeasible")
        ax.scatter(fe["k"], fe[col], s=26, color="#0072B2", zorder=3, label="feasible")
        c = ktab[ktab["k"].isin(cands)]
        ax.scatter(c["k"], c[col], s=70, facecolor="none", edgecolor="#000000", lw=1,
                   zorder=4, label="candidate")
        ax.axvline(rec, ls="--", lw=1, color="#D55E00", zorder=0)
        ax.set_ylabel(lab)
        ax.set_xlabel("k (groups)")
        ax.grid(alpha=0.25, lw=0.5)
        ax.set_xticks(ktab["k"], [str(k) for k in ktab["k"]], fontsize=7.5)
    hs, ls = axes[0].get_legend_handles_labels()
    hs.append(Line2D([], [], ls="--", color="#D55E00", lw=1))
    ls.append(f"recommended k = {rec}")
    leg = fig.legend(hs, ls, loc="upper center", bbox_to_anchor=(0.5, 0.0), ncol=4,
                     frameon=False)
    fig.tight_layout()
    return save(fig, figdir, "fig6_k_selection", [leg])


def fig7_heatmap(d: pd.DataFrame, kept, colors, figdir):
    """d: rows already ordered; columns kept + device_name, category, group, confidence."""
    nr, nc = len(d), len(kept)
    fig = plt.figure(figsize=(1.9 + 0.42 * nc + 1.6, 0.8 + 0.165 * nr))
    gs = fig.add_gridspec(1, 4, width_ratios=[0.035 * nc, 0.035 * nc, nc, 0.06 * nc],
                          wspace=0.03)
    axg, axc, ax, axb = (fig.add_subplot(gs[i]) for i in range(4))
    m = d[kept].to_numpy(dtype=float)
    cmap = plt.get_cmap("RdBu_r").copy()
    cmap.set_bad("#d9d9d9")
    im = ax.imshow(np.ma.masked_invalid(m), cmap=cmap, vmin=-CLIP, vmax=CLIP, aspect="auto",
                   interpolation="nearest")
    groups = sorted(d["group"].unique())
    axg.imshow(d["group"].to_numpy()[:, None] - 1,
               cmap=ListedColormap([group_colour(g) for g in range(1, max(groups) + 1)]),
               aspect="auto", vmin=-0.5, vmax=max(groups) - 0.5, interpolation="nearest")
    cats = [c for c in colors if c in set(d["category"])]
    cidx = d["category"].map({c: i for i, c in enumerate(cats)}).to_numpy()[:, None]
    axc.imshow(cidx, cmap=ListedColormap([colors[c] for c in cats]), aspect="auto",
               vmin=-0.5, vmax=len(cats) - 0.5, interpolation="nearest")
    low = (d["confidence"] != "high").to_numpy()
    ylab = [f"{n} †" if lo else n for n, lo in zip(d["device_name"], low)]
    axg.set_yticks(range(nr), ylab, fontsize=8)
    for tl, lo in zip(axg.get_yticklabels(), low):
        if lo:
            tl.set_color("#777777")
            tl.set_fontstyle("italic")
    for i in np.where(low)[0]:
        ax.add_patch(plt.Rectangle((-0.5, i - 0.5), nc, 1, fill=False, hatch="////",
                                   edgecolor="#555555", linewidth=0, alpha=0.5))
    gv = d["group"].to_numpy()
    for g in groups:
        rows = np.where(gv == g)[0]
        axg.text(0, rows.mean(), f"G{g}", ha="center", va="center", fontsize=6.5,
                 color="white" if g in (1, 3, 5, 7, 11) else "black", fontweight="bold")
    for b in np.where(gv[1:] != gv[:-1])[0]:
        for a in (ax, axc, axg):
            a.axhline(b + 0.5, color="black", lw=1.4)
    for a in (axg, axc):
        a.set_xticks([])
    axc.set_yticks([])
    ax.set_yticks([])
    ax.set_xticks(range(nc), [LABEL[k] for k in kept], rotation=55, ha="right",
                  rotation_mode="anchor")
    for a in (ax, axc, axg):
        a.tick_params(length=0)
        for s in a.spines.values():
            s.set_visible(False)
    cb = fig.colorbar(im, cax=axb, extend="both")
    cb.set_label(f"cluster-input z (robust, clipped ±{CLIP:g})")
    hs = cat_handles(colors, cats) + [
        Patch(facecolor="white", edgecolor="#555555", hatch="////",
              label="† low confidence (nearest centroid)"),
        Patch(facecolor="#d9d9d9", edgecolor="none", label="undefined (NaN)")]
    leg = ax.legend(handles=hs, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=3,
                    frameon=False)
    return save(fig, figdir, "fig7_fingerprints_by_group", [leg])


def fig8_pca(Xhi, labels, cats_hi, Xlow, low_groups, cats_low, colors, k, figdir):
    pca = PCA(n_components=2).fit(Xhi)
    P = pca.transform(Xhi)
    ev = pca.explained_variance_ratio_ * 100
    catlist = list(colors)
    mk = {c: CAT_MARKERS[i % len(CAT_MARKERS)] for i, c in enumerate(catlist)}
    fig, ax = plt.subplots(figsize=(6.6, 4.8))
    for i in range(len(P)):
        ax.scatter(P[i, 0], P[i, 1], marker=mk[cats_hi[i]], s=46, color=group_colour(labels[i]),
                   edgecolors="white", linewidths=0.6, zorder=3)
    if len(Xlow):
        Q = pca.transform(np.nan_to_num(Xlow, nan=0.0))  # NaN -> median (z = 0), display only
        for i in range(len(Q)):
            ax.scatter(Q[i, 0], Q[i, 1], marker=mk[cats_low[i]], s=46, facecolor="none",
                       edgecolors=group_colour(low_groups[i]), linewidths=1.3, zorder=4)
    ax.set_xlabel(f"PC1 ({ev[0]:.1f}% of variance)")
    ax.set_ylabel(f"PC2 ({ev[1]:.1f}% of variance)")
    ax.grid(alpha=0.25, lw=0.5)
    ax.annotate(f"2-D view only; clustering used all {Xhi.shape[1]} features",
                (0.01, 0.99), xycoords="axes fraction", ha="left", va="top", fontsize=7.5,
                color="#555555")
    gh = [Patch(facecolor=group_colour(g), edgecolor="none", label=f"G{g}")
          for g in range(1, k + 1)]
    leg1 = ax.legend(handles=gh, title="Group", title_fontsize=8.5, loc="upper left",
                     bbox_to_anchor=(1.01, 1.0), frameon=False, ncol=2)
    ax.add_artist(leg1)
    present = [c for c in catlist if c in set(cats_hi) | set(cats_low)]
    mh = [Line2D([], [], ls="", marker=mk[c], color="#555555", markersize=6, label=c)
          for c in present]
    mh.append(Line2D([], [], ls="", marker="o", markerfacecolor="none",
                     markeredgecolor="#555555", markersize=6, label="low confidence (hollow)"))
    leg2 = ax.legend(handles=mh, title="Category", title_fontsize=8.5, loc="lower left",
                     bbox_to_anchor=(1.01, 0.0), frameon=False)
    return save(fig, figdir, "fig8_pca_groups", [leg1, leg2]), ev.tolist()


def fig9_stability(boot: dict, rec: int, figdir):
    ks = sorted(boot)
    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    data = [boot[k] for k in ks]
    vp = ax.violinplot(data, positions=range(len(ks)), showextrema=False, widths=0.8)
    for body, k in zip(vp["bodies"], ks):
        body.set_facecolor("#D55E00" if k == rec else "#56B4E9")
        body.set_edgecolor("none")
        body.set_alpha(0.45)
    ax.boxplot(data, positions=range(len(ks)), widths=0.18, showfliers=True,
               medianprops=dict(color="black", lw=1.2),
               flierprops=dict(marker="o", markersize=3, markerfacecolor="#555555",
                               markeredgecolor="none"))
    ax.set_xticks(range(len(ks)), [f"k = {k}" + (" (rec.)" if k == rec else "") for k in ks])
    ax.set_ylabel("bootstrap ARI vs base partition")
    ax.set_ylim(min(0.0, min(min(x) for x in data) - 0.05), 1.02)
    ax.grid(axis="y", alpha=0.25, lw=0.5)
    return save(fig, figdir, "fig9_stability")


# --------------------------------------------------------------------------- report

def describe(medz: pd.Series) -> tuple[list[dict], str]:
    top = medz.abs().sort_values(ascending=False).index[:4]
    feats = [{"feature": f, "median_z": round(float(medz[f]), 3)} for f in top]
    words = [PHRASE[f][0 if medz[f] > 0 else 1] for f in top if abs(medz[f]) >= DESC_MIN_Z]
    words = list(dict.fromkeys(words))
    return feats, (", ".join(words) if words else "near the population median on all features")


def write_md(path: Path, rep: dict) -> None:
    L = ["# Step 6b -- behaviour group proposal (NOT locked)", ""]
    L += [f"- **{k}**: {v}" for k, v in rep["run"].items() if k != "input_sha256"]
    L += ["", "Input SHA256:", ""]
    L += [f"- `{k}`: {v}" for k, v in rep["run"]["input_sha256"].items()]
    ig = rep["integrity"]
    L += ["", f"## Integrity: **{'PASS' if ig['pass'] else 'FAIL'}**", ""]
    L += [f"- **{k}**: {v}" for k, v in ig.items() if k != "pass"]

    L += ["", "## 1. Cluster-input scaling (fit on high-confidence devices)", ""]
    L += md_table(rep["scaling"], ["feature", "scale_type", "scale", "median", "iqr",
                                   "p95_minus_p5", "max_abs_z_before_clip", "n_clipped"])
    L += ["", "## 2–3. Ward clustering and choice of k", "",
          f"Feasible = every group has ≥ {rep['run']['min_group_flows']} usable flows. "
          "Rank = mean of the ranks of silhouette (↑), CH (↑), DB (↓) and merge gap (↑) "
          "over all k.", ""]
    L += md_table(rep["k_selection"], ["k", "silhouette", "calinski_harabasz", "davies_bouldin",
                                       "merge_height", "merge_gap", "min_group_flows",
                                       "min_group_devices", "smallest_group_flows_devices",
                                       "feasible", "mean_rank"])
    L += ["", "### Candidates", ""]
    for c in rep["candidates"]:
        L += [f"- **k = {c['k']}**: {c['reasoning']}"]
    L += ["", f"### Recommended k = **{rep['recommended_k']}**", "", rep["recommendation_reason"],
          ""]

    L += ["## 4. Cross-checks (ARI vs Ward at the same k)", ""]
    L += md_table(rep["cross_checks"], ["k", "kmeans", "average_correlation",
                                        f"ward_without_{SENS_DROP}"])
    L += ["", "## 5. Stability", "", "### (a) Bootstrap over flows", "",
          rep["bootstrap_note"], ""]
    L += md_table([{"k": k, **{s: round(v, 3) for s, v in st.items()}}
                   for k, st in rep["bootstrap_summary"].items()],
                  ["k", "mean", "median", "p5", "min", "max"])
    L += ["", "Per-device stay frequency (share of bootstrap runs in which the device stays "
          "in the cluster matched to its base group):", ""]
    L += md_table(rep["device_stay"], ["device_name", "category"] +
                  [f"k{k}_group" for k in rep["candidate_ks"]] +
                  [f"k{k}_stay" for k in rep["candidate_ks"]])
    L += ["", "### (b) Leave-one-feature-out (ARI vs Ward with all features)", ""]
    L += md_table(rep["lofo"], ["dropped_feature"] + [f"k{k}" for k in rep["candidate_ks"]])

    L += ["", "## 6. Low-confidence devices (nearest group centroid, flagged)", "",
          "Distance in scaled space (NaN features skipped, distance rescaled by "
          "√(features/available)); spread = the group members' distances to their centroid.",
          ""]
    L += md_table(rep["low_confidence"], ["k", "device_name", "category", "usable_flows",
                                          "group", "distance", "group_median_spread",
                                          "group_max_spread", "ratio_to_median",
                                          "features_used", "flag"])

    L += ["", "## 7. Group profiles", ""]
    for k, prof in rep["profiles"].items():
        L += [f"### k = {k}", ""]
        for p in prof:
            feats = ", ".join(f"{f['feature']} {f['median_z']:+.2f}" for f in p["top_features"])
            L += [f"- **G{p['group']}** ({p['n_devices']} devices, {p['total_usable_flows']:,} "
                  f"usable flows) — *{p['description']}*  ",
                  f"  top |median z|: {feats}  ",
                  "  devices: " + "; ".join(f"{d['device_name']} [{d['category']}]"
                                            for d in p["devices"])]
            if p["low_confidence_assigned"]:
                L += ["  low-confidence assigned: " + "; ".join(p["low_confidence_assigned"])]
        L += [""]
    L += ["### Known-pair check", "",
          "Group of each member; 'together' = all members share one group; "
          "'boot' = share of bootstrap runs with all members in one cluster.", ""]
    L += md_table(rep["known_pairs"], ["set", "k", "n_members", "n_groups", "together",
                                       "boot_together", "placement"])
    L += ["", "## 8. Figures", ""]
    for f in rep["figures"]:
        L += [f"- **{f['name']}** ({', '.join(Path(x).name for x in f['files'])}): {f['caption']}"]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fingerprints", type=Path, default=ROOT / "results/step6/device_fingerprints.csv")
    ap.add_argument("--kept", type=Path, default=ROOT / "results/step6/kept_features.txt")
    ap.add_argument("--flows", type=Path,
                    default=ROOT / "data/interim/flows/benign/benign_flows_tagged.csv")
    ap.add_argument("--k-min", type=int, default=2)
    ap.add_argument("--k-max", type=int, default=12)
    ap.add_argument("--min-group-flows", type=int, default=2000)
    ap.add_argument("--n-boot", type=int, default=100)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", type=Path, default=ROOT / "results/step6")
    args = ap.parse_args()
    t0 = time.time()
    script05 = ROOT / "05_profile_devices.py"
    inputs = {"fingerprints": args.fingerprints, "kept_features": args.kept,
              "flows": args.flows, "05_profile_devices.py": script05}
    for p in inputs.values():
        if not p.is_file():
            fatal(f"missing input {p}")
    shas = {k: sha256(p) for k, p in inputs.items()}
    figdir = args.out_dir / "figures"
    figdir.mkdir(parents=True, exist_ok=True)

    fp = pd.read_csv(args.fingerprints, keep_default_na=True)
    fp["vendor_family"] = fp["vendor_family"].fillna("")
    kept = [l.strip() for l in args.kept.read_text(encoding="utf-8").splitlines() if l.strip()]
    missing = [k for k in kept if k not in fp.columns]
    if missing:
        fatal(f"kept features missing from fingerprints: {missing}")
    hi_mask = fp["confidence"] == "high"
    hi = fp[hi_mask].reset_index(drop=True)
    low = fp[~hi_mask & (fp["usable_flows"] > 0)].reset_index(drop=True)
    if hi[kept].isna().any().any():
        fatal(f"NaN in high-confidence features: {hi[kept].isna().sum()[lambda s: s > 0].to_dict()}")
    log(f"fingerprints: {len(fp)} devices ({len(hi)} high, {len(low)} low); {len(kept)} features")

    cats = [c for c in m05.CATEGORY_ORDER if c in set(fp["category"])]
    cats += sorted(set(fp["category"]) - set(cats))
    colors = {c: m05.OKABE_ITO[i % len(m05.OKABE_ITO)] for i, c in enumerate(cats)}

    # ---- 1. scaling
    params = fit_scaler(hi, kept)
    raw_z_hi = pd.DataFrame({k: (hi[k] - p["median"]) / p["scale"] for k, p in params.items()})
    raw_z_all = pd.DataFrame({k: (fp[k] - p["median"]) / p["scale"] for k, p in params.items()})
    scaling_rows = []
    for k, p in params.items():
        scaling_rows.append({"feature": k, "scale_type": p["scale_type"],
                             "scale": round(p["scale"], 6), "median": round(p["median"], 6),
                             "iqr": round(p["iqr"], 6), "p95_minus_p5": round(p["p95_minus_p5"], 6),
                             "max_abs_z_before_clip": round(float(raw_z_hi[k].abs().max()), 3),
                             "n_clipped": int((raw_z_hi[k].abs() > CLIP).sum()),
                             "max_abs_z_all_devices": round(float(raw_z_all[k].abs().max()), 3),
                             "n_clipped_all_devices": int((raw_z_all[k].abs() > CLIP).sum())})
    Zall = apply_scaler(fp, params)
    cluster_input = pd.concat([fp[META], Zall.round(6)], axis=1)
    cluster_input.to_csv(args.out_dir / "cluster_input.csv", index=False)
    X = apply_scaler(hi, params)[kept].to_numpy(dtype=float)
    Xlow_df = apply_scaler(low, params)[kept]
    n = len(X)
    flows_hi = hi["usable_flows"].to_numpy()

    # ---- 2-3. Ward + k selection
    Z = ward(X)
    leaves = dendrogram(Z, no_plot=True)["leaves"]
    ks = list(range(args.k_min, args.k_max + 1))
    rows, part = [], {}
    for k in ks:
        lab = relabel_by_leaf_order(cut(Z, k), leaves)
        part[k] = lab
        gflows = pd.Series(flows_hi).groupby(lab).sum()
        gsize = pd.Series(lab).value_counts()
        g_min = gflows.idxmin()
        rows.append({"k": k, "n_groups_found": int(len(np.unique(lab))),
                     "silhouette": round(float(silhouette_score(X, lab)), 4),
                     "calinski_harabasz": round(float(calinski_harabasz_score(X, lab)), 2),
                     "davies_bouldin": round(float(davies_bouldin_score(X, lab)), 4),
                     "merge_height": round(float(Z[-(k - 1), 2]), 4),
                     "merge_gap": round(float(Z[-(k - 1), 2] - Z[-k, 2]), 4),
                     "min_group_flows": int(gflows.min()),
                     "min_group_devices": int(gsize.min()),
                     "smallest_group_flows_devices": int(gsize[g_min]),
                     "feasible": bool(gflows.min() >= args.min_group_flows)})
    ktab = pd.DataFrame(rows)
    rk = pd.DataFrame({"s": ktab["silhouette"].rank(ascending=False),
                       "ch": ktab["calinski_harabasz"].rank(ascending=False),
                       "db": ktab["davies_bouldin"].rank(ascending=True),
                       "gap": ktab["merge_gap"].rank(ascending=False)})
    ktab["mean_rank"] = rk.mean(axis=1).round(3)
    for c in rk:
        ktab[f"rank_{c}"] = rk[c].astype(int)
    feas = ktab[ktab["feasible"]].sort_values(["mean_rank", "silhouette"],
                                              ascending=[True, False])
    if len(feas) == 0:
        log("WARNING: no feasible k; candidates taken from all k by mean rank")
        feas = ktab.sort_values(["mean_rank", "silhouette"], ascending=[True, False])
    cand = feas["k"].head(3).tolist()
    log(f"feasible k: {ktab.loc[ktab['feasible'], 'k'].tolist()}; candidates {cand}")

    # ---- 4. cross-checks + 5b LOFO
    cross, lofo = [], []
    for k in cand:
        km = KMeans(n_clusters=k, n_init=100, random_state=args.seed).fit_predict(X)
        avg = cut(linkage(pdist(X, "correlation"), method="average"), k)
        j = kept.index(SENS_DROP) if SENS_DROP in kept else None
        wo = cut(ward(np.delete(X, j, axis=1)), k) if j is not None else None
        cross.append({"k": k, "kmeans": round(adjusted_rand_score(part[k], km), 3),
                      "average_correlation": round(adjusted_rand_score(part[k], avg), 3),
                      f"ward_without_{SENS_DROP}":
                          round(adjusted_rand_score(part[k], wo), 3) if wo is not None else None})
    for i, f in enumerate(kept):
        Zd = ward(np.delete(X, i, axis=1))
        lofo.append({"dropped_feature": f, **{f"k{k}": round(adjusted_rand_score(part[k],
                                                                                cut(Zd, k)), 3)
                                               for k in cand}})

    # ---- 5a. bootstrap over flows (05's fingerprint code, same fitted scaler)
    log("loading flows for bootstrap ...")
    u, o, hours = load_usable(args.flows)
    homes_all = fp[["mac", "device_name", "category", "vendor_family"]]
    chk = m05.build_fingerprints(u, o, homes_all, hours, 100).set_index("mac").loc[fp["mac"]]
    feat_diff = float(np.nanmax(np.abs(chk[kept].to_numpy(dtype=float)
                                       - fp[kept].to_numpy(dtype=float))))
    flows_match = bool((chk["usable_flows"].to_numpy() == fp["usable_flows"].to_numpy()).all())
    log(f"recomputed fingerprints vs CSV: max |diff| {feat_diff:.2e}; usable counts match "
        f"{flows_match}")
    hi_macs = hi["mac"].tolist()
    sel = u["owner_mac"].isin(hi_macs).to_numpy()
    ub_src = u.loc[sel, ["owner_mac", "protocol", "duration", "ts"]].reset_index(drop=True)
    ob_src = o.loc[sel].reset_index(drop=True)
    del u, o
    pos = {m: np.flatnonzero(ub_src["owner_mac"].to_numpy() == m) for m in hi_macs}
    homes_hi = hi[["mac", "device_name", "category", "vendor_family"]]
    rng = np.random.default_rng(args.seed)
    boot_ari = {k: [] for k in cand}
    stay = {k: np.zeros(n) for k in cand}
    known_masks = {s: fn(hi).to_numpy() for s, fn in KNOWN_SETS.items()}
    boot_together = {(s, k): 0 for s in KNOWN_SETS for k in cand}
    nan_imputed = 0
    for b in range(args.n_boot):
        idx = np.concatenate([p[rng.integers(0, len(p), len(p))] for p in pos.values()])
        ub = ub_src.iloc[idx].reset_index(drop=True)
        ob = ob_src.iloc[idx].reset_index(drop=True)
        fb = m05.build_fingerprints(ub, ob, homes_hi, hours, 100).set_index("mac").loc[hi_macs]
        Xb = apply_scaler(fb, params)[kept]
        nan_imputed += int(Xb.isna().sum().sum())
        Xb = Xb.fillna(0.0).to_numpy(dtype=float)
        Zb = ward(Xb)
        for k in cand:
            lb = cut(Zb, k)
            boot_ari[k].append(adjusted_rand_score(part[k], lb))
            stay[k] += match_stay(part[k], lb)
            for s, msk in known_masks.items():
                boot_together[(s, k)] += int(len(np.unique(lb[msk])) == 1)
        if (b + 1) % 20 == 0:
            log(f"  bootstrap {b + 1}/{args.n_boot}  ({time.time() - t0:.0f}s)")
    boot_sum = {k: summarise(v) for k, v in boot_ari.items()}

    # ---- recommendation
    best_int = cand[0]
    most_stable = max(cand, key=lambda k: boot_sum[k]["mean"])
    if boot_sum[most_stable]["mean"] - boot_sum[best_int]["mean"] >= 0.10:
        rec = most_stable
        rec_reason = (f"k = {best_int} has the best internal-validity rank, but k = {rec} is "
                      f"clearly more stable under bootstrap (mean ARI "
                      f"{boot_sum[rec]['mean']:.3f} vs {boot_sum[best_int]['mean']:.3f}, "
                      f"≥ 0.10 better), so k = {rec} is recommended.")
    else:
        rec = best_int
        rec_reason = (f"k = {rec} has the best mean internal-validity rank among feasible k "
                      f"and no other candidate is ≥ 0.10 more stable under bootstrap (mean ARI "
                      f"{boot_sum[rec]['mean']:.3f}; most stable candidate k = {most_stable} at "
                      f"{boot_sum[most_stable]['mean']:.3f}).")
    rec_reason += " Rule: best mean rank unless another candidate's bootstrap mean ARI is ≥ 0.10 higher."

    candidates = []
    for k in cand:
        r = ktab.set_index("k").loc[k]
        candidates.append({
            "k": k, "mean_rank": float(r["mean_rank"]),
            "reasoning": (f"mean rank {r['mean_rank']:.2f}; silhouette {r['silhouette']:.3f} "
                          f"(rank {r['rank_s']}/{len(ks)}), CH {r['calinski_harabasz']:.1f} "
                          f"(rank {r['rank_ch']}), DB {r['davies_bouldin']:.3f} "
                          f"(rank {r['rank_db']}), merge gap {r['merge_gap']:.3f} "
                          f"(rank {r['rank_gap']}); smallest group {r['min_group_flows']:,} "
                          f"flows ({r['smallest_group_flows_devices']} devices); bootstrap "
                          f"mean ARI {boot_sum[k]['mean']:.3f}")})

    # ---- 6. centroids, distances, low-confidence assignment; 7. profiles; outputs
    Xlow = Xlow_df.to_numpy(dtype=float)
    d_feat = X.shape[1]
    low_rows, profiles, known_rows = [], {}, []
    stay_rows = hi[["device_name", "category"]].copy()
    low_assign = {}
    for k in cand:
        lab = part[k]
        groups = list(range(1, k + 1))
        cents = {g: X[lab == g].mean(axis=0) for g in groups}
        dist_hi = np.array([np.linalg.norm(X[i] - cents[lab[i]]) for i in range(n)])
        spread = {g: dist_hi[lab == g] for g in groups}
        la = []
        for i in range(len(low)):
            ok = ~np.isnan(Xlow[i])
            ds = {g: np.linalg.norm(Xlow[i, ok] - c[ok]) * np.sqrt(d_feat / ok.sum())
                  for g, c in cents.items()}
            g = min(ds, key=ds.get)
            med = float(np.median(spread[g]))
            la.append(g)
            low_rows.append({"k": k, "device_name": low.at[i, "device_name"],
                             "category": low.at[i, "category"],
                             "usable_flows": int(low.at[i, "usable_flows"]), "group": f"G{g}",
                             "distance": round(float(ds[g]), 3),
                             "group_median_spread": round(med, 3),
                             "group_max_spread": round(float(spread[g].max()), 3),
                             "ratio_to_median": round(float(ds[g] / med), 2) if med > 0 else None,
                             "features_used": f"{int(ok.sum())}/{d_feat}", "flag": LOW_FLAG,
                             "second_nearest": "G%d" % sorted(ds, key=ds.get)[1] if k > 1 else None})
        low_assign[k] = la

        out = pd.DataFrame({"device": hi["device_name"], "mac": hi["mac"],
                            "category": hi["category"], "group": [f"G{g}" for g in lab],
                            "confidence": "high", "distance_to_centroid": dist_hi.round(4)})
        if len(low):
            out = pd.concat([out, pd.DataFrame({
                "device": low["device_name"], "mac": low["mac"], "category": low["category"],
                "group": [f"G{g}" for g in la], "confidence": LOW_FLAG,
                "distance_to_centroid": [r["distance"] for r in low_rows[-len(low):]]})])
        out["_g"] = out["group"].str[1:].astype(int)
        out = out.sort_values(["_g", "confidence", "device"]).drop(columns="_g")
        out.to_csv(args.out_dir / f"groups_k{k}.csv", index=False)

        prof = []
        for g in groups:
            m = lab == g
            medz = pd.Series(np.median(X[m], axis=0), index=kept)
            top, desc = describe(medz)
            prof.append({"group": g, "n_devices": int(m.sum()),
                         "total_usable_flows": int(flows_hi[m].sum()),
                         "top_features": top, "description": desc,
                         "median_spread": round(float(np.median(spread[g])), 3),
                         "devices": hi.loc[m, ["device_name", "category"]].to_dict("records"),
                         "low_confidence_assigned": [low.at[i, "device_name"]
                                                     for i in range(len(low)) if la[i] == g]})
        profiles[k] = prof
        stay_rows[f"k{k}_group"] = [f"G{g}" for g in lab]
        stay_rows[f"k{k}_stay"] = (stay[k] / args.n_boot).round(2)
        for s, msk in known_masks.items():
            gs = lab[msk]
            plc = "; ".join(f"{nm}→G{g}" for nm, g in zip(hi.loc[msk, "device_name"], gs))
            known_rows.append({"set": s, "k": k, "n_members": int(msk.sum()),
                               "n_groups": int(len(np.unique(gs))),
                               "together": bool(len(np.unique(gs)) == 1),
                               "boot_together": round(boot_together[(s, k)] / args.n_boot, 2),
                               "placement": plc})

    # ---- 8. figures
    setup_style()
    figs = []
    f5, leaves_plot = fig5_dendrogram(Z, hi["device_name"].to_numpy(), hi["category"].to_numpy(),
                                      part[rec], rec, colors, figdir)
    figs.append({"name": "fig5_dendrogram", "files": f5,
                 "caption": f"Ward dendrogram of the {n} high-confidence devices over the "
                            f"{len(kept)} scaled fingerprint features; leaf labels are coloured "
                            f"by category, branches by group, and the dashed line marks the "
                            f"cut at the recommended k = {rec}."})
    figs.append({"name": "fig6_k_selection", "files": fig6_k_selection(ktab, cand, rec, figdir),
                 "caption": f"Internal validity of Ward partitions for k = {args.k_min}–"
                            f"{args.k_max}: silhouette, Calinski–Harabasz and Davies–Bouldin. "
                            f"Hollow grey points are infeasible (a group below "
                            f"{args.min_group_flows:,} usable flows); circled points are the "
                            f"candidates and the dashed line marks the recommended k = {rec}."})
    pos_leaf = {i: r for r, i in enumerate(leaves)}
    hd = hi.assign(group=part[rec], _o=[pos_leaf[i] for i in range(n)])
    hd[kept] = X
    ld = low.assign(group=low_assign[rec], _o=10_000)
    ld[kept] = Xlow
    heat = pd.concat([hd, ld]).sort_values(["group", "_o"]).reset_index(drop=True)
    figs.append({"name": "fig7_fingerprints_by_group",
                 "files": fig7_heatmap(heat, kept, colors, figdir),
                 "caption": f"Scaled behaviour fingerprints ordered by proposed group (k = {rec}) "
                            "and dendrogram order within each group; the left strip shows the "
                            "group and the second strip the category (companion to Fig. 2). "
                            "† hatched rows are low-confidence devices placed at their nearest "
                            "group centroid."})
    f8, ev = fig8_pca(X, part[rec], hi["category"].tolist(), Xlow, low_assign[rec],
                      low["category"].tolist(), colors, rec, figdir)
    figs.append({"name": "fig8_pca_groups", "files": f8,
                 "caption": f"First two principal components of the cluster input (PC1 "
                            f"{ev[0]:.1f}%, PC2 {ev[1]:.1f}% of variance); colour = proposed "
                            f"group (k = {rec}), marker = category, hollow = low confidence "
                            "(projected; an undefined feature is set to the median for display). "
                            f"A visual aid only: clustering used all {len(kept)} features."})
    figs.append({"name": "fig9_stability", "files": fig9_stability(boot_ari, rec, figdir),
                 "caption": f"Adjusted Rand index between the base Ward partition and "
                            f"{args.n_boot} flow-level bootstrap re-clusterings for each "
                            "candidate k (fingerprints recomputed, scaler held fixed)."})

    # ---- integrity + report
    ig = {"recomputed_fingerprints_max_abs_diff": feat_diff,
          "recomputed_fingerprints_match_csv": feat_diff < 1e-5,
          "recomputed_usable_counts_match_csv": flows_match,
          "high_confidence_devices": n, "low_confidence_devices_assigned": len(low),
          "every_candidate_has_k_groups": all(len(np.unique(part[k])) == k for k in cand),
          "bootstrap_nan_values_imputed_as_0": nan_imputed,
          "all_figures_written": all(Path(p).is_file() for fg in figs for p in fg["files"]),
          "device_table_untouched": True}
    for k_, p in inputs.items():
        ig[f"{k_}_sha256_unchanged"] = sha256(p) == shas[k_]
    ig["pass"] = all(v for v in ig.values() if isinstance(v, bool))

    rep = {
        "run": {"run_timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                **{k: str(p) for k, p in inputs.items()}, "input_sha256": shas,
                "out_dir": str(args.out_dir), "k_min": args.k_min, "k_max": args.k_max,
                "min_group_flows": args.min_group_flows, "n_boot": args.n_boot,
                "seed": args.seed, "kept_features": kept, "clip": CLIP,
                "capture_hours": round(hours, 4),
                "python": platform.python_version(), "numpy": np.__version__,
                "pandas": pd.__version__, "scipy": scipy.__version__,
                "scikit_learn": sklearn.__version__, "runtime_s": None},
        "integrity": ig,
        "scaling": scaling_rows,
        "scaler_params": params,
        "k_selection": ktab.to_dict("records"),
        "feasible_k": ktab.loc[ktab["feasible"], "k"].tolist(),
        "candidate_ks": cand,
        "candidates": candidates,
        "recommended_k": rec,
        "recommendation_reason": rec_reason,
        "status": "PROPOSED -- not locked; config/device_table.csv unchanged",
        "cross_checks": cross,
        "bootstrap_note": ("Each high-confidence device's usable flows were resampled with "
                           "replacement (same count), fingerprints recomputed with "
                           "05_profile_devices.build_fingerprints, rescaled with the scaler "
                           "fitted above, and re-clustered with Ward. Caveat: duplicated flows "
                           "add zero inter-flow gaps (inflating gap_cv) and cannot add new peers "
                           "(deflating log_distinct_peers), so ARI is a conservative estimate."),
        "bootstrap_summary": boot_sum,
        "bootstrap_ari": {k: [round(x, 4) for x in v] for k, v in boot_ari.items()},
        "device_stay": stay_rows.to_dict("records"),
        "lofo": lofo,
        "low_confidence": low_rows,
        "profiles": profiles,
        "known_pairs": known_rows,
        "category_colours": colors,
        "group_colours": {f"G{i + 1}": c for i, c in enumerate(GROUP_COLOURS)},
        "pca_explained_variance_pct": ev,
        "figures": figs,
    }
    rep["run"]["runtime_s"] = round(time.time() - t0, 1)
    write_md(args.out_dir / "group_report.md", rep)
    (args.out_dir / "group_report.json").write_text(json.dumps(jsonable(rep), indent=2),
                                                    encoding="utf-8")

    # ---- console summary
    log(f"\nintegrity: {'PASS' if ig['pass'] else 'FAIL'}")
    log("scaling: " + ", ".join(f"{r['feature']}={r['scale_type']}"
                                for r in scaling_rows if r["scale_type"] != "iqr")
        + (" (others IQR)" if any(r["scale_type"] == "iqr" for r in scaling_rows) else ""))
    log(f"feasible k: {rep['feasible_k']}")
    log(f"{'k':>3} {'sil':>6} {'bootARI mean/med/p5':>22} {'kmeans':>7} {'avgcorr':>7} "
        f"{'-medpk':>7}")
    for c in cross:
        k = c["k"]
        s = ktab.set_index("k").at[k, "silhouette"]
        b = boot_sum[k]
        log(f"{k:>3} {s:>6.3f} {b['mean']:>8.3f}/{b['median']:.3f}/{b['p5']:.3f}   "
            f"{c['kmeans']:>7.3f} {c['average_correlation']:>7.3f} "
            f"{c[f'ward_without_{SENS_DROP}']:>7.3f}" + ("  <- recommended" if k == rec else ""))
    log(f"\nrecommended k = {rec}: {rec_reason}")
    for p in profiles[rec]:
        log(f"  G{p['group']} ({p['n_devices']} dev, {p['total_usable_flows']:,} flows) "
            f"[{p['description']}]: " + "; ".join(d["device_name"] for d in p["devices"])
            + (f"  + low-conf: {', '.join(p['low_confidence_assigned'])}"
               if p["low_confidence_assigned"] else ""))
    log(f"runtime {rep['run']['runtime_s']}s")
    if not ig["pass"]:
        fatal(f"integrity check failed: {ig}")


if __name__ == "__main__":
    main()
