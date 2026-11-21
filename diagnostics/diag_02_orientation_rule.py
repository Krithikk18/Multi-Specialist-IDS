#!/usr/bin/env python
"""diagnostics/diag_02_orientation_rule.py -- READ-ONLY diagnostic: is the proposed orientation-normaliser rule safe
and sufficient?

Background (diag_01 / diag_01b): 99.6 % of the focus specialist's port_scan -> syn_flood errors on G1 val are flows
that CICFlowMeter wrote "backwards" -- the victim's RST/ACK (TCP window 0) is the first (forward) packet, the scanner's
SYN sits in the backward direction. Proposed fix (NOT built here): after extraction, flag

  R1 (proposed)   REVERSED  <=>  FWD Init Win Bytes == 0  AND  Bwd Init Win Bytes > 0
  R2 (variant)    R1  AND  SYN Flag Count >= 1      (a SYN exists, and it cannot be the window-0 first packet)

and rewrite a flagged row as if the other endpoint were the source: every forward/backward feature pair swapped,
src/dst IP, port and MAC swapped, the asymmetric / unpaired fields handled per the swap map (T1). Nothing here is
retrained or re-versioned: the swap is applied IN MEMORY to train / val rows only.

  T1 swap map     every one of the 70 features (features_v1.json) + the identity columns classified as pair /
                  asymmetric pair / direction-free / derived / unpaired, from CICFlowMeter's BasicFlow.java
                  (reviewed source; sha256 recorded) -> orientation_map_proposed.json (for review; NOT in config/)
  T2 flip counts  rows flagged per split x group x class, per device for benign; edge cases (both windows 0,
                  window missing / < 0, non-TCP); agreement with an independent orientation signal for attack rows
                  (victim device == source MAC)
  T3 coverage     focus-group val class-A flows with FWD Init Win == 0 flagged; focus specialist seed-0 errors flagged
  T4 benign       profile of flagged benign flows (devices, protocol, flags, duration, packets, ports)
  T5 shift        FWD Init Win distribution and per-feature KS (top-10 SHAP features of the focus specialist, from
                  step 25, read-only) of focus val class A vs train class A, before / after flipping
  T6 models       seed-0 primary models of step 22 (read-only, sha256-checked) predicting val, original vs flipped:
                  per-class recall, false alarms (benign -> attack), ROUTED vs FLAT_GLOBAL macro-F1 (all / non-rare).
                  The models were trained on UNFLIPPED train: this is a lower bound on what retraining on normalised
                  data would give.
Verdict rule (stated in summary.md before the numbers): PASS only if (a) R1 flags >= 95 % of focus-group val class-A
flows with FWD Init Win == 0, (b) flagged benign <= 1 % of benign in every split x group (or the excess is shown in T4
to be genuine reversals), (c) R1 never flags a non-TCP flow, (d) no UNRESOLVED swap-map entry without a safe default.

Outputs: results/diag_02/ (summary.md, run_manifest.json, run_meta.json, run.log, orientation_map_proposed.json,
figures/*.png); diag_02.json in ~/lgids_cache/v2/diag/<run_id>/. --dry-run: the 5 % sample, results/diag_02/dry_run/<run_id>/.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase2_data as D  # noqa: E402
from common import phase2_metrics as PM  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

SCRIPT = "diagnostics/diag_02_orientation_rule.py"
STEP = "diag_02"
TCP = 6                                                     # IANA protocol number
BENIGN = 0                                                  # class id 0 = benign (Phase 2 convention)
FIW, BIW, PROTO, SYN = "FWD Init Win Bytes", "Bwd Init Win Bytes", "Protocol", "SYN Flag Count"
NF, NB = "Total Fwd Packet", "Total Bwd packets"
CICFM_SRC = "~/tools/CICFlowMeter-sweep/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java"
QS = (0.05, 0.25, 0.5, 0.75, 0.95)

# --------------------------------------------------------------------------- T1 swap map (from BasicFlow.java)
_SRC = "BasicFlow.java (ahlashkari 98a5eba + LG-IDS patches)"
PAIRS = [
    ("Total Fwd Packet", "Total Bwd packets", "fwdPktStats.getN() / bwdPktStats.getN()"),
    ("Total Length of Fwd Packet", "Total Length of Bwd Packet", "fwdPktStats / bwdPktStats .getSum() (payload bytes)"),
    ("Fwd Packet Length Max", "Bwd Packet Length Max", "fwd/bwdPktStats.getMax(), 0 if no packets"),
    ("Fwd Packet Length Min", "Bwd Packet Length Min", "fwd/bwdPktStats.getMin(), 0 if no packets"),
    ("Fwd Packet Length Mean", "Bwd Packet Length Mean", "fwd/bwdPktStats.getMean(), 0 if no packets"),
    ("Fwd Packet Length Std", "Bwd Packet Length Std", "fwd/bwdPktStats.getStandardDeviation(), 0 if no packets"),
    ("Fwd IAT Total", "Bwd IAT Total", "forwardIAT / backwardIAT over same-direction gaps; 0 if <= 1 packet"),
    ("Fwd IAT Mean", "Bwd IAT Mean", "as Fwd/Bwd IAT Total"),
    ("Fwd IAT Std", "Bwd IAT Std", "as Fwd/Bwd IAT Total"),
    ("Fwd IAT Max", "Bwd IAT Max", "as Fwd/Bwd IAT Total"),
    ("Fwd IAT Min", "Bwd IAT Min", "as Fwd/Bwd IAT Total"),
    ("Fwd Header Length", "Bwd Header Length", "fHeaderBytes / bHeaderBytes: sum of TCP/UDP header bytes"),
    ("Fwd Packets/s", "Bwd Packets/s", "forward.size() / backward.size() over the same flow duration"),
    ("Fwd Segment Size Avg", "Bwd Segment Size Avg", "fwd/bwd payload sum / packet count"),
    ("Subflow Fwd Packets", "Subflow Bwd Packets", "forward/backward.size() / sfCount (integer); sfCount is direction-free"),
    ("Subflow Fwd Bytes", "Subflow Bwd Bytes", "forwardBytes/backwardBytes / sfCount (integer)"),
]
ASYM_PAIRS = [
    (FIW, BIW, "Init_Win_bytes_forward = window of the FIRST forward packet (firstPacket); Init_Win_bytes_backward is "
               "overwritten by EVERY backward packet in addPacket = window of the LAST backward packet. Swapped as a "
               "pair: new FWD = old Bwd is exact iff old Total Bwd packets == 1; new Bwd = old FWD is exact iff old "
               "Total Fwd Packet == 1."),
]
FREE = {
    "Protocol": "flow protocol",
    "Flow Duration": "flowLastSeen - flowStartTime: same packet set",
    "Flow Bytes/s": "(forwardBytes + backwardBytes) / duration",
    "Flow Packets/s": "packetCount() / duration",
    "Flow IAT Mean": "flowIAT: gaps between consecutive packets of either direction",
    "Flow IAT Std": "flowIAT", "Flow IAT Max": "flowIAT", "Flow IAT Min": "flowIAT",
    "Packet Length Min": "flowLengthStats over all packets (the time-first packet is added twice -- same packet "
                         "whichever endpoint is called source)",
    "Packet Length Max": "flowLengthStats", "Packet Length Mean": "flowLengthStats",
    "Packet Length Std": "flowLengthStats", "Packet Length Variance": "flowLengthStats",
    "FIN Flag Count": "checkFlags() on every packet: total over both directions",
    "SYN Flag Count": "total over both directions", "RST Flag Count": "total over both directions",
    "PSH Flag Count": "total over both directions", "ACK Flag Count": "total over both directions",
    "CWR Flag Count": "total over both directions", "ECE Flag Count": "total over both directions",
    "Average Packet Size": "flowLengthStats.getSum() / packetCount()",
    "Bwd Bytes/Bulk Avg": "NAME IS MISLEADING: updateFlowBulk() tests `this.src == packet.getSrc()` by reference and "
                          "getSrc() returns a copy, so EVERY packet goes to the 'backward' bulk counters (the Fwd bulk "
                          "features are constant 0 and were dropped). Computed over all packets in time order: "
                          "direction-free.",
    "Bwd Packet/Bulk Avg": "see Bwd Bytes/Bulk Avg: all packets, direction-free",
    "Bwd Bulk Rate Avg": "see Bwd Bytes/Bulk Avg: all packets, direction-free",
    "Active Mean": "updateActiveIdleTime() on every packet's timestamp (both directions)",
    "Active Std": "as Active Mean", "Active Max": "as Active Mean", "Active Min": "as Active Mean",
    "Idle Mean": "as Active Mean", "Idle Std": "as Active Mean", "Idle Max": "as Active Mean", "Idle Min": "as Active Mean",
}
DERIVED = {
    "Down/Up Ratio": {"how": "recompute floor(new_bwd / new_fwd) = floor(old Total Fwd Packet / old Total Bwd packets) "
                             "(Java integer division `backward.size()/forward.size()`; 0 if no forward packet)",
                      "exact_when": "always"},
}
UNPAIRED = {
    "Fwd Seg Size Min": {
        "source": "min_seg_size_forward = min header bytes over FORWARD packets; no backward counterpart is written",
        "how": "old Total Bwd packets == 1: old Bwd Header Length (exact); > 1: floor(old Bwd Header Length / old Total "
               "Bwd packets) (mean header >= true minimum: approximate); 0 backward packets: 0",
        "exact_when": "old Total Bwd packets == 1", "default": "floor(mean backward header bytes)"},
    "Fwd Act Data Pkts": {
        "source": "Act_data_pkt_forward = forward packets with payload >= 1, counted in addPacket only (the first "
                  "forward packet is never counted); no backward counterpart is written",
        "how": "old Total Bwd packets <= 1 -> 0; old Bwd Packet Length Max == 0 -> 0; old Bwd Packet Length Min >= 1 -> "
               "old Total Bwd packets - 1 (all exact); otherwise the lower bound max(0, ceil(old Total Length of Bwd "
               "Packet / old Bwd Packet Length Max) - 1)",
        "exact_when": "old Total Bwd packets <= 1, or backward payloads all 0, or all >= 1", "default": "lower bound"},
    "Fwd PSH Flags": {
        "source": "fPSH_cnt is incremented only in firstPacket(): 1 iff the FIRST forward packet has PSH (Bwd PSH Flags "
                  "is structurally 0 and was dropped as constant)",
        "how": "rest = PSH Flag Count - Fwd PSH Flags (PSH among the other packets). rest == 0 -> 0 (exact); old Total "
               "Fwd Packet == 1 and rest >= old Total Bwd packets -> 1 (every backward packet has PSH; exact); "
               "otherwise 0",
        "exact_when": "rest == 0, or (old Total Fwd Packet == 1 and rest >= old Total Bwd packets)", "default": "0"},
}
IDENTITY_PAIRS = [("Src IP", "Dst IP"), ("Src Port", "Dst Port"), ("src_mac", "dst_mac")]
IDENTITY_REBUILD = {"Flow ID": "rebuild '<Src IP>-<Dst IP>-<Src Port>-<Dst Port>-<Protocol>' from the swapped fields "
                               "(BasicPacketInfo.fwdFlowId format; verified on the data)"}
IDENTITY_FREE = {"Timestamp": "flow start time: same packets", "start_ts": "flow start time",
                 "device / device_mac / owner_mac / device_category / group": "dataset attribution of the flow to a "
                 "device -- independent of orientation, must NOT be swapped",
                 "session / label_id / label_name / attack_family / y / split / row_in_file": "dataset bookkeeping"}
DROPPED_NOTES = {"Bwd PSH Flags": "structurally 0 (incremented only in firstPacket's backward branch, never reached)",
                 "Fwd URG Flags / Bwd URG Flags / URG Flag Count": "constant 0 in train",
                 "Fwd Bytes/Bulk Avg / Fwd Packet/Bulk Avg / Fwd Bulk Rate Avg": "structurally 0 (reference-equality bug)"}


def build_swap_map(feats: list[str]) -> dict:
    """name -> {"class", "partner"?, ...} for every feature; raises if a feature is uncovered or covered twice, or if
    the map names a feature that is not in `feats`."""
    m = {}

    def put(name, entry):
        if name in m:
            raise ValueError(f"swap map: {name!r} classified twice")
        m[name] = entry
    for a, b, src in PAIRS:
        put(a, {"class": "pair", "partner": b, "source": src, "exact_when": "always"})
        put(b, {"class": "pair", "partner": a, "source": src, "exact_when": "always"})
    for a, b, src in ASYM_PAIRS:
        put(a, {"class": "pair_asymmetric", "partner": b, "source": src, "exact_when": f"old {NB} == 1"})
        put(b, {"class": "pair_asymmetric", "partner": a, "source": src, "exact_when": f"old {NF} == 1"})
    for k, src in FREE.items():
        put(k, {"class": "direction_free", "source": src, "exact_when": "always"})
    for k, d in DERIVED.items():
        put(k, {"class": "derived", **d})
    for k, d in UNPAIRED.items():
        put(k, {"class": "unpaired", **d, "status": "RESOLVED_WITH_DEFAULT"})
    extra = sorted(set(m) - set(feats))
    missing = sorted(set(feats) - set(m))
    if extra or missing:
        raise ValueError(f"swap map vs features: missing {missing}, not in features {extra}")
    return {f: m[f] for f in feats}


def rule_flags(df: pd.DataFrame, variant: str = "R1", tcp_guard: bool = False) -> np.ndarray:
    """R1: FWD Init Win == 0 and Bwd Init Win > 0 (NaN / negative windows never flag). R2: R1 and SYN Flag Count >= 1.
    tcp_guard: additionally Protocol == 6 (the verdict tests the bare rule)."""
    fw = pd.to_numeric(df[FIW], errors="coerce").to_numpy(float)
    bw = pd.to_numeric(df[BIW], errors="coerce").to_numpy(float)
    with np.errstate(invalid="ignore"):
        m = (fw == 0) & (bw > 0)
        if variant == "R2":
            m &= pd.to_numeric(df[SYN], errors="coerce").to_numpy(float) >= 1
        elif variant != "R1":
            raise ValueError(f"unknown rule variant {variant!r}")
        if tcp_guard:
            m &= pd.to_numeric(df[PROTO], errors="coerce").to_numpy(float) == TCP
    return m


def swap_rows(df: pd.DataFrame, mask: np.ndarray, smap: dict) -> tuple[pd.DataFrame, dict]:
    """Copy of df with the rows in `mask` rewritten as if the other endpoint were the source (swap map). Returns the
    frame and {feature: bool array over the swapped rows: value exact} for the approximated fields."""
    out = df.copy()
    idx = np.flatnonzero(np.asarray(mask, bool))
    if not len(idx):
        return out, {}
    sub = df.iloc[idx]
    g = lambda c: pd.to_numeric(sub[c], errors="coerce").to_numpy(float)   # noqa: E731
    nf, nb = g(NF), g(NB)
    new, exact = {}, {}
    for f, e in smap.items():
        if e["class"] in ("pair", "pair_asymmetric"):
            new[f] = sub[e["partner"]].to_numpy()
    exact[FIW] = nb == 1
    exact[BIW] = nf == 1
    if "Down/Up Ratio" in smap:
        with np.errstate(invalid="ignore", divide="ignore"):
            new["Down/Up Ratio"] = np.where(nb > 0, np.floor(nf / np.where(nb > 0, nb, 1)), 0.0)
    if "Fwd Seg Size Min" in smap:
        bh = g("Bwd Header Length")
        new["Fwd Seg Size Min"] = np.where(nb == 1, bh, np.where(nb > 1, np.floor(bh / np.maximum(nb, 1)), 0.0))
        exact["Fwd Seg Size Min"] = nb <= 1
    if "Fwd Act Data Pkts" in smap:
        bmax, bmin, blen = g("Bwd Packet Length Max"), g("Bwd Packet Length Min"), g("Total Length of Bwd Packet")
        with np.errstate(invalid="ignore", divide="ignore"):
            lb = np.maximum(0.0, np.ceil(blen / np.where(bmax > 0, bmax, 1)) - 1)
        new["Fwd Act Data Pkts"] = np.where(nb <= 1, 0.0, np.where(bmax == 0, 0.0, np.where(bmin >= 1, nb - 1, lb)))
        exact["Fwd Act Data Pkts"] = (nb <= 1) | (bmax == 0) | (bmin >= 1)
    if "Fwd PSH Flags" in smap:
        rest = g("PSH Flag Count") - g("Fwd PSH Flags")
        all_b = (nf == 1) & (rest >= nb) & (nb >= 1)
        new["Fwd PSH Flags"] = np.where(rest <= 0, 0.0, np.where(all_b, 1.0, 0.0))
        exact["Fwd PSH Flags"] = (rest <= 0) | all_b
    for a, b in IDENTITY_PAIRS:
        if a in df.columns and b in df.columns:
            new[a], new[b] = sub[b].to_numpy(), sub[a].to_numpy()
    cols = list(new)
    for c in cols:
        if pd.api.types.is_numeric_dtype(out[c].dtype):
            out.iloc[idx, out.columns.get_loc(c)] = np.asarray(new[c], dtype=out[c].dtype)
        else:
            out.iloc[idx, out.columns.get_loc(c)] = new[c]
    if "Flow ID" in df.columns and all(c in df.columns for c in ("Src IP", "Dst IP", "Src Port", "Dst Port")):
        s = out.iloc[idx]
        proto = pd.to_numeric(s[PROTO], errors="coerce").fillna(-1).astype(int).astype(str)
        out.iloc[idx, out.columns.get_loc("Flow ID")] = (s["Src IP"].astype(str) + "-" + s["Dst IP"].astype(str) + "-"
                                                          + s["Src Port"].astype(str) + "-" + s["Dst Port"].astype(str)
                                                          + "-" + proto).to_numpy()
    return out, exact


def normalise(df: pd.DataFrame, smap: dict, variant: str = "R1") -> tuple[pd.DataFrame, np.ndarray, dict]:
    """Flag with the rule, swap the flagged rows. Returns (frame, flags, exactness)."""
    fl = rule_flags(df, variant)
    out, ex = swap_rows(df, fl, smap)
    return out, fl, ex


def ks_stat(a: np.ndarray, b: np.ndarray) -> float:
    """Two-sample Kolmogorov-Smirnov statistic sup |F_a - F_b| (NaN if either side is empty)."""
    a, b = np.sort(np.asarray(a, float)), np.sort(np.asarray(b, float))
    if not len(a) or not len(b):
        return float("nan")
    v = np.concatenate([a, b])
    return float(np.max(np.abs(np.searchsorted(a, v, side="right") / len(a) - np.searchsorted(b, v, side="right") / len(b))))


def value_shares(v: np.ndarray, top: list) -> dict:
    v = np.asarray(v, float)
    out = {f"{t:g}": float((v == t).mean()) if len(v) else float("nan") for t in top}
    out["other"] = float((~np.isin(v, top)).mean()) if len(v) else float("nan")
    return out


def py(o):
    """JSON-safe Python types (numpy scalars / arrays, NaN -> None)."""
    if isinstance(o, dict):
        return {str(k): py(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [py(v) for v in o]
    if isinstance(o, np.ndarray):
        return py(o.tolist())
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating, float)):
        return None if not np.isfinite(o) else float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    return o


def qd(v) -> dict:
    v = np.asarray(v, float)
    return {f"q{int(q * 100)}": (float(np.quantile(v, q)) if len(v) else None) for q in QS} | {"n": int(len(v))}


# --------------------------------------------------------------------------- figures
def fig_flip_heatmap(path, rows: list[dict], names, title):
    import matplotlib.pyplot as plt
    from matplotlib.colors import Normalize
    PS.apply()
    cols = sorted({(r["split"], r["group"]) for r in rows}, key=lambda x: (x[0] != "train", x[1]))
    K = len(names)
    V = np.full((K, len(cols)), np.nan)
    N = np.zeros((K, len(cols)), int)
    for r in rows:
        j = cols.index((r["split"], r["group"]))
        V[r["class_id"], j], N[r["class_id"], j] = r["pct_R1"], r["n"]
    fig, ax = plt.subplots(figsize=(1.15 * len(cols) + 1.8, 0.62 * K + 1.3))
    shown = np.where(np.isnan(V), 0, V)
    ax.imshow(shown, cmap=PS.SEQUENTIAL_CMAP, norm=Normalize(0, max(1.0, float(np.nanmax(shown)))), aspect="auto")
    for i in range(K):
        for j in range(len(cols)):
            if N[i, j] == 0:
                ax.text(j, i, "-", ha="center", va="center", fontsize=8, color=PS.TEXT2)
            else:
                ax.text(j, i, f"{V[i, j]:.2f} %\nn={N[i, j]:,}", ha="center", va="center", fontsize=6.8,
                        color="#ffffff" if V[i, j] > 0.6 * max(1.0, float(np.nanmax(shown))) else PS.TEXT1)
    ax.set_xticks(range(len(cols)), [f"{s}\n{g}" for s, g in cols], fontsize=8)
    ax.set_yticks(range(K), names, fontsize=8)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title(title, loc="left", fontsize=9)
    PS.save(fig, path)


def fig_initwin(path, shares: dict, cls_id: int, title):
    """shares: {"before"|"after": {"train": {value: share}, "val": {...}}}."""
    import matplotlib.pyplot as plt
    PS.apply()
    cats = list(shares["before"]["train"])
    fig, axes = plt.subplots(1, 2, figsize=(8.4, 0.5 * len(cats) + 1.6), sharey=True)
    y = np.arange(len(cats))
    for ax, when in zip(axes, ("before", "after")):
        tr = [100 * shares[when]["train"][c] for c in cats]
        va = [100 * shares[when]["val"][c] for c in cats]
        ax.barh(y - 0.2, tr, 0.38, color=PS.NEUTRAL_LIGHT, edgecolor=PS.SURFACE, lw=1, label=shares["labels"]["train"])
        ax.barh(y + 0.2, va, 0.38, color=PS.class_color(cls_id), edgecolor=PS.SURFACE, lw=1, label=shares["labels"]["val"])
        for yi, (a, b) in enumerate(zip(tr, va)):                       # label non-empty bars only
            if a > 0:
                ax.text(a + 1, yi - 0.2, f"{a:.1f} %", va="center", fontsize=7, color=PS.TEXT2)
            if b > 0:
                ax.text(b + 1, yi + 0.2, f"{b:.1f} %", va="center", fontsize=7, color=PS.TEXT1)
        ax.set_xlim(0, 118)
        ax.set_yticks(y, cats)
        ax.invert_yaxis()
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_xlabel("% of flows")
        ax.set_title("before flipping" if when == "before" else "after flipping (R1, train and val)", loc="left", fontsize=8.5)
    axes[0].set_ylabel(FIW)
    axes[1].legend(frameon=False, loc="lower right", fontsize=7.5)
    fig.subplots_adjust(top=0.8, wspace=0.08)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_recall(path, rec: dict, names, title):
    """rec: {model: {"original": [K], "flipped": [K]}} (recall per class, NaN = no support)."""
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    PS.apply()
    models = list(rec)
    K = len(names)
    fig, axes = plt.subplots(1, len(models), figsize=(3.1 * len(models) + 0.8, 0.5 * K + 1.5), squeeze=False)
    for ax, m in zip(axes[0], models):
        for k in range(K):
            a, b = rec[m]["original"][k], rec[m]["flipped"][k]
            if a is None or (isinstance(a, float) and np.isnan(a)):
                continue
            ax.plot([a, b], [k, k], color=PS.GRID, lw=2, zorder=1)
            ax.plot([a], [k], "o", mfc=PS.SURFACE, mec=PS.class_color(k), ms=8, mew=1.6, zorder=2)
            ax.plot([b], [k], "o", color=PS.class_color(k), ms=5.5, zorder=3)
            if abs(b - a) >= 0.01:
                ax.text(max(a, b) + 0.03, k, f"{a:.3f} -> {b:.3f}", va="center", fontsize=6.8, color=PS.TEXT1)
        ax.set_yticks(range(K), names if ax is axes[0][0] else [""] * K, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlim(-0.02, 1.35)
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
        ax.xaxis.grid(True)
        ax.set_title(m, loc="left", fontsize=8.5)
        ax.set_xlabel("recall (seed 0)")
    h = [Line2D([], [], marker="o", ls="", mfc=PS.SURFACE, mec=PS.TEXT1, label="original val"),
         Line2D([], [], marker="o", ls="", color=PS.TEXT1, label="flipped val (R1)")]
    fig.legend(handles=h, frameon=False, ncol=2, loc="lower center", bbox_to_anchor=(0.5, -0.04), fontsize=7.5)
    fig.subplots_adjust(top=0.8, bottom=0.26, wspace=0.1)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_macro(path, mac: dict, title):
    """mac: {condition: {system: {"macro_f1_all", "macro_f1_nonrare"}}}."""
    import matplotlib.pyplot as plt
    PS.apply()
    conds = list(mac)
    systems = list(mac[conds[0]])
    styles = {systems[0]: dict(color=PS.TEXT1, ls="-", marker="o"), systems[1]: dict(color=PS.NEUTRAL_LIGHT, ls="--", marker="s")}
    fig, axes = plt.subplots(1, 2, figsize=(8.0, 3.0))
    for ax, key, lab in zip(axes, ("macro_f1_all", "macro_f1_nonrare"), ("macro-F1, all classes", "macro-F1, non-rare classes")):
        for si, s in enumerate(systems):
            v = [mac[c][s][key] for c in conds]
            ax.plot(range(len(conds)), v, lw=2, ms=8, mew=0, label=s, **styles[s])
            for xi, vi in enumerate(v):                                 # ROUTED labels left, FLAT_GLOBAL right
                ax.text(xi + (-0.08 if si == 0 else 0.08), vi, f"{vi:.4f}", fontsize=7, va="center",
                        ha="right" if si == 0 else "left", color=PS.TEXT1 if si == 0 else PS.TEXT2)
        ax.set_xticks(range(len(conds)), conds, fontsize=8)
        ax.set_xlim(-0.6, len(conds) - 0.4)
        ax.yaxis.grid(True)
        ax.set_title(lab, loc="left", fontsize=8.5)
    axes[0].legend(frameon=False, fontsize=7.5, loc="best")
    fig.subplots_adjust(top=0.8, wspace=0.3)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


# --------------------------------------------------------------------------- main
def main() -> int:
    import xgboost as xgb
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--class-a", default="port_scan", help="the class whose flows are reversed")
    ap.add_argument("--class-b", default="syn_flood", help="the class they are mislabelled as")
    ap.add_argument("--focus-group", default="G1")
    args = ap.parse_args()
    cfg = load_phase2_config()
    S.verify_v2_lock(strict=True)
    pins_before = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                     ("config/class_map.json", S.CLASS_MAP_PATH))}
    print(f"sha256 BEFORE  config/config.py {pins_before['config/config.py']}  "
          f"config/class_map.json {pins_before['config/class_map.json']}", flush=True)
    cm = S.load_class_map()
    names, K = list(cm.names), cm.n_classes
    if args.class_a not in names or args.class_b not in names:
        raise SystemExit(f"classes must be in the class map {names}")
    A, B = cm.id_of(args.class_a), cm.id_of(args.class_b)
    feats = S.feature_columns()
    smap = build_swap_map(feats)                                       # raises on any uncovered feature
    up22 = R.resolve_run("22", None, False)
    up23 = R.resolve_run("23", None, False)
    up25 = R.resolve_run("25", None, False)
    ctx = R.start_run(STEP, "diag", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    M.update({"train_run": up22["meta"]["run_id"], "train_run_manifest_sha256": up22["manifest_sha256"],
              "eval_run": up23["meta"]["run_id"], "eval_run_manifest_sha256": up23["manifest_sha256"],
              "shap_run": up25["meta"]["run_id"], "shap_run_manifest_sha256": up25["manifest_sha256"],
              "pins_before": pins_before, "class_a": args.class_a, "class_b": args.class_b,
              "focus_group": args.focus_group, "follows": ["results/diag_01", "results/diag_01b"],
              "read_only": "no model trained; no dataset version; flips in memory only; no existing file changed; "
                           "test never read"})
    ok, out = False, {}
    fg = args.focus_group
    try:
        c = cfg["columns"]
        import pyarrow.parquet as pq
        ident = ["Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "src_mac", "dst_mac", "device", "device_mac",
                 c["session"], c["start_ts"]]
        schema = pq.read_schema(D.split_file(cfg, "val")).names
        missing = [m for m in feats + ident + [c["group"], c["label_id"]] if m not in schema]
        if missing:
            raise RuntimeError(f"required columns missing: {missing}")
        cols = feats + ident + [c["group"], c["label_id"]]
        tr = D.load_split(cfg, "train", cols, sample=args.dry_run)
        va = D.load_split(cfg, "val", cols, sample=args.dry_run)
        M["inputs"] = {"train_sha256": D.verify_split_file(cfg, "train"), "val_sha256": D.verify_split_file(cfg, "val"),
                       "test_read": False, "n_train": int(len(tr)), "n_val": int(len(va))}
        src = Path(CICFM_SRC).expanduser()
        M["cicflowmeter_source"] = {"path": CICFM_SRC, "sha256": R.sha256_path(src) if src.is_file() else None}
        ctx.log(f"train {len(tr):,}  val {len(va):,}")
        splits = {"train": tr, "val": va}
        y = {s: d[c["label_id"]].to_numpy(np.int64) for s, d in splits.items()}
        grp = {s: d[c["group"]].astype(str).to_numpy() for s, d in splits.items()}
        groups = sorted(set(grp["train"]) | set(grp["val"]))
        if fg not in groups:
            raise RuntimeError(f"focus group {fg} not in the data {groups}")
        flags = {s: {v: rule_flags(d, v) for v in ("R1", "R2")} for s, d in splits.items()}
        # Flow ID format check (rebuild rule of the swap map)
        fid_ok = {}
        for s, d in splits.items():
            rebuilt = (d["Src IP"].astype(str) + "-" + d["Dst IP"].astype(str) + "-" + d["Src Port"].astype(str) + "-"
                       + d["Dst Port"].astype(str) + "-" + pd.to_numeric(d[PROTO]).astype(int).astype(str))
            fid_ok[s] = float((rebuilt == d["Flow ID"].astype(str)).mean())
        # ---------------- T1 map file
        omap = {"status": "PROPOSED -- for review; NOT in config/ and not used by any pipeline step",
                "created_by": SCRIPT, "run_id": ctx.run_id,
                "cicflowmeter_source_reviewed": M["cicflowmeter_source"],
                "features_file_sha256": S.FEATURES_V1_SHA256,
                "rule": {"R1_proposed": f"{FIW} == 0 AND {BIW} > 0",
                         "R2_variant": f"R1 AND {SYN} >= 1",
                         "recommended_guards": [f"{PROTO} == {TCP} (TCP only; a no-op on this data, defensive)",
                                                "NaN / negative window -> not reversed"],
                         "rationale": "the first packet of a flow is always written as forward; a TCP opener (SYN) "
                                      "never carries window 0, so a window-0 first packet (RST / RST-ACK) is not the "
                                      "initiator's; non-TCP flows have both windows 0"},
                "features": smap,
                "identity": {"pairs": [list(p) for p in IDENTITY_PAIRS], "rebuild": IDENTITY_REBUILD,
                             "direction_free": IDENTITY_FREE, "flow_id_format_match": fid_ok},
                "dropped_features_notes": DROPPED_NOTES,
                "counts": {k: sum(1 for e in smap.values() if e["class"] == k)
                           for k in ("pair", "pair_asymmetric", "direction_free", "derived", "unpaired")},
                "unresolved": [f for f, e in smap.items() if e.get("status") == "UNRESOLVED"],
                "limits": ["a swap re-labels orientation; it cannot change which packet came first in time "
                           "(time-first-packet fields keep the time-first packet)",
                           "CICFlowMeter's timeout / sweep successor inherits the OLD flow's orientation while its "
                           "first packet is always written forward: such mixed rows are not fixable by a swap",
                           "R1 does not catch reversals whose first packet has a non-zero window (e.g. SYN/ACK first)"]}
        out["t1"] = {"counts": omap["counts"], "unresolved": omap["unresolved"], "flow_id_format_match": fid_ok}
        # ---------------- T2 flip counts
        t2 = []
        for s in splits:
            for g in groups:
                for k in range(K):
                    m_ = (grp[s] == g) & (y[s] == k)
                    if m_.any():
                        n1, n2 = int(flags[s]["R1"][m_].sum()), int(flags[s]["R2"][m_].sum())
                        t2.append({"split": s, "group": g, "class": names[k], "class_id": k, "n": int(m_.sum()),
                                   "flag_R1": n1, "pct_R1": 100 * n1 / m_.sum(), "flag_R2": n2, "pct_R2": 100 * n2 / m_.sum()})
        out["t2_rows"] = t2
        dev = []
        for s, d in splits.items():
            b_ = y[s] == BENIGN
            tab = pd.DataFrame({"device": d["device"].astype(str).to_numpy()[b_], "group": grp[s][b_],
                                "R1": flags[s]["R1"][b_], "R2": flags[s]["R2"][b_]})
            gg = tab.groupby(["group", "device"]).agg(n=("R1", "size"), flag_R1=("R1", "sum"), flag_R2=("R2", "sum")).reset_index()
            gg["pct_R1"] = 100 * gg["flag_R1"] / gg["n"]
            gg["split"] = s
            dev += gg.sort_values(["flag_R1", "n"], ascending=False).to_dict("records")
        out["t2_benign_devices"] = dev
        edge = {}
        for s, d in splits.items():
            fw = pd.to_numeric(d[FIW], errors="coerce")
            bw = pd.to_numeric(d[BIW], errors="coerce")
            pr = pd.to_numeric(d[PROTO], errors="coerce")
            tcp = (pr == TCP).to_numpy()
            both0 = ((fw == 0) & (bw == 0)).to_numpy()
            edge[s] = {"protocol_counts": {f"{k:g}": int(v) for k, v in pr.value_counts().sort_index().items()},
                       "both_windows_0_by_protocol": {f"{k:g}": int(v) for k, v in pr[both0].value_counts().sort_index().items()},
                       "both_windows_0_tcp_by_class": {names[k]: int((both0 & tcp & (y[s] == k)).sum()) for k in range(K)},
                       "bwd_win_missing": int(bw.isna().sum()), "bwd_win_negative": int((bw < 0).sum()),
                       "fwd_win_missing": int(fw.isna().sum()), "fwd_win_negative": int((fw < 0).sum()),
                       "non_tcp_flagged_R1": int((flags[s]["R1"] & ~tcp).sum()),
                       "non_tcp_flagged_R2": int((flags[s]["R2"] & ~tcp).sum()),
                       "non_tcp_any_nonzero_window": int((~tcp & ((fw != 0) | (bw != 0)).to_numpy()).sum()),
                       "tcp_guard_changes_R1": int((flags[s]["R1"] != rule_flags(d, "R1", tcp_guard=True)).sum()),
                       "fwd_win_0_tcp": int(((fw == 0).to_numpy() & tcp).sum())}
        out["t2_edge"] = edge
        # independent orientation signal for attack rows: the attack's target device is the source
        orc = []
        for s, d in splits.items():
            vf = (d["src_mac"].astype(str) == d["device_mac"].astype(str)).to_numpy()
            for k in range(K):
                if k == BENIGN:
                    continue
                m_ = y[s] == k
                if not m_.any():
                    continue
                for v in ("R1", "R2"):
                    f_ = flags[s][v]
                    orc.append({"split": s, "class": names[k], "rule": v, "n": int(m_.sum()),
                                "victim_first": int((m_ & vf).sum()), "flagged": int((m_ & f_).sum()),
                                "flagged_and_victim_first": int((m_ & f_ & vf).sum()),
                                "flagged_not_victim_first": int((m_ & f_ & ~vf).sum()),
                                "victim_first_not_flagged": int((m_ & vf & ~f_).sum())})
            miss = (y[s] != BENIGN) & vf & ~flags[s]["R1"]
            out.setdefault("t2_missed_fwd_win", {})[s] = {
                names[k]: {f"{w:g}": int(n) for w, n in pd.Series(pd.to_numeric(d.loc[miss & (y[s] == k), FIW])).value_counts().head(6).items()}
                for k in range(K) if (miss & (y[s] == k)).any()}
        out["t2_oracle"] = orc
        # ---------------- models (seed 0, read-only) and predictions
        seed0 = cfg["seeds"][0]
        M22 = up22["manifest"]
        prim, default = M22["routing"]["primary"], M22["routing"]["default"]
        mids = sorted(set(prim.values()) | {default})
        boosters = {}
        for mid in mids:
            m = next(x for x in M22["models"] if x["model_id"] == mid and x["seed"] == seed0)
            p = up22["dir"] / m["file"]
            if R.sha256_path(p) != m["sha256"]:
                raise RuntimeError(f"{p}: sha256 != step 22 manifest")
            bst = xgb.Booster()
            bst.load_model(str(p))
            boosters[mid] = bst
        M["models_read"] = [f"{m}__s{seed0}" for m in mids]
        spec = prim.get(fg, default)
        # flipped val (and train, for T5) -- in memory only
        flipped, exact = {}, {}
        for v in ("R1", "R2"):
            flipped[v], f_, exact[v] = normalise(va, smap, v)
            assert (f_ == flags["val"][v]).all()
        tr_flip, _, _ = normalise(tr, smap, "R1")
        # sanity: unflagged rows untouched, normaliser idempotent
        un = ~flags["val"]["R1"]
        same = flipped["R1"][feats].to_numpy()[un]
        orig = va[feats].to_numpy()[un]
        R.add_check(ctx, M, "normaliser leaves unflagged val rows bit-identical",
                    bool(np.array_equal(same, orig, equal_nan=True)), f"{int(un.sum()):,} rows")
        again, f2, _ = normalise(flipped["R1"], smap, "R1")
        R.add_check(ctx, M, "normaliser is idempotent on val (flagged rows no longer flagged after the swap)",
                    bool(not f2.any() and np.array_equal(again[feats].to_numpy(), flipped["R1"][feats].to_numpy(), equal_nan=True)),
                    f"re-flagged {int(f2.sum())}")
        Xv = {"original": D.feature_matrix(va, feats), "flipped R1": D.feature_matrix(flipped["R1"], feats),
              "flipped R2": D.feature_matrix(flipped["R2"], feats)}
        P = {cond: {mid: boosters[mid].predict(xgb.DMatrix(X)) for mid in mids} for cond, X in Xv.items()}
        yv, gv = y["val"], grp["val"]
        # ---------------- T3 coverage
        fz = pd.to_numeric(va[FIW]).to_numpy() == 0
        sel = (gv == fg) & (yv == A)
        pred_spec = P["original"][spec].argmax(1)
        foc = gv == fg
        err_all = foc & (pred_spec != yv)
        err_ab = foc & (yv == A) & (pred_spec == B)
        t3 = {"focus_A_n": int(sel.sum()), "focus_A_fwd_win_0": int((sel & fz).sum())}
        for v in ("R1", "R2"):
            f_ = flags["val"][v]
            t3[v] = {"focus_A_fwd0_flagged": int((sel & fz & f_).sum()),
                     "pct_focus_A_fwd0_flagged": 100 * (sel & fz & f_).sum() / max(1, (sel & fz).sum()),
                     "focus_A_flagged": int((sel & f_).sum()),
                     "spec_errors_all": int(err_all.sum()), "spec_errors_all_flagged": int((err_all & f_).sum()),
                     "pct_spec_errors_all_flagged": 100 * (err_all & f_).sum() / max(1, err_all.sum()),
                     "spec_errors_A_to_B": int(err_ab.sum()), "spec_errors_A_to_B_flagged": int((err_ab & f_).sum()),
                     "pct_spec_errors_A_to_B_flagged": 100 * (err_ab & f_).sum() / max(1, err_ab.sum())}
        ex = exact["R1"]
        n_fl = int(flags["val"]["R1"].sum())
        t3["exactness_val_R1"] = {f: {"rows": n_fl, "exact": int(e.sum())} for f, e in ex.items()}
        allex = np.ones(n_fl, bool)
        for e in ex.values():
            allex &= e
        t3["exactness_val_R1"]["ALL_FIELDS"] = {"rows": n_fl, "exact": int(allex.sum())}
        sel_in_fl = sel[np.flatnonzero(flags["val"]["R1"])]
        t3["exactness_focus_A_all_fields"] = {"rows": int(sel_in_fl.sum()), "exact": int((allex & sel_in_fl).sum())}
        out["t3"] = t3
        # ---------------- T4 benign profile
        t4 = {}
        for s, d in splits.items():
            for v in ("R1", "R2"):
                m_ = (y[s] == BENIGN) & flags[s][v]
                sub = d.loc[m_]
                if not len(sub):
                    t4[f"{s}|{v}"] = {"n": 0}
                    continue
                num = lambda col: pd.to_numeric(sub[col], errors="coerce").to_numpy(float)  # noqa: E731
                sp, dp = num("Src Port"), num("Dst Port")
                t4[f"{s}|{v}"] = {
                    "n": int(len(sub)), "n_benign": int((y[s] == BENIGN).sum()),
                    "protocol": {f"{k:g}": int(n) for k, n in pd.Series(num(PROTO)).value_counts().items()},
                    "top_devices": sub["device"].astype(str).value_counts().head(8).to_dict(),
                    "n_devices": int(sub["device"].nunique()),
                    "share_syn_0": float((num(SYN) == 0).mean()), "share_rst_ge1": float((num("RST Flag Count") >= 1).mean()),
                    "share_fin_ge1": float((num("FIN Flag Count") >= 1).mean()), "share_ack_ge1": float((num("ACK Flag Count") >= 1).mean()),
                    "share_fwd_1pkt": float((num(NF) == 1).mean()),
                    "share_fwd_payload_0": float((num("Total Length of Fwd Packet") == 0).mean()),
                    "share_dst_port_lt1024": float((dp < 1024).mean()), "share_src_port_lt1024": float((sp < 1024).mean()),
                    "top_dst_port": sub["Dst Port"].astype(str).value_counts().head(5).to_dict(),
                    "top_src_port": sub["Src Port"].astype(str).value_counts().head(5).to_dict(),
                    "share_device_is_src": float((sub["src_mac"].astype(str) == sub["device_mac"].astype(str)).mean()),
                    "duration_us": qd(num("Flow Duration")), "fwd_pkts": qd(num(NF)), "bwd_pkts": qd(num(NB)),
                    "bwd_init_win": qd(num(BIW)), "syn": qd(num(SYN)), "rst": qd(num("RST Flag Count")),
                    "fin": qd(num("FIN Flag Count")), "ack": qd(num("ACK Flag Count"))}
            # reference: all benign TCP of the split
            mt = (y[s] == BENIGN) & (pd.to_numeric(d[PROTO]).to_numpy() == TCP)
            t4[f"{s}|benign_tcp_reference"] = {"n": int(mt.sum()),
                                              "share_syn_0": float((pd.to_numeric(d.loc[mt, SYN]) == 0).mean()),
                                              "share_rst_ge1": float((pd.to_numeric(d.loc[mt, "RST Flag Count"]) >= 1).mean()),
                                              "share_fwd_win_0": float((pd.to_numeric(d.loc[mt, FIW]) == 0).mean())}
        out["t4"] = t4
        # ---------------- T5 shift (focus val class A vs train class A)
        top10 = up25_top10(up25, spec, seed0)
        trA = y["train"] == A
        trA_fg = trA & (grp["train"] == fg)
        t5 = {"top10_features": top10, "ks": []}
        for f in top10:
            vr = pd.to_numeric(va.loc[sel, f]).to_numpy(float)
            vflip = pd.to_numeric(flipped["R1"].loc[sel, f]).to_numpy(float)
            for ref_name, tm in (("train all groups", trA), (f"train {fg}", trA_fg)):
                t_raw = pd.to_numeric(tr.loc[tm, f]).to_numpy(float)
                t_flip = pd.to_numeric(tr_flip.loc[tm, f]).to_numpy(float)
                t5["ks"].append({"feature": f, "reference": ref_name, "before": ks_stat(vr, t_raw),
                                 "after_both_flipped": ks_stat(vflip, t_flip), "flipped_val_vs_raw_train": ks_stat(vflip, t_raw)})
        tops = sorted(set(pd.to_numeric(tr.loc[trA, FIW]).value_counts().head(4).index.tolist())
                      | set(pd.to_numeric(va.loc[sel, FIW]).value_counts().head(3).index.tolist()))
        t5["initwin_values"] = [float(x) for x in tops]
        sh = {"labels": {"train": f"train {args.class_a} (all groups, n={int(trA.sum()):,})",
                         "val": f"{fg} val {args.class_a} (n={int(sel.sum()):,})"}}
        for when, tdf, vdf in (("before", tr, va), ("after", tr_flip, flipped["R1"])):
            sh[when] = {"train": value_shares(pd.to_numeric(tdf.loc[trA, FIW]).to_numpy(), tops),
                        "val": value_shares(pd.to_numeric(vdf.loc[sel, FIW]).to_numpy(), tops),
                        "train_focus_group": value_shares(pd.to_numeric(tdf.loc[trA_fg, FIW]).to_numpy(), tops)}
        t5["initwin_shares"] = sh
        t5["train_flagged_R1_classA"] = {"all_groups": int((trA & flags["train"]["R1"]).sum()), "n": int(trA.sum())}
        out["t5"] = t5
        # ---------------- T6 models: original vs flipped
        mv, lvl = cfg["min_val_flows"], cfg["eval"]["ci_level"]
        spec_of = {s_["model_id"]: s_ for s_ in M22["specs"]}
        t6 = {"models": {}, "systems": {}}
        for mid in mids:
            kind, val_ = spec_of[mid]["subset"]
            if kind not in ("all", "group"):
                raise RuntimeError(f"{mid}: subset kind {kind!r} not expected for a primary model")
            rows = np.ones(len(yv), bool) if kind == "all" else D.pooled_mask(yv, gv == str(val_))
            t6["models"][mid] = {}
            for cond in Xv:
                Pm = P[cond][mid]
                ent = {}
                for sname, smask in {"all": np.ones(len(yv), bool), **{g: gv == g for g in groups}}.items():
                    rr = rows & smask
                    if not rr.any():
                        continue
                    r_ = PM.classification_metrics(yv[rr], Pm[rr], K, mv, lvl, with_auc=False)
                    ent[sname] = {"recall": r_["recall"], "support": r_["support"], "macro_f1_all": r_["macro_f1_all"],
                                  "macro_f1_nonrare": r_["macro_f1_nonrare"], "confusion": r_["confusion"],
                                  "fa_count": int(((yv[rr] == BENIGN) & (Pm[rr].argmax(1) != BENIGN)).sum()),
                                  "n_benign": int((yv[rr] == BENIGN).sum())}
                t6["models"][mid][cond] = ent
        sysdefs = {"ROUTED": np.array([prim.get(g, default) for g in gv], dtype=object),
                   "FLAT_GLOBAL": np.full(len(gv), default, dtype=object)}
        for sname, mpr in sysdefs.items():
            t6["systems"][sname] = {}
            for cond in Xv:
                Ps = np.empty_like(P[cond][default])
                for mid in np.unique(mpr):
                    Ps[mpr == mid] = P[cond][mid][mpr == mid]
                ent = {}
                for sub_, smask in {"all": np.ones(len(yv), bool), **{g: gv == g for g in groups}}.items():
                    if not smask.any():
                        continue
                    r_ = PM.classification_metrics(yv[smask], Ps[smask], K, mv, lvl, with_auc=False)
                    ent[sub_] = {"recall": r_["recall"], "macro_f1_all": r_["macro_f1_all"],
                                 "macro_f1_nonrare": r_["macro_f1_nonrare"], "rare_classes": r_["rare_classes"],
                                 "fa_count": int(((yv[smask] == BENIGN) & (Ps[smask].argmax(1) != BENIGN)).sum()),
                                 "confusion": r_["confusion"]}
                t6["systems"][sname][cond] = ent
        out["t6"] = t6
        # reproduction of step 23 seed 0 on the original val (full run only)
        E23 = json.loads((up23["dir"] / "metrics_per_seed.json").read_text(encoding="utf-8"))
        sk = str(seed0)
        diffs = []
        for sname in sysdefs:
            for k_ in ("macro_f1_all", "macro_f1_nonrare"):
                diffs.append(abs(E23[sname]["all"][sk][k_] - t6["systems"][sname]["original"]["all"][k_]))
            diffs.append(abs(E23[sname]["all"][sk]["fa_count"] - t6["systems"][sname]["original"]["all"]["fa_count"]))
        for mid in mids:
            a_ = np.array(E23[mid]["all"][sk]["recall"], float)
            b_ = np.array(t6["models"][mid]["original"]["all"]["recall"], float)
            diffs.append(float(np.nanmax(np.abs(a_ - b_))))
            diffs.append(abs(E23[mid]["all"][sk]["fa_count"] - t6["models"][mid]["original"]["all"]["fa_count"]))
        repro = max(diffs)
        if args.dry_run:
            R.add_check(ctx, M, "original-val seed-0 metrics reproduce step 23 (n/a on the dry-run sample)", True,
                        f"max |diff| {repro:.3g} (sample, not comparable)", warn=True)
        else:
            R.add_check(ctx, M, "original-val seed-0 metrics reproduce step 23 (ROUTED / FLAT_GLOBAL macro-F1 + false "
                        "alarms, per-model recall + false alarms)", repro < 1e-9, f"max |diff| {repro:.3g}")
        out["t6_repro_max_abs_diff"] = repro
        # ---------------- verdict
        crit_a = t3["R1"]["pct_focus_A_fwd0_flagged"] >= 95.0
        ben = [r for r in t2 if r["class_id"] == BENIGN]
        worst_b = max(ben, key=lambda r: r["pct_R1"]) if ben else None
        crit_b = all(r["pct_R1"] <= 1.0 for r in ben)
        crit_c = all(edge[s]["non_tcp_flagged_R1"] == 0 for s in edge)
        crit_d = not omap["unresolved"] and all(e.get("default") for e in smap.values() if e["class"] == "unpaired")
        rs = t6["systems"]["ROUTED"]["flipped R1"]["all"]
        fgs = t6["systems"]["FLAT_GLOBAL"]["flipped R1"]["all"]
        out["verdict"] = {"pass": bool(crit_a and crit_b and crit_c and crit_d), "a": bool(crit_a), "b": bool(crit_b),
                          "c": bool(crit_c), "d": bool(crit_d),
                          "a_value": t3["R1"]["pct_focus_A_fwd0_flagged"],
                          "b_worst": worst_b, "c_values": {s: edge[s]["non_tcp_flagged_R1"] for s in edge},
                          "d_unresolved": omap["unresolved"],
                          "report_spec_A_recall_focus_flipped": t6["models"][spec]["flipped R1"].get(fg, {}).get("recall", [None] * K)[A],
                          "report_spec_A_recall_focus_original": t6["models"][spec]["original"].get(fg, {}).get("recall", [None] * K)[A],
                          "report_routed_ge_flat_all": bool(rs["macro_f1_all"] >= fgs["macro_f1_all"]),
                          "report_routed_ge_flat_nonrare": bool(rs["macro_f1_nonrare"] >= fgs["macro_f1_nonrare"])}
        omap["review_verdict_run"] = out["verdict"]
        omap_sha = R.write_json(ctx.res / "orientation_map_proposed.json", py(omap))
        M["orientation_map_proposed_sha256"] = omap_sha
        R.write_json(ctx.partial / "diag_02.json", py(out))
        # ---------------- figures
        fig_flip_heatmap(ctx.fig / "flip_rate_heatmap.png", t2, names,
                         "Rows flagged REVERSED by R1 (FWD Init Win == 0 and Bwd Init Win > 0), % of class per split x group")
        fig_initwin(ctx.fig / "fwd_init_win_before_after.png", sh, A,
                    f"{FIW}: {fg} val {args.class_a} vs train {args.class_a}, before and after flipping")
        rec = {}
        for mid in mids:
            key = "all"
            rec[f"{mid} (pooled val)"] = {"original": t6["models"][mid]["original"][key]["recall"],
                                          "flipped": t6["models"][mid]["flipped R1"][key]["recall"]}
        fig_recall(ctx.fig / "recall_before_after.png", rec, names,
                   "Per-class recall of the seed-0 models (trained on UNFLIPPED train), original vs flipped val")
        mac = {c_: {s_: {k_: t6["systems"][s_][c_]["all"][k_] for k_ in ("macro_f1_all", "macro_f1_nonrare")}
                    for s_ in sysdefs} for c_ in Xv}
        fig_macro(ctx.fig / "routed_vs_flat_macro_f1.png", mac,
                  "ROUTED vs FLAT_GLOBAL on val (seed 0): original vs flipped (lower bound -- models not retrained)")
        M["figures"] = sorted(str(p.relative_to(ctx.res)) for p in ctx.fig.glob("*.png"))
        M["verdict"] = out["verdict"]
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
        omap = {}
    M["pins_after"] = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                         ("config/class_map.json", S.CLASS_MAP_PATH))}
    print(f"sha256 AFTER   config/config.py {M['pins_after']['config/config.py']}  "
          f"config/class_map.json {M['pins_after']['config/class_map.json']}", flush=True)
    R.add_check(ctx, M, "config.py / class_map.json unchanged by this run", M["pins_after"] == pins_before,
                str(M["pins_after"]))
    ok = ok and M["pins_after"] == pins_before
    M["status"] = "PASS" if ok else "FAIL"
    write_summary(ctx.res / "summary.md", M, out, omap, names, args, ctx)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def up25_top10(up25: dict, spec: str, seed: int) -> list[str]:
    """Top-10 features (global mean |SHAP|) of the focus specialist from step 25's shap.json (read-only)."""
    p = up25["dir"] / "shap.json"
    sj = json.loads(p.read_text(encoding="utf-8"))
    ent = sj[f"{spec}__s{seed}"]
    out = []
    for it in ent["top10_global"]:
        out.append(it["feature"] if isinstance(it, dict) else (it[0] if isinstance(it, (list, tuple)) else str(it)))
    return out[:10]


# --------------------------------------------------------------------------- summary
def _f(x, d=4):
    return "n/a" if x is None or (isinstance(x, float) and not np.isfinite(x)) else f"{x:.{d}f}"


def write_summary(path, M, out, omap, names, args, ctx) -> None:
    a, b, fg = args.class_a, args.class_b, args.focus_group
    K = len(names)
    L = [f"# diag_02 -- orientation-normaliser rule check -- {M['status']}" + (" (DRY RUN)" if M["dry_run"] else ""), "",
         f"- run `{ctx.run_id}`; READ-ONLY: train / val via common/phase2_data.load_split (test never read); seed-0 "
         f"primary models of step 22 run `{M['train_run']}` loaded read-only (sha256 checked) and used to PREDICT val; "
         f"top-10 SHAP features from step 25 run `{M['shap_run']}`; every flip is in memory; nothing trained, no dataset "
         "version, no existing file changed.",
         f"- rule **R1 (proposed)**: `{FIW} == 0 AND {BIW} > 0`. Variant **R2**: R1 AND `{SYN} >= 1` (reported, not "
         "part of the verdict).",
         "- swap map from CICFlowMeter's `BasicFlow.java` (reviewed source, sha256 "
         f"`{(M.get('cicflowmeter_source') or {}).get('sha256')}`): `orientation_map_proposed.json` (for review; NOT in config/).",
         "", "## Verdict rule (fixed before the numbers)", "",
         "**PASS** only if all four hold:",
         f"- (a) R1 flags >= 95 % of {fg} val {a} flows that have {FIW} = 0;",
         "- (b) flagged benign <= 1 % of benign in every split x group (or the excess is shown in T4 to be genuine reversals);",
         "- (c) R1 never flags a non-TCP flow;",
         "- (d) the swap map has no UNRESOLVED feature, or each unresolved one has a stated safe default.",
         f"Reported separately (not part of PASS): the {fg} specialist's {a} recall on flipped {fg} val, and whether ROUTED "
         "now >= FLAT_GLOBAL.", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
        path.write_text("\n".join(L), encoding="utf-8")
        return
    V = out["verdict"]
    t3, t6 = out["t3"], out["t6"]
    wb = V["b_worst"]
    L += ["## Verdict", "",
          f"- **{'PASS' if V['pass'] else 'FAIL'}**",
          f"- (a) {'PASS' if V['a'] else 'FAIL'}: R1 flags {t3['R1']['focus_A_fwd0_flagged']:,} of "
          f"{t3['focus_A_fwd_win_0']:,} {fg} val {a} flows with {FIW} = 0 = **{V['a_value']:.2f} %** (>= 95 %).",
          f"- (b) {'PASS' if V['b'] else 'FAIL'}: worst split x group = {wb['split']} {wb['group']}: {wb['flag_R1']:,} of "
          f"{wb['n']:,} benign = **{wb['pct_R1']:.3f} %** (<= 1 %)." if wb else "- (b) n/a",
          f"- (c) {'PASS' if V['c'] else 'FAIL'}: non-TCP flows flagged = {V['c_values']}.",
          f"- (d) {'PASS' if V['d'] else 'FAIL'}: UNRESOLVED entries = {V['d_unresolved'] or 'none'}; the 3 unpaired fields "
          "and the asymmetric init-window pair carry a stated default and exactness condition (T1).",
          "", "Reported separately (lower bound: models trained on UNFLIPPED train, not retrained):", "",
          f"- {fg} specialist {a} recall on {fg} val: "
          f"original **{_f(V['report_spec_A_recall_focus_original'])}** -> flipped (R1) **{_f(V['report_spec_A_recall_focus_flipped'])}**.",
          f"- ROUTED >= FLAT_GLOBAL on flipped val: macro-F1 all **{'YES' if V['report_routed_ge_flat_all'] else 'NO'}**, "
          f"non-rare **{'YES' if V['report_routed_ge_flat_nonrare'] else 'NO'}** (numbers in T6).", ""]
    # T1
    counts = out["t1"]["counts"]
    L += ["## T1 -- swap map (70 features + identity)", "",
          f"- {counts['pair']} features in {counts['pair'] // 2} exact forward/backward pairs; {counts['pair_asymmetric']} in "
          f"1 asymmetric pair; {counts['direction_free']} direction-free; {counts['derived']} derived (recomputed); "
          f"{counts['unpaired']} unpaired with a stated default; **UNRESOLVED: {len(out['t1']['unresolved'])}**.",
          f"- identity: swap Src IP <-> Dst IP, Src Port <-> Dst Port, src_mac <-> dst_mac; rebuild Flow ID (format "
          f"'src-dst-sport-dport-proto' matches {', '.join(f'{s} {100 * v:.1f} %' for s, v in out['t1']['flow_id_format_match'].items())} "
          "of rows); keep device / device_mac / owner_mac / group / timestamps (dataset attribution, orientation-free).", "",
          "| feature | class | partner / handling | exact when |", "|---|---|---|---|"]
    for f, e in omap["features"].items():
        if e["class"] == "pair":
            if f.startswith(("Total Fwd", "Total Length of Fwd", "Fwd ", "Subflow Fwd")):
                L.append(f"| {f} | pair | <-> {e['partner']} | always |")
        elif e["class"] == "pair_asymmetric":
            L.append(f"| {f} | **asymmetric pair** | <-> {e['partner']} -- {'first fwd packet' if f == FIW else 'LAST bwd packet'}'s window | {e['exact_when']} |")
        elif e["class"] in ("derived", "unpaired"):
            L.append(f"| {f} | **{e['class']}** | {e['how']} | {e['exact_when']} |")
    free = [f for f, e in omap["features"].items() if e["class"] == "direction_free"]
    L += ["", f"Direction-free ({len(free)}): " + ", ".join(free) + ".", "",
          "Ambiguous fields resolved from the source:",
          "- **Subflow Fwd/Bwd Packets / Bytes**: direction count / sfCount, and sfCount (gaps > 1 s) is direction-free -> exact pairs.",
          "- **Fwd PSH Flags**: incremented only in firstPacket() -> 'the first forward packet has PSH'; Bwd PSH Flags is "
          "structurally 0 (dropped); no partner -> unpaired.",
          "- **Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg**: reference-equality bug sends every packet to the "
          "'backward' bulk counters -> they describe all packets, direction-free (the Fwd bulk features are structurally 0).",
          "- **Fwd Seg Size Min**: minimum header bytes of forward packets, no backward counterpart -> unpaired.",
          "- **FWD / Bwd Init Win Bytes**: first forward packet vs LAST backward packet -> asymmetric.",
          "- **Active / Idle**, **Flow IAT**: computed on every packet's timestamp -> direction-free; **Fwd / Bwd IAT**: exact pairs.",
          "- **Down/Up Ratio**: Java integer division of the packet counts -> recomputed.", ""]
    ex = t3["exactness_val_R1"]
    L += [f"Exactness on the {ex['ALL_FIELDS']['rows']:,} val rows R1 flags: " + "; ".join(
        f"{f} {v['exact']:,} ({100 * v['exact'] / max(1, v['rows']):.1f} %)" for f, v in ex.items()) +
          f". {fg} val {a} flagged rows exact in every field: {t3['exactness_focus_A_all_fields']['exact']:,} of "
          f"{t3['exactness_focus_A_all_fields']['rows']:,}.", ""]
    # T2
    L += ["## T2 -- what the rule flips", "",
          "| split | group | class | n | R1 flagged | R1 % | R2 flagged | R2 % |", "|---|---|---|---|---|---|---|---|"]
    for r in out["t2_rows"]:
        L.append(f"| {r['split']} | {r['group']} | {r['class']} | {r['n']:,} | {r['flag_R1']:,} | {r['pct_R1']:.3f} | "
                 f"{r['flag_R2']:,} | {r['pct_R2']:.3f} |")
    L += ["", "Benign per device (devices with >= 1 R1-flagged flow; top 12 per split):", "",
          "| split | group | device | benign n | R1 flagged | R1 % | R2 flagged |", "|---|---|---|---|---|---|---|"]
    for s in ("train", "val"):
        rows = [r for r in out["t2_benign_devices"] if r["split"] == s and r["flag_R1"] > 0][:12]
        L += [f"| {s} | {r['group']} | {r['device']} | {r['n']:,} | {int(r['flag_R1']):,} | {r['pct_R1']:.2f} | {int(r['flag_R2']):,} |" for r in rows]
    L += ["", "Edge cases:", ""]
    for s, e in out["t2_edge"].items():
        L += [f"- {s}: protocol column `{PROTO}` values {e['protocol_counts']}; both windows 0 by protocol "
              f"{e['both_windows_0_by_protocol']} (TCP by class {e['both_windows_0_tcp_by_class']}); Bwd window missing "
              f"{e['bwd_win_missing']} / negative {e['bwd_win_negative']}; FWD window missing {e['fwd_win_missing']} / negative "
              f"{e['fwd_win_negative']}; **non-TCP flagged R1 {e['non_tcp_flagged_R1']}**, R2 {e['non_tcp_flagged_R2']}; "
              f"non-TCP rows with any non-zero window {e['non_tcp_any_nonzero_window']}; a `{PROTO} == {TCP}` guard changes "
              f"{e['tcp_guard_changes_R1']} R1 flags."]
    L += ["", "Independent orientation signal for attack rows (source MAC == the attacked device's MAC = 'victim first'):", "",
          "| split | class | rule | n | victim-first | flagged | flagged & victim-first | flagged, not victim-first | victim-first, not flagged |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in out["t2_oracle"]:
        L.append(f"| {r['split']} | {r['class']} | {r['rule']} | {r['n']:,} | {r['victim_first']:,} | {r['flagged']:,} | "
                 f"{r['flagged_and_victim_first']:,} | {r['flagged_not_victim_first']:,} | {r['victim_first_not_flagged']:,} |")
    L += ["", f"- {FIW} of victim-first attack flows R1 does NOT flag (top values): "
          + "; ".join(f"{s}: {json.dumps(v)}" for s, v in out["t2_missed_fwd_win"].items()), ""]
    # T3
    L += ["## T3 -- coverage of the known errors", "",
          f"- {fg} val {a}: {t3['focus_A_n']:,} flows, {t3['focus_A_fwd_win_0']:,} with {FIW} = 0.", "",
          "| rule | flagged of the FWD-win-0 flows | % | specialist errors on " + fg + " val (all) flagged | % | "
          f"{a} -> {b} errors flagged | % |", "|---|---|---|---|---|---|---|"]
    for v in ("R1", "R2"):
        q = t3[v]
        L.append(f"| {v} | {q['focus_A_fwd0_flagged']:,} / {t3['focus_A_fwd_win_0']:,} | {q['pct_focus_A_fwd0_flagged']:.2f} | "
                 f"{q['spec_errors_all_flagged']:,} / {q['spec_errors_all']:,} | {q['pct_spec_errors_all_flagged']:.2f} | "
                 f"{q['spec_errors_A_to_B_flagged']:,} / {q['spec_errors_A_to_B']:,} | {q['pct_spec_errors_A_to_B_flagged']:.2f} |")
    L += [""]
    # T4
    L += ["## T4 -- safety on benign: profile of flagged benign flows", "",
          "| split, rule | flagged | devices | TCP | SYN = 0 | RST >= 1 | FIN >= 1 | 1 fwd pkt | fwd payload 0 | Dst Port < 1024 | "
          "Src Port < 1024 | device is source | duration q50 [q5, q95] us | bwd pkts q50 [q95] |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for k_, d in out["t4"].items():
        if k_.endswith("reference") or not d.get("n"):
            if not k_.endswith("reference"):
                L.append(f"| {k_.replace('|', ', ')} | 0 | | | | | | | | | | | | |")
            continue
        pct = lambda x: f"{100 * x:.1f} %"  # noqa: E731
        L.append(f"| {k_.replace('|', ', ')} | {d['n']:,} | {d['n_devices']} | {d['protocol'].get(str(TCP), 0):,} | "
                 f"{pct(d['share_syn_0'])} | {pct(d['share_rst_ge1'])} | {pct(d['share_fin_ge1'])} | {pct(d['share_fwd_1pkt'])} | "
                 f"{pct(d['share_fwd_payload_0'])} | {pct(d['share_dst_port_lt1024'])} | {pct(d['share_src_port_lt1024'])} | "
                 f"{pct(d['share_device_is_src'])} | {d['duration_us']['q50']:g} [{d['duration_us']['q5']:g}, "
                 f"{d['duration_us']['q95']:g}] | {d['bwd_pkts']['q50']:g} [{d['bwd_pkts']['q95']:g}] |")
    for s in ("train", "val"):
        r_ = out["t4"].get(f"{s}|benign_tcp_reference")
        if r_:
            L.append(f"- reference, all {s} benign TCP ({r_['n']:,}): SYN = 0 {100 * r_['share_syn_0']:.1f} %, RST >= 1 "
                     f"{100 * r_['share_rst_ge1']:.1f} %, {FIW} = 0 {100 * r_['share_fwd_win_0']:.1f} %.")
    for k_ in ("train|R1", "val|R1"):
        d = out["t4"].get(k_, {})
        if d.get("n"):
            L.append(f"- {k_}: top devices {d['top_devices']}; top Dst Port {d['top_dst_port']}; top Src Port {d['top_src_port']}.")
    L += ["", "Judgement: see the final report / section 'T4 judgement' below.", ""]
    L += t4_judgement(out, a)
    # T5
    t5 = out["t5"]
    L += ["## T5 -- does flipping make val look like train? (in memory)", "",
          f"{FIW} shares ({t5['initwin_shares']['labels']['val']} vs {t5['initwin_shares']['labels']['train']}):", "",
          "| value | train before | val before | train after | val after | train " + fg + " before | train " + fg + " after |",
          "|---|---|---|---|---|---|---|"]
    sh = t5["initwin_shares"]
    for v in sh["before"]["train"]:
        L.append(f"| {v} | {100 * sh['before']['train'][v]:.1f} % | {100 * sh['before']['val'][v]:.1f} % | "
                 f"{100 * sh['after']['train'][v]:.1f} % | {100 * sh['after']['val'][v]:.1f} % | "
                 f"{100 * sh['before']['train_focus_group'][v]:.1f} % | {100 * sh['after']['train_focus_group'][v]:.1f} % |")
    L += ["", f"KS statistic, {fg} val {a} vs train {a}, for the top-10 SHAP features of the {fg} specialist "
          "(after = normaliser applied to train and val; last column = flipped val vs the raw train the models saw):", "",
          "| feature | reference | before | after (both flipped) | flipped val vs raw train |", "|---|---|---|---|---|"]
    for r in t5["ks"]:
        L.append(f"| {r['feature']} | {r['reference']} | {_f(r['before'])} | {_f(r['after_both_flipped'])} | {_f(r['flipped_val_vs_raw_train'])} |")
    L += [""]
    # T6
    L += ["## T6 -- effect on the EXISTING models (predict only; seed 0)", "",
          "**Lower bound**: every model was trained on UNFLIPPED train; retraining on normalised data is the real test.", "",
          f"- original-val metrics reproduce step 23 seed 0: max |diff| = {out['t6_repro_max_abs_diff']:.3g}.", "",
          "Per model, step 23's evaluation rows (specialist: own-group benign + every attack row; GLOBAL: all val):", "",
          "| model | subset | condition | " + " | ".join(f"recall {n}" for n in names) + " | false alarms (benign -> attack) |",
          "|---|---|---|" + "---|" * K + "---|"]
    for mid, conds in t6["models"].items():
        for sub_ in conds["original"]:
            for cond, ent in conds.items():
                if sub_ in ent:
                    e = ent[sub_]
                    L.append(f"| {mid} | {sub_} | {cond} | " + " | ".join(_f(x) for x in e["recall"]) +
                             f" | {e['fa_count']} / {e['n_benign']:,} |")
    L += ["", "Systems (every val row; ROUTED = each flow -> its group's specialist, else GLOBAL):", "",
          "| system | subset | condition | macro-F1 all | macro-F1 non-rare | " + " | ".join(f"recall {n}" for n in names) +
          " | false alarms |", "|---|---|---|---|---|" + "---|" * K + "---|"]
    for sname, conds in t6["systems"].items():
        for sub_ in conds["original"]:
            for cond, ent in conds.items():
                if sub_ in ent:
                    e = ent[sub_]
                    L.append(f"| {sname} | {sub_} | {cond} | {_f(e['macro_f1_all'])} | {_f(e['macro_f1_nonrare'])} | "
                             + " | ".join(_f(x) for x in e["recall"]) + f" | {e['fa_count']} |")
    L += ["", "## Figures", "",
          "- `figures/flip_rate_heatmap.png` -- % of each class flagged REVERSED by R1, per split x group (n per cell).",
          f"- `figures/fwd_init_win_before_after.png` -- {FIW} value shares, {fg} val {a} vs train {a}, before and after "
          "flipping (normaliser applied to both splits).",
          "- `figures/recall_before_after.png` -- per-class recall of the seed-0 primary models on their step-23 val rows, "
          "original (hollow) vs flipped val (filled); models not retrained.",
          "- `figures/routed_vs_flat_macro_f1.png` -- ROUTED vs FLAT_GLOBAL macro-F1 (all / non-rare classes), original vs "
          "flipped (R1, R2) val, seed 0; lower bound.", ""]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def t4_judgement(out, a) -> list[str]:
    """Evidence-based judgement lines for the flagged benign flows (numbers from out['t4'])."""
    L = ["### T4 judgement", ""]
    for s in ("train", "val"):
        d = out["t4"].get(f"{s}|R1", {})
        d2 = out["t4"].get(f"{s}|R2", {})
        if not d.get("n"):
            L.append(f"- {s}: no benign flow flagged.")
            continue
        txt = (f"- {s}: {d['n']:,} of {d['n_benign']:,} benign flagged ({100 * d['n'] / d['n_benign']:.3f} %); TCP "
               f"{d['protocol'].get(str(TCP), 0):,}; {100 * d['share_syn_0']:.1f} % carry no SYN, "
               f"{100 * d['share_rst_ge1']:.1f} % a RST, {100 * d['share_fin_ge1']:.1f} % a FIN, "
               f"{100 * d['share_fwd_1pkt']:.1f} % a single forward packet.")
        if d["share_syn_0"] >= 0.9 and d["share_rst_ge1"] >= 0.9:
            txt += (" -> mostly connection TAILS (a window-0 RST written first, the peer's FIN/ACKs after), not openers: "
                    "genuine 'first packet is not the initiator's' cases.")
        if d["share_dst_port_lt1024"] >= 0.5 and d["share_device_is_src"] >= 0.5:
            txt += (f" But {100 * d['share_dst_port_lt1024']:.1f} % have a service port (< 1024) as Dst Port and "
                    f"{100 * d['share_device_is_src']:.1f} % the device as source: the current source is usually the "
                    "CLIENT, so the swap makes the SERVER the source -- a mis-flip in client/server terms.")
        txt += f" R2 (needs a SYN) flags {d2.get('n', 0):,} of them."
        L.append(txt)
    return L + [""]


if __name__ == "__main__":
    sys.exit(main())
