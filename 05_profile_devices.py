#!/usr/bin/env python
"""05_profile_devices.py -- one behaviour fingerprint per smart-home device (Step 6).

Inputs (never modified):
  flows    tagged benign flows from 04_tag_flows.py (84 CICFlowMeter columns + tag columns)
  devices  config/device_table.csv

Outputs (<out-dir>):
  device_fingerprints.csv          one row per smart-home device: metadata + all raw features
  device_fingerprints_scaled.csv   metadata + KEPT features, robust-scaled
  feature_correlation.csv          Spearman rho of all features (high-confidence devices)
  kept_features.txt                kept feature names, one per line
  profile_report.md / .json        run metadata, filter result, confidence, pruning, stats,
                                   category colours, figure list with suggested captions
  figures/fig1..fig4 .pdf + .png   paper figures (vector PDF + 300-dpi PNG)

Usable flows: owner_status == "owned" and exclude_reason blank. Grouped by owner_mac.

Direction: the owner is the Src side if owner_mac == src_mac, else the Dst side.
  upload bytes = bytes sent by the owner (fwd if owner is Src, bwd if owner is Dst)
  peer         = the other endpoint (IP, port, role)

Features (log = log10(1 + x); bytes = fwd + bwd payload bytes; pct_* in percent 0-100):
  Volume    log_flows_per_hour   usable flows / capture hours (capture = min..max Timestamp
                                 over ALL flows in the input, so every device shares one
                                 observation window)
            log_median_bytes, log_p90_bytes
  Shape     median_packets, pct_single_packet, log_median_duration_us,
            upload_ratio         sum upload bytes / sum total bytes (NaN if no bytes)
  Protocol  pct_tcp (6), pct_udp (17)
  Services  pct_dns (peer port 53), pct_discovery (peer port 5353 or 1900)
  Rhythm    gap_cv               std/mean (population std) of gaps between sorted flow start
                                 times; NaN if < 20 flows or mean gap 0. Timestamps have
                                 1-second resolution, so sub-second gaps read as 0.
  Peers     pct_internet (peer role external), pct_device (peer role iot),
            log_distinct_peers   distinct peer IPs (a count only, never an identity)

No clustering here. Exit status is non-zero if an input is missing, a column cannot be
matched, or any integrity check fails.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import platform
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import scipy  # noqa: E402
from matplotlib.colors import ListedColormap  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

ROOT = Path(__file__).resolve().parent
TS_FORMAT = "%d/%m/%Y %I:%M:%S %p"
SMART_HOME_ROLE = "iot"
MIN_GAP_FLOWS = 20
SENSITIVITY_THRESHOLDS = (50, 100, 200)
SCALED_CLIP = 3.0
DNS_PORTS = {53}
DISCOVERY_PORTS = {5353, 1900}

# Priority for correlation pruning: earlier = kept when a pair is too correlated.
PRIORITY = ["upload_ratio", "pct_udp", "pct_tcp", "log_flows_per_hour", "log_median_bytes",
            "pct_single_packet", "gap_cv", "pct_internet", "pct_device", "pct_dns",
            "pct_discovery", "log_median_duration_us", "median_packets", "log_p90_bytes",
            "log_distinct_peers"]
# Display order (grouped by family) for tables and figures.
FEATURES = ["log_flows_per_hour", "log_median_bytes", "log_p90_bytes",
            "median_packets", "pct_single_packet", "log_median_duration_us", "upload_ratio",
            "pct_tcp", "pct_udp", "pct_dns", "pct_discovery", "gap_cv",
            "pct_internet", "pct_device", "log_distinct_peers"]
FAMILY = {"log_flows_per_hour": "Volume", "log_median_bytes": "Volume",
          "log_p90_bytes": "Volume", "median_packets": "Shape",
          "pct_single_packet": "Shape", "log_median_duration_us": "Shape",
          "upload_ratio": "Shape", "pct_tcp": "Protocol", "pct_udp": "Protocol",
          "pct_dns": "Services", "pct_discovery": "Services", "gap_cv": "Rhythm",
          "pct_internet": "Peers", "pct_device": "Peers", "log_distinct_peers": "Peers"}
# Axis / tick labels with units.
LABEL = {"log_flows_per_hour": "log$_{10}$(1+flows/h)",
         "log_median_bytes": "log$_{10}$(1+median bytes)",
         "log_p90_bytes": "log$_{10}$(1+p90 bytes)",
         "median_packets": "median packets/flow",
         "pct_single_packet": "single-packet flows (%)",
         "log_median_duration_us": "log$_{10}$(1+median duration, µs)",
         "upload_ratio": "upload ratio",
         "pct_tcp": "TCP (%)", "pct_udp": "UDP (%)", "pct_dns": "DNS (%)",
         "pct_discovery": "mDNS/SSDP (%)", "gap_cv": "inter-flow gap CV",
         "pct_internet": "Internet peers (%)", "pct_device": "device peers (%)",
         "log_distinct_peers": "log$_{10}$(1+distinct peers)"}
assert sorted(PRIORITY) == sorted(FEATURES)

# Okabe-Ito (colour-blind safe); categories get colours in this fixed order.
OKABE_ITO = ["#E69F00", "#56B4E9", "#009E73", "#F0E442", "#0072B2", "#D55E00", "#CC79A7",
             "#000000"]
CATEGORY_ORDER = ["Camera", "Audio", "Hub", "Home Automation", "Lighting", "Power Outlet",
                  "Unidentified (Espressif)"]
NOTABLE = ["Fibaro", "Arlo Q", "HeimVision SmartLife", "LIFX", "Echo Dot 2", "GoSund",
           "ESP plug", "Smart Board"]

FLOW_COLS = {
    "src_ip": ["srcip", "sourceip"], "dst_ip": ["dstip", "destinationip"],
    "src_port": ["srcport", "sourceport"], "dst_port": ["dstport", "destinationport"],
    "protocol": ["protocol"], "timestamp": ["timestamp"], "duration": ["flowduration"],
    "fwd_pkts": ["totalfwdpacket", "totalfwdpackets", "totfwdpkts"],
    "bwd_pkts": ["totalbwdpackets", "totalbwdpacket", "totbwdpkts", "totalbackwardpackets"],
    "fwd_bytes": ["totallengthoffwdpacket", "totallengthoffwdpackets", "totlenfwdpkts"],
    "bwd_bytes": ["totallengthofbwdpacket", "totallengthofbwdpackets", "totlenbwdpkts"],
    "src_mac": ["srcmac"], "dst_mac": ["dstmac"], "src_role": ["srcrole"],
    "dst_role": ["dstrole"], "owner_mac": ["ownermac"], "owner_device": ["ownerdevice"],
    "owner_status": ["ownerstatus"], "exclude_reason": ["excludereason"],
}
NUMERIC = ["src_port", "dst_port", "protocol", "duration", "fwd_pkts", "bwd_pkts",
           "fwd_bytes", "bwd_bytes"]

# Reuse 02's helpers so every step parses MACs / columns / hashes identically.
_spec = importlib.util.spec_from_file_location("mac_ip_map", ROOT / "02_mac_ip_map.py")
m02 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m02)
log, fatal, pct, norm_mac, sha256 = m02.log, m02.fatal, m02.pct, m02.norm_mac, m02.sha256


def log1p10(x):
    return np.log10(1.0 + x)


# --------------------------------------------------------------------------- loading

def load_devices(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    cols = m02.match_columns(list(df.columns), m02.DEVICE_COLS, f"device table {path}")
    dev = pd.DataFrame({k: df[v].str.strip() for k, v in cols.items()})
    dev["mac"] = dev["mac"].map(norm_mac)
    dev["role"] = dev["role"].str.lower()
    if dev["mac"].duplicated().any():
        fatal(f"duplicate MACs in device table: {dev['mac'][dev['mac'].duplicated()].tolist()}")
    return dev


def load_flows(path: Path) -> tuple[pd.DataFrame, dict, int]:
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    cols = m02.match_columns(list(raw.columns), FLOW_COLS, f"flows {path}")
    f = pd.DataFrame({k: raw[v].str.strip() for k, v in cols.items()})
    for k in NUMERIC:
        f[k] = pd.to_numeric(f[k], errors="coerce")
    for k in ("src_mac", "dst_mac", "owner_mac"):
        f[k] = f[k].map(norm_mac)
    f["ts"] = pd.to_datetime(f["timestamp"], format=TS_FORMAT, errors="coerce", utc=True)
    return f, cols, len(raw)


# --------------------------------------------------------------------------- features

def orient(u: pd.DataFrame) -> pd.DataFrame:
    """Per usable flow: owner side, upload bytes, peer IP / port / role."""
    src = (u["owner_mac"] == u["src_mac"]).to_numpy()
    o = pd.DataFrame(index=u.index)
    o["owner_is_src"] = src
    o["bytes"] = u["fwd_bytes"] + u["bwd_bytes"]
    o["packets"] = u["fwd_pkts"] + u["bwd_pkts"]
    o["upload"] = np.where(src, u["fwd_bytes"], u["bwd_bytes"])
    o["peer_ip"] = np.where(src, u["dst_ip"], u["src_ip"])
    o["peer_port"] = np.where(src, u["dst_port"], u["src_port"])
    o["peer_role"] = np.where(src, u["dst_role"], u["src_role"])
    return o


def gap_cv(ts: pd.Series) -> float:
    if len(ts) < MIN_GAP_FLOWS:
        return np.nan
    t = np.sort(ts.astype("int64").to_numpy()) / 1e9
    g = np.diff(t)
    m = g.mean()
    return float(g.std() / m) if m > 0 else np.nan


def device_features(u: pd.DataFrame, o: pd.DataFrame, hours: float) -> dict:
    n = len(u)
    proto = u["protocol"]
    tot = o["bytes"].sum()
    return {
        "log_flows_per_hour": log1p10(n / hours),
        "log_median_bytes": log1p10(o["bytes"].median()),
        "log_p90_bytes": log1p10(o["bytes"].quantile(0.9)),
        "median_packets": float(o["packets"].median()),
        "pct_single_packet": pct(int((o["packets"] == 1).sum()), n),
        "log_median_duration_us": log1p10(u["duration"].median()),
        "upload_ratio": float(o["upload"].sum() / tot) if tot > 0 else np.nan,
        "pct_tcp": pct(int((proto == 6).sum()), n),
        "pct_udp": pct(int((proto == 17).sum()), n),
        "pct_dns": pct(int(o["peer_port"].isin(DNS_PORTS).sum()), n),
        "pct_discovery": pct(int(o["peer_port"].isin(DISCOVERY_PORTS).sum()), n),
        "gap_cv": gap_cv(u["ts"]),
        "pct_internet": pct(int((o["peer_role"] == "external").sum()), n),
        "pct_device": pct(int((o["peer_role"] == SMART_HOME_ROLE).sum()), n),
        "log_distinct_peers": log1p10(o["peer_ip"].nunique()),
    }


def build_fingerprints(u: pd.DataFrame, o: pd.DataFrame, homes: pd.DataFrame, hours: float,
                       min_flows: int) -> pd.DataFrame:
    rows = []
    groups = dict(tuple(u.groupby("owner_mac")))
    for _, d in homes.iterrows():
        g = groups.get(d["mac"])
        n = 0 if g is None else len(g)
        row = {"mac": d["mac"], "device_name": d["device_name"], "category": d["category"],
               "vendor_family": d.get("vendor_family", ""), "usable_flows": n,
               "confidence": "high" if n >= min_flows else "low"}
        feats = device_features(g, o.loc[g.index], hours) if n else {k: np.nan for k in FEATURES}
        row.update({k: (round(float(v), 6) if pd.notna(v) else np.nan) for k, v in feats.items()})
        rows.append(row)
    fp = pd.DataFrame(rows)
    cat_rank = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    fp["_r"] = fp["category"].map(lambda c: cat_rank.get(c, len(cat_rank)))
    return fp.sort_values(["_r", "category", "device_name"]).drop(columns="_r").reset_index(drop=True)


# --------------------------------------------------------------------------- pruning

def prune(rho: pd.DataFrame, thr: float) -> tuple[list[str], list[dict]]:
    """Resolve |rho| > thr pairs strongest-first; drop the lower-priority member."""
    rank = {f: i for i, f in enumerate(PRIORITY)}
    kept, drops = list(FEATURES), []
    while True:
        pairs = [(abs(rho.at[a, b]), a, b) for i, a in enumerate(kept) for b in kept[i + 1:]
                 if pd.notna(rho.at[a, b]) and abs(rho.at[a, b]) > thr]
        if not pairs:
            break
        r, a, b = max(pairs, key=lambda p: (p[0], -min(rank[p[1]], rank[p[2]])))
        keep, drop = (a, b) if rank[a] < rank[b] else (b, a)
        drops.append({"dropped": drop, "partner_kept": keep, "rho": round(float(rho.at[a, b]), 4),
                      "abs_rho": round(r, 4), "order": len(drops) + 1})
        kept.remove(drop)
    return kept, drops


def robust_scale(fp: pd.DataFrame, kept: list[str], hi: pd.Series) -> tuple[pd.DataFrame, dict]:
    params, out = {}, fp[["mac", "device_name", "category", "usable_flows", "confidence"]].copy()
    for k in kept:
        ref = fp.loc[hi, k].dropna()
        med = float(ref.median())
        iqr = float(ref.quantile(0.75) - ref.quantile(0.25))
        fallback = not iqr > 0
        scale = 1.0 if fallback else iqr
        params[k] = {"median": round(med, 6), "iqr": round(iqr, 6), "scale_used": scale,
                     "iqr_zero_fallback": fallback}
        out[k] = ((fp[k] - med) / scale).round(6)
    return out, params


# --------------------------------------------------------------------------- figures

def setup_style() -> None:
    plt.rcParams.update({
        "font.size": 9, "axes.labelsize": 10, "xtick.labelsize": 9, "ytick.labelsize": 9,
        "legend.fontsize": 8.5, "font.family": "DejaVu Sans", "pdf.fonttype": 42,
        "ps.fonttype": 42, "axes.spines.top": False, "axes.spines.right": False,
        "savefig.dpi": 300,
    })


def save(fig, figdir: Path, name: str, extra=()) -> list[str]:
    paths = []
    for ext in ("pdf", "png"):
        p = figdir / f"{name}.{ext}"
        fig.savefig(p, bbox_inches="tight", dpi=300, bbox_extra_artists=list(extra) or None)
        paths.append(str(p))
    plt.close(fig)
    return paths


def cat_handles(colors: dict, present: list[str]) -> list:
    return [Patch(facecolor=colors[c], edgecolor="none", label=c) for c in present]


def fig1_correlation(rho: pd.DataFrame, kept: list[str], figdir: Path) -> list[str]:
    n = len(FEATURES)
    fig, ax = plt.subplots(figsize=(7.4, 6.6))
    m = rho.loc[FEATURES, FEATURES].to_numpy(dtype=float)
    im = ax.imshow(m, cmap="RdBu_r", vmin=-1, vmax=1, aspect="equal")
    for i in range(n):
        for j in range(n):
            v = m[i, j]
            txt = "–" if np.isnan(v) else f"{v:.2f}"
            ax.text(j, i, txt, ha="center", va="center", fontsize=6.5,
                    color="white" if abs(np.nan_to_num(v)) > 0.6 else "black")
    labels = [LABEL[f] + ("" if f in kept else " *") for f in FEATURES]
    ax.set_xticks(range(n), labels, rotation=55, ha="right", rotation_mode="anchor")
    ax.set_yticks(range(n), labels)
    for tl in ax.get_xticklabels() + ax.get_yticklabels():
        if tl.get_text().endswith(" *"):
            tl.set_color("#777777")
            tl.set_fontstyle("italic")
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02, ticks=[-1, -0.5, 0, 0.5, 1])
    cb.set_label("Spearman ρ")
    ax.annotate("* dropped by correlation pruning (grey italic)", (0, 1.01),
                xycoords="axes fraction", va="bottom", fontsize=8, color="#555555")
    return save(fig, figdir, "fig1_feature_correlation")


def fig2_fingerprints(sc: pd.DataFrame, kept: list[str], colors: dict, figdir: Path) -> list[str]:
    d = sc[sc["usable_flows"] > 0].reset_index(drop=True)
    nr, nc = len(d), len(kept)
    fig = plt.figure(figsize=(1.9 + 0.42 * nc + 1.2, 0.8 + 0.165 * nr))
    gs = fig.add_gridspec(1, 3, width_ratios=[0.035 * nc, nc, 0.06 * nc], wspace=0.03)
    axc, ax, axb = fig.add_subplot(gs[0]), fig.add_subplot(gs[1]), fig.add_subplot(gs[2])
    m = np.clip(d[kept].to_numpy(dtype=float), -SCALED_CLIP, SCALED_CLIP)
    cmap = plt.get_cmap("RdBu_r").copy()
    cmap.set_bad("#d9d9d9")
    im = ax.imshow(np.ma.masked_invalid(m), cmap=cmap, vmin=-SCALED_CLIP, vmax=SCALED_CLIP,
                   aspect="auto", interpolation="nearest")
    cats = list(dict.fromkeys(d["category"]))
    cidx = d["category"].map({c: i for i, c in enumerate(cats)}).to_numpy()[:, None]
    axc.imshow(cidx, cmap=ListedColormap([colors[c] for c in cats]), aspect="auto",
               vmin=-0.5, vmax=len(cats) - 0.5, interpolation="nearest")
    axc.set_xticks([])
    low = (d["confidence"] == "low").to_numpy()
    ylabels = [f"{n} †" if lo else n for n, lo in zip(d["device_name"], low)]
    axc.set_yticks(range(nr), ylabels, fontsize=8)
    for tl, lo in zip(axc.get_yticklabels(), low):
        if lo:
            tl.set_color("#777777")
            tl.set_fontstyle("italic")
    for i in np.where(low)[0]:  # hatch low-confidence rows
        ax.add_patch(plt.Rectangle((-0.5, i - 0.5), nc, 1, fill=False, hatch="////",
                                   edgecolor="#555555", linewidth=0, alpha=0.5))
    ax.set_yticks([])
    ax.set_xticks(range(nc), [LABEL[k] for k in kept], rotation=55, ha="right",
                  rotation_mode="anchor")
    bounds = np.where(d["category"].to_numpy()[1:] != d["category"].to_numpy()[:-1])[0]
    for b in bounds:
        for a in (ax, axc):
            a.axhline(b + 0.5, color="white", lw=1.2)
    for a in (ax, axc):
        a.tick_params(length=0)
        for s in a.spines.values():
            s.set_visible(False)
    cb = fig.colorbar(im, cax=axb, extend="both")
    cb.set_label(f"robust z = (x − median)/IQR, clipped ±{SCALED_CLIP:g}")
    hs = cat_handles(colors, cats) + [
        Patch(facecolor="white", edgecolor="#555555", hatch="////",
              label="† low confidence"),
        Patch(facecolor="#d9d9d9", edgecolor="none", label="undefined (NaN)")]
    leg = ax.legend(handles=hs, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=3,
                    frameon=False)
    return save(fig, figdir, "fig2_device_fingerprints", [leg])


def place_labels(ax, fig, xs, ys, texts, idx_all_pts) -> None:
    """Greedy non-overlapping label placement among 16 candidate offsets."""
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    pts = ax.transData.transform(np.column_stack(idx_all_pts))
    taken = []
    cands = [(dx, dy) for rad in (14, 26, 40) for dx, dy in
             [(1, 1), (1, -1), (-1, 1), (-1, -1), (1, 0), (-1, 0), (0, 1), (0, -1)]]
    axbb = ax.get_window_extent(r)
    for x, y, t in zip(xs, ys, texts):
        best = None
        for k, (dx, dy) in enumerate(cands):
            rad = 14 if k < 8 else 26 if k < 16 else 40
            n = np.hypot(dx, dy)
            off = (dx / n * rad, dy / n * rad)
            ha = "left" if dx > 0 else "right" if dx < 0 else "center"
            va = "bottom" if dy > 0 else "top" if dy < 0 else "center"
            a = ax.annotate(t, (x, y), xytext=off, textcoords="offset points", ha=ha, va=va,
                            fontsize=8, arrowprops=dict(arrowstyle="-", lw=0.6, color="#444444",
                                                        shrinkA=0, shrinkB=3))
            bb = a.get_window_extent(r).expanded(1.05, 1.15)
            hit = sum(bb.overlaps(o) for o in taken)
            hit += int(np.sum((pts[:, 0] > bb.x0) & (pts[:, 0] < bb.x1) &
                              (pts[:, 1] > bb.y0) & (pts[:, 1] < bb.y1)))
            inside = (bb.x0 >= axbb.x0 and bb.x1 <= axbb.x1 and bb.y0 >= axbb.y0
                      and bb.y1 <= axbb.y1)
            score = hit + (0 if inside else 100)
            if best is None or score < best[0]:
                if best is not None:
                    best[1].remove()
                best = (score, a, bb)
            else:
                a.remove()
            if score == 0:
                break
        taken.append(best[2])


def fig3_volume_size(fp: pd.DataFrame, colors: dict, figdir: Path) -> tuple[list[str], list[str]]:
    d = fp[fp["usable_flows"] > 0]
    fig, ax = plt.subplots(figsize=(6.6, 4.6))
    size = lambda n: 12 * np.log10(n) + 4  # noqa: E731  (area ∝ log10 usable flows)
    for c in dict.fromkeys(d["category"]):
        s = d[d["category"] == c]
        ax.scatter(s["log_flows_per_hour"], s["log_median_bytes"], s=size(s["usable_flows"]),
                   c=colors[c], edgecolors=np.where(s["confidence"] == "low", "#000000", "white"),
                   linewidths=np.where(s["confidence"] == "low", 0.9, 0.5), label=c, zorder=3)
    names = []
    for pat in NOTABLE:
        hit = d[d["device_name"].str.contains(pat, regex=False)].sort_values("device_name")
        if len(hit):
            names.append(hit.iloc[0]["device_name"])
    lab = d.set_index("device_name").loc[names]
    ax.margins(0.12)
    place_labels(ax, fig, lab["log_flows_per_hour"].to_numpy(), lab["log_median_bytes"].to_numpy(),
                 names, (d["log_flows_per_hour"].to_numpy(), d["log_median_bytes"].to_numpy()))
    ax.set_xlabel(f"{LABEL['log_flows_per_hour']}   [flows per hour]")
    ax.set_ylabel(f"{LABEL['log_median_bytes']}   [bytes per flow]")
    ax.grid(alpha=0.25, lw=0.5)
    leg1 = ax.legend(handles=cat_handles(colors, list(dict.fromkeys(d["category"]))),
                     loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False,
                     title="Category", title_fontsize=9)
    ax.add_artist(leg1)
    sz = [100, 1000, 10000]
    hs = [Line2D([], [], ls="", marker="o", markersize=np.sqrt(size(v)), color="#999999",
                 markeredgecolor="white", label=f"{v:,}") for v in sz]
    hs.append(Line2D([], [], ls="", marker="o", markersize=6, color="#999999",
                     markeredgecolor="black", label="low confidence"))
    leg2 = ax.legend(handles=hs, loc="lower left", bbox_to_anchor=(1.01, 0.0), frameon=False,
                     title="Usable flows", title_fontsize=9, labelspacing=1.0)
    return save(fig, figdir, "fig3_volume_vs_size", [leg1, leg2]), names


def fig4_usable(fp: pd.DataFrame, colors: dict, min_flows: int, figdir: Path) -> list[str]:
    d = fp[fp["usable_flows"] > 0].sort_values("usable_flows").reset_index(drop=True)
    fig, ax = plt.subplots(figsize=(6.4, 0.6 + 0.165 * len(d)))
    ax.barh(range(len(d)), d["usable_flows"], color=d["category"].map(colors), height=0.75,
            edgecolor="none")
    ax.set_xscale("log")
    ax.set_yticks(range(len(d)), d["device_name"], fontsize=8)
    ax.set_ylim(-0.6, len(d) - 0.4)
    ax.axvline(min_flows, ls="--", lw=1, color="#333333")
    ax.text(min_flows * 1.08, -0.4, f"min-flows = {min_flows}", fontsize=8, va="bottom",
            color="#333333")
    ax.set_xlabel("usable flows (count, log scale)")
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", alpha=0.25, lw=0.5, which="both")
    ax.legend(handles=cat_handles(colors, [c for c in CATEGORY_ORDER if c in set(d["category"])]
                                  + sorted(set(d["category"]) - set(CATEGORY_ORDER))),
              loc="lower right", frameon=True, framealpha=0.9, edgecolor="none")
    return save(fig, figdir, "fig4_usable_flows")


# --------------------------------------------------------------------------- report

def summary_stats(fp: pd.DataFrame, hi: pd.Series) -> list[dict]:
    out = []
    for k in FEATURES:
        for scope, s in (("all", fp.loc[fp["usable_flows"] > 0, k]), ("high", fp.loc[hi, k])):
            v = s.dropna()
            out.append({"feature": k, "family": FAMILY[k], "scope": scope, "n": int(len(v)),
                        "nan": int(s.isna().sum()),
                        "min": round(float(v.min()), 4) if len(v) else None,
                        "q25": round(float(v.quantile(0.25)), 4) if len(v) else None,
                        "median": round(float(v.median()), 4) if len(v) else None,
                        "q75": round(float(v.quantile(0.75)), 4) if len(v) else None,
                        "max": round(float(v.max()), 4) if len(v) else None})
    return out


def md_table(rows: list[dict], cols: list[str]) -> list[str]:
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join("" if r.get(c) is None else str(r.get(c)) for c in cols) + " |"
            for r in rows]
    return out


def write_md(path: Path, rep: dict) -> None:
    L = ["# Step 6 -- device behaviour fingerprints", ""]
    L += [f"- **{k}**: {v}" for k, v in rep["run"].items()]
    ig = rep["integrity"]
    L += ["", f"## Integrity: **{'PASS' if ig['pass'] else 'FAIL'}**", ""]
    L += [f"- **{k}**: {v}" for k, v in ig.items() if k != "pass"]
    L += ["", "## Usable-flow filter", ""]
    L += [f"- **{k}**: {v}" for k, v in rep["filter"].items()]
    c = rep["confidence"]
    L += ["", "## Confidence", "",
          f"- **min_flows**: {c['min_flows']}",
          f"- **high**: {c['n_high']} devices, **low**: {c['n_low']} devices "
          f"(of which {len(c['zero_flow_devices'])} with 0 usable flows)",
          f"- **zero_flow_devices**: {c['zero_flow_devices'] or 'none'}", "",
          "Sensitivity (devices below threshold):", ""]
    L += md_table(c["sensitivity"], ["min_flows", "n_low", "n_high", "low_devices"])
    L += ["", "Low-confidence devices:", ""]
    L += md_table(c["low_devices"], ["device_name", "category", "usable_flows"])
    p = rep["pruning"]
    L += ["", "## Correlation pruning", "",
          f"- **method**: Spearman over {p['n_devices']} high-confidence devices; "
          f"|rho| > {p['threshold']}, strongest pair first, drop lower priority",
          f"- **kept ({len(p['kept'])})**: {', '.join(p['kept'])}",
          f"- **dropped ({len(p['drops'])})**: {', '.join(d['dropped'] for d in p['drops']) or 'none'}",
          ""]
    L += md_table(p["drops"], ["order", "dropped", "partner_kept", "rho"]) if p["drops"] else []
    L += ["", "All pairs with |rho| > threshold (before pruning):", ""]
    L += md_table(p["pairs_over_threshold"], ["a", "b", "rho"])
    L += ["", "Robust-scaling parameters (fit on high-confidence devices):", ""]
    L += md_table([{"feature": k, **v} for k, v in rep["scaling"].items()],
                  ["feature", "median", "iqr", "scale_used", "iqr_zero_fallback"])
    L += ["", "## Per-feature summary (raw values)", ""]
    L += md_table(rep["feature_stats"], ["feature", "family", "scope", "n", "nan", "min", "q25",
                                         "median", "q75", "max"])
    L += ["", "## Category → colour (Okabe-Ito, used in every figure)", ""]
    L += md_table([{"category": k, "colour": v} for k, v in rep["category_colours"].items()],
                  ["category", "colour"])
    L += ["", "## Figures", ""]
    for f in rep["figures"]:
        L += [f"- **{f['name']}** ({', '.join(Path(x).name for x in f['files'])}): {f['caption']}"]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def jsonable(o):
    if isinstance(o, dict):
        return {k: jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [jsonable(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating, float)):
        return None if np.isnan(o) else float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o


# --------------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--flows", type=Path,
                    default=ROOT / "data/interim/flows/benign/benign_flows_tagged.csv")
    ap.add_argument("--devices", type=Path, default=ROOT / "config/device_table.csv")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "results/step6")
    ap.add_argument("--min-flows", type=int, default=100)
    ap.add_argument("--corr-threshold", type=float, default=0.9)
    args = ap.parse_args()
    t0 = time.time()
    for p in (args.flows, args.devices):
        if not p.is_file():
            fatal(f"missing input {p}")
    figdir = args.out_dir / "figures"
    figdir.mkdir(parents=True, exist_ok=True)

    sha_flows, sha_dev = sha256(args.flows), sha256(args.devices)
    dev = load_devices(args.devices)
    homes = dev[dev["role"] == SMART_HOME_ROLE].reset_index(drop=True)
    log(f"device table: {len(dev)} rows, {len(homes)} smart-home (role '{SMART_HOME_ROLE}')")
    f, colmap, n_rows = load_flows(args.flows)
    log(f"flows: {n_rows} rows")

    owned = f["owner_status"] == "owned"
    usable = owned & (f["exclude_reason"] == "")
    u = f[usable].copy()
    bad_ts = int(u["ts"].isna().sum())
    bad_num = {k: int(u[k].isna().sum()) for k in NUMERIC if u[k].isna().any()}
    side_ok = bool(((u["owner_mac"] == u["src_mac"]) | (u["owner_mac"] == u["dst_mac"])).all())
    if bad_ts or bad_num:
        fatal(f"unparseable usable rows: timestamp {bad_ts}, numeric {bad_num}")
    o = orient(u)
    all_ts = f["ts"].dropna()
    t_min, t_max = all_ts.min(), all_ts.max()
    hours = (t_max - t_min).total_seconds() / 3600.0
    log(f"usable flows: {len(u)} ({u['owner_mac'].nunique()} owners); capture {hours:.3f} h")

    fp = build_fingerprints(u, o, homes, hours, args.min_flows)
    hi = fp["confidence"] == "high"
    rho = fp.loc[hi, FEATURES].corr(method="spearman")
    kept, drops = prune(rho, args.corr_threshold)
    sc, scale_params = robust_scale(fp, kept, hi)
    pairs = sorted([{"a": a, "b": b, "rho": round(float(rho.at[a, b]), 4)}
                    for i, a in enumerate(FEATURES) for b in FEATURES[i + 1:]
                    if pd.notna(rho.at[a, b]) and abs(rho.at[a, b]) > args.corr_threshold],
                   key=lambda r: -abs(r["rho"]))

    # outputs
    fp.to_csv(args.out_dir / "device_fingerprints.csv", index=False)
    sc.to_csv(args.out_dir / "device_fingerprints_scaled.csv", index=False)
    rho.loc[FEATURES, FEATURES].round(6).to_csv(args.out_dir / "feature_correlation.csv")
    (args.out_dir / "kept_features.txt").write_text("\n".join(kept) + "\n", encoding="utf-8")

    cats = [c for c in CATEGORY_ORDER if c in set(fp["category"])]
    cats += sorted(set(fp["category"]) - set(cats))
    colors = {c: OKABE_ITO[i % len(OKABE_ITO)] for i, c in enumerate(cats)}
    setup_style()
    figs = []
    figs.append({"name": "fig1_feature_correlation", "files": fig1_correlation(rho, kept, figdir),
                 "caption": f"Spearman rank correlation between the {len(FEATURES)} candidate "
                            f"fingerprint features across {int(hi.sum())} high-confidence "
                            f"devices; features marked * were removed (|ρ| > "
                            f"{args.corr_threshold})."})
    figs.append({"name": "fig2_device_fingerprints",
                 "files": fig2_fingerprints(sc, kept, colors, figdir),
                 "caption": "Robust-scaled behaviour fingerprints (retained features) of each "
                            "smart-home device, grouped by category; † hatched rows have fewer "
                            f"than {args.min_flows} usable flows."})
    f3, labelled = fig3_volume_size(fp, colors, figdir)
    figs.append({"name": "fig3_volume_vs_size", "files": f3,
                 "caption": "Flow rate versus median flow size per device; colour shows "
                            "category and marker area scales with log usable flows."})
    figs.append({"name": "fig4_usable_flows",
                 "files": fig4_usable(fp, colors, args.min_flows, figdir),
                 "caption": "Usable benign flows per smart-home device (log scale); the dashed "
                            f"line marks the {args.min_flows}-flow confidence threshold."})

    # integrity
    zero = fp.loc[fp["usable_flows"] == 0, "device_name"].tolist()
    non_home = sorted(set(u["owner_mac"]) - set(homes["mac"]))
    ig = {"input_rows": n_rows,
          "sum_usable_flows_over_devices": int(fp["usable_flows"].sum()),
          "usable_flows": int(len(u)),
          "sum_equals_usable": int(fp["usable_flows"].sum()) == len(u),
          "smart_home_devices_in_table": len(homes),
          "devices_in_fingerprints": int(len(fp)),
          "every_smart_home_device_present": set(fp["mac"]) == set(homes["mac"]),
          "usable_owners_not_smart_home": non_home,
          "owner_on_src_or_dst_side_for_all_usable": side_ok,
          "kept_features_nonempty": len(kept) > 0,
          "all_figures_written": all(Path(p).is_file() for fg in figs for p in fg["files"]),
          "flows_sha256_unchanged": sha256(args.flows) == sha_flows,
          "devices_sha256_unchanged": sha256(args.devices) == sha_dev}
    ig["pass"] = all(v for k, v in ig.items() if isinstance(v, bool)) and not non_home

    sens = []
    for t in sorted(set(SENSITIVITY_THRESHOLDS) | {args.min_flows}):
        low = fp.loc[fp["usable_flows"] < t, "device_name"].tolist()
        sens.append({"min_flows": t, "n_low": len(low), "n_high": len(fp) - len(low),
                     "low_devices": "; ".join(low)})
    low_rows = fp.loc[~hi, ["device_name", "category", "usable_flows"]] \
        .sort_values("usable_flows").to_dict("records")
    rep = {
        "run": {"run_timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "flows": str(args.flows), "flows_sha256": sha_flows,
                "devices": str(args.devices), "devices_sha256": sha_dev,
                "out_dir": str(args.out_dir), "min_flows": args.min_flows,
                "corr_threshold": args.corr_threshold,
                "timestamp_format": f"{TS_FORMAT} (UTC)",
                "columns_matched": colmap,
                "capture_start_utc": t_min.isoformat(), "capture_end_utc": t_max.isoformat(),
                "capture_hours": round(hours, 4),
                "python": platform.python_version(), "pandas": pd.__version__,
                "numpy": np.__version__, "scipy": scipy.__version__,
                "matplotlib": matplotlib.__version__,
                "runtime_s": round(time.time() - t0, 1)},
        "integrity": ig,
        "filter": {"input_rows": n_rows, "owned": int(owned.sum()),
                   "owned_but_excluded": int((owned & ~usable).sum()),
                   "owned_excluded_by_reason": f.loc[owned & ~usable, "exclude_reason"]
                   .value_counts().to_dict(),
                   "usable": int(usable.sum()), "usable_pct_of_input": pct(int(usable.sum()), n_rows),
                   "usable_owner_devices": int(u["owner_mac"].nunique()),
                   "owner_is_src": int(o["owner_is_src"].sum()),
                   "owner_is_dst": int((~o["owner_is_src"]).sum())},
        "confidence": {"min_flows": args.min_flows, "n_high": int(hi.sum()),
                       "n_low": int((~hi).sum()), "zero_flow_devices": zero,
                       "sensitivity": sens, "low_devices": low_rows},
        "pruning": {"threshold": args.corr_threshold, "n_devices": int(hi.sum()),
                    "priority": PRIORITY, "kept": kept,
                    "dropped": [d["dropped"] for d in drops], "drops": drops,
                    "pairs_over_threshold": pairs},
        "scaling": scale_params,
        "feature_stats": summary_stats(fp, hi),
        "category_colours": colors,
        "fig3_labelled_devices": labelled,
        "figures": figs,
    }
    rep["run"]["runtime_s"] = round(time.time() - t0, 1)
    write_md(args.out_dir / "profile_report.md", rep)
    (args.out_dir / "profile_report.json").write_text(json.dumps(jsonable(rep), indent=2),
                                                      encoding="utf-8")

    log(f"\nintegrity: {'PASS' if ig['pass'] else 'FAIL'}  (sum {ig['sum_usable_flows_over_devices']}"
        f" == usable {ig['usable_flows']}; {len(fp)}/{len(homes)} smart-home devices)")
    log(f"devices: {int(hi.sum())} high / {int((~hi).sum())} low confidence "
        f"(zero-flow: {zero or 'none'})")
    log(f"kept {len(kept)}: {', '.join(kept)}")
    for d in drops:
        log(f"  dropped {d['dropped']:<24} rho {d['rho']:+.3f} with {d['partner_kept']}")
    for fg in figs:
        log(f"  {fg['name']}: {', '.join(fg['files'])}")
    if not ig["pass"]:
        fatal(f"integrity check failed: {ig}")


if __name__ == "__main__":
    main()
