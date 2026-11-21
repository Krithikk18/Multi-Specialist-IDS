#!/usr/bin/env python
"""diagnostics/diag_01_portscan_synflood.py -- READ-ONLY diagnostic: why does SPEC_G1 label ~43 % of G1 val
port_scan flows as syn_flood (identically across seeds)?

Hypothesis: many port_scan and syn_flood flows have the same (or nearly the same) per-flow feature vector -- typically
single-packet SYN flows -- so no per-flow model can separate them; the difference is cross-flow (one source hitting
many ports vs many packets to one port).

Data: TRAIN and VAL of the Phase 2 dataset via common/phase2_data.load_split (refuses test). Feature matrix exactly as
step 22 fed the models: the 70 features of features_v1.json, float32 (D.feature_matrix). Models: the seed-0 primary
boosters of the step 22 run, loaded read-only (sha256 == its manifest) and scored on val only. Nothing is trained;
no existing file is changed.

  Q1 conflict matrix  share of class-a rows whose exact (float32) / 6-significant-figure feature vector also occurs
                      with label b: within train, within val, and val rows vs train
  Q2 per-flow ceiling recall per class if every vector gets one label: (i) its majority TRAIN label (vectors unseen in
                      train counted as correct = optimistic), (ii) its majority VAL label (val oracle)
  Q3 error anatomy    focus-group val rows of class A (default port_scan) by predicted label x conflict duplicate x
                      single-packet (Total Fwd Packet == 1 and Total Bwd packets == 0), for the focus group's specialist
                      and for GLOBAL (seed 0); focus vs other groups' profiles
  Q4 profiles         per group, A vs B (default syn_flood): single-packet share, quantiles of flow features and Dst Port,
                      distinct FWD Init Win Bytes values, source IPs / MACs and their overlap
  Q5 context          CAUSAL per-flow context from flows of the same Src IP that started strictly earlier, in [t - W, t)
                      (start_ts has whole-second resolution, so same-second flows are excluded), W = 2 / 10 / 60 s:
                      distinct dst ports, flows to the same (dst IP, dst port), distinct dst IPs; per-class quantiles per
                      group; one threshold per feature picked on train (balanced accuracy, A conflict duplicates vs B),
                      read on val; rows / second of the computation. CAVEAT: the dataset carries V1's caps -- B rows
                      (syn_flood) are a ~3-7 % sample of their sessions -- so context counts that involve B traffic are
                      undercounts; the caps' p per key is recorded.
Verdict rule (stated in the summary before the numbers): SUPPORTED if conflict duplicates (exact or 6 sig. fig.)
account for >= 50 % of the specialist's A -> B errors on focus-group val, OR the focus-group per-flow ceiling for A
recall (train-majority lookup) is <= 0.90; NOT SUPPORTED otherwise.

Outputs: results/diag_01/ (summary.md, run_manifest.json, run_meta.json, run.log, figures/*.png); diag.json in
~/lgids_cache/v2/diag/<run_id>/. --dry-run: the 5 % sample, results/diag_01/dry_run/<run_id>/.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase2_data as D  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

SCRIPT = "diagnostics/diag_01_portscan_synflood.py"
STEP = "diag_01"
SINGLE_FWD, SINGLE_BWD = "Total Fwd Packet", "Total Bwd packets"
PROFILE_FEATS = ["Flow Duration", "Total Fwd Packet", "Total Bwd packets", "SYN Flag Count", "RST Flag Count",
                 "FWD Init Win Bytes"]
META = ["Src IP", "Dst IP", "Dst Port", "src_mac", "start_ts", "session"]
WINDOWS = (2, 10, 60)
CTX = ["ctx_distinct_dports", "ctx_same_dst_dport", "ctx_distinct_dips"]
QS = [0.0, 0.05, 0.25, 0.5, 0.75, 0.95, 1.0]


# --------------------------------------------------------------------------- helpers (unit-tested)
def round_sig(A: np.ndarray, sig: int) -> np.ndarray:
    """Round every element to `sig` significant figures (0, NaN and inf unchanged)."""
    A = np.array(A, dtype=np.float64, copy=True)
    nz = np.isfinite(A) & (A != 0)
    e = np.floor(np.log10(np.abs(A[nz])))
    scale = 10.0 ** (sig - 1 - e)
    A[nz] = np.round(A[nz] * scale) / scale
    return A


def row_ids(X: np.ndarray, sig: int | None = None) -> np.ndarray:
    """Integer id per row, equal iff the rows are bit-identical (after rounding to `sig` significant figures if given;
    -0.0 == 0.0). Exact ids use the matrix's own dtype (float32 = what the models saw)."""
    A = round_sig(X, sig) if sig else np.array(X, copy=True)
    A[A == 0] = 0
    A = np.ascontiguousarray(A)
    v = A.view(np.dtype((np.void, A.dtype.itemsize * A.shape[1]))).ravel()
    return np.unique(v, return_inverse=True)[1].ravel().astype(np.int64)


def presence(ids: np.ndarray, y: np.ndarray, n_ids: int, K: int) -> np.ndarray:
    """(n_ids, K) bool: vector id occurs with label k."""
    P = np.zeros((n_ids, K), dtype=bool)
    P[ids, y] = True
    return P


def conflict_matrix(ids: np.ndarray, y: np.ndarray, P: np.ndarray, K: int) -> np.ndarray:
    """M[a, b] = share of class-a rows whose vector occurs with label b in P (b != a); diagonal NaN; NaN if no a rows."""
    M = np.full((K, K), np.nan)
    for a in range(K):
        ra = y == a
        if ra.any():
            for b in range(K):
                if b != a:
                    M[a, b] = float(P[ids[ra], b].mean())
    return M


def majority_label(ids: np.ndarray, y: np.ndarray, n_ids: int, K: int) -> np.ndarray:
    """Majority label per vector id (ties -> lowest class id); -1 for ids without rows."""
    C = np.zeros((n_ids, K), dtype=np.int64)
    np.add.at(C, (ids, y), 1)
    out = C.argmax(1)
    out[C.sum(1) == 0] = -1
    return out


def ceiling_recall(ids_eval: np.ndarray, y_eval: np.ndarray, lookup: np.ndarray, K: int) -> list:
    """Per-class recall when every vector is labelled lookup[id]; an id with lookup -1 (unseen) counts as correct."""
    pred = lookup[ids_eval]
    pred = np.where(pred < 0, y_eval, pred)
    return [float((pred[y_eval == c] == c).mean()) if (y_eval == c).any() else float("nan") for c in range(K)]


def context_features(src: np.ndarray, dst: np.ndarray, dport: np.ndarray, t: np.ndarray, W: float) -> np.ndarray:
    """(n, 3) causal context per flow from flows of the same source that started in [t - W, t) (strictly earlier):
    distinct destination ports, flows to the same (dst, dport), distinct destinations."""
    from collections import Counter
    n = len(t)
    out = np.zeros((n, 3), dtype=np.int64)
    src_c = pd.factorize(pd.Series(src).astype(str))[0]
    dst_c = pd.factorize(pd.Series(dst).astype(str))[0]
    port_c = np.asarray(dport, dtype=np.int64)
    order = np.lexsort((t, src_c))
    s_sorted = src_c[order]
    bounds = np.flatnonzero(np.diff(s_sorted)) + 1
    for grp in np.split(order, bounds):
        tt = t[grp]
        ports, dsts, pairs = Counter(), Counter(), Counter()
        left = 0
        i = 0
        m = len(grp)
        while i < m:
            j = i
            while j < m and tt[j] == tt[i]:
                j += 1
            while left < i and tt[left] < tt[i] - W:                 # drop flows that left the window
                r = grp[left]
                for C_, k in ((ports, port_c[r]), (dsts, dst_c[r]), (pairs, (dst_c[r], port_c[r]))):
                    C_[k] -= 1
                    if C_[k] == 0:
                        del C_[k]
                left += 1
            for q in range(i, j):                                     # same-second flows see only earlier seconds
                r = grp[q]
                out[r] = (len(ports), pairs.get((dst_c[r], port_c[r]), 0), len(dsts))
            for q in range(i, j):
                r = grp[q]
                ports[port_c[r]] += 1
                dsts[dst_c[r]] += 1
                pairs[(dst_c[r], port_c[r])] += 1
            i = j
    return out


def best_threshold(pos: np.ndarray, neg: np.ndarray, max_cand: int = 4000) -> dict:
    """Single threshold (either direction) maximising balanced accuracy of pos vs neg."""
    allv = np.unique(np.concatenate([pos, neg]).astype(float))
    if len(allv) > max_cand:
        allv = np.unique(np.quantile(allv, np.linspace(0, 1, max_cand)))
    cand = np.concatenate([allv, [allv.max() + 1]]) if len(allv) else np.array([0.0])
    ps, ns = np.sort(pos.astype(float)), np.sort(neg.astype(float))
    tpr_ge = 1 - np.searchsorted(ps, cand, side="left") / max(1, len(ps))      # pos >= theta
    fpr_ge = 1 - np.searchsorted(ns, cand, side="left") / max(1, len(ns))      # neg >= theta
    ba_ge = (tpr_ge + (1 - fpr_ge)) / 2
    ba_le = ((1 - tpr_ge) + fpr_ge) / 2                                          # pos < theta
    k1, k2 = int(ba_ge.argmax()), int(ba_le.argmax())
    if ba_ge[k1] >= ba_le[k2]:
        return {"theta": float(cand[k1]), "direction": ">=", "train_bal_acc": float(ba_ge[k1])}
    return {"theta": float(cand[k2]), "direction": "<", "train_bal_acc": float(ba_le[k2])}


def side(vals: np.ndarray, thr: dict) -> np.ndarray:
    """True where a row falls on the 'positive' (class A) side of the threshold."""
    return vals >= thr["theta"] if thr["direction"] == ">=" else vals < thr["theta"]


# --------------------------------------------------------------------------- figures
def fig_conflict(path, mats: dict, names, title):
    import matplotlib.pyplot as plt
    from matplotlib.colors import Normalize
    PS.apply()
    K = len(names)
    fig, axes = plt.subplots(1, len(mats), figsize=(3.4 * len(mats) + 0.8, 3.3), squeeze=False)
    for ax, (lab, M) in zip(axes[0], mats.items()):
        ax.imshow(np.nan_to_num(M * 100), cmap=PS.SEQUENTIAL_CMAP, norm=Normalize(0, 100))
        for i in range(K):
            for j in range(K):
                v = M[i, j]
                ax.text(j, i, "-" if np.isnan(v) else f"{100 * v:.1f}", ha="center", va="center", fontsize=7.5,
                        color="#ffffff" if (not np.isnan(v) and v > 0.6) else PS.TEXT1)
        ax.set_xticks(range(K), names, rotation=35, ha="right", fontsize=7.5)
        ax.set_yticks(range(K), names if ax is axes[0][0] else [""] * K, fontsize=7.5)
        ax.set_title(lab, loc="left", fontsize=8.5)
        ax.set_xlabel("label b the same vector also carries", fontsize=7.5)
        ax.tick_params(length=0)
        for sp in ax.spines.values():
            sp.set_visible(False)
    axes[0][0].set_ylabel("row class a")
    fig.subplots_adjust(top=0.8, wspace=0.15)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_anatomy(path, tab: pd.DataFrame, title):
    import matplotlib.pyplot as plt
    PS.apply()
    cmap = plt.get_cmap(PS.SEQUENTIAL_CMAP)
    segs = [("conflict dup, single-packet", 0.95), ("conflict dup, multi-packet", 0.7),
            ("no conflict, single-packet", 0.45), ("no conflict, multi-packet", 0.2)]
    preds = list(tab.index)
    fig, ax = plt.subplots(figsize=(6.2, 0.6 * len(preds) + 1.4))
    left = np.zeros(len(preds))
    for seg, shade in segs:
        v = tab[seg].to_numpy(float) if seg in tab else np.zeros(len(preds))
        ax.barh(range(len(preds)), v, left=left, color=cmap(shade), edgecolor=PS.SURFACE, lw=1.5, label=seg)
        for i, (l, w) in enumerate(zip(left, v)):
            if w > tab.to_numpy().sum() * 0.04:
                ax.text(l + w / 2, i, f"{int(w):,}", ha="center", va="center", fontsize=7,
                        color="#ffffff" if shade > 0.6 else PS.TEXT1)
        left += v
    ax.set_yticks(range(len(preds)), [f"predicted {p}" for p in preds])
    ax.invert_yaxis()
    ax.set_xlabel("flows")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(0.5, -0.25), fontsize=7.5)
    ax.set_title(title, loc="left")
    PS.save(fig, path)


def fig_ceiling(path, rows: list[dict], names, title):
    import matplotlib.pyplot as plt
    PS.apply()
    subs = sorted({r["subset"] for r in rows}, key=lambda s: (s != "all", s))
    fig, axes = plt.subplots(1, len(subs), figsize=(3.3 * len(subs) + 0.6, 3.0), squeeze=False)
    for ax, s in zip(axes[0], subs):
        R_ = {r["class"]: r for r in rows if r["subset"] == s}
        for k, n in enumerate(names):
            if n not in R_:
                continue
            r = R_[n]
            ax.plot([r["ceiling_train_lookup"]], [k], "o", mfc="none", mec=PS.class_color(k), ms=8, mew=1.6)
            ax.plot([r["ceiling_val_oracle"]], [k], "s", mfc="none", mec=PS.TEXT2, ms=6, mew=1.2)
            ax.plot([r["achieved_routed_s0"]], [k], "o", color=PS.class_color(k), ms=5)
        ax.set_yticks(range(len(names)), names if ax is axes[0][0] else [""] * len(names), fontsize=8)
        ax.invert_yaxis()
        ax.set_xlim(-0.02, 1.02)
        ax.xaxis.grid(True)
        ax.set_title(f"val {s}", loc="left", fontsize=8.5)
        ax.set_xlabel("recall")
    from matplotlib.lines import Line2D
    h = [Line2D([], [], marker="o", ls="", mfc="none", mec=PS.TEXT1, label="ceiling: train-majority lookup"),
         Line2D([], [], marker="s", ls="", mfc="none", mec=PS.TEXT2, label="ceiling: val oracle"),
         Line2D([], [], marker="o", ls="", color=PS.TEXT1, label="achieved: ROUTED seed 0")]
    fig.legend(handles=h, frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5, -0.06), fontsize=7.5)
    fig.subplots_adjust(top=0.8, bottom=0.25, wspace=0.12)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_context(path, df: pd.DataFrame, a: int, b: int, names, groups, W, title):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, axes = plt.subplots(len(groups), 3, figsize=(9.6, 2.4 * len(groups) + 0.8), squeeze=False)
    for gi, g in enumerate(groups):
        for fi, f in enumerate(CTX):
            ax = axes[gi][fi]
            for k, ls in ((a, "-"), (b, "--")):
                v = np.sort(df.loc[(df["group"] == g) & (df["y"] == k), f"{f}_W{W}"].to_numpy(float))
                if len(v):
                    ax.step(v + 1, np.arange(1, len(v) + 1) / len(v), where="post", color=PS.class_color(k), ls=ls,
                            lw=1.8, label=f"{names[k]} (n={len(v):,})")
            ax.set_xscale("log")
            ax.set_ylim(0, 1.02)
            ax.grid(True)
            ax.set_title(f"{g}: {f.replace('ctx_', '')}", loc="left", fontsize=8)
            if gi == len(groups) - 1:
                ax.set_xlabel(f"count in the previous {W} s + 1 (log)", fontsize=7.5)
            if fi == 0:
                ax.set_ylabel("ECDF")
            ax.legend(frameon=False, fontsize=6.5, loc="lower right")
    fig.subplots_adjust(top=0.9, hspace=0.45, wspace=0.25)
    fig.suptitle(title, x=0.01, ha="left", y=0.995)
    PS.save(fig, path)


# --------------------------------------------------------------------------- main
def qtab(v: np.ndarray) -> dict:
    v = np.asarray(v, float)
    return {f"q{int(q * 100)}": (float(np.quantile(v, q)) if len(v) else None) for q in QS} | {"n": int(len(v))}


def main() -> int:
    import xgboost as xgb
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--class-a", default="port_scan", help="the class being mislabelled")
    ap.add_argument("--class-b", default="syn_flood", help="the class it is mislabelled as")
    ap.add_argument("--focus-group", default="G1")
    ap.add_argument("--train-run", default=None, help="step 22 run (default: results/22)")
    args = ap.parse_args()
    cfg = load_phase2_config()
    S.verify_v2_lock(strict=True)
    pins_before = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                     ("config/class_map.json", S.CLASS_MAP_PATH))}
    cm = S.load_class_map()
    names, K = list(cm.names), cm.n_classes
    if args.class_a not in names or args.class_b not in names:
        raise SystemExit(f"classes must be in the class map {names}")
    A, B = cm.id_of(args.class_a), cm.id_of(args.class_b)
    feats = S.feature_columns()
    up = R.resolve_run("22", args.train_run, False)
    ctx = R.start_run(STEP, "diag", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    M.update({"train_run": up["meta"]["run_id"], "train_run_manifest_sha256": up["manifest_sha256"],
              "pins_before": pins_before, "class_a": args.class_a, "class_b": args.class_b,
              "focus_group": args.focus_group, "read_only": "no model trained; no existing file changed; test never read"})
    ok, out = False, {}
    try:
        c = cfg["columns"]
        missing = [f for f in PROFILE_FEATS if f not in feats]
        import pyarrow.parquet as pq
        schema = pq.read_schema(D.split_file(cfg, "val")).names
        missing += [m for m in META if m not in schema]
        if missing:
            raise RuntimeError(f"required columns missing: {missing}")
        cols = feats + [c["group"], c["label_id"]] + META
        tr = D.load_split(cfg, "train", cols, sample=args.dry_run)
        va = D.load_split(cfg, "val", cols, sample=args.dry_run)
        dm = D.load_dataset_manifest(cfg)
        M["inputs"] = {"dataset_manifest_sha256": dm["_sha256"], "train_sha256": D.verify_split_file(cfg, "train"),
                       "val_sha256": D.verify_split_file(cfg, "val"), "test_read": False,
                       "caps_p": {k: v["p"] for k, v in dm["caps"].items() if not k.startswith("attack|test")
                                  and v["p"] < 1}}
        groups = sorted(set(va[c["group"]].astype(str)) | set(tr[c["group"]].astype(str)))
        if args.focus_group not in groups:
            raise RuntimeError(f"focus group {args.focus_group} not in the data {groups}")
        Xtr, Xva = D.feature_matrix(tr, feats), D.feature_matrix(va, feats)
        ytr, yva = tr[c["label_id"]].to_numpy(np.int64), va[c["label_id"]].to_numpy(np.int64)
        gtr, gva = tr[c["group"]].astype(str).to_numpy(), va[c["group"]].astype(str).to_numpy()
        ctx.log(f"train {len(ytr):,}  val {len(yva):,}  groups {groups}")
        # ---------------- Q1 conflict matrices
        res_q1, ids = {}, {}
        for tag, sig in (("exact", None), ("sig6", 6)):
            allid = row_ids(np.vstack([Xtr, Xva]), sig)
            it, iv = allid[: len(ytr)], allid[len(ytr):]
            ids[tag] = (it, iv)
            n = int(allid.max()) + 1
            Pt, Pv = presence(it, ytr, n, K), presence(iv, yva, n, K)
            res_q1[tag] = {"train_within": conflict_matrix(it, ytr, Pt, K).tolist(),
                           "val_within": conflict_matrix(iv, yva, Pv, K).tolist(),
                           "val_vs_train": conflict_matrix(iv, yva, Pt, K).tolist(),
                           "unique_vectors": {"train": int(len(np.unique(it))), "val": int(len(np.unique(iv)))}}
            per_g = []
            for g in groups:
                for split, ii, yy, gg, P in (("train", it, ytr, gtr, Pt), ("val", iv, yva, gva, Pv)):
                    ra = (yy == A) & (gg == g)
                    if ra.any():
                        per_g.append({"sig": tag, "split": split, "group": g, f"n_{args.class_a}": int(ra.sum()),
                                      f"also_{args.class_b}_same_split": int(P[ii[ra], B].sum()),
                                      "pct_same_split": 100 * float(P[ii[ra], B].mean())})
                rv = (yva == A) & (gva == g)
                if rv.any():
                    per_g.append({"sig": tag, "split": "val vs train", "group": g, f"n_{args.class_a}": int(rv.sum()),
                                  f"also_{args.class_b}_same_split": int(Pt[iv[rv], B].sum()),
                                  "pct_same_split": 100 * float(Pt[iv[rv], B].mean())})
            res_q1[tag]["per_group_A_with_B"] = per_g
            res_q1[tag]["_Pt"], res_q1[tag]["_Pv"] = Pt, Pv
        # conflict duplicate flag per val row (A rows whose vector carries B in train OR val)
        dup = {tag: res_q1[tag]["_Pt"][ids[tag][1], B] | res_q1[tag]["_Pv"][ids[tag][1], B] for tag in ids}
        dup_any = dup["exact"] | dup["sig6"]
        single = (va[SINGLE_FWD].to_numpy() == 1) & (va[SINGLE_BWD].to_numpy() == 0)
        single_tr = (tr[SINGLE_FWD].to_numpy() == 1) & (tr[SINGLE_BWD].to_numpy() == 0)
        # ---------------- predictions (read-only models, seed 0)
        seed0 = cfg["seeds"][0]
        prim = up["manifest"]["routing"]["primary"]
        default = up["manifest"]["routing"]["default"]
        preds = {}
        for mid in sorted(set(prim.values()) | {default}):
            m = next(x for x in up["manifest"]["models"] if x["model_id"] == mid and x["seed"] == seed0)
            p = up["dir"] / m["file"]
            if R.sha256_path(p) != m["sha256"]:
                raise RuntimeError(f"{p}: sha256 != step 22 manifest")
            b = xgb.Booster()
            b.load_model(str(p))
            preds[mid] = b.predict(xgb.DMatrix(Xva)).argmax(1)
        M["models_read"] = sorted(preds)
        routed = np.array([preds[prim.get(g, default)][i] for i, g in enumerate(gva)]) if len(gva) else np.zeros(0, int)
        # ---------------- Q2 ceilings
        rows_q2 = []
        for tag in ("exact", "sig6"):
            it, iv = ids[tag]
            n = int(max(it.max(initial=0), iv.max(initial=0))) + 1
            lk_tr = majority_label(it, ytr, n, K)
            lk_va = majority_label(iv, yva, n, K)
            for s in ["all", *groups]:
                m_ = np.ones(len(yva), bool) if s == "all" else gva == s
                if not m_.any():
                    continue
                ct = ceiling_recall(iv[m_], yva[m_], lk_tr, K)
                cv = ceiling_recall(iv[m_], yva[m_], lk_va, K)
                unseen = float((lk_tr[iv[m_]] < 0).mean())
                for k in range(K):
                    if (yva[m_] == k).any():
                        rows_q2.append({"sig": tag, "subset": s, "class": names[k], "n_val": int((yva[m_] == k).sum()),
                                        "ceiling_train_lookup": ct[k], "ceiling_val_oracle": cv[k],
                                        "achieved_routed_s0": float((routed[m_][yva[m_] == k] == k).mean()),
                                        "val_rows_unseen_in_train": unseen})
        out["q2"] = rows_q2
        # ---------------- Q3 error anatomy
        fg = args.focus_group
        spec = prim.get(fg, default)
        q3 = {}
        for mname in (spec, default):
            sel = (gva == fg) & (yva == A)
            pr = preds[mname][sel]
            d_e, d_6, sp = dup["exact"][sel], dup["sig6"][sel], single[sel]
            err = pr == B
            lab = np.where(pr == A, f"{args.class_a} (correct)", np.where(pr == B, args.class_b, "other"))
            seg = np.where(d_e | d_6, "conflict dup", "no conflict")
            seg = np.char.add(np.char.add(seg.astype(str), ", "), np.where(sp, "single-packet", "multi-packet"))
            tab = pd.crosstab(pd.Series(lab, name="pred"), pd.Series(seg, name="seg"))
            q3[mname] = {"n": int(sel.sum()), "errors_to_B": int(err.sum()),
                         "error_rate_to_B": float(err.mean()) if sel.any() else float("nan"),
                         "errors_conflict_exact": int((err & d_e).sum()), "errors_conflict_sig6": int((err & d_6).sum()),
                         "errors_conflict_any": int((err & (d_e | d_6)).sum()),
                         "errors_single_packet": int((err & sp).sum()),
                         "share_errors_conflict_any": float((err & (d_e | d_6)).sum() / max(1, err.sum())),
                         "share_errors_conflict_exact": float((err & d_e).sum() / max(1, err.sum())),
                         "share_errors_single_packet": float((err & sp).sum() / max(1, err.sum())),
                         "correct_but_conflict_any": int((~err & (d_e | d_6)).sum()),
                         "crosstab": tab.to_dict()}
            if mname == spec:
                fig_tab = tab
        out["q3"] = q3
        # ---------------- Q4 profiles (val and train)
        q4 = []
        for split, df_, yy, gg, spk in (("train", tr, ytr, gtr, single_tr), ("val", va, yva, gva, single)):
            for g in groups:
                for k in (A, B):
                    m_ = (gg == g) & (yy == k)
                    if not m_.any():
                        continue
                    sub = df_.loc[m_]
                    srcs = sub["Src IP"].astype(str)
                    macs = sub["src_mac"].astype(str)
                    q4.append({"split": split, "group": g, "class": names[k], "n": int(m_.sum()),
                               "single_packet_share": float(spk[m_].mean()),
                               "quantiles": {f: qtab(sub[f].to_numpy()) for f in PROFILE_FEATS + ["Dst Port"]},
                               "distinct_init_win": int(sub["FWD Init Win Bytes"].nunique()),
                               "top_init_win": {str(k_): int(v) for k_, v in sub["FWD Init Win Bytes"].value_counts().head(5).items()},
                               "distinct_src_ip": int(srcs.nunique()), "top_src_ip": srcs.value_counts().head(3).to_dict(),
                               "distinct_src_mac": int(macs.nunique()), "top_src_mac": macs.value_counts().head(3).to_dict(),
                               "distinct_dst_port": int(sub["Dst Port"].nunique()),
                               "distinct_dst_ip": int(sub["Dst IP"].nunique())})
        overlap = {}
        for split, df_, yy in (("train", tr, ytr), ("val", va, yva)):
            sa = set(df_.loc[yy == A, "Src IP"].astype(str))
            sb = set(df_.loc[yy == B, "Src IP"].astype(str))
            ma = set(df_.loc[yy == A, "src_mac"].astype(str))
            mb = set(df_.loc[yy == B, "src_mac"].astype(str))
            overlap[split] = {"src_ip_A": len(sa), "src_ip_B": len(sb), "src_ip_shared": len(sa & sb),
                              "B_rows_with_src_ip_seen_in_A": float(df_.loc[yy == B, "Src IP"].astype(str).isin(sa).mean())
                              if (yy == B).any() else None,
                              "src_mac_A": sorted(ma)[:5], "src_mac_B": sorted(mb)[:5], "src_mac_shared": sorted(ma & mb)}
        out["q4"], out["q4_overlap"] = q4, overlap
        # ---------------- Q5 context features
        q5, cost = {"quantiles": [], "thresholds": []}, {}
        ctxdf = {}
        for split, df_, yy, gg in (("train", tr, ytr, gtr), ("val", va, yva, gva)):
            d = pd.DataFrame({"y": yy, "group": gg})
            t = df_["start_ts"].to_numpy(np.int64)
            for W in WINDOWS:
                t0 = time.perf_counter()
                F = context_features(df_["Src IP"].to_numpy(), df_["Dst IP"].to_numpy(),
                                     pd.to_numeric(df_["Dst Port"], errors="coerce").fillna(-1).to_numpy(np.int64), t, W)
                el = time.perf_counter() - t0
                cost[f"{split}_W{W}"] = {"rows": int(len(t)), "seconds": round(el, 2),
                                         "rows_per_second": round(len(t) / el, 1) if el > 0 else None}
                for j, f in enumerate(CTX):
                    d[f"{f}_W{W}"] = F[:, j]
            ctxdf[split] = d
        out["q5_cost"] = cost
        for split in ("train", "val"):
            d = ctxdf[split]
            for g in groups:
                for k in (A, B):
                    m_ = (d["group"] == g) & (d["y"] == k)
                    if m_.any():
                        for W in WINDOWS:
                            for f in CTX:
                                q5["quantiles"].append({"split": split, "group": g, "class": names[k], "W": W, "feature": f,
                                                        **qtab(d.loc[m_, f"{f}_W{W}"].to_numpy())})
        dup_tr = {tag: res_q1[tag]["_Pt"][ids[tag][0], B] | res_q1[tag]["_Pv"][ids[tag][0], B] for tag in ids}
        dtr_any = dup_tr["exact"] | dup_tr["sig6"]
        for W in WINDOWS:
            for f in CTX:
                col = f"{f}_W{W}"
                trd, vad = ctxdf["train"], ctxdf["val"]
                pos_tr = trd.loc[(trd["y"] == A).to_numpy() & dtr_any, col].to_numpy()
                neg_tr = trd.loc[trd["y"] == B, col].to_numpy()
                if not len(pos_tr) or not len(neg_tr):
                    continue
                thr = best_threshold(pos_tr, neg_tr)
                for s in ["all", fg]:
                    gm = np.ones(len(vad), bool) if s == "all" else (vad["group"] == s).to_numpy()
                    pv = vad.loc[(vad["y"] == A).to_numpy() & dup_any & gm, col].to_numpy()
                    nv = vad.loc[(vad["y"] == B).to_numpy() & gm, col].to_numpy()
                    if not len(pv) or not len(nv):
                        continue
                    q5["thresholds"].append({"W": W, "feature": f, "subset": s, **thr,
                                             "val_conflict_A_separated": float(side(pv, thr).mean()),
                                             "val_B_on_B_side": float((~side(nv, thr)).mean()),
                                             "n_conflict_A": int(len(pv)), "n_B": int(len(nv))})
        out["q5"] = q5
        # ---------------- verdict
        sq3 = q3[spec]
        ceil_fg = next((r["ceiling_train_lookup"] for r in rows_q2 if r["sig"] == "exact" and r["subset"] == fg
                        and r["class"] == args.class_a), float("nan"))
        ceil_fg6 = next((r["ceiling_train_lookup"] for r in rows_q2 if r["sig"] == "sig6" and r["subset"] == fg
                         and r["class"] == args.class_a), float("nan"))
        crit1 = sq3["share_errors_conflict_any"] >= 0.5
        crit2 = min(ceil_fg, ceil_fg6) <= 0.90
        best_sep = max(q5["thresholds"], key=lambda r: min(r["val_conflict_A_separated"], r["val_B_on_B_side"]),
                       default=None)
        any90 = [r for r in q5["thresholds"] if r["val_conflict_A_separated"] >= 0.9 and r["val_B_on_B_side"] >= 0.9]
        out["verdict"] = {"supported": bool(crit1 or crit2), "criterion_errors_conflict_share": sq3["share_errors_conflict_any"],
                          "criterion_ceiling_focus_A_exact": ceil_fg, "criterion_ceiling_focus_A_sig6": ceil_fg6,
                          "crit1": bool(crit1), "crit2": bool(crit2), "context_separates_90": bool(any90),
                          "best_context": best_sep, "n_context_90": len(any90)}
        # strip helper arrays, save
        for tag in res_q1:
            res_q1[tag].pop("_Pt"), res_q1[tag].pop("_Pv")
        out["q1"] = res_q1
        R.write_json(ctx.partial / "diag.json", out)
        # ---------------- figures
        fig_conflict(ctx.fig / "conflict_matrix_exact.png",
                     {"train (within train)": np.array(res_q1["exact"]["train_within"]),
                      "val (within val)": np.array(res_q1["exact"]["val_within"]),
                      "val rows vs train": np.array(res_q1["exact"]["val_vs_train"])}, names,
                     "Exact conflicting duplicates: % of row class a whose float32 feature vector also carries label b")
        fig_anatomy(ctx.fig / "error_anatomy_focus.png", fig_tab,
                    f"{fg} val {args.class_a} flows under {spec} seed 0: prediction x conflict duplicate x single packet")
        fig_ceiling(ctx.fig / "ceiling_vs_achieved.png", [r for r in rows_q2 if r["sig"] == "exact"], names,
                    "Per-flow ceiling vs achieved recall (exact vectors; hollow = ceilings, filled = ROUTED seed 0)")
        fig_context(ctx.fig / "context_W10.png", ctxdf["val"], A, B, names,
                    [g for g in groups if ((gva == g) & (yva == A)).any()], 10,
                    f"Causal context (W = 10 s, val): {args.class_a} (solid) vs {args.class_b} (dashed); "
                    f"{args.class_b} rows are a capped sample")
        M["figures"] = sorted(str(p.relative_to(ctx.res)) for p in ctx.fig.glob("*.png"))
        M["verdict"] = out["verdict"]
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                         ("config/class_map.json", S.CLASS_MAP_PATH))}
    R.add_check(ctx, M, "config.py / class_map.json unchanged by this run", M["pins_after"] == pins_before,
                str(M["pins_after"]))
    ok = ok and M["pins_after"] == pins_before
    M["status"] = "PASS" if ok else "FAIL"
    write_summary(ctx.res / "summary.md", M, out, names, args, ctx)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def write_summary(path, M, out, names, args, ctx) -> None:
    a, b, fg = args.class_a, args.class_b, args.focus_group
    L = [f"# diag_01 -- why {a} is labelled {b} ({fg}) -- {M['status']}" + (" (DRY RUN)" if M["dry_run"] else ""), "",
         f"- run `{ctx.run_id}`; READ-ONLY: models of step 22 run `{M['train_run']}` (seed-0 primary boosters, sha256 "
         f"checked) scored on val; train / val via common/phase2_data.load_split (test never read); nothing trained.",
         "- feature matrix = the models' input: the 70 features of features_v1.json as float32 (step 22's preprocessing).",
         "", "## Verdict rule (fixed before the numbers)", "",
         f"- **SUPPORTED** if conflict duplicates (exact or 6 significant figures) account for >= 50 % of the {fg} "
         f"specialist's {a} -> {b} errors on {fg} val, **or** the per-flow ceiling for {fg} {a} recall (train-majority "
         f"lookup) is <= 0.90. **NOT SUPPORTED** otherwise.",
         f"- Context: a feature 'separates' when one threshold, picked on train, puts >= 90 % of the val conflict-duplicate "
         f"{a} flows on the {a} side **and** >= 90 % of val {b} flows on the {b} side.", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
        path.write_text("\n".join(L), encoding="utf-8")
        return
    V = out["verdict"]
    L += ["## Verdict", "",
          f"- **{'SUPPORTED' if V['supported'] else 'NOT SUPPORTED'}**: conflict duplicates are "
          f"{100 * V['criterion_errors_conflict_share']:.1f} % of the specialist's {a} -> {b} errors "
          f"({'>=' if V['crit1'] else '<'} 50 %); {fg} {a} per-flow ceiling = {V['criterion_ceiling_focus_A_exact']:.4f} "
          f"exact / {V['criterion_ceiling_focus_A_sig6']:.4f} at 6 sig. fig. ({'<=' if V['crit2'] else '>'} 0.90).",
          f"- Context separation >= 90 / 90 on val: **{'YES' if V['context_separates_90'] else 'NO'}** "
          f"({V['n_context_90']} feature x window combinations); best: "
          + (f"{V['best_context']['feature']} W={V['best_context']['W']} s ({V['best_context']['subset']}): "
             f"{100 * V['best_context']['val_conflict_A_separated']:.1f} % of conflict {a} vs "
             f"{100 * V['best_context']['val_B_on_B_side']:.1f} % of {b} correct (threshold "
             f"{V['best_context']['direction']} {V['best_context']['theta']:g})" if V["best_context"] else "n/a"), ""]
    # Q1
    L += ["## Q1 -- conflicting duplicates", ""]
    for tag in ("exact", "sig6"):
        q = out["q1"][tag]
        L += [f"### {tag} ({'float32 bit-identical' if tag == 'exact' else 'rounded to 6 significant figures'}); unique "
              f"vectors train {q['unique_vectors']['train']:,}, val {q['unique_vectors']['val']:,}", "",
              f"| split | group | {a} rows | also carry {b} | % |", "|---|---|---|---|---|"]
        for r in q["per_group_A_with_B"]:
            L.append(f"| {r['split']} | {r['group']} | {r[f'n_{a}']:,} | {r[f'also_{b}_same_split']:,} | {r['pct_same_split']:.1f} |")
        L += ["", "Conflict matrix, % of row class a whose vector also carries label b:", ""]
        for lab in ("train_within", "val_within", "val_vs_train"):
            Mx = np.array(q[lab])
            L += [f"- {lab}: " + "; ".join(f"{names[i]}->{names[j]} {100 * Mx[i, j]:.1f}"
                                           for i in range(len(names)) for j in range(len(names))
                                           if i != j and np.isfinite(Mx[i, j]) and Mx[i, j] > 0) or f"- {lab}: none"]
        L += [""]
    # Q2
    L += ["## Q2 -- per-flow ceiling (one label per feature vector)", "",
          "| vectors | val subset | class | val flows | ceiling: train-majority lookup | ceiling: val oracle | achieved (ROUTED s0) |",
          "|---|---|---|---|---|---|---|"]
    for r in out["q2"]:
        if r["class"] in (a, b):
            L.append(f"| {r['sig']} | {r['subset']} | {r['class']} | {r['n_val']:,} | {r['ceiling_train_lookup']:.4f} | "
                     f"{r['ceiling_val_oracle']:.4f} | {r['achieved_routed_s0']:.4f} |")
    L += ["", "Train-majority lookup: vectors never seen in train count as correct (optimistic). Val oracle: each val vector "
          "gets its majority val label (the best any deterministic per-flow function can do on these rows).", ""]
    # Q3
    L += [f"## Q3 -- anatomy of the {a} -> {b} errors on {fg} val (seed 0)", "",
          "| model | {a} flows | errors -> {b} | conflict dup (exact) | conflict dup (exact or 6sf) | single-packet | correct but conflict dup |".replace("{a}", a).replace("{b}", b),
          "|---|---|---|---|---|---|---|"]
    for mname, q in out["q3"].items():
        e = max(1, q["errors_to_B"])
        L.append(f"| {mname} | {q['n']:,} | {q['errors_to_B']:,} ({100 * q['error_rate_to_B']:.1f} %) | "
                 f"{q['errors_conflict_exact']:,} ({100 * q['errors_conflict_exact'] / e:.1f} %) | "
                 f"{q['errors_conflict_any']:,} ({100 * q['share_errors_conflict_any']:.1f} %) | "
                 f"{q['errors_single_packet']:,} ({100 * q['share_errors_single_packet']:.1f} %) | {q['correct_but_conflict_any']:,} |")
    L += ["", "Crosstab (rows = prediction, columns = conflict x packets), specialist:", ""]
    ct = pd.DataFrame(out["q3"][next(iter(out["q3"]))]["crosstab"]).fillna(0).astype(int)
    L += ["| prediction | " + " | ".join(ct.columns) + " |", "|---|" + "---|" * len(ct.columns)]
    L += [f"| {i} | " + " | ".join(f"{v:,}" for v in row) + " |" for i, row in ct.iterrows()] + [""]
    # Q4
    L += [f"## Q4 -- profiles ({a} vs {b})", "",
          "| split | group | class | n | single-packet % | Flow Duration q50 [q5, q95] | Fwd pkts q50 [q95] | Bwd pkts q50 [q95] | "
          "SYN q50 | RST q50 | distinct Dst Port | distinct init-win | top init-win | distinct src IP | top src MAC |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in out["q4"]:
        Q = r["quantiles"]
        L.append(f"| {r['split']} | {r['group']} | {r['class']} | {r['n']:,} | {100 * r['single_packet_share']:.1f} | "
                 f"{Q['Flow Duration']['q50']:g} [{Q['Flow Duration']['q5']:g}, {Q['Flow Duration']['q95']:g}] | "
                 f"{Q['Total Fwd Packet']['q50']:g} [{Q['Total Fwd Packet']['q95']:g}] | "
                 f"{Q['Total Bwd packets']['q50']:g} [{Q['Total Bwd packets']['q95']:g}] | {Q['SYN Flag Count']['q50']:g} | "
                 f"{Q['RST Flag Count']['q50']:g} | {r['distinct_dst_port']:,} | {r['distinct_init_win']:,} | "
                 f"{', '.join(f'{k}:{v}' for k, v in list(r['top_init_win'].items())[:3])} | {r['distinct_src_ip']:,} | "
                 f"{next(iter(r['top_src_mac']), '-')} |")
    L += ["", "Source overlap:", ""] + [f"- {s}: {json.dumps(v)}" for s, v in out["q4_overlap"].items()] + [""]
    # Q5
    L += ["## Q5 -- causal cross-flow context (same Src IP, flows started strictly earlier in [t - W, t))", "",
          f"- **caveat**: the dataset carries V1's caps -- {b} rows are a sample (p per key "
          f"{', '.join(f'{k} {v:.3f}' for k, v in M['inputs']['caps_p'].items() if b in k)}), so counts involving {b} "
          f"traffic are undercounts here; {a} is never capped.",
          "- compute cost (single Python process, dict counters; dev machine): " + ", ".join(
              f"{k} {v['rows_per_second']:,.0f} rows/s" for k, v in out["q5_cost"].items()), "",
          "Thresholds picked on train (conflict-duplicate " + a + " vs all " + b + "), read on val:", "",
          "| W (s) | feature | subset | rule | conflict " + a + " on " + a + " side | " + b + " on " + b + " side |",
          "|---|---|---|---|---|---|"]
    for r in out["q5"]["thresholds"]:
        L.append(f"| {r['W']} | {r['feature']} | {r['subset']} | {r['direction']} {r['theta']:g} | "
                 f"{100 * r['val_conflict_A_separated']:.1f} % ({r['n_conflict_A']:,}) | {100 * r['val_B_on_B_side']:.1f} % ({r['n_B']:,}) |")
    L += ["", "Val quantiles at W = 10 s (q5 / q50 / q95):", "", "| group | class | feature | q5 | q50 | q95 | n |", "|---|---|---|---|---|---|---|"]
    for r in out["q5"]["quantiles"]:
        if r["split"] == "val" and r["W"] == 10:
            L.append(f"| {r['group']} | {r['class']} | {r['feature']} | {r['q5']:g} | {r['q50']:g} | {r['q95']:g} | {r['n']:,} |")
    L += ["", "## Figures", "",
          "- `figures/conflict_matrix_exact.png` -- % of each class whose exact feature vector also carries another label (train, val, val vs train).",
          f"- `figures/error_anatomy_focus.png` -- {fg} val {a} flows by the specialist's prediction, split by conflict duplicate and single packet.",
          "- `figures/ceiling_vs_achieved.png` -- per-flow ceilings (train-majority lookup, val oracle) vs ROUTED seed-0 recall per class, all / per group.",
          f"- `figures/context_W10.png` -- ECDFs of the three causal context features (W = 10 s) for {a} vs {b} per group (val; {b} capped)."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
