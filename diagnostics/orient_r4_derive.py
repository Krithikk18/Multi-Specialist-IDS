#!/usr/bin/env python
"""diagnostics/orient_r4_derive.py -- STEP A: derive the second orientation rule R4 (device SYN/ACK-first reversals) on
TRAIN only (v2_1_oriented, i.e. after R3). READ-ONLY: writes results/orient_r4/derive/ + its cache run dir.

A1  ground truth (EVALUATION ONLY, never in a rule): TCP attack rows; TRUTH_REVERSED = inventory device -> attack source;
    TRUTH_FORWARD = attack source -> inventory device (diagnostics/orient_r4_common.Truth). Counts per class x group,
    profile of REVERSED vs FORWARD on every predicate and on the numeric fields.
A2  candidates = Protocol == TCP AND up to 4 of the 42 structural predicates (orient_r4_common.predicates()), applied
    only to rows R3 did not flip.
A3  selection (fixed): admissible iff on TRAIN benign flagged <= 0.05 % in every group, TRUTH_FORWARD flagged
    <= 0.1 % per attack class, non-TCP flagged = 0; pick the highest TRUTH_REVERSED recall; ties -> fewer predicates
    -> no port predicate (-> D-log tie-breaks). Best admissible recall < 90 % -> STOP (no rule; exit code 2).
A4  R3 over-flip audit (report-only): rows R3 flipped (train, val) that were TRUTH_FORWARD before the flip (v2_0
    MACs); the 2 diag_03 flows traced; a structural R3 exclusion proposed only if it costs no R3 recall.
Figures: profile_predicates.png, profile_numeric.png, frontier.png.
"""

from __future__ import annotations

import argparse
import itertools
import sys
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
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402
from diagnostics import orient_r4_common as Q  # noqa: E402

SCRIPT = "diagnostics/orient_r4_derive.py"
BENIGN = 0
BEN_MAX, FWD_MAX, MIN_RECALL, MAX_EXTRA = 0.0005, 0.001, 0.90, 4
DIAG03_FLOWS = REPO_ROOT / "results" / "diag_03" / "B_flows.csv"
R3_GATE = RESULTS_DIR / "orient_gate" / "rerun_pct_fix"
META = ["session", "row_in_file", "label_id", "group", "src_mac", "dst_mac", "orientation_flipped", "Flow ID", "start_ts"]


def pins() -> dict:
    return {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH), ("config/class_map.json", S.CLASS_MAP_PATH))}


def load(cfg21: dict, cfg20: dict, split: str, dry: bool, truth: Q.Truth, names: list) -> pd.DataFrame:
    d = D.load_split(cfg21, split, Q.RULE_COLUMNS + META, sample=dry)
    raw = D.load_split(cfg20, split, ["session", "row_in_file", "src_mac", "dst_mac", "group", "label_id"], sample=dry)
    if not (np.array_equal(d["session"].to_numpy(), raw["session"].to_numpy())
            and np.array_equal(d["row_in_file"].to_numpy(), raw["row_in_file"].to_numpy())):
        raise RuntimeError(f"{split}: v2_1 and v2_0 rows are not in the same order")
    d["raw_src_mac"], d["raw_dst_mac"] = raw["src_mac"].to_numpy(), raw["dst_mac"].to_numpy()
    y = d["label_id"].to_numpy(np.int64)
    proto = pd.to_numeric(d[Q.PROTO]).to_numpy()
    T = truth.labels(d["src_mac"].astype(str).to_numpy(), d["dst_mac"].astype(str).to_numpy(), proto, y, BENIGN)
    Tr = truth.labels(d["raw_src_mac"].astype(str).to_numpy(), d["raw_dst_mac"].astype(str).to_numpy(), proto, y, BENIGN)
    d["REV"], d["FWD"], d["RAW_REV"], d["RAW_FWD"] = T["REV"], T["FWD"], Tr["REV"], Tr["FWD"]
    d["cls"] = [names[k] for k in y]
    d["uid"] = d["session"].astype(str) + ":" + d["row_in_file"].astype(str)
    return d


def counts_table(d: pd.DataFrame, names: list) -> list[dict]:
    rows = []
    fl = d["orientation_flipped"].to_numpy(bool)
    tcp = pd.to_numeric(d[Q.PROTO]).to_numpy() == Q.TCP
    for (g, c), s in d.groupby(["group", "cls"], sort=True):
        if c == names[BENIGN]:
            continue
        ix = s.index.to_numpy()
        rows.append({"group": g, "class": c, "n": len(ix), "tcp": int(tcp[ix].sum()),
                     "REV": int(d["REV"].to_numpy()[ix].sum()), "REV_unflipped": int((d["REV"].to_numpy()[ix] & ~fl[ix]).sum()),
                     "FWD": int(d["FWD"].to_numpy()[ix].sum()), "R3_flipped": int(fl[ix].sum()),
                     "other_tcp": int((tcp[ix] & ~d["REV"].to_numpy()[ix] & ~d["FWD"].to_numpy()[ix]).sum())})
    return rows


def search(d: pd.DataFrame, P: list, names: list, att_classes: list, groups: list) -> tuple[pd.DataFrame, dict]:
    """Every conjunction (TCP AND <= MAX_EXTRA predicates) on the unflipped TCP rows; counts via unique bit patterns."""
    fl = d["orientation_flipped"].to_numpy(bool)
    tcp = pd.to_numeric(d[Q.PROTO]).to_numpy() == Q.TCP
    scope = tcp & ~fl
    y = d["label_id"].to_numpy(np.int64)
    g = d["group"].astype(str).to_numpy()
    cats = ["REV", *[f"FWD|{c}" for c in att_classes], *[f"BEN|{gg}" for gg in groups], "OTHER_ATT"]
    cat = np.full(len(d), -1)
    cat[d["REV"].to_numpy()] = 0
    for k, c in enumerate(att_classes):
        cat[d["FWD"].to_numpy() & (d["cls"].to_numpy() == c)] = 1 + k
    for k, gg in enumerate(groups):
        cat[(y == BENIGN) & (g == gg)] = 1 + len(att_classes) + k
    cat[(cat == -1) & (y != BENIGN)] = len(cats) - 1
    code = Q.encode(d.loc[scope], P)
    df = pd.DataFrame({"code": code, "cat": cat[scope]})
    tab = df.groupby(["code", "cat"]).size().unstack(fill_value=0)
    tab = tab.reindex(columns=range(len(cats)), fill_value=0)
    codes = tab.index.to_numpy(np.uint64)
    C = tab.to_numpy(np.int64)
    den = {"REV": int((d["REV"].to_numpy() & ~fl).sum()), "REV_all": int(d["REV"].to_numpy().sum()),
           **{f"FWD|{c}": int((d["FWD"].to_numpy() & (d["cls"].to_numpy() == c)).sum()) for c in att_classes},
           **{f"BEN|{gg}": int(((y == BENIGN) & (g == gg)).sum()) for gg in groups},
           "patterns": int(len(codes)), "scope_rows": int(scope.sum()), "non_tcp_rows": int((~tcp).sum())}
    combos = [()]
    for k in range(1, MAX_EXTRA + 1):
        combos += list(itertools.combinations(range(len(P)), k))
    masks = np.array([sum(np.uint64(1) << np.uint64(i) for i in cb) if cb else np.uint64(0) for cb in combos], np.uint64)
    out = np.zeros((len(combos), len(cats)), np.int64)
    B = 500
    Cf = C.astype(np.float64)
    for s in range(0, len(combos), B):
        mk = masks[s:s + B]
        sat = (codes[None, :] & mk[:, None]) == mk[:, None]
        out[s:s + B] = np.rint(sat.astype(np.float64) @ Cf).astype(np.int64)
    res = pd.DataFrame(out, columns=cats)
    res["combo"] = combos
    res["n_pred"] = [len(cb) for cb in combos]
    res["has_port"] = [any(P[i]["port"] for i in cb) for cb in combos]
    res["recall"] = res["REV"] / max(den["REV"], 1)
    for gg in groups:
        res[f"ben_pct|{gg}"] = 100 * res[f"BEN|{gg}"] / max(den[f"BEN|{gg}"], 1)
    res["ben_pct_max"] = res[[f"ben_pct|{gg}" for gg in groups]].max(axis=1)
    for c in att_classes:
        res[f"fwd_pct|{c}"] = 100 * res[f"FWD|{c}"] / den[f"FWD|{c}"] if den[f"FWD|{c}"] else 0.0
    res["fwd_pct_max"] = res[[f"fwd_pct|{c}" for c in att_classes]].max(axis=1) if att_classes else 0.0
    res["ben_total"] = res[[f"BEN|{gg}" for gg in groups]].sum(axis=1)
    res["fwd_total"] = res[[f"FWD|{c}" for c in att_classes]].sum(axis=1)
    res["admissible"] = (res["ben_pct_max"] <= 100 * BEN_MAX) & (res["fwd_pct_max"] <= 100 * FWD_MAX)
    return res, den


def choose(res: pd.DataFrame) -> pd.Series | None:
    a = res[res["admissible"] & (res["n_pred"] > 0)]
    if not len(a):
        return None
    a = a.assign(_lex=[tuple(cb) for cb in a["combo"]])
    a = a.sort_values(["recall", "n_pred", "has_port", "ben_total", "fwd_total", "OTHER_ATT", "_lex"],
                      ascending=[False, True, True, True, True, True, True], kind="mergesort")
    return a.iloc[0]


def overflip_audit(sp: dict, P: list, gate_args: dict, names: list) -> dict:
    """Rows R3 flipped that were TRUTH_FORWARD before the flip (raw MACs); best single-predicate exclusion."""
    out = {"per_split": {}, "traced": []}
    r3c = Q.r3_clauses()
    for s, d in sp.items():
        fl = d["orientation_flipped"].to_numpy(bool)
        rows = []
        for c in sorted(set(d["cls"])):
            m = fl & (d["cls"].to_numpy() == c)
            rows.append({"class": c, "R3_flipped": int(m.sum()), "raw_FORWARD_overflip": int((m & d["RAW_FWD"].to_numpy()).sum()),
                         "raw_REVERSED_correct": int((m & d["RAW_REV"].to_numpy()).sum())})
        out["per_split"][s] = rows
    if DIAG03_FLOWS.is_file():
        B = pd.read_csv(DIAG03_FLOWS)
        h4 = B[(B["hypothesis"] == "H4") & B["orientation_flipped"]].drop_duplicates("flow_uid")
        for u in h4["flow_uid"]:
            for s, d in sp.items():
                r = d[d["uid"] == u]
                if len(r):
                    r = r.iloc[0]
                    out["traced"].append({"flow_uid": u, "split": s, "class": r["cls"], "R3_flipped": bool(r["orientation_flipped"]),
                                          "raw_src_mac": r["raw_src_mac"], "raw_dst_mac": r["raw_dst_mac"],
                                          "raw_FORWARD": bool(r["RAW_FWD"]), "raw_REVERSED": bool(r["RAW_REV"]),
                                          **{k: float(r[k]) for k in (Q.NF, Q.NB, Q.FIW, Q.BIW, *Q.FLAGS[:4])}})
    # exclusion search: R3 AND p (p one predicate, evaluated on the RAW row = the R3-flipped row swapped back is not
    # available here, so the predicate is evaluated on the v2_0 features); keep 100 % of raw-REVERSED flips and of the
    # R3 gate's (a) rows; remove as many raw-FORWARD flips as possible (train)
    return out


def exclusion_search(raw: dict, P: list, gate_args: dict, names: list) -> dict:
    """raw[split] = v2_0 rows with R3 / truth columns. R3 AND p must keep every raw-REVERSED R3 flip and every R3 gate
    (a) row (focus group, class A, FWD Init Win == 0) in train and val; maximise removed raw-FORWARD flips on train."""
    best = None
    rows = []
    for k, p in enumerate(P):
        ok, rem, rem_val, lost = True, 0, 0, {}
        for s, d in raw.items():
            r3 = d["R3"].to_numpy(bool)
            pm = Q.clause_mask(d, p["clause"])
            keep_rev = d["RAW_REV"].to_numpy() & r3
            ga = (d["group"].astype(str).to_numpy() == gate_args["focus_group"]) & (d["cls"].to_numpy() == gate_args["class_a"]) \
                & (pd.to_numeric(d[Q.FIW]).to_numpy() == 0) & r3
            lost[s] = int((keep_rev & ~pm).sum()) + int((ga & ~pm).sum())
            ok &= lost[s] == 0
            removed = int((r3 & d["RAW_FWD"].to_numpy() & ~pm).sum())
            if s == "train":
                rem = removed
            else:
                rem_val = removed
        rows.append({"predicate": p["name"], "keeps_all_correct_flips": ok, "removed_overflips_train": rem,
                     "removed_overflips_val": rem_val, "lost": lost})
        if ok and rem > 0 and (best is None or rem > best["removed_overflips_train"]):
            best = rows[-1]
    return {"candidates": sorted(rows, key=lambda r: (-r["keeps_all_correct_flips"], -r["removed_overflips_train"]))[:10],
            "proposal": best}


def stop_diagnosis(res: pd.DataFrame, sp: dict, P: list, att: list, groups: list, names: list) -> dict:
    """REPORT-ONLY (never changes the selection): which constraint binds, where the best admissible candidate's recall
    comes from (class x group x Bwd Init Win shape), and how many of the diag_03 H1 alert flows it would flag."""
    cand = res[res["n_pred"] > 0]
    ben_ok = (cand["ben_pct_max"] <= 100 * BEN_MAX).to_numpy()
    fwd_ok = {c: (cand[f"fwd_pct|{c}"] <= 100 * FWD_MAX).to_numpy() for c in att}
    ones = np.ones(len(cand), bool)
    all_fwd = np.logical_and.reduce([v for v in fwd_ok.values()] + [ones])
    rec = cand["recall"].to_numpy()

    def best(m):
        return float(rec[m].max()) if m.any() else float("nan")

    D_ = {"best_recall": {"admissible": best(ben_ok & all_fwd), "benign_limit_only": best(ben_ok),
                          "truth_forward_limit_only": best(all_fwd), "no_limit": best(ones),
                          **{f"admissible_without_the_{c}_FORWARD_limit":
                             best(ben_ok & np.logical_and.reduce([fwd_ok[k] for k in att if k != c] + [ones])) for c in att}}}
    a = cand[ben_ok & all_fwd].sort_values(["recall", "n_pred"], ascending=[False, True])
    if not len(a):
        return D_
    cl = [dict(Q.TCP_CLAUSE)] + [P[i]["clause"] for i in a.iloc[0]["combo"]]
    D_["best_admissible"] = Q.describe(cl)
    seg = []
    for s, d in sp.items():
        fl = d["orientation_flipped"].to_numpy(bool)
        rev = d["REV"].to_numpy() & ~fl
        hit = Q.rule_mask(d, cl) & ~fl
        bz = pd.to_numeric(d[Q.BIW]).to_numpy() == 0
        sub = d.loc[rev, ["group", "cls"]]
        for (g, c), ss in sub.groupby(["group", "cls"]):
            ix = ss.index.to_numpy()
            for shape, m in (("Bwd Init Win == 0", bz[ix]), ("Bwd Init Win > 0", ~bz[ix])):
                if m.any():
                    seg.append({"split": s, "group": g, "class": c, "shape": shape, "REVERSED": int(m.sum()),
                                "flagged": int(hit[ix][m].sum())})
    D_["segments"] = seg
    if DIAG03_FLOWS.is_file():
        B = pd.read_csv(DIAG03_FLOWS)
        h1 = B[B["hypothesis"] == "H1"]
        va = sp["val"]
        hit = pd.Series(Q.rule_mask(va, cl) & ~va["orientation_flipped"].to_numpy(bool), index=va["uid"].to_numpy())
        u = h1["flow_uid"].drop_duplicates()
        D_["diag03_H1"] = {"occurrences": int(len(h1)), "unique": int(len(u)),
                           "flagged_unique": int(hit.reindex(u).fillna(False).astype(bool).sum()),
                           "flagged_occurrences": int(hit.reindex(h1["flow_uid"]).fillna(False).astype(bool).sum())}
    return D_


# --------------------------------------------------------------------------- figures
def fig_profile(path, prof: pd.DataFrame, chosen_names: list):
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    PS.apply()
    n = len(prof)
    fig, ax = plt.subplots(figsize=(8.8, 0.21 * n + 1.6))
    y = np.arange(n)
    sty = {"REV": (PS.CATEGORICAL[1], "o", "TRUTH_REVERSED (unflipped)"), "FWD": (PS.CATEGORICAL[0], "s", "TRUTH_FORWARD"),
           "BEN": (PS.BENIGN_GRAY, "^", "benign")}
    for k, (col, mk, lab) in sty.items():
        ax.plot(100 * prof[k], y, mk, color=col, ms=4.5, ls="none", label=lab, alpha=0.9)
    for i, nm in enumerate(prof["name"]):
        if nm in chosen_names:
            ax.axhspan(i - 0.45, i + 0.45, color=PS.CATEGORICAL[3], alpha=0.18, lw=0)
    ax.set_yticks(y, prof["name"], fontsize=6.5)
    ax.invert_yaxis()
    ax.set_xlim(-2, 102)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_xlabel("% of rows where the predicate holds (TCP rows, TRAIN)")
    hand = ax.get_legend_handles_labels()[0] + ([Line2D([], [], color=PS.CATEGORICAL[3], lw=6, alpha=0.4,
                                                        label="predicate in the chosen R4")] if chosen_names else [])
    ax.legend(handles=hand, frameon=False, fontsize=7, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=4)
    ax.set_title("STEP A: structural predicates, TRUTH_REVERSED vs TRUTH_FORWARD vs benign (train, v2_1)", loc="left",
                 fontsize=9, pad=22)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_numeric(path, d: pd.DataFrame):
    import matplotlib.pyplot as plt
    PS.apply()
    fl = d["orientation_flipped"].to_numpy(bool)
    sel = {"REV": d["REV"].to_numpy() & ~fl, "FWD": d["FWD"].to_numpy()}
    fields = [(Q.FIW, None), (Q.BIW, None), (Q.FHL, Q.NF), (Q.BHL, Q.NB), (Q.NF, None), (Q.NB, None), *[(f, None) for f in Q.FLAGS[:4]]]
    fig, axes = plt.subplots(2, 5, figsize=(12.5, 5.0))
    rng = np.random.default_rng(0)
    for ax, (f, per) in zip(axes.flat, fields):
        for j, (k, col) in enumerate((("REV", PS.CATEGORICAL[1]), ("FWD", PS.CATEGORICAL[0]))):
            ix = np.flatnonzero(sel[k])
            if len(ix) > 3000:
                ix = np.sort(rng.choice(ix, 3000, replace=False))
            v = pd.to_numeric(d[f]).to_numpy(float)[ix]
            if per:
                n = pd.to_numeric(d[per]).to_numpy(float)[ix]
                v = np.where(n > 0, v / np.where(n > 0, n, 1), np.nan)
            v = v[~np.isnan(v)]
            ax.scatter(j + rng.uniform(-0.2, 0.2, len(v)), v, s=4, color=col, alpha=0.4, lw=0)
            if len(v):
                ax.plot([j - 0.3, j + 0.3], [np.median(v)] * 2, color=PS.TEXT1, lw=1.2)
        if per is None:
            ax.set_yscale("symlog", linthresh=1)
        ax.set_xticks([0, 1], ["REV", "FWD"])
        ax.set_title(f + (f" / {per}" if per else ""), loc="left", fontsize=7.5)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
    fig.suptitle("STEP A: TRUTH_REVERSED (unflipped) vs TRUTH_FORWARD, TCP attack rows, train (sample <= 3,000 each; "
                 "bar = median; symlog except the per-packet header lengths)", x=0.01, ha="left", fontsize=9)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    return PS.save(fig, path)


def fig_frontier(path, res: pd.DataFrame, best):
    import matplotlib.pyplot as plt
    PS.apply()
    r = res[res["n_pred"] > 0].drop_duplicates(["recall", "ben_pct_max", "admissible"])
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    for adm, col, lab in ((False, PS.NEUTRAL_LIGHT, "not admissible (benign or TRUTH_FORWARD limit)"),
                          (True, PS.CATEGORICAL[0], "admissible")):
        s = r[r["admissible"] == adm]
        ax.scatter(np.maximum(s["ben_pct_max"], 1e-4), 100 * s["recall"], s=5, color=col, alpha=0.5, lw=0, label=lab,
                   rasterized=True)
    ax.axvline(100 * BEN_MAX, color=PS.TEXT2, lw=0.8, ls="--")
    ax.text(100 * BEN_MAX * 1.12, 45, f"benign limit {100 * BEN_MAX:g} %", fontsize=6.5, color=PS.TEXT2, rotation=90,
            va="center")
    ax.axhline(100 * MIN_RECALL, color=PS.TEXT2, lw=0.8, ls=":")
    ax.text(2e-4, 100 * MIN_RECALL + 1, f"min recall {100 * MIN_RECALL:g} %", fontsize=6.5, color=PS.TEXT2)
    if best is not None:
        ax.plot(max(best["ben_pct_max"], 1e-4), 100 * best["recall"], "*", ms=14, color=PS.CATEGORICAL[1],
                mec=PS.TEXT1, mew=0.6, label="chosen R4")
    ax.set_xscale("log")
    ax.set_xlabel("max benign flagged % over groups (train; 0 drawn at 1e-4)")
    ax.set_ylabel("TRUTH_REVERSED recall % (train, unflipped)")
    ax.set_ylim(-2, 104)
    ax.legend(frameon=True, facecolor=PS.SURFACE, edgecolor="none", fontsize=7, loc="upper left",
              bbox_to_anchor=(0.0, 0.86))
    ax.set_title("STEP A: recall vs benign-flag frontier of every candidate (TCP + <= 4 predicates)", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None, help="results/orient_r4/derive/<tag>/ (a corrected rerun; earlier runs kept)")
    args = ap.parse_args()
    cfg21 = load_phase2_config(REPO_ROOT / "config" / "v2_phase2_v2_1.json")
    cfg20 = load_phase2_config(REPO_ROOT / "config" / "v2_phase2.json")
    cfg21["_results_root"] = str(RESULTS_DIR / "orient_r4")
    step = "derive"
    if args.rerun_tag:
        cfg21["_results_root"] = str(RESULTS_DIR / "orient_r4" / "derive")
        step = args.rerun_tag
    S.verify_v2_lock(strict=True)
    p0 = pins()
    cm = S.load_class_map()
    names = list(cm.names)
    ctx = R.start_run(step, "diag", SCRIPT, cfg21, args.dry_run, args.run_id)
    ctx.log(f"  [start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    M = R.base_manifest(ctx, SCRIPT, ["diagnostics/orient_r4_common.py", "diagnostics/diag_03_common.py",
                                      "13_rate_guard_calibrate.py", "07a_attack_coverage.py", "config/device_table.csv",
                                      "config/v2_phase3.json"])
    M.update({"pins_before": p0, "read_only": True, "selection": {"benign_max_pct": 100 * BEN_MAX,
                                                                   "truth_forward_max_pct": 100 * FWD_MAX,
                                                                   "min_recall": MIN_RECALL, "max_extra_predicates": MAX_EXTRA}})
    ok, out, best, res = False, {}, None, None
    rc = 0
    try:
        truth = Q.Truth()
        M["truth"] = truth.describe()
        P = Q.predicates()
        M["predicates"] = [p["name"] for p in P]
        sp = {s: load(cfg21, cfg20, s, args.dry_run, truth, names) for s in ("train", "val")}
        M["inputs"] = {"v2_1_oriented": {s: D.verify_split_file(cfg21, s) for s in sp},
                       "v2_0_v1equiv": {s: D.verify_split_file(cfg20, s) for s in sp}, "test_read": False}
        tr = sp["train"]
        att = [c for c in names if c != names[BENIGN]]
        groups = sorted(set(tr["group"].astype(str)))
        out["counts"] = {s: counts_table(d, names) for s, d in sp.items()}
        # ---- A1 profile (train)
        fl = tr["orientation_flipped"].to_numpy(bool)
        tcp = pd.to_numeric(tr[Q.PROTO]).to_numpy() == Q.TCP
        grp = {"REV": tr["REV"].to_numpy() & ~fl, "FWD": tr["FWD"].to_numpy(),
               "BEN": (tr["label_id"].to_numpy() == BENIGN) & tcp & ~fl}
        prof = pd.DataFrame({"name": [p["name"] for p in P]})
        for k, m in grp.items():
            sub = tr.loc[m]
            prof[k] = [float(Q.clause_mask(sub, p["clause"]).mean()) if len(sub) else np.nan for p in P]
            prof[f"n_{k}"] = int(m.sum())
        out["profile_predicates"] = prof.to_dict("records")
        num = {}
        for k in ("REV", "FWD"):
            sub = tr.loc[grp[k]]
            num[k] = {}
            for f, per in [(Q.FIW, None), (Q.BIW, None), (Q.FHL, Q.NF), (Q.BHL, Q.NB), (Q.NF, None), (Q.NB, None),
                           *[(f, None) for f in Q.FLAGS], (Q.SPORT, None), (Q.DPORT, None)]:
                v = pd.to_numeric(sub[f]).to_numpy(float)
                if per:
                    n = pd.to_numeric(sub[per]).to_numpy(float)
                    v = np.where(n > 0, v / np.where(n > 0, n, 1), np.nan)
                v = v[~np.isnan(v)]
                num[k][f + (f" / {per}" if per else "")] = ({"p05": float(np.quantile(v, .05)), "median": float(np.median(v)),
                                                            "p95": float(np.quantile(v, .95)), "share_zero": float((v == 0).mean()),
                                                            "n": int(len(v))} if len(v) else {"n": 0})
            if len(sub):
                sp_, dp_ = pd.to_numeric(sub[Q.SPORT]).to_numpy(float), pd.to_numeric(sub[Q.DPORT]).to_numpy(float)
                num[k]["Src Port < Dst Port (share)"] = float((sp_ < dp_).mean())
        out["profile_numeric"] = num
        # ---- A2 / A3 search
        res, den = search(tr, P, names, att, groups)
        out["denominators"] = den
        best = choose(res)
        M["n_candidates"] = int((res["n_pred"] > 0).sum())
        M["n_admissible"] = int((res["admissible"] & (res["n_pred"] > 0)).sum())
        r3c = Q.r3_clauses()
        if best is None or best["recall"] < MIN_RECALL:
            M["rule_found"] = False
            M["stop_reason"] = ("no admissible candidate" if best is None else
                                f"best admissible recall {best['recall']:.4f} < {MIN_RECALL}")
            rc = 2
        else:
            clauses = [dict(Q.TCP_CLAUSE)] + [P[i]["clause"] for i in best["combo"]]
            ties = res[res["admissible"] & (res["n_pred"] > 0) & (res["recall"] == best["recall"])]
            M["rule_found"] = True
            M["chosen"] = {"clauses": clauses, "text": Q.describe(clauses), "predicates": [P[i]["name"] for i in best["combo"]],
                           "uses_port_predicate": bool(best["has_port"]), "train_recall": float(best["recall"]),
                           "train_REV_flagged": int(best["REV"]), "train_REV_unflipped": den["REV"],
                           "train_benign_flagged": {g: int(best[f"BEN|{g}"]) for g in groups},
                           "train_benign_pct": {g: float(best[f"ben_pct|{g}"]) for g in groups},
                           "train_FWD_flagged": {c: int(best[f"FWD|{c}"]) for c in att},
                           "train_FWD_pct": {c: float(best[f"fwd_pct|{c}"]) for c in att},
                           "train_other_attack_flagged": int(best["OTHER_ATT"]),
                           "ties_at_best_recall": {"n": int(len(ties)), "n_min_size": int((ties["n_pred"] == best["n_pred"]).sum()),
                                                   "examples": [Q.describe([P[i]["clause"] for i in cb])
                                                                for cb in ties.sort_values("n_pred")["combo"].head(8)]}}
            # overlap with R3 on raw rows (R3 is evaluated on the extractor's orientation)
            for s, d in sp.items():
                fl_s = d["orientation_flipped"].to_numpy(bool)
                r4 = Q.rule_mask(d, clauses) & ~fl_s
                M["chosen"][f"{s}_flagged_total"] = int(r4.sum())
            ctx.log(f"  chosen R4: {M['chosen']['text']}  (train recall {best['recall']:.4f})")
        out["stop_diagnosis"] = stop_diagnosis(res, sp, P, att, groups, names)
        # top admissible
        top = res[res["admissible"] & (res["n_pred"] > 0)].sort_values(["recall", "n_pred"], ascending=[False, True]).head(15)
        out["top_admissible"] = [{"rule": Q.describe([P[i]["clause"] for i in cb]), "recall": float(r), "n_pred": int(n),
                                  "ben_pct_max": float(b), "fwd_pct_max": float(f), "other_att": int(o)}
                                 for cb, r, n, b, f, o in zip(top["combo"], top["recall"], top["n_pred"], top["ben_pct_max"],
                                                              top["fwd_pct_max"], top["OTHER_ATT"])]
        top_any = res[res["n_pred"] > 0].sort_values(["recall", "ben_pct_max"], ascending=[False, True]).head(10)
        out["top_any"] = [{"rule": Q.describe([P[i]["clause"] for i in cb]), "recall": float(r), "ben_pct_max": float(b),
                           "fwd_pct_max": float(f), "admissible": bool(a)}
                          for cb, r, b, f, a in zip(top_any["combo"], top_any["recall"], top_any["ben_pct_max"],
                                                    top_any["fwd_pct_max"], top_any["admissible"])]
        res.drop(columns=["combo"]).assign(rule=[Q.describe([P[i]["clause"] for i in cb]) for cb in res["combo"]]) \
            .to_parquet(ctx.partial / "candidates.parquet", index=False)
        # ---- A4 over-flip audit
        gm = R.resolve_run("rerun_pct_fix", None, False, RESULTS_DIR / "orient_gate")["manifest"]
        gate_args = {"class_a": gm["class_a"], "focus_group": gm["focus_group"]}
        audit = overflip_audit(sp, P, gate_args, names)
        raw = {}
        for s in sp:
            rd = D.load_split(cfg20, s, Q.RULE_COLUMNS + ["label_id", "group"], sample=args.dry_run)
            rd["R3"] = Q.rule_mask(rd, r3c)
            if not np.array_equal(rd["R3"].to_numpy(), sp[s]["orientation_flipped"].to_numpy(bool)):
                raise RuntimeError(f"{s}: R3 on v2_0 != v2_1 orientation_flipped")
            rd["RAW_REV"], rd["RAW_FWD"] = sp[s]["RAW_REV"].to_numpy(), sp[s]["RAW_FWD"].to_numpy()
            rd["cls"] = sp[s]["cls"].to_numpy()
            raw[s] = rd
        R.add_check(ctx, M, "R3 recomputed from the pinned map on v2_0 == v2_1 orientation_flipped (train, val)", True, "")
        audit["exclusion"] = exclusion_search(raw, P, gate_args, names)
        audit["gate_args"] = gate_args
        out["overflip"] = audit
        R.write_json(ctx.partial / "derive.json", out)
        M["overflip_summary"] = {s: {"R3_flipped": sum(r["R3_flipped"] for r in v),
                                     "raw_FORWARD_overflip": sum(r["raw_FORWARD_overflip"] for r in v)}
                                 for s, v in audit["per_split"].items()}
        M["overflip_proposal"] = audit["exclusion"]["proposal"]
        # ---- figures
        figs = [fig_profile(ctx.fig / "profile_predicates.png", prof, M.get("chosen", {}).get("predicates", [])),
                fig_numeric(ctx.fig / "profile_numeric.png", tr),
                fig_frontier(ctx.fig / "frontier.png", res, best if M.get("rule_found") else None)]
        M["figures"] = [str(Path(f).relative_to(ctx.res)) for f in figs]
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = pins()
    R.add_check(ctx, M, "config.py / class_map.json unchanged", M["pins_after"] == p0, str(M["pins_after"]))
    ctx.log(f"  [end] config.py {M['pins_after']['config/config.py']}; class_map.json {M['pins_after']['config/class_map.json']}")
    ok = ok and M["pins_after"] == p0
    write_summary(ctx.res / "summary.md", M, out, ctx)
    R.finish_run(ctx, ok, M)
    return (rc or 0) if ok else 1


def write_summary(path, M, out, ctx) -> None:
    L = [f"# Orientation R4 -- STEP A derivation (train) -- run {'PASS' if not M.get('error') else 'FAIL'}"
         + (" (DRY RUN)" if M["dry_run"] else ""), "",
         f"- run `{ctx.run_id}`; READ-ONLY; v2_1_oriented train (+ val for the R3 audit) via load_split; test never read.",
         f"- ground truth (evaluation only): {M.get('truth')}", "",
         "## Selection rule (fixed before the numbers)", "",
         f"- candidates: Protocol == TCP AND <= {MAX_EXTRA} of {len(M.get('predicates', []))} structural predicates, on rows "
         "R3 did not flip;",
         f"- admissible iff on TRAIN: benign flagged <= {100 * BEN_MAX:g} % in every group, TRUTH_FORWARD flagged <= "
         f"{100 * FWD_MAX:g} % per attack class, non-TCP flagged = 0 (TCP clause);",
         "- best = highest TRUTH_REVERSED recall; ties -> fewer predicates -> no port predicate -> fewer benign flags -> "
         "fewer TRUTH_FORWARD flags -> fewer other attack rows -> predicate order;",
         f"- STOP if the best admissible recall < {100 * MIN_RECALL:g} %.", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```"]
        path.write_text("\n".join(L) + "\n", encoding="utf-8")
        return
    L += ["## A1 -- ground-truth counts (TCP attack rows)", "", "| split | group | class | rows | TCP | REVERSED | REVERSED "
          "(R3 did not flip) | FORWARD | R3 flipped | other TCP |", "|---|---|---|---|---|---|---|---|---|---|"]
    for s, rows in out["counts"].items():
        L += [f"| {s} | {r['group']} | {r['class']} | {r['n']:,} | {r['tcp']:,} | {r['REV']:,} | {r['REV_unflipped']:,} | "
              f"{r['FWD']:,} | {r['R3_flipped']:,} | {r['other_tcp']:,} |" for r in rows]
    L += ["", "Predicate profile (train, % of rows where it holds):", "",
          "| predicate | REVERSED | FORWARD | benign TCP |", "|---|---|---|---|"]
    L += [f"| {r['name']} | {100 * r['REV']:.1f} | {100 * r['FWD']:.1f} | {100 * r['BEN']:.2f} |" for r in out["profile_predicates"]]
    L += ["", "Numeric profile (train; p05 / median / p95, share == 0):", "", "| field | REVERSED | FORWARD |", "|---|---|---|"]
    for f in out["profile_numeric"]["REV"]:
        a, b = out["profile_numeric"]["REV"][f], out["profile_numeric"].get("FWD", {}).get(f)
        fm = lambda v: (f"{v:.3f}" if isinstance(v, float) else str(v)) if not isinstance(v, dict) else (  # noqa: E731
            f"{v['p05']:g} / {v['median']:g} / {v['p95']:g}, zero {100 * v['share_zero']:.0f} %" if v.get("n") else "-")
        L.append(f"| {f} | {fm(a)} | {fm(b) if b is not None else '-'} |")
    den = out["denominators"]
    L += ["", f"## A2 / A3 -- search ({M['n_candidates']:,} candidates, {M['n_admissible']:,} admissible; "
          f"{den['patterns']:,} distinct predicate patterns over {den['scope_rows']:,} unflipped TCP train rows)", ""]
    if M.get("rule_found"):
        ch = M["chosen"]
        L += [f"- **R4 = `{ch['text']}`**",
              f"- predicates: {ch['predicates']}; port predicate used: {ch['uses_port_predicate']}",
              f"- train TRUTH_REVERSED recall **{100 * ch['train_recall']:.2f} %** ({ch['train_REV_flagged']:,} / "
              f"{ch['train_REV_unflipped']:,} unflipped; all REVERSED incl. R3-flipped: {den['REV_all']:,})",
              f"- train benign flagged per group: " + ", ".join(f"{g} {ch['train_benign_flagged'][g]} ({ch['train_benign_pct'][g]:.4f} %)"
                                                             for g in ch["train_benign_flagged"]),
              f"- train TRUTH_FORWARD flagged per class: " + ", ".join(f"{c} {ch['train_FWD_flagged'][c]} "
                                                                     f"({ch['train_FWD_pct'][c]:.4f} %)" for c in ch["train_FWD_flagged"]),
              f"- other attack rows flagged (neither REVERSED nor FORWARD): {ch['train_other_attack_flagged']:,}; rows flagged "
              f"in total: train {ch['train_flagged_total']:,}, val {ch['val_flagged_total']:,}",
              f"- ties at the best recall: {ch['ties_at_best_recall']['n']} candidates ({ch['ties_at_best_recall']['n_min_size']} "
              f"of the minimum size); e.g. " + "; ".join(f"`{t}`" for t in ch["ties_at_best_recall"]["examples"][:4])]
    else:
        L += [f"- **STOP: no rule** ({M.get('stop_reason')})"]
    L += ["", "Top admissible candidates:", "", "| rule | recall | predicates | max benign % | max FORWARD % | other attack |",
          "|---|---|---|---|---|---|"]
    L += [f"| `{r['rule']}` | {100 * r['recall']:.2f} | {r['n_pred']} | {r['ben_pct_max']:.4f} | {r['fwd_pct_max']:.4f} | "
          f"{r['other_att']:,} |" for r in out["top_admissible"]]
    L += ["", "Highest-recall candidates regardless of admissibility:", "", "| rule | recall | max benign % | max FORWARD % | admissible |",
          "|---|---|---|---|---|"]
    L += [f"| `{r['rule']}` | {100 * r['recall']:.2f} | {r['ben_pct_max']:.4f} | {r['fwd_pct_max']:.4f} | {r['admissible']} |"
          for r in out["top_any"]]
    sd = out.get("stop_diagnosis") or {}
    if sd:
        L += ["", "## Why no rule (REPORT-ONLY; the selection above is unchanged)", "",
              "Best train recall under each subset of the limits:", ""]
        L += [f"- {k.replace('_', ' ')}: {100 * v:.2f} %" for k, v in sd["best_recall"].items()]
        if sd.get("best_admissible"):
            L += ["", f"Where the best admissible candidate `{sd['best_admissible']}` gets its recall (REVERSED rows R3 did "
                  "not flip, by class x group x shape of the backward window):", "",
                  "| split | group | class | shape | REVERSED | flagged | % |", "|---|---|---|---|---|---|---|"]
            L += [f"| {r['split']} | {r['group']} | {r['class']} | {r['shape']} | {r['REVERSED']:,} | {r['flagged']:,} | "
                  f"{100 * r['flagged'] / r['REVERSED']:.1f} |" for r in sd["segments"]]
            if sd.get("diag03_H1"):
                h = sd["diag03_H1"]
                L += ["", f"- diag_03 H1 alert flows it would flag: {h['flagged_unique']} of {h['unique']} unique flows "
                      f"({h['flagged_occurrences']} of {h['occurrences']} occurrences over the 10 runs)."]
    A = out["overflip"]
    L += ["", "## A4 -- R3 over-flip audit (report-only)", "", "| split | class | R3 flipped | FORWARD before the flip "
          "(over-flip) | REVERSED before the flip (correct) |", "|---|---|---|---|---|"]
    for s, rows in A["per_split"].items():
        L += [f"| {s} | {r['class']} | {r['R3_flipped']:,} | {r['raw_FORWARD_overflip']:,} | {r['raw_REVERSED_correct']:,} |"
              for r in rows]
    L += ["", "diag_03 flows traced (R3-flipped flows that ended in H4):", ""]
    L += [f"- `{t['flow_uid']}` ({t['split']}, {t['class']}): R3 flipped {t['R3_flipped']}; before the flip src "
          f"{t['raw_src_mac']} -> dst {t['raw_dst_mac']}; FORWARD before the flip: {t['raw_FORWARD']}; fwd / bwd packets "
          f"{t[Q.NF]:g} / {t[Q.NB]:g}, FWD / Bwd Init Win {t[Q.FIW]:g} / {t[Q.BIW]:g} (as extracted)" for t in A["traced"]]
    ex = A["exclusion"]
    L += ["", f"Exclusion search (R3 AND one predicate; must keep every correct R3 flip and every R3 gate (a) row "
          f"[{A['gate_args']}] in train and val):", ""]
    if ex["proposal"]:
        p = ex["proposal"]
        L.append(f"- **proposed follow-up (NOT applied)**: R3 AND `{p['predicate']}` removes {p['removed_overflips_train']} "
                 f"train / {p['removed_overflips_val']} val over-flips and loses no correct flip.")
    else:
        L.append("- no single structural predicate removes an over-flip without losing a correct R3 flip: no proposal.")
    L += [f"  - {c['predicate']}: keeps all correct flips {c['keeps_all_correct_flips']}, removes {c['removed_overflips_train']} "
          f"train / {c['removed_overflips_val']} val, lost {c['lost']}" for c in ex["candidates"][:6]]
    L += ["", "## Figures", "", "- `figures/profile_predicates.png` -- share of REVERSED / FORWARD / benign rows per predicate",
          "- `figures/profile_numeric.png` -- Init Win, header length per packet, packet counts, flags: REVERSED vs FORWARD",
          "- `figures/frontier.png` -- recall vs max benign flag % of every candidate, chosen rule marked", "",
          "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M["checks"]]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
