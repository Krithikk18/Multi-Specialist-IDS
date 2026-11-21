#!/usr/bin/env python
"""diagnostics/orient_gate_r3.py -- READ-ONLY gate before the orientation normaliser is built (Phase 2 closeout step A).

Measures, on TRAIN and VAL (common/phase2_data.load_split; test never read), per split x group x class:
  R1  FWD Init Win Bytes == 0 AND Bwd Init Win Bytes > 0                                    (diag_02's proposal)
  R3  Protocol == 6 AND R1 AND SYN Flag Count >= 1 AND Total Fwd Packet == 1                (the rule to build)
Gate (all must hold, else STOP -- nothing else is built):
  (a) R3 flags 100 % of the focus-group val class-A flows with FWD Init Win == 0, and exactly the class-A rows R1 flags
      in train (and in val); every class-A row R1 flags and R3 does not is listed with its profile
  (b) benign flagged by R3 <= 0.05 % in every split x group
  (c) class-B (default syn_flood) rows flagged by R3 <= 10 per split
  (d) 0 non-TCP rows flagged by R3 (also reported without R3's protocol clause)
Outputs: results/orient_gate/ (summary.md, run_manifest.json, run_meta.json, run.log, figures/flag_rate_r1_vs_r3.png);
gate.json in ~/lgids_cache/v2/diag/<run_id>/. --dry-run: the 5 % sample, results/orient_gate/dry_run/<run_id>/.
"""

from __future__ import annotations

import argparse
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

SCRIPT = "diagnostics/orient_gate_r3.py"
STEP = "orient_gate"
TCP, BENIGN = 6, 0
FIW, BIW, PROTO, SYN, NF, NB = ("FWD Init Win Bytes", "Bwd Init Win Bytes", "Protocol", "SYN Flag Count",
                                "Total Fwd Packet", "Total Bwd packets")
BENIGN_MAX_PCT, B_MAX_ROWS = 0.05, 10


def flags(df: pd.DataFrame) -> dict:
    """{"R1", "R3", "R3_no_proto"} boolean arrays (NaN never flags)."""
    g = lambda c: pd.to_numeric(df[c], errors="coerce").to_numpy(float)   # noqa: E731
    with np.errstate(invalid="ignore"):
        r1 = (g(FIW) == 0) & (g(BIW) > 0)
        r3np = r1 & (g(SYN) >= 1) & (g(NF) == 1)
        return {"R1": r1, "R3": r3np & (g(PROTO) == TCP), "R3_no_proto": r3np}


def fig_rates(path, rows, names, title):
    import matplotlib.pyplot as plt
    from matplotlib.colors import Normalize
    PS.apply()
    cols = sorted({(r["split"], r["group"]) for r in rows}, key=lambda x: (x[0] != "train", x[1]))
    K = len(names)
    fig, axes = plt.subplots(1, 2, figsize=(2.0 * len(cols) + 2.4, 0.62 * K + 1.6), sharey=True)
    vmax = max([1.0] + [r[f"pct_{v}"] for r in rows for v in ("R1", "R3")])
    for ax, v in zip(axes, ("R1", "R3")):
        V = np.full((K, len(cols)), np.nan)
        N = np.zeros((K, len(cols)), int)
        Fc = np.zeros((K, len(cols)), int)
        for r in rows:
            j = cols.index((r["split"], r["group"]))
            V[r["class_id"], j], N[r["class_id"], j], Fc[r["class_id"], j] = r[f"pct_{v}"], r["n"], r[f"flag_{v}"]
        ax.imshow(np.nan_to_num(V), cmap=PS.SEQUENTIAL_CMAP, norm=Normalize(0, vmax), aspect="auto")
        for i in range(K):
            for j in range(len(cols)):
                if N[i, j] == 0:
                    ax.text(j, i, "-", ha="center", va="center", fontsize=8, color=PS.TEXT2)
                else:
                    ax.text(j, i, f"{V[i, j]:.3f} %\n{Fc[i, j]:,} / {N[i, j]:,}", ha="center", va="center", fontsize=6.3,
                            color="#ffffff" if V[i, j] > 0.6 * vmax else PS.TEXT1)
        ax.set_xticks(range(len(cols)), [f"{s}\n{g}" for s, g in cols], fontsize=7.5)
        ax.set_yticks(range(K), names, fontsize=8)
        ax.tick_params(length=0)
        for sp in ax.spines.values():
            sp.set_visible(False)
        ax.set_title(v, loc="left", fontsize=9)
    fig.subplots_adjust(top=0.82, wspace=0.05)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--class-a", default="port_scan")
    ap.add_argument("--class-b", default="syn_flood")
    ap.add_argument("--focus-group", default="G1")
    ap.add_argument("--rerun-tag", default=None,
                    help="write results to results/orient_gate/<tag>/ (a corrected rerun; earlier runs are kept)")
    args = ap.parse_args()
    cfg = load_phase2_config()
    step = STEP
    if args.rerun_tag:
        from config.config import RESULTS_DIR
        cfg["_results_root"] = str(RESULTS_DIR / STEP)
        step = args.rerun_tag
    S.verify_v2_lock(strict=True)
    pins_before = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                     ("config/class_map.json", S.CLASS_MAP_PATH))}
    cm = S.load_class_map()
    names, K = list(cm.names), cm.n_classes
    A, B = cm.id_of(args.class_a), cm.id_of(args.class_b)
    fg = args.focus_group
    ctx = R.start_run(step, "diag", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    M.update({"pins_before": pins_before, "read_only": True, "class_a": args.class_a, "class_b": args.class_b,
              "focus_group": fg, "rules": {"R1": f"{FIW} == 0 AND {BIW} > 0",
                                           "R3": f"{PROTO} == {TCP} AND R1 AND {SYN} >= 1 AND {NF} == 1"}})
    ok, out = False, {}
    try:
        c = cfg["columns"]
        feats = S.feature_columns()
        need = [FIW, BIW, PROTO, SYN, NF, NB]
        if any(f not in feats for f in need):
            raise RuntimeError(f"required columns missing from the feature list: {[f for f in need if f not in feats]}")
        cols = feats + [c["group"], c["label_id"], "device", "Src Port", "Dst Port"]
        sp = {s: D.load_split(cfg, s, cols, sample=args.dry_run) for s in ("train", "val")}
        M["inputs"] = {s: D.verify_split_file(cfg, s) for s in sp} | {"test_read": False}
        rows, F = [], {}
        for s, d in sp.items():
            F[s] = flags(d)
            y = d[c["label_id"]].to_numpy(np.int64)
            g = d[c["group"]].astype(str).to_numpy()
            for gg in sorted(set(g)):
                for k in range(K):
                    m = (g == gg) & (y == k)
                    if m.any():
                        rows.append({"split": s, "group": gg, "class": names[k], "class_id": k, "n": int(m.sum()),
                                     **{f"flag_{v}": int((F[s][v] & m).sum()) for v in ("R1", "R3")},
                                     **{f"pct_{v}": 100 * float(F[s][v][m].mean()) for v in ("R1", "R3")}})
        out["rows"] = rows
        # (a)
        va = sp["val"]
        yv, gv = va[c["label_id"]].to_numpy(), va[c["group"]].astype(str).to_numpy()
        fz = pd.to_numeric(va[FIW]).to_numpy() == 0
        selv = (gv == fg) & (yv == A) & fz
        a_val = {"n": int(selv.sum()), "R3": int((selv & F["val"]["R3"]).sum()), "R1": int((selv & F["val"]["R1"]).sum())}
        diff = {}
        for s, d in sp.items():
            ya = d[c["label_id"]].to_numpy() == A
            d13 = ya & F[s]["R1"] & ~F[s]["R3"]
            d31 = ya & F[s]["R3"] & ~F[s]["R1"]
            prof = d.loc[d13, [FIW, BIW, PROTO, SYN, NF, NB, "RST Flag Count", "ACK Flag Count", "Flow Duration",
                               c["group"], "device", "Src Port", "Dst Port"]]
            diff[s] = {"A_R1": int((ya & F[s]["R1"]).sum()), "A_R3": int((ya & F[s]["R3"]).sum()),
                       "A_R1_not_R3": int(d13.sum()), "A_R3_not_R1": int(d31.sum()),
                       "profile_R1_not_R3": prof.head(50).astype(str).to_dict("records"),
                       "profile_counts": {col: {str(k): int(v) for k, v in prof[col].value_counts().head(5).items()}
                                          for col in (NF, NB, SYN, c["group"])} if len(prof) else {}}
        out["a"] = {"val_focus": a_val, "per_split": diff}
        crit_a = a_val["n"] > 0 and a_val["R3"] == a_val["n"] and all(v["A_R1_not_R3"] == 0 and v["A_R3_not_R1"] == 0
                                                                       for v in diff.values())
        ben = [r for r in rows if r["class_id"] == BENIGN]
        crit_b = all(r["pct_R3"] <= BENIGN_MAX_PCT for r in ben)
        bsyn = {s: sum(r["flag_R3"] for r in rows if r["split"] == s and r["class_id"] == B) for s in sp}
        crit_c = all(v <= B_MAX_ROWS for v in bsyn.values())
        nontcp = {s: {"R3": int((F[s]["R3"] & (pd.to_numeric(d[PROTO]).to_numpy() != TCP)).sum()),
                      "R3_without_protocol_clause": int((F[s]["R3_no_proto"] & (pd.to_numeric(d[PROTO]).to_numpy() != TCP)).sum())}
                  for s, d in sp.items()}
        crit_d = all(v["R3"] == 0 for v in nontcp.values())
        out["gate"] = {"pass": bool(crit_a and crit_b and crit_c and crit_d), "a": bool(crit_a), "b": bool(crit_b),
                       "c": bool(crit_c), "d": bool(crit_d), "b_worst": max(ben, key=lambda r: r["pct_R3"]),
                       "c_counts": bsyn, "d_counts": nontcp}
        # benign R3 profile (what is still flipped)
        bp = {}
        for s, d in sp.items():
            m = (d[c["label_id"]].to_numpy() == BENIGN) & F[s]["R3"]
            bp[s] = d.loc[m, ["device", "Src Port", "Dst Port", NF, NB, SYN, "RST Flag Count", "FIN Flag Count"]].astype(str).to_dict("records")
        out["benign_R3_rows"] = bp
        R.write_json(ctx.partial / "gate.json", out)
        fig_rates(ctx.fig / "flag_rate_r1_vs_r3.png", rows, names,
                  "Rows flagged REVERSED: R1 vs R3, % of class per split x group (flagged / n)")
        M["figures"] = ["figures/flag_rate_r1_vs_r3.png"]
        M["gate"] = {k: v for k, v in out["gate"].items() if k != "b_worst"} | {"b_worst": out["gate"]["b_worst"]}
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                         ("config/class_map.json", S.CLASS_MAP_PATH))}
    R.add_check(ctx, M, "config.py / class_map.json unchanged", M["pins_after"] == pins_before, "")
    ok = ok and M["pins_after"] == pins_before
    M["status"] = "PASS" if ok else "FAIL"
    write_summary(ctx.res / "summary.md", M, out, args, ctx)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def write_summary(path, M, out, args, ctx) -> None:
    a, b, fg = args.class_a, args.class_b, args.focus_group
    L = [f"# Orientation normaliser -- R3 gate -- run {M['status']}" + (" (DRY RUN)" if M["dry_run"] else ""), "",
         f"- run `{ctx.run_id}`; READ-ONLY; train / val via common/phase2_data.load_split (test never read).",
         f"- R1 = `{M['rules']['R1']}`; **R3 = `{M['rules']['R3']}`**."]
    if getattr(args, "rerun_tag", None):
        L += [f"- **corrected rerun** (`--rerun-tag {args.rerun_tag}`): supersedes the percentages of the first run in "
              "`results/orient_gate/` (kept, not overwritten), whose % columns divided by the split's row count instead "
              "of the cell's; its flag COUNTS and gate decisions are identical to this run's."]
    L += ["",
         "## Gate (fixed before the numbers; all must hold, else STOP)", "",
         f"- (a) R3 flags 100 % of {fg} val {a} flows with {FIW} = 0, and exactly the {a} rows R1 flags in train and val;",
         f"- (b) benign flagged by R3 <= {BENIGN_MAX_PCT} % in every split x group;",
         f"- (c) {b} rows flagged by R3 <= {B_MAX_ROWS} per split;", "- (d) 0 non-TCP rows flagged by R3.", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```"]
        path.write_text("\n".join(L) + "\n", encoding="utf-8")
        return
    G = out["gate"]
    av = out["a"]["val_focus"]
    wb = G["b_worst"]
    L += ["## Result", "", f"- **GATE {'PASS' if G['pass'] else 'FAIL'}**",
          f"- (a) {'PASS' if G['a'] else 'FAIL'}: R3 flags {av['R3']:,} of {av['n']:,} {fg} val {a} flows with {FIW} = 0 "
          f"(R1 {av['R1']:,}); per split {a} rows R1 / R3 / R1-not-R3 / R3-not-R1: "
          + "; ".join(f"{s} {v['A_R1']:,} / {v['A_R3']:,} / {v['A_R1_not_R3']} / {v['A_R3_not_R1']}" for s, v in out["a"]["per_split"].items()),
          f"- (b) {'PASS' if G['b'] else 'FAIL'}: worst split x group {wb['split']} {wb['group']}: {wb['flag_R3']} of {wb['n']:,} "
          f"benign = {wb['pct_R3']:.4f} %",
          f"- (c) {'PASS' if G['c'] else 'FAIL'}: {b} rows flagged by R3 per split {G['c_counts']}",
          f"- (d) {'PASS' if G['d'] else 'FAIL'}: non-TCP flagged {G['d_counts']}", "",
          "## Flags per split x group x class", "",
          "| split | group | class | n | R1 | R1 % | R3 | R3 % |", "|---|---|---|---|---|---|---|---|"]
    for r in out["rows"]:
        L.append(f"| {r['split']} | {r['group']} | {r['class']} | {r['n']:,} | {r['flag_R1']:,} | {r['pct_R1']:.4f} | "
                 f"{r['flag_R3']:,} | {r['pct_R3']:.4f} |")
    L += ["", f"## {a} rows R1 flags and R3 does not", ""]
    for s, v in out["a"]["per_split"].items():
        L.append(f"- {s}: {v['A_R1_not_R3']} rows" + (f"; value counts {v['profile_counts']}" if v["A_R1_not_R3"] else ""))
    L += ["", "## Benign rows R3 still flags", ""]
    for s, rws in out["benign_R3_rows"].items():
        L.append(f"- {s}: {len(rws)} rows" + ("" if not rws else ": " + "; ".join(
            f"{r['device']} {r['Src Port']}->{r['Dst Port']} (fwd {r[NF]}, bwd {r[NB]}, SYN {r[SYN]}, RST {r['RST Flag Count']}, "
            f"FIN {r['FIN Flag Count']})" for r in rws[:25])))
    L += ["", "## Figures", "", "- `figures/flag_rate_r1_vs_r3.png` -- % of each class flagged by R1 (left) and R3 (right) "
          "per split x group, with flagged / n."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
