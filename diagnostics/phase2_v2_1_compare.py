#!/usr/bin/env python
"""diagnostics/phase2_v2_1_compare.py -- Phase 2 closeout step F: v2_0_v1equiv vs v2_1_oriented, VAL only, READ-ONLY.

Inputs (all read-only, sha256-checked through common/phase2_run.resolve_run): step 23 per-seed metrics of the v2_0 run
(results/23, config/v2_phase2.json) and of the v2_1 run (results/v2_1/23, config/v2_phase2_v2_1.json, whose manifest
carries the Amendment 1 choice); the seed-0 models of both step 22 runs (for SHAP only).

Configurations compared (weighting x dataset): the pre-registered weighting (sqrt) and the Amendment 1 choice c*, on
both datasets -- so the effect of the data (orientation) and of the weighting can be told apart. The v2_1 primary is
(v2_1, c*); the v2_0 primary was (v2_0, sqrt).
  - per-class recall / F1 (mean +- 95 % t-CI over seeds) for ROUTED and FLAT_GLOBAL (= GLOBAL of that weighting on
    every flow)
  - macro-F1 (all classes / non-rare), false alarms / hour (mean +- t-CI over seeds; seed 0 with Garwood CI)
  - ROUTED - FLAT_GLOBAL per seed (paired by seed), mean +- t-CI, for both macro-F1s and false alarms / hour
  - share of the port_scan (focus class) output's mean |SHAP| carried by FWD Init Win Bytes, per seed-0 model,
    computed exactly as step 25 does (its helpers; same per-class sample); cross-checked against the step 25 runs
Outputs: results/phase2_v2_1_compare/ (summary.md, run_manifest.json, run_meta.json, run.log, figures/*.png);
compare.json in ~/lgids_cache/v2/diag/<run_id>/.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import traceback
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from common import amendment as A  # noqa: E402
from common import phase2_data as D  # noqa: E402
from common import phase2_metrics as PM  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import config_from_arg  # noqa: E402

SCRIPT = "diagnostics/phase2_v2_1_compare.py"
STEP = "phase2_v2_1_compare"
IW = "FWD Init Win Bytes"
_spec = importlib.util.spec_from_file_location("s25", REPO / "25_explain_shap.py")
S25 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(S25)


def ci(vals, lvl):
    return PM.t_ci(list(vals), lvl)


def fmt(a, d=4):
    if a is None or not np.isfinite(a.get("mean", np.nan)):
        return "n/a"
    if not np.isfinite(a.get("lo", np.nan)):
        return f"{a['mean']:.{d}f}"
    return f"{a['mean']:.{d}f} [{a['lo']:.{d}f}, {a['hi']:.{d}f}]"


def entity_stats(Eps: dict, name: str, K: int, lvl: float) -> dict:
    """Mean +- t-CI over seeds of one entity's 'all' subset (metrics_per_seed.json of step 23)."""
    ps = Eps[name]["all"]
    seeds = sorted(ps, key=int)
    g = lambda k: [ps[s][k] for s in seeds]  # noqa: E731
    return {"seeds": seeds, "macro_f1_all": ci(g("macro_f1_all"), lvl), "macro_f1_nonrare": ci(g("macro_f1_nonrare"), lvl),
            "fa_per_hour": ci(g("fa_per_hour"), lvl), "fa_count": ci(g("fa_count"), lvl),
            "recall": [ci([ps[s]["recall"][c] for s in seeds], lvl) for c in range(K)],
            "f1": [ci([ps[s]["f1"][c] for s in seeds], lvl) for c in range(K)],
            "support": ps[seeds[0]]["support"], "rare_classes": ps[seeds[0]]["rare_classes"],
            "seed0_fa": {"count": ps[seeds[0]]["fa_count"], "per_hour": ps[seeds[0]]["fa_per_hour"],
                         "ci": ps[seeds[0]]["fa_per_hour_ci"], "hours": ps[seeds[0]]["benign_hours"]},
            "per_seed": {k: g(k) for k in ("macro_f1_all", "macro_f1_nonrare", "fa_per_hour", "fa_count")}}


def paired(a: dict, b: dict, lvl: float) -> dict:
    """a - b per seed (same seeds), mean +- t-CI."""
    out = {}
    for k in ("macro_f1_all", "macro_f1_nonrare", "fa_per_hour", "fa_count"):
        d = [x - y for x, y in zip(a["per_seed"][k], b["per_seed"][k])]
        out[k] = {**ci(d, lvl), "per_seed": d}
    return out


def shap_shares(cfg, up22, mids, A_id, feats, names, ctx) -> dict:
    """{model_id: {"share_IW_in_A": float, "top_A": [(feature, share)]}} recomputed like step 25 (seed-0 models)."""
    import xgboost as xgb
    c = cfg["columns"]
    va = D.load_split(cfg, "val", feats + [c["group"], c["label_id"]])
    y = va[c["label_id"]].to_numpy(np.int64)
    grp = va[c["group"]].astype(str).to_numpy()
    X = D.feature_matrix(va, feats)
    del va
    spec_of = {s["model_id"]: s for s in up22["manifest"]["specs"]}
    seed0 = cfg["seeds"][0]
    out, imps = {}, {}
    for mid in mids:
        m = next(x for x in up22["manifest"]["models"] if x["model_id"] == mid and x["seed"] == seed0)
        p = up22["dir"] / m["file"]
        if R.sha256_path(p) != m["sha256"]:
            raise RuntimeError(f"{p}: sha256 != step 22 manifest")
        b = xgb.Booster()
        b.load_model(str(p))
        kind, val = spec_of[mid]["subset"]
        rows = np.ones(len(y), bool) if kind == "all" else D.pooled_mask(y, grp == str(val))
        pos = np.flatnonzero(rows)
        pick = pos[S25.sample_per_class(y[pos], cfg["shap"]["shap_per_class"], seed0)]
        C, err = S25.tree_shap(b, X[pick])
        I = S25.importance(C)
        imps[mid] = I
        a = I[A_id]
        top = np.argsort(a)[::-1][:5]
        out[mid] = {"share_IW_in_A": float(a[feats.index(IW)] / a.sum()), "additivity_err": err,
                    "top_A": [(feats[j], float(a[j] / a.sum())) for j in top], "n_rows": int(len(pick))}
        ctx.log(f"  SHAP {cfg['dataset_version']} {mid}: {IW} share of {names[A_id]} output {out[mid]['share_IW_in_A']:.1%}")
    return out, imps


# --------------------------------------------------------------------------- figures
def fig_recall(path, rows: dict, names, title):
    """rows: {label: {"ROUTED": stats, "FLAT_GLOBAL": stats}}; one panel per system, dots +- CI, offsets per config."""
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    PS.apply()
    labels = list(rows)
    K = len(names)
    marks = ["o", "s", "D", "^"]
    fills = [False, False, True, True]
    off = np.linspace(-0.27, 0.27, len(labels))
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 0.85 * K + 1.9), sharey=True)
    for ax, sysn in zip(axes, ("ROUTED", "FLAT_GLOBAL")):
        for li, lab in enumerate(labels):
            st = rows[lab][sysn]
            for k in range(K):
                r = st["recall"][k]
                if not np.isfinite(r.get("mean", np.nan)):
                    continue
                y = k + off[li]
                lo, hi = r.get("lo", np.nan), r.get("hi", np.nan)
                if np.isfinite(lo):
                    ax.plot([max(lo, -0.02), min(hi, 1.02)], [y, y], color=PS.class_color(k), lw=1.2, alpha=0.7)
                ax.plot([r["mean"]], [y], marker=marks[li], ms=6.5, mew=1.4, ls="",
                        mfc=PS.class_color(k) if fills[li] else PS.SURFACE, mec=PS.class_color(k))
                ax.text(1.05, y, f"{r['mean']:.4f}", va="center", fontsize=6.3, color=PS.TEXT1 if fills[li] else PS.TEXT2)
        ax.set_yticks(range(K), names)
        ax.invert_yaxis()
        ax.set_xlim(-0.03, 1.22)
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_xlabel("recall (mean over 5 seeds, 95 % t-CI)")
        ax.set_title(sysn, loc="left", fontsize=9)
    h = [Line2D([], [], marker=marks[i], ls="", mfc=PS.TEXT2 if fills[i] else PS.SURFACE, mec=PS.TEXT1, label=lab)
         for i, lab in enumerate(labels)]
    fig.legend(handles=h, frameon=False, ncol=len(labels), loc="lower center", bbox_to_anchor=(0.5, -0.03), fontsize=7.5)
    fig.subplots_adjust(top=0.85, bottom=0.2, wspace=0.08)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_systems(path, rows: dict, title):
    """macro-F1 all / non-rare / FA per hour: ROUTED vs FLAT_GLOBAL per configuration (dots +- CI, labels offset)."""
    import matplotlib.pyplot as plt
    PS.apply()
    labels = list(rows)
    keys = [("macro_f1_all", "macro-F1, all classes"), ("macro_f1_nonrare", "macro-F1, non-rare classes"),
            ("fa_per_hour", "false alarms / hour")]
    sty = {"ROUTED": dict(color=PS.TEXT1, marker="o", dx=-0.14, dy=7, va="bottom"),
           "FLAT_GLOBAL": dict(color=PS.NEUTRAL_LIGHT, marker="s", dx=0.14, dy=-7, va="top")}
    ticks = [l.split(" (")[0].replace(", ", "\n") + ("\n(pre-registered)" if "pre-registered" in l else
                                                     "\n(Amendment 1)" if "Amendment" in l else "") for l in labels]
    fig, axes = plt.subplots(1, 3, figsize=(13.2, 4.0))
    for ax, (k, lab) in zip(axes, keys):
        for sysn, st in sty.items():                                    # ROUTED labels above, FLAT_GLOBAL below
            xs = np.arange(len(labels)) + st["dx"]
            for x, l in zip(xs, labels):
                a = rows[l][sysn][k]
                if np.isfinite(a.get("lo", np.nan)):
                    ax.plot([x, x], [a["lo"], a["hi"]], color=st["color"], lw=1.4)
                ax.plot([x], [a["mean"]], marker=st["marker"], color=st["color"], ms=7, ls="")
                ax.annotate(f"{a['mean']:.4f}" if k != "fa_per_hour" else f"{a['mean']:.2f}", (x, a["mean"]),
                            xytext=(0, st["dy"]), textcoords="offset points", fontsize=6.2, ha="center", va=st["va"],
                            color=PS.TEXT1 if sysn == "ROUTED" else PS.TEXT2,
                            bbox=dict(fc=PS.SURFACE, ec="none", pad=0.4, alpha=0.85))
            ax.plot([], [], marker=st["marker"], color=st["color"], ls="", label=sysn)
        ax.set_xticks(range(len(labels)), ticks, fontsize=6.8)
        ax.set_xlim(-0.6, len(labels) - 0.4)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_title(lab, loc="left", fontsize=9)
    axes[0].legend(frameon=False, fontsize=7.5, loc="lower left")
    fig.subplots_adjust(top=0.8, wspace=0.3)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_shap(path, shares: dict, title):
    """shares: {config label: {model short name: share}} -> grouped horizontal bars with direct labels."""
    import matplotlib.pyplot as plt
    PS.apply()
    labels = list(shares)
    models = sorted({m for v in shares.values() for m in v})
    shades = [PS.NEUTRAL_LIGHT, PS.TEXT2, PS.CATEGORICAL[2], PS.CATEGORICAL[0]]
    h = 0.8 / len(labels)
    fig, ax = plt.subplots(figsize=(7.6, 0.75 * len(models) * len(labels) * 0.45 + 1.6))
    for li, lab in enumerate(labels):
        ys = np.arange(len(models)) + (li - (len(labels) - 1) / 2) * h
        v = [100 * shares[lab].get(m, np.nan) for m in models]
        ax.barh(ys, np.nan_to_num(v), h * 0.92, color=shades[li % len(shades)], label=lab)
        for y, x in zip(ys, v):
            if np.isfinite(x):
                ax.text(x + 0.8, y, f"{x:.1f} %", va="center", fontsize=6.8, color=PS.TEXT1, zorder=4,
                        bbox=dict(fc=PS.SURFACE, ec="none", pad=0.3))
    ax.axvline(50, color=PS.TEXT2, lw=0.8, ls=":", zorder=1)
    ax.set_yticks(range(len(models)), models)
    ax.set_ylim(len(models) - 0.5, -0.85)                              # inverted, with headroom for the flag note
    ax.text(50.6, -0.68, "50 % dominance flag (prereg)", fontsize=6.5, color=PS.TEXT2, va="center")
    ax.set_xlim(0, 105)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_xlabel(f"share of the port_scan output's mean |SHAP| carried by {IW} (seed-0 model)")
    ax.legend(frameon=False, fontsize=7, loc="lower right")
    ax.set_title(title, loc="left", fontsize=9)
    PS.save(fig, path)


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config-v2-0", default=None, help="default config/v2_phase2.json")
    ap.add_argument("--config-v2-1", default=str(REPO / "config" / "v2_phase2_v2_1.json"))
    ap.add_argument("--class-a", default="port_scan", help="class whose SHAP share of FWD Init Win Bytes is reported")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None,
                    help="write to results/phase2_v2_1_compare/<tag>/ (a corrected rerun; earlier runs are kept)")
    args = ap.parse_args()
    c0, c1 = config_from_arg(args.config_v2_0), config_from_arg(args.config_v2_1)
    S.verify_v2_lock(strict=True)
    pins_before = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                     ("config/class_map.json", S.CLASS_MAP_PATH))}
    cm = S.load_class_map()
    names, K = list(cm.names), cm.n_classes
    feats = S.feature_columns()
    A_id = cm.id_of(args.class_a)
    lvl = c1["eval"]["ci_level"]
    up = {"v2_0": {s: R.resolve_run(s, None, False, R.results_root(c0)) for s in ("22", "23", "25")},
          "v2_1": {s: R.resolve_run(s, None, False, R.results_root(c1)) for s in ("22", "23", "25")}}
    cfgs = {"v2_0": c0, "v2_1": c1}
    ctx_cfg = {k: v for k, v in c1.items() if k != "_results_root"}      # results/phase2_v2_1_compare/ (top level)
    step = STEP
    if args.rerun_tag:
        from config.config import RESULTS_DIR
        ctx_cfg["_results_root"], step = str(RESULTS_DIR / STEP), args.rerun_tag
    ctx = R.start_run(step, "diag", SCRIPT, ctx_cfg, False, args.run_id)
    M = R.base_manifest(ctx, SCRIPT, ["25_explain_shap.py", "config/v2_phase2_v2_1.json"])
    M.update({"inputs": {d: {s: {"run_id": u["meta"]["run_id"], "manifest_sha256": u["manifest_sha256"]}
                             for s, u in v.items()} for d, v in up.items()},
              "read_only": "no model trained; val only; test never read", "pins_before": pins_before})
    ok, out = False, {}
    try:
        sel = up["v2_1"]["23"]["manifest"].get("primary_selection")
        if not sel:
            raise RuntimeError("the v2_1 step 23 run carries no Amendment 1 selection")
        cstar = sel["chosen"]
        prim_w = c1["class_weights"]["primary"]
        weights = [prim_w] + ([cstar] if cstar != prim_w else [])
        out["chosen"] = cstar
        Eps = {d: json.loads((up[d]["23"]["dir"] / "metrics_per_seed.json").read_text(encoding="utf-8")) for d in up}
        default = up["v2_0"]["22"]["manifest"]["routing"]["default"]
        rows, diffs = {}, {}
        for d in ("v2_0", "v2_1"):
            for w in weights:
                lab = f"{d}, {w}" + (" (pre-registered primary)" if (d, w) == ("v2_0", prim_w) else
                                     " (Amendment 1 primary)" if (d, w) == ("v2_1", cstar) else "")
                rn, fn = A.routed_name(c1, w), A.swap_weights(default, w)        # flat = GLOBAL of w on every flow
                rows[lab] = {"ROUTED": entity_stats(Eps[d], rn, K, lvl), "FLAT_GLOBAL": entity_stats(Eps[d], fn, K, lvl),
                             "routed_entity": rn, "flat_entity": fn}
                diffs[lab] = paired(rows[lab]["ROUTED"], rows[lab]["FLAT_GLOBAL"], lvl)
        # sanity: v2_1 chosen numbers == the step 23 summary aggregate of the chosen systems
        agg1 = json.loads((up["v2_1"]["23"]["dir"] / "metrics_summary.json").read_text(encoding="utf-8"))["entities"]
        lab1 = next(l for l in rows if l.startswith("v2_1, " + cstar))
        dd = abs(agg1[sel["chosen_routed_system"]]["all"]["macro_f1_nonrare"]["mean"] - rows[lab1]["ROUTED"]["macro_f1_nonrare"]["mean"])
        dd = max(dd, abs(agg1[sel["chosen_flat_system"]]["all"]["macro_f1_nonrare"]["mean"]
                         - rows[lab1]["FLAT_GLOBAL"]["macro_f1_nonrare"]["mean"]))
        R.add_check(ctx, M, "per-seed recomputation == step 23 aggregates (v2_1 chosen ROUTED / FLAT_GLOBAL)", dd < 1e-12,
                    f"max |diff| {dd:.2g}")
        out["rows"], out["diffs"] = rows, diffs
        # SHAP shares
        shares, checks = {}, []
        for d in ("v2_0", "v2_1"):
            sj = json.loads((up[d]["25"]["dir"] / "shap.json").read_text(encoding="utf-8"))
            for w in weights:
                mids = [A.swap_weights(m, w) for m in sorted(set(up[d]["22"]["manifest"]["routing"]["primary"].values()))]
                res, _ = shap_shares(cfgs[d], up[d]["22"], mids, A_id, feats, names, ctx)
                lab = f"{d}, {w}"
                shares[lab] = {m.rsplit("__", 1)[0]: r["share_IW_in_A"] for m, r in res.items()}
                out.setdefault("shap", {})[lab] = res
                for m in mids:                                           # cross-check against the step 25 run
                    key = f"{m}__s{cfgs[d]['seeds'][0]}"
                    if key in sj:
                        ref = sj[key]["mean_abs_shap"][names[A_id]]
                        tot = sum(ref.values())
                        checks.append(abs(ref[IW] / tot - res[m]["share_IW_in_A"]))
        R.add_check(ctx, M, "SHAP shares reproduce the step 25 runs for the models they covered", bool(checks) and max(checks) < 1e-5,
                    f"{len(checks)} models, max |diff| {max(checks) if checks else float('nan'):.2g}")
        out["shap_shares"] = shares
        R.write_json(ctx.partial / "compare.json", out)
        # figures
        fig_recall(ctx.fig / "per_class_recall_v2_0_vs_v2_1.png", rows, names,
                   "Per-class recall on val, v2_0_v1equiv vs v2_1_oriented (hollow = v2_0, filled = v2_1)")
        fig_systems(ctx.fig / "routed_vs_flat_macro_f1_and_false_alarms.png", rows,
                    "ROUTED vs FLAT_GLOBAL on val: macro-F1 and false alarms / hour (mean over 5 seeds, 95 % t-CI)")
        fig_shap(ctx.fig / "init_win_shap_share.png", shares,
                 f"{IW}: share of the {args.class_a} output's mean |SHAP|, v2_0 vs v2_1")
        M["figures"] = sorted(str(p.relative_to(ctx.res)) for p in ctx.fig.glob("*.png"))
        M["chosen"] = cstar
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                         ("config/class_map.json", S.CLASS_MAP_PATH))}
    R.add_check(ctx, M, "config.py / class_map.json unchanged", M["pins_after"] == pins_before, "")
    ok = ok and M["pins_after"] == pins_before
    M["status"] = "PASS" if ok else "FAIL"
    write_summary(ctx.res / "summary.md", M, out, names, args)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def write_summary(path, M, out, names, args) -> None:
    L = [f"# Phase 2: v2_0_v1equiv vs v2_1_oriented (val only) -- {M['status']}", "",
         f"- run `{M['run_id']}`; READ-ONLY; inputs: " + "; ".join(f"{d} 22 `{v['22']['run_id']}`, 23 `{v['23']['run_id']}`, "
                                                                  f"25 `{v['25']['run_id']}`" for d, v in M["inputs"].items()),
         "- FLAT_GLOBAL = GLOBAL of the same weighting on every flow; CIs: mean +- 95 % t-CI over the 5 seeds; ROUTED - "
         "FLAT_GLOBAL paired by seed."]
    if getattr(args, "rerun_tag", None):
        L.append(f"- **figure-fix rerun** (`--rerun-tag {args.rerun_tag}`): same inputs and numbers as the first run in "
                 "`results/phase2_v2_1_compare/` (kept, not overwritten), whose macro-F1 / false-alarm and SHAP figures had "
                 "overlapping labels.")
    L += [""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```"]
        path.write_text("\n".join(L) + "\n", encoding="utf-8")
        return
    L += [f"- Amendment 1 chose weighting **`{out['chosen']}`** on v2_1.", "", "## Systems", "",
          "| configuration | system | macro-F1 all | macro-F1 non-rare | false alarms / h | seed-0 FA / h [Garwood] |",
          "|---|---|---|---|---|---|"]
    for lab, r in out["rows"].items():
        for s in ("ROUTED", "FLAT_GLOBAL"):
            st = r[s]
            z = st["seed0_fa"]
            L.append(f"| {lab} | {s} (`{r['routed_entity'] if s == 'ROUTED' else r['flat_entity']}`) | {fmt(st['macro_f1_all'])} | "
                     f"{fmt(st['macro_f1_nonrare'])} | {fmt(st['fa_per_hour'], 3)} | {z['per_hour']:.3f} [{z['ci'][0]:.3f}, "
                     f"{z['ci'][1]:.3f}] ({z['count']} FP / {z['hours']:.3f} h) |")
    L += ["", "## ROUTED - FLAT_GLOBAL (paired by seed)", "",
          "| configuration | macro-F1 all | macro-F1 non-rare | false alarms / h | false alarms (count) |", "|---|---|---|---|---|"]
    for lab, d in out["diffs"].items():
        L.append(f"| {lab} | {fmt(d['macro_f1_all'], 5)} | {fmt(d['macro_f1_nonrare'], 5)} | {fmt(d['fa_per_hour'], 3)} | "
                 f"{fmt(d['fa_count'], 1)} |")
    L += ["", "## Per-class recall and F1", ""]
    for s in ("ROUTED", "FLAT_GLOBAL"):
        L += [f"### {s}", "", "| configuration | " + " | ".join(f"recall {n}" for n in names) + " | "
              + " | ".join(f"F1 {n}" for n in names) + " |", "|---|" + "---|" * (2 * len(names))]
        for lab, r in out["rows"].items():
            st = r[s]
            rare = set(st["rare_classes"])
            L.append(f"| {lab} | " + " | ".join(fmt(x) + (" (rare)" if c in rare else "") for c, x in enumerate(st["recall"]))
                     + " | " + " | ".join(fmt(x) for x in st["f1"]) + " |")
        L += [""]
    L += [f"## Scanner-fingerprint shortcut: share of the {args.class_a} output's mean |SHAP| carried by {IW}", "",
          "| configuration | " + " | ".join(sorted({m for v in out["shap_shares"].values() for m in v})) + " |",
          "|---|" + "---|" * len({m for v in out["shap_shares"].values() for m in v})]
    ms = sorted({m for v in out["shap_shares"].values() for m in v})
    for lab, v in out["shap_shares"].items():
        L.append(f"| {lab} | " + " | ".join(f"{100 * v[m]:.1f} %" if m in v else "-" for m in ms) + " |")
    L += ["", "Top-5 features of the port_scan output (seed-0 models):", ""]
    for lab, res in out["shap"].items():
        for m, r in res.items():
            L.append(f"- {lab} {m}: " + ", ".join(f"{f} {100 * s:.1f} %" for f, s in r["top_A"]))
    L += ["", "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M["checks"]]
    L += ["", "## Figures", "",
          "- `figures/per_class_recall_v2_0_vs_v2_1.png` -- per-class recall (mean, 95 % t-CI) of ROUTED and FLAT_GLOBAL "
          "for each weighting x dataset; hollow = v2_0, filled = v2_1.",
          "- `figures/routed_vs_flat_macro_f1_and_false_alarms.png` -- ROUTED vs FLAT_GLOBAL macro-F1 (all / non-rare) and "
          "false alarms / hour per weighting x dataset (mean, 95 % t-CI).",
          f"- `figures/init_win_shap_share.png` -- share of the {args.class_a} output's mean |SHAP| carried by {IW} per seed-0 "
          "model, per weighting x dataset (50 % = the prereg's dominance flag)."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
