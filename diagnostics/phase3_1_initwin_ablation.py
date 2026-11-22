#!/usr/bin/env python
"""diagnostics/phase3_1_initwin_ablation.py -- Phase 3.1 PART C (REPORT-ONLY): the Init Win shortcut ablation.

Rule (fixed before any number; written at the top of summary.md before training): with the dropped columns (default
FWD Init Win Bytes, Bwd Init Win Bytes) removed, the model is "shortcut-DEPENDENT" iff the focus class's (default
port_scan) recall drops by more than 0.02 (5-seed mean of the paired per-seed difference) AND the paired-by-seed 95 %
t-CI of that difference lies entirely below 0; otherwise "shortcut-CONVENIENT" (an alternative signal exists).

Model: FLAT_GLOBAL exactly as the Amendment 1 primary on v2_1_oriented (step 22's own train_one, weights `none`, the
config's xgb params / inner split / early stopping, seeds 0-4), with the dropped columns removed at train and predict
time only (config/features_v1.json unchanged). Baseline: step 22's own GLOBAL__none boosters (run of results/v2_1/22,
sha256 checked), scored by the same code; must reproduce step 23's FLAT_GLOBAL_A1_none numbers (hard check).
Metrics: step 23's evaluate_entity (per-class recall / F1, macro-F1 all / non-rare, flow-level false alarms / h).
SHAP: step 25's helpers (sample_per_class, tree_shap, importance) on the seed-0 models: the focus class output's
mean |SHAP| share by feature, before vs after.
Outputs: results/phase3_1/initwin_ablation/ (summary.md, ablation.json, run_manifest.json, run_meta.json, run.log,
figures/); models under ~/lgids_cache/v2/ablations/<run_id>/ only (no registry entry).
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase2_data as D  # noqa: E402
from common import phase2_metrics as PM  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402

SCRIPT = "diagnostics/phase3_1_initwin_ablation.py"
DROP_MIN = 0.02


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pins() -> dict:
    return {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH), ("config/class_map.json", S.CLASS_MAP_PATH))}


def rule_text(drop: list, cls: str) -> str:
    return (f"## Rule (fixed before any number)\n\nWith {' and '.join(drop)} removed, the model is **shortcut-DEPENDENT** iff "
            f"{cls} recall drops by more than {DROP_MIN} (5-seed mean of the paired per-seed difference) AND the "
            f"paired-by-seed 95 % t-CI of that difference lies entirely below 0. Otherwise it is **shortcut-CONVENIENT** "
            "(an alternative signal exists).\n\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--drop", nargs="+", default=["FWD Init Win Bytes", "Bwd Init Win Bytes"])
    ap.add_argument("--class-a", default="port_scan")
    ap.add_argument("--weights", default="none", help="the Amendment 1 primary weighting (step 23's choice)")
    ap.add_argument("--replot", action="store_true", help="re-draw the figures of the full run from its ablation.json "
                    "into new *_fixed.png files (nothing else is computed or written)")
    args = ap.parse_args()
    if args.replot:
        return replot(args)
    cfg = load_phase2_config(REPO_ROOT / "config" / "v2_phase2_v2_1.json")
    up_root = R.results_root(cfg)
    cfg["_results_root"] = str(RESULTS_DIR / "phase3_1")
    S.verify_v2_lock(strict=True)
    p0 = pins()
    m22 = _load("train22_ro", "22_train_multiclass.py")
    m23 = _load("eval23_ro", "23_evaluate.py")
    m25 = _load("shap25_ro", "25_explain_shap.py")
    cm = S.load_class_map()
    names, K = list(cm.names), cm.n_classes
    A = cm.id_of(args.class_a)
    ctx = R.start_run("initwin_ablation", "ablations", SCRIPT, cfg, args.dry_run, args.run_id)
    ctx.log(f"  [start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    (ctx.res / "summary.md").write_text(f"# Phase 3.1 part C -- Init Win shortcut ablation (report-only) -- RUNNING\n\n"
                                        + rule_text(args.drop, args.class_a), encoding="utf-8")
    M = R.base_manifest(ctx, SCRIPT, ["22_train_multiclass.py", "23_evaluate.py", "25_explain_shap.py"])
    M.update({"pins_before": p0, "report_only": True, "dropped": args.drop, "class_a": args.class_a, "weights": args.weights,
              "rule": {"drop_min": DROP_MIN, "ci": "paired-by-seed t-CI entirely below 0"}})
    ok, out = False, {}
    try:
        feats = S.feature_columns()
        miss = [f for f in args.drop if f not in feats]
        if miss:
            raise RuntimeError(f"--drop columns not in the feature list: {miss}")
        keep = [f for f in feats if f not in args.drop]
        c = cfg["columns"]
        up22 = R.resolve_run("22", None, False, up_root)
        up23 = R.resolve_run("23", None, False, up_root)
        M["baseline_runs"] = {"22": up22["meta"]["run_id"], "23": up23["meta"]["run_id"]}
        sel = up23["manifest"]["primary_selection"]["chosen"]
        R.add_check(ctx, M, "baseline weighting == step 23's Amendment 1 choice", sel == args.weights, f"{sel}")
        tr = D.load_split(cfg, "train", feats + [c["group"], c["label_id"]], sample=args.dry_run)
        Xtr = D.feature_matrix(tr, keep)
        ytr = tr[c["label_id"]].to_numpy(np.int64)
        del tr
        va = D.load_split(cfg, "val", feats + [c["group"], c["label_id"], c["session"], c["start_ts"]], sample=args.dry_run)
        Xfull = D.feature_matrix(va, feats)
        Xva = D.feature_matrix(va, keep)
        y = va[c["label_id"]].to_numpy(np.int64)
        sess, ts = va[c["session"]].astype(str).to_numpy(), va[c["start_ts"]].to_numpy(np.int64)
        del va
        M["inputs"] = {s: D.verify_split_file(cfg, s) for s in ("train", "val")} | {"test_read": False}
        gap = cfg["eval"]["benign_hours_idle_gap_s"]
        cache: dict = {}

        def hours_fn(rows):
            k = hash(rows.tobytes())
            if k not in cache:
                cache[k] = PM.benign_hours(sess, ts, rows, gap)
            return cache[k]

        import xgboost as xgb
        base_id = f"GLOBAL__{args.weights}"
        Pb, Pa, models = {}, {}, {}
        for seed in cfg["seeds"]:
            m = next(x for x in up22["manifest"]["models"] if x["model_id"] == base_id and x["seed"] == seed)
            p = up22["dir"] / m["file"]
            if R.sha256_path(p) != m["sha256"]:
                raise RuntimeError(f"{p}: sha256 != step 22 manifest")
            b = xgb.Booster()
            b.load_model(str(p))
            Pb[seed] = b.predict(xgb.DMatrix(Xfull))
            r = m22.train_one(Xtr, ytr, K, args.weights, seed, cfg)
            f = ctx.partial / f"FLAT_GLOBAL__{args.weights}__no_initwin__s{seed}.ubj"
            r["booster"].save_model(str(f))
            models[seed] = {"file": f.name, "sha256": R.sha256_path(f), "best_iteration": r["best_iteration"],
                            "rounds_run": r["rounds_run"], "fit_seconds": r["fit_seconds"]}
            Pa[seed] = r["booster"].predict(xgb.DMatrix(Xva))
            ctx.log(f"  seed {seed}: ablated model best iteration {r['best_iteration']} ({r['fit_seconds']} s)")
        M["models"] = models
        subsets = {"all": np.ones(len(y), bool)}
        Eb = m23.evaluate_entity(y, Pb, np.ones(len(y), bool), subsets, hours_fn, K, cfg)["all"]
        Ea = m23.evaluate_entity(y, Pa, np.ones(len(y), bool), subsets, hours_fn, K, cfg)["all"]
        if not args.dry_run:
            ref = __import__("json").loads((up_root / "23" / "metrics_summary.json").read_text(encoding="utf-8"))
            ra = ref["entities"][f"FLAT_GLOBAL_A1_{args.weights}"]["all"]
            same = (Eb["aggregate"]["fa_counts_per_seed"] == ra["fa_counts_per_seed"]
                    and np.allclose([r["mean"] for r in Eb["aggregate"]["recall"]], [r["mean"] for r in ra["recall"]], atol=1e-12)
                    and abs(Eb["aggregate"]["macro_f1_nonrare"]["mean"] - ra["macro_f1_nonrare"]["mean"]) < 1e-12)
            R.add_check(ctx, M, f"baseline reproduces step 23 FLAT_GLOBAL_A1_{args.weights} (FA counts per seed, mean recall, "
                        "mean non-rare macro-F1)", bool(same), f"FA {Eb['aggregate']['fa_counts_per_seed']} vs {ra['fa_counts_per_seed']}")
        lvl = cfg["eval"]["ci_level"]
        seeds = sorted(Pb)

        def per(E, key, k=None):
            return [E["per_seed"][s][key] if k is None else E["per_seed"][s][key][k] for s in seeds]

        def paired(key, k=None):
            d = [a - b for a, b in zip(per(Ea, key, k), per(Eb, key, k))]
            return {**PM.t_ci(d, lvl), "per_seed": d}

        cmp_ = {"recall": [{"base": PM.t_ci(per(Eb, "recall", k), lvl), "abl": PM.t_ci(per(Ea, "recall", k), lvl),
                            "diff": paired("recall", k)} for k in range(K)],
                "f1": [{"base": PM.t_ci(per(Eb, "f1", k), lvl), "abl": PM.t_ci(per(Ea, "f1", k), lvl),
                        "diff": paired("f1", k)} for k in range(K)]}
        for key in ("macro_f1_all", "macro_f1_nonrare", "fa_per_hour", "fa_count"):
            cmp_[key] = {"base": PM.t_ci(per(Eb, key), lvl), "abl": PM.t_ci(per(Ea, key), lvl), "diff": paired(key)}
        cmp_["support"] = Eb["aggregate"]["support"]
        cmp_["rare_classes"] = Eb["aggregate"]["rare_classes"]
        dA = cmp_["recall"][A]["diff"]
        dep = (dA["mean"] < -DROP_MIN) and np.isfinite(dA["hi"]) and dA["hi"] < 0
        out["verdict"] = {"verdict": "shortcut-DEPENDENT" if dep else "shortcut-CONVENIENT",
                          "focus_recall_diff": dA, "drop_min": DROP_MIN}
        out["compare"] = cmp_
        # SHAP (seed-0 models; step 25's helpers and sample)
        s0 = cfg["seeds"][0]
        pick = m25.sample_per_class(y, cfg["shap"]["shap_per_class"], s0)
        b0 = xgb.Booster()
        b0.load_model(str(up22["dir"] / next(x for x in up22["manifest"]["models"]
                                             if x["model_id"] == base_id and x["seed"] == s0)["file"]))
        a0 = xgb.Booster()
        a0.load_model(str(ctx.partial / models[s0]["file"]))
        sh = {}
        for lab, bst, X_, fl in (("with Init Win (v2_1 primary)", b0, Xfull, feats), ("without Init Win", a0, Xva, keep)):
            C, err = m25.tree_shap(bst, X_[pick])
            I = m25.importance(C)[A]
            share = I / I.sum()
            order = np.argsort(share)[::-1]
            sh[lab] = {"additivity_err": err, "n_rows": int(len(pick)),
                       "shares": {fl[j]: float(share[j]) for j in order}, "top10": [(fl[j], float(share[j])) for j in order[:10]]}
        out["shap"] = sh
        R.write_json(ctx.partial / "ablation.json", out)
        R.write_json(ctx.res / "ablation.json", out)
        figs = [fig_recall(ctx.fig / "recall_with_without_initwin.png", cmp_, names, args.drop),
                fig_shap(ctx.fig / "shap_share_before_after.png", sh, args.class_a, args.drop)]
        M["figures"] = [str(Path(f).relative_to(ctx.res)) for f in figs]
        M["verdict"] = out["verdict"]["verdict"]
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = pins()
    R.add_check(ctx, M, "config.py / class_map.json unchanged", M["pins_after"] == p0, str(M["pins_after"]))
    ctx.log(f"  [end] config.py {M['pins_after']['config/config.py']}; class_map.json {M['pins_after']['config/class_map.json']}")
    ok = ok and all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    write_summary(ctx.res / "summary.md", M, out, names, args, ok)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def _f(a, d=4):
    return f"{a['mean']:.{d}f} [{a['lo']:.{d}f}, {a['hi']:.{d}f}]" if np.isfinite(a.get("lo", np.nan)) else f"{a['mean']:.{d}f}"


def write_summary(path, M, out, names, args, ok) -> None:
    L = [f"# Phase 3.1 part C -- Init Win shortcut ablation (report-only) -- {'PASS' if ok else 'FAIL'}"
         + (" (DRY RUN)" if M["dry_run"] else ""), "", rule_text(args.drop, args.class_a).rstrip(), "",
         f"- FLAT_GLOBAL, weights `{args.weights}` (Amendment 1 primary), v2_1_oriented, seeds {M['seeds']}; dropped at train "
         f"and predict time only: {args.drop}; baseline = step 22 run `{(M.get('baseline_runs') or {}).get('22')}` GLOBAL "
         f"boosters scored by the same code; models in the ablations cache only (no registry entry).", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```"]
    if out.get("verdict"):
        v = out["verdict"]
        L += [f"## VERDICT: **{v['verdict']}**", "",
              f"- {args.class_a} recall change (ablated - baseline, paired by seed): {_f(v['focus_recall_diff'])} "
              f"(per seed {[round(x, 5) for x in v['focus_recall_diff']['per_seed']]})", ""]
        C = out["compare"]
        L += ["## Per class (5-seed mean [95 % t-CI]; diff paired by seed)", "",
              "| class | support | recall with | recall without | diff | F1 with | F1 without | diff |", "|---|---|---|---|---|---|---|---|"]
        for k, n in enumerate(names):
            L.append(f"| {n}{' (rare)' if k in C['rare_classes'] else ''} | {C['support'][k]:,} | {_f(C['recall'][k]['base'])} | "
                     f"{_f(C['recall'][k]['abl'])} | {_f(C['recall'][k]['diff'])} | {_f(C['f1'][k]['base'])} | "
                     f"{_f(C['f1'][k]['abl'])} | {_f(C['f1'][k]['diff'])} |")
        L += ["", "| measure | with Init Win | without | diff (paired) |", "|---|---|---|---|"]
        for key, lab in (("macro_f1_nonrare", "macro-F1 non-rare"), ("macro_f1_all", "macro-F1 all"),
                         ("fa_per_hour", "flow-level false alarms / h"), ("fa_count", "false-alarm count")):
            L.append(f"| {lab} | {_f(C[key]['base'])} | {_f(C[key]['abl'])} | {_f(C[key]['diff'])} |")
        L += ["", f"## {args.class_a} output: share of mean |SHAP| (seed-0 models, step 25's sample)", ""]
        for lab, s in out["shap"].items():
            L.append(f"- {lab}: " + ", ".join(f"{f} {100 * v:.1f} %" for f, v in s["top10"]))
    L += ["", "## Figures", "", "- `figures/recall_with_without_initwin.png`", "- `figures/shap_share_before_after.png`", "",
          "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M["checks"]]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def replot(args) -> int:
    """Figure fix (D-log): re-draw from the full run's ablation.json; new file names, originals kept."""
    import json
    S.verify_v2_lock(strict=True)
    p0 = pins()
    print(f"[start] verify_v2_lock OK; {p0}")
    res = RESULTS_DIR / "phase3_1" / "initwin_ablation"
    out = json.loads((res / "ablation.json").read_text(encoding="utf-8"))
    names = list(S.load_class_map().names)
    f = fig_recall(res / "figures" / "recall_with_without_initwin_fixed.png", out["compare"], names, args.drop)
    p1 = pins()
    print(f"[end] wrote {f}; {p1}")
    return 0 if p0 == p1 else 1


def fig_recall(path, C, names, drop):
    import matplotlib.pyplot as plt
    PS.apply()
    K = len(names)
    fig, ax = plt.subplots(figsize=(7.4, 0.7 * K + 1.4))
    for k in range(K):
        for off, key, col, mk, lab in ((-0.14, "base", PS.TEXT2, "o", "with Init Win"),
                                       (0.14, "abl", PS.CATEGORICAL[4], "s", "without Init Win")):
            a = C["recall"][k][key]
            lo, hi = (a["lo"], a["hi"]) if np.isfinite(a.get("lo", np.nan)) else (a["mean"], a["mean"])
            ax.errorbar(a["mean"], k + off, xerr=[[a["mean"] - lo], [hi - a["mean"]]], fmt=mk, color=col, ms=6, capsize=2,
                        label=lab if k == 0 else None)
            ax.annotate(f"{a['mean']:.4f}", (max(hi, a["mean"]), k + off), textcoords="offset points", xytext=(6, 0),
                        va="center", fontsize=6.5, color=PS.TEXT1)
    ax.set_yticks(range(K), names)
    ax.invert_yaxis()
    ax.set_xlim(ax.get_xlim()[0], 1.035)
    ax.set_xlabel("recall (val, 5-seed mean +- 95 % t-CI; value labels right of the CI)")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7.5, loc="lower left")
    ax.set_title(f"Per-class recall with vs without {' + '.join(drop)} (FLAT_GLOBAL, v2_1)", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_shap(path, sh, cls, drop):
    import matplotlib.pyplot as plt
    PS.apply()
    labs = list(sh)
    feats = []
    for lab in labs:
        for f, _ in sh[lab]["top10"]:
            if f not in feats:
                feats.append(f)
    fig, ax = plt.subplots(figsize=(8.0, 0.36 * len(feats) + 1.4))
    y = np.arange(len(feats))
    for j, (lab, col) in enumerate(zip(labs, (PS.TEXT2, PS.CATEGORICAL[0]))):
        v = [100 * sh[lab]["shares"].get(f, 0.0) if f in sh[lab]["shares"] else np.nan for f in feats]
        ax.barh(y + (j - 0.5) * 0.4, np.nan_to_num(v), 0.38, color=col, label=lab)
        for yy, vv, f in zip(y, v, feats):
            txt = "dropped" if f not in sh[lab]["shares"] else f"{vv:.1f} %"
            ax.text((0 if np.isnan(vv) else vv) + 0.5, yy + (j - 0.5) * 0.4, txt, va="center", fontsize=6.5, color=PS.TEXT1)
    ax.set_yticks(y, feats, fontsize=7.5)
    ax.invert_yaxis()
    ax.set_xlabel(f"share of the {cls} output's mean |SHAP| (seed-0 model)")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_xlim(0, max(100 * max(max(s["shares"].values()) for s in sh.values()) * 1.18, 5))
    ax.legend(frameon=False, fontsize=7.5, loc="lower right")
    ax.set_title(f"{cls}: SHAP share by feature before vs after dropping {' + '.join(drop)} (top 10 of each)", loc="left",
                 fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


if __name__ == "__main__":
    sys.exit(main())
