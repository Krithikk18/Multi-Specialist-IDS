#!/usr/bin/env python
"""40_train_ctx_stage1.py -- Phase 5B step C (docs/V2_PREREG_PHASE5B.md section 3): Stage 1 arms on v2_2_context.
OFFLINE: train + val only; nothing registered; models under <cache>/stage1/<run>/.

Arms x seeds (Amendment 1 primary configuration via common/cl_retrain.fit: weights none, step 22 hyperparameters,
early stopping on a seeded 10 % inner split, fixed nthread): GLOBAL = the v2_1 step 22 GLOBAL__none models (reused,
sha256 checked; not retrained); GLOBAL_CTX (70 + 44), CTX_ONLY (44), GLOBAL_NOFP and GLOBAL_CTX_NOFP (minus the pinned
fingerprint features). Full val (argmax): per-class recall / F1, non-rare macro-F1, flow-level FA count and FA / h
(common/cl_gate.eval_set: Phases 3-4 benign hours), paired differences vs GLOBAL with 95 % percentile bootstrap CIs over
seeds; the same with ctx_warmup flows excluded (sensitivity); the pre-registered non-inferiority rule.
Outputs: <cache>/stage1/<run>/<arm>__s<seed>.ubj, .temperature.json, .pred.npy; results/phase5b/40/ (stage1.json,
summary.md, run_manifest.json, run_meta.json). --dry-run: needs --dataset-run (a dry step 39 run); seed 0 only.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback

import numpy as np

from config.config import REPO_ROOT
from common import cl_gate as CG
from common import cl_retrain as RT
from common import context_config as CC
from common import phase2_run as R2run
from common import phase5b_eval as EV
from common import phase5b_run as PR
from common import schemas as S
from common.phase2_config import load_phase2_config

SCRIPT = "40_train_ctx_stage1.py"


def arm_features(cfg: dict, FL: dict) -> dict:
    flow, ctx = list(S.feature_columns()), list(FL["context_features"])
    fp = list(cfg["stage1"]["fingerprint_features"])
    missing = [f for f in fp if f not in flow]
    if missing:
        raise RuntimeError(f"fingerprint features not in the flow feature list: {missing}")
    return {"GLOBAL": flow, "GLOBAL_CTX": flow + ctx, "CTX_ONLY": ctx,
            "GLOBAL_NOFP": [f for f in flow if f not in fp], "GLOBAL_CTX_NOFP": [f for f in flow + ctx if f not in fp]}


def global_models(cfg: dict, cfg2: dict) -> dict:
    up = R2run.resolve_run("22", cfg["deployed"]["train_run"], False, R2run.results_root(cfg2))
    rec = {m["seed"]: m for m in up["manifest"]["models"] if m["model_id"] == cfg["deployed"]["model_id"]}
    return {"dir": up["dir"], "run": up["meta"]["run_id"], "seeds": {s: (up["dir"] / r["file"], r["sha256"]) for s, r in rec.items()}}


def load_booster(path, sha):
    import xgboost as xgb
    if PR.sha256_path(path) != sha:
        raise RuntimeError(f"{path}: sha256 != manifest")
    b = xgb.Booster()
    b.load_model(str(path))
    return b


def summarise(E: dict, arms: list[str], seeds: list[int], K: int, names: list[str], ev: dict) -> dict:
    """E[(arm, s)] = eval_set dict. Per arm: mean + per-seed values; vs GLOBAL: paired bootstrap CIs."""
    out = {}
    for a in arms:
        es = [E[(a, s)] for s in seeds]
        rec = {"recall": {names[c]: [e["recall"][c] for e in es] for c in range(K)},
               "f1": {names[c]: [e["f1"][c] for e in es] for c in range(K)},
               "macro_f1_nonrare": [e["macro_f1_nonrare"] for e in es], "fa_count": [e["fa_count"] for e in es],
               "fa_per_hour": [e["fa_per_hour"] for e in es], "benign_hours": es[0]["benign_hours"],
               "support": {names[c]: es[0]["support"][c] for c in range(K)}}
        if a != "GLOBAL":
            g = [E[("GLOBAL", s)] for s in seeds]
            rec["vs_global"] = {
                "macro_f1_nonrare": EV.paired_ci([x["macro_f1_nonrare"] for x in g], rec["macro_f1_nonrare"], ev),
                "fa_count": EV.paired_ci([x["fa_count"] for x in g], rec["fa_count"], ev),
                "fa_per_hour": EV.paired_ci([x["fa_per_hour"] for x in g], rec["fa_per_hour"], ev),
                "recall": {names[c]: EV.paired_ci([x["recall"][c] for x in g], rec["recall"][names[c]], ev)
                           for c in range(K) if g[0]["support"][c] > 0}}
        out[a] = rec
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    ap.add_argument("--dataset-run", default=None, help="step 39 run id (default: the full run in results/phase5b/39/)")
    args = ap.parse_args()
    cfg = CC.load_phase5b_config()
    up39 = PR.resolve("39", args.dataset_run, args.dry_run)
    run = PR.P5BRun("40", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/phase2_config.py", "common/phase2_run.py"])
    PR.lock_banner(run, M, "start")
    M["dataset_run"] = up39["meta"]["run_id"]
    ok = False
    try:
        cm = S.load_class_map()
        names, K = list(cm.names), cm.n_classes
        FL = CC.load_feature_list()
        cfg2 = load_phase2_config(REPO_ROOT / cfg["phase2_config"])
        st, ev = cfg["stage1"], cfg["eval"]
        seeds = [0] if args.dry_run else st["seeds"]
        AF = arm_features(cfg, FL)
        c = cfg["columns"]
        wc = cfg["context"]["warmup_column"]
        meta = [c["label_id"], c["group"], c["session"], c["start"], c["row"], wc]
        tr = PR.load_ctx_split(up39, "train", FL["features"] + [c["label_id"]])
        Xtr = np.ascontiguousarray(tr[FL["features"]].to_numpy(np.float32))
        ytr = tr[c["label_id"]].to_numpy(np.int64)
        del tr
        va = PR.load_ctx_split(up39, "val", FL["features"] + meta)
        Xva = np.ascontiguousarray(va[FL["features"]].to_numpy(np.float32))
        yva = va[c["label_id"]].to_numpy(np.int64)
        sess = va[c["session"]].astype(str).to_numpy()
        ts = va[c["start"]].to_numpy(np.int64)
        warm = va[wc].to_numpy(np.int8) == 1
        uid = (va[c["session"]].astype(str) + ":" + va[c["row"]].astype(str)).tolist()
        del va
        col = {f: i for i, f in enumerate(FL["features"])}
        M["data"] = {"train_rows": int(len(ytr)), "val_rows": int(len(yva)), "val_warmup": int(warm.sum()),
                     "val_uid_sha256": PR.sha256_bytes("\n".join(uid).encode("utf-8")), "seeds": seeds}
        nonrare = CG.nonrare_classes(yva, K, ev["min_val_flows"])
        M["nonrare"] = [names[k] for k in nonrare]
        run.log(f"  train {len(ytr):,}, val {len(yva):,} (warm-up {int(warm.sum()):,}); non-rare {M['nonrare']}; arms "
                f"{ {a: len(f) for a, f in AF.items()} }")
        G = global_models(cfg, cfg2)
        mdir = run.cache_dir("stage1")
        gap = ev["benign_hours_idle_gap_s"]
        E, Ew, models = {}, {}, []
        for s in seeds:
            for a in st["arms"]:
                ix = [col[f] for f in AF[a]]
                Xv = np.ascontiguousarray(Xva[:, ix])
                if a in st["reused_arms"]:
                    p, sha = G["seeds"][s]
                    b = load_booster(p, sha)
                    rec = {"arm": a, "seed": s, "reused": True, "file": str(p), "sha256": sha, "n_features": len(ix)}
                else:
                    r = RT.fit(np.ascontiguousarray(Xtr[:, ix]), ytr, K, st["weights"], s, cfg2, st["nthread"])
                    b = r["booster"]
                    fn = f"{a}__s{s}.ubj"
                    b.save_model(str(mdir / fn))
                    cal = {"model_file": fn, "model_sha256": PR.sha256_path(mdir / fn), "temperature": r["temperature"],
                           "fitted_on": r["temperature_fitted_on"], "features": AF[a], "apply": "P = softmax(margin / T)"}
                    PR.write_json(mdir / f"{a}__s{s}.temperature.json", cal)
                    rec = {"arm": a, "seed": s, "reused": False, "file": fn, "sha256": cal["model_sha256"],
                           "temperature": r["temperature"], "best_iteration": r["best_iteration"],
                           "fit_seconds": r["fit_seconds"], "n_features": len(ix), "peak_rss_mb": r["peak_rss_mb"]}
                pred = RT.predict_proba(b, Xv, st["nthread"]).argmax(1).astype(np.int8)
                pf = f"{a}__s{s}.pred.npy"
                np.save(mdir / pf, pred)
                rec.update({"pred_file": pf, "pred_sha256": PR.sha256_path(mdir / pf)})
                E[(a, s)] = EV.eval_arm(yva, pred, K, nonrare, sess, ts, gap)
                Ew[(a, s)] = EV.eval_arm(yva[~warm], pred[~warm], K, nonrare, sess[~warm], ts[~warm], gap)
                models.append(rec)
                e = E[(a, s)]
                run.log(f"  {a:<16} s{s}  {len(ix):>3} feats  " + (f"fit {rec['fit_seconds']:6.1f} s  " if not rec["reused"] else "reused        ")
                        + "recall " + " ".join(f"{names[k]} {e['recall'][k]:.4f}" for k in range(K) if e["support"][k])
                        + f" | mF1nr {e['macro_f1_nonrare']:.5f} | FA {e['fa_count']} ({e['fa_per_hour']:.3f}/h)")
                del Xv, b
        arms = st["arms"]
        S1 = summarise(E, arms, seeds, K, names, ev)
        S1w = summarise(Ew, arms, seeds, K, names, ev)
        NI = EV.noninferiority(S1["GLOBAL_CTX"]["macro_f1_nonrare"], S1["GLOBAL"]["macro_f1_nonrare"],
                               S1["GLOBAL_CTX"]["fa_count"], S1["GLOBAL"]["fa_count"], cfg["noninferiority"], ev)
        NIw = EV.noninferiority(S1w["GLOBAL_CTX"]["macro_f1_nonrare"], S1w["GLOBAL"]["macro_f1_nonrare"],
                                S1w["GLOBAL_CTX"]["fa_count"], S1w["GLOBAL"]["fa_count"], cfg["noninferiority"], ev)
        run.log(f"  NON-INFERIORITY (GLOBAL_CTX vs GLOBAL): {NI['status']}  macro-F1 d {NI['macro_f1_diff']['mean']:+.5f} "
                f"[{NI['macro_f1_diff']['lo']:+.5f}, {NI['macro_f1_diff']['hi']:+.5f}]; FA count d median {NI['fa_count_diff_median']:+.1f}"
                f"  | warm-up excluded: {NIw['status']}")
        out = {"arms": arms, "features": AF, "seeds": seeds, "names": names, "nonrare": nonrare, "all": S1,
               "no_warmup": S1w, "noninferiority": NI, "noninferiority_no_warmup": NIw, "models": models,
               "models_dir": str(mdir), "global_run": G["run"], "data": M["data"]}
        PR.write_json(run.res / "stage1.json", out)
        M.update({"models": models, "models_dir": str(mdir), "noninferiority": NI["status"],
                  "noninferiority_no_warmup": NIw["status"]})
        run.check(M, "every arm x seed scored", len(models) == len(arms) * len(seeds), f"{len(models)}")
        PR.lock_banner(run, M, "end")
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M)
    run.finish(ok, M)
    return 0 if ok else 1


def _ci(c, f="{:+.4f}"):
    return f"{f.format(c['mean'])} [{f.format(c['lo'])}, {f.format(c['hi'])}]" if c and c.get("n") else "n/a"


def write_summary(run, M: dict) -> None:
    st = "PASS" if all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") and not M.get("error") else "FAIL"
    L = [f"# Step 40 -- Stage 1 arms on v2_2_context -- {st}" + (" (DRY RUN)" if run.dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    p = run.res / "stage1.json"
    if p.exists():
        O = json.loads(p.read_text(encoding="utf-8"))
        names = O["names"]
        for key, title in (("all", "all val flows"), ("no_warmup", "warm-up flows excluded (sensitivity)")):
            S1 = O[key]
            L += [f"## {title}", "", "| arm | " + " | ".join(f"recall {n}" for n in names) +
                  " | macro-F1 non-rare | FA count per seed | FA/h mean |", "|---" * (len(names) + 4) + "|"]
            for a in O["arms"]:
                r = S1[a]
                L.append(f"| {a} | " + " | ".join(f"{np.mean(r['recall'][n]):.4f}" if r["support"][n] else "n/a" for n in names)
                         + f" | {np.mean(r['macro_f1_nonrare']):.5f} | {r['fa_count']} | {np.mean(r['fa_per_hour']):.3f} |")
            L += ["", "| arm - GLOBAL | macro-F1 non-rare | FA count | FA/h | " + " | ".join(f"recall {n}" for n in names) + " |",
                  "|---" * (len(names) + 4) + "|"]
            for a in O["arms"]:
                if a == "GLOBAL":
                    continue
                v = S1[a]["vs_global"]
                L.append(f"| {a} | {_ci(v['macro_f1_nonrare'], '{:+.5f}')} | {_ci(v['fa_count'], '{:+.1f}')} | "
                         f"{_ci(v['fa_per_hour'], '{:+.3f}')} | " + " | ".join(_ci(v["recall"].get(n)) for n in names) + " |")
            L.append("")
        for key in ("noninferiority", "noninferiority_no_warmup"):
            N = O[key]
            L.append(f"- **{key}: {N['status']}** -- macro-F1 (GLOBAL_CTX - GLOBAL) {_ci(N['macro_f1_diff'], '{:+.5f}')} "
                     f"(needs lower bound > -{N['macro_f1_margin']}): {N['macro_f1_ok']}; FA-count differences "
                     f"{N['fa_count_diffs']}, median {N['fa_count_diff_median']:+.1f} (needs <= {N['fa_count_margin']}): {N['fa_ok']}")
        L.append("")
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
