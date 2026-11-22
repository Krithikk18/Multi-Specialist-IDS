#!/usr/bin/env python
"""36_loao_stage1.py -- Phase 5A step B (docs/V2_PREREG_PHASE5.md section 3): leave-one-attack-out Stage 1 retrains.
OFFLINE: train + val only; never test; no registry entry; the runtime is not touched.

For every attack class k of the class map x seed in loao.seeds: retrain Stage 1 GLOBAL without class k (the promoted
configuration: weights none, step 22 hyperparameters, early stopping on a seeded 10 % inner split, fixed nthread;
common/loao.fit_without), predict full val (argmax, back to class-map ids), and record where the val k flows went
(Stage 1 misses = predicted benign; caught = predicted as another attack) and the model's benign recall + FA / h.
Classes with < loao.rare_min_val_flows val flows are rare: retrained and reported, report-only for the verdict.
Control (report-only): the same code without removing a class (seed control_full_refit_seed) vs the step 22
GLOBAL seed-0 model (= the deployed registry entry, sha256 checked): model bytes and val argmax agreement.
Outputs: <cache>/loao/<run>/ (k<id>__s<seed>.ubj, k<id>__s<seed>.pred.npy), results/phase5a/36/ (summary.md,
loao.json, run_manifest.json, run_meta.json, run.log). --dry-run: 5 % stratified train / val samples, seed 0 only.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import traceback

import numpy as np

from config.config import REPO_ROOT
from common import loao as L
from common import phase2_data as D
from common import phase2_metrics as PM
from common import phase2_run as R2run
from common import schemas as S
from common import zeroday_config as ZC
from common import zeroday_run as ZR
from common.phase2_config import load_phase2_config

SCRIPT = "36_loao_stage1.py"
MIN_FREE_GB = 10.0


def core(Xtr, ytr, Xva, yva, sess, ts, names: list[str], cfg5: dict, cfg2: dict, seeds: list[int], log=print,
         save=None) -> dict:
    """The step's logic on arrays (the e2e test calls this). save(k, s, fit_result, pred) persists one pair."""
    K = len(names)
    lo, ev = cfg5["loao"], cfg5["eval"]
    nonrare, rare = L.heldout_classes(yva, K, lo["rare_min_val_flows"])
    hours = PM.benign_hours(np.asarray(sess).astype(str), np.asarray(ts, np.int64), np.asarray(yva) == 0,
                            ev["benign_hours_idle_gap_s"])
    pairs, preds = [], {}
    for k in nonrare + rare:
        for s in seeds:
            r = L.fit_without(Xtr, ytr, K, k, s, cfg2, lo["nthread"], lo["weights"])
            pred = L.predict_global(r["booster"], Xva, r["keep"], lo["nthread"])
            o = L.outcome(yva, pred, k, names)
            san = L.benign_sanity(yva, pred, sess, ts, ev["benign_hours_idle_gap_s"], hours=hours)
            rec = {"k": int(k), "class": names[k], "s": int(s), "rare": k in rare, **o, "sanity": san,
                   "train_rows": int(len(ytr) - r["n_removed"]), "removed_rows": r["n_removed"],
                   "train_counts": {names[c]: n for c, n in r["train_counts_global"].items()},
                   "keep": r["keep"].tolist(), "best_iteration": r["best_iteration"], "fit_seconds": r["fit_seconds"],
                   "peak_rss_mb": r["peak_rss_mb"]}
            if save is not None:
                rec.update(save(k, s, r, pred))
            pairs.append(rec)
            preds[(int(k), int(s))] = pred
            log(f"  k={names[k]:<10} s{s}  train {rec['train_rows']:>8,} (-{r['n_removed']:,})  trees {r['best_iteration'] + 1:>3}"
                f"  {r['fit_seconds']:6.1f} s | val k {o['n_val']:>7,}: miss {o['misses']:>7,} ({o['miss_share']:.4f})"
                f"  caught {o['caught']:>7,} {o['caught_as']} | benign recall {san['benign_recall']:.5f}"
                f"  FA {san['fa_count']} ({san['fa_per_hour']:.3f}/h)" + ("  [rare: report-only]" if k in rare else ""))
    return {"nonrare": nonrare, "rare": rare, "benign_hours": float(hours), "pairs": pairs, "preds": preds,
            "val_support": {names[c]: int((np.asarray(yva) == c).sum()) for c in range(K)}}


def deployed_global(cfg2: dict, cfg5: dict) -> dict:
    """The step 22 GLOBAL model of the deployed weighting, seed 0, and the registry entry's model sha256."""
    up = R2run.resolve_run("22", cfg5["deployed"]["train_run"], False, R2run.results_root(cfg2))
    M22 = up["manifest"]
    mid = cfg5["deployed"]["model_id"]
    rec = [m for m in M22["models"] if m["model_id"] == mid and m["seed"] == 0]
    if len(rec) != 1:
        raise RuntimeError(f"step 22 run {up['meta']['run_id']}: {len(rec)} records for {mid} seed 0")
    reg = ZC.expand(cfg5["paths"]["registry_root"]) / cfg5["deployed"]["entry"] / "manifest.json"
    dep = json.loads(reg.read_text(encoding="utf-8"))
    return {"path": up["dir"] / rec[0]["file"], "sha256": rec[0]["sha256"], "registry_sha256": dep["files"]["model.ubj"],
            "registry_model_id": dep["model_id"], "train_run": up["meta"]["run_id"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg5 = ZC.load_phase5_config()
    run = ZR.ZRun("36", SCRIPT, cfg5, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/phase2_config.py", "common/phase2_run.py", "22_train_multiclass.py"])
    ZR.lock_banner(run, M, "start")
    ok = False
    try:
        free = shutil.disk_usage(run.cache).free / 1e9
        run.check(M, f"free space on the cache filesystem >= {MIN_FREE_GB:.0f} GB", free >= MIN_FREE_GB, f"{free:,.1f} GB")
        if free < MIN_FREE_GB:
            raise RuntimeError("not enough free space")
        cm = S.load_class_map()
        names = list(cm.names)
        feats = S.feature_columns()
        cfg2 = load_phase2_config(REPO_ROOT / cfg5["phase2_config"])
        lo = cfg5["loao"]
        seeds = [0] if args.dry_run else lo["seeds"]
        tr = D.load_split(cfg2, "train", feats + ["label_id", "group"], sample=args.dry_run)   # group: dry-run strata
        Xtr = D.feature_matrix(tr, feats)
        ytr = tr["label_id"].to_numpy(np.int64)
        del tr
        va = D.load_split(cfg2, "val", feats + ["label_id", "group", "session", "row_in_file", "start_ts"], sample=args.dry_run)
        Xva = D.feature_matrix(va, feats)
        yva = va["label_id"].to_numpy(np.int64)
        sess = va["session"].astype(str).to_numpy()
        ts = va["start_ts"].to_numpy(np.int64)
        uid = (va["session"].astype(str) + ":" + va["row_in_file"].astype(str)).tolist()
        del va
        M["data"] = {"dataset": cfg2["dataset_version"], "train_rows": int(len(ytr)), "val_rows": int(len(yva)),
                     "train_sha256": D.verify_split_file(cfg2, "train"), "val_sha256": D.verify_split_file(cfg2, "val"),
                     "val_uid_sha256": ZR.sha256_bytes("\n".join(uid).encode("utf-8")),
                     "sample": args.dry_run, "seeds": seeds}
        run.log(f"  train {len(ytr):,} rows, val {len(yva):,} rows; seeds {seeds}; nthread {lo['nthread']}")
        mdir = run.cache_dir("loao")

        def save(k, s, r, pred):
            stem = f"k{k}__s{s}"
            r["booster"].save_model(str(mdir / f"{stem}.ubj"))
            np.save(mdir / f"{stem}.pred.npy", pred.astype(np.int8))
            return {"model_file": f"{stem}.ubj", "model_sha256": ZR.sha256_path(mdir / f"{stem}.ubj"),
                    "pred_file": f"{stem}.pred.npy", "pred_sha256": ZR.sha256_path(mdir / f"{stem}.pred.npy")}

        out = core(Xtr, ytr, Xva, yva, sess, ts, names, cfg5, cfg2, seeds, run.log, save)
        M["classes"] = {"nonrare": [names[c] for c in out["nonrare"]], "rare": [names[c] for c in out["rare"]],
                        "nonrare_ids": out["nonrare"], "rare_ids": out["rare"], "val_support": out["val_support"],
                        "rare_rule": f"< {lo['rare_min_val_flows']} val flows (Phase 2 rule): report-only"}
        M["benign_hours"] = out["benign_hours"]
        M["pairs"] = out["pairs"]
        M["dir"] = str(mdir)
        run.check(M, "at least one non-rare held-out class", len(out["nonrare"]) >= 1, f"{M['classes']['nonrare']}")
        run.check(M, "every class x seed retrained and saved",
                  len(out["pairs"]) == (len(out["nonrare"]) + len(out["rare"])) * len(seeds), f"{len(out['pairs'])} pairs")
        run.check(M, "held-out class absent from every training set",
                  all(p["class"] not in p["train_counts"] for p in out["pairs"]), "")
        bad = [(p["class"], p["s"], p["sanity"]["benign_recall"]) for p in out["pairs"] if p["sanity"]["benign_recall"] < 0.99]
        run.check(M, "LOAO benign recall >= 0.99 on val (removing k does not break benign)", not bad, f"{bad or 'all'}",
                  warn=True)
        # ---------------------------------------------------------------- control: same code, no class removed
        if args.dry_run:
            M["control"] = {"skipped": "dry run (5 % sample is not the step 22 training set)"}
        else:
            from common import cl_retrain as RT
            import xgboost as xgb
            dg = deployed_global(cfg2, cfg5)
            run.check(M, "step 22 GLOBAL seed 0 == deployed registry entry (sha256)",
                      dg["sha256"] == dg["registry_sha256"] and dg["registry_model_id"] == cfg5["deployed"]["model_id"]
                      and ZR.sha256_path(dg["path"]) == dg["sha256"], f"{dg['sha256'][:16]}...")
            cs = lo["control_full_refit_seed"]
            rc = RT.fit(Xtr, ytr, len(names), lo["weights"], cs, cfg2, lo["nthread"])
            raw = bytes(rc["booster"].save_raw("ubj"))
            b0 = xgb.Booster()
            b0.load_model(str(dg["path"]))
            p_ref = RT.predict_proba(b0, Xva, lo["nthread"]).argmax(1)
            p_new = RT.predict_proba(rc["booster"], Xva, lo["nthread"]).argmax(1)
            agree = float((p_ref == p_new).mean())
            M["control"] = {"seed": cs, "refit_sha256": ZR.sha256_bytes(raw), "step22_sha256": dg["sha256"],
                            "bytes_identical": ZR.sha256_bytes(raw) == ZR.sha256_bytes(bytes(b0.save_raw("ubj"))),
                            "val_argmax_agreement": agree, "val_disagreements": int((p_ref != p_new).sum()),
                            "best_iteration": rc["best_iteration"], "step22_rounds": int(b0.num_boosted_rounds()),
                            "fit_seconds": rc["fit_seconds"]}
            run.check(M, "control: full refit reproduces the deployed model's val predictions (report-only)",
                      agree == 1.0, f"agreement {agree:.6f}, bytes identical {M['control']['bytes_identical']}", warn=True)
        ZC_json = {"classes": M["classes"], "benign_hours": M["benign_hours"], "pairs": M["pairs"],
                   "control": M["control"], "dir": M["dir"], "data": M["data"]}
        ZR.write_json(run.res / "loao.json", ZC_json)
        ZR.lock_banner(run, M, "end")
        ok = all(c["pass"] for c in M["checks"] if c["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def write_summary(run, M: dict, dry: bool) -> None:
    st = "PASS" if all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") and not M.get("error") else "FAIL"
    L_ = [f"# Step 36 -- leave-one-attack-out Stage 1 retrains -- {st}" + (" (DRY RUN)" if dry else ""), "",
          "Offline; train + val only; nothing registered. Stage 1 miss = a val flow of the held-out class predicted "
          "benign; caught = predicted as another attack class (still alerts).", ""]
    if M.get("error"):
        L_ += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("classes"):
        c = M["classes"]
        L_ += [f"- held-out classes (verdict): {', '.join(c['nonrare']) or 'none'}; rare (report-only): "
               f"{', '.join(c['rare']) or 'none'} ({c['rare_rule']})", f"- val support: {c['val_support']}",
               f"- val benign hours: {M['benign_hours']:.3f}", ""]
    if M.get("pairs"):
        L_ += ["| held out | seed | train rows (removed) | trees | fit s | val k flows | misses (share) | caught (as) | "
               "benign recall | Stage 1 FA (FA/h) |", "|---|---|---|---|---|---|---|---|---|---|"]
        for p in M["pairs"]:
            L_.append(f"| {p['class']}{' (rare)' if p['rare'] else ''} | {p['s']} | {p['train_rows']:,} ({p['removed_rows']:,}) | "
                      f"{p['best_iteration'] + 1} | {p['fit_seconds']:.1f} | {p['n_val']:,} | {p['misses']:,} "
                      f"({p['miss_share']:.4f}) | {p['caught']:,} {p['caught_as']} | {p['sanity']['benign_recall']:.5f} | "
                      f"{p['sanity']['fa_count']} ({p['sanity']['fa_per_hour']:.3f}) |")
        L_.append("")
    if M.get("control"):
        L_ += [f"- control (report-only): {M['control']}", ""]
    L_ += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                               f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L_) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
