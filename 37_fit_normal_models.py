#!/usr/bin/env python
"""37_fit_normal_models.py -- Phase 5A step C (docs/V2_PREREG_PHASE5.md section 4): fit the models of normal.
OFFLINE: v2_1_oriented TRAIN benign rows only; never val labels, never test; nothing registered.

Arms x seeds (normal_model.seeds): GLOBAL_NORMAL, PER_GROUP_NORMAL (fallback below min_group_benign -> GLOBAL of the
same seed, logged), RANDOM_GROUP_NORMAL (report-only control: per-group rule on a seeded permutation of the group
labels). Input = the 70 pinned features, V1 NaN / +-inf -> 0 policy (counted), sign(x) log1p|x|. IsolationForest per
common/normal_model.py; threshold = 99.9th percentile of each model's scores on all its own training rows.
Report-only: threshold check (refit on a seeded 90 %, threshold there, flag rate on the held-out 10 % vs 0.1 %) and
determinism check (seed 0 of each arm refitted: identical scores).
Outputs: <cache>/normal/<run>/ (<arm>__s<seed>__<model key>.joblib, <arm>__s<seed>.train_scores.npy, train_groups.npy,
manifest.json with every file's sha256), results/phase5a/37/ (summary.md, normal_models.json, run_manifest.json,
run_meta.json, run.log). --dry-run: 5 % stratified train sample, seed 0 only.
"""

from __future__ import annotations

import argparse
import sys
import traceback

import numpy as np

from config.config import REPO_ROOT
from common import normal_model as NM
from common import phase2_data as D
from common import schemas as S
from common import zeroday_config as ZC
from common import zeroday_run as ZR
from common.phase2_config import load_phase2_config

SCRIPT = "37_fit_normal_models.py"


def owner_scores(A: dict, n: int) -> np.ndarray:
    """Each training row's score under the model that owns it in training (its fit group's, or the fallback global)."""
    out = np.full(n, np.nan)
    gk = A["models"].get(NM.GLOBAL_KEY)
    if A["arm"] == NM.GLOBAL:
        return A["models"][NM.GLOBAL_KEY]["train_scores"].copy()
    for grp, key in A["route"].items():
        ix = np.flatnonzero(A["fit_group"] == grp)
        if key == NM.GLOBAL_KEY:
            out[ix] = gk["train_scores"][ix]
        else:
            out[ix] = A["models"][key]["train_scores"]
    return out


def core(Z: np.ndarray, g: np.ndarray, cfg5: dict, seeds: list[int], log=print, save=None) -> dict:
    """The step's logic on the transformed train-benign matrix Z and its group labels g (the e2e test calls this)."""
    p, tc = cfg5["normal_model"], cfg5["threshold_check"]
    fits, recs, tchk = {}, [], {}
    for s in seeds:
        G = NM.fit_arm(NM.GLOBAL, Z, g, s, p)
        grec = G["models"][NM.GLOBAL_KEY]
        PG = NM.fit_arm(NM.PER_GROUP, Z, g, s, p, global_rec=grec)
        RG = NM.fit_arm(NM.RANDOM_GROUP, Z, g, s, p, global_rec=grec)
        for A in (G, PG, RG):
            fits[(A["arm"], s)] = A
            r = NM.summary_record(A)
            r["owner_flag_rate"] = float(np.mean(owner_scores(A, len(Z)) >
                                                 np.array([A["models"][A["route"][x]]["threshold"] for x in A["fit_group"]])))
            if save is not None:
                r.update(save(A, owner_scores(A, len(Z))))
            tchk[(A["arm"], s)] = NM.threshold_check(A, Z, s, p, tc)
            r["threshold_check"] = tchk[(A["arm"], s)]
            recs.append(r)
            desc = ", ".join("%s: n %s thr %.5f" % (k, format(m["n_train"], ","), m["threshold"])
                             for k, m in r["models"].items())
            log(f"  {A['arm']:<20} s{s}  models {desc}  fallback {A['fallback'] or '-'}  | 90/10 check: held-out flag "
                f"rate {r['threshold_check']['held_out_flag_rate']:.5f} (nominal {r['threshold_check']['nominal']:.4f})")
    # determinism: refit the first seed of each arm, scores must be identical
    s0 = seeds[0]
    det = {}
    G2 = NM.fit_arm(NM.GLOBAL, Z, g, s0, p)
    for arm in (NM.GLOBAL, NM.PER_GROUP, NM.RANDOM_GROUP):
        B = G2 if arm == NM.GLOBAL else NM.fit_arm(arm, Z, g, s0, p, global_rec=G2["models"][NM.GLOBAL_KEY])
        A = fits[(arm, s0)]
        same = {k: bool(np.array_equal(A["models"][k]["train_scores"], B["models"][k]["train_scores"])
                        and A["models"][k]["threshold"] == B["models"][k]["threshold"]) for k in A["models"]}
        det[arm] = {"seed": s0, "identical": all(same.values()), "per_model": same}
    return {"fits": fits, "records": recs, "determinism": det}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg5 = ZC.load_phase5_config()
    run = ZR.ZRun("37", SCRIPT, cfg5, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/phase2_config.py"])
    ZR.lock_banner(run, M, "start")
    ok = False
    try:
        import joblib
        import sklearn
        cm = S.load_class_map()
        feats = S.feature_columns()
        cfg2 = load_phase2_config(REPO_ROOT / cfg5["phase2_config"])
        p = cfg5["normal_model"]
        seeds = [0] if args.dry_run else p["seeds"]
        tr = D.load_split(cfg2, "train", feats + ["label_id", "group"], sample=args.dry_run)
        b = tr["label_id"].to_numpy(np.int64) == cm.id_of("benign")
        X = D.feature_matrix(tr.loc[b], feats)
        g = tr.loc[b, "group"].astype(str).to_numpy()
        del tr
        Z, nonfinite = NM.prepare(X, feats)
        del X
        gs, gn = np.unique(g, return_counts=True)
        M["data"] = {"dataset": cfg2["dataset_version"], "train_sha256": D.verify_split_file(cfg2, "train"),
                     "train_benign_rows": int(len(g)), "groups": {str(a): int(n) for a, n in zip(gs, gn)},
                     "nonfinite_before_cleaning": nonfinite, "cleaning": S.NAN_INF_POLICY,
                     "transform": "sign(x) * log1p(|x|)", "n_features": len(feats), "sample": args.dry_run, "seeds": seeds,
                     "sklearn": sklearn.__version__, "n_jobs": p["n_jobs"]}
        run.log(f"  train benign {len(g):,} rows, groups {M['data']['groups']}; non-finite values "
                f"{sum(v['nan'] + v['inf'] for v in nonfinite.values())} ({len(nonfinite)} features); sklearn {sklearn.__version__}")
        mdir = run.cache_dir("normal")
        np.save(mdir / "train_groups.npy", g.astype(str))
        files = {"train_groups.npy": ZR.sha256_path(mdir / "train_groups.npy")}

        def save(A, own):
            out = {"files": {}}
            for k, rec in A["models"].items():
                if k == NM.GLOBAL_KEY and A["arm"] != NM.GLOBAL:
                    out["files"][k] = {"file": f"{NM.GLOBAL}__s{A['seed']}__{NM.GLOBAL_KEY}.joblib", "fallback": True}
                    continue
                fn = f"{A['arm']}__s{A['seed']}__{k}.joblib"
                joblib.dump(rec["model"], mdir / fn)
                sha = ZR.sha256_path(mdir / fn)
                files[fn] = sha
                out["files"][k] = {"file": fn, "sha256": sha, "size_bytes": (mdir / fn).stat().st_size}
            fn = f"{A['arm']}__s{A['seed']}.train_scores.npy"
            np.save(mdir / fn, own)
            files[fn] = ZR.sha256_path(mdir / fn)
            out["train_scores_file"] = fn
            if A["arm"] == NM.RANDOM_GROUP:
                fn = f"{A['arm']}__s{A['seed']}.fit_groups.npy"
                np.save(mdir / fn, A["fit_group"].astype(str))
                files[fn] = ZR.sha256_path(mdir / fn)
                out["fit_groups_file"] = fn
            return out

        out = core(Z, g, cfg5, seeds, run.log, save)
        recs = out["records"]
        man = {"run_id": run.run_id, "dir": str(mdir), "files_sha256": files, "records": recs, "params": p,
               "threshold_check_params": cfg5["threshold_check"], "data": M["data"], "determinism": out["determinism"],
               "config_sha256": cfg5["_sha256"], "class_map_sha256": S.CLASS_MAP_SHA256,
               "features_file_sha256": S.FEATURES_V1_SHA256}
        man_sha = ZR.write_json(mdir / "manifest.json", man)
        M["models_dir"], M["models_manifest_sha256"] = str(mdir), man_sha
        M["records"], M["determinism"] = recs, out["determinism"]
        ZR.write_json(run.res / "normal_models.json", {**man, "manifest_sha256": man_sha})
        fb = {r["arm"]: r["fallback"] for r in recs}
        run.log(f"  fallbacks: {fb}")
        run.check(M, "every arm x seed fitted and saved", len(recs) == 3 * len(seeds), f"{len(recs)} arm x seed fits")
        run.check(M, "every model's in-sample flag rate == the nominal 1 - q (+- 1 row)",
                  all(abs(m["train_flag_rate"] - (1 - p["threshold_quantile"])) <= 1.0 / m["n_train"] + 1e-12
                      for r in recs for m in r["models"].values()),
                  "ties at the top of a model's scores would lower it (report-only)", warn=True)
        run.check(M, "determinism: seed-0 refit of every arm gives identical scores",
                  all(v["identical"] for v in out["determinism"].values()),
                  f"{ {a: v['identical'] for a, v in out['determinism'].items()} }")
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
    L = [f"# Step 37 -- models of normal (train benign only) -- {st}" + (" (DRY RUN)" if dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("data"):
        d = M["data"]
        L += [f"- train benign rows {d['train_benign_rows']:,}, groups {d['groups']}; non-finite before cleaning: "
              f"{d['nonfinite_before_cleaning'] or 'none'} ({d['cleaning']}); transform {d['transform']}; sklearn "
              f"{d['sklearn']}, n_jobs {d['n_jobs']}", ""]
    if M.get("records"):
        L += ["| arm | seed | model | n train benign | threshold | fit s | size KB | 90/10 held-out flag rate (n) |",
              "|---|---|---|---|---|---|---|---|"]
        for r in M["records"]:
            for k, m in r["models"].items():
                f = r["files"][k]
                tcm = r["threshold_check"]["per_model"].get(k)
                tcs = f"{tcm['held_out_flag_rate']:.5f} ({tcm['n_held_out']:,})" if tcm else "(fallback: see GLOBAL)"
                L.append(f"| {r['arm']} | {r['seed']} | {k} | {m['n_train']:,} | {m['threshold']:.5f} | {m['fit_seconds']:.2f} | "
                         f"{(f.get('size_bytes') or 0) / 1024:.0f} | {tcs} |")
        L += ["", "| arm | seed | fallback (group, n) | held-out flag rate pooled (nominal 0.001) |", "|---|---|---|---|"]
        for r in M["records"]:
            t = r["threshold_check"]
            L.append(f"| {r['arm']} | {r['seed']} | {r['fallback'] or '-'} | {t['held_out_flag_rate']:.5f} "
                     f"({t['held_out_flagged']} / {t['held_out_n']:,}) |")
        L.append("")
    if M.get("determinism"):
        L += [f"- determinism (seed-0 refit): {M['determinism']}", ""]
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
