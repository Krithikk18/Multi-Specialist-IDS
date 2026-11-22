#!/usr/bin/env python
"""43_shap_perturbation.py -- Phase 5B step F, Part B (docs/V2_PREREG_PHASE5B.md section 6): does TreeSHAP's ranking drive
the prediction? OFFLINE: val (+ train benign medians); nothing registered.

Models: GLOBAL seed 0 (= the deployed model; sha256 == the registry entry; deployed temperature from its registry
calibrator) and GLOBAL_CTX seed 0 (step 40; temperature fitted on its own inner split). Sample: per predicted
non-benign class up to per_class_cap val alerts + benign_cap benign predictions (seeded). Per flow: TreeSHAP of the
predicted class; perturb top-k / random-k (draws, outside the top-k) / bottom-k features to the train-benign median;
drop of the predicted class's calibrated probability and flip rate (common/shap_perturb.py). Verdict per predicted class
and model: FAITHFUL iff mean(top-k drop - random-k drop) has a 95 % bootstrap CI (over flows) lower bound > 0.
Report-only: |SHAP| mass on context vs flow features per class (GLOBAL_CTX); share of flows with a fingerprint feature in
the top-k. Disclosed: median replacement can create out-of-distribution rows; this describes the model, not the attack.
Outputs: results/phase5b/43/ (perturbation.json, summary.md, manifests).
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

import numpy as np

from common import context_config as CC
from common import phase5b_run as PR
from common import schemas as S
from common import shap_perturb as SP

SCRIPT = "43_shap_perturbation.py"


def load_booster(p: Path, sha: str):
    import xgboost as xgb
    if PR.sha256_path(p) != sha:
        raise RuntimeError(f"{p}: sha256 mismatch")
    b = xgb.Booster()
    b.load_model(str(p))
    return b


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    ap.add_argument("--dataset-run", default=None)
    ap.add_argument("--stage1-run", default=None)
    args = ap.parse_args()
    cfg = CC.load_phase5b_config()
    up39 = PR.resolve("39", args.dataset_run, args.dry_run)
    up40 = PR.resolve("40", args.stage1_run, args.dry_run)
    run = PR.P5BRun("43", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest()
    PR.lock_banner(run, M, "start")
    M.update({"dataset_run": up39["meta"]["run_id"], "stage1_run": up40["meta"]["run_id"]})
    ok = False
    try:
        cm = S.load_class_map()
        names, K = list(cm.names), cm.n_classes
        FL = CC.load_feature_list()
        ctxset = set(FL["context_features"])
        sh, ev, c = cfg["shap"], cfg["eval"], cfg["columns"]
        fp = set(cfg["stage1"]["fingerprint_features"])
        S40 = json.loads((up40["dir"] / "stage1.json").read_text(encoding="utf-8"))
        mdir = Path(up40["manifest"]["models_dir"])
        recs = {(m["arm"], int(m["seed"])): m for m in S40["models"]}
        s0 = int(sh["seed_model"])
        reg = CC.expand(cfg["paths"]["registry_root"]) / cfg["deployed"]["entry"]
        regM = json.loads((reg / "manifest.json").read_text(encoding="utf-8"))
        rg = recs[("GLOBAL", s0)]
        run.check(M, "GLOBAL seed-0 model == the deployed registry entry (sha256)", rg["sha256"] == regM["files"]["model.ubj"],
                  f"{rg['sha256'][:16]}...")
        if PR.sha256_path(reg / "calibrator.json") != regM["files"]["calibrator.json"]:
            raise RuntimeError("registry calibrator.json sha256 != entry manifest")
        T_dep = float(json.loads((reg / "calibrator.json").read_text(encoding="utf-8"))["temperature"])
        rc = recs[("GLOBAL_CTX", s0)]
        cal = json.loads((mdir / f"GLOBAL_CTX__s{s0}.temperature.json").read_text(encoding="utf-8"))
        if cal["model_sha256"] != rc["sha256"]:
            raise RuntimeError("GLOBAL_CTX temperature file does not belong to its model")
        models = {"GLOBAL": (load_booster(Path(rg["file"]), rg["sha256"]), T_dep, "deployed registry calibrator (val fit)"),
                  "GLOBAL_CTX": (load_booster(mdir / rc["file"], rc["sha256"]), float(cal["temperature"]), cal["fitted_on"])}
        tr = PR.load_ctx_split(up39, "train", FL["features"] + [c["label_id"]])
        tb = tr[c["label_id"]].to_numpy(np.int64) == 0
        med_all = np.median(tr.loc[tb, FL["features"]].to_numpy(np.float32), axis=0)
        del tr
        va = PR.load_ctx_split(up39, "val", FL["features"])
        Xall = va[FL["features"]].to_numpy(np.float32)
        del va
        colix = {f: i for i, f in enumerate(FL["features"])}
        OUT = {}
        for a in sh["models"]:
            b, T, T_src = models[a]
            feats = S40["features"][a]
            ix = [colix[f] for f in feats]
            X = np.ascontiguousarray(Xall[:, ix])
            med = med_all[ix]
            P = SP.proba(b, X, T)
            pred = P.argmax(1)
            pos = SP.sample(pred, K, sh["per_class_cap"], sh["benign_cap"], sh["sample_seed"])
            Xs, ps = X[pos], pred[pos]
            C = SP.tree_shap(b, Xs)
            import xgboost as xgb
            add_err = float(np.abs(C.sum(2) - b.predict(xgb.DMatrix(Xs), output_margin=True).reshape(len(Xs), -1)).max())
            phi = SP.class_phi(C, ps)
            top, bot, rnd = SP.select(phi, sh["k"], sh["random_draws"], sh["random_seed"])
            R = SP.perturbation(b, Xs, ps, T, med, top, bot, rnd)
            run.check(M, f"{a}: TreeSHAP additivity (sum of contributions == margin)", add_err < 1e-3, f"max error {add_err:.2e}")
            per = {}
            for k in sorted(set(ps.tolist())):
                m = ps == k
                V = SP.verdict(R["drop_top"][m] - R["drop_rand"][m], ev)
                absphi = np.abs(phi[m])
                ctx_mask = np.array([f in ctxset for f in feats])
                fp_mask = np.array([f in fp for f in feats])
                per[names[k]] = {
                    "n": int(m.sum()), "verdict": V["verdict"], "diff": V["diff"],
                    "drop_top": float(R["drop_top"][m].mean()), "drop_rand": float(R["drop_rand"][m].mean()),
                    "drop_bottom": float(R["drop_bottom"][m].mean()), "flip_top": float(R["flip_top"][m].mean()),
                    "flip_rand": float(R["flip_rand"][m].mean()), "flip_bottom": float(R["flip_bottom"][m].mean()),
                    "p0_mean": float(R["p0"][m].mean()),
                    "ctx_shap_share": float((absphi[:, ctx_mask].sum(1) / np.maximum(absphi.sum(1), 1e-300)).mean())
                    if ctx_mask.any() else 0.0,
                    "fingerprint_in_topk": float(fp_mask[top[m]].any(1).mean()),
                    "top_features": {feats[j]: int(n) for j, n in zip(*np.unique(top[m], return_counts=True))}}
                run.log(f"  {a:<11} pred {names[k]:<10} n {int(m.sum()):>5}: top drop {per[names[k]]['drop_top']:.4f}, random "
                        f"{per[names[k]]['drop_rand']:.4f}, bottom {per[names[k]]['drop_bottom']:.4f}; flips top "
                        f"{per[names[k]]['flip_top']:.3f} -> {V['verdict']} (d {V['diff']['mean']:.4f} [{V['diff']['lo']:.4f}, "
                        f"{V['diff']['hi']:.4f}]); ctx SHAP share {per[names[k]]['ctx_shap_share']:.3f}; fingerprint in top-k "
                        f"{per[names[k]]['fingerprint_in_topk']:.3f}")
            OUT[a] = {"temperature": T, "temperature_source": T_src, "n_sample": int(len(pos)), "additivity_max_error": add_err,
                      "argmax_consistent": R["argmax_consistent"], "per_class": per, "n_features": len(feats)}
        out = {"models": OUT, "k": sh["k"], "random_draws": sh["random_draws"], "names": names,
               "disclosure": "median replacement can create out-of-distribution rows; results describe the model, not the attack"}
        PR.write_json(run.res / "perturbation.json", out)
        M["verdicts"] = {a: {k: v["verdict"] for k, v in OUT[a]["per_class"].items()} for a in OUT}
        PR.lock_banner(run, M, "end")
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M)
    run.finish(ok, M)
    return 0 if ok else 1


def write_summary(run, M: dict) -> None:
    st = "PASS" if all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") and not M.get("error") else "FAIL"
    L = [f"# Step 43 -- Part B: TreeSHAP perturbation check -- {st}" + (" (DRY RUN)" if run.dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    p = run.res / "perturbation.json"
    if p.exists():
        O = json.loads(p.read_text(encoding="utf-8"))
        L += [f"- k = {O['k']}, random draws {O['random_draws']}; {O['disclosure']}", "",
              "| model | predicted class | n | drop top-k | drop random-k | drop bottom-k | top - random [95 % CI] | verdict | "
              "flip top / random / bottom | context SHAP share | fingerprint in top-k |", "|---" * 11 + "|"]
        for a, R in O["models"].items():
            for k, v in R["per_class"].items():
                d = v["diff"]
                L.append(f"| {a} | {k} | {v['n']:,} | {v['drop_top']:.4f} | {v['drop_rand']:.4f} | {v['drop_bottom']:.4f} | "
                         f"{d['mean']:.4f} [{d['lo']:.4f}, {d['hi']:.4f}] | {v['verdict']} | {v['flip_top']:.3f} / "
                         f"{v['flip_rand']:.3f} / {v['flip_bottom']:.3f} | {v['ctx_shap_share']:.3f} | {v['fingerprint_in_topk']:.3f} |")
        L += ["", "| model | temperature | source | sample | TreeSHAP additivity max error |", "|---|---|---|---|---|"]
        for a, R in O["models"].items():
            L.append(f"| {a} | {R['temperature']:.4f} | {R['temperature_source']} | {R['n_sample']:,} | {R['additivity_max_error']:.1e} |")
        L.append("")
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
