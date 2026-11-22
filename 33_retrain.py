#!/usr/bin/env python
"""33_retrain.py -- Phase 4 steps D + E (docs/V2_PREREG_PHASE4.md sections 4-5, + the experiment arms of 9-11).
OFFLINE: the Pi never trains. TRAIN + VAL (val-A labelled flows only); never test.

D  replay buffer (common/replay_buffer.py): one fixed, seeded, class x group stratified sample of v2_1 train
   (25 % per stratum; all rows of a class with < 1,000 rows), written once with a manifest.
E  arms, 5 seeds each, Amendment 1 primary configuration (weights none, step 22 hyperparameters + early stopping on a
   10 % inner split of each arm's own training set), fixed thread count (config retrain.nthread):
     R1          GLOBAL full retrain: train + all valid val-A labels
     R2          warm start of the same-seed v2_1 GLOBAL (xgb_model, <= warm_start_rounds new trees): replay + labels
     R3          warm start, labels only
     S2_GLOBAL   GLOBAL full retrain: train + the S2 group's labels
     S2_<group>  that group's specialist full retrain: its original pooled training set + the group's labels
   experiment arms (never registered): R2 on P1 / P2 (poisoned: used anyway, explicitly), on the alerts-only batch
   (feedback bias) and on each operator sweep batch.
Labels are read only through common/label_store.load_batch (signature / hash refused otherwise) and re-validated here
(common/cl_validator.py); a QUARANTINED batch never enters a primary arm. R0 = the v2_1 models themselves (step 22 run,
sha256 checked). Per arm x seed: wall-clock fit time, peak RSS during the fit, best iteration, temperature (inner split).
Outputs: <cache>/replay/<run>/ (positions.npy, manifest.json), <cache>/models/<run>/<arm>__s<seed>.ubj +
.temperature.json; results/phase4/33/ summary.md, models.json, replay.json, run_manifest.json, run_meta.json, run.log.
--dry-run: 5 % train sample (Phase 2 rule), needs --labels-run <dry step 32 run id>.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import REPO_ROOT
from common import cl_config as CC
from common import cl_retrain as RT
from common import cl_run as CR
from common import cl_validator as CV
from common import label_store as LS
from common import phase2_data as D
from common import phase2_run as R2run
from common import replay_buffer as RB
from common import schemas as S
from common.phase2_config import load_phase2_config

SCRIPT = "33_retrain.py"
PRIMARY_ARMS = ("R1", "R2", "R3", "S2_GLOBAL", "S2_SPEC")


def base_models(cfg2: dict, cfg4: dict) -> dict:
    """The v2_1 step 22 models of the retrain weighting: {model_id: {"kind", "key", "seeds": {s: (path, sha256)}}}."""
    w = cfg4["retrain"]["weights"]
    up = R2run.resolve_run("22", cfg4["deployed"]["train_run"], False, R2run.results_root(cfg2))
    M22 = up["manifest"]
    out = {}
    for s in M22["specs"]:
        if s["weights"] != w or s["kind"] not in ("specialist", "global") or s["config"] not in ("primary", f"A1_{w}"):
            continue
        rec = {m["seed"]: m for m in M22["models"] if m["model_id"] == s["model_id"]}
        out[s["model_id"]] = {"kind": s["kind"], "key": s["key"], "subset": s["subset"],
                              "seeds": {sd: (up["dir"] / rec[sd]["file"], rec[sd]["sha256"]) for sd in rec}}
    return {"models": out, "run": up["meta"]["run_id"], "manifest_sha256": up["manifest_sha256"], "dir": str(up["dir"])}


def load_booster(path: Path, sha: str):
    import xgboost as xgb
    if CR.sha256_path(path) != sha:
        raise RuntimeError(f"{path}: sha256 != step 22 manifest")
    b = xgb.Booster()
    b.load_model(str(path))
    return b


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--labels-run", default=None, help="step 32 run id (default: the full run in results/phase4/32/)")
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg4 = CC.load_phase4_config()
    up32 = CR.resolve("32", args.labels_run, args.dry_run)
    up31 = CR.resolve("31", up32["manifest"]["queue_run"], args.dry_run)
    run = CR.Run("33", SCRIPT, cfg4, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["22_train_multiclass.py", "config/v2_phase2_v2_1.json"])
    CR.lock_banner(run, M, "start")
    M.update({"labels_run": up32["meta"]["run_id"], "queue_run": up31["meta"]["run_id"]})
    ok = False
    try:
        cm = S.load_class_map()
        names, K = list(cm.names), cm.n_classes
        feats = S.feature_columns()
        cfg2 = load_phase2_config(REPO_ROOT / cfg4["phase2_config"])
        rt = cfg4["retrain"]
        seeds = [0] if args.dry_run else rt["seeds"]
        nthread = rt["nthread"]
        # ---------------------------------------------------------------- base models (R0) + deployed check
        B = base_models(cfg2, cfg4)
        glob = [m for m, v in B["models"].items() if v["kind"] == "global"]
        run.check(M, "exactly one GLOBAL model of the retrain weighting in the step 22 run", len(glob) == 1, f"{glob}")
        gid = glob[0]
        reg = CC.expand(cfg4["paths"]["registry_root"]) / cfg4["deployed"]["entry"]
        dep = json.loads((reg / "manifest.json").read_text(encoding="utf-8"))
        run.check(M, "deployed entry model == step 22 GLOBAL seed 0 (sha256)",
                  dep["files"]["model.ubj"] == B["models"][gid]["seeds"][0][1] and dep["model_id"] == gid
                  and dep["model_id"] == cfg4["deployed"]["model_id"],
                  f"{dep['files']['model.ubj'][:16]}... == {B['models'][gid]['seeds'][0][1][:16]}...")
        grp_s2 = cfg4["s2"]["label_group"]
        spec = [m for m, v in B["models"].items() if v["kind"] == "specialist" and v["key"] == grp_s2]
        run.check(M, f"the S2 group {grp_s2!r} has a specialist in the step 22 run", len(spec) == 1, f"{spec}")
        sid = spec[0]
        M["base"] = {"train_run": B["run"], "manifest_sha256": B["manifest_sha256"], "global": gid, "s2_specialist": sid,
                     "models": {k: {"kind": v["kind"], "key": v["key"], "sha256": {s: v["seeds"][s][1] for s in v["seeds"]}}
                                for k, v in B["models"].items()}}
        # ---------------------------------------------------------------- data
        tr = D.load_split(cfg2, "train", feats + ["label_id", "group", "session", "row_in_file"], sample=args.dry_run)
        Xtr = D.feature_matrix(tr, feats)
        ytr = tr["label_id"].to_numpy(np.int64)
        gtr = tr["group"].astype(str).to_numpy()
        tr_uid = (tr["session"].astype(str) + ":" + tr["row_in_file"].astype(str)).to_numpy()
        del tr
        va = D.load_split(cfg2, "val", feats + ["label_id", "group", "session", "row_in_file"], sample=args.dry_run)
        va_uid = (va["session"].astype(str) + ":" + va["row_in_file"].astype(str)).to_numpy()
        va_pos = {u: i for i, u in enumerate(va_uid)}
        Xva = D.feature_matrix(va, feats)
        del va
        M["data"] = {"train_rows": int(len(ytr)), "train_sha256": D.verify_split_file(cfg2, "train"),
                     "val_sha256": D.verify_split_file(cfg2, "val")}
        # ---------------------------------------------------------------- D replay buffer
        rp = cfg4["replay"]
        Rb = RB.select(ytr, gtr, rp["frac"], rp["min_class_rows"], rp["seed"])
        rdir = run.cache_dir("replay")
        np.save(rdir / "positions.npy", Rb["pos"])
        uid_sha = CR.sha256_bytes("\n".join(tr_uid[Rb["pos"]].tolist()).encode("utf-8"))
        rman = {"n": int(len(Rb["pos"])), "of_train_rows": int(len(ytr)), "strata": [{**s, "class": names[s["class_id"]]}
                                                                                    for s in Rb["strata"]],
                "frac": Rb["frac"], "min_class_rows": Rb["min_class_rows"], "seed": Rb["seed"],
                "positions_sha256": Rb["pos_sha256"], "positions_file_sha256": CR.sha256_path(rdir / "positions.npy"),
                "uids_sha256": uid_sha, "train_file_sha256": M["data"]["train_sha256"], "dataset": cfg2["dataset_version"],
                "dir": str(rdir), "rule": RB.__doc__.split("Rule: ", 1)[1].split("\n\n")[0].replace("\n", " ")}
        rman_sha = CR.write_json(rdir / "manifest.json", rman)
        rman["manifest_sha256"] = rman_sha
        CR.write_json(run.res / "replay.json", rman)
        M["replay"] = {k: v for k, v in rman.items() if k != "strata"}
        run.log(f"  replay buffer: {rman['n']:,} of {len(ytr):,} train rows -> {rdir}")
        # ---------------------------------------------------------------- labels (signed store + validator)
        _, public = LS.ensure_operator_keys(CC.expand(cfg4["paths"]["operator_keys_dir"]), REPO_ROOT)
        q31 = up31["manifest"]["queues"]
        queues = {qid: pd.read_parquet(Path(q["dir"]) / "queue.parquet") for qid, q in q31.items()}
        for qid, q in q31.items():
            if CR.sha256_path(Path(q["dir"]) / "queue.parquet") != q["queue_parquet_sha256"]:
                raise RuntimeError(f"queue {qid}: parquet sha256 != manifest")
        b32 = json.loads((up32["dir"] / "batches.json").read_text(encoding="utf-8"))
        LBL = {}
        for name, b in b32.items():
            df, Mb = LS.load_batch(Path(b["root"]), b["batch_id"], public, names)       # refuses unsigned / tampered
            Q = queues[b["queue_id"]]
            V = CV.validate_batch(Path(b["root"]), b["batch_id"], public, names,
                                  {"flow_uid": Q["flow_uid"].tolist(), "pred": Q["pred"].to_numpy(np.int64),
                                   "pmax": Q["pmax"].to_numpy(np.float64)}, cfg4["validator"])
            qg = dict(zip(Q["flow_uid"], Q["group"].astype(str)))
            ix = np.array([va_pos.get(u, -1) for u in df["flow_uid"]], dtype=np.int64)
            if (ix < 0).any():
                raise RuntimeError(f"batch {b['batch_id']}: {int((ix < 0).sum())} labels for flows not in val")
            LBL[name] = {"X": Xva[ix], "y": df["label_id"].to_numpy(np.int64),
                         "group": np.array([qg[u] for u in df["flow_uid"]], dtype=object).astype(str),
                         "batch_id": b["batch_id"], "manifest_sha256": LS.manifest_sha256(Path(b["root"]), b["batch_id"]),
                         "parquet_sha256": Mb["files"]["labels.parquet"], "status": V["status"], "fired": V["fired"],
                         "n": int(len(df))}
            run.log(f"  labels {name}: {len(df):,} rows (signature OK), validator {V['status']} {V['fired'] or ''}")
        run.check(M, "primary batch is VALID (only valid batches enter the primary arms)", LBL["primary"]["status"] == CV.VALID,
                  f"{LBL['primary']['status']} {LBL['primary']['fired']}")
        if LBL["primary"]["status"] != CV.VALID:
            raise RuntimeError("primary label batch QUARANTINED: the primary arms cannot run (human review needed)")
        M["labels"] = {k: {kk: v[kk] for kk in ("batch_id", "manifest_sha256", "parquet_sha256", "status", "fired", "n")}
                       for k, v in LBL.items()}
        # ---------------------------------------------------------------- arms
        Lp = LBL["primary"]
        s2m = Lp["group"] == grp_s2
        spec_mask = D.pooled_mask(ytr, gtr == grp_s2)
        arms = {
            "R1": {"model_id": gid, "base": None, "parts": [("train", None), ("labels", "primary")], "batch": "primary"},
            "R2": {"model_id": gid, "base": gid, "parts": [("replay", None), ("labels", "primary")], "batch": "primary"},
            "R3": {"model_id": gid, "base": gid, "parts": [("labels", "primary")], "batch": "primary"},
            "S2_GLOBAL": {"model_id": gid, "base": None, "parts": [("train", None), ("labels_s2", "primary")], "batch": "primary"},
            "S2_SPEC": {"model_id": sid, "base": None, "parts": [("spec_train", None), ("labels_s2", "primary")],
                        "batch": "primary"},
        }
        for name in LBL:
            if name == "primary":
                continue
            arms[f"R2__{name}"] = {"model_id": gid, "base": gid, "parts": [("replay", None), ("labels", name)], "batch": name,
                                   "experiment": True, "used_anyway": LBL[name]["status"] != CV.VALID}
        M["arms"] = {a: {k: v for k, v in d.items()} for a, d in arms.items()}
        M["s2"] = {"label_group": grp_s2, "labels_in_group": int(s2m.sum()), "spec_model": sid,
                   "spec_train_rows": int(spec_mask.sum())}

        def assemble(a: dict):
            Xs, ys = [], []
            for kind, bname in a["parts"]:
                if kind == "train":
                    Xs.append(Xtr), ys.append(ytr)
                elif kind == "spec_train":
                    Xs.append(Xtr[spec_mask]), ys.append(ytr[spec_mask])
                elif kind == "replay":
                    Xs.append(Xtr[Rb["pos"]]), ys.append(ytr[Rb["pos"]])
                elif kind == "labels":
                    Xs.append(LBL[bname]["X"]), ys.append(LBL[bname]["y"])
                elif kind == "labels_s2":
                    m = LBL[bname]["group"] == grp_s2
                    Xs.append(LBL[bname]["X"][m]), ys.append(LBL[bname]["y"][m])
            return (np.ascontiguousarray(np.vstack(Xs)) if len(Xs) > 1 else Xs[0]), np.concatenate(ys)

        mdir = run.cache_dir("models")
        models = []
        for seed in seeds:                                             # seed-major: arms interleaved (fair timing)
            for an, a in arms.items():
                X, y = assemble(a)
                base = None
                if a["base"]:
                    p, sha = B["models"][a["base"]]["seeds"][seed]
                    base = load_booster(p, sha)
                    raw0 = bytes(base.save_raw("ubj"))
                r = RT.fit(X, y, K, rt["weights"], seed, cfg2, nthread, base=base,
                           rounds=rt["warm_start_rounds"] if base is not None else None,
                           temperature_bounds=rt["temperature_bounds"])
                if base is not None and bytes(base.save_raw("ubj")) != raw0:
                    raise RuntimeError(f"{an} s{seed}: the base booster was modified by the warm start")
                fname = f"{an}__s{seed}.ubj"
                r["booster"].save_model(str(mdir / fname))
                msha = CR.sha256_path(mdir / fname)
                cal = {"model_key": f"{an}__s{seed}", "model_file": fname, "model_sha256": msha, "train_run": run.run_id,
                       "method": "temperature", "temperature": r["temperature"], "fitted_on": r["temperature_fitted_on"],
                       "n": r["n_inner"], "class_map_sha256": S.CLASS_MAP_SHA256, "features_file_sha256": S.FEATURES_V1_SHA256,
                       "config_sha256": cfg4["_sha256"], "apply": "P = softmax(margin / temperature)"}
                CR.write_json(mdir / f"{an}__s{seed}.temperature.json", cal)
                rec = {"arm": an, "seed": seed, "model_id": a["model_id"], "kind": B["models"][a["model_id"]]["kind"],
                       "file": fname, "sha256": msha, "temperature": r["temperature"],
                       "base": ({"model_id": a["base"], "sha256": B["models"][a["base"]]["seeds"][seed][1]} if a["base"] else None),
                       "batch": a["batch"], "batch_id": LBL[a["batch"]]["batch_id"], "experiment": bool(a.get("experiment")),
                       "used_anyway": bool(a.get("used_anyway")),
                       **{k: r[k] for k in ("counts", "n_rows", "n_fit", "n_inner", "best_iteration", "best_score",
                                            "rounds_total", "base_rounds", "new_rounds", "fit_seconds", "peak_rss_mb",
                                            "rss_before_mb", "peak_rss_increase_mb", "peak_rss_method")}}
                models.append(rec)
                run.log(f"  {an:<22} s{seed}  rows {r['n_rows']:>8,}  trees {r['rounds_total']:>4} (+{r['new_rounds']})  "
                        f"{r['fit_seconds']:7.2f} s  peak {r['peak_rss_mb']:7.0f} MB (+{r['peak_rss_increase_mb']:.0f})  "
                        f"T {r['temperature']:.3f}" + ("  [QUARANTINED batch, used anyway]" if a.get("used_anyway") else ""))
                del X, y, r, base
        M["models"] = models
        M["models_dir"] = str(mdir)
        M["nthread"] = nthread
        CR.write_json(run.res / "models.json", models)
        run.check(M, "every arm x seed trained and saved", len(models) == len(arms) * len(seeds),
                  f"{len(models)} models ({len(arms)} arms x {len(seeds)} seeds)")
        run.check(M, "no QUARANTINED batch in a primary arm",
                  all(LBL[a["batch"]]["status"] == CV.VALID for an, a in arms.items() if not a.get("experiment")), "")
        CR.lock_banner(run, M, "end")
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def write_summary(run, M: dict, dry: bool) -> None:
    st = "PASS" if all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") and not M.get("error") else "FAIL"
    L = [f"# Step 33 -- replay buffer + retraining arms -- {st}" + (" (DRY RUN)" if dry else ""), "",
         f"- labels run `{M.get('labels_run')}`, queue run `{M.get('queue_run')}`; base models step 22 run "
         f"`{(M.get('base') or {}).get('train_run')}`; fixed nthread {M.get('nthread')}; offline only (the Pi never trains)", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("replay"):
        r = M["replay"]
        L += [f"- replay buffer: {r['n']:,} of {r['of_train_rows']:,} train rows (frac {r['frac']}, all rows of classes "
              f"< {r['min_class_rows']}), positions sha256 `{r['positions_sha256'][:16]}...`; strata in `replay.json`", ""]
    if M.get("labels"):
        L += ["| batch | labels | validator | used by |", "|---|---|---|---|"]
        for k, v in M["labels"].items():
            used = [a for a, d in M["arms"].items() if d["batch"] == k]
            L.append(f"| {v['batch_id']} | {v['n']:,} | {v['status']} {', '.join(v['fired'])} | {', '.join(used)} |")
        L.append("")
    if M.get("models"):
        L += ["## Arms x seeds", "", "| arm | seed | rows | trees (new) | fit s | peak RSS MB (+ over before) | T |",
              "|---|---|---|---|---|---|---|"]
        for m in M["models"]:
            L.append(f"| {m['arm']} | {m['seed']} | {m['n_rows']:,} | {m['rounds_total']} ({m['new_rounds']}) | "
                     f"{m['fit_seconds']:.2f} | {m['peak_rss_mb']:.0f} (+{m['peak_rss_increase_mb']:.0f}) | {m['temperature']:.3f} |")
        L.append("")
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
