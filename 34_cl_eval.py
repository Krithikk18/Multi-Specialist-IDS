#!/usr/bin/env python
"""34_cl_eval.py -- Phase 4 steps F + G evaluation (docs/V2_PREREG_PHASE4.md sections 6-10). VAL-B only (never test).

Scores every model on the val-B rows (v2_1_oriented, argmax of step 23's predict path), then
  gate          common/cl_gate.gate per arm x seed vs the deployed configuration (v2_1 FLAT_GLOBAL, same seed):
                (i) non-rare recall drop <= 0.01, (ii) non-rare macro-F1 drop <= 0.002, (iii) FA/h rise <= 0.5
  metrics       per arm: per-class recall / F1, macro-F1 (all, non-rare), FA/h; 5-seed means, paired t-CIs vs R0
  forgetting    S1 per class (F1 R0 - arm); S2 non-rare macro-F1 drop on the groups without labels (S2_GLOBAL vs v2_1
                FLAT_GLOBAL, S2_SPEC's ROUTED system vs v2_1 ROUTED); affected-group macro-F1; retrain time / memory
  verdict       Amendment 2 section 4 (common/cl_gate.verdict_a2s4), with the zero-by-construction proof (S2_SPEC's
                predictions on the other groups' rows == v2_1 ROUTED's, every seed)
  poisoning     P1 / P2: validator result + R2-on-it through the gate -> CAUGHT_BY_VALIDATOR / CAUGHT_BY_GATE / NOT_CAUGHT
  feedback bias val-A misses labelled with vs without the random sample; val-B recall of those miss classes
  registry      gate-passing SEED-0 models of the primary arms -> signed CANDIDATE entries (existing registry + key;
                nothing approved or promoted; the promoted entry's files and state log are checked unchanged);
                every gate-failing arm x seed -> REJECTED (reason logged)
Outputs: <cache>/rejected/<run>/rejected.jsonl; registry entries; results/phase4/34/ summary.md, eval.json, gate.json,
verdict.json, registry.json, rejected.json, run_manifest.json, run_meta.json, run.log. --dry-run: needs --retrain-run
<dry step 33 run id>; registers into the *_dry_run registry.
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
from common import cl_gate as CG
from common import cl_retrain as RT
from common import cl_run as CR
from common import phase2_data as D
from common import phase2_metrics as PM
from common import predictions_io as PIO
from common import registry as REG
from common import schemas as S
from common.phase2_config import load_phase2_config

SCRIPT = "34_cl_eval.py"
PRIMARY = ("R1", "R2", "R3", "S2_GLOBAL", "S2_SPEC")


def booster(path: Path, sha: str, nthread: int):
    import xgboost as xgb
    if CR.sha256_path(path) != sha:
        raise RuntimeError(f"{path}: sha256 != manifest")
    b = xgb.Booster()
    b.load_model(str(path))
    b.set_param({"nthread": int(nthread)})
    return b


def agg(vals: list, level: float) -> dict:
    t = PM.t_ci(vals, level)
    return {"mean": t["mean"], "lo": t["lo"], "hi": t["hi"], "values": [float(v) for v in vals]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--retrain-run", default=None, help="step 33 run id (default: the full run in results/phase4/33/)")
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg4 = CC.load_phase4_config()
    up33 = CR.resolve("33", args.retrain_run, args.dry_run)
    up32 = CR.resolve("32", up33["manifest"]["labels_run"], args.dry_run)
    up31 = CR.resolve("31", up33["manifest"]["queue_run"], args.dry_run)
    run = CR.Run("34", SCRIPT, cfg4, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/predictions_io.py"])
    CR.lock_banner(run, M, "start")
    M.update({"retrain_run": up33["meta"]["run_id"], "labels_run": up32["meta"]["run_id"], "queue_run": up31["meta"]["run_id"]})
    ok = False
    try:
        cm = S.load_class_map()
        names, K = list(cm.names), cm.n_classes
        feats = S.feature_columns()
        cfg2 = load_phase2_config(REPO_ROOT / cfg4["phase2_config"])
        lvl, gap = cfg4["eval"]["ci_level"], cfg4["eval"]["benign_hours_idle_gap_s"]
        nth = cfg4["retrain"]["nthread"]
        M33 = up33["manifest"]
        seeds = sorted({m["seed"] for m in M33["models"]})
        grp_s2 = M33["s2"]["label_group"]
        # ---------------------------------------------------------------- val-B rows
        sp = up31["manifest"]["split"]
        spq = pd.read_parquet(Path(sp["dir"]) / "split.parquet")
        run.check(M, "split parquet sha256 == step 31 manifest", CR.sha256_path(Path(sp["dir"]) / "split.parquet") ==
                  sp["split_parquet_sha256"], "")
        va = D.load_split(cfg2, "val", feats + ["label_id", "group", "session", "row_in_file", "start_ts"], sample=args.dry_run)
        uid = (va["session"].astype(str) + ":" + va["row_in_file"].astype(str)).to_numpy()
        part = dict(zip(spq["flow_uid"], spq["part"]))
        B = np.array([part[u] == "val_B" for u in uid])
        run.check(M, "every val row has a split part", len(part) == len(uid), f"{len(part):,} / {len(uid):,}")
        XB = D.feature_matrix(va.loc[B], feats)
        yB = va["label_id"].to_numpy(np.int64)[B]
        gB = va["group"].astype(str).to_numpy()[B]
        sB = va["session"].astype(str).to_numpy()[B]
        tB = va["start_ts"].to_numpy(np.int64)[B]
        uB = uid[B]
        groups = sorted(set(gB.tolist()))
        nonrare = CG.nonrare_classes(yB, K, cfg4["gate"]["min_val_flows"])
        M["val_B"] = {"n": int(len(yB)), "support": {names[k]: int((yB == k).sum()) for k in range(K)},
                      "nonrare": [names[k] for k in nonrare], "groups": groups}
        subsets = {"all": np.ones(len(yB), bool), **{f"group:{g}": gB == g for g in groups},
                   "other_groups": gB != grp_s2, "affected_group": gB == grp_s2}
        sub_nonrare = {k: CG.nonrare_classes(yB[m], K, cfg4["gate"]["min_val_flows"]) for k, m in subsets.items()}
        # ---------------------------------------------------------------- systems -> predictions on val-B
        base = M33["base"]
        b22 = {mid: v for mid, v in base["models"].items()}
        up22_dir = Path(json.loads((REPO_ROOT / "results/v2_1/22/run_meta.json").read_text(encoding="utf-8"))["cache_dir"])
        m22 = json.loads((up22_dir / "run_manifest.json").read_text(encoding="utf-8"))
        file22 = {(m["model_id"], m["seed"]): m["file"] for m in m22["models"]}
        run.check(M, "step 22 run dir is the run 33 used", m22["run_id"] == base["train_run"], f"{m22['run_id']}")
        gid = base["global"]
        spec_by_group = {v["key"]: mid for mid, v in b22.items() if v["kind"] == "specialist"}

        def v21(mid, s):
            return booster(up22_dir / file22[(mid, s)], b22[mid]["sha256"][str(s)] if str(s) in b22[mid]["sha256"]
                           else b22[mid]["sha256"][s], nth)

        mdir = Path(M33["models_dir"])
        arm_models = {(m["arm"], m["seed"]): m for m in M33["models"]}
        arms = sorted({m["arm"] for m in M33["models"]}, key=lambda a: (a not in PRIMARY, PRIMARY.index(a) if a in PRIMARY else 0, a))
        pred, E = {}, {}
        for s in seeds:
            g0 = v21(gid, s)
            specs = {g: v21(mid, s) for g, mid in spec_by_group.items()}
            pred[("R0", s)] = RT.predict_proba(g0, XB).argmax(1)
            pred[("ROUTED_v21", s)] = RT.routed_proba(specs, g0, XB, gB).argmax(1)
            for a in arms:
                m = arm_models[(a, s)]
                b = booster(mdir / m["file"], m["sha256"], nth)
                if a == "S2_SPEC":
                    pred[(a, s)] = RT.routed_proba({**specs, grp_s2: b}, g0, XB, gB).argmax(1)
                else:
                    pred[(a, s)] = RT.predict_proba(b, XB).argmax(1)
        systems = ["R0", "ROUTED_v21"] + arms
        for sysname in systems:
            for s in seeds:
                for sub, msk in subsets.items():
                    E[(sysname, s, sub)] = CG.eval_set(yB[msk], pred[(sysname, s)][msk], K, sub_nonrare[sub], sB[msk], tB[msk], gap)
        # zero-by-construction proof for S2_SPEC
        oth = subsets["other_groups"]
        same_other = all((pred[("S2_SPEC", s)][oth] == pred[("ROUTED_v21", s)][oth]).all() for s in seeds)
        run.check(M, "S2_SPEC predictions on the other groups' val-B rows == v2_1 ROUTED (zero forgetting by construction)",
                  same_other, f"{int(oth.sum()):,} rows x {len(seeds)} seeds")
        # ---------------------------------------------------------------- gate
        gcfg = cfg4["gate"]
        gates = {}
        for sysname in [x for x in systems if x != "R0"]:
            for s in seeds:
                gates[(sysname, s)] = CG.gate(E[(sysname, s, "all")], E[("R0", s, "all")], nonrare, gcfg)
        # ---------------------------------------------------------------- metrics + forgetting
        times = {a: [arm_models[(a, s)]["fit_seconds"] for s in seeds] for a in arms}
        mem = {a: [arm_models[(a, s)]["peak_rss_mb"] for s in seeds] for a in arms}
        memi = {a: [arm_models[(a, s)]["peak_rss_increase_mb"] for s in seeds] for a in arms}
        table = {}
        for sysname in systems:
            row = {}
            for sub in subsets:
                es = [E[(sysname, s, sub)] for s in seeds]
                e0 = [E[("R0", s, sub)] for s in seeds]
                row[sub] = {"macro_f1_nonrare": agg([e["macro_f1_nonrare"] for e in es], lvl),
                            "macro_f1_all": agg([e["macro_f1_all"] for e in es], lvl),
                            "fa_per_hour": agg([e["fa_per_hour"] for e in es], lvl),
                            "fa_count": [e["fa_count"] for e in es], "benign_hours": es[0]["benign_hours"],
                            "recall": [agg([e["recall"][k] for e in es], lvl) for k in range(K)],
                            "f1": [agg([e["f1"][k] for e in es], lvl) for k in range(K)],
                            "support": es[0]["support"], "nonrare": [names[k] for k in sub_nonrare[sub]],
                            "vs_R0": {"macro_f1_nonrare": CG.paired([e["macro_f1_nonrare"] for e in es],
                                                                    [e["macro_f1_nonrare"] for e in e0], lvl),
                                      "fa_per_hour": CG.paired([e["fa_per_hour"] for e in es], [e["fa_per_hour"] for e in e0], lvl),
                                      "recall": [CG.paired([e["recall"][k] for e in es], [e["recall"][k] for e in e0], lvl)
                                                 for k in range(K)]}}
            if sysname in arms:
                row["cost"] = {"fit_seconds": agg(times[sysname], lvl), "peak_rss_mb": agg(mem[sysname], lvl),
                               "peak_rss_increase_mb": agg(memi[sysname], lvl),
                               "trees": [arm_models[(sysname, s)]["rounds_total"] for s in seeds],
                               "new_trees": [arm_models[(sysname, s)]["new_rounds"] for s in seeds],
                               "train_rows": arm_models[(sysname, seeds[0])]["n_rows"]}
            elif sysname == "R0":
                row["cost"] = {"fit_seconds": agg([0.0] * len(seeds), lvl), "note": "no retrain"}
            if sysname != "R0":
                gl = [gates[(sysname, s)] for s in seeds]
                row["gate"] = {"pass_count": int(sum(g["pass"] for g in gl)), "of": len(gl),
                               "per_seed": {s: {"status": g["status"], "reason": g["reason"]} for s, g in zip(seeds, gl)}}
            table[sysname] = row
        forget_s1 = {}
        for a in [x for x in arms] + ["ROUTED_v21"]:
            forget_s1[a] = {names[k]: CG.forgetting([E[("R0", s, "all")]["f1"][k] for s in seeds],
                                                    [E[(a, s, "all")]["f1"][k] for s in seeds], lvl) for k in nonrare}
        # ---------------------------------------------------------------- S2 + Amendment 2 section 4
        fsub = "other_groups"
        f_gl = [E[("R0", s, fsub)]["macro_f1_nonrare"] - E[("S2_GLOBAL", s, fsub)]["macro_f1_nonrare"] for s in seeds]
        f_pg = [E[("ROUTED_v21", s, fsub)]["macro_f1_nonrare"] - E[("S2_SPEC", s, fsub)]["macro_f1_nonrare"] for s in seeds]
        a_gl = [E[("S2_GLOBAL", s, "affected_group")]["macro_f1_nonrare"] for s in seeds]
        a_pg = [E[("S2_SPEC", s, "affected_group")]["macro_f1_nonrare"] for s in seeds]
        V = CG.verdict_a2s4(f_pg, f_gl, a_pg, a_gl, times["S2_SPEC"], times["S2_GLOBAL"], cfg4["verdict"], lvl)
        per_group_forget = {g: {"S2_GLOBAL": CG.forgetting([E[("R0", s, f"group:{g}")]["macro_f1_nonrare"] for s in seeds],
                                                           [E[("S2_GLOBAL", s, f"group:{g}")]["macro_f1_nonrare"] for s in seeds], lvl),
                                "S2_SPEC": CG.forgetting([E[("ROUTED_v21", s, f"group:{g}")]["macro_f1_nonrare"] for s in seeds],
                                                         [E[("S2_SPEC", s, f"group:{g}")]["macro_f1_nonrare"] for s in seeds], lvl)}
                            for g in groups if g != grp_s2}
        V.update({"label_group": grp_s2, "other_groups": [g for g in groups if g != grp_s2],
                  "forgetting_S2_SPEC": CG.forgetting([E[("ROUTED_v21", s, fsub)]["macro_f1_nonrare"] for s in seeds],
                                                      [E[("S2_SPEC", s, fsub)]["macro_f1_nonrare"] for s in seeds], lvl),
                  "forgetting_S2_GLOBAL": CG.forgetting([E[("R0", s, fsub)]["macro_f1_nonrare"] for s in seeds],
                                                        [E[("S2_GLOBAL", s, fsub)]["macro_f1_nonrare"] for s in seeds], lvl),
                  "affected_group_macro_f1": {"S2_SPEC": agg(a_pg, lvl), "S2_GLOBAL": agg(a_gl, lvl),
                                              "before_FLAT_GLOBAL": agg([E[("R0", s, "affected_group")]["macro_f1_nonrare"] for s in seeds], lvl),
                                              "before_ROUTED": agg([E[("ROUTED_v21", s, "affected_group")]["macro_f1_nonrare"] for s in seeds], lvl)},
                  "per_group_forgetting": per_group_forget, "zero_by_construction_proof": bool(same_other),
                  "note": "In the per-group arm, the other groups' specialists are unchanged, so their forgetting is zero by "
                          "construction. The real question of Amendment 2 §4 is whether retraining GLOBAL causes forgetting on "
                          "the other groups. If it doesn't, per-group can win only on cost.",
                  "kill_rule_section_5": ("Phase 4 test favours per-group" if V["wins"] else
                                          "Phase 4 test does NOT favour per-group (Amendment 2 section 5: no Stage 3 routing claim)")})
        run.log(f"  Amendment 2 section 4: {V['verdict']}; forgetting S2_SPEC {V['forgetting_S2_SPEC']['mean']:.5f}, "
                f"S2_GLOBAL {V['forgetting_S2_GLOBAL']['mean']:.5f} [{V['forgetting_S2_GLOBAL']['lo']:.5f}, "
                f"{V['forgetting_S2_GLOBAL']['hi']:.5f}]; time ratio {V['time_ratio_global_over_per_group']:.2f}")
        # ---------------------------------------------------------------- poisoning
        labs = M33["labels"]
        poison = {}
        for pn in ("P1", "P2"):
            a = f"R2__{pn}"
            if a not in arms:
                continue
            q = labs[pn]["status"] == "QUARANTINED"
            g0 = gates[(a, seeds[0])]
            b32 = json.loads((up32["dir"] / "batches.json").read_text(encoding="utf-8"))[pn]
            poison[pn] = {"batch_id": labs[pn]["batch_id"], "validator": labs[pn]["status"], "fired": labs[pn]["fired"],
                          "poison": b32.get("poison"),
                          "gate_if_used": {s: {"status": gates[(a, s)]["status"], "reason": gates[(a, s)]["reason"]} for s in seeds},
                          "gate_pass_count": int(sum(gates[(a, s)]["pass"] for s in seeds)),
                          "verdict": CG.poisoning_verdict(q, g0["pass"]),
                          "target_recall_val_B": agg([E[(a, s, "all")]["recall"][names.index(b32["poison"]["target_class"])]
                                                      for s in seeds], lvl) if b32.get("poison") else None}
            run.log(f"  poisoning {pn}: {poison[pn]['verdict']} (validator {poison[pn]['validator']} {poison[pn]['fired']}; "
                    f"gate if used {poison[pn]['gate_pass_count']}/{len(seeds)} pass)")
        # ---------------------------------------------------------------- feedback bias
        fb = {}
        if "R2__no_random" in arms:
            rdir = Path(up31["manifest"]["runtime"]["dir"])
            P = PIO.read_predictions(rdir, columns=["flow_uid", "alert", "pred"])
            ya = dict(zip(uid, va["label_id"].to_numpy(np.int64)))
            tA = np.array([ya[u] for u in P["flow_uid"]], dtype=np.int64)
            fn = (tA != 0) & ~P["alert"].to_numpy(bool)
            fn_uids = set(P["flow_uid"].to_numpy()[fn].tolist())
            bb = json.loads((up32["dir"] / "batches.json").read_text(encoding="utf-8"))
            from common import label_store as LS
            _, opub = LS.ensure_operator_keys(CC.expand(cfg4["paths"]["operator_keys_dir"]), REPO_ROOT)
            lab_with = set(LS.load_batch(Path(bb["primary"]["root"]), bb["primary"]["batch_id"], opub, names)[0]["flow_uid"])
            lab_wo = set(LS.load_batch(Path(bb["no_random"]["root"]), bb["no_random"]["batch_id"], opub, names)[0]["flow_uid"])
            miss_cls = sorted({int(t) for t in tA[fn]})
            fb = {"val_A_missed_attack_flows": int(fn.sum()),
                  "missed_by_class": {names[k]: int((tA[fn] == k).sum()) for k in range(K) if (tA[fn] == k).any()},
                  "labelled_with_random": int(len(fn_uids & lab_with)), "labelled_without_random": int(len(fn_uids & lab_wo)),
                  "labelled_with_random_by_class": {names[k]: int(sum(1 for u, t in zip(P["flow_uid"].to_numpy()[fn], tA[fn])
                                                                      if t == k and u in lab_with)) for k in miss_cls},
                  "miss_classes": [names[k] for k in miss_cls], "recall_val_B": {}}
            for k in miss_cls:
                r_w = [E[("R2", s, "all")]["recall"][k] for s in seeds]
                r_wo = [E[("R2__no_random", s, "all")]["recall"][k] for s in seeds]
                r_0 = [E[("R0", s, "all")]["recall"][k] for s in seeds]
                # recall on the val-B flows of class k the same-seed R0 misses (predicts benign)
                rm_w, rm_wo, nmiss = [], [], []
                for s in seeds:
                    mm = (yB == k) & (pred[("R0", s)] == 0)
                    nmiss.append(int(mm.sum()))
                    rm_w.append(float((pred[("R2", s)][mm] == k).mean()) if mm.any() else float("nan"))
                    rm_wo.append(float((pred[("R2__no_random", s)][mm] == k).mean()) if mm.any() else float("nan"))
                fb["recall_val_B"][names[k]] = {"R0": agg(r_0, lvl), "R2_with_random": agg(r_w, lvl),
                                                "R2_without_random": agg(r_wo, lvl),
                                                "with_minus_without": CG.paired(r_w, r_wo, lvl),
                                                "R0_missed_val_B_flows": nmiss,
                                                "recall_on_R0_misses_with_random": agg(rm_w, lvl),
                                                "recall_on_R0_misses_without_random": agg(rm_wo, lvl)}
            run.log(f"  feedback bias: val-A misses {fb['val_A_missed_attack_flows']:,}; labelled with random "
                    f"{fb['labelled_with_random']:,}, without {fb['labelled_without_random']:,}")
        # ---------------------------------------------------------------- registry: candidates + rejected
        reg_root = CC.expand(cfg4["paths"]["registry_root"])
        reg_root = reg_root.with_name(reg_root.name + "_dry_run") if args.dry_run else reg_root
        prod_root = CC.expand(cfg4["paths"]["registry_root"])
        dep = prod_root / cfg4["deployed"]["entry"]
        dep_before = {f: CR.sha256_path(dep / f) for f in ("manifest.json", "manifest.sig", "state.log", "model.ubj", "calibrator.json")}
        secret, public = REG.ensure_keys(CC.expand(cfg4["paths"]["registry_keys_dir"]), REPO_ROOT)
        dep_state = REG.read_state(dep, public)
        dep_man = json.loads((dep / "manifest.json").read_text(encoding="utf-8"))
        spec_entry = json.loads((prod_root / [e for e in json.loads((REPO_ROOT / cfg4["phase3_config"]).read_text(
            encoding="utf-8"))["models"]["ROUTED"]["entries"] if e.startswith(M33["s2"]["spec_model"] + "__s0__")][0]
                                 / "manifest.json").read_text(encoding="utf-8"))
        dm = D.load_dataset_manifest(cfg2)
        registered, rejected, passed_unreg = [], [], []
        for a in arms:
            for s in seeds:
                g = gates[(a, s)]
                m = arm_models[(a, s)]
                rec = {"arm": a, "seed": s, "model_file": str(mdir / m["file"]), "model_sha256": m["sha256"],
                       "gate": g["status"], "reason": g["reason"], "conditions": g["conditions"],
                       "experiment": a not in PRIMARY}
                if not g["pass"]:
                    rejected.append({**rec, "state": "REJECTED"})
                elif a in PRIMARY and s == 0:
                    pass
                else:
                    passed_unreg.append({**rec, "state": "PASS_NOT_REGISTERED",
                                         "why": "experiment arm" if a not in PRIMARY else "only seed 0 is registered"})
        for a in PRIMARY:
            s = 0
            if s not in seeds or not gates[(a, s)]["pass"]:
                continue
            m = arm_models[(a, s)]
            is_spec = a == "S2_SPEC"
            ref_man = spec_entry if is_spec else dep_man
            model_id = f"{m['model_id']}__P4_{a}"
            entry_id = f"{model_id}__s0__{M33['run_id']}"
            lb = M33["labels"][m["batch"]]
            ev_all = E[(a, s, "all")]
            fields = {"model_id": model_id, "model_key": f"{a}__s0", "seed": 0, "kind": ref_man["kind"],
                      "serves_groups": ref_man["serves_groups"], "class_names": names, "class_map_sha256": S.CLASS_MAP_SHA256,
                      "features_file_sha256": S.FEATURES_V1_SHA256, "features_list_sha256": S.FEATURES_V1_LIST_SHA256,
                      "dataset_version": cfg2["dataset_version"], "dataset_manifest_sha256": dm["_sha256"],
                      "prereg_phase2_sha256": S.PREREG_PHASE2_SHA256, "prereg_amendment_1_sha256": S.PREREG_PHASE2_AMENDMENT_1_SHA256,
                      "orientation_map_sha256": S.ORIENTATION_MAP_SHA256, "config_sha256": cfg4["_sha256"],
                      "train_run": M33["run_id"], "train_run_manifest_sha256": up33["manifest_sha256"],
                      "eval_run": run.run_id, "temperature": m["temperature"], "best_iteration": m["best_iteration"],
                      "training_counts": m["counts"], "class_weights": [1.0] * K,
                      "val_metrics": {"eval_set": "val-B (Phase 4 split), all groups", "n": ev_all["n"],
                                      "support": ev_all["support"], "recall": ev_all["recall"], "f1": ev_all["f1"],
                                      "macro_f1_all": ev_all["macro_f1_all"], "macro_f1_nonrare": ev_all["macro_f1_nonrare"],
                                      "fa_per_hour": ev_all["fa_per_hour"]},
                      "runtime_contract": ref_man["runtime_contract"],
                      "phase4": {"tag": "phase4", "arm": a, "prereg_phase4_sha256": S.PREREG_PHASE4_SHA256,
                                 "phase4_config_sha256": S.V2_PHASE4_CONFIG_SHA256,
                                 "label_batches": [{"batch_id": lb["batch_id"], "manifest_sha256": lb["manifest_sha256"],
                                                    "parquet_sha256": lb["parquet_sha256"]}],
                                 "replay_manifest_sha256": M33["replay"]["manifest_sha256"] if m["base"] and a == "R2" else None,
                                 "base_model": ({**m["base"], "entry": cfg4["deployed"]["entry"]} if m["base"] else None),
                                 "gate": {"status": gates[(a, s)]["status"], "vs": f"{cfg4['deployed']['entry']} (seed 0, val-B)",
                                          "conditions": gates[(a, s)]["conditions"]},
                                 "evaluated_as": "ROUTED system (other specialists / GLOBAL = v2_1)" if is_spec else "FLAT_GLOBAL",
                                 "temperature_note": "fitted on the retrain's own inner split; review before any promotion"}}
            cal = mdir / f"{a}__s0.temperature.json"
            d = REG.register(reg_root, entry_id, mdir / m["file"], cal, fields, secret, by=f"{SCRIPT} (Phase 4 gate PASS)")
            st = REG.read_state(d, public)
            ok_off = REG.load_model(d, public, S.CLASS_MAP_PATH, S.FEATURES_PATH, allow_states=("candidate",))
            try:
                REG.load_model(d, public, S.CLASS_MAP_PATH, S.FEATURES_PATH)
                refused = False
            except REG.RegistryRefused:
                refused = True
            run.check(M, f"{entry_id}: registered CANDIDATE; deployment load refused, offline load allowed",
                      st == "candidate" and refused and ok_off["state"] == "candidate", str(d))
            registered.append({"entry_id": entry_id, "dir": str(d), "arm": a, "state": st, "model_sha256": m["sha256"],
                               "kind": fields["kind"], "serves_groups": fields["serves_groups"],
                               "fingerprint": REG.fingerprint(public)})
        dep_after = {f: CR.sha256_path(dep / f) for f in dep_before}
        run.check(M, "promoted entry unchanged (files + state log sha256, state promoted)",
                  dep_before == dep_after and REG.read_state(dep, public) == dep_state == "promoted",
                  f"{cfg4['deployed']['entry']}: state {dep_state}")
        rjd = run.cache_dir("rejected")
        with open(rjd / "rejected.jsonl", "x", encoding="utf-8") as fh:
            for r in rejected:
                fh.write(json.dumps(r, default=CR._default, sort_keys=True) + "\n")
        # ---------------------------------------------------------------- outputs
        out_eval = {"seeds": seeds, "names": names, "nonrare": [names[k] for k in nonrare], "val_B": M["val_B"],
                    "subsets_nonrare": {k: [names[c] for c in v] for k, v in sub_nonrare.items()},
                    "systems": systems, "arms": arms, "table": table, "forgetting_s1": forget_s1,
                    "per_seed": {f"{a}|{s}|{sub}": E[(a, s, sub)] for a in systems for s in seeds for sub in ("all", "other_groups",
                                                                                                                "affected_group")},
                    "split": {k: v for k, v in sp.items()}, "split_counts": json.loads((up31["dir"] / "split.json").read_text(
                        encoding="utf-8"))["counts"]}
        gate_j = {f"{a}|{s}": g for (a, s), g in gates.items()}
        CR.write_json(run.res / "eval.json", out_eval)
        CR.write_json(run.res / "gate.json", gate_j)
        CR.write_json(run.res / "verdict.json", {"amendment_2_section_4": V, "poisoning": poison, "feedback_bias": fb})
        CR.write_json(run.res / "registry.json", {"registered": registered, "registry_root": str(reg_root),
                                                  "promoted_entry_unchanged": dep_before == dep_after})
        CR.write_json(run.res / "rejected.json", {"rejected": rejected, "passed_not_registered": passed_unreg})
        M.update({"verdict": {k: V[k] for k in ("verdict", "wins", "forgetting_lower", "forgetting_equal_within_tol",
                                                 "time_ratio_global_over_per_group", "affected_group_ok")},
                  "poisoning": {k: v["verdict"] for k, v in poison.items()}, "registered": registered,
                  "rejected": [(r["arm"], r["seed"], r["reason"]) for r in rejected],
                  "gate_pass_counts": {a: table[a]["gate"]["pass_count"] for a in systems if a != "R0"}})
        CR.lock_banner(run, M, "end")
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
        M["_table"], M["_V"], M["_poison"], M["_fb"] = table, V, poison, fb
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run, cfg4)
    for k in ("_table", "_V", "_poison", "_fb"):
        M.pop(k, None)
    run.finish(ok, M)
    return 0 if ok else 1


def _ci(a: dict, f: str = "{:.4f}") -> str:
    if a is None:
        return "-"
    lo, hi = a.get("lo"), a.get("hi")
    s = f.format(a["mean"])
    if lo is not None and hi is not None and np.isfinite(lo) and np.isfinite(hi):
        s += " [" + f.format(lo) + ", " + f.format(hi) + "]"
    return s


def write_summary(run, M: dict, dry: bool, cfg4: dict) -> None:
    st = "PASS" if all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") and not M.get("error") else "FAIL"
    L = [f"# Step 34 -- val-B evaluation, regression gate, Amendment 2 section 4, poisoning, feedback bias -- {st}"
         + (" (DRY RUN)" if dry else ""), "",
         f"- retrain run `{M.get('retrain_run')}`, labels run `{M.get('labels_run')}`, queue run `{M.get('queue_run')}`; "
         f"val-B {M.get('val_B', {}).get('n', 0):,} flows, non-rare {M.get('val_B', {}).get('nonrare')}", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    T = M.get("_table")
    if T:
        names = list(S.load_class_map().names)
        L += ["## Per arm on val-B (5-seed mean [95 % t-CI]; paired diff vs R0)", "",
              "| system | macro-F1 non-rare | diff vs R0 | FA / h | " + " | ".join(f"recall {n}" for n in names)
              + " | fit s | gate PASS |", "|" + "---|" * (6 + len(names))]
        for a, r in T.items():
            al = r["all"]
            L.append(f"| {a} | {_ci(al['macro_f1_nonrare'], '{:.5f}')} | {_ci(al['vs_R0']['macro_f1_nonrare'], '{:+.5f}')} | "
                     f"{_ci(al['fa_per_hour'], '{:.3f}')} | " + " | ".join(_ci(x, '{:.4f}') for x in al["recall"])
                     + f" | {_ci(r.get('cost', {}).get('fit_seconds'), '{:.2f}')} | "
                     + (f"{r['gate']['pass_count']}/{r['gate']['of']}" if r.get("gate") else "(deployed)") + " |")
        L.append("")
    V = M.get("_V")
    if V:
        L += ["## Amendment 2 section 4 verdict", "", f"**{V['verdict']}** -- {V['rule']}", "",
              f"- forgetting on the groups without labels {V['other_groups']} (non-rare macro-F1 drop): S2_SPEC "
              f"{_ci(V['forgetting_S2_SPEC'], '{:+.5f}')}, S2_GLOBAL {_ci(V['forgetting_S2_GLOBAL'], '{:+.5f}')}; difference "
              f"(per-group - global) {_ci(V['forgetting_diff_pg_minus_global'], '{:+.5f}')}; lower: {V['forgetting_lower']}, "
              f"equal within {cfg4['verdict']['forgetting_equal_tol']}: {V['forgetting_equal_within_tol']}",
              f"- retrain time: S2_SPEC {V['time_mean_s']['per_group']:.2f} s, S2_GLOBAL {V['time_mean_s']['global']:.2f} s "
              f"(ratio {V['time_ratio_global_over_per_group']:.2f}; >= {cfg4['verdict']['time_ratio']} needed): "
              f"{V['time_cheaper']}",
              f"- affected group {V['label_group']} non-rare macro-F1: S2_SPEC {_ci(V['affected_group_macro_f1']['S2_SPEC'], '{:.5f}')}, "
              f"S2_GLOBAL {_ci(V['affected_group_macro_f1']['S2_GLOBAL'], '{:.5f}')}; diff "
              f"{_ci(V['affected_group_diff_pg_minus_global'], '{:+.5f}')} (>= -{cfg4['verdict']['affected_group_tol']}): "
              f"{V['affected_group_ok']}",
              f"- note: {V['note']} (proof: S2_SPEC predictions on the other groups' rows == v2_1 ROUTED: "
              f"{V['zero_by_construction_proof']})", f"- kill rule: {V['kill_rule_section_5']}", ""]
    if M.get("_poison"):
        L += ["## Poisoning", "", "| batch | poison | validator | gate if used (PASS / seeds) | verdict |", "|---|---|---|---|---|"]
        for k, p in M["_poison"].items():
            L.append(f"| {k} | {p['poison']} | {p['validator']} {p['fired']} | {p['gate_pass_count']}/{len(p['gate_if_used'])} | "
                     f"**{p['verdict']}** |")
        L.append("")
    fb = M.get("_fb")
    if fb:
        L += ["## Feedback bias", "", f"- val-A missed attack flows: {fb['val_A_missed_attack_flows']:,} {fb['missed_by_class']}; "
              f"labelled with the random sample {fb['labelled_with_random']:,}, without {fb['labelled_without_random']:,}"]
        for c, r in fb["recall_val_B"].items():
            L.append(f"- {c}: val-B recall R0 {_ci(r['R0'])}, R2 with random {_ci(r['R2_with_random'])}, without "
                     f"{_ci(r['R2_without_random'])}; on R0's val-B misses ({r['R0_missed_val_B_flows']}): with "
                     f"{_ci(r['recall_on_R0_misses_with_random'])}, without {_ci(r['recall_on_R0_misses_without_random'])}")
        L.append("")
    if M.get("registered") is not None:
        L += ["## Registry", ""] + [f"- CANDIDATE `{r['entry_id']}` ({r['arm']}, {r['kind']}, serves {r['serves_groups']})"
                                    for r in M["registered"]] + \
             [f"- REJECTED {a} s{s}: {why}" for a, s, why in M.get("rejected", [])] + [""]
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
