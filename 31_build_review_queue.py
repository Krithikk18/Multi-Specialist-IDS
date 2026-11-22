#!/usr/bin/env python
"""31_build_review_queue.py -- Phase 4 steps A1 + B (docs/V2_PREREG_PHASE4.md sections 1-2). VAL only (never test).

A1  val-A / val-B split (common/cl_split.py): each val session window of the dataset's split_definition.json cut at the
    time midpoint of its data extent; flows per class x group in each part; rare-for-the-gate classes (< min_val_flows
    val-B flows).
B   the Phase 3 runtime (common/runtime.Runtime; config/v2_phase3_1.json, pinned) replays the val-A rows of the runtime
    input dataset (v2_0_v1equiv, extractor orientation) at max speed with the PROMOTED model loaded the deployment way
    (flow path only); PARITY (hard, the Phase 3 gate's criteria via 28_run_stream.parity) against the offline step 23 /
    24 path on the same v2_1 val-A rows; then the review queue (common/review_queue.py): every alert + a seeded random
    5 % of the non-alerted flows; and the alerts-only queue for the feedback-bias test.
Outputs  <cache>/split/<run>/ (split.parquet, manifest.json), <cache>/runtime/<run>_GLOBAL_s0_valA/ (runtime run folder),
         <cache>/queue/<run>/ and <cache>/queue/<run>__no_random/ (queue.parquet, manifest.json);
         results/phase4/31/ summary.md, split.json, queue.json, parity.json, run_manifest.json, run_meta.json, run.log.
--dry-run: the 5 % val sample (Phase 2 dry-run rule), *_dry_run cache, results/phase4/31/dry_run/<run_id>/.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import REPO_ROOT
from common import alert_log as AL
from common import cl_config as CC
from common import cl_run as CR
from common import cl_split as SP
from common import flow_source as FS
from common import model_loader as ML
from common import phase2_data as D
from common import phase3_config as C3
from common import predictions_io as PIO
from common import review_queue as RQ
from common import schemas as S
from common.phase2_config import load_phase2_config
from common.routing import Router
from common.runtime import Runtime

SCRIPT = "31_build_review_queue.py"
EXTRA = ["common/runtime.py", "common/flow_source.py", "common/model_loader.py", "common/routing.py",
         "common/inference.py", "common/policy.py", "common/orientation.py", "common/predictions_io.py",
         "common/alert_log.py", "common/phase3_config.py", "config/v2_phase3_1.json", "config/v2_phase2_v2_1.json",
         "config/v2_phase2.json", "28_run_stream.py"]


def load_28():
    spec = importlib.util.spec_from_file_location("run28_stream", REPO_ROOT / "28_run_stream.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def split_definition(cfg2: dict) -> tuple[dict, str]:
    p = D.dataset_dir(cfg2) / "split_definition.json"
    sd = json.loads(p.read_text(encoding="utf-8"))
    body = {k: v for k, v in sd.items() if k not in ("sha256", "sha256_of")}
    own = CR.sha256_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if own != sd.get("sha256"):
        raise RuntimeError(f"{p}: own sha256 field {sd.get('sha256')} != recomputed {own}")
    return sd, CR.sha256_path(p)


def counts_table(part, label_id, group, names: list[str]) -> dict:
    out = {}
    for pp in SP.PARTS:
        m = part == pp
        out[pp] = {g: {names[k]: int(((group == g) & (label_id == k) & m).sum()) for k in range(len(names))}
                   for g in sorted(set(group.tolist()))}
        out[pp]["_all"] = {names[k]: int(((label_id == k) & m).sum()) for k in range(len(names))}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg4 = CC.load_phase4_config()
    run = CR.Run("31", SCRIPT, cfg4, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(EXTRA)
    CR.lock_banner(run, M, "start")
    ok = False
    try:
        cm = S.load_class_map()
        names = list(cm.names)
        feats = S.feature_columns()
        cfg2 = load_phase2_config(REPO_ROOT / cfg4["phase2_config"])
        cfg3 = C3.load_phase3_config(REPO_ROOT / cfg4["phase3_config"])
        cfg2r = load_phase2_config(REPO_ROOT / cfg3["source"]["replay_phase2_config"])
        run.check(M, "Phase 3 config pinned (the latest pinned runtime config)", cfg3["_pinned"],
                  f"{cfg4['phase3_config']} sha256 {cfg3['_sha256'][:16]}...")
        run.check(M, "replay / reference datasets as the Phase 3 config says",
                  cfg2r["dataset_version"] == cfg3["source"]["replay_dataset_version"]
                  and cfg2["dataset_version"] == cfg3["source"]["reference_dataset_version"],
                  f"replay {cfg2r['dataset_version']}, reference {cfg2['dataset_version']}")
        # ---------------------------------------------------------------- A1 split
        sd, sd_sha = split_definition(cfg2)
        va = D.load_split(cfg2, "val", feats + ["session", "row_in_file", "start_ts", "label_id", "group", "device_mac"],
                          sample=args.dry_run)
        uid = (va["session"].astype(str) + ":" + va["row_in_file"].astype(str)).to_numpy()
        W = SP.val_windows(sd, va["session"], va["start_ts"])
        part = SP.assign(va["session"], va["start_ts"], W)
        y = va["label_id"].to_numpy(np.int64)
        grp = va["group"].astype(str).to_numpy()
        tab = counts_table(part, y, grp, names)
        supB = np.bincount(y[part == "val_B"], minlength=len(names))
        rare = [names[k] for k in range(len(names)) if 0 < supB[k] < cfg4["gate"]["min_val_flows"]]
        absent = [names[k] for k in range(len(names)) if supB[k] == 0]
        split_info = {"split_definition_sha256": sd_sha, "split_definition_own_sha256": sd["sha256"],
                      "windows": SP.jsonable_windows(W), "counts": tab, "n": {p: int((part == p).sum()) for p in SP.PARTS},
                      "val_B_support": {names[k]: int(supB[k]) for k in range(len(names))}, "rare_for_gate": rare,
                      "absent_in_val_B": absent, "min_val_flows": cfg4["gate"]["min_val_flows"],
                      "val_file_sha256": D.verify_split_file(cfg2, "val")}
        sdir = run.cache_dir("split")
        pq_split = pd.DataFrame({"flow_uid": uid, "session": va["session"].astype(str).to_numpy(),
                                 "row_in_file": va["row_in_file"].to_numpy(np.int64),
                                 "start_ts": va["start_ts"].to_numpy(np.int64), "part": part})
        pq_split.to_parquet(sdir / "split.parquet", index=False)
        split_info["split_parquet_sha256"] = CR.sha256_path(sdir / "split.parquet")
        split_info["dir"] = str(sdir)
        CR.write_json(sdir / "manifest.json", split_info)
        CR.write_json(run.res / "split.json", split_info)
        M["split"] = {k: v for k, v in split_info.items() if k != "counts"}
        run.log(f"  split: val_A {split_info['n']['val_A']:,} / val_B {split_info['n']['val_B']:,}; rare in val_B {rare}")
        for s, w in split_info["windows"].items():
            run.log(f"    {s:<18} extent [{w['lo']:.0f}, {w['hi']:.0f}] mid {w['mid']:.1f}  n {w['n']:,}")
        # ---------------------------------------------------------------- B runtime on val-A
        rv = D.load_split(cfg2r, "val", feats + FS.ID_COLS[:-1] + FS.MAC_COLS + ["start_ts", "session", "row_in_file",
                                                                                 "label_id", "group", "split"],
                          sample=args.dry_run)
        uid_r = (rv["session"].astype(str) + ":" + rv["row_in_file"].astype(str)).to_numpy()
        same = len(uid_r) == len(uid) and (uid_r == uid).all() and (rv["label_id"].to_numpy() == y).all() \
            and (rv["group"].astype(str).to_numpy() == grp).all()
        run.check(M, "replay rows == reference rows (same uids, order, labels, groups)", bool(same),
                  f"{len(uid_r):,} vs {len(uid):,}")
        A = part == "val_A"
        frameA = rv.loc[A].reset_index(drop=True)
        rcfg = C3.with_overrides(cfg3, mode="GLOBAL", seed=0, rate_guard_enabled=False)
        src = FS.CsvReplaySource(rcfg, frame=frameA)
        src.info.update({"dataset_version": cfg2r["dataset_version"], "file_sha256": D.verify_split_file(cfg2r, "val"),
                         "phase4_part": "val_A", "split_run": run.run_id})
        rm = ML.load_runtime_model(rcfg, mode="GLOBAL", seed=0, evaluation=False)
        srcs = [m.source for m in rm.models.values()]
        run.check(M, "runtime model = the promoted deployed entry (deployment load, promoted only)",
                  srcs == [cfg4["deployed"]["entry"]] and not rm.evaluation_only
                  and all(m.state == "promoted" for m in rm.models.values()), f"{srcs}")
        secret, public = AL.ensure_runtime_keys(C3.expand(cfg3["paths"]["runtime_keys_dir"]), REPO_ROOT)
        rdir = run.cache_dir("runtime", "_GLOBAL_s0_valA")
        router = Router(rcfg, ip_mac_source=C3.ip_mac_source(rcfg, "csv_replay"))
        rt = Runtime(rcfg, rm, rdir, secret, rate_guard=None, store_features=True, router=router)
        run.log(f"  runtime on val-A: {len(src):,} flows -> {rdir}")
        summ = rt.run(src, None, info=src.info)
        c = summ["counts"]
        run.log(f"    {c.get('flows_scored', 0):,} flows in {summ['wall_s']:.1f} s; alerts {c.get('flow_alerts', 0):,}; "
                f"incidents {summ['incidents']}; quarantined {c.get('quarantined', 0)}; dropped {c.get('dropped', 0)}")
        CR.write_json(rdir / "manifest.json", {"run_dir": str(rdir), "mode": "GLOBAL", "seed": 0, "model": rm.describe(),
                                              "config": cfg4["phase3_config"], "config_sha256": rcfg["_sha256"],
                                              "overrides": rcfg["_overrides"], "source": src.info, "summary": summ,
                                              "runtime_key_fingerprint": AL.REG.fingerprint(public), "parent_run": run.run_id,
                                              "script": SCRIPT})
        m28 = load_28()
        ref = {"X": D.feature_matrix(va.loc[A], feats), "group": grp[A], "device_mac": va["device_mac"].astype(str).to_numpy()[A],
               "uid": uid[A]}
        off = m28.offline_scores(rm, ref)
        par = m28.parity(run, M, {"dir": rdir, "rm": rm, "summary": summ}, ref, off, hard=True,
                         label="parity val-A GLOBAL s0")
        par_j = {k: v for k, v in par.items() if k not in ("dp", "pred_rt", "pred_off")}
        P = PIO.read_predictions(rdir)
        if not args.dry_run:                                           # report-only: same flows in the Phase 3 full run
            try:
                up = json.loads((REPO_ROOT / "results/phase3/28/rerun_full/run_manifest.json").read_text(encoding="utf-8"))
                P3 = PIO.read_predictions(Path(up["runs"]["GLOBAL_s0"]["dir"]))
                p3 = P3.set_index("flow_uid").loc[P["flow_uid"]]
                K = len(names)
                dp = np.abs(p3[[f"p_{k}" for k in range(K)]].to_numpy() - P[[f"p_{k}" for k in range(K)]].to_numpy()).max()
                eq = bool((p3["pred"].to_numpy() == P["pred"].to_numpy()).all())
                par_j["vs_phase3_full_run"] = {"pred_equal": eq, "max_abs_dp": float(dp), "rows": int(len(P))}
                run.check(M, "val-A predictions == Phase 3 full-val runtime run for the same flows (report-only)",
                          eq and dp <= 1e-6, f"pred equal {eq}, max |dp| {dp:.2e}", warn=True)
            except Exception as e:                                     # noqa: BLE001
                par_j["vs_phase3_full_run"] = {"error": repr(e)}
        CR.write_json(run.res / "parity.json", par_j)
        M["parity"] = par_j
        M["runtime"] = {"dir": str(rdir), "counts": c, "wall_s": summ["wall_s"], "flows_per_s": summ["flows_per_s"],
                        "incidents": summ["incidents"], "predictions": summ["predictions"]}
        # ---------------------------------------------------------------- queue
        fid = dict(zip(uid_r[A], frameA["Flow ID"].astype(str)))
        alert = P["alert"].to_numpy(bool)
        qcfg = cfg4["queue"]
        qinfo = {}
        for tag, rate in (("", qcfg["random_review_rate"]), ("__no_random", 0.0)):
            Q = RQ.build_queue(alert, rate, qcfg["seed"])
            qd = P.iloc[Q["pos"]].reset_index(drop=True)
            cols = ["flow_uid", "session", "row", "start_ts", "event_time", "decision_time", "group", "device_mac", "device",
                    "model_id", "pred", "pmax", "alert"] + [f"p_{k}" for k in range(len(names))]
            qd = qd[cols].copy()
            qd.insert(1, "flow_id", [fid[u] for u in qd["flow_uid"]])
            qd["reason"] = Q["reason"]
            qd["runtime_run_id"] = run.run_id
            qdir = run.cache_dir("queue", tag)
            qd.to_parquet(qdir / "queue.parquet", index=False)
            man = {"queue_id": f"{run.run_id}{tag}", "runtime_run_dir": str(rdir), "runtime_run_id": run.run_id,
                   "rows_scored": int(len(P)), "n": int(len(qd)), "n_alert": Q["n_alert"], "n_random": Q["n_random"],
                   "n_non_alerted": Q["n_non_alerted"], "random_review_rate": rate, "seed": Q["seed"],
                   "by_reason_pred": {r: {names[k]: int(((qd["reason"] == r) & (qd["pred"] == k)).sum())
                                          for k in range(len(names))} for r in RQ.REASONS},
                   "by_group_reason": {g: {r: int(((qd["group"] == g) & (qd["reason"] == r)).sum()) for r in RQ.REASONS}
                                       for g in sorted(set(qd["group"]))},
                   "queue_parquet_sha256": CR.sha256_path(qdir / "queue.parquet"), "dir": str(qdir),
                   "policy_threshold": rcfg["policy"]["confidence_threshold"], "split_run": run.run_id}
            man["manifest_note"] = "the queue is what the operator sees: no ground-truth labels in it"
            CR.write_json(qdir / "manifest.json", man)
            qinfo[man["queue_id"]] = man
            run.log(f"  queue {man['queue_id']}: {man['n']:,} items (alerts {man['n_alert']:,}, random {man['n_random']:,} "
                    f"of {man['n_non_alerted']:,} non-alerted)")
        CR.write_json(run.res / "queue.json", qinfo)
        M["queues"] = qinfo
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
    L = [f"# Step 31 -- val-A / val-B split + runtime on val-A + review queue -- {st}" + (" (DRY RUN)" if dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    s = M.get("split")
    if s:
        L += ["## Split (docs/V2_PREREG_PHASE4.md section 1)", "",
              f"- val_A {s['n']['val_A']:,} flows, val_B {s['n']['val_B']:,} flows; split definition sha256 "
              f"`{s['split_definition_sha256'][:16]}...`",
              f"- val_B support {s['val_B_support']}; rare for the gate (< {s['min_val_flows']}): {s['rare_for_gate']}; "
              f"absent in val_B: {s['absent_in_val_B']}", "",
              "| session | extent lo | extent hi | midpoint | val flows |", "|---|---|---|---|---|"]
        for k, w in s["windows"].items():
            L.append(f"| {k} | {w['lo']:.0f} | {w['hi']:.0f} | {w['mid']:.1f} | {w['n']:,} |")
        L += ["", "Per class x group counts: `split.json`.", ""]
    p = M.get("parity")
    if p:
        L += ["## Runtime on val-A + parity", "",
              f"- runtime `{M['runtime']['dir']}`: {M['runtime']['counts'].get('flows_scored', 0):,} flows, "
              f"{M['runtime']['flows_per_s']:,.0f} flows/s, alerts {M['runtime']['counts'].get('flow_alerts', 0):,}, "
              f"incidents {M['runtime']['incidents']}",
              f"- parity: features identical {p.get('features_equal_rows', 0):,} / {p.get('n_runtime', 0):,}; class agree "
              f"{p.get('class_agree', 0):,}; max |dp| {p.get('max_abs_dp', float('nan')):.2e}; group {p.get('group_agree', 0):,}; "
              f"device {p.get('device_agree', 0):,}" + (f"; vs Phase 3 full run {p['vs_phase3_full_run']}"
                                                         if p.get("vs_phase3_full_run") else ""), ""]
    if M.get("queues"):
        L += ["## Review queues", "", "| queue | items | alerts | random | non-alerted | rate |", "|---|---|---|---|---|---|"]
        for q, m in M["queues"].items():
            L.append(f"| {q} | {m['n']:,} | {m['n_alert']:,} | {m['n_random']:,} | {m['n_non_alerted']:,} | {m['random_review_rate']} |")
        L.append("")
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
