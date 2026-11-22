#!/usr/bin/env python
"""32_simulate_labels.py -- Phase 4 step C (+ the label batches of steps G1 / G2; docs/V2_PREREG_PHASE4.md sections
3, 9-11). VAL only.

Reads the step 31 queues (sha256-checked) and the ground truth of the queued flows (v2_1 val label_id by flow uid),
then writes Ed25519-signed, append-only label batches (common/label_store.py, operator key ~/lgids_cache/keys/operator/,
created if absent, never in the repo) and runs the pre-registered validator (common/cl_validator.py) on each:
  <cache>/labels/                 <run>__primary          noise 0, unlimited budget (the only batch the primary arms read)
  <cache>/labels_experiments/     <run>__<sweep name>     report-only sweeps (noise 0.02; budget 1,000 / 10,000)
                                  <run>__no_random        the alerts-only queue (feedback-bias test)
  <cache>/labels_poison_test/     <run>__P1, <run>__P2    poisoned copies of the primary batch (insider model: signed)
Live tamper check (hard): a copy of the primary batch with one label edited, and one without its signature, are refused
by load_batch. Outputs: <cache>/validation/<run>/<batch>.json; results/phase4/32/ summary.md, batches.json,
validation.json, run_manifest.json, run_meta.json, run.log. --dry-run: needs --queue-run <dry step 31 run id>.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import REPO_ROOT
from common import cl_config as CC
from common import cl_gate as CG
from common import cl_run as CR
from common import cl_validator as CV
from common import label_store as LS
from common import operator_sim as OP
from common import phase2_data as D
from common import schemas as S
from common.phase2_config import load_phase2_config

SCRIPT = "32_simulate_labels.py"
STORES = {"primary": "labels", "experiments": "labels_experiments", "poison": "labels_poison_test"}


def load_queue(qdir: Path) -> tuple[pd.DataFrame, dict]:
    man = json.loads((qdir / "manifest.json").read_text(encoding="utf-8"))
    if CR.sha256_path(qdir / "queue.parquet") != man["queue_parquet_sha256"]:
        raise RuntimeError(f"{qdir}/queue.parquet sha256 != its manifest")
    return pd.read_parquet(qdir / "queue.parquet"), man


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--queue-run", default=None, help="step 31 run id (default: the full run in results/phase4/31/)")
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg4 = CC.load_phase4_config()
    up31 = CR.resolve("31", args.queue_run, args.dry_run)
    run = CR.Run("32", SCRIPT, cfg4, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest()
    CR.lock_banner(run, M, "start")
    M["queue_run"] = up31["meta"]["run_id"]
    ok = False
    try:
        cm = S.load_class_map()
        names, K = list(cm.names), cm.n_classes
        cfg2 = load_phase2_config(REPO_ROOT / cfg4["phase2_config"])
        q31 = up31["manifest"]["queues"]
        qid = up31["meta"]["run_id"]
        Qp, Mp = load_queue(Path(q31[qid]["dir"]))
        Qn, Mn = load_queue(Path(q31[f"{qid}__no_random"]["dir"]))
        run.check(M, "queues sha256-checked against their manifests", True, f"primary {len(Qp):,}, no_random {len(Qn):,}")
        va = D.load_split(cfg2, "val", ["session", "row_in_file", "label_id", "group"], sample=args.dry_run)
        truth = dict(zip((va["session"].astype(str) + ":" + va["row_in_file"].astype(str)), va["label_id"].astype(int)))
        miss = [u for u in Qp["flow_uid"] if u not in truth]
        run.check(M, "every queued flow has a ground-truth label", not miss, f"missing {len(miss)}")
        split = up31["manifest"]["split"]
        nonrare = [k for k in range(K) if split["val_B_support"][names[k]] >= cfg4["gate"]["min_val_flows"]]
        secret, public = LS.ensure_operator_keys(CC.expand(cfg4["paths"]["operator_keys_dir"]), REPO_ROOT)
        M["operator_key_fingerprint"] = LS.REG.fingerprint(public)
        run.check(M, "operator key outside the repository (created if absent, file 600)", True,
                  f"fingerprint {M['operator_key_fingerprint']}")
        op = cfg4["operator"]
        roots = {k: run.cache / v for k, v in STORES.items()}
        batches, vals = {}, {}
        vdir = run.cache_dir("validation")

        def make(Q: pd.DataFrame, Qman: dict, name: str, store: str, noise: float, budget, label_override=None,
                 extra: dict | None = None):
            t = np.array([truth[u] for u in Q["flow_uid"]], dtype=np.int64)
            L = OP.simulate(t, Q["reason"].to_numpy(object), K, noise=noise, budget=budget, seed=op["seed"])
            sel = L["sel"]
            lab = L["label"] if label_override is None else label_override
            rows = LS.make_rows(Q["flow_uid"].to_numpy()[sel], Q["flow_id"].to_numpy()[sel], Q["start_ts"].to_numpy()[sel],
                                Qman["runtime_run_id"], lab, Q["reason"].to_numpy()[sel], op["operator_id"], names)
            bid = f"{run.run_id}__{name}"
            prov = {"queue_id": Qman["queue_id"], "queue_manifest_sha256": CR.sha256_path(Path(Qman["dir"]) / "manifest.json"),
                    "runtime_run_id": Qman["runtime_run_id"], "operator": "simulated from ground truth (Phase 4)",
                    "noise": noise, "budget": budget, "seed": op["seed"], "script": SCRIPT, "run_id": run.run_id,
                    **(extra or {})}
            W = LS.write_batch(roots[store], bid, rows, secret, prov, names, cm.sha256)
            acc = float((lab == t[sel]).mean()) if len(sel) else float("nan")
            info = {"batch_id": bid, "store": store, "root": str(roots[store]), "dir": W["dir"],
                    "manifest_sha256": W["manifest_sha256"], "parquet_sha256": W["manifest"]["files"]["labels.parquet"],
                    "rows_sha256": W["manifest"]["rows_sha256"], "n": int(len(sel)), "n_alert": L["n_alert"],
                    "n_random": L["n_random"], "noise": noise, "budget": budget, "label_accuracy_vs_truth": acc,
                    "n_flipped_by_noise": int(L["flipped"].sum()), "counts_per_class": W["manifest"]["counts_per_class"],
                    "counts_per_reason": W["manifest"]["counts_per_reason"], "queue_id": Qman["queue_id"], **(extra or {})}
            deployed = {"flow_uid": Q["flow_uid"].tolist(), "pred": Q["pred"].to_numpy(np.int64),
                        "pmax": Q["pmax"].to_numpy(np.float64)}
            V = CV.validate_batch(roots[store], bid, public, names, deployed, cfg4["validator"])
            CR.write_json(vdir / f"{bid}.json", V)
            batches[name], vals[name] = info, V
            run.log(f"  batch {bid}: {info['n']:,} labels ({info['counts_per_class']}), accuracy {acc:.4f} -> "
                    f"{V['status']} {V['fired'] or ''}")
            return info, V, sel, t

        _, Vp, sel_p, t_p = make(Qp, Mp, "primary", "primary", op["primary"]["noise"], op["primary"]["budget"])
        run.check(M, "primary batch validator result (report)", Vp["status"] == CV.VALID,
                  f"{Vp['status']}; fired {Vp['fired']}; (c) {Vp['checks']['c_confident_disagreement']}", warn=True)
        for sw in op["sweeps"]:
            make(Qp, Mp, sw["name"], "experiments", sw["noise"], sw["budget"])
        make(Qn, Mn, "no_random", "experiments", 0.0, None)
        # ---- poisoned copies of the primary batch (section 9)
        lab_p = t_p[sel_p] if op["primary"]["noise"] == 0 else None
        if lab_p is None:
            raise RuntimeError("poisoning is defined on the noise-0 primary batch")
        tg = CG.poison_targets(lab_p, K, nonrare, benign_id=0)
        M["poison_targets"] = {"p1": names[tg["p1"]] if tg["p1"] is not None else None,
                               "p2": names[tg["p2"]] if tg["p2"] is not None else None,
                               "batch_counts": {names[k]: int(n) for k, n in enumerate(tg["counts"])},
                               "nonrare_val_B": [names[k] for k in nonrare]}
        po = cfg4["poisoning"]
        for pname, target, frac in (("P1", tg["p1"], po["p1_flip_frac"]), ("P2", tg["p2"], po["p2_flip_frac"])):
            if target is None:
                run.log(f"  {pname}: no target class in the batch -- not built")
                continue
            newlab, flipped = CG.flip_labels(lab_p, target, 0, frac, po["seed"])
            make(Qp, Mp, pname, "poison", 0.0, None, label_override=newlab,
                 extra={"poison": {"target_class": names[target], "flipped_to": names[0], "flip_frac": frac,
                                   "n_flipped": int(flipped.sum()), "n_target": int((lab_p == target).sum())}})
        # ---- live tamper checks (store refuses edited / unsigned copies)
        tdir = run.cache_dir("tamper_test")
        bp = batches["primary"]["batch_id"]
        for case in ("edited_label", "no_signature"):
            root_t = tdir / case
            root_t.mkdir()
            shutil.copytree(Path(roots["primary"]) / bp, root_t / bp)
            shutil.copyfile(Path(roots["primary"]) / LS.INDEX, root_t / LS.INDEX)
            if case == "edited_label":
                df = pd.read_parquet(root_t / bp / "labels.parquet")
                i0 = 0
                df.loc[i0, "label_id"] = (int(df.loc[i0, "label_id"]) + 1) % K
                df.loc[i0, "label"] = names[int(df.loc[i0, "label_id"])]
                (root_t / bp / "labels.parquet").unlink()
                df.to_parquet(root_t / bp / "labels.parquet", index=False)
            else:
                (root_t / bp / "manifest.sig").unlink()
            try:
                LS.load_batch(root_t, bp, public, names)
                refused, why = False, "loaded (!)"
            except LS.LabelStoreRefused as e:
                refused, why = True, str(e)
            run.check(M, f"label store refuses a tampered copy ({case})", refused, why[:160])
        M["batches"], M["validation"] = batches, {k: {"status": v["status"], "fired": v["fired"]} for k, v in vals.items()}
        CR.write_json(run.res / "batches.json", batches)
        CR.write_json(run.res / "validation.json", vals)
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
    L = [f"# Step 32 -- simulated operator, signed label batches, validator -- {st}" + (" (DRY RUN)" if dry else ""), "",
         f"- queue run `{M.get('queue_run')}`; operator key fingerprint `{M.get('operator_key_fingerprint')}` "
         "(~/lgids_cache/keys/operator/, outside the repo)", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("batches"):
        L += ["## Label batches", "", "| batch | store | labels | alert / random | accuracy vs truth | per class | validator | fired |",
              "|---|---|---|---|---|---|---|---|"]
        for k, b in M["batches"].items():
            v = M["validation"][k]
            L.append(f"| {b['batch_id']} | {b['store']} | {b['n']:,} | {b['n_alert']:,} / {b['n_random']:,} | "
                     f"{b['label_accuracy_vs_truth']:.4f} | {b['counts_per_class']} | {v['status']} | {', '.join(v['fired']) or '-'} |")
        L += ["", f"- poisoning targets: {M.get('poison_targets')}", "",
              "Validator details (check (c): confident items, disagreements, rate): `validation.json`.", ""]
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
