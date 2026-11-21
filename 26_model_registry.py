#!/usr/bin/env python
"""26_model_registry.py -- Phase 2 step 6: register the seed-0 primary models as CANDIDATE in the signed registry
(common/registry.py). No data is read.

  register   (this run) for every primary model of the step 22 run at seed registry.register_seed: copy the model
             file and its step 24 temperature calibrator into <registry_root>/<model_id>__s<seed>__<train run>/, write a
             manifest (class_map / features / dataset / prereg / config hashes, seed, file hashes, step 23 val metrics)
             and sign it (Ed25519, key in <keys_dir>, created if absent, outside the repo). State: candidate. Then
             proves the runtime guard: load_model refuses the candidate (not promoted) and accepts it only with
             allow_states=("candidate",) (offline evaluation).
  transition --entry <dir> --to approved|promoted
             the author's MANUAL approval / promotion step (signed state record). Never run by the pipeline.
  verify     signature, file hashes and state of every entry.
Runs 22 / 23 / 24 must chain (23 and 24 evaluated / calibrated the same step 22 run). Outputs: registry entries,
~/lgids_cache/v2/registry_runs/<run_id>/run_manifest.json, results/26/ (run_meta.json, run.log, summary.md with the
registry table; no figures). --dry-run: registry_dry_run, dry upstream runs (ids required).
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from config.config import REPO_ROOT
from common import phase2_data as D
from common import phase2_run as R
from common import registry as REG
from common import schemas as S
from common import amendment as A
from common.phase2_config import config_from_arg, expand

SCRIPT = "26_model_registry.py"


def registry_root(cfg: dict, dry: bool) -> Path:
    r = expand(cfg["paths"]["registry_root"])
    return r.with_name(r.name + "_dry_run") if dry else r


def metrics_for(summary: dict, model_id: str, names: list[str]) -> dict:
    a = summary["entities"][model_id]["all"]
    pick = lambda x: {k: x[k] for k in ("mean", "lo", "hi")}  # noqa: E731
    return {"eval_set": "the model's own val set (pooled rule)", "n": a["n"], "support": a["support"],
            "macro_f1_all": pick(a["macro_f1_all"]), "macro_f1_nonrare": pick(a["macro_f1_nonrare"]),
            "mcc": pick(a["mcc"]), "recall": {n: pick(a["recall"][c]) for c, n in enumerate(names)},
            "fa_per_hour_seed0": a["seed0"]["fa_per_hour"], "fa_per_hour_seed0_ci": a["seed0"]["fa_per_hour_ci"],
            "rare_classes": [names[c] for c in a["rare_classes"]], "ci": "mean and 95 % t-CI over the 5 seeds"}


def cmd_register(args, cfg) -> int:
    S.verify_v2_lock(strict=True)
    cm = S.load_class_map()
    names = list(cm.names)
    up22 = R.resolve_run("22", args.train_run, args.dry_run, R.results_root(cfg))
    up23 = R.resolve_run("23", args.eval_run, args.dry_run, R.results_root(cfg))
    up24 = R.resolve_run("24", args.calib_run, args.dry_run, R.results_root(cfg))
    ch = A.chosen(cfg, up22["manifest"], up23)
    ctx = R.start_run("26", "registry_runs", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT)
    tr = up22["meta"]["run_id"]
    M.update({"train_run": tr, "eval_run": up23["meta"]["run_id"], "calib_run": up24["meta"]["run_id"],
              "registry_root": str(registry_root(cfg, args.dry_run)), "entries": [], "warnings": []})
    ok = False
    try:
        R.add_check(ctx, M, "runs chain: steps 23 and 24 used this step 22 run",
                    up23["manifest"]["train_run"] == tr and up24["manifest"]["train_run"] == tr,
                    f"22 {tr}; 23 -> {up23['manifest']['train_run']}; 24 -> {up24['manifest']['train_run']}")
        secret, public = REG.ensure_keys(expand(cfg["paths"]["keys_dir"]), REPO_ROOT)
        R.add_check(ctx, M, "signing key outside the repository (created if absent, mode 600)", True,
                    f"fingerprint {REG.fingerprint(public)}, backend {REG.BACKEND}")
        summary = json.loads((up23["dir"] / "metrics_summary.json").read_text(encoding="utf-8"))
        dm = D.load_dataset_manifest(cfg)
        M22 = up22["manifest"]
        seed = cfg["registry"]["register_seed"]
        serves = {}
        for g, mid in ch["routing"].items():
            serves.setdefault(mid, []).append(g)
        root = registry_root(cfg, args.dry_run)
        if A.active(cfg):
            M["primary"] = {k: v for k, v in ch.items() if k != "selection"}
        for s in [x for x in M22["specs"] if x["config"] == ch["config_label"]]:
            m = next(x for x in M22["models"] if x["model_id"] == s["model_id"] and x["seed"] == seed)
            mfile = up22["dir"] / m["file"]
            cfile = up24["dir"] / f"{m['key']}.temperature.json"
            cal = json.loads(cfile.read_text(encoding="utf-8"))
            R.add_check(ctx, M, f"{m['key']}: model sha256 == step 22 manifest == calibrator's model_sha256",
                        R.sha256_path(mfile) == m["sha256"] == cal["model_sha256"], m["sha256"][:16] + "...")
            entry_id = f"{s['model_id']}__s{seed}__{tr}"
            fields = {"model_id": s["model_id"], "model_key": m["key"], "seed": seed, "kind": s["kind"],
                      "serves_groups": serves.get(s["model_id"], []), "class_names": names,
                      "class_map_sha256": S.CLASS_MAP_SHA256, "features_file_sha256": S.FEATURES_V1_SHA256,
                      "features_list_sha256": S.FEATURES_V1_LIST_SHA256, "dataset_version": cfg["dataset_version"],
                      "dataset_manifest_sha256": dm["_sha256"], "prereg_phase2_sha256": S.PREREG_PHASE2_SHA256,
                      "config_sha256": cfg["_sha256"], "train_run": tr, "train_run_manifest_sha256": up22["manifest_sha256"],
                      "eval_run": up23["meta"]["run_id"], "eval_run_manifest_sha256": up23["manifest_sha256"],
                      "calib_run": up24["meta"]["run_id"], "calib_run_manifest_sha256": up24["manifest_sha256"],
                      "temperature": cal["temperature"], "best_iteration": m["best_iteration"],
                      "training_counts": m["counts"], "class_weights": m["class_weights"],
                      "val_metrics": metrics_for(summary, s["model_id"], names),
                      "runtime_contract": "P = softmax(margin(model.ubj, 70 features in features_v1 order, float32) / temperature)"}
            if A.active(cfg):                                          # Amendment 1 tags (absent for v2_0 entries)
                fields.update({"prereg_amendment_1_sha256": S.PREREG_PHASE2_AMENDMENT_1_SHA256,
                               "orientation_map_sha256": S.ORIENTATION_MAP_SHA256,
                               "primary_selection": {"weights": ch["weights"], "config_label": ch["config_label"],
                                                     "source": ch["source"]},
                               "runtime_contract": fields["runtime_contract"] + "; flows normalised first with "
                                                   "common/orientation.normalise_flow (rule R3, map sha256 above)"})
            d = REG.register(root, entry_id, mfile, cfile, fields, secret)
            st = REG.read_state(d, public)
            ok_off = REG.load_model(d, public, S.CLASS_MAP_PATH, S.FEATURES_PATH, allow_states=("candidate",))
            try:
                REG.load_model(d, public, S.CLASS_MAP_PATH, S.FEATURES_PATH)
                refused = False
            except REG.RegistryRefused:
                refused = True
            R.add_check(ctx, M, f"{entry_id}: registered as candidate; runtime load refused, offline load allowed",
                        st == "candidate" and refused and ok_off["state"] == "candidate", str(d))
            M["entries"].append({"entry_id": entry_id, "dir": str(d), "state": st, "model_id": s["model_id"],
                                 "serves_groups": fields["serves_groups"], "model_sha256": m["sha256"],
                                 "temperature": cal["temperature"], "macro_f1_all": fields["val_metrics"]["macro_f1_all"],
                                 "macro_f1_nonrare": fields["val_metrics"]["macro_f1_nonrare"],
                                 "fingerprint": REG.fingerprint(public)})
            ctx.log(f"  registered {entry_id} (candidate)")
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["status"] = "PASS" if ok else "FAIL"
    L = [f"# Step 26 -- model registry -- {M['status']}" + (" (DRY RUN)" if args.dry_run else ""), "",
         f"- run `{ctx.run_id}`; models of step 22 run `{M['train_run']}`, metrics of step 23 run `{M['eval_run']}`, "
         f"calibrators of step 24 run `{M['calib_run']}`", f"- registry root `{M['registry_root']}`; signature Ed25519 "
         f"({REG.BACKEND}); key outside the repo", "- every entry is **candidate**: approval and promotion are the author's "
         "manual steps (`26_model_registry.py transition --entry <dir> --to approved|promoted`); load_model refuses "
         "anything not promoted unless offline evaluation explicitly allows it."]
    if M.get("primary"):
        L.append(f"- Amendment 1: registered weighting `{M['primary']['weights']}` ({M['primary']['source']}); entries "
                 f"tagged with dataset `{cfg['dataset_version']}`, amendment sha256 "
                 f"`{S.PREREG_PHASE2_AMENDMENT_1_SHA256[:16]}...`, orientation map sha256 `{S.ORIENTATION_MAP_SHA256[:16]}...`")
    L += [""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    L += ["## Registry", "", "| entry | state | serves | model sha256 | temperature | macro-F1 all (own val set) | "
          "macro-F1 non-rare | signer |", "|---|---|---|---|---|---|---|---|"]
    for e in M["entries"]:
        f = lambda a: f"{a['mean']:.4f} [{a['lo']:.4f}, {a['hi']:.4f}]"  # noqa: E731
        L.append(f"| {e['entry_id']} | {e['state']} | {', '.join(e['serves_groups']) or '-'} | {e['model_sha256'][:16]}... | "
                 f"{e['temperature']:.4f} | {f(e['macro_f1_all'])} | {f(e['macro_f1_nonrare'])} | {e['fingerprint']} |")
    L += ["", "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M["checks"]]
    (ctx.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def cmd_transition(args, cfg) -> int:
    secret, _ = REG.ensure_keys(expand(cfg["paths"]["keys_dir"]), REPO_ROOT)
    rec = REG.transition(Path(args.entry), args.to, secret, by=args.by)
    print(f"{args.entry}: now {rec['state']} ({rec['utc']})")
    return 0


def cmd_verify(args, cfg) -> int:
    _, public = REG.ensure_keys(expand(cfg["paths"]["keys_dir"]), REPO_ROOT)
    root = registry_root(cfg, args.dry_run)
    bad = 0
    for d in sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []:
        try:
            REG.verify_entry(d, public)
            print(f"  OK    {d.name}  state {REG.read_state(d, public)}")
        except REG.RegistryRefused as e:
            bad += 1
            print(f"  FAIL  {d.name}  {e}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("register")
    for a in ("--train-run", "--eval-run", "--calib-run", "--run-id"):
        r.add_argument(a, default=None)
    r.add_argument("--dry-run", action="store_true")
    t = sub.add_parser("transition", help="MANUAL approval / promotion (author only)")
    t.add_argument("--entry", required=True)
    t.add_argument("--to", required=True, choices=["approved", "promoted"])
    t.add_argument("--by", required=True, help="who approves / promotes")
    v = sub.add_parser("verify")
    v.add_argument("--dry-run", action="store_true")
    for p in (r, t, v):
        p.add_argument("--config", default=None, help="Phase 2 config file (default config/v2_phase2.json)")
    args = ap.parse_args(sys.argv[1:] or ["register"])
    cfg = config_from_arg(getattr(args, "config", None))
    return {"register": cmd_register, "transition": cmd_transition, "verify": cmd_verify}[args.cmd or "register"](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
