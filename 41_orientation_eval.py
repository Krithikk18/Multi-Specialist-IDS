#!/usr/bin/env python
"""41_orientation_eval.py -- Phase 5B step D (docs/V2_PREREG_PHASE5B.md section 4): orientation robustness (H-C1),
real reversals, contamination. OFFLINE: val only; nothing registered.

Flip test: every val flow's forward / backward fields are swapped with the R3 normaliser's own mapping
(common/orientation.swap, all-true mask; its TCP-only guard applies). The context features are recomputed on the flipped
stream (common/context_features.compute_segments) and must equal the stored ones exactly; each arm x seed of step 40 then
predicts the flipped rows. Agreement = share of flows whose predicted class is unchanged; CTX_ONLY must be exactly 1.0
(else FAIL: the construction is broken). H-C1: HOLDS iff (GLOBAL_CTX - GLOBAL) agreement has a 95 % bootstrap CI lower
bound > 0 over seeds on all val flows AND on val benign flows.
Real reversals: the diag_03 B saved alert flows of hypothesis H1 (mode GLOBAL), each arm's error rate on exactly those
flows; an incident of B_incidents.csv (GLOBAL runs) is still false if any of its contributing flows is still
mispredicted by the same-seed arm. Contamination (report-only): a val benign flow whose host had >= 1 attack flow in its
causal contamination window; FA of each arm on contaminated vs clean benign.
Outputs: <cache>/orient/<run>/contaminated.npy; results/phase5b/41/ (orientation.json, summary.md, manifests).
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
from common import cl_retrain as RT
from common import context_config as CC
from common import context_features as CF
from common import orientation as O
from common import phase2_metrics as PM
from common import phase5b_eval as EV
from common import phase5b_run as PR
from common import schemas as S

SCRIPT = "41_orientation_eval.py"


def load_arm_model(rec: dict, mdir: Path):
    import xgboost as xgb
    p = Path(rec["file"]) if rec["reused"] else mdir / rec["file"]
    if PR.sha256_path(p) != rec["sha256"]:
        raise RuntimeError(f"{p}: sha256 != step 40 manifest")
    b = xgb.Booster()
    b.load_model(str(p))
    return b


def fa_subset(pred, y, mask, sess, ts, gap) -> dict:
    b = (np.asarray(y) == 0) & np.asarray(mask, bool)
    fa = int((b & (np.asarray(pred) != 0)).sum())
    h = PM.benign_hours(np.asarray(sess).astype(str), np.asarray(ts, np.int64), b, gap) if b.any() else 0.0
    return {"n_benign": int(b.sum()), "fa_count": fa, "fa_rate": fa / int(b.sum()) if b.any() else None,
            "benign_hours": float(h), "fa_per_hour": fa / h if h > 0 else None}


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
    run = PR.P5BRun("41", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest()
    PR.lock_banner(run, M, "start")
    M.update({"dataset_run": up39["meta"]["run_id"], "stage1_run": up40["meta"]["run_id"]})
    ok = False
    try:
        cm = S.load_class_map()
        names, K = list(cm.names), cm.n_classes
        FL = CC.load_feature_list()
        ctx = FL["context_features"]
        c, ev = cfg["columns"], cfg["eval"]
        gap = ev["benign_hours_idle_gap_s"]
        S40 = json.loads((up40["dir"] / "stage1.json").read_text(encoding="utf-8"))
        if S40["models_dir"] != up40["manifest"]["models_dir"]:
            raise RuntimeError("stage1.json and the step 40 manifest disagree")
        mdir = Path(up40["manifest"]["models_dir"])
        seeds, arms, AF = S40["seeds"], S40["arms"], S40["features"]
        va = PR.load_ctx_split(up39, "val")
        y = va[c["label_id"]].to_numpy(np.int64)
        sess = va[c["session"]].astype(str).to_numpy()
        ts = va[c["start"]].to_numpy(np.int64)
        uid = (va[c["session"]].astype(str) + ":" + va[c["row"]].astype(str)).to_numpy()
        run.check(M, "val rows == step 40's (uid sha256)", PR.sha256_bytes("\n".join(uid.tolist()).encode("utf-8")) ==
                  S40["data"]["val_uid_sha256"], f"{len(y):,}")
        omap = O.load_map(expected_sha256=S.ORIENTATION_MAP_SHA256)
        base_cols = [col for col in va.columns if col not in ctx + [cfg["context"]["warmup_column"]]]
        flipped = O.swap(va[base_cols], np.ones(len(va), bool), omap)
        guard = O._guard(va[base_cols], omap)                         # the normaliser's own TCP-only guard (read-only use)
        changed = int((flipped[S.feature_columns()].to_numpy() != va[S.feature_columns()].to_numpy()).any(1).sum())
        M["flip"] = {"rows": int(len(va)), "swapped_by_guard": int(guard.sum()), "not_swapped_non_tcp": int((~guard).sum()),
                     "rows_with_changed_flow_features": changed}
        run.log(f"  flip: {int(guard.sum()):,} of {len(va):,} val flows swapped (TCP guard; {int((~guard).sum()):,} "
                f"non-TCP unchanged); {changed:,} rows have changed flow features")
        F_orig, _, _ = CF.compute_segments(va[base_cols], cfg)
        F_flip, _, _ = CF.compute_segments(flipped, cfg)
        stored = va[ctx].to_numpy(np.float64)
        e1, e2 = bool(np.array_equal(F_orig, stored)), bool(np.array_equal(F_flip, stored))
        run.check(M, "context recomputed on the original val stream == stored (exact)", e1, "")
        run.check(M, "context recomputed on the FLIPPED val stream == stored (exact)", e2, "")
        if not (e1 and e2):
            raise RuntimeError("STOP: context features change under the flip; the construction is broken")
        Xf_all = flipped[S.feature_columns()].to_numpy(np.float32)
        Xc = stored.astype(np.float32)
        Xfull = np.ascontiguousarray(np.c_[Xf_all, Xc])                 # flipped flow features + unchanged context
        colix = {f: i for i, f in enumerate(FL["features"])}
        benign = y == 0
        A, preds = {}, {}
        for m in S40["models"]:
            a, s = m["arm"], int(m["seed"])
            b = load_arm_model(m, mdir)
            pf = mdir / m["pred_file"]
            if PR.sha256_path(pf) != m["pred_sha256"]:
                raise RuntimeError(f"{pf}: sha256 != step 40")
            p0 = np.load(pf).astype(np.int64)
            ix = [colix[f] for f in AF[a]]
            p1 = RT.predict_proba(b, np.ascontiguousarray(Xfull[:, ix]), cfg["stage1"]["nthread"]).argmax(1)
            preds[(a, s)] = p0
            A[(a, s)] = {"all": EV.flip_agreement(p0, p1), "benign": EV.flip_agreement(p0, p1, benign),
                         "tcp": EV.flip_agreement(p0, p1, guard), "tcp_benign": EV.flip_agreement(p0, p1, guard & benign),
                         "non_tcp": EV.flip_agreement(p0, p1, ~guard),
                         "per_class": {names[k]: EV.flip_agreement(p0, p1, guard & (y == k)) for k in range(K)
                                       if (guard & (y == k)).any()},
                         "n_changed": int((p0 != p1).sum())}
            run.log(f"  {a:<16} s{s}: agreement TCP {A[(a, s)]['tcp']:.6f}, TCP benign {A[(a, s)]['tcp_benign']:.6f}, "
                    f"non-TCP {A[(a, s)]['non_tcp']:.6f} (by construction), changed {A[(a, s)]['n_changed']:,}")
        ctx_only = [A[("CTX_ONLY", s)]["all"] for s in seeds]
        run.check(M, "CTX_ONLY flip agreement == 1.0 exactly (every seed)", all(v == 1.0 for v in ctx_only), f"{ctx_only}")
        if not all(v == 1.0 for v in ctx_only):
            raise RuntimeError("STOP: CTX_ONLY flip agreement < 1.0 -- the construction is broken (do not tune)")
        H1 = EV.h_c1([A[("GLOBAL_CTX", s)]["tcp"] for s in seeds], [A[("GLOBAL", s)]["tcp"] for s in seeds],
                     [A[("GLOBAL_CTX", s)]["tcp_benign"] for s in seeds], [A[("GLOBAL", s)]["tcp_benign"] for s in seeds], ev)
        H1["scope"] = "TCP flows only (the normaliser's TCP guard); non-TCP agreement is 1 by construction, not evidence"
        run.log(f"  H-C1 (TCP): {H1['verdict']}  TCP d {H1['all']['mean']:+.6f} [{H1['all']['lo']:+.6f}, {H1['all']['hi']:+.6f}]; "
                f"TCP benign d {H1['benign']['mean']:+.6f} [{H1['benign']['lo']:+.6f}, {H1['benign']['hi']:+.6f}]")
        # ---------------------------------------------------------------- real reversals (diag_03 B)
        fl = cfg["flip"]
        src = REPO_ROOT / fl["reversal_source"]
        RR = {"available": src.is_file()}
        if src.is_file():
            Bf = pd.read_csv(src)
            Bi = pd.read_csv(REPO_ROOT / fl["incidents_source"])
            RR["source_sha256"] = PR.sha256_path(src)
            RR["incidents_sha256"] = PR.sha256_path(REPO_ROOT / fl["incidents_source"])
            pos = {u: i for i, u in enumerate(uid)}
            h1 = Bf[(Bf["hypothesis"] == fl["reversal_hypothesis"])]
            u1 = sorted(set(h1["flow_uid"]))
            ix = np.array([pos.get(u, -1) for u in u1])
            RR["h1_flows"] = len(u1)
            RR["h1_flows_in_val"] = int((ix >= 0).sum())
            ix = ix[ix >= 0]
            truth = y[ix]
            RR["arms"] = {}
            g = Bf[Bf["mode"] == "GLOBAL"]
            for a in arms:
                per = {}
                for s in seeds:
                    p = preds[(a, s)]
                    err = float((p[ix] != truth).mean()) if len(ix) else None
                    inc = Bi[(Bi["mode"] == "GLOBAL") & (Bi["seed"] == s)]
                    still = 0
                    for _, r in inc.iterrows():
                        fu = g[(g["run"] == r["run"]) & (g["incident_id"] == r["incident_id"])]["flow_uid"]
                        jj = np.array([pos[u] for u in fu if u in pos])
                        if len(jj) and (preds[(a, s)][jj] != y[jj]).any():
                            still += 1
                    per[str(s)] = {"error_rate": err, "errors": int((p[ix] != truth).sum()), "incidents": int(len(inc)),
                                   "incidents_still_false": still}
                RR["arms"][a] = per
            run.log(f"  real reversals: {RR['h1_flows_in_val']} H1 flows; error rate per arm (seed mean) "
                    + ", ".join(f"{a} {np.mean([RR['arms'][a][str(s)]['error_rate'] for s in seeds]):.3f}" for a in arms))
        # ---------------------------------------------------------------- contamination
        wcont = int(ev["contamination_window_s"])
        if wcont not in cfg["context"]["windows_s"]:
            raise RuntimeError(f"contamination window {wcont} s is not a context window {cfg['context']['windows_s']}")
        Fatt, _, _ = CF.compute_segments(va[base_cols], cfg, insert_mask=(y != 0))
        jn = CC.context_feature_names(cfg).index(f"{cfg['context']['prefix']}_hostmax_n_flows_{wcont}s")
        cont = benign & (Fatt[:, jn] >= 1)
        odir = run.cache_dir("orient")
        np.save(odir / "contaminated.npy", cont)
        CT = {"window_s": wcont, "n_benign": int(benign.sum()), "contaminated": int(cont.sum()),
              "share": float(cont.sum() / max(1, benign.sum())), "file": str(odir / "contaminated.npy"),
              "file_sha256": PR.sha256_path(odir / "contaminated.npy"), "arms": {}}
        for a in arms:
            CT["arms"][a] = {str(s): {"contaminated": fa_subset(preds[(a, s)], y, cont, sess, ts, gap),
                                      "clean": fa_subset(preds[(a, s)], y, benign & ~cont, sess, ts, gap)} for s in seeds}
        run.log(f"  contamination: {CT['contaminated']:,} of {CT['n_benign']:,} val benign flows ({CT['share']:.4f})")
        out = {"flip": M["flip"], "agreement": {f"{a}|{s}": v for (a, s), v in A.items()}, "h_c1": H1,
               "real_reversals": RR, "contamination": CT, "seeds": seeds, "arms": arms, "names": names}
        PR.write_json(run.res / "orientation.json", out)
        M.update({"h_c1": H1["verdict"], "contamination_file": CT["file"], "contamination_sha256": CT["file_sha256"]})
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
    L = [f"# Step 41 -- orientation robustness (H-C1), real reversals, contamination -- {st}" + (" (DRY RUN)" if run.dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    p = run.res / "orientation.json"
    if p.exists():
        O_ = json.loads(p.read_text(encoding="utf-8"))
        H = O_["h_c1"]
        L += [f"- flip: {O_['flip']}", "",
              f"- **H-C1 ({H['scope']}): {H['verdict']}** -- agreement GLOBAL_CTX - GLOBAL, TCP flows {H['all']['mean']:+.6f} "
              f"[{H['all']['lo']:+.6f}, {H['all']['hi']:+.6f}] (lo > 0: {H['all_ok']}); TCP benign {H['benign']['mean']:+.6f} "
              f"[{H['benign']['lo']:+.6f}, {H['benign']['hi']:+.6f}] (lo > 0: {H['benign_ok']})", "",
              "| arm | seed | TCP | TCP benign | TCP per class | non-TCP (by construction) | all | flows changed |",
              "|---|---|---|---|---|---|---|---|"]
        for k, v in O_["agreement"].items():
            a, s = k.split("|")
            L.append(f"| {a} | {s} | {v['tcp']:.6f} | {v['tcp_benign']:.6f} | "
                     + ", ".join(f"{n} {x:.6f}" for n, x in v["per_class"].items())
                     + f" | {v['non_tcp']:.6f} | {v['all']:.6f} | {v['n_changed']:,} |")
        RR = O_["real_reversals"]
        L += ["", f"- real reversals (diag_03 B, H1): available {RR['available']}" +
              (f", {RR['h1_flows_in_val']} flows" if RR["available"] else ""), ""]
        if RR.get("arms"):
            L += ["| arm | seed | error rate on H1 flows | errors | diag_03 incidents still false |", "|---|---|---|---|---|"]
            for a, per in RR["arms"].items():
                for s, v in per.items():
                    L.append(f"| {a} | {s} | {v['error_rate']:.4f} | {v['errors']} | {v['incidents_still_false']} / {v['incidents']} |")
        CT = O_["contamination"]
        L += ["", f"- contamination ({CT['window_s']} s): {CT['contaminated']:,} of {CT['n_benign']:,} val benign flows "
              f"({CT['share']:.4f})", "", "| arm | seed | FA contaminated (n) | FA clean (n) | FA/h clean |", "|---|---|---|---|---|"]
        for a, per in CT["arms"].items():
            for s, v in per.items():
                cc, cl = v["contaminated"], v["clean"]
                L.append(f"| {a} | {s} | {cc['fa_count']} ({cc['n_benign']:,}) | {cl['fa_count']} ({cl['n_benign']:,}) | "
                         f"{cl['fa_per_hour'] if cl['fa_per_hour'] is None else round(cl['fa_per_hour'], 3)} |")
        L.append("")
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
