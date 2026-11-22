#!/usr/bin/env python
"""42_context_zeroday.py -- Phase 5B step E (docs/V2_PREREG_PHASE5B.md section 5): H-C2 fingerprint independence and
H-C3 zero-day with context. OFFLINE: train benign + val only; nothing registered.

H-C2 (from step 40): Δ_flow = GLOBAL_NOFP - GLOBAL, Δ_ctx = GLOBAL_CTX_NOFP - GLOBAL_CTX recall per seed; HOLDS for the
pre-registered class iff (Δ_ctx - Δ_flow) has a 95 % bootstrap CI lower bound > 0; every attack class reported.
H-C3: Stage 1 misses = the Phase 5A LOAO predictions (70-feature Stage 1; runs pinned in the config; sha256 checked,
mapped to these val rows by uid). Primary model of normal CTX_TAIL_GLOBAL (D165; common/tail_rule.py: per-feature
upper-tail rule on the 44 raw context features, one shared q calibrated on held-out train benign). HOLDS iff the lower CI
bound of mean miss-recall over eligible pairs >= recall_lo_min AND the upper CI bound of its val FA / h <= the Phase 5A
GLOBAL_NORMAL mean FA / h. Report-only: CTX_IF_GLOBAL (the pinned 5A IsolationForest recipe on the 44 context features),
CTX_TAIL_PER_GROUP (not a routing claim -- D163), FLOWCTX_TAIL_GLOBAL (70 + 44), detector alone on all held-out flows,
combined system, drift per group, the firing features, contaminated vs clean FA (step 41's mask), and the out-of-range
diagnostic (share of flows with a context feature above the train-benign maximum).
Outputs: <cache>/normal/<run>/ (tail rules json, IF joblib models, manifest), results/phase5b/42/ (zeroday.json,
summary.md, manifests).
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

import numpy as np

from config.config import REPO_ROOT, RESULTS_DIR
from common import context_config as CC
from common import normal_model as NM
from common import phase2_data as D
from common import phase2_metrics as PM
from common import phase5b_eval as EV
from common import phase5b_run as PR
from common import schemas as S
from common import tail_rule as TR
from common import zeroday_config as ZC
from common import zeroday_metrics as ZM
from common import zeroday_run as ZR
from common.phase2_config import load_phase2_config

SCRIPT = "42_context_zeroday.py"
PRIMARY = "CTX_TAIL_GLOBAL"


def hist(v, edges):
    return np.histogram(v, edges)[0].tolist()


def tail_score(X, t):
    """max_j (x_j + 1) / (t_j + 1): > 1 iff the rule fires (context features are >= 0); for the figure only."""
    return ((np.asarray(X, float) + 1.0) / (np.asarray(t, float)[None, :] + 1.0)).max(1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    ap.add_argument("--dataset-run", default=None)
    ap.add_argument("--stage1-run", default=None)
    ap.add_argument("--orient-run", default=None)
    args = ap.parse_args()
    cfg = CC.load_phase5b_config()
    up39 = PR.resolve("39", args.dataset_run, args.dry_run)
    up40 = PR.resolve("40", args.stage1_run, args.dry_run)
    up41 = PR.resolve("41", args.orient_run, args.dry_run)
    run = PR.P5BRun("42", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/zeroday_config.py"])
    PR.lock_banner(run, M, "start")
    M.update({"dataset_run": up39["meta"]["run_id"], "stage1_run": up40["meta"]["run_id"], "orient_run": up41["meta"]["run_id"]})
    ok = False
    try:
        cm = S.load_class_map()
        names, K = list(cm.names), cm.n_classes
        FL = CC.load_feature_list()
        ctx, flow = FL["context_features"], S.feature_columns()
        c, ev, zd, tp = cfg["columns"], cfg["eval"], cfg["zeroday"], cfg["tail"]
        gap = ev["benign_hours_idle_gap_s"]
        # ---------------------------------------------------------------- H-C2 (step 40 numbers)
        S40 = json.loads((up40["dir"] / "stage1.json").read_text(encoding="utf-8"))
        A40 = S40["all"]
        HC2 = {}
        for k in range(1, K):
            n = names[k]
            if not A40["GLOBAL"]["support"][n]:
                continue
            HC2[n] = EV.h_c2({a: A40[a]["recall"][n] for a in ("GLOBAL", "GLOBAL_NOFP", "GLOBAL_CTX", "GLOBAL_CTX_NOFP")}, ev)
            HC2[n]["rare"] = A40["GLOBAL"]["support"][n] < ev["min_val_flows"]
        k2 = cfg["stage1"]["h_c2_class"]
        if k2 not in HC2:
            raise RuntimeError(f"h_c2_class {k2!r} has no val support / is not in the class map")
        run.log(f"  H-C2 ({k2}): {HC2[k2]['verdict']}  Δ_flow {np.mean(HC2[k2]['delta_flow']):+.4f}, Δ_ctx "
                f"{np.mean(HC2[k2]['delta_ctx']):+.4f}, Δ_ctx - Δ_flow {HC2[k2]['diff']['mean']:+.4f} "
                f"[{HC2[k2]['diff']['lo']:+.4f}, {HC2[k2]['diff']['hi']:+.4f}]")
        # ---------------------------------------------------------------- Phase 5A inputs (loaded, sha256 checked)
        p5 = ZC.load_phase5_config()
        P = p5["normal_model"]
        runs5 = zd["phase5a_runs"]
        up36 = ZR.resolve("36", runs5["36"], False)
        M36 = up36["manifest"]
        e38 = RESULTS_DIR / "phase5a" / "38" / "eval.json"
        E5 = json.loads(e38.read_text(encoding="utf-8"))
        if E5["runs"]["38"] != runs5["38"] or E5["runs"]["36"] != runs5["36"]:
            raise RuntimeError(f"{e38}: runs {E5['runs']} != config {runs5}")
        fa_ref = float(np.mean([E5["fa"]["GLOBAL_NORMAL"][str(s)]["fa_per_hour"] for s in E5["seeds"]]))
        M["phase5a"] = {"runs": runs5, "eval_json_sha256": PR.sha256_path(e38), "fa_ref_global_normal_mean": fa_ref,
                        "if_params": P, "phase5_config_sha256": p5["_sha256"]}
        cfg2 = load_phase2_config(REPO_ROOT / cfg["phase2_config"])
        v21 = D.load_split(cfg2, "val", [c["session"], c["row"]])
        u21 = (v21[c["session"]].astype(str) + ":" + v21[c["row"]].astype(str)).tolist()
        run.check(M, "v2_1 val uid order == the Phase 5A LOAO run's", PR.sha256_bytes("\n".join(u21).encode("utf-8")) ==
                  M36["data"]["val_uid_sha256"], f"{len(u21):,}")
        pos21 = {u: i for i, u in enumerate(u21)}
        d36 = Path(M36["dir"])
        LO = {}
        for p in M36["pairs"]:
            f = d36 / p["pred_file"]
            if PR.sha256_path(f) != p["pred_sha256"]:
                raise RuntimeError(f"{f}: sha256 != Phase 5A step 36 manifest")
            LO[(int(p["k"]), int(p["s"]))] = np.load(f).astype(np.int64)
        nonrare5, rare5 = M36["classes"]["nonrare_ids"], M36["classes"]["rare_ids"]
        # ---------------------------------------------------------------- data
        tr = PR.load_ctx_split(up39, "train", flow + ctx + [c["label_id"], c["group"]])
        b = tr[c["label_id"]].to_numpy(np.int64) == 0
        Xtr_c = tr.loc[b, ctx].to_numpy(np.float64)
        Xtr_fc = tr.loc[b, flow + ctx].to_numpy(np.float64)
        gtr = tr.loc[b, c["group"]].astype(str).to_numpy()
        del tr
        Ztr_c, nf_tr = NM.prepare(Xtr_c, ctx)
        va = PR.load_ctx_split(up39, "val", flow + ctx + [c["label_id"], c["group"], c["session"], c["row"], c["start"]])
        y = va[c["label_id"]].to_numpy(np.int64)
        g = va[c["group"]].astype(str).to_numpy()
        sess = va[c["session"]].astype(str).to_numpy()
        ts = va[c["start"]].to_numpy(np.int64)
        uid = (va[c["session"]].astype(str) + ":" + va[c["row"]].astype(str)).tolist()
        pos = np.array([pos21.get(u, -1) for u in uid])
        run.check(M, "every val row maps to a Phase 5A val row", bool((pos >= 0).all()), f"{int((pos < 0).sum())} unmapped")
        Xva_c = va[ctx].to_numpy(np.float64)
        Xva_fc = va[flow + ctx].to_numpy(np.float64)
        del va
        Zva_c, nf_va = NM.prepare(Xva_c, ctx)
        cpath = Path(up41["manifest"]["contamination_file"])
        if PR.sha256_path(cpath) != up41["manifest"]["contamination_sha256"]:
            raise RuntimeError("contamination mask sha256 != step 41")
        cont = np.load(cpath)
        benign = y == 0
        hours = PM.benign_hours(sess, ts, benign, gap)
        seeds = [s for s in zd["seeds"] if any(int(p["s"]) == s for p in M36["pairs"])]
        seeds = seeds[:1] if args.dry_run else seeds
        tmax = Xtr_c.max(0)
        above = (Xva_c > tmax[None, :]).any(1)
        OOR = {"benign": float(above[benign].mean()),
               **{names[k]: float(above[y == k].mean()) for k in range(1, K) if (y == k).any()},
               "misses": {f"{names[k]}|{s}": float(above[(y == k) & (pr[pos] == 0)].mean())
                          for (k, s), pr in LO.items() if ((y == k) & (pr[pos] == 0)).any()}}
        run.log(f"  out-of-range diagnostic (any context feature > train-benign max): benign {OOR['benign']:.4f}; "
                + ", ".join(f"{n} {v:.4f}" for n, v in OOR.items() if n not in ("benign", "misses")))
        M["data"] = {"train_benign": int(b.sum()), "val_rows": int(len(y)), "benign_hours": hours, "seeds": seeds,
                     "nonfinite_train": nf_tr, "nonfinite_val": nf_va}
        ndir = run.cache_dir("normal")
        R = {a: {} for a in [PRIMARY] + zd["report_only_arms"]}
        hist6, rules_out = None, {}
        for s in seeds:
            Tg = TR.fit(Xtr_c, s, tp)
            Tpg = TR.fit_groups(Xtr_c, gtr, s, tp, global_rule=Tg)
            Tfc = TR.fit(Xtr_fc, s, tp)
            Gif = NM.fit_arm(NM.GLOBAL, Ztr_c, gtr, s, P)
            fl_if = NM.flags(*NM.score_arm(Gif, Zva_c, g, P)[:2])
            fl_pg, _ = TR.flag_groups(Tpg, Xva_c, g)
            arms = {PRIMARY: TR.flag(Xva_c, Tg["t"]), "CTX_TAIL_PER_GROUP": fl_pg,
                    "FLOWCTX_TAIL_GLOBAL": TR.flag(Xva_fc, Tfc["t"]), "CTX_IF_GLOBAL": fl_if}
            rules_out[str(s)] = {
                PRIMARY: {"q": Tg["q"], "hold_rate": Tg["hold_rate"], "met": Tg["met"], "n_fit": Tg["n_fit"],
                          "n_hold": Tg["n_hold"], "t": dict(zip(ctx, Tg["t"].tolist()))},
                "CTX_TAIL_PER_GROUP": {k: {"q": r["q"], "hold_rate": r["hold_rate"], "met": r["met"], "n_fit": r["n_fit"]}
                                       for k, r in Tpg["rules"].items()} | {"fallback": Tpg["fallback"]},
                "FLOWCTX_TAIL_GLOBAL": {"q": Tfc["q"], "hold_rate": Tfc["hold_rate"], "met": Tfc["met"]},
                "CTX_IF_GLOBAL": {"threshold": Gif["models"][NM.GLOBAL_KEY]["threshold"]}}
            import joblib
            fn = f"CTX_IF_GLOBAL__s{s}.joblib"
            joblib.dump(Gif["models"][NM.GLOBAL_KEY]["model"], ndir / fn)
            PR.write_json(ndir / f"tail_rules__s{s}.json", {"ctx_features": ctx, "flowctx_features": flow + ctx,
                                                             PRIMARY: Tg["t"].tolist(), "FLOWCTX_TAIL_GLOBAL": Tfc["t"].tolist(),
                                                             "CTX_TAIL_PER_GROUP": {k: r["t"].tolist() for k, r in Tpg["rules"].items()},
                                                             "route": Tpg["route"], "q": rules_out[str(s)]})
            run.log(f"  s{s}: CTX_TAIL_GLOBAL q {Tg['q']:.6f} (held-out flag rate {Tg['hold_rate']:.5f}, met {Tg['met']}); "
                    f"per group {[(k, round(r['q'], 6)) for k, r in Tpg['rules'].items()]} fallback {Tpg['fallback']}; "
                    f"FLOWCTX q {Tfc['q']:.6f}")
            for a, fl in arms.items():
                pairs = []
                for (k, s5), pr in LO.items():
                    if s5 != s:
                        continue
                    miss = (y == k) & (pr[pos] == 0)
                    mr = ZM.miss_recall(fl, miss)
                    isk = y == k
                    comb = (pr[pos] != 0) | fl
                    pairs.append({"k": k, "class": names[k], "s": s, "n_miss": mr["n"], "flagged": mr["flagged"],
                                  "recall": mr["recall"], "rare": k in rare5,
                                  "detector_alone": float(fl[isk].mean()) if isk.any() else None,
                                  "combined": float(comb[isk].mean()) if isk.any() else None,
                                  "combined_fa": int((benign & comb).sum()), "stage1_fa": int((benign & (pr[pos] != 0)).sum())})
                fa = ZM.fa_rate(fl, benign, hours)
                fa_c = {"contaminated": int((fl & cont).sum()), "n_contaminated": int(cont.sum()),
                        "clean": int((fl & benign & ~cont).sum()), "n_clean": int((benign & ~cont).sum())}
                drift = {gg: {"flagged": int((fl & benign & (g == gg)).sum()), "n": int((benign & (g == gg)).sum())}
                         for gg in sorted(set(g.tolist()))}
                rec = {"pairs": pairs, "fa": fa, "fa_contamination": fa_c, "drift": drift}
                if a == PRIMARY:
                    firing = {}
                    for k in range(K):
                        m = (y == k) & fl
                        if m.any():
                            firing[names[k]] = dict(list(TR.explain(Xva_c[m], Tg["t"], ctx)["fire_counts"].items())[:5])
                    rec["top_firing_features"] = firing
                R[a][str(s)] = rec
                run.log(f"  {a:<20} s{s}: FA {fa['fa_count']} ({fa['fa_per_hour']:.2f}/h; contaminated {fa_c['contaminated']}, "
                        f"clean {fa_c['clean']}) | miss-recall " + ", ".join(
                            f"{p['class']} {p['recall']:.4f} ({p['flagged']}/{p['n_miss']})" for p in pairs))
            if hist6 is None:
                fi, hi = TR.split(len(Xtr_c), tp["fit_share"], s)
                sc_h, sc_v = tail_score(Xtr_c[hi], Tg["t"]), tail_score(Xva_c, Tg["t"])
                edges = np.geomspace(min(sc_h.min(), sc_v.min()) * 0.98, max(sc_h.max(), sc_v.max()) * 1.02, 81)
                hist6 = {"seed": s, "edges": edges.tolist(), "threshold": 1.0, "score": "max_j (x_j + 1) / (t_j + 1)",
                         "train_benign": hist(sc_h, edges), "train_benign_label": "train benign (held-out 20 %)",
                         "val_benign": hist(sc_v[benign], edges),
                         "misses": {names[k]: hist(sc_v[(y == k) & (pr[pos] == 0)], edges)
                                    for (k, s5), pr in LO.items() if s5 == s and k in nonrare5
                                    and ((y == k) & (pr[pos] == 0)).any()}}
        # ---------------------------------------------------------------- H-C3 verdict (primary) + the same rule for the IF arm
        def verdict(a):
            vp = [{"k": p["k"], "s": p["s"], "n_miss": p["n_miss"], "recall": p["recall"]} for s in R[a] for p in R[a][s]["pairs"]]
            return EV.h_c3(vp, [R[a][str(s)]["fa"]["fa_per_hour"] for s in seeds], fa_ref, zd, ev, nonrare5)

        HC3 = verdict(PRIMARY)
        side = {a: verdict(a) for a in zd["report_only_arms"]}
        for a, H in [(PRIMARY, HC3)] + list(side.items()):
            run.log(f"  H-C3 rule on {a:<20}: {H['verdict']}{'' if a == PRIMARY else ' (report-only)'}  miss-recall "
                    f"{H['recall']['mean']:.4f} [{H['recall']['lo']:.4f}, {H['recall']['hi']:.4f}] (n={H['recall']['n']}); FA/h "
                    f"{H['fa']['mean']:.2f} [{H['fa']['lo']:.2f}, {H['fa']['hi']:.2f}] vs 5A {fa_ref:.2f} -- {H['reason']}")
        g5 = {(p["k"], p["s"]): p["recall"]["GLOBAL_NORMAL"] for p in E5["pairs"]}
        out = {"h_c2": HC2, "h_c2_class": k2, "h_c3": HC3, "h_c3_rule_on_report_only_arms": side, "primary_arm": PRIMARY,
               "arms": R, "rules": rules_out, "seeds": seeds, "names": names, "nonrare": nonrare5, "rare": rare5,
               "fa_ref": fa_ref, "benign_hours": hours, "hist": hist6, "out_of_range": OOR,
               "phase5a_global_normal_recall": {f"{k}|{s}": v for (k, s), v in g5.items()},
               "contamination_share": float(cont.sum() / max(1, benign.sum())),
               "per_group_note": "CTX_TAIL_PER_GROUP is report-only and not a routing claim (D163)"}
        PR.write_json(run.res / "zeroday.json", out)
        man = {"dir": str(ndir), "files": {f.name: PR.sha256_path(f) for f in sorted(ndir.iterdir())}}
        M["models_manifest_sha256"] = PR.write_json(ndir / "manifest.json", man)
        M.update({"h_c2": HC2[k2]["verdict"], "h_c3": HC3["verdict"], "models_dir": str(ndir),
                  "h_c3_report_only": {a: v["verdict"] for a, v in side.items()}})
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
    L = [f"# Step 42 -- H-C2 fingerprint independence, H-C3 zero-day with context -- {st}" + (" (DRY RUN)" if run.dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    p = run.res / "zeroday.json"
    if p.exists():
        Z = json.loads(p.read_text(encoding="utf-8"))
        L += ["## H-C2", "", "| class | Δ_flow (NOFP - GLOBAL) | Δ_ctx (CTX_NOFP - CTX) | Δ_ctx - Δ_flow [95 % CI] | verdict |",
              "|---|---|---|---|---|"]
        for n, h in Z["h_c2"].items():
            d = h["diff"]
            L.append(f"| {n}{' (rare)' if h['rare'] else ''}{' **(pre-registered)**' if n == Z['h_c2_class'] else ''} | "
                     f"{np.mean(h['delta_flow']):+.4f} | {np.mean(h['delta_ctx']):+.4f} | {d['mean']:+.4f} [{d['lo']:+.4f}, "
                     f"{d['hi']:+.4f}] | {h['verdict']} |")
        L += ["", "## H-C3", "", "| arm | role | verdict | mean miss-recall [95 % CI] (eligible pairs) | FA/h [95 % CI] | reason |",
              "|---|---|---|---|---|---|"]
        for a, H in [(Z["primary_arm"], Z["h_c3"])] + list(Z["h_c3_rule_on_report_only_arms"].items()):
            L.append(f"| {a} | {'**primary**' if a == Z['primary_arm'] else 'report-only'} | {H['verdict']} | "
                     f"{H['recall']['mean']:.4f} [{H['recall']['lo']:.4f}, {H['recall']['hi']:.4f}] ({H['recall']['n']}) | "
                     f"{H['fa']['mean']:.2f} [{H['fa']['lo']:.2f}, {H['fa']['hi']:.2f}] | {H['reason']} |")
        L += ["", f"- FA reference (Phase 5A GLOBAL_NORMAL mean FA/h): {Z['fa_ref']:.3f}; val benign hours {Z['benign_hours']:.3f}",
              f"- out-of-range diagnostic: {Z['out_of_range']}", "",
              "| arm | seed | FA (FA/h) | FA contaminated / clean | miss-recall (flagged / misses) | detector alone | combined recall |",
              "|---|---|---|---|---|---|---|"]
        for a, per in Z["arms"].items():
            for s, v in per.items():
                f = v["fa"]
                L.append(f"| {a} | {s} | {f['fa_count']} ({f['fa_per_hour']:.2f}) | {v['fa_contamination']['contaminated']} / "
                         f"{v['fa_contamination']['clean']} | " + ", ".join(
                             f"{q['class']} {q['recall']:.4f} ({q['flagged']}/{q['n_miss']})" for q in v["pairs"]) + " | "
                         + ", ".join(f"{q['class']} {q['detector_alone']:.4f}" for q in v["pairs"]) + " | "
                         + ", ".join(f"{q['class']} {q['combined']:.4f}" for q in v["pairs"]) + " |")
        L += ["", "### CTX_TAIL_GLOBAL rules (q, held-out flag rate) and top firing features", ""]
        for s, r in Z["rules"].items():
            L.append(f"- s{s}: q {r[Z['primary_arm']]['q']:.6f}, held-out rate {r[Z['primary_arm']]['hold_rate']:.5f} "
                     f"(met {r[Z['primary_arm']]['met']}); per-group {r['CTX_TAIL_PER_GROUP']}")
        for s, v in Z["arms"][Z["primary_arm"]].items():
            L.append(f"- s{s} top firing features per class: {v.get('top_firing_features')}")
        L += ["", f"- {Z['per_group_note']}", f"- val benign contamination share {Z['contamination_share']:.4f}", ""]
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
