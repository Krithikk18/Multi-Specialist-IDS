#!/usr/bin/env python
"""diagnostics/phase3_1_drift.py -- Phase 3.1 PART D (READ-ONLY): what is the train -> val timing drift?

Rules (the prompt's, fixed before any number; written at the top of summary.md with their operational reading first):
  D1 capture-wide shift: >= 70 % of eligible devices (>= 100 benign flows in BOTH splits) have KS > 0.2 on at least one
     timing feature.
  D2 device-concentrated shift: for every timing feature whose pooled benign KS > 0.2, the <= 2 largest devices among
     the devices with their own KS > 0.2 on it hold >= 70 % of all benign rows (train + val); no such feature -> NO.
  D3 attack-tool shift: some attack class (>= 100 rows in both splits) has KS > 0.2 on a timing feature while the
     pooled benign KS stays < 0.1 on EVERY timing feature.
  D4 load / time-of-day: per 5-minute window (session, floor(start / 300); windows with >= 30 benign flows; both
     splits), the median of some timing feature (benign flows) has Spearman |rho| >= 0.5 with the window's total packet
     rate (sum of Total Fwd + Bwd packets of ALL flows starting in it / 300 s) or with the UTC time of day (hours).
  Each is HOLDS / DOES NOT HOLD with its numbers; more than one may hold.
Timing features = the features whose names start with one of --timing-prefixes (defaults: the prompt's list).
Also: adversarial validation (XGBoost, train = 0 vs val = 1 on benign flows, all 70 features, 5-fold stratified
out-of-fold AUC overall / per group / per eligible device, top features by mean gain) and error vs drift (per eligible
device: the promoted model's val error rate = the step 28 rerun_full GLOBAL_s0 runtime predictions, identical to the
offline model, vs the device's adversarial AUC; Spearman).
Outputs: results/phase3_1/drift/ (summary.md, drift.json, run_manifest.json, run_meta.json, run.log, figures/).
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase2_data as D  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import predictions_io as PIO  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402

SCRIPT = "diagnostics/phase3_1_drift.py"
BENIGN = 0
KS_HI, KS_LO, D1_SHARE, D2_SHARE, D2_TOP, MIN_DEV, RHO, WIN_S, MIN_WIN = 0.2, 0.1, 0.70, 0.70, 2, 100, 0.5, 300, 30
TIMING_DEFAULT = ["Flow IAT", "Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
                  "Active ", "Idle "]
RUN28 = RESULTS_DIR / "phase3" / "28" / "rerun_full" / "runs.json"


def pins() -> dict:
    return {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH), ("config/class_map.json", S.CLASS_MAP_PATH))}


RULES = f"""## Rules (fixed before any number)

- **D1 capture-wide shift**: >= {D1_SHARE:.0%} of devices with >= {MIN_DEV} benign flows in both splits have KS > {KS_HI} on at
  least one timing feature.
- **D2 device-concentrated shift**: <= {D2_TOP} devices account for >= {D2_SHARE:.0%} of the benign rows in features with KS > {KS_HI}.
  Operational: for EVERY timing feature with pooled benign KS > {KS_HI}, the {D2_TOP} largest devices among those with their own
  KS > {KS_HI} on it hold >= {D2_SHARE:.0%} of all benign rows (train + val); no such feature -> DOES NOT HOLD.
- **D3 attack-tool shift**: attack classes show KS > {KS_HI} on timing features while benign stays < {KS_LO}. Operational: some
  attack class (>= {MIN_DEV} rows in both splits) has KS > {KS_HI} on a timing feature AND the pooled benign KS < {KS_LO} on every
  timing feature.
- **D4 load / time-of-day**: per {WIN_S // 60}-minute window, median timing features correlate with the total packet rate or the
  time of day (Spearman |rho| >= {RHO}). Operational: windows = (session, floor(start / {WIN_S})) with >= {MIN_WIN} benign flows,
  both splits; median over the window's benign flows; packet rate = sum of Total Fwd + Bwd packets of all flows starting in
  the window / {WIN_S} s; time of day = UTC hours.
- Each verdict is HOLDS / DOES NOT HOLD with its numbers; more than one may hold. Evaluated on BENIGN flows unless stated.

"""


def ks(a: np.ndarray, b: np.ndarray) -> float:
    from scipy.stats import ks_2samp
    if len(a) == 0 or len(b) == 0:
        return float("nan")
    return float(ks_2samp(a, b).statistic)


def auc(y: np.ndarray, s: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s)) if len(np.unique(y)) == 2 else float("nan")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--timing-prefixes", nargs="+", default=TIMING_DEFAULT)
    ap.add_argument("--replot", action="store_true", help="re-draw the error-vs-drift figure of the full run from its "
                    "drift.json into figures/error_vs_drift_fixed.png (nothing else is computed or written)")
    args = ap.parse_args()
    if args.replot:
        S.verify_v2_lock(strict=True)
        p0 = pins()
        print(f"[start] verify_v2_lock OK; {p0}")
        res = RESULTS_DIR / "phase3_1" / "drift"
        out = json.loads((res / "drift.json").read_text(encoding="utf-8"))
        f = fig_err(res / "figures" / "error_vs_drift_fixed.png", out["error_vs_drift"])
        p1 = pins()
        print(f"[end] wrote {f}; {p1}")
        return 0 if p0 == p1 else 1
    cfg = load_phase2_config(REPO_ROOT / "config" / "v2_phase2_v2_1.json")
    cfg["_results_root"] = str(RESULTS_DIR / "phase3_1")
    S.verify_v2_lock(strict=True)
    p0 = pins()
    names = list(S.load_class_map().names)
    ctx = R.start_run("drift", "diag", SCRIPT, cfg, args.dry_run, args.run_id)
    ctx.log(f"  [start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    (ctx.res / "summary.md").write_text("# Phase 3.1 part D -- train -> val drift diagnosis (read-only) -- RUNNING\n\n" + RULES,
                                        encoding="utf-8")
    M = R.base_manifest(ctx, SCRIPT, ["common/predictions_io.py"])
    M.update({"pins_before": p0, "read_only": True, "timing_prefixes": args.timing_prefixes})
    ok, out = False, {}
    try:
        feats = S.feature_columns()
        tim = [f for f in feats if any(f.startswith(p) for p in args.timing_prefixes)]
        M["timing_features"] = tim
        c = cfg["columns"]
        meta = ["device_mac", "device", c["group"], c["label_id"], c["session"], c["start_ts"], "row_in_file"]
        sp = {s: D.load_split(cfg, s, feats + meta, sample=args.dry_run) for s in ("train", "val")}
        M["inputs"] = {s: D.verify_split_file(cfg, s) for s in sp} | {"test_read": False}
        ben = {s: d[d[c["label_id"]] == BENIGN] for s, d in sp.items()}
        # ---- KS per device x feature (benign)
        nb = {s: b["device_mac"].value_counts() for s, b in ben.items()}
        elig = sorted(set(nb["train"][nb["train"] >= MIN_DEV].index) & set(nb["val"][nb["val"] >= MIN_DEV].index))
        dev_name = dict(zip(pd.concat([sp["train"]["device_mac"], sp["val"]["device_mac"]]),
                            pd.concat([sp["train"]["device"], sp["val"]["device"]])))
        dev_group = dict(zip(pd.concat([sp["train"]["device_mac"], sp["val"]["device_mac"]]),
                             pd.concat([sp["train"][c["group"]], sp["val"][c["group"]]]).astype(str)))
        KSd = pd.DataFrame(index=elig, columns=tim, dtype=float)
        for dmac in elig:
            a = ben["train"][ben["train"]["device_mac"] == dmac]
            b = ben["val"][ben["val"]["device_mac"] == dmac]
            for f in tim:
                KSd.loc[dmac, f] = ks(a[f].to_numpy(float), b[f].to_numpy(float))
        pooled = {f: ks(ben["train"][f].to_numpy(float), ben["val"][f].to_numpy(float)) for f in tim}
        # per class KS (pooled)
        cls_ks = {}
        for k, n in enumerate(names):
            a, b = sp["train"][sp["train"][c["label_id"]] == k], sp["val"][sp["val"][c["label_id"]] == k]
            if len(a) >= MIN_DEV and len(b) >= MIN_DEV:
                cls_ks[n] = {f: ks(a[f].to_numpy(float), b[f].to_numpy(float)) for f in tim}
        # ---- D1
        dmax = KSd.max(axis=1)
        d1_share = float((dmax > KS_HI).mean()) if len(elig) else float("nan")
        D1 = {"holds": bool(len(elig) and d1_share >= D1_SHARE), "eligible_devices": len(elig),
              "devices_ks_gt": int((dmax > KS_HI).sum()), "share": d1_share}
        # ---- D2
        rows_all = pd.concat([ben["train"]["device_mac"], ben["val"]["device_mac"]]).value_counts()
        n_ben = int(rows_all.sum())
        drifted = [f for f in tim if pooled[f] > KS_HI]
        per_f = {}
        for f in drifted:
            dd = [m for m in elig if KSd.loc[m, f] > KS_HI]
            top = rows_all.reindex(dd).fillna(0).sort_values(ascending=False).head(D2_TOP)
            per_f[f] = {"drifted_devices": len(dd), "top": [(dev_name.get(m, m), m, int(v)) for m, v in top.items()],
                        "share": float(top.sum() / n_ben) if n_ben else float("nan")}
        D2 = {"holds": bool(drifted) and all(v["share"] >= D2_SHARE for v in per_f.values()), "drifted_features": drifted,
              "per_feature": per_f}
        # ---- D3
        att = {n: v for n, v in cls_ks.items() if n != names[BENIGN]}
        bmax = max(pooled.values()) if pooled else float("nan")
        hit = {n: [f for f, v in d.items() if v > KS_HI] for n, d in att.items()}
        D3 = {"holds": bool(bmax < KS_LO and any(hit.values())), "benign_pooled_max_ks": bmax,
              "attack_features_ks_gt": hit, "attack_max_ks": {n: max(d.values()) for n, d in att.items()}}
        # ---- D4
        allf = pd.concat([sp["train"].assign(_split="train"), sp["val"].assign(_split="val")], ignore_index=True)
        allf["_win"] = allf[c["start_ts"]].to_numpy(np.int64) // WIN_S
        pk = allf["Total Fwd Packet"].to_numpy(float) + allf["Total Bwd packets"].to_numpy(float)
        allf["_pk"] = pk
        key = [c["session"], "_win"]
        rate = allf.groupby(key)["_pk"].sum() / WIN_S
        bb = allf[allf[c["label_id"]] == BENIGN]
        cnt = bb.groupby(key).size()
        med = bb.groupby(key)[tim].median()
        keep = cnt[cnt >= MIN_WIN].index
        med = med.loc[keep]
        from scipy.stats import spearmanr
        W = pd.DataFrame({"rate": rate.reindex(keep).to_numpy(),
                          "tod": ((np.array([w for _, w in keep]) * WIN_S) % 86400) / 3600.0}, index=keep)
        rho = {}
        for f in tim:
            r1 = spearmanr(med[f].to_numpy(float), W["rate"].to_numpy(float)).statistic if len(W) > 2 else np.nan
            r2 = spearmanr(med[f].to_numpy(float), W["tod"].to_numpy(float)).statistic if len(W) > 2 else np.nan
            rho[f] = {"rate": float(r1), "tod": float(r2)}
        mx = max((abs(v[k]) for v in rho.values() for k in v if np.isfinite(v[k])), default=float("nan"))
        D4 = {"holds": bool(np.isfinite(mx) and mx >= RHO), "windows": int(len(W)), "max_abs_rho": mx,
              "features_over": {f: v for f, v in rho.items() if max((abs(x) for x in v.values() if np.isfinite(x)), default=0.0) >= RHO}
              if np.isfinite(mx) else {}, "rho": rho}
        out["verdicts"] = {"D1": D1, "D2": D2, "D3": D3, "D4": D4}
        out["pooled_benign_ks"] = pooled
        out["class_ks"] = cls_ks
        out["device_ks"] = {m: {"name": dev_name.get(m, m), "group": dev_group.get(m), "n_train": int(nb["train"][m]),
                                "n_val": int(nb["val"][m]), **{f: float(KSd.loc[m, f]) for f in tim}} for m in elig}
        ctx.log(f"  D1 {D1['holds']} ({D1['share']:.2f}), D2 {D2['holds']}, D3 {D3['holds']} (benign max {bmax:.3f}), "
                f"D4 {D4['holds']} (max |rho| {mx:.2f})")
        # ---- adversarial validation (benign, all features, 5-fold OOF)
        import xgboost as xgb
        from sklearn.model_selection import StratifiedKFold
        XB = np.vstack([D.feature_matrix(ben["train"], feats), D.feature_matrix(ben["val"], feats)])
        yB = np.r_[np.zeros(len(ben["train"])), np.ones(len(ben["val"]))].astype(int)
        gB = np.r_[ben["train"][c["group"]].astype(str).to_numpy(), ben["val"][c["group"]].astype(str).to_numpy()]
        mB = np.r_[ben["train"]["device_mac"].astype(str).to_numpy(), ben["val"]["device_mac"].astype(str).to_numpy()]
        oof = np.zeros(len(yB))
        gain = pd.Series(0.0, index=feats)
        params = {"objective": "binary:logistic", "eval_metric": "auc", "tree_method": "hist", "eta": 0.3, "max_depth": 6,
                  "seed": 0, "nthread": -1}
        for tr_i, te_i in StratifiedKFold(5, shuffle=True, random_state=0).split(XB, yB):
            b = xgb.train(params, xgb.DMatrix(XB[tr_i], label=yB[tr_i], feature_names=feats), num_boost_round=100)
            oof[te_i] = b.predict(xgb.DMatrix(XB[te_i], feature_names=feats))
            g = pd.Series(b.get_score(importance_type="total_gain"))
            gain = gain.add(g.reindex(feats).fillna(0.0), fill_value=0.0)
        gain = gain / gain.sum()
        adv = {"auc_all": auc(yB, oof), "auc_group": {g: auc(yB[gB == g], oof[gB == g]) for g in sorted(set(gB))},
               "n_group": {g: {"train": int(((gB == g) & (yB == 0)).sum()), "val": int(((gB == g) & (yB == 1)).sum())}
                           for g in sorted(set(gB))},
               "auc_device": {m: auc(yB[mB == m], oof[mB == m]) for m in elig},
               "top_features": [(f, float(v)) for f, v in gain.sort_values(ascending=False).head(15).items()]}
        out["adversarial"] = adv
        ctx.log(f"  adversarial AUC all {adv['auc_all']:.3f}; per group {adv['auc_group']}")
        # ---- error vs drift (the promoted model = rerun_full GLOBAL_s0 runtime predictions)
        if not args.dry_run:
            runs = json.loads(RUN28.read_text(encoding="utf-8"))
            P = PIO.read_predictions(Path(runs["GLOBAL_s0"]["dir"]), columns=["flow_uid", "pred"])
            va = sp["val"]
            uid = (va[c["session"]].astype(str) + ":" + va["row_in_file"].astype(str)).to_numpy()
            pr = pd.Series(P["pred"].to_numpy(), index=P["flow_uid"].to_numpy()).reindex(uid).to_numpy()
            if np.isnan(pr.astype(float)).any():
                raise RuntimeError("runtime predictions do not cover every val row")
            yv = va[c["label_id"]].to_numpy()
            err = []
            for m in elig:
                k = va["device_mac"].to_numpy() == m
                kb = k & (yv == BENIGN)
                err.append({"device": dev_name.get(m, m), "mac": m, "group": dev_group.get(m), "n_val": int(k.sum()),
                            "error_rate": float((pr[k] != yv[k]).mean()), "benign_fa_rate": float((pr[kb] != BENIGN).mean()),
                            "adv_auc": adv["auc_device"][m], "max_ks": float(dmax[m])})
            from scipy.stats import spearmanr as sr
            E_ = pd.DataFrame(err)
            out["error_vs_drift"] = {"rows": err, "spearman_error_vs_auc": float(sr(E_["error_rate"], E_["adv_auc"]).statistic),
                                     "spearman_fa_vs_auc": float(sr(E_["benign_fa_rate"], E_["adv_auc"]).statistic),
                                     "spearman_error_vs_maxks": float(sr(E_["error_rate"], E_["max_ks"]).statistic),
                                     "source": f"{runs['GLOBAL_s0']['dir']} (promoted GLOBAL s0 runtime predictions)"}
        R.write_json(ctx.partial / "drift.json", out)
        R.write_json(ctx.res / "drift.json", out)
        figs = [fig_ks_heatmap(ctx.fig / "ks_device_feature.png", KSd, dev_name, dev_group, pooled),
                fig_class_ks(ctx.fig / "ks_per_class.png", cls_ks, pooled, names),
                fig_auc(ctx.fig / "adversarial_auc.png", adv, dev_name)]
        if out.get("error_vs_drift"):
            figs.append(fig_err(ctx.fig / "error_vs_drift.png", out["error_vs_drift"]))
        M["figures"] = [str(Path(f).relative_to(ctx.res)) for f in figs]
        M["verdicts"] = {k: v["holds"] for k, v in out["verdicts"].items()}
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = pins()
    R.add_check(ctx, M, "config.py / class_map.json unchanged", M["pins_after"] == p0, str(M["pins_after"]))
    ctx.log(f"  [end] config.py {M['pins_after']['config/config.py']}; class_map.json {M['pins_after']['config/class_map.json']}")
    ok = ok and M["pins_after"] == p0
    write_summary(ctx.res / "summary.md", M, out, names, ok)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def write_summary(path, M, out, names, ok) -> None:
    L = [f"# Phase 3.1 part D -- train -> val drift diagnosis (read-only) -- {'PASS' if ok else 'FAIL'}"
         + (" (DRY RUN)" if M["dry_run"] else ""), "", RULES.rstrip(), "",
         f"- v2_1_oriented train vs val (test never read); timing features ({len(M.get('timing_features', []))}): "
         f"{', '.join(M.get('timing_features', []))}", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```"]
    V = out.get("verdicts")
    if V:
        d1, d2, d3, d4 = V["D1"], V["D2"], V["D3"], V["D4"]
        L += ["## Verdicts", "", "| rule | verdict | numbers |", "|---|---|---|",
              f"| D1 capture-wide | **{'HOLDS' if d1['holds'] else 'DOES NOT HOLD'}** | {d1['devices_ks_gt']} of "
              f"{d1['eligible_devices']} eligible devices ({d1['share']:.0%}) have KS > {KS_HI} on >= 1 timing feature |",
              f"| D2 device-concentrated | **{'HOLDS' if d2['holds'] else 'DOES NOT HOLD'}** | features with pooled KS > {KS_HI}: "
              f"{len(d2['drifted_features'])}; top-{D2_TOP} drifted-device row share per feature: "
              + ("; ".join(f"{f} {v['share']:.0%}" for f, v in d2["per_feature"].items()) or "none") + " |",
              f"| D3 attack-tool | **{'HOLDS' if d3['holds'] else 'DOES NOT HOLD'}** | pooled benign max KS "
              f"{d3['benign_pooled_max_ks']:.3f}; attack max KS " + ", ".join(f"{n} {v:.3f}" for n, v in d3["attack_max_ks"].items()) + " |",
              f"| D4 load / time of day | **{'HOLDS' if d4['holds'] else 'DOES NOT HOLD'}** | {d4['windows']} windows; max "
              f"|rho| {d4['max_abs_rho']:.2f}; features over {RHO}: "
              + (", ".join(f"{f} (rate {v['rate']:+.2f}, tod {v['tod']:+.2f})" for f, v in d4["features_over"].items()) or "none") + " |",
              "", "## Pooled KS per timing feature (benign) and per class", "",
              "| feature | benign | " + " | ".join(n for n in out["class_ks"] if n != names[BENIGN]) + " |",
              "|---|---|" + "---|" * (len(out["class_ks"]) - (1 if names[BENIGN] in out["class_ks"] else 0))]
        for f, v in out["pooled_benign_ks"].items():
            L.append(f"| {f} | {v:.3f} | " + " | ".join(f"{out['class_ks'][n][f]:.3f}" for n in out["class_ks"] if n != names[BENIGN]) + " |")
        L += ["", "## Devices (benign, >= 100 flows in both splits): max KS over timing features and adversarial AUC", "",
              "| device | group | train | val | max KS | feature | adversarial AUC |", "|---|---|---|---|---|---|---|"]
        adv = out["adversarial"]
        for m, r in sorted(out["device_ks"].items(), key=lambda kv: -max(v for k, v in kv[1].items() if k in M["timing_features"])):
            vals = {k: v for k, v in r.items() if k in M["timing_features"]}
            fm = max(vals, key=vals.get)
            L.append(f"| {r['name']} | {r['group']} | {r['n_train']:,} | {r['n_val']:,} | {vals[fm]:.3f} | {fm} | "
                     f"{adv['auc_device'][m]:.3f} |")
        L += ["", "## Adversarial validation (benign train vs val, 5-fold out-of-fold)", "",
              f"- AUC overall **{adv['auc_all']:.3f}**; per group " + ", ".join(
                  f"{g} {v:.3f} (train {adv['n_group'][g]['train']:,} / val {adv['n_group'][g]['val']:,})" for g, v in adv["auc_group"].items()),
              "- top features (share of total gain): " + ", ".join(f"{f} {100 * v:.1f} %" for f, v in adv["top_features"][:10])]
        ev = out.get("error_vs_drift")
        if ev:
            L += ["", "## Does model error rise with drift? (promoted GLOBAL s0, val, per eligible device)", "",
                  f"- Spearman(error rate, adversarial AUC) = {ev['spearman_error_vs_auc']:+.2f}; Spearman(benign false-alarm "
                  f"rate, AUC) = {ev['spearman_fa_vs_auc']:+.2f}; Spearman(error rate, max KS) = {ev['spearman_error_vs_maxks']:+.2f}",
                  "", "| device | group | val flows | error rate | benign FA rate | adversarial AUC |", "|---|---|---|---|---|---|"]
            L += [f"| {r['device']} | {r['group']} | {r['n_val']:,} | {r['error_rate']:.4f} | {r['benign_fa_rate']:.4f} | "
                  f"{r['adv_auc']:.3f} |" for r in sorted(ev["rows"], key=lambda r: -r["adv_auc"])]
    L += ["", "## Figures", ""] + [f"- `{f}`" for f in M.get("figures", [])]
    L += ["", "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M["checks"]]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------- figures
def fig_ks_heatmap(path, KSd, dev_name, dev_group, pooled):
    import matplotlib.pyplot as plt
    from matplotlib.colors import Normalize
    PS.apply()
    order = sorted(KSd.index, key=lambda m: (dev_group.get(m, ""), -KSd.loc[m].max()))
    V = KSd.loc[order].to_numpy(float)
    feats = list(KSd.columns)
    fig, ax = plt.subplots(figsize=(0.42 * len(feats) + 3.2, 0.3 * len(order) + 2.6))
    im = ax.imshow(V, cmap=PS.SEQUENTIAL_CMAP, norm=Normalize(0, 1), aspect="auto")
    for i in range(V.shape[0]):
        for j in range(V.shape[1]):
            if V[i, j] > KS_HI:
                ax.text(j, i, f"{V[i, j]:.2f}"[1:], ha="center", va="center", fontsize=5.2,
                        color="white" if V[i, j] > 0.6 else PS.TEXT1)
    ax.set_xticks(range(len(feats)), [f"{f}\n(pooled {pooled[f]:.2f})" for f in feats], rotation=60, ha="right", fontsize=6.3)
    ax.set_yticks(range(len(order)), [f"{dev_name.get(m, m)[:26]} ({dev_group.get(m, '')})" for m in order], fontsize=6.3)
    fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01, label="KS train vs val (benign)")
    ax.set_title(f"Benign KS per device x timing feature (cells > {KS_HI} labelled); devices with >= {MIN_DEV} flows in both "
                 "splits", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_class_ks(path, cls_ks, pooled, names):
    import matplotlib.pyplot as plt
    PS.apply()
    feats = list(pooled)
    cl = list(cls_ks)
    fig, ax = plt.subplots(figsize=(8.6, 0.3 * len(feats) + 1.5))
    y = np.arange(len(feats))
    w = 0.8 / max(len(cl), 1)
    for k, n in enumerate(cl):
        col = PS.class_color(names.index(n))
        ax.barh(y + (k - (len(cl) - 1) / 2) * w, [cls_ks[n][f] for f in feats], w * 0.95, color=col, label=n)
    ax.axvline(KS_HI, color=PS.TEXT1, lw=0.8, ls="--")
    ax.axvline(KS_LO, color=PS.TEXT2, lw=0.8, ls=":")
    ax.set_yticks(y, feats, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xlabel(f"KS train vs val, per class (pooled); dashed {KS_HI}, dotted {KS_LO}")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7.5, loc="lower right")
    ax.set_title("Train -> val KS per class and timing feature", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_auc(path, adv, dev_name):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, axes = plt.subplots(1, 2, figsize=(10.4, 4.0), gridspec_kw={"width_ratios": [1, 2.4]})
    g = list(adv["auc_group"])
    v = [adv["auc_group"][x] for x in g]
    axes[0].bar(range(len(g)), v, color=PS.CATEGORICAL[0], width=0.55)
    for i, x in enumerate(v):
        axes[0].text(i, x + 0.01, f"{x:.3f}", ha="center", fontsize=7.5)
    axes[0].axhline(0.5, color=PS.TEXT2, lw=0.8, ls=":")
    axes[0].set_xticks(range(len(g)), g)
    axes[0].set_ylim(0.4, 1.06)
    axes[0].set_ylabel("adversarial AUC (benign train vs val)")
    axes[0].set_title(f"per group (all: {adv['auc_all']:.3f})", loc="left", fontsize=9)
    tf = adv["top_features"][:12][::-1]
    axes[1].barh(range(len(tf)), [100 * x for _, x in tf], color=PS.NEUTRAL_LIGHT)
    for i, (_, x) in enumerate(tf):
        axes[1].text(100 * x + 0.3, i, f"{100 * x:.1f} %", va="center", fontsize=7)
    axes[1].set_yticks(range(len(tf)), [f for f, _ in tf], fontsize=7.5)
    axes[1].set_xlabel("share of total gain (5 folds)")
    axes[1].set_title("features that separate train from val", loc="left", fontsize=9)
    fig.suptitle("Adversarial validation on benign flows", x=0.01, ha="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_err(path, ev):
    import matplotlib.pyplot as plt
    PS.apply()
    E = pd.DataFrame(ev["rows"])
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    groups = sorted(E["group"].astype(str).unique())
    for k, g in enumerate(groups):
        s = E[E["group"].astype(str) == g]
        ax.scatter(s["adv_auc"], 100 * s["error_rate"], s=26, color=PS.CATEGORICAL[k], label=g, alpha=0.85)
    top = E.sort_values("error_rate", ascending=False).head(5)
    for i, (_, r) in enumerate(top.iterrows()):                         # alternate above-right / below-right
        ax.annotate(r["device"][:24], (r["adv_auc"], 100 * r["error_rate"]), textcoords="offset points",
                    xytext=(8, 5) if i % 2 == 0 else (8, -12), fontsize=6.5, color=PS.TEXT1,
                    bbox={"boxstyle": "round,pad=0.1", "fc": PS.SURFACE, "ec": "none", "alpha": 0.85})
    ax.set_yscale("symlog", linthresh=0.01)
    ax.set_xlabel("device adversarial AUC (benign train vs val)")
    ax.set_ylabel("val error rate % (promoted GLOBAL s0; symlog)")
    ax.legend(frameon=False, fontsize=7.5, title="group", title_fontsize=7.5)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.set_title(f"Error vs drift per device (Spearman {ev['spearman_error_vs_auc']:+.2f})", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


if __name__ == "__main__":
    sys.exit(main())
