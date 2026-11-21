#!/usr/bin/env python
"""diagnostics/diag_01b_alternatives.py -- READ-ONLY follow-up to diag_01 (whose duplicate hypothesis was NOT
SUPPORTED: 0 conflicting duplicates, per-flow ceiling 1.0). Characterises the focus specialist's A -> B errors on
focus-group val (default port_scan -> syn_flood, G1) to rank alternative explanations, and repeats diag_01's Q5
threshold test on the sets that exist: ALL A flows and the MISCLASSIFIED A flows (instead of the empty conflict set).

  E1 init-window shift   A flows per FWD Init Win Bytes value: share in train vs val, specialist error rate per value
  E2 error vs correct    quantiles of flags / packet counts / duration for errors vs correctly classified A flows
  E3 where / when        errors per victim device, per Dst IP, per minute of the val window
  E4 context thresholds  diag_01's causal context features (same Src IP, [t - W, t)), threshold picked on train
                         (all A vs all B), read on val for all A, misclassified A, and B
Train / val via common/phase2_data.load_split (test never read); seed-0 boosters of step 22 loaded read-only (sha256
checked); nothing trained; no existing file changed. Outputs: results/diag_01b/ (summary.md, run_manifest.json,
run_meta.json, run.log, figures/*.png); diag_01b.json in ~/lgids_cache/v2/diag/<run_id>/.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from common import phase2_data as D  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

_spec = importlib.util.spec_from_file_location("diag01", REPO / "diagnostics" / "diag_01_portscan_synflood.py")
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)                                            # reuse diag_01's tested helpers

SCRIPT = "diagnostics/diag_01b_alternatives.py"
STEP = "diag_01b"
IW = "FWD Init Win Bytes"
CMP = ["Flow Duration", "Total Fwd Packet", "Total Bwd packets", "SYN Flag Count", "RST Flag Count", "ACK Flag Count",
       "FIN Flag Count", IW, "Bwd Init Win Bytes", "Fwd Header Length", "Flow IAT Min"]


def fig_initwin(path, rows: pd.DataFrame, title):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 0.42 * len(rows) + 1.4))
    y = np.arange(len(rows))
    axes[0].barh(y + 0.2, 100 * rows["share_train"], 0.38, color=PS.NEUTRAL_LIGHT, label="train")
    axes[0].barh(y - 0.2, 100 * rows["share_val"], 0.38, color=PS.CATEGORICAL[0], label="val")
    axes[0].set_yticks(y, [f"{v:g}" for v in rows["init_win"]])
    axes[0].invert_yaxis()
    axes[0].set_xlabel("% of the group's port_scan flows")
    axes[0].set_ylabel("FWD Init Win Bytes")
    axes[0].legend(frameon=False, loc="lower right")
    axes[0].xaxis.grid(True)
    er = 100 * rows["val_error_rate"].to_numpy(float)
    axes[1].barh(y, np.nan_to_num(er), 0.5, color=PS.TEXT2)
    for yi, (e, n) in enumerate(zip(er, rows["n_val"])):
        axes[1].text((0 if np.isnan(e) else e) + 1, yi, f"{'n/a' if np.isnan(e) else f'{e:.1f} %'}  (n={n:,})",
                     va="center", fontsize=7.5)
    axes[1].set_yticks(y, [""] * len(rows))
    axes[1].invert_yaxis()
    axes[1].set_xlim(0, 118)
    axes[1].set_xlabel("val flows labelled syn_flood by the specialist (%)")
    axes[1].xaxis.grid(True)
    fig.subplots_adjust(top=0.82, wspace=0.08)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def main() -> int:
    import xgboost as xgb
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--class-a", default="port_scan")
    ap.add_argument("--class-b", default="syn_flood")
    ap.add_argument("--focus-group", default="G1")
    args = ap.parse_args()
    cfg = load_phase2_config()
    S.verify_v2_lock(strict=True)
    pins_before = {"config/config.py": R.sha256_path(S.CONFIG_PY_PATH), "config/class_map.json": R.sha256_path(S.CLASS_MAP_PATH)}
    cm = S.load_class_map()
    names = list(cm.names)
    A, B = cm.id_of(args.class_a), cm.id_of(args.class_b)
    feats = S.feature_columns()
    up = R.resolve_run("22", None, False)
    ctx = R.start_run(STEP, "diag", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT, ["diagnostics/diag_01_portscan_synflood.py"])
    M.update({"train_run": up["meta"]["run_id"], "pins_before": pins_before, "follows": "results/diag_01",
              "read_only": "no model trained; no existing file changed; test never read"})
    ok, out, L = False, {}, []
    fg = args.focus_group
    try:
        c = cfg["columns"]
        cols = feats + [c["group"], c["label_id"], "Src IP", "Dst IP", "Dst Port", "start_ts", "device", "session"]
        tr = D.load_split(cfg, "train", cols, sample=args.dry_run)
        va = D.load_split(cfg, "val", cols, sample=args.dry_run)
        M["inputs"] = {"train_sha256": D.verify_split_file(cfg, "train"), "val_sha256": D.verify_split_file(cfg, "val"),
                       "test_read": False}
        prim, default = up["manifest"]["routing"]["primary"], up["manifest"]["routing"]["default"]
        spec = prim.get(fg, default)
        m = next(x for x in up["manifest"]["models"] if x["model_id"] == spec and x["seed"] == cfg["seeds"][0])
        p = up["dir"] / m["file"]
        if R.sha256_path(p) != m["sha256"]:
            raise RuntimeError(f"{p}: sha256 != step 22 manifest")
        b = xgb.Booster()
        b.load_model(str(p))
        selv = ((va[c["group"]].astype(str) == fg) & (va[c["label_id"]] == A)).to_numpy()
        selt = ((tr[c["group"]].astype(str) == fg) & (tr[c["label_id"]] == A)).to_numpy()
        pred = b.predict(xgb.DMatrix(D.feature_matrix(va.loc[selv], feats))).argmax(1)
        vA, tA = va.loc[selv].reset_index(drop=True), tr.loc[selt].reset_index(drop=True)
        err = pred == B
        out["n"] = {"val_A": int(len(vA)), "errors": int(err.sum()), "train_A": int(len(tA)), "model": m["key"]}
        # E1 init-window shift
        vals = sorted(set(vA[IW].unique()) | set(tA[IW].unique()))
        rows = []
        for v in vals:
            mv, mt = (vA[IW] == v).to_numpy(), (tA[IW] == v).to_numpy()
            rows.append({"init_win": float(v), "n_train": int(mt.sum()), "share_train": float(mt.mean()),
                         "n_val": int(mv.sum()), "share_val": float(mv.mean()),
                         "val_errors": int((err & mv).sum()),
                         "val_error_rate": float(err[mv].mean()) if mv.any() else float("nan"),
                         "share_of_all_errors": float((err & mv).sum() / max(1, err.sum()))})
        e1 = pd.DataFrame(rows).sort_values("n_val", ascending=False)
        out["e1_init_window"] = e1.to_dict("records")
        # train-side: how do B flows look at the init-window values where A errors concentrate?
        trB = tr.loc[(tr[c["label_id"]] == B).to_numpy()]
        out["e1_B_train_init_window"] = {str(k): int(v) for k, v in trB[IW].value_counts().head(8).items()}
        out["e1_A_train_all_groups_init_window"] = {str(k): int(v) for k, v in
                                                   tr.loc[(tr[c["label_id"]] == A).to_numpy(), IW].value_counts().head(8).items()}
        # E2 errors vs correct
        q = lambda s: {"q5": float(s.quantile(0.05)), "q50": float(s.quantile(0.5)), "q95": float(s.quantile(0.95))}  # noqa: E731
        out["e2"] = {f: {"error": q(vA.loc[err, f]), "correct": q(vA.loc[~err, f]), "train_A": q(tA[f])} for f in CMP}
        # E3 where / when
        e3 = {}
        for col in ("device", "Dst IP", "session"):
            g = vA.groupby(vA[col].astype(str)).apply(lambda d: pd.Series({"n": len(d), "errors": int(err[d.index].sum())}),
                                                       include_groups=False)
            g["error_rate"] = g["errors"] / g["n"]
            e3[col] = g.sort_values("errors", ascending=False).head(10).reset_index().to_dict("records")
        minute = (vA["start_ts"] // 60).astype(int)
        tm = pd.DataFrame({"minute": minute, "err": err}).groupby("minute")["err"].agg(["size", "sum"])
        out["e3"] = e3
        out["e3_minutes"] = {"n_minutes": int(len(tm)), "minutes_all_errors": int(((tm["sum"] == tm["size"]) & (tm["size"] > 0)).sum()),
                             "minutes_no_errors": int((tm["sum"] == 0).sum()),
                             "first_utc": pd.to_datetime(int(vA["start_ts"].min()), unit="s", utc=True).isoformat() if len(vA) else None,
                             "last_utc": pd.to_datetime(int(vA["start_ts"].max()), unit="s", utc=True).isoformat() if len(vA) else None}
        tmt = (tA["start_ts"] // 60)
        out["e3_train_window"] = {"first_utc": pd.to_datetime(int(tA["start_ts"].min()), unit="s", utc=True).isoformat(),
                                  "last_utc": pd.to_datetime(int(tA["start_ts"].max()), unit="s", utc=True).isoformat(),
                                  "n_minutes": int(tmt.nunique())}
        # E4 context thresholds on existing sets
        ctxs = {}
        for split, df_ in (("train", tr), ("val", va)):
            F = {W: G.context_features(df_["Src IP"].to_numpy(), df_["Dst IP"].to_numpy(),
                                       pd.to_numeric(df_["Dst Port"], errors="coerce").fillna(-1).to_numpy(np.int64),
                                       df_["start_ts"].to_numpy(np.int64), W) for W in G.WINDOWS}
            ctxs[split] = F
        ytr, yva = tr[c["label_id"]].to_numpy(), va[c["label_id"]].to_numpy()
        gva = va[c["group"]].astype(str).to_numpy()
        err_full = np.zeros(len(va), bool)
        err_full[np.flatnonzero(selv)[err]] = True
        e4 = []
        for W in G.WINDOWS:
            for j, f in enumerate(G.CTX):
                thr = G.best_threshold(ctxs["train"][W][ytr == A, j], ctxs["train"][W][ytr == B, j])
                Fv = ctxs["val"][W][:, j]
                for s, mA in (("all val A", yva == A), (f"{fg} val A", (yva == A) & (gva == fg)),
                              (f"{fg} val A misclassified as B", err_full)):
                    e4.append({"W": W, "feature": f, "A_set": s, **thr, "n_A": int(mA.sum()),
                               "A_on_A_side": float(G.side(Fv[mA], thr).mean()) if mA.any() else float("nan"),
                               "B_on_B_side": float((~G.side(Fv[yva == B], thr)).mean())})
        out["e4"] = e4
        R.write_json(ctx.partial / "diag_01b.json", out)
        fig_initwin(ctx.fig / "init_window_shift.png", e1.head(8),
                    f"{fg} {args.class_a}: FWD Init Win Bytes, train vs val share, and {m['key']} error rate per value (val)")
        M["figures"] = sorted(str(x.relative_to(ctx.res)) for x in ctx.fig.glob("*.png"))
        ok = True
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
    M["pins_after"] = {"config/config.py": R.sha256_path(S.CONFIG_PY_PATH), "config/class_map.json": R.sha256_path(S.CLASS_MAP_PATH)}
    ok = ok and M["pins_after"] == pins_before
    R.add_check(ctx, M, "config.py / class_map.json unchanged by this run", M["pins_after"] == pins_before, "")
    M["status"] = "PASS" if ok else "FAIL"
    a, b_ = args.class_a, args.class_b
    L = [f"# diag_01b -- alternatives: what the {fg} {a} -> {b_} errors have in common -- {M['status']}"
         + (" (DRY RUN)" if args.dry_run else ""), "",
         "- READ-ONLY follow-up to `results/diag_01` (duplicate hypothesis NOT SUPPORTED). Train / val only; the seed-0 "
         "specialist loaded read-only; nothing trained.", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```"]
    else:
        n = out["n"]
        L += [f"- {n['model']} on {fg} val {a}: {n['errors']:,} of {n['val_A']:,} labelled {b_} "
              f"({100 * n['errors'] / max(1, n['val_A']):.1f} %)", "",
              f"## E1 -- {IW} of {fg} {a} flows, train vs val, and the error rate per value", "",
              "| init win | train n | train % | val n | val % | val errors | val error rate | % of all errors |", "|---|---|---|---|---|---|---|---|"]
        for r in out["e1_init_window"][:10]:
            L.append(f"| {r['init_win']:g} | {r['n_train']:,} | {100 * r['share_train']:.1f} | {r['n_val']:,} | "
                     f"{100 * r['share_val']:.1f} | {r['val_errors']:,} | "
                     + ("n/a" if np.isnan(r["val_error_rate"]) else f"{100 * r['val_error_rate']:.1f} %")
                     + f" | {100 * r['share_of_all_errors']:.1f} |")
        L += ["", f"- train {b_} {IW} (all groups, top values): {out['e1_B_train_init_window']}",
              f"- train {a} {IW} (all groups, top values): {out['e1_A_train_all_groups_init_window']}", "",
              f"## E2 -- errors vs correct {a} flows ({fg} val) and train {a} (q50 [q5, q95])", "",
              "| feature | errors | correct | train " + a + " |", "|---|---|---|---|"]
        for f, d in out["e2"].items():
            L.append(f"| {f} | {d['error']['q50']:g} [{d['error']['q5']:g}, {d['error']['q95']:g}] | "
                     f"{d['correct']['q50']:g} [{d['correct']['q5']:g}, {d['correct']['q95']:g}] | "
                     f"{d['train_A']['q50']:g} [{d['train_A']['q5']:g}, {d['train_A']['q95']:g}] |")
        L += ["", "## E3 -- where and when", ""]
        for col, rws in out["e3"].items():
            L += [f"Top {col} by errors:", "", f"| {col} | n | errors | error rate |", "|---|---|---|---|"]
            L += [f"| {r[col]} | {int(r['n']):,} | {int(r['errors']):,} | {100 * r['error_rate']:.1f} % |" for r in rws] + [""]
        L += [f"- val window {out['e3_minutes']['first_utc']} .. {out['e3_minutes']['last_utc']} "
              f"({out['e3_minutes']['n_minutes']} minutes with {a} flows; {out['e3_minutes']['minutes_all_errors']} minutes "
              f"where every flow is an error, {out['e3_minutes']['minutes_no_errors']} with none); train window "
              f"{out['e3_train_window']['first_utc']} .. {out['e3_train_window']['last_utc']}", "",
              f"## E4 -- causal context (same Src IP, [t - W, t)): threshold picked on train (all {a} vs all {b_}), read on val", "",
              f"- {b_} rows are V1's capped sample, so {b_}-side counts are undercounts (see diag_01).", "",
              f"| W (s) | feature | {a} set (val) | rule | {a} on {a} side | {b_} on {b_} side |", "|---|---|---|---|---|---|"]
        for r in out["e4"]:
            L.append(f"| {r['W']} | {r['feature']} | {r['A_set']} (n={r['n_A']:,}) | {r['direction']} {r['theta']:g} | "
                     f"{100 * r['A_on_A_side']:.1f} % | {100 * r['B_on_B_side']:.1f} % |")
        L += ["", "## Figures", "", f"- `figures/init_window_shift.png` -- share of {fg} {a} flows per {IW} value in train vs "
              f"val (left) and the specialist's val error rate per value (right)."]
    (ctx.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
