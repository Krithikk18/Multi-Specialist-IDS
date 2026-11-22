#!/usr/bin/env python
"""28_run_stream.py -- Phase 3 step E: run the streaming runtime on VAL (CSV replay, max speed) and apply the
PARITY GATE (docs/V2_PREREG_PHASE3.md section 1); then the report-only pcap path.

Runs (one runtime run folder each: ~/lgids_cache/v2/runtime/<run_id>_<MODE>_s<seed>/ with predictions.parquet,
alerts.jsonl, health.jsonl, alerts_outbox.jsonl, incidents.json, latency.npz, rss.json, manifest.json):
  GLOBAL s0   the promoted model (deployment load) + rate guard v2 / V1 on the val packets; features stored (parity)
  ROUTED s0   comparison (evaluation-only load) + the same packet path
  GLOBAL / ROUTED s1-4   evaluation-only loads, no packet path (rate_guard_enabled=False: it does not depend on the
              model; 29 uses the s0 runs' rate-guard alerts)
Parity gate (hard, GLOBAL s0): every val flow processed (0 quarantined, 0 dropped) and matched 1:1; runtime-normalised
features == v2_1_oriented (exact float32); predicted class == offline step 23 path (DMatrix predict) 100 %;
calibrated probabilities within 1e-6 of softmax(margin / T); routing group == dataset group and device == dataset
device_mac 100 %; the offline reference reproduces step 23's recorded seed-0 numbers (FLAT_GLOBAL_A1_none false-alarm
count and per-class recall). ROUTED / seeds: the same comparisons, reported.
pcap path (report-only): the Recon-PortScan val window written to a slice pcap (+ slice manifest), the locked
CICFlowMeter run on it (CicfmPcapSource), its rows matched to the dataset (Flow ID + start second, in order), feature
equality within tolerance, mismatch profile by feature, emission-time lag; the runtime run on that source too.
Outputs: results/phase3/28/ summary.md, parity.json, runs.json, run_manifest.json, run_meta.json, run.log, figures/.
--dry-run: the 5 % val sample, GLOBAL / ROUTED s0 only, packets of Recon-PortScan only, a 20,000-packet pcap slice;
*_dry_run cache dirs, results/phase3/28/dry_run/<run_id>/.
Phase 3.1 options: --config <file> (e.g. config/v2_phase3_1.json: chunked predictions, sequential capture reading,
learned IP -> MAC routing on the pcap path; pinned like the Phase 3 config); --s0-only (GLOBAL s0 with the packet path
+ ROUTED s0); --compare-to <tag> (hard checks: every run's predictions, rate-guard alerts and incidents equal those of
the same run in results/phase3/28/<tag>/, row for row). Predictions are read with common/predictions_io (either
layout). The pcap path routes with routing.ip_mac_source[cicfm_pcap] (learned: the slice's own frames, ARP included,
feed the learner in event time) and reports static vs learned routing agreement side by side.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import defaultdict
from pathlib import Path

import numpy as np

from config.config import REPO_ROOT
from common import alert_log as AL
from common import flow_source as FS
from common import model_loader as ML
from common import packet_source as PK
from common import predictions_io as PIO
from common import phase3_config as C
from common import phase3_run as R3
from common import plot_style as PS
from common import rate_guard_v2 as RG
from common import schemas as S
from common.phase2_metrics import softmax
from common.routing import Router
from common.runtime import Runtime

SCRIPT = "28_run_stream.py"
TOL_P = 1e-6


def reference(cfg: dict, dry: bool) -> dict:
    """Offline v2_1 val rows (the step 23 / 24 inputs): features, labels, groups, devices, keys."""
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    cfg2 = load_phase2_config(REPO_ROOT / cfg["phase2_config"])
    feats = S.feature_columns()
    va = D.load_split(cfg2, "val", feats + ["session", "row_in_file", "label_id", "group", "device_mac"], sample=dry)
    return {"X": D.feature_matrix(va, feats), "y": va["label_id"].to_numpy(np.int64),
            "group": va["group"].astype(str).to_numpy(), "device_mac": va["device_mac"].astype(str).to_numpy(),
            "uid": (va["session"].astype(str) + ":" + va["row_in_file"].astype(str)).to_numpy(),
            "file_sha256": D.verify_split_file(cfg2, "val"), "cfg2": cfg2}


def offline_scores(rm, ref: dict) -> dict:
    import xgboost as xgb
    X = ref["X"]
    mids = np.array([rm.model_for(g) for g in ref["group"]], dtype=object)
    P23 = np.empty((len(X), len(rm.class_names)))
    Pc = np.empty_like(P23)
    for mid in dict.fromkeys(mids.tolist()):
        ix = np.flatnonzero(mids == mid)
        m = rm.models[mid]
        dm = xgb.DMatrix(X[ix])
        P23[ix] = m.booster.predict(dm)                                     # step 23's path (T = 1)
        Pc[ix] = softmax(m.booster.predict(dm, output_margin=True).astype(np.float64), m.temperature)   # step 24
    return {"P23": P23, "Pcal": Pc, "pred": P23.argmax(1)}


def run_one(cfg, run, tag: str, mode: str, seed: int, dry: bool, packets: bool, store: bool, secret: bytes,
            pk_sessions=None, source=None, learn_pcap: Path | None = None) -> dict:
    rcfg = C.with_overrides(cfg, mode=mode, seed=seed, rate_guard_enabled=packets)
    root = C.expand(cfg["paths"]["runtime_root"])
    root = root.with_name(root.name + "_dry_run") if dry else root
    d = root / f"{run.run_id}_{tag}"
    d.mkdir(parents=True, exist_ok=False)
    rm = ML.load_runtime_model(rcfg, mode=mode, seed=seed, evaluation=not (mode == cfg["mode"] and seed == 0))
    src = source if source is not None else FS.CsvReplaySource(rcfg, sample=dry)
    kind = "cicfm_pcap" if source is not None else rcfg["source"]["kind"]
    router = Router(rcfg, ip_mac_source=C.ip_mac_source(rcfg, kind))
    rg, pkts, thr_info = None, None, None
    if packets:
        T, TM = RG.load_thresholds(rcfg)
        r = rcfg["rate_guard"]
        rg = (RG.RateGuardV2(router, T["thresholds"], r["families"], r["other_family"], r["window_s"], r["consecutive"],
                             fallback_group=router.fallback), RG.V1Guard(rcfg))
        pkts = PK.PacketSource(rcfg, rcfg["source"]["split"], sessions=pk_sessions,
                               sequential=bool(rcfg["packets"].get("open_sequentially", False)),
                               arp=router.learner is not None)
        thr_info = {"thresholds_sha256": TM["thresholds_sha256"], "fit_run": TM["run_id"]}
    learn_counts = None
    if pkts is None and router.learner is not None and learn_pcap is not None:
        from collections import Counter
        learn_counts = Counter()
        pkts = PK.iter_pcap(Path(learn_pcap), learn_counts, arp=True)  # the slice is already split-confined
    rt = Runtime(rcfg, rm, d, secret, rate_guard=rg, store_features=store, router=router)
    run.log(f"  run {tag}: {len(src):,} flows, packets {'on' if packets else 'off'} -> {d}")
    summ = rt.run(src, pkts, info=getattr(src, "info", {}))
    man = {"run_dir": str(d), "tag": tag, "mode": mode, "seed": seed, "evaluation_only": rm.evaluation_only,
           "model": rm.describe(), "config_sha256": rcfg["_sha256"], "overrides": rcfg["_overrides"],
           "source": getattr(src, "info", {}), "packets": (pkts.describe() if hasattr(pkts, "describe") else
                                                            {"learner_frames_from": str(learn_pcap), "reader": dict(learn_counts or {})})
           if pkts is not None else None, "rate_guard": thr_info, "ip_mac_source": router.ip_mac_source,
           "runtime_key_fingerprint": AL.REG.fingerprint(AL.REG.public_key(secret)),
           "summary": summ, "parent_run": run.run_id, "script": SCRIPT}
    R3.write_json(d / "manifest.json", man)
    c = summ["counts"]
    run.log(f"    {c.get('flows_scored', 0):,} flows scored in {summ['wall_s']:.1f} s ({summ['flows_per_s']:,.0f}/s), "
            f"flow alerts {c.get('flow_alerts', 0):,}, rg alerts v2 {c.get('rg_alerts_v2', 0):,} / v1 {c.get('rg_alerts_v1', 0):,}, "
            f"incidents {summ['incidents']:,}, quarantined {c.get('quarantined', 0)}, dropped {c.get('dropped', 0)}, "
            f"packets {c.get('packets', 0):,}")
    return {"dir": d, "rm": rm, "summary": summ, "manifest": man}


def parity(run, M, res: dict, ref: dict, off: dict, hard: bool, label: str) -> dict:
    import pyarrow.parquet as pq
    d = res["dir"]
    P = PIO.read_predictions(d)
    K = len(res["rm"].class_names)
    c = res["summary"]["counts"]
    pos = {u: i for i, u in enumerate(ref["uid"])}
    idx = np.array([pos.get(u, -1) for u in P["flow_uid"]])
    ok_match = len(P) == len(ref["uid"]) and (idx >= 0).all() and len(set(idx.tolist())) == len(idx)
    chk = lambda n, o, det: run.check(M, f"{label}: {n}", o, det, warn=not hard)   # noqa: E731
    out = {"n_runtime": int(len(P)), "n_offline": int(len(ref["uid"]))}
    chk("every val flow processed and matched 1:1 (0 quarantined, 0 dropped)",
        ok_match and c.get("quarantined", 0) == 0 and c.get("dropped", 0) == 0,
        f"runtime {len(P):,} / offline {len(ref['uid']):,}; quarantined {c.get('quarantined', 0)}, dropped {c.get('dropped', 0)}")
    if not ok_match:
        return out
    if (d / "features.npy").is_file():
        Xr = np.load(d / "features.npy")
        eq = np.all(Xr == ref["X"][idx], axis=1)
        out["features_equal_rows"] = int(eq.sum())
        chk("runtime-normalised features == v2_1_oriented (exact float32, all 70)", bool(eq.all()),
            f"{int(eq.sum()):,} / {len(eq):,} rows identical")
    pr = P["pred"].to_numpy()
    agree = pr == off["pred"][idx]
    Pr = P[[f"p_{k}" for k in range(K)]].to_numpy()
    dp = np.abs(Pr - off["Pcal"][idx]).max(1)
    out.update({"class_agree": int(agree.sum()), "max_abs_dp": float(dp.max()), "dp": dp, "pred_rt": pr,
                "pred_off": off["pred"][idx]})
    chk("predicted class == offline step 23 path (100 %)", bool(agree.all()), f"{int(agree.sum()):,} / {len(agree):,}")
    chk(f"calibrated probabilities within {TOL_P:g} of softmax(margin / T)", float(dp.max()) <= TOL_P,
        f"max |dp| {dp.max():.3e}")
    g_ok = P["group"].to_numpy() == ref["group"][idx]
    m_ok = P["device_mac"].to_numpy() == ref["device_mac"][idx]
    out.update({"group_agree": int(g_ok.sum()), "device_agree": int(m_ok.sum())})
    chk("routing group == dataset group (100 %)", bool(g_ok.all()), f"{int(g_ok.sum()):,} / {len(g_ok):,}")
    chk("protected device == dataset device_mac (100 %)", bool(m_ok.all()), f"{int(m_ok.sum()):,} / {len(m_ok):,}")
    return out


def pcap_path(cfg, run, M, dry: bool, secret: bytes) -> dict:
    """Report-only: slice -> locked CICFlowMeter -> match to dataset rows -> feature equality, lag; runtime run."""
    import pandas as pd
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    ps = cfg["pcap_source"]
    sess = ps["slice_session"]
    root = C.expand(cfg["paths"]["runtime_root"]).parent / ("runtime_inputs_dry_run" if dry else "runtime_inputs")
    sd = root / run.run_id
    pcap = sd / f"{sess}_{ps['split']}.pcap"
    man = PK.write_slice(cfg, sess, ps["split"], pcap, max_packets=20000 if dry else None)
    run.log(f"  pcap slice {pcap}: {man['frames_written']:,} frames, {man['first_ts']:.1f} .. {man['last_ts']:.1f}")
    src = FS.CicfmPcapSource(cfg, pcap, sd / "cfm")
    info = src.extract()
    run.log(f"  CICFlowMeter: {info['rows']:,} flows in {info['cfm']['wall_s']:.1f} s wall "
            f"({man['frames_written'] / info['cfm']['wall_s']:,.0f} frames/s incl. JVM start)")
    cfg2 = load_phase2_config(REPO_ROOT / cfg["source"]["replay_phase2_config"])
    feats = S.feature_columns()
    ds = D.load_split(cfg2, ps["split"], feats + ["Flow ID", "start_ts", "session", "row_in_file", "group", "device_mac"])
    ds = ds[(ds["session"] == sess) & (ds["start_ts"] >= int(man["first_ts"])) & (ds["start_ts"] <= int(man["last_ts"]))]
    ds = ds.reset_index(drop=True)
    by = defaultdict(list)
    for i, (f, t) in enumerate(zip(ds["Flow ID"], ds["start_ts"])):
        by[(f, int(t))].append(i)
    pairs = []
    for j, (f, t) in enumerate(zip(src._ids["Flow ID"], src._start)):
        L = by.get((f, int(t)))
        if L:
            pairs.append((L.pop(0), j))
    di = np.array([a for a, _ in pairs], dtype=np.int64)
    cj = np.array([b for _, b in pairs], dtype=np.int64)
    A = ds[feats].to_numpy(np.float64)[di]
    B = np.column_stack([np.asarray(src._feat[f], np.float64) for f in feats])[cj]
    B[~np.isfinite(B)] = 0.0
    tol = ps["match_tolerance"]
    close = np.abs(A - B) <= tol["abs"] + tol["rel"] * np.abs(A)
    row_eq = close.all(1)
    lag = src.lags()
    rep = {"slice": man, "cfm": info["cfm"], "schema": info["schema"], "csv_rows": int(info["rows"]),
           "dataset_rows_in_window": int(len(ds)), "matched": int(len(pairs)),
           "match_rate_of_dataset": float(len(pairs) / max(len(ds), 1)),
           "feature_equal_rows": int(row_eq.sum()), "feature_equal_share": float(row_eq.mean()) if len(row_eq) else None,
           "mismatch_by_feature": {f: int((~close[:, k]).sum()) for k, f in enumerate(feats) if (~close[:, k]).any()},
           "lag_s_all": {q: float(np.quantile(lag, x)) for q, x in (("p50", .5), ("p95", .95), ("p99", .99), ("max", 1.0))},
           "lag_s_matched": ({q: float(np.quantile(lag[cj], x)) for q, x in (("p50", .5), ("p95", .95), ("max", 1.0))}
                             if len(cj) else None),
           "frames_per_s_incl_jvm": man["frames_written"] / info["cfm"]["wall_s"]}
    run.check(M, "pcap path: feature equality on matched flows >= 99 % (report-only target)",
              rep["feature_equal_share"] is not None and rep["feature_equal_share"] >= 0.99,
              f"{rep['feature_equal_rows']:,} / {rep['matched']:,} matched rows identical; matched "
              f"{rep['matched']:,} of {rep['dataset_rows_in_window']:,} dataset rows ({rep['match_rate_of_dataset']:.1%}); "
              f"CSV rows {rep['csv_rows']:,}", warn=True)
    r = run_one(cfg, run, "PCAP_GLOBAL_s0", cfg["mode"], 0, dry, False, False, secret, source=src, learn_pcap=pcap)
    P = PIO.read_predictions(r["dir"])
    rows = P["row"].to_numpy()
    g_rt = dict(zip(rows, P["group"]))
    m_rt = dict(zip(rows, P["device_mac"]))
    pred_rt = dict(zip(rows, P["pred"]))
    rep["runtime"] = {"run_dir": str(r["dir"]), "flows": int(len(P)), "router": r["summary"]["router"],
                      "ip_mac_source": r["manifest"]["ip_mac_source"], "learner": r["summary"].get("learner"),
                      "health_events": {k: r["summary"]["counts"].get(k, 0)
                                        for k in ("ip_mac_change", "ip_mac_flap", "gateway_detected")},
                      "arp_records": r["summary"]["counts"].get("arp_records", 0)}
    if len(pairs):
        rep["runtime"]["group_agree_matched"] = float(np.mean([g_rt.get(j) == ds["group"].iloc[i] for i, j in pairs]))
        rep["runtime"]["device_agree_matched"] = float(np.mean([m_rt.get(j) == ds["device_mac"].iloc[i] for i, j in pairs]))
        # the same rows routed with the static IP -> MAC map (Phase 3's pcap-path routing), for comparison
        st = Router(cfg, ip_mac_source="static")
        sg, sm = [], []
        for i, j in pairs:
            rr = st.route({"Src IP": src._ids["Src IP"][j], "Dst IP": src._ids["Dst IP"][j], "_meta": {"start_ts": src._start[j]}})
            sg.append(rr.group == ds["group"].iloc[i])
            sm.append(rr.device_mac == ds["device_mac"].iloc[i])
        rep["static_routing"] = {"group_agree_matched": float(np.mean(sg)), "device_agree_matched": float(np.mean(sm)),
                                 "router": dict(st.stats)}
        run.check(M, "pcap path: learned routing group agreement on matched flows >= 99 % (report-only target)",
                  rep["runtime"]["group_agree_matched"] >= 0.99,
                  f"learned ({rep['runtime']['ip_mac_source']}) group {rep['runtime']['group_agree_matched']:.2%}, device "
                  f"{rep['runtime']['device_agree_matched']:.2%}; static group {rep['static_routing']['group_agree_matched']:.2%}, "
                  f"device {rep['static_routing']['device_agree_matched']:.2%}", warn=True)
        rep["_pred_matched"] = [pred_rt.get(j) for _, j in pairs]
        rep["_ds_rows"] = di
    rep["_mismatch"] = rep["mismatch_by_feature"]
    return rep


def _rg_records(d: Path) -> list:
    out = []
    for line in (d / "alerts.jsonl").read_text(encoding="utf-8").splitlines():
        a = json.loads(line)
        if a.get("path") == "rate_guard":
            out.append({k: v for k, v in a.items() if k not in ("wall_time", "sig", "prev_sha256", "seq")})
    return out


def compare_runs(run, M: dict, runs: dict, tag: str) -> dict:
    """Hard: each run's predictions (row for row, every column), rate-guard alert records (minus wall time / chain
    fields) and incidents equal the same run of the earlier step 28 run results/phase3/28/<tag>/."""
    up = R3.resolve("28", None, False, tag)
    out = {"run_id": up["meta"]["run_id"], "tag": tag, "runs": {}}
    for t, r in runs.items():
        o = up["manifest"]["runs"].get(t)
        if o is None:
            run.check(M, f"compare {t}: present in {tag}", False, "")
            continue
        od, nd = Path(o["dir"]), r["dir"]
        Po, Pn = PIO.read_predictions(od), PIO.read_predictions(nd)
        same_p = list(Po.columns) == list(Pn.columns) and len(Po) == len(Pn) and Po.equals(Pn)
        rgo, rgn = _rg_records(od), _rg_records(nd)
        inc_o = json.loads((od / "incidents.json").read_text(encoding="utf-8"))
        inc_n = json.loads((nd / "incidents.json").read_text(encoding="utf-8"))
        out["runs"][t] = {"rows": int(len(Pn)), "predictions_equal": bool(same_p), "rate_guard_alerts": len(rgn),
                          "rate_guard_equal": rgo == rgn, "incidents_equal": inc_o == inc_n,
                          "layout": PIO.layout(nd), "layout_before": PIO.layout(od)}
        run.check(M, f"compare {t}: predictions identical to {tag} row for row (every column)", same_p,
                  f"{len(Pn):,} rows ({PIO.layout(nd)}) vs {len(Po):,} ({PIO.layout(od)})")
        run.check(M, f"compare {t}: rate-guard alerts and incidents identical to {tag}", rgo == rgn and inc_o == inc_n,
                  f"rate-guard alerts {len(rgn)} vs {len(rgo)}; incidents {len(inc_n)} vs {len(inc_o)}")
    return out


def figures(run, par: dict, names: list, pcap: dict | None) -> list:
    import matplotlib.pyplot as plt
    PS.apply()
    out = []
    K = len(names)
    cm = np.zeros((K, K), np.int64)
    np.add.at(cm, (par["pred_off"], par["pred_rt"]), 1)
    fig, ax = plt.subplots(figsize=(4.6, 3.9))
    ax.imshow(np.log10(cm + 1), cmap=PS.SEQUENTIAL_CMAP)
    for i in range(K):
        for j in range(K):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=8,
                    color="white" if cm[i, j] > cm.max() / 10 else PS.TEXT1)
    ax.set_xticks(range(K), names, rotation=20, ha="right")
    ax.set_yticks(range(K), names)
    ax.set_xlabel("runtime predicted class")
    ax.set_ylabel("offline (step 23 path) predicted class")
    ax.set_title("GLOBAL s0: offline vs runtime (counts; diagonal = agree)", loc="left", fontsize=9)
    f = run.fig / "parity_confusion.png"
    out.append(PS.save(fig, f))
    fig, ax = plt.subplots(figsize=(5.6, 3.0))
    dp = np.maximum(par["dp"], 1e-18)
    bins = np.logspace(-18, max(-5, np.log10(dp.max()) + 0.5), 60)
    ax.hist(dp, bins=bins, color=PS.CATEGORICAL[0])
    ax.axvline(TOL_P, color=PS.CATEGORICAL[1], lw=1.3)
    ax.text(TOL_P, ax.get_ylim()[1] * 0.92, f" gate {TOL_P:g}", color=PS.CATEGORICAL[1], fontsize=8, va="top")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("max over classes |p_runtime - p_offline| per flow (0 shown at 1e-18)")
    ax.set_ylabel("flows")
    ax.set_title(f"Calibrated probability difference, GLOBAL s0 (max {par['max_abs_dp']:.2e})", loc="left", fontsize=9)
    out.append(PS.save(fig, run.fig / "parity_abs_dp_hist.png"))
    if pcap and pcap.get("matched"):
        mm = sorted(pcap["mismatch_by_feature"].items(), key=lambda kv: -kv[1])[:20]
        fig, ax = plt.subplots(figsize=(6.4, 0.28 * max(len(mm), 3) + 1.0))
        if mm:
            y = np.arange(len(mm))[::-1]
            share = [v / pcap["matched"] for _, v in mm]
            ax.barh(y, share, color=PS.CATEGORICAL[0])
            for yy, s, (_, v) in zip(y, share, mm):
                ax.text(s, yy, f" {v:,} ({s:.1%})", va="center", fontsize=7)
            ax.set_yticks(y, [k for k, _ in mm], fontsize=7)
            ax.set_xlim(0, max(share) * 1.35)
        else:
            ax.text(0.5, 0.5, "no feature mismatches", transform=ax.transAxes, ha="center")
        ax.set_xlabel("share of matched flows whose value differs (beyond tolerance)")
        ax.set_title(f"pcap path: feature mismatches by feature ({pcap['matched']:,} matched flows, "
                     f"{(pcap['feature_equal_share'] or 0):.2%} fully equal)", loc="left", fontsize=9)
        out.append(PS.save(fig, run.fig / "pcap_feature_mismatch.png"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--no-pcap", action="store_true")
    ap.add_argument("--rerun-tag", default=None, help="full re-run: results go to results/phase3/28/<tag>/ (D85)")
    ap.add_argument("--config", default=None, help="runtime config file (default config/v2_phase3.json); pinned")
    ap.add_argument("--s0-only", action="store_true", help="GLOBAL s0 (with the packet path) + ROUTED s0 only")
    ap.add_argument("--compare-to", default=None, help="rerun tag of an earlier full step 28 run: predictions, rate-guard "
                    "alerts and incidents must equal its runs' row for row (hard)")
    args = ap.parse_args()
    cfg = C.load_phase3_config(Path(args.config)) if args.config else C.load_phase3_config()
    run = R3.Run("28", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest()
    R3.lock_banner(run, M, "start")
    ok, gate, runs, par, pc = False, False, {}, {}, None
    try:
        secret, public = AL.ensure_runtime_keys(C.expand(cfg["paths"]["runtime_keys_dir"]), REPO_ROOT)
        M["runtime_key_fingerprint"] = AL.REG.fingerprint(public)
        ref = reference(cfg, args.dry_run)
        M["reference"] = {"dataset": cfg["source"]["reference_dataset_version"], "val_sha256": ref["file_sha256"],
                          "n": int(len(ref["uid"]))}
        pk_sessions = ["Recon-PortScan"] if args.dry_run else None
        seeds = [0] if args.dry_run else cfg["models"]["evaluation"]["seeds"]
        plan = [("GLOBAL", 0, True, True), ("ROUTED", 0, True, False)] + \
               ([] if args.s0_only else [(m, s, False, False) for m in ("GLOBAL", "ROUTED") for s in seeds if s != 0])
        for mode, seed, packets, store in plan:
            tag = f"{mode}_s{seed}"
            runs[tag] = run_one(cfg, run, tag, mode, seed, args.dry_run, packets, store, secret, pk_sessions)
            off = offline_scores(runs[tag]["rm"], ref)
            if tag == "GLOBAL_s0" and not args.dry_run:
                up = json.loads((REPO_ROOT / "results/v2_1/23/metrics_summary.json").read_text(encoding="utf-8"))
                s0 = up["entities"]["FLAT_GLOBAL_A1_none"]["all"]["seed0"]
                fa = int(((ref["y"] == 0) & (off["pred"] != 0)).sum())
                rec = [float((off["pred"][ref["y"] == k] == k).mean()) for k in range(len(runs[tag]["rm"].class_names))]
                run.check(M, "offline reference reproduces step 23 (FLAT_GLOBAL_A1_none seed 0: FA count, recall)",
                          fa == s0["fa_count"] and np.allclose(rec, s0["recall"], atol=1e-12, rtol=0),
                          f"FA {fa} vs {s0['fa_count']}; recall {np.round(rec, 6).tolist()} vs {np.round(s0['recall'], 6).tolist()}")
            par[tag] = parity(run, M, runs[tag], ref, off, hard=(tag == "GLOBAL_s0"), label=f"parity {tag}")
        if args.compare_to:
            M["compare_to"] = compare_runs(run, M, runs, args.compare_to)
        hard = [c for c in M["checks"] if c["level"] == "hard"]
        gate = all(c["pass"] for c in hard)
        M["parity_gate"] = "PASS" if gate else "FAIL"
        run.log(f"PARITY GATE: {M['parity_gate']}")
        if not args.no_pcap:
            try:
                pc = pcap_path(cfg, run, M, args.dry_run, secret)
            except Exception as e:                                     # noqa: BLE001  (report-only path)
                M["pcap_error"] = "".join(traceback.format_exception(e))
                run.log(f"pcap path error (report-only): {e!r}")
        names = list(S.load_class_map().names)
        M["figures"] = [str(Path(p).relative_to(run.res)) for p in figures(run, par["GLOBAL_s0"], names, pc)]
        M["runs"] = {t: {"dir": str(r["dir"]), "mode": r["manifest"]["mode"], "seed": r["manifest"]["seed"],
                         "evaluation_only": r["manifest"]["evaluation_only"], "counts": r["summary"]["counts"],
                         "wall_s": r["summary"]["wall_s"], "flows_per_s": r["summary"]["flows_per_s"],
                         "incidents": r["summary"]["incidents"], "logs": r["summary"]["logs"],
                         "peak_rss_mb": r["summary"]["peak_rss_mb"]} for t, r in runs.items()}
        if pc is not None:
            M["pcap_path"] = {k: v for k, v in pc.items() if not k.startswith("_")}
        M["parity"] = {t: {k: v for k, v in p.items() if k not in ("dp", "pred_rt", "pred_off")} for t, p in par.items()}
        R3.write_json(run.res / "parity.json", M["parity"])
        R3.write_json(run.res / "runs.json", M["runs"])
        R3.lock_banner(run, M, "end")
        ok = gate
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def write_summary(run, M: dict, dry: bool) -> None:
    st = "PASS" if (M.get("parity_gate") == "PASS" and not M.get("error")) else "FAIL"
    L = [f"# Step 28 -- streaming runtime on val + parity gate -- {st}" + (" (DRY RUN)" if dry else ""), "",
         f"- run `{run.run_id}`; CSV replay of `{run.cfg['source']['replay_dataset_version']}` val rows (extractor "
         f"orientation) at max speed; offline reference `{run.cfg['source']['reference_dataset_version']}` val "
         f"(n = {M.get('reference', {}).get('n', 0):,}); runtime alert key fingerprint `{M.get('runtime_key_fingerprint')}`",
         f"- **PARITY GATE: {M.get('parity_gate', 'not reached')}** (GLOBAL s0, the promoted model; criteria in "
         "docs/V2_PREREG_PHASE3.md section 1)", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("parity"):
        L += ["## Parity per run", "", "| run | flows | features identical | class agree | max abs dp | group agree | "
              "device agree |", "|---|---|---|---|---|---|---|"]
        for t, p in M["parity"].items():
            n = p.get("n_runtime", 0)
            fe = f"{p['features_equal_rows']:,}" if "features_equal_rows" in p else "-"
            L.append(f"| {t} | {n:,} | {fe} | {p.get('class_agree', 0):,} | {p.get('max_abs_dp', float('nan')):.2e} | "
                     f"{p.get('group_agree', 0):,} | {p.get('device_agree', 0):,} |")
    if M.get("runs"):
        L += ["", "## Runtime runs", "", "| run | eval-only | flows | wall s | flows / s | flow alerts | rate-guard alerts "
              "v2 / v1 | incidents | packets | quarantined | dropped | backlog peak | peak RSS MB |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for t, r in M["runs"].items():
            c = r["counts"]
            L.append(f"| {t} | {r['evaluation_only']} | {c.get('flows_scored', 0):,} | {r['wall_s']:.1f} | "
                     f"{r['flows_per_s']:,.0f} | {c.get('flow_alerts', 0):,} | {c.get('rg_alerts_v2', 0):,} / "
                     f"{c.get('rg_alerts_v1', 0):,} | {r['incidents']:,} | {c.get('packets', 0):,} | "
                     f"{c.get('quarantined', 0)} | {c.get('dropped', 0)} | {c.get('backlog_peak', 0):,} | "
                     f"{r['peak_rss_mb']:.0f} |")
        L += ["", "Run folders hold predictions.parquet, alerts.jsonl, health.jsonl, alerts_outbox.jsonl (all three "
              "chained + signed), incidents.json, latency.npz, rss.json, manifest.json."]
    p = M.get("pcap_path")
    if p:
        L += ["", "## pcap path (report-only)", "",
              f"- slice `{p['slice']['session']}` {p['slice']['split']} window: {p['slice']['frames_written']:,} frames "
              f"(sha256 `{p['slice']['pcap_sha256'][:16]}...`, source sha256 checked); locked CICFlowMeter: "
              f"{p['csv_rows']:,} flows in {p['cfm']['wall_s']:.1f} s wall ({p['frames_per_s_incl_jvm']:,.0f} frames/s "
              f"incl. JVM start); CSV schema required checks pass: {p['schema']['required_pass']}",
              f"- matched to dataset rows (Flow ID + start second, in order): **{p['matched']:,} of "
              f"{p['dataset_rows_in_window']:,}** dataset rows in the window ({p['match_rate_of_dataset']:.1%}); "
              f"features identical within tolerance on **{p['feature_equal_rows']:,} ({(p['feature_equal_share'] or 0):.2%})** "
              f"of matched flows (target >= 99 %)",
              f"- emission-time lag (reconstructed emission - (start + duration)), all rows: p50 {p['lag_s_all']['p50']:.2f} s, "
              f"p95 {p['lag_s_all']['p95']:.2f} s, p99 {p['lag_s_all']['p99']:.2f} s, max {p['lag_s_all']['max']:.1f} s",
              f"- runtime on this source: {p['runtime']['flows']:,} flows; routing `{p['runtime'].get('ip_mac_source', 'static')}`; "
              f"group == dataset group on matched flows: {p['runtime'].get('group_agree_matched', float('nan')):.2%}, device "
              f"{p['runtime'].get('device_agree_matched', float('nan')):.2%}"
              + (f"; static IP -> MAC map on the same rows: group {p['static_routing']['group_agree_matched']:.2%}, device "
                 f"{p['static_routing']['device_agree_matched']:.2%}" if p.get("static_routing") else ""),
              f"- learner: {p['runtime'].get('learner')}; health events {p['runtime'].get('health_events')}; ARP records "
              f"{p['runtime'].get('arp_records', 0):,}",
              f"- mismatching features (count of matched flows): {p['mismatch_by_feature'] or 'none'}"]
    if M.get("pcap_error"):
        L += ["", "pcap path error (report-only):", "", "```", M["pcap_error"][-2000:], "```"]
    if M.get("figures"):
        L += ["", "## Figures", ""] + [f"- `{f}`" for f in M["figures"]]
    L += ["", "## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  "
                                  f"{c['check']}  {c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
