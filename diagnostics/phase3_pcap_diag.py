#!/usr/bin/env python
"""diagnostics/phase3_pcap_diag.py -- READ-ONLY follow-up of the step 28 pcap path (report-only), two findings:

1. Emission-time lag. The prereg's reconstruction (docs/V2_PREREG_PHASE3.md section 2) raises a flow's emission to its
   same-Flow-ID successor's start when that successor starts >= flow_timeout later. The locked jar's idle sweeper
   (config/config.py EXTRACTOR.note: every 10 s of capture time, flows past flow timeout + 60 s slack are emitted)
   emits such flows much earlier, so that clause overstates the lag. Reported side by side: (a) the prereg rule (as in
   28), (b) running max of end only, (c) sweeper-aware: min(rule (a), start + flow_timeout + 60 + 10).
2. Routing on the pcap path. CICFlowMeter writes no MACs, so the router resolves them from config/ip_mac_map.csv, which
   covers the benign_night capture only; V1 tagged each attack capture with its own map (07: ~/lgids_cache/maps/
   <stem>_ip_mac_map.csv). Re-routes the same CSV rows with that capture's map (same Router code) and compares with the
   dataset group / device, and compares the pcap-path runtime predictions with the CSV-replay runtime (GLOBAL s0) on
   the matched flows.
Inputs: the step 28 re-run (results/phase3/28/rerun_full, manifest sha256 checked), its pcap-path CSV and run folders.
Output: results/phase3/pcap_diag/summary.md + pcap_diag.json (refused if they exist). Nothing else is written.
"""

from __future__ import annotations

import copy
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import CACHE_DIR, EXTRACTOR, RESULTS_DIR, REPO_ROOT  # noqa: E402
from common import flow_source as FS  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import phase3_run as R3  # noqa: E402
from common.routing import Router  # noqa: E402

SWEEP_SLACK_S, SWEEP_EVERY_S = 60, 10          # EXTRACTOR.note (idle sweeper)


def main() -> int:
    out = RESULTS_DIR / "phase3" / "pcap_diag"
    if (out / "summary.md").exists() or (out / "pcap_diag.json").exists():
        print(f"{out} exists (never overwritten)")
        return 1
    from common import schemas as S
    S.verify_v2_lock(strict=True)
    cfg = C.load_phase3_config()
    up = R3.resolve("28", rerun_tag="rerun_full")
    pc = up["manifest"]["pcap_path"]
    sess = pc["slice"]["session"]
    # rebuild the source object from the step 28 CSV without re-running the jar
    pcap = Path(pc["runtime"]["run_dir"]).parent.parent / "runtime_inputs" / up["meta"]["run_id"] / f"{sess}_{pc['slice']['split']}.pcap"
    src = FS.CicfmPcapSource(cfg, pcap, pcap.parent / "cfm", csv=Path(pc["cfm"]["csv"]))
    src.extract()
    T = float(cfg["pcap_source"]["flow_timeout_s"])
    start, end = np.asarray(src._start, float), np.asarray(src._end, float)
    a = src.lags()
    b = np.maximum.accumulate(end) - end
    ev_c = np.minimum(np.asarray(src._ev), start + T + SWEEP_SLACK_S + SWEEP_EVERY_S)
    c = np.maximum(np.maximum.accumulate(ev_c), end) - end
    qs = lambda v: {k: float(np.quantile(v, x)) for k, x in (("p50", .5), ("p95", .95), ("p99", .99), ("max", 1.0))}  # noqa: E731
    lag = {"a_prereg_rule": qs(a), "b_running_max_end_only": qs(b), "c_sweeper_aware": qs(c),
           "share_raised_by_successor_clause": float(np.mean(np.asarray(src._ev) > np.maximum.accumulate(end) + 1e-9))}
    # routing with the capture's own map
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    feats = S.feature_columns()
    cfg2 = load_phase2_config(REPO_ROOT / cfg["source"]["replay_phase2_config"])
    ds = D.load_split(cfg2, "val", ["Flow ID", "start_ts", "session", "row_in_file", "group", "device_mac"])
    first, last = pc["slice"]["first_ts"], pc["slice"]["last_ts"]
    ds = ds[(ds["session"] == sess) & (ds["start_ts"] >= int(first)) & (ds["start_ts"] <= int(last))].reset_index(drop=True)
    by = defaultdict(list)
    for i, (f, t) in enumerate(zip(ds["Flow ID"], ds["start_ts"])):
        by[(f, int(t))].append(i)
    pairs = []
    for j, (f, t) in enumerate(zip(src._ids["Flow ID"], src._start)):
        L = by.get((f, int(t)))
        if L:
            pairs.append((L.pop(0), j))
    own_map = CACHE_DIR / "maps" / f"{sess}_ip_mac_map.csv"
    res = {"config_map": str(cfg["routing"]["ip_mac_map"]), "capture_map": str(own_map), "matched": len(pairs)}
    for name, mp in (("config_map", None), ("capture_map", own_map)):
        c2 = copy.deepcopy(cfg)
        if mp is not None:
            c2["routing"]["ip_mac_map"] = str(mp)
        r = Router(c2)
        rows = list(src._rows())
        g_ok = d_ok = 0
        for i, j in pairs:
            x = r.route(rows[j])
            g_ok += x.group == ds["group"].iloc[i]
            d_ok += x.device_mac == ds["device_mac"].iloc[i]
        res[name + "_group_agree"] = g_ok / max(len(pairs), 1)
        res[name + "_device_agree"] = d_ok / max(len(pairs), 1)
        res[name + "_ipmap_stats"] = dict(r.stats)
    # predictions: pcap-path runtime vs CSV-replay runtime (GLOBAL s0), matched flows
    import pyarrow.parquet as pq
    Pp = pq.read_table(Path(pc["runtime"]["run_dir"]) / "predictions.parquet").to_pandas()
    Pg = pq.read_table(Path(up["manifest"]["runs"]["GLOBAL_s0"]["dir"]) / "predictions.parquet").to_pandas()
    pp = dict(zip(Pp["row"], Pp["pred"]))
    pg = dict(zip(Pg["flow_uid"], Pg["pred"]))
    uid = (ds["session"] + ":" + ds["row_in_file"].astype(str)).tolist()
    agree = [pp[j] == pg[uid[i]] for i, j in pairs]
    res["pred_agree_matched"] = float(np.mean(agree)) if agree else None
    res["pred_disagree_matched"] = int(len(agree) - sum(agree))
    J = {"step28_run": up["meta"]["run_id"], "lag_s": lag, "routing": res, "sweeper": EXTRACTOR.note}
    out.mkdir(parents=True, exist_ok=True)
    R3.write_json(out / "pcap_diag.json", J)
    f = lambda d: f"p50 {d['p50']:.1f} / p95 {d['p95']:.1f} / p99 {d['p99']:.1f} / max {d['max']:.1f} s"  # noqa: E731
    L = ["# Phase 3 pcap path -- diagnostic follow-up (read-only, report-only)", "",
         f"- step 28 re-run `{up['meta']['run_id']}`, slice `{sess}` val window, {len(src):,} CICFlowMeter rows, "
         f"{len(pairs):,} matched to dataset rows", "", "## 1. Emission-time lag (emission - (start + duration))", "",
         f"- (a) prereg rule, as reported by 28: {f(lag['a_prereg_rule'])}; the successor clause raised "
         f"{lag['share_raised_by_successor_clause']:.1%} of rows",
         f"- (b) running max of end only: {f(lag['b_running_max_end_only'])}",
         f"- (c) sweeper-aware (cap at start + {T:g} + {SWEEP_SLACK_S} + {SWEEP_EVERY_S} s): {f(lag['c_sweeper_aware'])}",
         "- Reading: the prereg's successor clause assumes a timed-out flow stays open until its successor's first packet; "
         "the locked jar's idle sweeper emits it within flow timeout + 70 s, so (a) overstates the lag; (c) is the "
         "realistic bound for this extractor. The pcap path is report-only; no metric depends on it.", "",
         "## 2. Routing and predictions on the pcap path", "",
         f"- IP -> MAC from `config/ip_mac_map.csv` (benign_night capture only): group == dataset "
         f"{res['config_map_group_agree']:.2%}, device == dataset {res['config_map_device_agree']:.2%} "
         f"(resolver {res['config_map_ipmap_stats']})",
         f"- IP -> MAC from the capture's own map `{own_map}` (what V1's 07 used): group == dataset "
         f"{res['capture_map_group_agree']:.2%}, device == dataset {res['capture_map_device_agree']:.2%}",
         f"- predicted class, pcap-path runtime vs CSV-replay runtime (GLOBAL s0) on the matched flows: "
         f"{res['pred_agree_matched']:.4%} agree ({res['pred_disagree_matched']} differ)",
         "- Reading: the runtime router's rule is right; the static map only covers one capture. On the Pi the router "
         "needs a live IP -> MAC source (ARP / DHCP table) -- a deployment item."]
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
