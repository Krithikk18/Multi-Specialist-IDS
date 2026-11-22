#!/usr/bin/env python
"""diagnostics/phase3_2_attack_sources.py -- Phase 3.2 PART B evidence: do the val floods spoof source IPs?

For each slice pcap of a phase3_2_gateway.py run (read-only; sha256 checked against the slice manifest in its
gateway.json): per attack-source MAC (D74 identity, diagnostics/diag_03_common.Hosts) the frames sent, the distinct
IPv4 source addresses over the whole slice and the maximum within the learner's gateway window (300 s; the same
window_series as the gateway figure, exact below its cap), and the source IPs themselves when few. Also, for the
dataset rows of the slice window that no CICFlowMeter row matched: their count by start second relative to the slice
start (to explain a low match rate).
Output: results/phase3_2/gateway/attack_sources.json (refused if it exists).
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402
from common import packet_source as PK  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import phase3_run as R3  # noqa: E402
from common import schemas as S  # noqa: E402
from diagnostics.phase3_2_gateway import window_series  # noqa: E402


def pins() -> dict:
    return {"config/config.py": R3.sha256_path(S.CONFIG_PY_PATH), "config/class_map.json": R3.sha256_path(S.CLASS_MAP_PATH)}


def main() -> int:
    S.verify_v2_lock(strict=True)
    p0 = pins()
    print(f"[start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    gj = RESULTS_DIR / "phase3_2" / "gateway" / "gateway.json"
    out_p = gj.with_name("attack_sources.json")
    if out_p.exists():
        raise SystemExit(f"{out_p} exists (never overwritten)")
    res_g = json.loads(gj.read_text(encoding="utf-8"))
    c31 = C.load_phase3_config(C.CONFIG_PATH_3_1)
    from diagnostics.diag_03_common import Hosts
    hosts = Hosts()
    lp = res_g["learner_params"]
    root = C.expand(c31["paths"]["runtime_root"]).parent / "runtime_inputs" / f"{res_g['run_id']}_p32"
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    cfg2 = load_phase2_config(REPO_ROOT / c31["source"]["replay_phase2_config"])
    ds = D.load_split(cfg2, "val", ["Flow ID", "start_ts", "session"])
    out = {"gateway_run": res_g["run_id"], "slices": {}}
    for sess, z in res_g["slices"].items():
        pcap = root / f"{sess}_val.pcap"
        if PK.sha256_file(pcap) != z["slice"]["pcap_sha256"]:
            raise SystemExit(f"{pcap}: sha256 differs from the slice manifest")
        ips = defaultdict(set)
        frames = Counter()
        for ts, sip, _dip, proto, smac, _dmac in PK.iter_pcap(pcap, Counter()):
            smac = str(smac or "").lower()
            if hosts.is_attacker(smac):
                frames[smac] += 1
                if len(ips[smac]) < 100000:
                    ips[smac].add(sip)
        ws = window_series(pcap, float(lp["window_s"]), int(lp["threshold"]))
        att = {m: {"category": hosts.cat(m), "frames": frames[m], "distinct_src_ips_slice": len(ips[m]),
                   "max_distinct_src_ips_in_window": ws["max"].get(m, 0),
                   "src_ips": sorted(ips[m])[:10]} for m in sorted(frames, key=lambda k: -frames[k])}
        w = ds[(ds["session"] == sess) & (ds["start_ts"] >= int(z["slice"]["first_ts"]))
               & (ds["start_ts"] <= int(z["slice"]["last_ts"]))].reset_index(drop=True)
        import pandas as pd
        csv = sorted((root / f"cfm_{sess}").glob("*.csv"))[0]
        cf = pd.read_csv(csv, usecols=["Flow ID", "Timestamp"], dtype=str, keep_default_na=False)
        cst = ((S.parse_timestamps(cf["Timestamp"]) - pd.Timestamp(0, tz="UTC")) // pd.Timedelta(seconds=1)).to_numpy(np.int64)
        avail = Counter(zip(cf["Flow ID"].tolist(), cst.tolist()))
        um = []
        for f, t in zip(w["Flow ID"].tolist(), w["start_ts"].astype(np.int64).tolist()):
            if avail.get((f, t), 0) > 0:
                avail[(f, t)] -= 1
            else:
                um.append(t)
        um = np.asarray(um, np.int64) - int(z["slice"]["first_ts"])
        any_fid = set(cf["Flow ID"].tolist())
        um_fid = sum(1 for f, t in zip(w["Flow ID"].tolist(), w["start_ts"].astype(np.int64).tolist()) if f not in any_fid)
        out["slices"][sess] = {"attack_sources": att, "frames": z["slice"]["frames_written"],
                               "attack_source_frames": int(sum(frames.values())),
                               "max_distinct_src_ips_any_attack_source": max((a["max_distinct_src_ips_in_window"]
                                                                               for a in att.values()), default=0),
                               "dataset_rows_in_window": int(len(w)), "matched": z["matched"],
                               "unmatched_recount": int(len(um)),
                               "unmatched_flow_id_absent_from_cfm": int(um_fid),
                               "unmatched_start_s_rel_hist_60s": {str(int(k)): int(v) for k, v in
                                                                  sorted(Counter((um // 60 * 60).tolist()).items())},
                               "all_start_s_rel_hist_60s": {str(int(k)): int(v) for k, v in
                                                            sorted(Counter(((w["start_ts"].to_numpy() - int(z["slice"]["first_ts"])) // 60 * 60).tolist()).items())}}
        print(f"  {sess}: unmatched {len(um):,} of {len(w):,} (Flow ID absent from the slice CSV: {um_fid:,}); by "
              f"minute after slice start: {out['slices'][sess]['unmatched_start_s_rel_hist_60s']}", flush=True)
        print(f"  {sess}: {len(att)} attack-source MACs, {sum(frames.values()):,} of {z['slice']['frames_written']:,} "
              f"frames; per MAC (frames, distinct src IPs, max in window): "
              f"{[(m[-5:], a['frames'], a['distinct_src_ips_slice'], a['max_distinct_src_ips_in_window']) for m, a in att.items()]}",
              flush=True)
    S.verify_v2_lock(strict=True)
    p1 = pins()
    out["lock"] = {"start": p0, "end": p1}
    out_p.write_text(json.dumps(out, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)) + "\n",
                     encoding="utf-8")
    print(f"[end] verify_v2_lock OK; config.py {p1['config/config.py']}; class_map.json {p1['config/class_map.json']} -> {out_p}")
    return 0 if p0 == p1 else 1


if __name__ == "__main__":
    sys.exit(main())
