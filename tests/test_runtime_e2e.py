"""tests/test_runtime_e2e.py -- common/runtime.py end to end on a tiny stream: 120 real val flows (extractor
orientation, one session: benign + attack) + 3 malformed rows + a synthetic packet flood into a protected device.
Checks: every valid flow scored once and equal to the offline path (v2_1 features, softmax(margin / T)); the malformed
rows quarantined (health records) without stopping the loop; flow and rate-guard alerts logged and aggregated into
incidents; the alerts / health / outbox chains verify with the runtime key; every incident has an opened and a closed
outbox message; queue overflow under the drop policy is counted (flows in + dropped == offered) and logged.

Plain asserts. Usage (repo root): python tests/test_runtime_e2e.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import alert_log as AL  # noqa: E402
from common import flow_source as FS  # noqa: E402
from common import model_loader as ML  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import rate_guard_v2 as RG  # noqa: E402
from common import routing as RT  # noqa: E402
from common import runtime as RTM  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_metrics import softmax  # noqa: E402

CFG = C.load_phase3_config()
_D: dict = {}


def _data():
    if not _D:
        from common import phase2_data as D
        from common.phase2_config import load_phase2_config
        from config.config import REPO_ROOT
        feats = S.feature_columns()
        cols = feats + FS.ID_COLS + FS.MAC_COLS + ["start_ts", "session", "row_in_file", "label_id", "group"]
        raw = D.load_split(load_phase2_config(REPO_ROOT / CFG["source"]["replay_phase2_config"]), "val", cols)
        v21 = D.load_split(load_phase2_config(REPO_ROOT / CFG["phase2_config"]), "val", feats + ["session", "row_in_file"])
        m = (raw["session"] == "Recon-PortScan").to_numpy()
        ix = np.flatnonzero(m)
        pick = np.concatenate([ix[raw["label_id"].to_numpy()[ix] == 0][:60], ix[raw["label_id"].to_numpy()[ix] != 0][:60]])
        _D["raw"] = raw.iloc[np.sort(pick)].reset_index(drop=True)
        key = v21["session"] + ":" + v21["row_in_file"].astype(str)
        _D["v21"] = v21.set_index(key)
    return _D


class WithMalformed(FS.FlowSource):
    def __init__(self, inner, bad):
        super().__init__("max")
        self.inner, self.bad = inner, bad

    def events(self):
        it = self.inner.events()
        for i, ev in enumerate(it):
            yield ev
            if i in (5, 50, 90):
                yield "flow", ev[1], self.bad.pop(0)


def _run(cfg, src, packets=None, rg=None, delay=0.0):
    d = Path(tempfile.mkdtemp(prefix="p3e2e_"))
    sk, pk = AL.ensure_runtime_keys(d / "keys")
    run = d / "run"
    run.mkdir()
    rm = ML.load_runtime_model(cfg)
    rt = RTM.Runtime(cfg, rm, run, sk, rate_guard=rg, store_features=True, consumer_delay_s=delay)
    return rt.run(src, packets), run, pk, rm


def test_end_to_end_tiny_stream():
    d = _data()
    raw = d["raw"]
    src = FS.CsvReplaySource(CFG, frame=raw)
    good = next(r for k, t, r in FS.CsvReplaySource(CFG, frame=raw.iloc[:1]).events() if k == "flow")
    b1 = {k: v for k, v in good.items() if k != "Flow Bytes/s"}
    b1["_meta"] = dict(good["_meta"], flow_uid="bad:1")
    b2 = dict(good, **{"Flow IAT Mean": "abc"})
    b2["_meta"] = dict(good["_meta"], flow_uid="bad:2")
    b3 = {k: v for k, v in good.items() if k != "_meta"}
    router = RT.Router(CFG)
    victim = next(m for m, (n, role, g) in router.inv.items() if role in router.owner_roles)
    t0 = float(raw["start_ts"].min())
    packets = [(t0 + i / 200.0, "10.9.9.9", "192.168.137.250", 6, "02:00:00:00:00:01", victim) for i in range(200 * 6)]
    thr = {g: {"TCP": 100, "UDP": 100, "other": 100} for g in router.labels}
    rg = (RG.RateGuardV2(router, thr, CFG["rate_guard"]["families"], CFG["rate_guard"]["other_family"],
                         fallback_group=router.fallback), RG.V1Guard(CFG))
    summ, run, pk, rm = _run(CFG, WithMalformed(src, [b1, b2, b3]), packets, rg)
    c = summ["counts"]
    assert c["flows_in"] == 123 and c["flows_scored"] == 120 and c["quarantined"] == 3 and c["dropped"] == 0, c
    import pyarrow.parquet as pq
    P = pq.read_table(run / "predictions.parquet").to_pandas()
    assert len(P) == 120 and P["flow_uid"].is_unique
    X = np.load(run / "features.npy")
    V = d["v21"].loc[P["flow_uid"], S.feature_columns()].to_numpy(np.float32)
    assert np.array_equal(X, V)                                               # runtime-normalised == v2_1 features
    m = rm.models[rm.default]
    import xgboost as xgb
    Z = m.booster.predict(xgb.DMatrix(V), output_margin=True).astype(np.float64)
    Poff = softmax(Z, m.temperature)
    Prt = P[[f"p_{k}" for k in range(4)]].to_numpy()
    assert np.array_equal(Poff.argmax(1), P["pred"].to_numpy()) and np.max(np.abs(Poff - Prt)) <= 1e-6
    assert P["alert"].sum() > 0 and c["flow_alerts"] == int(P["alert"].sum())
    assert c["rg_alerts_v2"] >= 1
    logs = summ["logs"]
    for name, fn in (("alerts", "alerts.jsonl"), ("health", "health.jsonl"), ("outbox", CFG["paths"]["outbox"])):
        r = AL.verify_chain(run / fn, pk, expect_n=logs[name]["n"], expect_head=logs[name]["head_sha256"])
        assert r["ok"], (name, r)
    H = [json.loads(x) for x in (run / "health.jsonl").read_text().splitlines()]
    assert [h["kind"] for h in H].count("quarantine") == 3 and H[0]["kind"] == "start" and H[-1]["kind"] == "end"
    A = [json.loads(x) for x in (run / "alerts.jsonl").read_text().splitlines()]
    fa = [a for a in A if a["path"] == "flow"]
    assert len(fa) == c["flow_alerts"] and all(len(a["top3"]) == 3 and a["model"]["model_sha256"] == m.model_sha256 for a in fa)
    assert any(a["path"] == "rate_guard" and a["rule"] == "v2" and a["device"] == victim for a in A)
    inc = json.loads((run / "incidents.json").read_text())
    assert any(i["class"] == CFG["policy"]["rate_guard_class"] and i["device"] == victim for i in inc)
    O = [json.loads(x) for x in (run / CFG["paths"]["outbox"]).read_text().splitlines()]
    op = sorted(o["incident"]["incident_id"] for o in O if o["type"] == "incident.opened")
    cl = sorted(o["incident"]["incident_id"] for o in O if o["type"] == "incident.closed")
    assert op == cl == sorted(i["incident_id"] for i in inc) and len(op) == summ["incidents"]


def test_queue_overflow_counted_and_logged():
    d = _data()
    cfg = copy.deepcopy(CFG)
    cfg["queue"]["max_items"] = 2
    cfg["queue"]["overflow_max_speed"] = "drop"
    src = FS.CsvReplaySource(cfg, frame=d["raw"])
    summ, run, pk, _ = _run(cfg, src, delay=0.003)
    c = summ["counts"]
    assert c["dropped"] > 0 and c["flows_in"] + c["dropped"] == 120, c
    H = [json.loads(x) for x in (run / "health.jsonl").read_text().splitlines()]
    assert H[-1]["kind"] == "end" and H[-1]["dropped"] == c["dropped"]
    assert AL.verify_chain(run / "health.jsonl", pk)["ok"]


def test_block_policy_is_lossless():
    d = _data()
    cfg = copy.deepcopy(CFG)
    cfg["queue"]["max_items"] = 2
    summ, _, _, _ = _run(cfg, FS.CsvReplaySource(cfg, frame=d["raw"]), delay=0.001)
    assert summ["counts"]["dropped"] == 0 and summ["counts"]["flows_scored"] == 120


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items(), key=lambda kv: kv[1].__code__.co_firstlineno
                                       if callable(kv[1]) and hasattr(kv[1], "__code__") else 0)
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}\n{traceback.format_exc()}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
