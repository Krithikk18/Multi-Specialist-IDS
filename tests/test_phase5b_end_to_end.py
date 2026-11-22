"""tests/test_phase5b_end_to_end.py -- Phase 5B end to end on a tiny synthetic stream (no project data):
benign hosts talk to servers (normal flows + short probe-like flows); a scan (one attacker, many hosts and ports) and a
flood (one attacker, one victim, 100 flows/s) are built from flows drawn from the SAME per-flow distribution as the benign
short flows, so per flow they look benign while their fan-out / volume is extreme.
  -> CTX_TAIL (H-C3 primary detector, D165: per-feature upper-tail rule on the 44 context features, threshold calibrated
     on held-out train benign) flags >= 0.9 of the scan and of the flood flows;
  -> the per-flow model of normal (Phase 5A recipe on the 70 flow features) flags <= 0.05 of them;
  -> characterisation of Phase 5A limitation 7: CTX_IF (the 5A recipe on the context features) scores the out-of-range
     attack rows no higher than its highest train-benign score, so it cannot flag them;
  -> flipping every flow with the R3 normaliser's swap leaves the context features identical and a CTX_ONLY Stage 1
     model's predictions unchanged, while the flow features do change.

Plain asserts. Usage (repo root): python tests/test_phase5b_end_to_end.py
"""

from __future__ import annotations

import copy
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common import cl_retrain as RT  # noqa: E402
from common import context_config as CC  # noqa: E402
from common import context_features as CF  # noqa: E402
from common import normal_model as NM  # noqa: E402
from common import orientation as O  # noqa: E402
from common import schemas as S  # noqa: E402
from common import tail_rule as TR  # noqa: E402
from common import zeroday_config as ZC  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

CFG = CC.load_phase5b_config(verify_pin=False)
C = CFG["columns"]
CFG2 = load_phase2_config(ROOT / "config" / "v2_phase2_v2_1.json")
P = copy.deepcopy(ZC.load_phase5_config(verify_pin=False)["normal_model"])
P.update({"n_estimators": 100, "n_jobs": 1})
FEATS = S.feature_columns()
CTX = CC.context_feature_names(CFG)


def _flows(rng, n, src, dst, sport, dport, t0, t1, short: bool):
    if short:                                                           # probe-like: 2 packets, tiny, sub-ms
        fp, bp = np.ones(n), np.ones(n)
        fb, bb = rng.integers(0, 40, n), rng.integers(0, 40, n)
        dur = rng.integers(200, 2000, n)
        syn, ack = np.ones(n), np.ones(n)
    else:
        fp, bp = rng.integers(5, 20, n), rng.integers(3, 15, n)
        fb, bb = rng.integers(300, 4000, n), rng.integers(500, 9000, n)
        dur = rng.integers(100_000, 2_000_000, n)
        syn, ack = np.ones(n), rng.integers(5, 30, n)
    d = {f: np.zeros(n) for f in FEATS}
    d.update({"Protocol": np.full(n, 6.0), "Flow Duration": dur.astype(float), "Total Fwd Packet": fp.astype(float),
              "Total Bwd packets": bp.astype(float), "Total Length of Fwd Packet": fb.astype(float),
              "Total Length of Bwd Packet": bb.astype(float), "SYN Flag Count": syn.astype(float),
              "ACK Flag Count": ack.astype(float)})
    df = pd.DataFrame(d)
    df[C["src_ip"]], df[C["dst_ip"]] = src, dst
    df[C["src_port"]], df[C["dst_port"]] = np.asarray(sport).astype(str), np.asarray(dport).astype(str)
    df[C["start"]] = rng.integers(t0, t1, n)
    return df


def make(seed: int, attacks: bool, T: int = 600):
    rng = np.random.default_rng(seed)
    hosts = [f"192.168.1.{i}" for i in range(10)]
    servers = [f"10.0.0.{j}" for j in range(3)]
    parts, lab = [], []
    n = 2000
    h, s = rng.choice(hosts, n), rng.choice(servers, n)
    parts.append(_flows(rng, n, h, s, rng.integers(30000, 60000, n), rng.choice([80, 443], n), 0, T, short=False))
    lab.append(np.zeros(n))
    n = 600
    h, s = rng.choice(hosts, n), rng.choice(servers, n)
    parts.append(_flows(rng, n, h, s, rng.integers(30000, 60000, n), rng.choice([80, 443], n), 0, T, short=True))
    lab.append(np.zeros(n))
    if attacks:
        n = 1500                                                        # scan: 25 flows/s for 60 s, many hosts x ports
        parts.append(_flows(rng, n, "192.168.1.200", rng.choice(hosts, n), rng.integers(40000, 41000, n),
                            rng.integers(1, 1024, n), 200, 260, short=True))
        lab.append(np.ones(n))
        n = 6000                                                        # flood: 100 flows/s for 60 s, one victim
        parts.append(_flows(rng, n, "192.168.1.201", hosts[3], rng.integers(1024, 65535, n), np.full(n, 80), 400, 460,
                            short=True))
        lab.append(np.full(n, 2))
    df = pd.concat(parts, ignore_index=True)
    df[C["start"]] = df[C["start"]] + 1_700_000_000
    df[C["flow_id"]] = (df[C["src_ip"]] + "-" + df[C["dst_ip"]] + "-" + df[C["src_port"]] + "-" + df[C["dst_port"]] + "-6")
    df[C["session"]], df[C["split"]] = "syn", "val"
    df[C["row"]] = np.arange(len(df))
    return df, np.concatenate(lab).astype(np.int64)


_CACHE: dict = {}


def _run():
    if _CACHE:
        return _CACHE
    tr, _ = make(1, attacks=False)
    te, yte = make(2, attacks=True)
    Ftr, _, _ = CF.compute_segments(tr, CFG)
    Fte, warm, _ = CF.compute_segments(te, CFG)
    g_tr, g_te = np.array(["G"] * len(tr)), np.array(["G"] * len(te))
    R = TR.fit(Ftr, 0, CFG["tail"])
    _CACHE["tail"] = TR.flag(Fte, R["t"])
    _CACHE["tail_rule"] = R
    for name, Ztr, Zte in (("ctx_if", NM.prepare(Ftr, CTX)[0], NM.prepare(Fte, CTX)[0]),
                           ("flow_if", NM.prepare(tr[FEATS].to_numpy(np.float64), FEATS)[0],
                            NM.prepare(te[FEATS].to_numpy(np.float64), FEATS)[0])):
        A = NM.fit_arm(NM.GLOBAL, Ztr, g_tr, 0, P)
        sc, thr, _, _ = NM.score_arm(A, Zte, g_te, P)
        _CACHE[name] = NM.flags(sc, thr)
        _CACHE[name + "_scores"] = sc
        _CACHE[name + "_train_max"] = float(A["models"][NM.GLOBAL_KEY]["train_scores"].max())
    _CACHE.update({"y": yte, "warm": warm, "above": (Fte > Ftr.max(0)).any(1), "Fte": Fte})
    return _CACHE


def test_ctx_tail_flags_scan_and_flood_per_flow_does_not():
    D = _run()
    y = D["y"]
    # (calibration on held-out rows is tested in test_phase5b_tail_rule; this tiny stream has ~520 held-out rows, where a
    # 0.1 % target means zero flags, so the largest q may be used here)
    for k in (1, 2):
        assert D["tail"][y == k].mean() >= 0.9, (k, D["tail"][y == k].mean())
        assert D["flow_if"][y == k].mean() <= 0.05, (k, D["flow_if"][y == k].mean())
    te, _ = make(2, attacks=True)                                        # contamination: an attack flow on a host in 60 s
    Fa, _, _ = CF.compute_segments(te, CFG, insert_mask=y > 0)
    cont = Fa[:, CTX.index(f"{CFG['context']['prefix']}_hostmax_n_flows_60s")] >= 1
    clean = (y == 0) & (D["warm"] == 0) & ~cont
    assert clean.sum() > 1000 and D["tail"][clean].mean() < 0.02, D["tail"][clean].mean()
    assert D["tail"][(y == 0) & cont].mean() > D["tail"][clean].mean()   # contaminated benign is flagged more (measured)
    E = TR.explain(D["Fte"][y == 2][:50], D["tail_rule"]["t"], CTX)
    assert len(E["rows"]) >= 45 and all(r["fired"][0][1] > 1 for r in E["rows"])


def test_ctx_if_out_of_range_limitation_7():
    """The attack rows' context exceeds every train-benign value; the 5A recipe scores them no higher than its highest
    train-benign score, so its 99.9th-percentile threshold cannot flag them (characterisation, Phase 5A limitation 7)."""
    D = _run()
    att = D["y"] > 0
    oor = att & D["above"]
    assert oor.mean() / att.mean() > 0.9
    assert D["ctx_if_scores"][oor].max() <= D["ctx_if_train_max"], (D["ctx_if_scores"][oor].max(), D["ctx_if_train_max"])
    assert D["ctx_if"][att].mean() < 0.5


def test_flip_leaves_context_and_ctx_only_predictions_unchanged():
    te, yte = make(3, attacks=True)
    omap = O.load_map(expected_sha256=S.ORIENTATION_MAP_SHA256)
    fl = O.swap(te, np.ones(len(te), bool), omap)
    assert (fl[C["src_ip"]] != te[C["src_ip"]]).all()                    # every flow was swapped
    assert not np.array_equal(fl[FEATS].to_numpy(), te[FEATS].to_numpy())
    F0, _, _ = CF.compute_segments(te, CFG)
    F1, _, _ = CF.compute_segments(fl, CFG)
    assert np.array_equal(F0, F1)
    r = RT.fit(F0.astype(np.float32), yte, 3, "none", 0, CFG2, 2)
    p0 = RT.predict_proba(r["booster"], F0.astype(np.float32)).argmax(1)
    p1 = RT.predict_proba(r["booster"], F1.astype(np.float32)).argmax(1)
    assert np.array_equal(p0, p1) and (p0 == yte).mean() > 0.9


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
