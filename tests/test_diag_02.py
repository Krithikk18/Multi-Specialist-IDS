"""tests/test_diag_02.py -- helpers of diagnostics/diag_02_orientation_rule.py on synthetic data: swap map coverage,
swap involution, normaliser idempotence, rule logic (R1 / R2, edge cases), the unpaired-field defaults, KS statistic.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_diag_02.py
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
_spec = importlib.util.spec_from_file_location("diag02", REPO / "diagnostics" / "diag_02_orientation_rule.py")
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)
from common import schemas as S  # noqa: E402

FEATS = S.feature_columns()
SMAP = G.build_swap_map(FEATS)


def _flow(nf=1, nb=1, fwin=0.0, bwin=1024.0, proto=6.0, syn=1.0, seed=0, **over) -> dict:
    """One CICFlowMeter-consistent synthetic row (1 fwd + 1 bwd packet by default: every swap rule exact)."""
    rng = np.random.default_rng(seed)
    r = {f: float(rng.integers(1, 500)) for f in FEATS}
    fh, bh = 20.0, 24.0
    r.update({"Protocol": proto, G.NF: float(nf), G.NB: float(nb), G.FIW: fwin, G.BIW: bwin, G.SYN: syn,
              "Fwd Header Length": fh * nf, "Bwd Header Length": bh * nb, "Fwd Seg Size Min": fh,
              "Total Length of Fwd Packet": 0.0, "Total Length of Bwd Packet": 0.0,
              "Fwd Packet Length Max": 0.0, "Fwd Packet Length Min": 0.0, "Bwd Packet Length Max": 0.0,
              "Bwd Packet Length Min": 0.0, "Fwd Act Data Pkts": 0.0, "Fwd PSH Flags": 0.0, "PSH Flag Count": 0.0,
              "Down/Up Ratio": float(nb // nf) if nf else 0.0,
              "Src IP": "10.0.0.2", "Dst IP": "10.0.0.9", "Src Port": "22", "Dst Port": "60610",
              "src_mac": "aa", "dst_mac": "bb", "Flow ID": "10.0.0.2-10.0.0.9-22-60610-6", "device": "dev1"})
    r.update(over)
    return r


def _df(rows) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for c in ("Src IP", "Dst IP", "Src Port", "Dst Port", "src_mac", "dst_mac", "Flow ID", "device"):
        df[c] = df[c].astype("string")
    return df


def test_swap_map_covers_every_feature_once():
    assert list(SMAP) == FEATS and len(SMAP) == 70
    classes = {"pair", "pair_asymmetric", "direction_free", "derived", "unpaired"}
    assert all(e["class"] in classes for e in SMAP.values())
    for f, e in SMAP.items():
        if e["class"] in ("pair", "pair_asymmetric"):
            p = e["partner"]
            assert p in SMAP and SMAP[p]["partner"] == f and SMAP[p]["class"] == e["class"], f
        if e["class"] == "unpaired":
            assert e.get("default") and e.get("how") and e.get("status") != "UNRESOLVED", f
    assert SMAP[G.FIW]["partner"] == G.BIW and SMAP["Protocol"]["class"] == "direction_free"
    try:
        G.build_swap_map(FEATS + ["Brand New Feature"])
        raise AssertionError("an uncovered feature must raise")
    except ValueError:
        pass
    try:
        G.build_swap_map([f for f in FEATS if f != "Flow Duration"])
        raise AssertionError("a map entry outside the feature list must raise")
    except ValueError:
        pass


def test_rule_logic():
    rows = [_flow(fwin=0, bwin=1024), _flow(fwin=0, bwin=0), _flow(fwin=1024, bwin=0), _flow(fwin=1024, bwin=512),
            _flow(fwin=0, bwin=-1), _flow(fwin=np.nan, bwin=1024), _flow(fwin=0, bwin=np.nan),
            _flow(fwin=0, bwin=0, proto=17), _flow(fwin=0, bwin=1024, syn=0), _flow(fwin=0, bwin=1024, proto=17)]
    df = _df(rows)
    r1 = G.rule_flags(df, "R1")
    assert r1.tolist() == [True, False, False, False, False, False, False, False, True, True]
    r2 = G.rule_flags(df, "R2")
    assert r2.tolist() == [True, False, False, False, False, False, False, False, False, True]
    g = G.rule_flags(df, "R1", tcp_guard=True)
    assert g.tolist() == [True, False, False, False, False, False, False, False, True, False]
    try:
        G.rule_flags(df, "R9")
        raise AssertionError("unknown variant must raise")
    except ValueError:
        pass


def test_swap_is_an_involution_on_single_packet_directions():
    df = _df([_flow(seed=s, fwin=float(w1), bwin=float(w2)) for s, (w1, w2) in enumerate([(0, 1024), (512, 0), (7, 9)])])
    m = np.ones(len(df), bool)
    once, ex = G.swap_rows(df, m, SMAP)
    twice, _ = G.swap_rows(once, m, SMAP)
    pd.testing.assert_frame_equal(twice, df)
    assert all(e.all() for e in ex.values())                         # 1 fwd + 1 bwd: every field exact
    # once: pairs and identity really swapped
    assert once.loc[0, G.FIW] == 1024 and once.loc[0, G.BIW] == 0
    assert once.loc[0, "Fwd Header Length"] == df.loc[0, "Bwd Header Length"]
    assert once.loc[0, "Src IP"] == "10.0.0.9" and once.loc[0, "Dst Port"] == "22" and once.loc[0, "src_mac"] == "bb"
    assert once.loc[0, "Flow ID"] == "10.0.0.9-10.0.0.2-60610-22-6"
    assert once.loc[0, "Fwd Seg Size Min"] == 24.0                    # = old Bwd Header Length (1 bwd packet)
    for f, e in SMAP.items():                                         # direction-free values untouched
        if e["class"] == "direction_free":
            assert (once[f] == df[f]).all(), f


def test_normaliser_idempotent_and_leaves_unflagged_rows():
    rows = [_flow(fwin=0, bwin=1024), _flow(fwin=1024, bwin=0, seed=1), _flow(fwin=0, bwin=0, proto=17, seed=2),
            _flow(nf=3, nb=2, fwin=0, bwin=65535, seed=3)]
    df = _df(rows)
    n1, f1, _ = G.normalise(df, SMAP)
    assert f1.tolist() == [True, False, False, True]
    pd.testing.assert_frame_equal(n1.loc[~f1], df.loc[~f1])
    n2, f2, _ = G.normalise(n1, SMAP)
    assert not f2.any()
    pd.testing.assert_frame_equal(n2, n1)
    assert G.normalise(df.iloc[:0], SMAP)[0].empty


def test_derived_and_unpaired_defaults():
    rows = [
        _flow(nf=3, nb=2, **{"Down/Up Ratio": 0.0}),                                       # 0: Down/Up 2//3 -> 3//2
        _flow(nf=1, nb=3, **{"Bwd Header Length": 80.0, "Bwd Packet Length Max": 0.0}),    # 1: seg floor(80/3), act 0
        _flow(nf=1, nb=3, **{"Bwd Packet Length Max": 10.0, "Bwd Packet Length Min": 5.0,
                             "Total Length of Bwd Packet": 25.0}),                          # 2: all payload -> nb-1
        _flow(nf=1, nb=4, **{"Bwd Packet Length Max": 10.0, "Bwd Packet Length Min": 0.0,
                             "Total Length of Bwd Packet": 15.0}),                          # 3: lower bound ceil(1.5)-1
        _flow(nf=1, nb=2, **{"PSH Flag Count": 2.0, "Fwd PSH Flags": 0.0}),                 # 4: both bwd PSH -> 1 exact
        _flow(nf=1, nb=3, **{"PSH Flag Count": 1.0, "Fwd PSH Flags": 0.0}),                 # 5: ambiguous -> 0, inexact
        _flow(nf=2, nb=1, **{"PSH Flag Count": 1.0, "Fwd PSH Flags": 1.0}),                 # 6: rest 0 -> 0 exact
    ]
    df = _df(rows)
    out, ex = G.swap_rows(df, np.ones(len(df), bool), SMAP)
    assert out.loc[0, "Down/Up Ratio"] == 1.0                         # floor(3 / 2)
    assert out.loc[1, "Fwd Seg Size Min"] == 26.0 and not ex["Fwd Seg Size Min"][1]
    assert out.loc[1, "Fwd Act Data Pkts"] == 0.0 and ex["Fwd Act Data Pkts"][1]
    assert out.loc[2, "Fwd Act Data Pkts"] == 2.0 and ex["Fwd Act Data Pkts"][2]
    assert out.loc[3, "Fwd Act Data Pkts"] == 1.0 and not ex["Fwd Act Data Pkts"][3]
    assert out.loc[4, "Fwd PSH Flags"] == 1.0 and ex["Fwd PSH Flags"][4]
    assert out.loc[5, "Fwd PSH Flags"] == 0.0 and not ex["Fwd PSH Flags"][5]
    assert out.loc[6, "Fwd PSH Flags"] == 0.0 and ex["Fwd PSH Flags"][6]
    assert not ex[G.FIW][1] and ex[G.BIW][1]                          # 3 bwd packets: new FWD window inexact
    assert not ex[G.BIW][6] and ex[G.FIW][6]                          # 2 fwd packets: new Bwd window inexact


def test_ks_stat():
    assert G.ks_stat(np.array([1, 2, 3]), np.array([1, 2, 3])) == 0.0
    assert G.ks_stat(np.array([0, 0]), np.array([5, 5])) == 1.0
    assert abs(G.ks_stat(np.array([1, 2, 3, 4]), np.array([3, 4, 5, 6])) - 0.5) < 1e-12
    assert np.isnan(G.ks_stat(np.array([]), np.array([1.0])))


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
