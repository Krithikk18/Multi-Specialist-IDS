"""tests/test_orientation.py -- common/orientation.py on synthetic flows: map pin + structure, R3 truth table, non-TCP
untouched, swap o swap = identity on exact pairs and identity fields, dict API == DataFrame API on random rows,
Flow ID rebuild, Down/Up Ratio recompute, unpaired defaults, feature set / column order unchanged.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_orientation.py
"""

from __future__ import annotations

import copy
import math
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from common import orientation as O  # noqa: E402
from common import schemas as S  # noqa: E402

OMAP = O.load_map(S.ORIENTATION_MAP_PATH, S.ORIENTATION_MAP_SHA256)
FEATS = S.feature_columns()
MC = OMAP["machine"]
FIW, BIW, SYN, NF, NB, PROTO = "FWD Init Win Bytes", "Bwd Init Win Bytes", "SYN Flag Count", "Total Fwd Packet", \
    "Total Bwd packets", "Protocol"
IDENT = ["Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "src_mac", "dst_mac", "device", "group", "start_ts"]


def _flow(rng, **over) -> dict:
    """A random flow (CICFlowMeter-shaped where the rule / handlers look), identity as strings."""
    r = {f: float(rng.integers(0, 400)) for f in FEATS}
    nf, nb = float(rng.integers(1, 4)), float(rng.integers(1, 5))
    r.update({PROTO: 6.0, NF: nf, NB: nb, FIW: float(rng.choice([0, 1024])), BIW: float(rng.choice([0, 29200])),
              SYN: float(rng.integers(0, 3)), "PSH Flag Count": float(rng.integers(0, 4)),
              "Fwd PSH Flags": float(rng.integers(0, 2)), "Bwd Packet Length Min": float(rng.choice([0, 5])),
              "Bwd Packet Length Max": float(rng.choice([0, 10, 60])), "Total Length of Bwd Packet": float(rng.integers(0, 200)),
              "Bwd Header Length": 20.0 * nb + float(rng.integers(0, 9))})
    sip, dip = f"10.0.0.{rng.integers(1, 250)}", f"10.0.1.{rng.integers(1, 250)}"
    sp, dp = str(rng.integers(1, 65535)), str(rng.integers(1, 65535))
    r.update({"Src IP": sip, "Dst IP": dip, "Src Port": sp, "Dst Port": dp, "src_mac": "aa:aa", "dst_mac": "bb:bb",
              "Flow ID": f"{sip}-{dip}-{sp}-{dp}-6", "device": "dev", "group": "G1", "start_ts": 1700000000})
    r.update(over)
    return r


def _df(rows) -> pd.DataFrame:
    df = pd.DataFrame(rows)[IDENT[:1] + FEATS + IDENT[1:]]
    for c in ("Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "src_mac", "dst_mac", "device", "group"):
        df[c] = df[c].astype("string")
    return df


def _r3(**over) -> dict:
    """A flow that satisfies R3 (port-scan shape: victim RST/ACK first, scanner SYN backward)."""
    d = {PROTO: 6.0, FIW: 0.0, BIW: 1024.0, SYN: 1.0, NF: 1.0, NB: 1.0}
    d.update(over)
    return _flow(np.random.default_rng(0), **d)


def test_map_pinned_and_structural():
    assert OMAP["_sha256"] == S.ORIENTATION_MAP_SHA256
    assert list(OMAP["features"]) == FEATS                              # map covers the feature list, in order
    assert MC["rule"]["name"] == "R3" and OMAP["rule"]["adopted"] == "R3"
    bad = copy.deepcopy(OMAP)
    bad["features"]["Total Fwd Packet"]["partner"] = "Flow Duration"
    try:
        O.check_map(bad)
        raise AssertionError("broken pair must raise")
    except O.OrientationError:
        pass
    bad = copy.deepcopy(OMAP)
    del bad["machine"]["handlers"]["Fwd Seg Size Min"]
    try:
        O.check_map(bad)
        raise AssertionError("unpaired feature without handler must raise")
    except O.OrientationError:
        pass


def test_r3_truth_table():
    cases = [({}, True),
             ({PROTO: 17.0}, False), ({PROTO: 0.0}, False),
             ({FIW: 1024.0}, False), ({BIW: 0.0}, False), ({SYN: 0.0}, False), ({NF: 2.0}, False),
             ({BIW: -1.0}, False), ({FIW: np.nan}, False), ({BIW: np.nan}, False), ({SYN: 3.0, NB: 3.0}, True),
             ({FIW: 0.0, BIW: 0.0}, False)]
    rows = [_r3(**o) for o, _ in cases]
    got = O.is_reversed(_df(rows), OMAP).tolist()
    assert got == [w for _, w in cases], got
    assert [O.is_reversed_flow(r, OMAP) for r in rows] == [w for _, w in cases]
    assert not O.is_reversed_flow({**_r3(), SYN: "x"}, OMAP)          # non-numeric -> not reversed


def test_non_tcp_never_touched():
    rng = np.random.default_rng(1)
    rows = [_flow(rng, **{PROTO: p, FIW: 0.0, BIW: 99.0, SYN: 1.0, NF: 1.0}) for p in (17.0, 0.0, 1.0)]
    df = _df(rows)
    out = O.swap(df, np.ones(len(df), bool), OMAP)                       # even when asked to
    pd.testing.assert_frame_equal(out, df)
    n = O.normalise(df, OMAP)
    assert not n[MC["flag_column"]].any()
    pd.testing.assert_frame_equal(n.drop(columns=[MC["flag_column"]]), df)
    for r in rows:
        assert O.swap_flow(r, OMAP) == r and O.normalise_flow(r, OMAP)[MC["flag_column"]] is False


def test_swap_twice_is_identity_on_pairs_and_identity():
    rng = np.random.default_rng(2)
    df = _df([_flow(rng) for _ in range(40)])
    m = np.ones(len(df), bool)
    twice = O.swap(O.swap(df, m, OMAP), m, OMAP)
    cols = [f for f, e in OMAP["features"].items() if e["class"] in ("pair", "pair_asymmetric", "direction_free")]
    cols += ["Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "src_mac", "dst_mac", "device", "group", "start_ts"]
    pd.testing.assert_frame_equal(twice[cols], df[cols])
    once = O.swap(df, m, OMAP)
    assert (once["Src IP"] == df["Dst IP"]).all() and (once["src_mac"] == df["dst_mac"]).all()
    assert (once[FIW] == df[BIW]).all() and (once[NF] == df[NB]).all()
    for c in ("device", "group", "start_ts"):                           # attribution / time never swapped
        assert (once[c] == df[c]).all()


def test_dict_api_equals_dataframe_api():
    rng = np.random.default_rng(3)
    rows = [_flow(rng) for _ in range(300)] + [_r3() for _ in range(5)] + [_r3(**{NB: 3.0, SYN: 3.0})]
    df = _df(rows)
    n = O.normalise(df, OMAP)
    assert n[MC["flag_column"]].sum() >= 6
    for i, r in enumerate(rows):
        d = O.normalise_flow(r, OMAP)
        for c in n.columns:
            a, b = n.iloc[i][c], d[c]
            if isinstance(b, float) or isinstance(a, (float, np.floating)):
                assert (math.isnan(float(a)) and math.isnan(float(b))) or float(a) == float(b), (i, c, a, b)
            else:
                assert str(a) == str(b) and bool(a == b), (i, c, a, b)


def test_flow_id_rebuild_and_down_up():
    r = _r3(**{"Src IP": "192.168.1.5", "Dst IP": "192.168.1.9", "Src Port": "22", "Dst Port": "60610",
               "Flow ID": "192.168.1.5-192.168.1.9-22-60610-6", NF: 1.0, NB: 3.0, SYN: 2.0, "Down/Up Ratio": 3.0})
    d = O.normalise_flow(r, OMAP)
    assert d["Flow ID"] == "192.168.1.9-192.168.1.5-60610-22-6"
    assert d["Down/Up Ratio"] == 0.0                                     # floor(old fwd 1 / old bwd 3)
    n = O.normalise(_df([r]), OMAP)
    assert n.loc[0, "Flow ID"] == d["Flow ID"] and n.loc[0, "Down/Up Ratio"] == 0.0
    r2 = _r3(**{NF: 1.0, NB: 1.0})
    assert O.normalise_flow(r2, OMAP)["Down/Up Ratio"] == 1.0


def test_unpaired_defaults_port_scan_shape():
    r = _r3(**{"Fwd Header Length": 20.0, "Bwd Header Length": 24.0, "Fwd Seg Size Min": 20.0, "Fwd Act Data Pkts": 0.0,
               "Fwd PSH Flags": 0.0, "PSH Flag Count": 0.0, "Bwd Packet Length Max": 0.0, "Bwd Packet Length Min": 0.0})
    d = O.normalise_flow(r, OMAP)
    assert d[MC["flag_column"]] is True
    assert d[FIW] == 1024.0 and d[BIW] == 0.0 and d["Fwd Seg Size Min"] == 24.0 and d["Fwd Header Length"] == 24.0
    assert d["Fwd Act Data Pkts"] == 0.0 and d["Fwd PSH Flags"] == 0.0
    for f, e in OMAP["features"].items():                               # direction-free fields untouched
        if e["class"] == "direction_free":
            assert d[f] == r[f], f


def test_columns_order_and_refusals():
    rng = np.random.default_rng(4)
    df = _df([_flow(rng) for _ in range(10)] + [_r3()])
    n = O.normalise(df, OMAP)
    assert list(n.columns) == list(df.columns) + [MC["flag_column"]]
    assert n.dtypes.drop(MC["flag_column"]).equals(df.dtypes) and n[MC["flag_column"]].dtype == bool
    assert len(n) == len(df)
    for fn in (lambda: O.normalise(n, OMAP), lambda: O.normalise_flow({**_r3(), MC["flag_column"]: False}, OMAP),
               lambda: O.swap(df.drop(columns=[FIW]), np.ones(len(df), bool), OMAP)):
        try:
            fn()
            raise AssertionError("must refuse")
        except O.OrientationError:
            pass
    again = O.normalise(n.drop(columns=[MC["flag_column"]]), OMAP)    # after a swap R3 no longer holds
    assert not again[MC["flag_column"]].any()


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
