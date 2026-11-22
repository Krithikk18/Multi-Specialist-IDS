"""tests/test_flow_source.py -- common/flow_source.py: emission-time ordering (ties in file order), the raw-row format,
event slices, pacing (speed factor, ticks), test-split refusal (config, frame, pcap slices), the pcap path's emission-
time reconstruction; and on the real val split: every v2_1 val flow replayed once, in emission order.

Plain asserts. Usage (repo root): python tests/test_flow_source.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import flow_source as FS  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import schemas as S  # noqa: E402

CFG = C.load_phase3_config()


def _raises(fn, exc=Exception, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or match.lower() in str(e).lower()
    return False


def _frame(starts, durs_us) -> pd.DataFrame:
    n = len(starts)
    d = {f: np.full(n, float(i)) for i, f in enumerate(S.feature_columns())}
    d["Flow Duration"] = np.asarray(durs_us, float)
    d.update({"Flow ID": [f"f{i}" for i in range(n)], "Src IP": ["10.0.0.1"] * n, "Src Port": ["1"] * n,
              "Dst IP": ["10.0.0.2"] * n, "Dst Port": ["2"] * n, "Timestamp": pd.NaT,
              "src_mac": ["aa"] * n, "dst_mac": [""] * n, "start_ts": np.asarray(starts, np.int64),
              "session": ["s"] * n, "row_in_file": np.arange(n)})
    return pd.DataFrame(d)


def _cfg(**src) -> dict:
    c = copy.deepcopy(CFG)
    c["source"].update(src)
    return c


def test_order_by_emission_time_ties_in_file_order():
    df = _frame([100, 100, 101, 99, 100], [2e6, 0, 0, 3e6, 0])      # emissions 102, 100, 101, 102, 100
    src = FS.CsvReplaySource(_cfg(), frame=df)
    ev = [(t, r["_meta"]["row"]) for k, t, r in src.events() if k == "flow"]
    assert ev == [(100.0, 1), (100.0, 4), (101.0, 2), (102.0, 0), (102.0, 3)], ev
    assert len(src) == 5


def test_raw_row_format():
    df = _frame([1665186351], [5e5])
    row = next(r for k, t, r in FS.CsvReplaySource(_cfg(), frame=df).events() if k == "flow")
    for c in S.feature_columns() + FS.ID_COLS + FS.MAC_COLS:
        assert c in row, c
    assert row["Timestamp"] == "07/10/2022 11:45:51 PM", row["Timestamp"]
    assert isinstance(row["Flow Duration"], float) and row["dst_mac"] == ""
    m = row["_meta"]
    assert m["flow_uid"] == "s:0" and m["start_ts"] == 1665186351 and m["event_time"] == 1665186351.5


def test_event_slice_and_busiest_window():
    df = _frame(list(range(0, 1000, 10)) + [500] * 50, [0] * 150)
    src = FS.CsvReplaySource(_cfg(), frame=df, event_slice=(200, 300))
    ts = [t for k, t, _ in src.events() if k == "flow"]
    assert len(ts) == 10 and min(ts) >= 200 and max(ts) < 300
    full = FS.CsvReplaySource(_cfg(), frame=df)
    lo, hi = full.busiest_window(1.0)                                   # 60 s window holding the 50 extra flows
    assert lo <= 500 < hi and hi - lo == 60


def test_speed_pacing_and_ticks():
    df = _frame([0, 1, 3], [0, 0, 0])
    t0 = time.monotonic()
    ev = list(FS.CsvReplaySource(_cfg(speed="10x", tick_s=1.0), frame=df).events())
    wall = time.monotonic() - t0
    assert 0.27 <= wall < 1.5, wall                                    # 3 event s at 10x = 0.3 s
    assert [k for k, _, _ in ev].count("flow") == 3
    assert any(k == "tick" for k, _, _ in ev)
    t0 = time.monotonic()
    list(FS.CsvReplaySource(_cfg(speed="max"), frame=df).events())
    assert time.monotonic() - t0 < 0.1


def test_refuses_test_split():
    c = copy.deepcopy(CFG)
    c["source"]["split"] = "test"
    assert _raises(lambda: FS.CsvReplaySource(c), exc=C.TestSplitRefused)
    df = _frame([0], [0])
    df["split"] = "test"
    assert _raises(lambda: FS.CsvReplaySource(_cfg(), frame=df), exc=C.TestSplitRefused)


def test_pcap_source_refuses_unsliced_or_test_pcaps():
    d = Path(tempfile.mkdtemp(prefix="p3fs_"))
    p = d / "slice.pcap"
    p.write_bytes(b"")
    assert _raises(lambda: FS.CicfmPcapSource(CFG, p, d / "o"), exc=FS.FlowSourceError, match="slice manifest")
    (d / "slice.pcap.slice.json").write_text(json.dumps({"split": "test"}), encoding="utf-8")
    assert _raises(lambda: FS.CicfmPcapSource(CFG, p, d / "o"), exc=C.TestSplitRefused)
    t = d / "DDoS-SYN_Flood10_test.pcap"
    t.write_bytes(b"")
    assert _raises(lambda: FS.CicfmPcapSource(CFG, t, d / "o"), exc=C.TestSplitRefused)
    (d / "slice.pcap.slice.json").write_text(json.dumps({"split": "val", "session": "x"}), encoding="utf-8")
    assert FS.CicfmPcapSource(CFG, p, d / "o").slice_manifest["split"] == "val"


def test_emission_time_reconstruction():
    fids = ["a", "b", "a", "c"]
    start = np.array([0.0, 1.0, 130.0, 2.0])                            # a's successor starts 130 s after a
    end = np.array([5.0, 50.0, 131.0, 3.0])
    e = FS.emission_times(fids, start, end, 120)
    assert np.all(np.diff(e) >= 0) and np.all(e >= end)
    assert e[0] == 130.0 and e[1] == 130.0 and e[3] == 131.0, e      # a held until its successor's packet


def test_real_val_replay_covers_every_flow_once():
    src = FS.CsvReplaySource(CFG)
    assert src.info["dataset_version"] == "v2_0_v1equiv" and len(src) == 157558
    ev, uids = [], set()
    for k, t, r in src.events():
        ev.append(t)
        uids.add(r["_meta"]["flow_uid"])
    assert len(uids) == 157558 and np.all(np.diff(ev) >= 0)
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    from config.config import REPO_ROOT
    v21 = D.load_split(load_phase2_config(REPO_ROOT / CFG["phase2_config"]), "val", ["session", "row_in_file"])
    assert uids == set(v21["session"] + ":" + v21["row_in_file"].astype(str))


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
