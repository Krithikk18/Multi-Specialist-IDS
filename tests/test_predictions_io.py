"""tests/test_predictions_io.py -- common/predictions_io.py: chunk boundaries by rows and by event time, atomic writes
(no tmp files left), manifest sha256 check, reading both layouts, a simulated crash between parts leaves a readable
prefix, and the runtime under a chunked config writes the same rows as the single-file layout.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_predictions_io.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from common import predictions_io as PIO  # noqa: E402


def _batch(i0: int, n: int, t0: float, dt: float = 0.01) -> dict:
    return {"flow_uid": [f"s:{i}" for i in range(i0, i0 + n)], "event_time": [t0 + k * dt for k in range(n)],
            "pred": [i % 4 for i in range(i0, i0 + n)], "alert": [bool(i % 3 == 0) for i in range(i0, i0 + n)],
            "incident_id": ["" for _ in range(n)], "p_0": [0.25 for _ in range(n)]}


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="pio_"))


def _raises(fn, exc=Exception) -> bool:
    try:
        fn()
    except exc:
        return True
    return False


def test_chunk_by_rows_exact():
    d = _tmp()
    w = PIO.ChunkWriter(d, chunk_rows=10, chunk_seconds=1e9)
    for k in range(5):                                              # 5 batches of 7 rows = 35 rows
        w.add(_batch(7 * k, 7, 100.0 + k))
    man = w.close()
    assert [p["rows"] for p in man["parts"]] == [10, 10, 10, 5], man["parts"]
    df = PIO.read_predictions(d)
    assert list(df["flow_uid"]) == [f"s:{i}" for i in range(35)]
    assert man["complete"] and man["rows"] == 35
    shutil.rmtree(d)


def test_chunk_by_time():
    d = _tmp()
    w = PIO.ChunkWriter(d, chunk_rows=10_000, chunk_seconds=60.0)
    w.add(_batch(0, 3, 0.0))
    w.add(_batch(3, 3, 30.0))
    assert len(w.parts) == 0
    w.add(_batch(6, 3, 61.0))                                       # span 0 .. 61.02 >= 60 -> one part of 9 rows
    assert [p["rows"] for p in w.parts] == [9]
    w.add(_batch(9, 2, 70.0))
    man = w.close()
    assert [p["rows"] for p in man["parts"]] == [9, 2]
    assert man["parts"][0]["first_event_time"] == 0.0 and abs(man["parts"][0]["last_event_time"] - 61.02) < 1e-9
    shutil.rmtree(d)


def test_atomic_no_tmp_and_sha_checked():
    d = _tmp()
    w = PIO.ChunkWriter(d, chunk_rows=4, chunk_seconds=1e9)
    w.add(_batch(0, 9, 0.0))
    w.close()
    names = sorted(p.name for p in (d / PIO.PART_DIR).iterdir())
    assert names == ["manifest.json", "part-00000.parquet", "part-00001.parquet", "part-00002.parquet"], names
    df, info = PIO.read_predictions(d, with_info=True)
    assert info["layout"] == "parts" and info["parts"] == 3 and info["rows"] == 9 and not info["ignored"]
    p = d / PIO.PART_DIR / "part-00001.parquet"
    b = bytearray(p.read_bytes())
    b[len(b) // 2] ^= 0xFF
    p.write_bytes(bytes(b))
    assert _raises(lambda: PIO.read_predictions(d), PIO.PredictionsError)
    shutil.rmtree(d)


def test_read_single_layout_and_refusals():
    import pyarrow as pa
    import pyarrow.parquet as pq
    d = _tmp()
    pq.write_table(pa.table(_batch(0, 5, 0.0)), d / PIO.SINGLE)
    df, info = PIO.read_predictions(d, with_info=True)
    assert info["layout"] == "single" and len(df) == 5
    assert _raises(lambda: PIO.ChunkWriter(d, 10, 60.0), PIO.PredictionsError)      # never next to an existing layout
    e = _tmp()
    assert _raises(lambda: PIO.read_predictions(e), PIO.PredictionsError)           # nothing there
    w = PIO.ChunkWriter(e, 10, 60.0)
    assert _raises(lambda: w.add({"flow_uid": ["a"], "event_time": [1.0, 2.0]}), PIO.PredictionsError)
    w.add(_batch(0, 2, 0.0))
    assert _raises(lambda: w.add({"flow_uid": ["a"], "event_time": [1.0]}), PIO.PredictionsError)  # column set changed
    shutil.rmtree(d)
    shutil.rmtree(e)


def test_both_layouts_give_identical_frames():
    import pyarrow as pa
    import pyarrow.parquet as pq
    a, b = _tmp(), _tmp()
    batches = [_batch(10 * k, 10, float(k)) for k in range(7)]
    cols = {k: sum((bb[k] for bb in batches), []) for k in batches[0]}
    pq.write_table(pa.table(cols), a / PIO.SINGLE)
    w = PIO.ChunkWriter(b, chunk_rows=16, chunk_seconds=2.5)
    for bb in batches:
        w.add(bb)
    w.close()
    A, B = PIO.read_predictions(a), PIO.read_predictions(b)
    assert A.equals(B), (A.dtypes, B.dtypes)
    shutil.rmtree(a)
    shutil.rmtree(b)


def test_crash_between_parts_leaves_readable_prefix():
    d = _tmp()
    w = PIO.ChunkWriter(d, chunk_rows=5, chunk_seconds=1e9)
    w.add(_batch(0, 12, 0.0))                                       # parts 0, 1 written; 2 rows buffered
    # simulated crash: a part file renamed into place but the manifest never updated, plus a stray tmp file
    shutil.copyfile(d / PIO.PART_DIR / "part-00001.parquet", d / PIO.PART_DIR / "part-00002.parquet")
    (d / PIO.PART_DIR / ".part-00003.parquet.tmp").write_bytes(b"partial")
    del w                                                           # never closed
    df, info = PIO.read_predictions(d, with_info=True)
    assert len(df) == 10 and list(df["flow_uid"]) == [f"s:{i}" for i in range(10)]
    assert not info["complete"] and info["parts"] == 2
    assert info["ignored"] == [".part-00003.parquet.tmp", "part-00002.parquet"], info["ignored"]
    man = json.loads((d / PIO.PART_DIR / PIO.MANIFEST).read_text())
    assert man["complete"] is False and man["rows"] == 10
    shutil.rmtree(d)


def test_runtime_chunked_config_same_rows():
    """The runtime writes the same prediction rows with and without chunking (tests/test_runtime_e2e's 120 real val
    flows, imported read-only): single file under the Phase 3 config, 7-row parts under a chunked copy of it."""
    import copy
    sys.path.insert(0, str(REPO / "tests"))
    import test_runtime_e2e as E
    from common import flow_source as FS
    raw = E._data()["raw"]
    s1, run1, _, _ = E._run(E.CFG, FS.CsvReplaySource(E.CFG, frame=raw))
    cfg = copy.deepcopy(E.CFG)
    cfg["predictions_chunk_rows"], cfg["predictions_chunk_seconds"] = 7, 1e9
    s2, run2, _, _ = E._run(cfg, FS.CsvReplaySource(cfg, frame=raw))
    assert PIO.layout(run1) == "single" and PIO.layout(run2) == "parts"
    A, B = PIO.read_predictions(run1), PIO.read_predictions(run2)
    assert len(A) == 120 and A.equals(B)
    man = json.loads((run2 / PIO.PART_DIR / PIO.MANIFEST).read_text())
    assert man["complete"] and len(man["parts"]) == 18 and s2["predictions"]["n_parts"] == 18    # ceil(120 / 7)
    assert s1["predictions"]["layout"] == "single"


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
    np.random.seed(0)
    _ = pd
    sys.exit(main())
