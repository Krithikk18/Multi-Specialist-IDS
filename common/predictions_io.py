"""common/predictions_io.py -- runtime predictions on disk: the Phase 3 single file or the Phase 3.1 chunked parts.

    w = ChunkWriter(run_dir, chunk_rows=10_000, chunk_seconds=60.0)     # Phase 3.1 runtime
    w.add({"flow_uid": [...], "event_time": [...], ...})                # one micro-batch; full parts are written
    w.close()                                                           # last part + manifest "complete": true
    df = read_predictions(run_dir)                                      # either layout -> one pandas DataFrame
    df, info = read_predictions(run_dir, with_info=True)

Layouts in a run folder:
  single  predictions.parquet (Phase 3: everything written once at the end of the run)
  parts   predictions/part-00000.parquet, part-00001.parquet, ... + predictions/manifest.json
A part is cut when the buffer holds chunk_rows rows (cut exactly there; the rest stays buffered) or when the buffered
rows span >= chunk_seconds of event time (time_column), whichever comes first; the buffer is freed once a part is on
disk. Every part is written to a dot-tmp file, fsynced and renamed (atomic on POSIX); then the manifest (also tmp +
rename) lists it with its rows, first / last event time and sha256. A crash therefore loses at most the rows not yet in
a listed part, and the manifest says exactly what was saved. The reader trusts the manifest only: each listed part's
sha256 is checked, parts / tmp files the manifest does not list are reported (info) and ignored.
Rows are written in the order they were added; reading concatenates the parts in manifest order, so the concatenation
equals the single-file layout row for row.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

SINGLE = "predictions.parquet"
PART_DIR = "predictions"
MANIFEST = "manifest.json"
VERSION = 1


class PredictionsError(RuntimeError):
    pass


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _atomic_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class ChunkWriter:
    def __init__(self, run_dir: Path, chunk_rows: int, chunk_seconds: float, time_column: str = "event_time"):
        if int(chunk_rows) < 1 or not float(chunk_seconds) > 0:
            raise PredictionsError("chunk_rows must be >= 1 and chunk_seconds > 0")
        self.dir = Path(run_dir) / PART_DIR
        if self.dir.exists() or (Path(run_dir) / SINGLE).exists():
            raise PredictionsError(f"{run_dir}: predictions already present (never overwritten)")
        self.dir.mkdir(parents=True)
        self.rows, self.secs, self.tcol = int(chunk_rows), float(chunk_seconds), time_column
        self.buf: dict = {}
        self.n = 0
        self.t_first = None
        self.t_last = None
        self.parts: list = []
        self.closed = False
        self._write_manifest(complete=False)

    # ---------------------------------------------------------------- writing
    def add(self, cols: dict) -> int:
        """Append the rows of `cols` (column -> list, equal lengths, same columns every call); returns parts written."""
        if self.closed:
            raise PredictionsError("writer is closed")
        if not cols:
            return 0
        k = {len(v) for v in cols.values()}
        if len(k) != 1:
            raise PredictionsError(f"columns of unequal length {sorted(k)}")
        m = k.pop()
        if m == 0:
            return 0
        if self.buf and set(cols) != set(self.buf):
            raise PredictionsError("column set changed between batches")
        if self.tcol not in cols:
            raise PredictionsError(f"time column {self.tcol!r} missing")
        for c, v in cols.items():
            self.buf.setdefault(c, []).extend(v)
        ts = [float(x) for x in cols[self.tcol]]
        self.t_first = ts[0] if self.t_first is None else self.t_first
        self.t_last = max([self.t_last if self.t_last is not None else ts[0], *ts])
        self.n += m
        written = 0
        while self.n >= self.rows:
            self._flush(self.rows)
            written += 1
        if self.n and self.t_last - self.t_first >= self.secs:
            self._flush(self.n)
            written += 1
        return written

    def _flush(self, n: int) -> None:
        import pyarrow as pa
        import pyarrow.parquet as pq
        part = {c: v[:n] for c, v in self.buf.items()}
        rest = {c: v[n:] for c, v in self.buf.items()}
        ts = [float(x) for x in part[self.tcol]]
        name = f"part-{len(self.parts):05d}.parquet"
        path = self.dir / name
        tmp = self.dir / f".{name}.tmp"
        pq.write_table(pa.table(part), tmp)
        with open(tmp, "rb+") as fh:
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        self.parts.append({"file": name, "rows": n, "first_event_time": ts[0], "last_event_time": max(ts),
                           "min_event_time": min(ts), "sha256": _sha256(path)})
        self._write_manifest(complete=False)
        self.buf = rest                                                # the written rows are freed here
        self.n -= n
        rt = [float(x) for x in rest.get(self.tcol, [])]
        self.t_first = rt[0] if rt else None
        self.t_last = max(rt) if rt else None

    def close(self) -> dict:
        if self.closed:
            return self.manifest()
        if self.n:
            self._flush(self.n)
        self.closed = True
        self._write_manifest(complete=True)
        return self.manifest()

    def manifest(self, complete: bool | None = None) -> dict:
        return {"layout": "parts", "version": VERSION, "chunk_rows": self.rows, "chunk_seconds": self.secs,
                "time_column": self.tcol, "complete": self.closed if complete is None else complete,
                "rows": sum(p["rows"] for p in self.parts), "parts": list(self.parts)}

    def _write_manifest(self, complete: bool) -> None:
        _atomic_bytes(self.dir / MANIFEST, (json.dumps(self.manifest(complete), indent=1) + "\n").encode("utf-8"))


# -------------------------------------------------------------------- reading
def layout(run_dir: Path) -> str | None:
    d = Path(run_dir)
    single, parts = (d / SINGLE).is_file(), (d / PART_DIR / MANIFEST).is_file()
    if single and parts:
        raise PredictionsError(f"{d}: both layouts present")
    return "single" if single else ("parts" if parts else None)


def read_predictions(run_dir: Path, columns: list | None = None, verify: bool = True, with_info: bool = False):
    """Every saved prediction row of a run folder (either layout) as one pandas DataFrame, in written order."""
    import pandas as pd
    import pyarrow.parquet as pq
    d = Path(run_dir)
    lay = layout(d)
    if lay is None:
        raise PredictionsError(f"{d}: no predictions ({SINGLE} or {PART_DIR}/{MANIFEST})")
    if lay == "single":
        df = pq.read_table(d / SINGLE, columns=columns).to_pandas()
        info = {"layout": "single", "rows": len(df), "complete": True, "parts": 1, "ignored": []}
        return (df, info) if with_info else df
    man = json.loads((d / PART_DIR / MANIFEST).read_text(encoding="utf-8"))
    if man.get("layout") != "parts":
        raise PredictionsError(f"{d}: manifest layout {man.get('layout')!r}")
    listed = {p["file"] for p in man["parts"]}
    ignored = sorted(p.name for p in (d / PART_DIR).iterdir() if p.name != MANIFEST and p.name not in listed)
    frames = []
    for p in man["parts"]:
        f = d / PART_DIR / p["file"]
        if not f.is_file():
            raise PredictionsError(f"{f}: listed in the manifest but missing")
        if verify and _sha256(f) != p["sha256"]:
            raise PredictionsError(f"{f}: sha256 != manifest")
        t = pq.read_table(f, columns=columns)
        if t.num_rows != p["rows"]:
            raise PredictionsError(f"{f}: {t.num_rows} rows != manifest {p['rows']}")
        frames.append(t.to_pandas())
    df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=columns or [])
    info = {"layout": "parts", "rows": int(len(df)), "complete": bool(man.get("complete")), "parts": len(man["parts"]),
            "ignored": ignored}
    return (df, info) if with_info else df
