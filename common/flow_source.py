"""common/flow_source.py -- Phase 3 flow sources (val only). Both yield the same raw-row dict format.

Raw row = one CICFlowMeter output row as the extractor wrote it (NOT orientation-normalised): the 70 feature columns
(floats) + identity columns Flow ID, Src IP, Src Port, Dst IP, Dst Port, Timestamp (strings, TS_FORMAT) and, when the
source knows them, src_mac / dst_mac ("" = off-LAN / unknown); plus key "_meta" = {"flow_uid", "start_ts",
"event_time", "session", "row"} which the runtime uses for bookkeeping only (never as a model input).

    src = CsvReplaySource(cfg)                       # dataset replay (default: v2_0_v1equiv val = v2_1 val flows, raw)
    for kind, t, payload in src.events(): ...        # kind "flow" (payload = row dict) | "tick" (payload None)

CsvReplaySource  rows of the configured replay dataset's split (common/phase2_data.load_split: refuses test), ordered
                 by emission time = start_ts + Flow Duration / 1e6 (ties: file order); optional dry-run sample, event
                 slice and pacing (speed "max" = no sleeping; "<f>x" = f event seconds per wall second, with "tick"
                 events every tick_s of event time while waiting so the consumer can advance its clock).
CicfmPcapSource  runs the locked CICFlowMeter (extraction/run_cicflowmeter.py, jar sha256 checked by verify_lock) on a
                 val-window pcap slice that carries a slice manifest (split must be val / train, never test), schema-
                 checks the CSV (common.schemas.validate_schema) and replays its rows in their real emission order;
                 event time reconstructed per docs/V2_PREREG_PHASE3.md section 2 (emission_times()). No MACs: the router
                 resolves them from the IP -> MAC map.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

from common import phase3_config as C
from common import schemas as S

ID_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp"]
MAC_COLS = ["src_mac", "dst_mac"]
DURATION_COL = "Flow Duration"            # microseconds (CICFlowMeter)


class FlowSourceError(RuntimeError):
    pass


def _ts_str(epoch_s) -> list[str]:
    import pandas as pd
    return pd.to_datetime(np.asarray(epoch_s, dtype=np.int64), unit="s", utc=True).strftime(S.TS_FORMAT).tolist()


class FlowSource:
    """Interface: events() yields ("flow", event_time, row) in non-decreasing event time, and ("tick", t, None)."""
    name = "flow_source"

    def __init__(self, speed: str = "max", tick_s: float = 1.0):
        self.factor = C.speed_factor(speed)
        self.speed = speed
        self.tick_s = float(tick_s)
        self.stats = {"rows": 0, "ticks": 0, "slept_s": 0.0}

    def _rows(self):
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError

    def events(self):
        w0 = e0 = None
        for row in self._rows():
            t = row["_meta"]["event_time"]
            if self.factor is not None:
                if w0 is None:
                    w0, e0 = time.monotonic(), t
                target = w0 + (t - e0) / self.factor
                while True:
                    now = time.monotonic()
                    if now >= target:
                        break
                    step = min(target - now, self.tick_s / self.factor)
                    time.sleep(step)
                    self.stats["slept_s"] += step
                    if target - time.monotonic() > 0:
                        self.stats["ticks"] += 1
                        yield "tick", e0 + (time.monotonic() - w0) * self.factor, None
            self.stats["rows"] += 1
            yield "flow", t, row


# --------------------------------------------------------------------------- CSV replay
class CsvReplaySource(FlowSource):
    name = "csv_replay"

    def __init__(self, cfg: dict, sample: bool = False, event_slice: tuple | None = None, frame=None):
        """cfg = Phase 3 config. frame (tests): a DataFrame in the dataset layout instead of the dataset file."""
        super().__init__(cfg["source"]["speed"], cfg["source"]["tick_s"])
        so = cfg["source"]
        C.refuse_test(so["split"], "(CsvReplaySource)")
        feats = S.feature_columns()
        self.info = {"kind": self.name, "split": so["split"], "sample": bool(sample), "event_slice": event_slice}
        if frame is None:
            from common import phase2_data as D
            from common.phase2_config import load_phase2_config
            from config.config import REPO_ROOT
            cfg2 = load_phase2_config(REPO_ROOT / so["replay_phase2_config"])
            if cfg2["dataset_version"] != so["replay_dataset_version"]:
                raise FlowSourceError(f"{so['replay_phase2_config']} is dataset {cfg2['dataset_version']}, config asks "
                                      f"for {so['replay_dataset_version']}")
            c = cfg2["columns"]
            cols = feats + ID_COLS + MAC_COLS + [c["start_ts"], c["session"], "row_in_file", c["group"], c["label_id"]]
            df = D.load_split(cfg2, so["split"], cols, sample=sample)
            self.info.update({"dataset_version": cfg2["dataset_version"],
                              "file_sha256": D.verify_split_file(cfg2, so["split"]),
                              "phase2_config_sha256": cfg2["_sha256"]})
            start_col, sess_col = c["start_ts"], c["session"]
        else:
            df, start_col, sess_col = frame, "start_ts", "session"
            if "split" in df.columns and (df["split"].astype(str) == "test").any():
                raise C.TestSplitRefused("frame holds test rows")
        start = df[start_col].to_numpy(np.int64)
        dur = df[DURATION_COL].to_numpy(np.float64)
        ev = start + dur / 1e6
        order = np.lexsort((np.arange(len(df)), ev))                     # emission time, ties in file order
        if event_slice is not None:
            lo, hi = event_slice
            order = order[(ev[order] >= lo) & (ev[order] < hi)]
        self._n = len(order)
        self._feat = {f: df[f].to_numpy(np.float64)[order].tolist() for f in feats}
        ids = {k: df[k].astype(str).to_numpy()[order].tolist() for k in ID_COLS if k != "Timestamp"}
        ids["Timestamp"] = _ts_str(start[order])
        self._ids = ids
        self._macs = {k: (df[k].fillna("").astype(str).to_numpy()[order].tolist() if k in df.columns else None)
                      for k in MAC_COLS}
        self._start = start[order].tolist()
        self._ev = ev[order].tolist()
        self._sess = df[sess_col].astype(str).to_numpy()[order].tolist()
        self._rowid = (df["row_in_file"].to_numpy(np.int64)[order].tolist() if "row_in_file" in df.columns
                       else order.tolist())
        self.info["rows"] = self._n
        self.info["event_span"] = [self._ev[0], self._ev[-1]] if self._n else None

    def __len__(self) -> int:
        return self._n

    def busiest_window(self, minutes: float) -> tuple[float, float]:
        """[t0, t0 + minutes) with the most flows (by emission time; earliest on ties) -- the benchmark slice rule."""
        ev = np.asarray(self._ev)
        w = minutes * 60.0
        j = np.searchsorted(ev, ev + w, side="left")
        i = int(np.argmax(j - np.arange(len(ev))))
        return float(ev[i]), float(ev[i] + w)

    def _rows(self):
        feats = list(self._feat)
        fcols = [self._feat[f] for f in feats]
        icols = [(k, v) for k, v in self._ids.items()]
        mcols = [(k, v) for k, v in self._macs.items() if v is not None]
        for i in range(self._n):
            row = {f: col[i] for f, col in zip(feats, fcols)}
            for k, v in icols:
                row[k] = v[i]
            for k, v in mcols:
                row[k] = v[i]
            row["_meta"] = {"flow_uid": f"{self._sess[i]}:{self._rowid[i]}", "start_ts": self._start[i],
                            "event_time": self._ev[i], "session": self._sess[i], "row": self._rowid[i]}
            yield row


# --------------------------------------------------------------------------- CICFlowMeter on a val pcap slice
def emission_times(flow_ids: list[str], start: np.ndarray, end: np.ndarray, flow_timeout_s: float) -> np.ndarray:
    """Event time per row given the real emission (row) order: running max of end over the rows emitted so far, raised
    to the start of the same Flow ID's next flow when that one starts >= flow_timeout_s after this flow's start."""
    start, end = np.asarray(start, float), np.asarray(end, float)
    e = np.maximum.accumulate(end) if len(end) else end.copy()
    nxt: dict = {}
    succ = np.full(len(start), np.nan)
    for i in np.argsort(start, kind="stable")[::-1]:                  # latest start first
        fid = flow_ids[i]
        if fid in nxt:
            succ[i] = nxt[fid]
        nxt[fid] = start[i]
    trig = ~np.isnan(succ) & (succ >= start + flow_timeout_s)
    e = np.where(trig, np.maximum(e, succ), e)
    return np.maximum.accumulate(e) if len(e) else e


class CicfmPcapSource(FlowSource):
    name = "cicfm_pcap"

    def __init__(self, cfg: dict, pcap: Path, out_dir: Path, csv: Path | None = None):
        super().__init__(cfg["source"]["speed"], cfg["source"]["tick_s"])
        pcap = Path(pcap)
        man_p = pcap.with_suffix(pcap.suffix + ".slice.json")
        if "test" in pcap.name.lower():
            raise C.TestSplitRefused(f"refused pcap {pcap}")
        if not man_p.is_file():
            raise FlowSourceError(f"{pcap}: no slice manifest {man_p.name} (only val / train slices are accepted)")
        man = json.loads(man_p.read_text(encoding="utf-8"))
        C.refuse_test(man.get("split", "test"), f"(slice manifest {man_p.name})")
        self.slice_manifest = man
        self.flow_timeout_s = float(cfg["pcap_source"]["flow_timeout_s"])
        self.out_dir = Path(out_dir)
        self.csv = Path(csv) if csv is not None else None
        self.info = {"kind": self.name, "pcap": str(pcap), "slice": man, "cfm": None}
        self.pcap = pcap

    def extract(self) -> dict:
        """Run the locked jar (wrapper: verify_lock, TZ=UTC, heap cap, sidecar) unless csv was given. Returns info."""
        from config.config import REPO_ROOT
        if self.csv is None:
            self.out_dir.mkdir(parents=True, exist_ok=False)
            t0 = time.monotonic()
            r = subprocess.run([sys.executable, str(REPO_ROOT / "extraction" / "run_cicflowmeter.py"), "--pcap",
                                str(self.pcap), "--out-dir", str(self.out_dir), "--suffix", "phase3"],
                               capture_output=True, text=True)
            wall = time.monotonic() - t0
            (self.out_dir / "cfm_wrapper.log").write_text(r.stdout + "\n--- stderr ---\n" + r.stderr, encoding="utf-8")
            if r.returncode != 0:
                raise FlowSourceError(f"run_cicflowmeter.py exited {r.returncode}: {r.stderr[-800:]}")
            csvs = sorted(self.out_dir.glob("*.csv"))
            if len(csvs) != 1:
                raise FlowSourceError(f"expected one CSV in {self.out_dir}, got {csvs}")
            self.csv = csvs[0]
            self.info["cfm"] = {"wall_s": wall, "csv": str(self.csv)}
        self._load()
        return self.info

    def _load(self) -> None:
        import pandas as pd
        feats = S.feature_columns()
        df = pd.read_csv(self.csv, dtype={c: str for c in ID_COLS + ["Label"]}, keep_default_na=False)
        num = {}
        for f in feats:
            num[f] = pd.to_numeric(df[f], errors="coerce").to_numpy(np.float64)
        sch = S.validate_schema(pd.DataFrame({**{f: num[f] for f in feats}, **{k: df[k] for k in df.columns if k not in feats}}),
                                assume_label="unlabelled", columns=list(df.columns))
        need = ("feature columns present", "feature columns in features_v1 order", "feature dtypes numeric",
                "Timestamp parses (TS_FORMAT, tz=UTC)")
        req = {c["check"]: c for c in sch["checks"] if c["check"] in need}
        self.info["schema"] = {"required_pass": all(c["pass"] for c in req.values()),
                               "checks": [{"check": c["check"], "pass": c["pass"], "required": c["check"] in need}
                                          for c in sch["checks"]]}
        if not self.info["schema"]["required_pass"]:
            raise FlowSourceError(f"{self.csv}: schema checks failed {[c for c in req.values() if not c['pass']]}")
        ts = S.parse_timestamps(df["Timestamp"])                      # resolution-independent epoch seconds
        start = ((ts - pd.Timestamp(0, tz="UTC")) // pd.Timedelta(seconds=1)).to_numpy(np.int64)
        end = start + num[DURATION_COL] / 1e6
        ev = emission_times(df["Flow ID"].tolist(), start, end, self.flow_timeout_s)
        self._n = len(df)
        self._feat = {f: num[f].tolist() for f in feats}
        self._ids = {k: df[k].tolist() for k in ID_COLS}
        self._start, self._end, self._ev = start.tolist(), end.tolist(), ev.tolist()
        self.info.update({"rows": self._n, "csv_sha256": _sha(self.csv)})

    def __len__(self) -> int:
        return self._n

    def lags(self) -> np.ndarray:
        """Reconstructed emission time - (start + duration), per row (>= 0)."""
        return np.asarray(self._ev) - np.asarray(self._end)

    def _rows(self):
        feats = list(self._feat)
        sess = self.slice_manifest.get("session", "pcap")
        for i in range(self._n):
            row = {f: self._feat[f][i] for f in feats}
            for k, v in self._ids.items():
                row[k] = v[i]
            row["_meta"] = {"flow_uid": f"{sess}:cfm{i}", "start_ts": self._start[i], "event_time": self._ev[i],
                            "session": sess, "row": i}
            yield row


def _sha(p: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
