#!/usr/bin/env python
"""08b_extend_test.py -- dataset v1.1: v1 plus the CICIoT2023 daytime benign captures
(BenignTraffic1-3) as TEST-ONLY sessions, for a less noisy test FP / hour.

Nothing of v1 is rebuilt or re-split:
  train / val  byte copies of ~/lgids_cache/datasets/v1/{train,val}.parquet (sha256 asserted)
  test         v1 test rows, unchanged and first, then the daytime benign rows

Inputs (never modified): config/split_plan.json (v1.0), config/features_v1.json,
config/device_table.csv, results/step8/manifest_v1.json, the v1 parquet files and, per daytime
session, 07's output for its pcap (extraction/run_cicflowmeter.py -> 07a_attack_coverage.py ->
07_label_attacks.py --family benign_daytime, flows under --flows-dir, reports under --label-dir):
  <flows-dir>/<stem>/<stem>.pcap_Flow__singlepkt.csv.meta.json   extractor provenance
  <flows-dir>/<stem>/<stem>_labelled.csv.gz                       84 + 14 tag + 5 label columns
  <label-dir>/<stem>_label_report.json                            hard_pass, completion key
The v1 test.parquet is opened only to copy its rows (and hash them to verify the copy): no
scoring, no model.

Rules for the daytime rows (08's, via 08's own functions):
  filter   owner_status == "owned" AND exclude_reason == "" AND label != "excluded"; owned rows
           whose owner has no behaviour_group are dropped as "ungrouped"
  group    device_table behaviour_group (the v1.0 lock; 06c placements included); no re-grouping
  unregistered MACs (the map has the MAC, device_table does not: 04's role "unlisted", which can
           never own a flow): a row that 04 left "unowned" with an unlisted endpoint, exclude_reason
           blank and label != "excluded" is kept with owner = that MAC (the Src side if both),
           group GEN, device "unregistered:<mac>", device_category "unregistered_mac". Rows owned
           by a registered device keep that owner. device_table is not changed.
  features the 70 columns of config/features_v1.json in order (sha256 checked against v1),
           float64 as in v1 (the parquet schema is v1's test schema), NaN / +-inf -> 0
  meta     y = 0, attack_family "", group, device, device_category, session = stem,
           split = "test", start_ts (flow Timestamp, epoch s)
  no subsampling (08 never samples test benign)
  hours    08's active benign hours: active segments over ALL flow starts of the file (a pause >
           active_idle_gap_seconds ends one) holding >= 1 usable benign flow start; the whole
           session is test

Assertions (any failure: exit 1, no parquet / plan written, manifest + summary say why):
  verify_lock passes; extractor sidecars match the lock (jar, commit, patches, 120 s / 5 s, TZ
  UTC, heap); 07 reports hard_pass for the same pcap and jar; v1 files match manifest_v1 rows /
  bytes; device_table, behaviour_groups, split_plan.json unchanged since v1; features sha256 =
  v1; CICFlowMeter columns = benign_night's; NO daytime row labelled attack (all rows, not only
  usable ones); daytime flow-start ranges overlap no v1 session and no other daytime session
  (sharing one boundary second is reported, not an overlap: Timestamps are truncated to
  seconds and the pcaps are packet-disjoint); every daytime row written has y 0, split test,
  group in G1 / G2 / GEN; train / val sha256 = v1; the first rows of v1.1 test = v1 test
  (per-column sha256 over the rows); row counts add up; v1 files, results/step8 and
  split_plan.json unchanged at the end.

Outputs
  <out-dir>/{train,val,test}.parquet        default ~/lgids_cache/datasets/v1_1
  config/split_plan_v1_1.json               v1.0 plan + the daytime sessions as "test_only"
  <report-dir>/manifest_v1_1.json, summary.md   default results/step8b
  logs/08b_extend_test_<UTC>.log            timestamped log (also on stdout)

--dry-run: only the first --sessions entry (all of them with --limit-rows), outputs in
~/lgids_cache/datasets/v1_1_dry_run and results/step8b/dry_run (the plan goes there too, never
to config/). --limit-rows N reads the first N rows of each daytime file.

One run at a time: an exclusive flock on <out-dir>/.08b_extend.lock and <report-dir>/.08b_extend.lock.

Exit status: 0 ok, 1 bad input / lock / assertion failed / another run active, 2 unexpected
exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from config.config import (BEHAVIOUR_GROUPS, CACHE_DIR, CONFIG_DIR, DEVICE_TABLE, EXTRACTOR, GROUPS, REPO_ROOT,
                           RESULTS_DIR, LockError, sha256_file, verify_lock)


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m08 = _load("build_datasets", "08_build_datasets.py")
md_table, norm_mac = m08.md_table, m08.norm_mac

DAY_SESSIONS = ("BenignTraffic1", "BenignTraffic2", "BenignTraffic3")
DAY_FLOWS_DIR = CACHE_DIR / "flows" / "benign_day"
DAY_LABELS = RESULTS_DIR / "step8b" / "labels"
V1_DIR = CACHE_DIR / "datasets" / "v1"
V1_MANIFEST = RESULTS_DIR / "step8" / "manifest_v1.json"
OUT_DIR = CACHE_DIR / "datasets" / "v1_1"
OUT_DIR_DRY = CACHE_DIR / "datasets" / "v1_1_dry_run"
REPORT_DIR = RESULTS_DIR / "step8b"
PLAN_OUT = CONFIG_DIR / "split_plan_v1_1.json"
LOG_DIR = REPO_ROOT / "logs"
DATASET_VERSION = "v1_1"
PLAN_VERSION = "v1.1"
DAY_FAMILY = "benign_daytime"          # 07 --family for the daytime pcaps (any attack row is a failure)
UNREG_GROUP, UNREG_REASON = "GEN", "unregistered_mac"
SIDE_COLS = ["src_mac", "src_role", "dst_mac", "dst_role"]
SPLITS = m08.SPLITS
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
RUN_LOCK = ".08b_extend.lock"
FP_EXAMPLES = (1, 2, 5, 10, 20, 50)

_LOG = None


def log(msg: str) -> None:
    line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')}  {msg}"
    print(line, flush=True)
    if _LOG is not None:
        _LOG.write(line + "\n")
        _LOG.flush()


def fatal(msg: str) -> None:
    log(f"FATAL: {msg}")
    print(f"FATAL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


m08.log, m08.fatal = log, fatal          # 08's helpers report through this log


def utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat(timespec="seconds")


def iso_epoch(s: str) -> float:
    return dt.datetime.fromisoformat(s).timestamp()


def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.08b_extend.lock for the whole run."""
    d.mkdir(parents=True, exist_ok=True)
    path = d / RUN_LOCK
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another 08b_extend_test.py run is using {d} (lock {path} held by: {holder})")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}"
             f" argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


class ColumnHasher:
    """sha256 per column over the rows fed so far, independent of how they are batched."""

    def __init__(self, names: list[str]):
        self.h = {n: hashlib.sha256() for n in names}
        self.rows = 0

    def update(self, b) -> None:
        if not b.num_rows:
            return
        self.rows += b.num_rows
        for n, h in self.h.items():
            col = b.column(n)
            if pa.types.is_string(col.type):
                h.update("".join(v + "\x00" for v in col.to_pylist()).encode("utf-8"))
            else:
                h.update(np.ascontiguousarray(np.asarray(col)).tobytes())

    def digest(self) -> str:
        return hashlib.sha256("".join(h.hexdigest() for h in self.h.values()).encode()).hexdigest()


# --------------------------------------------------------------------------- inputs

def check_v1(M: dict, checks: dict) -> dict:
    """v1 parquet files vs manifest_v1 (rows from the parquet footer, bytes) and their sha256."""
    out, bad = {}, []
    for split in SPLITS:
        p = V1_DIR / f"{split}.parquet"
        if not p.is_file():
            fatal(f"v1 file missing: {p}")
        want = M["outputs"][split]
        rows, size = pq.ParquetFile(p).metadata.num_rows, p.stat().st_size
        if rows != want["rows"] or size != want["bytes"]:
            bad.append(f"{split}: rows {rows:,} / bytes {size:,} vs manifest {want['rows']:,} / {want['bytes']:,}")
        out[split] = {"path": str(p), "rows": rows, "bytes": size, "sha256": sha256_file(p)}
    checks["v1 files match manifest_v1 (rows, bytes)"] = {"pass": not bad, "detail": "; ".join(bad) or "ok"}
    return out


def check_features(M: dict, checks: dict) -> tuple[list[str], pa.Schema]:
    F = json.loads(m08.FEATURES_JSON.read_text(encoding="utf-8"))
    feats = F["features"]
    sha = hashlib.sha256(json.dumps(feats, separators=(",", ":")).encode("utf-8")).hexdigest()
    schemas = {s: pq.ParquetFile(V1_DIR / f"{s}.parquet").schema_arrow for s in SPLITS}
    schema = schemas["test"]
    ok = (sha == F["sha256"] == M["features"]["sha256"] and len(feats) == F["n_features"] == M["features"]["n"]
          and schema.names == feats + m08.OUT_META and all(schemas[s].equals(schema) for s in SPLITS)
          and all(schema.field(c).type == pa.float64() for c in feats))
    checks["features = v1 (features_v1.json sha256, order, v1 parquet schema)"] = {
        "pass": ok, "detail": f"{len(feats)} features, sha256 {sha[:16]}... (json {F['sha256'][:16]}..., "
                              f"manifest_v1 {M['features']['sha256'][:16]}...); parquet columns = features + "
                              f"{m08.OUT_META}: {schema.names == feats + m08.OUT_META}"}
    return feats, schema


def check_config(M: dict, checks: dict) -> dict:
    now = {"device_table": sha256_file(DEVICE_TABLE), "behaviour_groups": sha256_file(BEHAVIOUR_GROUPS),
           "split_plan": sha256_file(m08.SPLIT_PLAN)}
    was = {"device_table": M["config"]["device_table"]["sha256"],
           "behaviour_groups": M["config"]["behaviour_groups"]["sha256"],
           "split_plan": M["config"]["split_plan"]["sha256"]}
    diff = [k for k in now if now[k] != was[k]]
    checks["device_table, behaviour_groups, split_plan.json unchanged since v1"] = {
        "pass": not diff, "detail": f"changed: {diff}" if diff else "ok (sha256 = manifest_v1)"}
    return now


def load_sessions(stems: list[str], flows_dir: Path, label_dir: Path, dev_sha: str, ref_header: list[str],
                  checks: dict) -> list[dict]:
    out, bad = [], []
    for stem in stems:
        d = flows_dir / stem
        meta_p = d / f"{stem}.pcap_Flow__{EXTRACTOR.build}.csv.meta.json"
        gz = d / f"{stem}_labelled.csv.gz"
        rp = label_dir / f"{stem}_label_report.json"
        for p in (meta_p, gz, rp):
            if not p.is_file():
                fatal(f"{stem}: input not found {p} (extraction + 07a + 07 for this pcap first)")
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        R = json.loads(rp.read_text(encoding="utf-8"))
        k = R["completion_key"]
        want = {"jar_sha256": EXTRACTOR.jar_sha256, "commit": EXTRACTOR.commit, "patch": EXTRACTOR.patch,
                "patch_sweeper": EXTRACTOR.patch_sweeper, "build": EXTRACTOR.build,
                "flow_timeout_s": EXTRACTOR.flow_timeout_s, "activity_timeout_s": EXTRACTOR.activity_timeout_s,
                "tz": EXTRACTOR.tz, "java_heap_max": EXTRACTOR.java_heap_max}
        got = {x: meta.get(x) for x in want}
        if got != want:
            bad.append(f"{stem}: extractor sidecar {[(x, got[x]) for x in want if got[x] != want[x]]}")
        if not str(meta.get("timeouts_check", "")).startswith("verified"):
            bad.append(f"{stem}: timeouts_check {meta.get('timeouts_check')!r}")
        if not R.get("hard_pass"):
            bad.append(f"{stem}: 07 hard checks failed")
        if k["pcap_sha256"] != meta["input_pcap_sha256"] or k["jar_sha256"] != EXTRACTOR.jar_sha256:
            bad.append(f"{stem}: 07 report is for pcap {k['pcap_sha256'][:16]}... / jar {k['jar_sha256'][:16]}..., "
                       f"extraction for {meta['input_pcap_sha256'][:16]}...")
        if k["device_table_sha256"] != dev_sha:
            bad.append(f"{stem}: 07 ran with device_table {k['device_table_sha256'][:16]}..., current {dev_sha[:16]}...")
        if R["flows"] != meta["row_count"]:
            bad.append(f"{stem}: 07 flows {R['flows']:,} != extractor rows {meta['row_count']:,}")
        h = m08.read_header(gz)
        if h[:m08.N_ORIG] != ref_header[:m08.N_ORIG]:
            bad.append(f"{stem}: CICFlowMeter columns differ from benign_night")
        miss = [c for c in ["Timestamp", *m08.META_COLS, *m08.LABEL_COLS, *SIDE_COLS] if c not in h]
        if miss:
            bad.append(f"{stem}: missing columns {miss}")
        out.append({"session": stem, "path": gz, "meta": meta, "report": R, "report_path": rp,
                    "input": {"session": stem, "path": str(gz), "sha256": sha256_file(gz),
                              "pcap": meta["input_pcap"], "pcap_sha256": meta["input_pcap_sha256"],
                              "extractor_rows": meta["row_count"], "label_report": str(rp),
                              "label_completion_key": k, "by_label": R["by_label"],
                              "by_exclude_reason": R["by_exclude_reason"]}})
    checks["daytime inputs: extractor lock, 07 hard_pass, same pcap / jar / device_table, columns"] = {
        "pass": not bad, "detail": "; ".join(bad) or f"ok ({len(stems)} session(s))"}
    return out


# --------------------------------------------------------------------------- daytime rows

def usable_day(f: pd.DataFrame, dev: pd.DataFrame, D: Counter, U_mac: dict) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """08's filter on one chunk plus the unregistered-MAC rule. Returns (start t of all rows, positions
    of the rows kept, frame of the kept rows: t, mac, group, device, category, unreg)."""
    t = m08.flow_start(f["Timestamp"])
    n = len(f)
    label = f["label"].to_numpy(object)
    D["rows"] += n
    D["label_attack"] += int((label == "attack").sum())
    status = f["owner_status"].to_numpy(object)
    owned = status == "owned"
    clean = f["exclude_reason"].to_numpy(object) == ""
    notexc = label != "excluded"
    D["not_owned"] += int((~owned).sum())
    D["exclude_reason"] += int((owned & ~clean).sum())
    D["label_excluded"] += int((owned & clean & ~notexc).sum())
    mac = f["owner_mac"].str.lower().to_numpy(object)
    group = pd.Series(mac).map(dev["behaviour_group"]).fillna("").to_numpy(object)
    keep = owned & clean & notexc
    ung = keep & ~np.isin(group, GROUPS.labels)
    D["ungrouped"] += int(ung.sum())
    reg = keep & ~ung

    s_un = f["src_role"].to_numpy(object) == "unlisted"
    d_un = f["dst_role"].to_numpy(object) == "unlisted"
    smac, dmac = f["src_mac"].str.lower().to_numpy(object), f["dst_mac"].str.lower().to_numpy(object)
    unreg = (status == "unowned") & (s_un | d_un) & clean & notexc
    umac = np.where(s_un, smac, dmac)
    D["unregistered_mac_kept"] += int(unreg.sum())
    for side_un, side_mac in ((s_un, smac), (d_un, dmac)):          # census of every unlisted endpoint
        for m, k in Counter(side_mac[side_un]).items():
            U_mac[m]["endpoint_flows"] += k
    D["unlisted_endpoint_owned_by_registered"] += int((owned & (s_un | d_un)).sum())
    for m, k in Counter(umac[unreg]).items():
        U_mac[m]["kept_as_gen"] += k
    for m, k in Counter(umac[(status == "unowned") & (s_un | d_un) & ~(clean & notexc)]).items():
        U_mac[m]["dropped_excluded"] += k

    pos = np.flatnonzero(reg | unreg)
    mac = np.where(unreg, umac, mac)[pos]
    is_un = unreg[pos]
    U = pd.DataFrame({"t": t[pos], "mac": mac, "unreg": is_un})
    U["group"] = np.where(is_un, UNREG_GROUP, group[pos])
    U["device"] = np.where(is_un, "unregistered:" + U["mac"], U["mac"].map(dev["device_name"]).fillna(""))
    U["category"] = np.where(is_un, UNREG_REASON, U["mac"].map(dev["paper_category"]).fillna(""))
    odev = f["owner_device"].to_numpy(object)[pos]
    D["owner_device_name_mismatch"] += int(((odev != U["device"].to_numpy(object)) & ~is_un).sum())
    return t, pos, U


def process_sessions(sources: list[dict], feats: list[str], schema: pa.Schema, dev: pd.DataFrame, P: dict,
                     day_part: Path, args) -> dict:
    """One pass per daytime file: written rows -> day_part (v1 test schema), hours, counts."""
    W = None
    res = {"drops": {}, "ranges": {}, "segments": {}, "hours": {}, "hours_registered_only": {}, "rows": Counter(),
           "nan": np.zeros(len(feats), np.int64), "inf": np.zeros(len(feats), np.int64), "unreg_macs": {},
           "bad_rows": 0, "n": 0}
    cols = ["Timestamp", *m08.META_COLS, *m08.LABEL_COLS, *SIDE_COLS, *feats]
    hasher = ColumnHasher(schema.names)
    t0 = time.monotonic()
    for s in sources:
        sess, D = s["session"], Counter()
        U_mac = defaultdict(Counter)
        secs, ben_t, ben_t_reg, tmin, tmax = [], [], [], None, None
        for off, f in m08.iter_chunks(s["path"], cols, feats, args.chunk, args.block_mb, args.limit_rows):
            t, pos, U = usable_day(f, dev, D, U_mac)
            tmin = int(t.min()) if tmin is None else min(tmin, int(t.min()))
            tmax = int(t.max()) if tmax is None else max(tmax, int(t.max()))
            secs.append(np.unique(t))
            ben_t.append(np.unique(U["t"].to_numpy(np.int64)))
            ben_t_reg.append(np.unique(U.loc[~U["unreg"], "t"].to_numpy(np.int64)))
            X = f[feats].to_numpy(np.float64)[pos]
            res["nan"] += np.isnan(X).sum(0)
            res["inf"] += np.isinf(X).sum(0)
            X[~np.isfinite(X)] = 0.0
            n = len(U)
            cols_out = {c: X[:, j] for j, c in enumerate(feats)}
            cols_out.update({"y": np.zeros(n, np.int8), "attack_family": np.full(n, "", dtype=object),
                             "group": U["group"].to_numpy(object), "device": U["device"].to_numpy(object),
                             "device_category": U["category"].to_numpy(object),
                             "session": np.full(n, sess, dtype=object), "split": np.full(n, "test", dtype=object),
                             "start_ts": U["t"].to_numpy(np.int64)})
            tab = pa.Table.from_pydict(cols_out, schema=schema)
            if W is None:
                W = pq.ParquetWriter(day_part, schema, compression="zstd")
            W.write_table(tab, row_group_size=1 << 20)
            hasher.update(tab)
            res["n"] += n
            res["bad_rows"] += int((~U["group"].isin(GROUPS.labels)).sum())
            for (g, dname), k in U.groupby(["group", "device"]).size().items():
                res["rows"][(sess, g, dname)] += int(k)
            log(f"  [{sess}] rows {off + len(f):>10,}  kept {len(pos):>8,}  attack-labelled {D['label_attack']:,}  "
                f"{time.monotonic() - t0:7.1f} s")
        if tmin is None:
            fatal(f"{sess}: no rows in {s['path']}")
        seg = m08.active_segments(np.unique(np.concatenate(secs)), P["active_idle_gap_seconds"])
        cuts = ([], ["test"])
        res["segments"][sess] = seg
        res["hours"][sess] = m08.benign_hours(seg, np.unique(np.concatenate(ben_t)), cuts)["test"]
        res["hours_registered_only"][sess] = m08.benign_hours(seg, np.unique(np.concatenate(ben_t_reg)), cuts)["test"]
        res["ranges"][sess] = (tmin, tmax)
        res["drops"][sess] = dict(D)
        res["unreg_macs"][sess] = {m: dict(c) for m, c in U_mac.items()}
    if W is not None:
        W.close()
    res["day_hash"] = hasher.digest()
    return res


# --------------------------------------------------------------------------- assemble

def build_outputs(out_dir: Path, schema: pa.Schema, day_part: Path, n_day: int, v1: dict, checks: dict) -> dict:
    """train / val: byte copies; test: v1 test rows then the daytime rows. Written as *.partial."""
    parts = {}
    for split in ("train", "val"):
        part = out_dir / f"{split}.parquet.partial"
        shutil.copyfile(V1_DIR / f"{split}.parquet", part)
        parts[split] = part
    same = {s: sha256_file(parts[s]) == v1[s]["sha256"] for s in ("train", "val")}
    checks["train / val parquet = byte copies of v1 (sha256)"] = {"pass": all(same.values()), "detail": f"{same}"}

    part = out_dir / "test.parquet.partial"
    h_v1, n_v1 = ColumnHasher(schema.names), 0
    with pq.ParquetWriter(part, schema, compression="zstd") as w:
        for b in pq.ParquetFile(V1_DIR / "test.parquet").iter_batches(batch_size=500_000):   # copy only
            w.write_batch(b, row_group_size=1 << 20)
            h_v1.update(b)
            n_v1 += b.num_rows
        if n_day:
            for b in pq.ParquetFile(day_part).iter_batches(batch_size=500_000):
                w.write_batch(b, row_group_size=1 << 20)
    parts["test"] = part

    # re-read the written test file: its first n_v1 rows must hash like v1's, the rest like the daytime rows
    h_head, h_tail, seen = ColumnHasher(schema.names), ColumnHasher(schema.names), 0
    for b in pq.ParquetFile(part).iter_batches(batch_size=500_000):
        k = max(0, min(b.num_rows, n_v1 - seen))
        h_head.update(b.slice(0, k))
        h_tail.update(b.slice(k))
        seen += b.num_rows
    h_day = ColumnHasher(schema.names)
    if n_day:
        for b in pq.ParquetFile(day_part).iter_batches(batch_size=500_000):
            h_day.update(b)
    ok_head = h_head.digest() == h_v1.digest() and h_head.rows == n_v1 == v1["test"]["rows"]
    ok_tail = h_tail.digest() == h_day.digest() and h_tail.rows == n_day
    checks["v1.1 test = v1 test rows unchanged, then the daytime rows"] = {
        "pass": ok_head and ok_tail and seen == n_v1 + n_day,
        "detail": f"head {h_head.rows:,} rows {'=' if ok_head else '!='} v1 test {n_v1:,} (column sha256 "
                  f"{h_v1.digest()[:16]}...); tail {h_tail.rows:,} {'=' if ok_tail else '!='} daytime {n_day:,}; "
                  f"total {seen:,}"}
    return {"parts": parts, "v1_test_rows_hash": h_v1.digest(), "v1_1_test_rows": seen}


def write_plan(path: Path, P: dict, plan_sha: str, sources: list[dict], ranges: dict) -> dict:
    Q = json.loads(json.dumps(P))
    Q["version"] = PLAN_VERSION
    Q["note"] = ("v1.0 plan (config/split_plan.json, unchanged) + the CICIoT2023 daytime benign captures as "
                 "test_only sessions, added by 08b_extend_test.py. 08_build_datasets.py does not read this file: "
                 "v1.1 train / val are byte copies of v1, v1.1 test = v1 test + the test_only sessions.")
    Q["base_plan"] = {"path": "config/split_plan.json", "version": P["version"], "sha256": plan_sha}
    for s in sources:
        Q["sessions"][s["session"]] = "test_only"
        Q.setdefault("session_aliases", {})[s["session"]] = f"daytime benign ({s['session']})"
    Q["test_only_sessions"] = {
        s["session"]: {"kind": "benign", "split": "test", "source": "07_label_attacks.py --family " + DAY_FAMILY,
                       "flows": s["input"]["path"], "pcap": s["input"]["pcap"], "pcap_sha256": s["input"]["pcap_sha256"],
                       "start_utc": utc(ranges[s["session"]][0]), "end_utc": utc(ranges[s["session"]][1])}
        for s in sources}
    Q["test_only_rules"] = {"filter": "08: owned, exclude_reason blank, label != excluded, grouped",
                            "unregistered_mac": f"unowned row with an unlisted endpoint -> group {UNREG_GROUP}, "
                                                f"device unregistered:<mac>, device_category {UNREG_REASON}",
                            "subsample": "none", "group": "device_table behaviour_group (v1.0 lock)"}
    path.write_text(json.dumps(Q, indent=1) + "\n", encoding="utf-8")
    return {"path": str(path), "version": PLAN_VERSION, "sha256": sha256_file(path)}


# --------------------------------------------------------------------------- report

def write_md(path: Path, M: dict) -> None:
    H = M["hours"]
    L = [f"# Step 8b -- dataset {DATASET_VERSION}: v1 + daytime benign test sessions"
         + (" (DRY RUN)" if M["dry_run"] else ""), "",
         f"- run {M['run_utc']}, runtime {M['runtime_s']:,} s, peak RSS {M['peak_rss_mb']:,} MB",
         f"- args: `{' '.join(M['argv'])}`", f"- log: `{M['log']}`"]
    if M["dry_run"]:
        L.append("- **DRY RUN: " + (f"first {M['limit_rows']:,} rows of each file" if M["limit_rows"]
                                    else "first session only") + "; outputs are NOT the v1.1 dataset**")
    L += ["", "## Assertions", "", f"**{'PASS' if M['hard_pass'] else 'FAIL'}**", ""]
    L += md_table([{"check": k, "pass": "PASS" if v["pass"] else "FAIL", "detail": v["detail"]}
                   for k, v in M["checks"].items()], ["check", "pass", "detail"])
    if M.get("touching"):
        L += ["", "Boundary seconds shared (not an overlap; Timestamps are whole seconds, the pcaps are "
              "packet-disjoint):", ""] + [f"- {x}" for x in M["touching"]]
    L += ["", "## Test active benign hours (08 rule) and FP / hour", "",
          f"- v1 test: **{H['v1_test']:.3f} h** (manifest_v1)",
          f"- added: **{H['added']:.3f} h** ({', '.join(f'{k} {v:.3f}' for k, v in H['per_session'].items())})"
          f"; registered-owner rows only: {H['added_registered_only']:.3f} h",
          f"- v1.1 test: **{H['v1_1_test']:.3f} h** (x{H['v1_1_test'] / H['v1_test']:.2f})", ""]
    L += md_table(M["fp_per_hour"], ["test_FPs", "FP_per_h_v1", "FP_per_h_v1_1"]) + [""]
    L += ["## Test rows before / after", ""]
    L += md_table(M["test_totals"], ["dataset", "benign", "attack", "total"]) + [""]
    L += ["## Daytime sessions", "", "rows = all flows in the file; added = rows written to test", ""]
    L += md_table(M["sessions"], ["session", "start_utc", "end_utc", "span_h", "active_h", "segments", "rows",
                                  "label_attack", "not_owned", "exclude_reason", "label_excluded", "ungrouped",
                                  "unregistered_mac_kept", "added", "benign_h"]) + [""]
    L += ["## 07 labels per daytime session (all rows)", ""]
    L += md_table(M["labels07"], ["session", "attack", "benign", "excluded", "excluded_by_reason"]) + [""]
    L += ["## Rows added per group", ""] + md_table(M["by_group"], ["group", *M["session_names"], "total"]) + [""]
    L += ["## Rows added per device", ""] + md_table(M["by_device"], ["group", "device", *M["session_names"], "total"]) + [""]
    L += ["## Unregistered MACs (in the pcap map, not in device_table)", "",
          "endpoint_flows = flows with this MAC as an endpoint (role unlisted); kept_as_gen = written to test "
          f"(group {UNREG_GROUP}, device_category {UNREG_REASON}); dropped_excluded = unowned + exclude_reason or "
          "label excluded. Flows with a registered smart-home device on the other side stay that device's rows.", ""]
    L += md_table(M["unregistered_macs"], ["session", "mac", "endpoint_flows", "kept_as_gen", "dropped_excluded"])
    L += ["", f"- flows with an unlisted endpoint owned by a registered device: {M['unreg_owned_by_registered']:,}", ""]
    L += ["## NaN / Inf replaced by 0 (daytime rows written)", ""]
    L += md_table(M["nan_inf"], ["column", "nan", "inf"]) + [""]
    L += ["## Outputs", ""] + md_table([{"file": k, **v} for k, v in M["outputs"].items()],
                                       ["file", "rows", "bytes", "sha256", "path"]) + [""]
    L += ["## Inputs", ""] + md_table(M["inputs"], ["session", "extractor_rows", "sha256", "pcap_sha256", "path"])
    L += ["", "v1: " + ", ".join(f"{k} sha256 {v['sha256'][:16]}... ({v['rows']:,} rows)" for k, v in M["v1"].items())]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def main() -> int:
    global _LOG
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="first session only (all with --limit-rows); dry-run dirs")
    ap.add_argument("--limit-rows", type=int, default=None, help="read only the first N rows of each daytime file")
    ap.add_argument("--sessions", nargs="+", default=list(DAY_SESSIONS), help="daytime pcap stems")
    ap.add_argument("--flows-dir", type=Path, default=DAY_FLOWS_DIR)
    ap.add_argument("--label-dir", type=Path, default=DAY_LABELS, help="07 --out-dir of the daytime run")
    ap.add_argument("--out-dir", type=Path, default=None, help=f"default {OUT_DIR} ({OUT_DIR_DRY} with --dry-run)")
    ap.add_argument("--report-dir", type=Path, default=None,
                    help=f"default {REPORT_DIR.relative_to(REPO_ROOT)} (<that>/dry_run with --dry-run)")
    ap.add_argument("--force", action="store_true", help="replace existing parquet files in --out-dir / the v1.1 plan")
    ap.add_argument("--chunk", type=int, default=500_000)
    ap.add_argument("--block-mb", type=int, default=32)
    args = ap.parse_args()
    t0 = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"08b_extend_test_{run_utc.replace(':', '').replace('+0000', 'Z')}{'_dry_run' if args.dry_run else ''}.log"
    _LOG = open(log_path, "a", encoding="utf-8")

    if args.limit_rows is not None and args.limit_rows < 1:
        fatal("--limit-rows must be >= 1")
    if args.block_mb < 1 or args.chunk < 1000:
        fatal("--block-mb must be >= 1 and --chunk >= 1000")
    if len(set(args.sessions)) != len(args.sessions):
        fatal(f"--sessions must be unique: {args.sessions}")
    if args.dry_run and args.limit_rows is None:
        args.sessions = args.sessions[:1]
    out_dir = (args.out_dir or (OUT_DIR_DRY if args.dry_run else OUT_DIR)).expanduser()
    report_dir = args.report_dir or (REPORT_DIR / "dry_run" if args.dry_run else REPORT_DIR)
    out_dir = out_dir if out_dir.is_absolute() else REPO_ROOT / out_dir
    report_dir = report_dir if report_dir.is_absolute() else REPO_ROOT / report_dir
    plan_path = report_dir / PLAN_OUT.name if args.dry_run else PLAN_OUT
    v1r, rep8 = V1_DIR.resolve(), (RESULTS_DIR / "step8").resolve()
    if out_dir.resolve() == v1r or out_dir.resolve().is_relative_to(v1r) or v1r.is_relative_to(out_dir.resolve()):
        fatal(f"--out-dir {out_dir} must not be (in) the v1 dataset dir {V1_DIR}")
    if report_dir.resolve().is_relative_to(rep8) or report_dir.resolve().is_relative_to(CONFIG_DIR.resolve()):
        fatal(f"--report-dir {report_dir} must not be under results/step8 or config/")
    if set(args.sessions) & set(json.loads(m08.SPLIT_PLAN.read_text(encoding="utf-8"))["sessions"]):
        fatal(f"--sessions {args.sessions} collide with v1 session names")
    label_dir = args.label_dir if args.label_dir.is_absolute() else REPO_ROOT / args.label_dir

    try:
        lock = verify_lock()
    except LockError as e:
        fatal(str(e))
    locks = [run_lock(d) for d in dict.fromkeys([out_dir.resolve(), report_dir.resolve()])]   # noqa: F841
    finals = [out_dir / f"{s}.parquet" for s in SPLITS]
    if any(p.exists() for p in finals) and not args.force:
        fatal(f"{out_dir} already holds a dataset; pass --force to replace it")
    log(f"08b_extend_test  {'DRY RUN' if args.dry_run else 'BUILD'}  sessions {args.sessions}"
        + (f"  LIMIT {args.limit_rows:,} rows/file" if args.limit_rows else "") + f"  -> {out_dir}  log {log_path}")

    checks: dict = {}
    M1 = json.loads(V1_MANIFEST.read_text(encoding="utf-8"))
    P = json.loads(m08.SPLIT_PLAN.read_text(encoding="utf-8"))
    plan_sha = sha256_file(m08.SPLIT_PLAN)
    if plan_path.exists() and not args.force:
        fatal(f"{plan_path} exists; pass --force to replace it")
    checks["verify_lock"] = {"pass": lock["ok"], "detail": f"{len(lock['checks'])} checks"}
    log("hashing v1 files and inputs")
    v1 = check_v1(M1, checks)
    feats, schema = check_features(M1, checks)
    cfg = check_config(M1, checks)
    step8_sha = {p.name: sha256_file(p) for p in sorted((RESULTS_DIR / "step8").glob("*")) if p.is_file()}
    dev = m08.load_device_map()
    ref_header = m08.read_header(m08.BENIGN_TAGGED)
    sources = load_sessions(args.sessions, args.flows_dir.expanduser(), label_dir, cfg["device_table"], ref_header,
                            checks)
    if not all(c["pass"] for c in checks.values()):
        bad = {k: v["detail"] for k, v in checks.items() if not v["pass"]}
        fatal(f"input checks failed: {bad}")

    out_dir.mkdir(parents=True, exist_ok=True)
    day_part = out_dir / "test.daytime.parquet.partial"
    log("daytime sessions: one pass each")
    R = process_sessions(sources, feats, schema, dev, P, day_part, args)

    n_att = {s: d["label_attack"] for s, d in R["drops"].items()}
    checks["no daytime row labelled attack (07, all rows)"] = {
        "pass": sum(n_att.values()) == 0, "detail": f"attack-labelled rows per session {n_att}"}
    v1_ranges = {s["session"]: (iso_epoch(s["start_utc"]), iso_epoch(s["end_utc"])) for s in M1["sessions"]}
    overlaps, touching, seen = [], [], set()
    every = {**v1_ranges, **R["ranges"]}
    for a in R["ranges"]:
        for b in every:
            if a == b or (b, a) in seen:
                continue
            seen.add((a, b))
            (a0, a1), (b0, b1) = every[a], every[b]
            span = f"{a} [{utc(a0)}, {utc(a1)}] / {b} [{utc(b0)}, {utc(b1)}]"
            if a0 < b1 and b0 < a1:
                overlaps.append(f"overlap: {span}")
            elif a0 == b1 or a1 == b0:
                touching.append(f"{span}: share second {utc(a0 if a0 == b1 else a1)}")
    checks["daytime time ranges overlap no v1 session and no other daytime session"] = {
        "pass": not overlaps, "detail": "; ".join(overlaps) or f"ok ({len(touching)} shared boundary second(s))"}
    checks["daytime rows written: y 0, attack_family blank, split test, group in G1/G2/GEN"] = {
        "pass": R["bad_rows"] == 0, "detail": f"{R['bad_rows']} rows with a group outside {GROUPS.labels} "
                                              "(y / family / split are set as constants)"}

    pre_ok = all(c["pass"] for c in checks.values())
    outputs, built = {}, None
    if pre_ok:
        log("assembling v1.1 (train / val copies, test = v1 test + daytime)")
        built = build_outputs(out_dir, schema, day_part, R["n"], v1, checks)
    day_part.unlink(missing_ok=True)
    hard_pass = pre_ok and all(c["pass"] for c in checks.values())
    plan_info = None
    if hard_pass:
        for split, part in built["parts"].items():
            os.replace(part, out_dir / f"{split}.parquet")
        plan_info = write_plan(plan_path, P, plan_sha, sources, R["ranges"])
        for split in SPLITS:
            p = out_dir / f"{split}.parquet"
            outputs[f"{split}.parquet"] = {"rows": pq.ParquetFile(p).metadata.num_rows, "bytes": p.stat().st_size,
                                           "sha256": sha256_file(p), "path": str(p)}
        outputs[plan_path.name] = {"rows": "", "bytes": plan_path.stat().st_size, "sha256": plan_info["sha256"],
                                   "path": str(plan_path)}
    elif built:
        for part in built["parts"].values():
            part.unlink(missing_ok=True)

    # nothing of v1 / step 8 / the v1.0 plan changed during the run
    after_v1 = {s: sha256_file(V1_DIR / f"{s}.parquet") for s in SPLITS}
    after8 = {p.name: sha256_file(p) for p in sorted((RESULTS_DIR / "step8").glob("*")) if p.is_file()}
    unchanged = (after_v1 == {s: v1[s]["sha256"] for s in SPLITS} and after8 == step8_sha
                 and sha256_file(m08.SPLIT_PLAN) == plan_sha)
    checks["v1 parquet, results/step8, split_plan.json unchanged after the run"] = {
        "pass": unchanged, "detail": "ok (sha256 before = after)" if unchanged else "CHANGED"}
    hard_pass = hard_pass and unchanged

    # ---- report
    v1_hours = float(M1["benign_active_hours"]["per_split"]["test"])
    added = sum(R["hours"].values())
    after_h = v1_hours + added
    v1_tot = next(r for r in M1["totals"] if r["split"] == "test")
    names = [s["session"] for s in sources]
    rows = R["rows"]
    by_g = defaultdict(Counter)
    by_d = defaultdict(Counter)
    for (sess, g, d), n in rows.items():
        by_g[g][sess] += n
        by_d[(g, d)][sess] += n
    seg = R["segments"]
    M = {"dataset_version": DATASET_VERSION, "run_utc": run_utc, "argv": sys.argv, "log": str(log_path),
         "dry_run": args.dry_run, "limit_rows": args.limit_rows, "code_sha256": CODE_SHA256,
         "hard_pass": hard_pass, "checks": checks, "touching": touching,
         "config": {"split_plan_v1_0": {"path": str(m08.SPLIT_PLAN), "sha256": plan_sha}, "split_plan_v1_1": plan_info,
                    **{k: {"sha256": v} for k, v in cfg.items() if k != "split_plan"},
                    "features": {"n": len(feats), "sha256": M1["features"]["sha256"]},
                    "verify_lock": [{"check": n, "pass": o, "detail": d} for n, o, d in lock["checks"]]},
         "v1": v1, "v1_test_rows_column_sha256": built["v1_test_rows_hash"] if built else None,
         "daytime_rows_column_sha256": R["day_hash"],
         "inputs": [s["input"] for s in sources],
         "sessions": [{"session": s, "start_utc": utc(R["ranges"][s][0]), "end_utc": utc(R["ranges"][s][1]),
                       "span_h": round((R["ranges"][s][1] - R["ranges"][s][0]) / 3600, 2),
                       "active_h": round(float((seg[s][:, 1] - seg[s][:, 0]).sum()) / 3600, 2),
                       "segments": len(seg[s]), **{k: R["drops"][s].get(k, 0) for k in
                                                   ("rows", "label_attack", "not_owned", "exclude_reason",
                                                    "label_excluded", "ungrouped", "unregistered_mac_kept",
                                                    "owner_device_name_mismatch")},
                       "added": sum(n for (x, _, _), n in rows.items() if x == s), "benign_h": round(R["hours"][s], 3)}
                      for s in names],
         "labels07": [{"session": s["session"], **{k: s["report"]["by_label"].get(k, 0) for k in ("attack", "benign", "excluded")},
                       "excluded_by_reason": ", ".join(f"{k} {v:,}" for k, v in s["report"]["by_exclude_reason"].items() if v)
                                             or "-"} for s in sources],
         "session_names": names,
         "by_group": [{"group": g, **{s: c.get(s, 0) for s in names}, "total": sum(c.values())} for g, c in sorted(by_g.items())],
         "by_device": [{"group": g, "device": d, **{s: c.get(s, 0) for s in names}, "total": sum(c.values())}
                       for (g, d), c in sorted(by_d.items(), key=lambda kv: (kv[0][0], -sum(kv[1].values())))],
         "unregistered_macs": [{"session": s, "mac": m, **{k: c.get(k, 0) for k in ("endpoint_flows", "kept_as_gen",
                                                                                    "dropped_excluded")}}
                               for s, d in R["unreg_macs"].items() for m, c in sorted(d.items())],
         "unreg_owned_by_registered": sum(d.get("unlisted_endpoint_owned_by_registered", 0) for d in R["drops"].values()),
         "hours": {"v1_test": v1_hours, "added": added, "per_session": R["hours"],
                   "added_registered_only": sum(R["hours_registered_only"].values()), "v1_1_test": after_h,
                   "definition": M1["benign_active_hours"]["definition"]},
         "fp_per_hour": [{"test_FPs": k, "FP_per_h_v1": round(k / v1_hours, 4), "FP_per_h_v1_1": round(k / after_h, 4)}
                         for k in FP_EXAMPLES],
         "test_totals": [{"dataset": "v1", "benign": v1_tot["benign"], "attack": v1_tot["attack"], "total": v1_tot["total"]},
                         {"dataset": DATASET_VERSION, "benign": v1_tot["benign"] + R["n"], "attack": v1_tot["attack"],
                          "total": v1_tot["total"] + R["n"]}],
         "nan_inf": [{"column": c, "nan": int(R["nan"][j]), "inf": int(R["inf"][j])}
                     for j, c in enumerate(feats) if R["nan"][j] or R["inf"][j]],
         "outputs": outputs}
    M["runtime_s"], M["peak_rss_mb"] = round(time.monotonic() - t0, 1), m08.peak_rss_mb()
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "manifest_v1_1.json").write_text(json.dumps(M, indent=1, default=str) + "\n", encoding="utf-8")
    write_md(report_dir / "summary.md", M)

    log("=" * 100)
    for k, v in checks.items():
        log(f"  {'PASS' if v['pass'] else 'FAIL'}  {k}: {v['detail']}")
    log(f"rows added {R['n']:,}; test active benign hours {v1_hours:.3f} -> {after_h:.3f} "
        f"(+{added:.3f}); 1 FP = {1 / v1_hours:.4f} -> {1 / after_h:.4f} FP/h")
    log(f"{'BUILD' if not args.dry_run else 'DRY RUN'} {'PASS' if hard_pass else 'FAIL'}   "
        f"summary {report_dir / 'summary.md'}   runtime {M['runtime_s']} s")
    log("=" * 100)
    return 0 if hard_pass else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        if _LOG is not None:
            traceback.print_exc(file=_LOG)
        sys.exit(2)
