#!/usr/bin/env python
"""21_version_dataset.py -- an immutable V2 dataset version from a passed 20_ingest_csv.py run, with V1's
split and V1's seeded caps reproduced exactly (default version v2_0_v1equiv: the V1-equivalent selection).

Inputs (never modified)
  ~/lgids_cache/v2/ingest/<run_id>/  ingest_manifest.json (status PASS, not a dry run; sha256 == the copy in
        results/20 and results/20/run_meta.json) + flows/<session>.parquet (sha256 == ingest manifest)
  results/step8/manifest_v1.json     session_cuts (V1's recorded cut boundaries per session), cap_keys,
        by_split_group_label_family, outputs; sha256 == step10_prereg pin
  config/split_plan_v1_1.json        seed, gap, caps, session modes (BenignTraffic1-3 test_only); == prereg pin
  results/step8b/manifest_v1_1.json  v1.1 rows per split, daytime by_group, test column hashes; == prereg pin
  ~/lgids_cache/datasets/v1_1/{train,val}.parquet   row-level identity (sha256 == step10_prereg)
  ~/lgids_cache/datasets/v1_1/test.parquet          KEY COLUMNS ONLY (session, start_ts, y, group); its
        feature columns are never read; file identity by rows / bytes from metadata

Split: REUSED, never re-derived. V1 sessions: manifest_v1 session_cuts (boundaries_epoch + labels) through
08.assign; flows starting in a gap window are dropped (08). The boundaries are recorded rounded to 3 decimals;
flow starts are whole seconds, so the rounding cannot move a row as long as no boundary lies within 0.0005 s
of an integer (asserted). BenignTraffic1-3: test (split_plan_v1_1 test_only).
Caps: 08's own cap_keys / cap_of / stable_hash with the plan's seed; one numpy stream per cap key,
SeedSequence([seed, stable_hash(key)]), consumed in plan order then file order (08 pass 2), keep a row iff
draw < p, p = min(1, cap / count). Counts and p must equal manifest_v1 cap_keys.

Checks (any failure: exit 1, the version directory is not created, no index line; the report is written)
  counts     per (split, group, label, family): before caps == manifest_v1 before_caps, written == manifest_v1
             written (V1 sessions); daytime test rows per group == manifest_v1_1 by_group; rows per split ==
             manifest_v1_1 outputs
  rows       train / val: every row identical to V1's v1_1 parquet, positionally (70 features after NaN / inf
             -> 0, y, attack_family, group, device, device_category, session, split, start_ts); mismatches == 0
             test: keys (session, start_ts, y, group) identical to V1's test, positionally; plus 08b's column
             sha256 of our test rows in V1's schema == manifest_v1_1 v1_test_rows_column_sha256 /
             daytime_rows_column_sha256 (full identity without reading V1's test features)
  coverage   every class with >= 1 flow in train and in val for each group it appears in anywhere (WARN only;
             udp_flood reported prominently)
No feature-value statistics are computed on any split (the test rows are counted and hashed, nothing else).

Outputs
  ~/lgids_cache/v2/datasets/<version>/{train,val,test}.parquet   ingest columns + split, V1 row order
  ~/lgids_cache/v2/datasets/<version>/split_definition.json      the reused cuts + caps + seed (hashed)
  ~/lgids_cache/v2/datasets/<version>/dataset_manifest.json
  ~/lgids_cache/v2/datasets/index.jsonl                         one appended line per version (append-only)
  results/21/  run_meta.json, run.log, summary.md, dataset_manifest.json (copy),
               figures/{split_class_balance, split_group_class_table}.png
  --dry-run: ~/lgids_cache/v2/datasets_dry_run/<version>/ (+ its own index.jsonl), results/21/dry_run/<version>/
Refuses if the version directory (or the results files) exist. One run at a time: flock on
<datasets root>/.21_version.lock.

Exit status: 0 ok, 1 refused / check failed, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from config.config import CACHE_DIR, CONFIG_DIR, GROUPS, REPO_ROOT, RESULTS_DIR, sha256_file
from common import plot_style as PS
from common import schemas as S


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m08b = _load("extend_test", "08b_extend_test.py")
m08 = m08b.m08

SCRIPT = "21_version_dataset.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
DEFAULT_VERSION = "v2_0_v1equiv"
INGEST_ROOT = CACHE_DIR / "v2" / "ingest"
DATASETS_ROOT = CACHE_DIR / "v2" / "datasets"
DATASETS_DRY_ROOT = CACHE_DIR / "v2" / "datasets_dry_run"
V1_DATA = CACHE_DIR / "datasets" / "v1_1"
RESULTS_20 = RESULTS_DIR / "20"
RESULTS_OUT = RESULTS_DIR / "21"
MANIFEST_V1 = RESULTS_DIR / "step8" / "manifest_v1.json"
MANIFEST_V11 = RESULTS_DIR / "step8b" / "manifest_v1_1.json"
SPLIT_PLAN_V11 = CONFIG_DIR / "split_plan_v1_1.json"
PREREG = CONFIG_DIR / "step10_prereg.json"
RUN_LOCK = ".21_version.lock"
SPLITS = tuple(m08.SPLITS)                                  # train, val, test
V1_META = list(m08.OUT_META)                               # y, attack_family, group, device, device_category, session, split, start_ts
TEST_KEYS = ["session", "start_ts", "y", "group"]
V2_CODE = ["20_ingest_csv.py", "21_version_dataset.py", "common/schemas.py", "common/plot_style.py",
           "common/__init__.py", "config/class_map.json", "tests/test_schemas.py"]
TEST_POLICY = ("test rows: selected, written, counted and hashed (identity checks) only; V1's test.parquet is read "
               "for the key columns session, start_ts, y, group only; no feature-value statistics on any split")

_LOG = None


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')}  {msg}"
    print(line, flush=True)
    if _LOG is not None:
        _LOG.write(line + "\n")
        _LOG.flush()


def fatal(msg: str) -> None:
    print(f"FATAL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


class CheckFailed(RuntimeError):
    pass


class V1Fatal(RuntimeError):
    pass


def v1_fatal(msg: str) -> None:
    log(f"V1 helper refused: {msg}")
    raise V1Fatal(msg)


m08.log = m08b.log = log
m08.fatal = m08b.fatal = v1_fatal


def git(*args: str) -> str:
    r = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else f"<git {' '.join(args)} failed>"


def read_json(p: Path):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def write_json(p: Path, obj) -> str:
    data = (json.dumps(obj, indent=1, default=str) + "\n").encode("utf-8")
    with open(p, "xb") as fh:
        fh.write(data)
    return hashlib.sha256(data).hexdigest()


def canon_sha256(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def run_lock(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    path = d / RUN_LOCK
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another {SCRIPT} run holds {path} ({holder}); refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {now_utc()} argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


def add_check(M: dict, name: str, ok: bool, detail: str = "", warn: bool = False) -> bool:
    M["checks"].append({"check": name, "pass": bool(ok), "detail": detail, "level": "warn" if warn else "hard"})
    log(f"  {'PASS' if ok else ('WARN' if warn else 'FAIL')}  {name}  {detail}")
    return bool(ok)


def md_table(rows: list[dict], cols: list[str] | None = None) -> list[str]:
    if not rows:
        return ["(none)"]
    cols = cols or list(rows[0])
    fmt = lambda v: f"{v:,}" if isinstance(v, (int, np.integer)) and not isinstance(v, bool) else str(v)  # noqa: E731
    return (["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
            + ["| " + " | ".join(fmt(r.get(c, "")) for c in cols) + " |" for r in rows])


# --------------------------------------------------------------------------- inputs

def check_inputs(M: dict, run_id: str) -> dict:
    """V2 lock, V1 frozen files, the ingest run (PASS, hashes), returns the loaded records."""
    lock = S.verify_v2_lock(strict=False)
    for n, o, d in lock["checks"]:
        add_check(M, f"lock: {n}", o, d)
    P10 = read_json(PREREG)
    for rel in ("results/step8/manifest_v1.json", "results/step8b/manifest_v1_1.json", "config/split_plan_v1_1.json"):
        got = sha256_file(REPO_ROOT / rel)
        add_check(M, f"V1 frozen: {rel} == step10_prereg", got == P10["inputs_sha256"][rel], got[:16] + "...")
    idir = INGEST_ROOT / run_id
    man_p = idir / "ingest_manifest.json"
    if not man_p.is_file():
        raise CheckFailed(f"no ingest manifest {man_p}")
    IM = read_json(man_p)
    man_sha = sha256_file(man_p)
    add_check(M, "ingest run PASS, full (not dry, no --limit-rows), source v1_cicflowmeter",
              IM["status"] == "PASS" and not IM["dry_run"] and IM["limit_rows"] is None
              and IM["source"] == "v1_cicflowmeter", f"status {IM['status']}, dry {IM['dry_run']}, limit {IM['limit_rows']}")
    copy_sha = sha256_file(RESULTS_20 / "ingest_manifest.json") if (RESULTS_20 / "ingest_manifest.json").is_file() else None
    meta20 = read_json(RESULTS_20 / "run_meta.json") if (RESULTS_20 / "run_meta.json").is_file() else {}
    add_check(M, "ingest_manifest sha256 == results/20 copy == results/20/run_meta.json",
              man_sha == copy_sha == meta20.get("ingest_manifest_sha256") and meta20.get("run_id") == run_id,
              f"{man_sha[:16]}... (run_meta run_id {meta20.get('run_id')})")
    add_check(M, "ingest class_map / features pins == current",
              IM["class_map"]["sha256"] == S.CLASS_MAP_SHA256 and IM["features"]["file_sha256"] == S.FEATURES_V1_SHA256,
              f"class_map {IM['class_map']['sha256'][:16]}..., features {IM['features']['file_sha256'][:16]}...")
    files = {}
    for o in IM["outputs"]["parquets"]:
        p = idir / "flows" / f"{o['session']}.parquet"
        got = sha256_file(p) if p.is_file() else None
        ok = got == o["sha256"] and pq.read_metadata(p).num_rows == o["rows"]
        add_check(M, f"ingest parquet sha256 + rows == ingest manifest: {o['session']}", ok, f"{(got or 'missing')[:16]}...")
        files[o["session"]] = p
    M["ingest"] = {"run_id": run_id, "dir": str(idir), "ingest_manifest": str(man_p), "ingest_manifest_sha256": man_sha,
                   "source_order": IM["source_order"],
                   "parquets": {o["session"]: {"rows": o["rows"], "sha256": o["sha256"]} for o in IM["outputs"]["parquets"]}}
    return {"IM": IM, "files": files, "m1": read_json(MANIFEST_V1), "m11": read_json(MANIFEST_V11),
            "P": read_json(SPLIT_PLAN_V11), "P10": P10}


def split_definition(M: dict, R: dict) -> dict:
    """V1's recorded cuts (never re-derived) + caps + seed, with the rounding-safety check."""
    m1, P = R["m1"], R["P"]
    modes = P["sessions"]
    sess = {}
    for s in R["IM"]["source_order"]:
        if s in m1["session_cuts"]:
            c = m1["session_cuts"][s]
            sess[s] = {"mode": modes[s], "labels": list(c["splits"]), "boundaries_epoch": list(c["boundaries_epoch"]),
                       "from": "results/step8/manifest_v1.json session_cuts"}
        elif modes.get(s) == "test_only":
            sess[s] = {"mode": "test_only", "labels": ["test"], "boundaries_epoch": [],
                       "from": "config/split_plan_v1_1.json test_only_sessions"}
        else:
            raise CheckFailed(f"session {s}: no V1 cut record and not test_only in split_plan_v1_1")
    want_labels = {"train": ["train", "gap@train|val", "val"], "test": ["test"], "test_only": ["test"],
                   "time_split": ["train", "gap@train|val", "val", "gap@val|test", "test"]}
    add_check(M, "recorded cut labels agree with the session modes (split_plan_v1_1)",
              all(v["labels"] == want_labels[v["mode"]] for v in sess.values()),
              ", ".join(f"{k}:{v['mode']}" for k, v in sess.items()))
    dist = [min(b - np.floor(b), np.ceil(b) - b) for v in sess.values() for b in v["boundaries_epoch"]]
    add_check(M, "3-decimal boundary rounding cannot move a whole-second flow start (all boundaries > 0.0005 s from an integer)",
              all(d > 0.0005 for d in dist), f"min distance {min(dist):.3f} s over {len(dist)} boundaries")
    D = {"seed": P["seed"], "gap_seconds": P["gap_seconds"], "caps": P["caps"], "sessions": sess,
         "rule": "08.assign(start_ts, (boundaries_epoch, labels)); gap@* rows dropped; caps per 08.cap_keys / cap_of, "
                 "SeedSequence([seed, 08.stable_hash(key)]) per key, plan order then file order, keep iff draw < p",
         "sources": {"manifest_v1": sha256_file(MANIFEST_V1), "split_plan_v1_1": sha256_file(SPLIT_PLAN_V11)}}
    return D


# --------------------------------------------------------------------------- selection

def select(R: dict, D: dict, M: dict, t0: float) -> dict:
    """Pass A: split + cap keys per row (08's functions), counts -> p, then the seeded draws."""
    P = {"caps": D["caps"], "seed": D["seed"]}
    order = R["IM"]["source_order"]
    per, pre, kid = {}, Counter(), {}                               # kid: cap key -> int code
    for s in order:
        t = pq.read_table(R["files"][s], columns=["start_ts", "y", "attack_family", "group", "device", "row_in_file"]).to_pandas()
        rif = t["row_in_file"].to_numpy(np.int64)
        if len(rif) > 1 and not (np.diff(rif) > 0).all():
            raise CheckFailed(f"{s}: ingest rows are not in file order (row_in_file not increasing)")
        c = D["sessions"][s]
        split = m08.assign(t["start_ts"].to_numpy(np.int64), (c["boundaries_epoch"], c["labels"]))
        df = pd.DataFrame({"label": np.where(t["y"].to_numpy() == 1, "attack", "benign"),
                           "family": t["attack_family"].to_numpy(object), "group": t["group"].to_numpy(object),
                           "device": t["device"].to_numpy(object), "split": split})
        gap = df["split"].str.startswith("gap@").to_numpy()
        kser = m08.cap_keys(df, P)
        kser[gap] = ""
        codes, uniq = pd.factorize(kser.to_numpy(object))
        gmap = np.array([kid.setdefault(u, len(kid)) if u else -1 for u in uniq], dtype=np.int32)
        key = gmap[codes] if len(codes) else np.zeros(0, np.int32)  # int code per row, -1 = never sampled
        pre.update(df[~gap].groupby(["split", "group", "label", "family"]).size().to_dict())
        per[s] = {"split": split, "gap": gap, "key": key}
        del df, kser, t
        log(f"  [{s}] {len(key):>10,} rows  gap {int(gap.sum()):>8,}  capped-key rows {int((key >= 0).sum()):>10,}  "
            f"{time.monotonic() - t0:6.1f} s")
    names = {i: k for k, i in kid.items()}
    n_by = Counter()
    for A in per.values():
        n_by.update(Counter(A["key"][A["key"] >= 0].tolist()))
    counts = {names[i]: n for i, n in n_by.items()}
    probs = {k: {"count": int(n), "cap": m08.cap_of(k, P), "p": min(1.0, m08.cap_of(k, P) / n)} for k, n in counts.items()}
    v1caps = R["m1"]["cap_keys"]
    bad = {k: (probs.get(k), v1caps.get(k)) for k in set(probs) | set(v1caps)
           if probs.get(k) is None or v1caps.get(k) is None or probs[k]["count"] != v1caps[k]["count"]
           or probs[k]["cap"] != v1caps[k]["cap"] or probs[k]["p"] != v1caps[k]["p"]}
    add_check(M, "cap keys: count, cap, p == manifest_v1 cap_keys (exact)", not bad,
              f"{len(probs)} keys" if not bad else f"differ: {dict(list(bad.items())[:4])}")
    rngs = {k: np.random.default_rng(np.random.SeedSequence([D["seed"], m08.stable_hash(k)])) for k in probs}
    for s in order:
        A = per[s]
        keep = ~A["gap"]
        for i, ix in pd.Series(A["key"]).groupby(A["key"], sort=True).indices.items():
            if i >= 0:                                               # ix ascending = file order
                k = names[int(i)]
                keep[ix] = rngs[k].random(len(ix)) < probs[k]["p"]
        A["keep"] = keep
    return {"per": per, "probs": probs, "pre": pre}


# --------------------------------------------------------------------------- write + identity

def write_splits(R: dict, sel: dict, out: Path, M: dict, t0: float) -> dict:
    """Pass B: kept rows, plan order then file order, into one writer per split; 08b column hashes of the test rows
    in V1's schema (V1 sessions / daytime separately); counts."""
    feats = S.feature_columns()
    v1_names = feats + V1_META
    order, v1_set = R["IM"]["source_order"], set(R["m1"]["session_cuts"])
    writers, rows, schema = {}, Counter(), None
    h_test_v1, h_test_day = m08b.ColumnHasher(v1_names), m08b.ColumnHasher(v1_names)
    written, written_cls = Counter(), Counter()
    for s in order:
        A = sel["per"][s]
        pf = pq.ParquetFile(R["files"][s])
        if schema is None:
            schema = pa.schema(list(pf.schema_arrow) + [pa.field("split", pa.string())],
                               metadata={**(pf.schema_arrow.metadata or {}), b"lgids.dataset_version": M["dataset_version"].encode()})
        off = 0
        for b in pf.iter_batches(batch_size=500_000):
            n = b.num_rows
            keep, split = A["keep"][off:off + n], A["split"][off:off + n]
            off += n
            for sp in SPLITS:
                m = keep & (split == sp)
                if not m.any():
                    continue
                tb = pa.Table.from_batches([b]).filter(pa.array(m))
                tb = tb.append_column("split", pa.array(np.full(tb.num_rows, sp, dtype=object), type=pa.string()))
                tb = tb.replace_schema_metadata(schema.metadata)
                if sp not in writers:
                    writers[sp] = pq.ParquetWriter(out / f"{sp}.parquet.partial", schema, compression="zstd")
                writers[sp].write_table(tb, row_group_size=1 << 20)
                rows[sp] += tb.num_rows
                if sp == "test":
                    (h_test_v1 if s in v1_set else h_test_day).update(tb.select(v1_names))
                lab = np.where(np.asarray(tb.column("y")) == 1, "attack", "benign")
                written.update(Counter(zip([sp] * tb.num_rows, tb.column("group").to_pylist(), lab.tolist(),
                                           tb.column("attack_family").to_pylist())))
                written_cls.update(Counter(zip([sp] * tb.num_rows, tb.column("group").to_pylist(),
                                               tb.column("label_name").to_pylist())))
        if off != len(A["keep"]):
            raise CheckFailed(f"{s}: batch rows {off} != selection rows {len(A['keep'])}")
        log(f"  [{s}] written {int(A['keep'].sum()):>9,}  {time.monotonic() - t0:6.1f} s")
    for w in writers.values():
        w.close()
    return {"rows": rows, "written": written, "written_cls": written_cls,
            "test_hash_v1": h_test_v1.digest(), "test_rows_v1": h_test_v1.rows,
            "test_hash_day": h_test_day.digest(), "test_rows_day": h_test_day.rows}


def identity_train_val(out: Path, R: dict, M: dict) -> dict:
    """Positional row identity of our train / val against V1's v1_1 files (all V1 columns)."""
    res = {}
    feats = S.feature_columns()
    cols = feats + V1_META
    for sp in ("train", "val"):
        v1p = V1_DATA / f"{sp}.parquet"
        want = R["P10"]["datasets"][sp]["sha256"]
        ok_sha = sha256_file(v1p) == want
        A = pq.read_table(out / f"{sp}.parquet.partial", columns=cols).to_pandas()
        B = pq.read_table(v1p, columns=cols).to_pandas()
        r = {"v1_file": str(v1p), "v1_sha256_ok": ok_sha, "rows_ours": len(A), "rows_v1": len(B)}
        if len(A) != len(B):
            r.update({"row_mismatches": None, "per_column": {}})
        else:
            bad_any = np.zeros(len(A), dtype=bool)
            per = {}
            for c in cols:
                a, b = A[c].to_numpy(), B[c].to_numpy()
                d = ~(a == b) if a.dtype.kind in "fiu" else (pd.Series(a).astype(str).to_numpy() != pd.Series(b).astype(str).to_numpy())
                if a.dtype.kind == "f":
                    d &= ~(np.isnan(a) & np.isnan(b))
                per[c] = int(d.sum())
                bad_any |= d
            r.update({"row_mismatches": int(bad_any.sum()), "per_column": {c: n for c, n in per.items() if n}})
        res[sp] = r
        add_check(M, f"row identity {sp}: every row == V1 v1_1/{sp}.parquet (70 features + {len(V1_META)} meta, positional)",
                  ok_sha and r["row_mismatches"] == 0,
                  f"rows {r['rows_ours']:,} vs {r['rows_v1']:,}, mismatching rows {r['row_mismatches']}, "
                  f"V1 file sha256 {'== prereg' if ok_sha else '!= prereg'}")
    return res


def identity_test(out: Path, R: dict, W: dict, M: dict) -> dict:
    """Test: keys only from V1 (no feature columns), plus 08b column hashes vs manifest_v1_1."""
    v1p = V1_DATA / "test.parquet"
    rec = R["m11"]["outputs"]["test.parquet"]
    md = pq.read_metadata(v1p)
    ok_file = md.num_rows == rec["rows"] and v1p.stat().st_size == rec["bytes"]
    A = pq.read_table(out / "test.parquet.partial", columns=TEST_KEYS).to_pandas()
    B = pq.read_table(v1p, columns=TEST_KEYS).to_pandas()            # key columns only
    r = {"v1_file": str(v1p), "v1_file_rows_bytes_ok": ok_file, "rows_ours": len(A), "rows_v1": len(B),
         "columns_read_from_v1": TEST_KEYS}
    if len(A) == len(B):
        bad = np.zeros(len(A), dtype=bool)
        per = {}
        for c in TEST_KEYS:
            d = A[c].astype(str).to_numpy() != B[c].astype(str).to_numpy()
            per[c] = int(d.sum())
            bad |= d
        r.update({"key_mismatches": int(bad.sum()), "per_column": {c: n for c, n in per.items() if n}})
    else:
        r.update({"key_mismatches": None, "per_column": {}})
    add_check(M, "test keys (session, start_ts, y, group) == V1 v1_1/test.parquet, positional (no V1 feature column read)",
              ok_file and r["key_mismatches"] == 0,
              f"rows {r['rows_ours']:,} vs {r['rows_v1']:,}, mismatching rows {r['key_mismatches']}; V1 file rows/bytes "
              f"{'== manifest_v1_1' if ok_file else '!= manifest_v1_1'}")
    h1, hd = R["m11"]["v1_test_rows_column_sha256"], R["m11"]["daytime_rows_column_sha256"]
    r["column_hash"] = {"v1_part": {"ours": W["test_hash_v1"], "v1_record": h1, "rows": W["test_rows_v1"]},
                        "daytime_part": {"ours": W["test_hash_day"], "v1_record": hd, "rows": W["test_rows_day"]}}
    add_check(M, "test rows in V1 schema: 08b column sha256 == manifest_v1_1 (V1 part, daytime part)",
              W["test_hash_v1"] == h1 and W["test_hash_day"] == hd,
              f"v1 part {W['test_hash_v1'][:16]}... {'==' if W['test_hash_v1'] == h1 else '!='} {h1[:16]}... "
              f"({W['test_rows_v1']:,} rows); daytime {W['test_hash_day'][:16]}... {'==' if W['test_hash_day'] == hd else '!='} "
              f"{hd[:16]}... ({W['test_rows_day']:,} rows)")
    return r


# --------------------------------------------------------------------------- count regression + coverage

def count_regression(R: dict, sel: dict, W: dict, M: dict) -> dict:
    m1, m11 = R["m1"], R["m11"]
    v1_pre, v1_wr = Counter(), Counter()
    for r in m1["by_split_group_label_family"]:
        k = (r["split"], r["group"], r["label"], r["family"])
        v1_pre[k] += r["before_caps"]
        v1_wr[k] += r["written"]
    day = {g["group"]: g["total"] for g in m11["by_group"]}
    for g, n in day.items():
        v1_wr[("test", g, "benign", "")] += n
        v1_pre[("test", g, "benign", "")] += n
    rows = []
    for k in sorted(set(v1_wr) | set(W["written"]) | set(sel["pre"]) | set(v1_pre)):
        rows.append({"split": k[0], "group": k[1], "label": k[2], "family": k[3],
                     "pre_ours": sel["pre"].get(k, 0), "pre_v1": v1_pre.get(k, 0),
                     "written_ours": W["written"].get(k, 0), "written_v1": v1_wr.get(k, 0)})
    for r in rows:
        r["pass"] = "PASS" if r["pre_ours"] == r["pre_v1"] and r["written_ours"] == r["written_v1"] else "FAIL"
    bad = [r for r in rows if r["pass"] != "PASS"]
    add_check(M, "per (split, group, label, family): before caps and written == V1 (manifest_v1 + v1_1 daytime)",
              not bad, f"{len(rows)} keys" if not bad else f"{len(bad)} differ, e.g. {bad[:2]}")
    tot = {sp: m11["outputs"][f"{sp}.parquet"]["rows"] for sp in SPLITS}
    add_check(M, "rows per split == manifest_v1_1 outputs", all(W["rows"][sp] == tot[sp] for sp in SPLITS),
              ", ".join(f"{sp} {W['rows'][sp]:,}/{tot[sp]:,}" for sp in SPLITS))
    return {"rows": rows, "split_totals": {sp: {"ours": W["rows"][sp], "v1_1": tot[sp]} for sp in SPLITS}}


def coverage(W: dict, names: list[str], M: dict) -> dict:
    groups = list(GROUPS.labels)
    C = W["written_cls"]
    table = {sp: {g: {n: C.get((sp, g, n), 0) for n in names} for g in groups} for sp in SPLITS}
    gaps = []
    for n in names:
        for g in groups:
            if sum(table[sp][g][n] for sp in SPLITS) == 0:
                continue                                              # never appears for this group
            miss = [sp for sp in ("train", "val") if table[sp][g][n] == 0]
            if miss:
                gaps.append({"class": n, "group": g, "missing_in": "+".join(miss),
                             **{sp: table[sp][g][n] for sp in SPLITS}})
    absent = [{"class": n, "group": g} for n in names for g in groups if sum(table[sp][g][n] for sp in SPLITS) == 0]
    add_check(M, "coverage: each class >= 1 flow in train and val for every group it appears in", not gaps,
              "ok" if not gaps else "; ".join(f"{x['class']}/{x['group']} missing in {x['missing_in']} "
                                              f"(train {x['train']}, val {x['val']}, test {x['test']})" for x in gaps),
              warn=True)
    udp = {sp: {g: table[sp][g]["udp_flood"] for g in groups} for sp in SPLITS} if "udp_flood" in names else {}
    return {"table": table, "gaps": gaps, "absent_everywhere": absent, "udp_flood": udp}


def udp_statements(udp: dict) -> list[str]:
    out = []
    for g in GROUPS.labels:
        tr, va, te = (udp[sp][g] for sp in SPLITS)
        if tr == va == te == 0:
            out.append(f"**{g} has 0 udp_flood flows in every split** (train 0, val 0, test 0).")
        elif tr == 0 and va == 0:
            out.append(f"**{g} has 0 udp_flood flows in train and val**; its {te:,} udp_flood flows are all in test.")
        elif tr == 0 or va == 0:
            out.append(f"**{g} has 0 udp_flood flows in {'train' if tr == 0 else 'val'}** (train {tr:,}, val {va:,}, test {te:,}).")
        else:
            out.append(f"{g}: train {tr:,}, val {va:,}, test {te:,} udp_flood flows.")
    return out


# --------------------------------------------------------------------------- figures + summary

def figures(fig_dir: Path, cov: dict, names: list[str], version: str) -> dict:
    import matplotlib.pyplot as plt
    PS.apply()
    made = {}
    groups = list(GROUPS.labels)
    T = cov["table"]
    # 1 class counts per split, grouped bars (log y)
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    w = 0.19
    x = np.arange(len(SPLITS))
    for i, n in enumerate(names):
        vals = [sum(T[sp][g][n] for g in groups) for sp in SPLITS]
        xs = x + (i - (len(names) - 1) / 2) * (w + 0.015)
        ax.bar(xs, [v if v > 0 else np.nan for v in vals], width=w, color=PS.class_color(i), label=n)
        for xi, v in zip(xs, vals):
            ax.annotate(f"{v:,}", (xi, max(v, 1)), xytext=(0, 2), textcoords="offset points", ha="center",
                        va="bottom", fontsize=6.5, rotation=90, color=PS.TEXT1)
    ax.set_yscale("log")
    ax.set_ylim(1, max(sum(T[sp][g][n] for g in groups) for sp in SPLITS for n in names) * 40)
    ax.set_xticks(x, list(SPLITS))
    ax.set_ylabel("flows (log scale)")
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=len(names), loc="upper center", bbox_to_anchor=(0.5, -0.1))
    ax.set_title(f"Flows per class and split ({version}, V1-equivalent caps)", loc="left")
    made["split_class_balance.png"] = PS.save(fig, fig_dir / "split_class_balance.png")
    # 2 split x group x class table
    header = ["split", "group", *names, "total"]
    cells, zero = [], []
    for sp in SPLITS:
        for g in groups:
            row = [T[sp][g][n] for n in names]
            cells.append([sp, g, *[f"{v:,}" for v in row], f"{sum(row):,}"])
            zero.append([False, False, *[v == 0 for v in row], sum(row) == 0])
    notes = [s.replace("**", "") for s in udp_statements(cov["udp_flood"]) if "**" in s]   # the zero statements
    fig = plt.figure(figsize=(6.8, 0.26 * (len(cells) + 1) + 0.55 + 0.16 * len(notes)))
    foot = (0.16 * len(notes) + 0.12) / fig.get_figheight()
    ax = fig.add_axes((0.01, foot, 0.98, 1 - foot - 0.36 / fig.get_figheight()))
    ax.axis("off")
    tb = ax.table(cellText=cells, colLabels=header, bbox=(0, 0, 1, 1), cellLoc="right", colLoc="right")
    tb.auto_set_font_size(False)
    tb.set_fontsize(8)
    for (r, c), cell in tb.get_celld().items():
        cell.set_edgecolor(PS.GRID)
        cell.set_linewidth(0.6)
        if c < 2:
            cell.set_text_props(ha="left")
            cell._loc = "left"
        if r == 0:
            cell.set_text_props(weight="bold", color=PS.TEXT1)
            cell.set_facecolor(PS.SURFACE)
        else:
            cell.set_facecolor("#efeee9" if (r - 1) // len(groups) % 2 == 0 else PS.SURFACE)
            if zero[r - 1][c]:
                cell.set_text_props(weight="bold", color=PS.TEXT1)
                cell.set_facecolor("#dddcd6")
    ax.set_title(f"Flows per split x group x class ({version})", loc="left", pad=6)
    for i, line in enumerate(["Bold, darker cells = 0 flows."] + [f"udp_flood: {s}" for s in notes]):
        fig.text(0.01, foot - 0.03 / fig.get_figheight() - i * 0.16 / fig.get_figheight(), line,
                 fontsize=7.5, color=PS.TEXT1 if i else PS.TEXT2, va="top")
    made["split_group_class_table.png"] = PS.save(fig, fig_dir / "split_group_class_table.png")
    return made


def write_summary(path: Path, M: dict) -> None:
    cov, reg = M.get("coverage") or {}, M.get("count_regression") or {}
    names = M.get("class_map", {}).get("classes", [])
    L = [f"# Step 21 -- dataset version `{M['dataset_version']}` -- {M['status']}", "",
         f"- {M['created_utc']}, git `{M['git_head'][:12]}` ({M['git_branch']}, dirty={M['git_dirty']}), {SCRIPT} sha256 "
         f"`{CODE_SHA256[:16]}...`, runtime {M.get('runtime_s', '?')} s, peak RSS {M.get('peak_rss_mb', '?')} MB"
         + (" -- **DRY RUN**" if M["dry_run"] else ""),
         f"- ingest run `{M.get('ingest', {}).get('run_id')}`, ingest_manifest sha256 "
         f"`{M.get('ingest', {}).get('ingest_manifest_sha256', '')}`",
         f"- split definition sha256 `{M.get('split_definition', {}).get('sha256', '')}` (V1's recorded cuts, reused; "
         f"V1's seeded caps, reproduced)", f"- {TEST_POLICY}", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if cov.get("udp_flood"):
        U = cov["udp_flood"]
        L += ["## !!! udp_flood coverage (decide in Phase 2)", ""] + [f"- {s}" for s in udp_statements(U)] + [""]
        L += md_table([{"split": sp, **{g: U[sp][g] for g in GROUPS.labels}, "total": sum(U[sp].values())}
                       for sp in SPLITS]) + [""]
        L += ["A G2 or GEN udp_flood flow can therefore only be learned from G1 examples (or not at all); "
              "Phase 1 does not fix this.", ""]
    if cov.get("gaps"):
        L += ["## Coverage warnings (class present for a group, but 0 flows in train and / or val)", ""]
        L += md_table(cov["gaps"]) + [""]
    hard = [c for c in M["checks"] if c["level"] == "hard"]
    fails = [c for c in hard if not c["pass"]]
    L += ["## Checks", "", f"**{'PASS' if not fails else 'FAIL'}** ({len(hard)} hard checks, {len(fails)} failed; "
          f"{sum(1 for c in M['checks'] if c['level'] == 'warn' and not c['pass'])} warnings)", ""]
    L += md_table([{"check": c["check"], "result": "PASS" if c["pass"] else ("WARN" if c["level"] == "warn" else "FAIL"),
                    "detail": c["detail"]} for c in M["checks"] if not c["check"].startswith(("lock: v1:", "ingest parquet"))]) + [""]
    if cov.get("table"):
        L += ["## Flows per split x group x class", ""]
        L += md_table([{"split": sp, "group": g, **cov["table"][sp][g], "total": sum(cov["table"][sp][g].values())}
                       for sp in SPLITS for g in GROUPS.labels]) + [""]
        L += md_table([{"split": sp, **{n: sum(cov["table"][sp][g][n] for g in GROUPS.labels) for n in names},
                        "total": sum(sum(cov["table"][sp][g].values()) for g in GROUPS.labels)} for sp in SPLITS]) + [""]
    RI = M.get("row_identity") or {}
    if RI:
        L += ["## Row-level identity vs V1", ""]
        rows = [{"split": sp, "rows_ours": RI[sp]["rows_ours"], "rows_v1": RI[sp]["rows_v1"],
                 "mismatching_rows": RI[sp].get("row_mismatches", RI[sp].get("key_mismatches")),
                 "compared": "70 features + " + ", ".join(V1_META) if sp != "test" else ", ".join(TEST_KEYS) + " (keys only)"}
                for sp in SPLITS if sp in RI]
        L += md_table(rows) + [""]
        if "test" in RI:
            ch = RI["test"]["column_hash"]
            L += [f"- test, full content in V1's schema (08b ColumnHasher, nothing read from V1's test file): V1 part "
                  f"`{ch['v1_part']['ours'][:16]}...` vs record `{ch['v1_part']['v1_record'][:16]}...` "
                  f"({ch['v1_part']['rows']:,} rows); daytime `{ch['daytime_part']['ours'][:16]}...` vs record "
                  f"`{ch['daytime_part']['v1_record'][:16]}...` ({ch['daytime_part']['rows']:,} rows)", ""]
    if reg.get("rows"):
        L += ["## Counts vs V1 (before caps, written)", ""]
        L += md_table(reg["rows"]) + [""]
    if M.get("caps"):
        L += ["## Caps (08's sampler, reproduced; == manifest_v1 cap_keys)", ""]
        L += md_table([{"cap_key": k, **v} for k, v in sorted(M["caps"].items()) if v["p"] < 1]) + [""]
        L += [f"({sum(1 for v in M['caps'].values() if v['p'] >= 1)} more cap keys under their cap, p = 1)", ""]
    if M.get("files"):
        L += ["## Files", "", f"- dir `{M['dataset_dir']}`", ""]
        L += md_table([{"split": sp, **{k: v for k, v in f.items() if k != "path"}} for sp, f in M["files"].items()]) + [""]
        L += [f"- index line appended to `{M.get('index_path')}`", f"- figures: {', '.join(M.get('figures', {}))}", ""]
    path.write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- main

def run(args, M: dict, part: Path, t0: float) -> bool:
    log("inputs:")
    R = check_inputs(M, args.ingest_run)
    cm = S.load_class_map()
    M["class_map"] = {"sha256": cm.sha256, "version": cm.version, "classes": list(cm.names)}
    M["features"] = {"file_sha256": S.FEATURES_V1_SHA256, "list_sha256": S.FEATURES_V1_LIST_SHA256, "n": 70}
    M["v2_code_sha256"] = {f: sha256_file(REPO_ROOT / f) for f in V2_CODE}
    if not all(c["pass"] for c in M["checks"]):
        return False
    log("split definition (V1's recorded cuts):")
    D = split_definition(M, R)
    D_sha = canon_sha256(D)
    write_json(part / "split_definition.json", {**D, "sha256_of": "canonical JSON (sort_keys, no spaces) of this "
                                                "object without sha256 / sha256_of", "sha256": D_sha})
    M["split_definition"] = {"path": "split_definition.json", "sha256": D_sha, "sources": D["sources"],
                             "sessions": {k: v["mode"] for k, v in D["sessions"].items()}}
    log("selection (08 assign / cap_keys / seeded draws):")
    sel = select(R, D, M, t0)
    M["caps"] = sel["probs"]
    if not all(c["pass"] for c in M["checks"]):
        return False
    log("write splits:")
    W = write_splits(R, sel, part, M, t0)
    log("count regression + coverage:")
    M["count_regression"] = count_regression(R, sel, W, M)
    cov = coverage(W, list(cm.names), M)
    M["coverage"] = cov
    M["counts"] = {sp: {g: cov["table"][sp][g] for g in GROUPS.labels} for sp in SPLITS}
    log("row-level identity vs V1:")
    M["row_identity"] = {**identity_train_val(part, R, M), "test": identity_test(part, R, W, M)}
    return all(c["pass"] for c in M["checks"] if c["level"] == "hard")


def main() -> int:
    global _LOG
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ingest-run", required=True, help="run id of a PASS 20_ingest_csv.py run")
    ap.add_argument("--version", default=DEFAULT_VERSION)
    ap.add_argument("--dry-run", action="store_true", help="outputs under datasets_dry_run/ and results/21/dry_run/")
    args = ap.parse_args()
    t0 = time.monotonic()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.version):
        fatal(f"--version {args.version!r}: letters, digits, _ . - only")
    root = DATASETS_DRY_ROOT if args.dry_run else DATASETS_ROOT
    final, part = root / args.version, root / f".{args.version}.partial"
    res = RESULTS_OUT / "dry_run" / args.version if args.dry_run else RESULTS_OUT
    index = root / "index.jsonl"
    targets = [final, part] + [res / x for x in ("run_meta.json", "run.log", "summary.md", "dataset_manifest.json", "figures")]
    existing = [str(p) for p in targets if p.exists()]
    if existing:
        fatal(f"refusing: {existing} already exist (a dataset version is immutable; results are never overwritten)")
    if index.is_file() and any(json.loads(line).get("dataset_version") == args.version
                               for line in index.read_text(encoding="utf-8").splitlines() if line.strip()):
        fatal(f"refusing: {args.version} is already in {index}")
    lock = run_lock(root)
    res.mkdir(parents=True, exist_ok=True)
    _LOG = open(res / "run.log", "x", encoding="utf-8")
    part.mkdir()
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...  version {args.version}  -> {final}")
    M = {"manifest_version": 1, "dataset_version": args.version, "created_utc": now_utc(), "status": "RUNNING",
         "dry_run": args.dry_run, "script": SCRIPT, "code_sha256": CODE_SHA256, "argv": [SCRIPT, *sys.argv[1:]],
         "git_head": git("rev-parse", "HEAD"), "git_branch": git("branch", "--show-current"),
         "git_dirty": bool(git("status", "--porcelain")), "test_policy": TEST_POLICY, "checks": [],
         "v1_code": {"08_build_datasets.py": sha256_file(REPO_ROOT / "08_build_datasets.py"),
                     "08b_extend_test.py": sha256_file(REPO_ROOT / "08b_extend_test.py"),
                     "used": ["08.assign", "08.cap_keys", "08.cap_of", "08.stable_hash", "08.SPLITS", "08.OUT_META",
                              "08b.ColumnHasher"]}}
    code = 0
    try:
        ok = run(args, M, part, t0)
    except (CheckFailed, V1Fatal, S.SchemaError) as e:
        ok, code = False, 1
        M["error"] = "".join(traceback.format_exception(e))
        log(f"CHECK FAILURE: {e}")
    except Exception as e:                                             # noqa: BLE001
        ok, code = False, 2
        M["error"] = "".join(traceback.format_exception(e))
        log(f"ERROR: {e!r}")
    M["status"] = "PASS" if ok else "FAIL"
    M["runtime_s"], M["peak_rss_mb"] = round(time.monotonic() - t0, 1), m08.peak_rss_mb()
    M["figures"] = {}
    if ok:
        M["files"] = {}
        for sp in SPLITS:
            p = part / f"{sp}.parquet.partial"
            h = m08b.ColumnHasher(pq.read_schema(p).names)
            for b in pq.ParquetFile(p).iter_batches(batch_size=500_000):
                h.update(b)
            os.replace(p, part / f"{sp}.parquet")
            q = part / f"{sp}.parquet"
            M["files"][sp] = {"path": str(final / q.name), "rows": h.rows, "bytes": q.stat().st_size,
                              "file_sha256": sha256_file(q), "content_sha256": h.digest()}
        M["content_sha256_of"] = "08b ColumnHasher: sha256 per column over the rows (strings NUL-joined, numbers raw), sha256 of the concatenated column digests"
        M["dataset_dir"] = str(final)
        M["index_path"] = str(index)
        M["figures"] = {k: str(Path(v).relative_to(REPO_ROOT)) for k, v in
                        figures(res / "figures", M["coverage"], M["class_map"]["classes"], args.version).items()}
        man_sha = write_json(part / "dataset_manifest.json", M)
        part.rename(final)
        line = {"dataset_version": args.version, "created_utc": M["created_utc"], "path": str(final),
                "dataset_manifest_sha256": man_sha, "split_definition_sha256": M["split_definition"]["sha256"],
                "ingest_run_id": M["ingest"]["run_id"], "ingest_manifest_sha256": M["ingest"]["ingest_manifest_sha256"],
                "class_map_sha256": M["class_map"]["sha256"], "git_head": M["git_head"], "git_dirty": M["git_dirty"],
                "rows": {sp: f["rows"] for sp, f in M["files"].items()}}
        with open(index, "a", encoding="utf-8") as fh:                  # append-only log
            fh.write(json.dumps(line, sort_keys=True) + "\n")
        shutil.copyfile(final / "dataset_manifest.json", res / "dataset_manifest.json")
    else:
        for p in part.iterdir():                                        # this run's own partial files only
            p.unlink()
        part.rmdir()
        man_sha = write_json(res / "dataset_manifest.json", M)
        log("FAIL: version directory not created, no index line; report only")
    write_summary(res / "summary.md", M)
    meta = {"script": SCRIPT, "code_sha256": CODE_SHA256, "run_utc": M["created_utc"], "argv": M["argv"],
            "git_head": M["git_head"], "git_branch": M["git_branch"], "git_dirty": M["git_dirty"],
            "dataset_version": args.version, "status": M["status"], "dry_run": args.dry_run,
            "dataset_dir": str(final) if ok else None, "dataset_manifest_sha256": man_sha,
            "ingest_run_id": (M.get("ingest") or {}).get("run_id"),
            "ingest_manifest_sha256": (M.get("ingest") or {}).get("ingest_manifest_sha256"),
            "split_definition_sha256": (M.get("split_definition") or {}).get("sha256"),
            "checks": M["checks"], "figures": M["figures"], "test_policy": TEST_POLICY,
            "runtime_s": M["runtime_s"], "peak_rss_mb": M["peak_rss_mb"]}
    write_json(res / "run_meta.json", meta)
    log(f"{M['status']}  -> {final if ok else '(not created)'}  |  {res}  ({M['runtime_s']} s, peak RSS {M['peak_rss_mb']} MB)")
    _LOG.close()
    lock.close()
    return code or (0 if ok else 1)


if __name__ == "__main__":
    sys.exit(main())
