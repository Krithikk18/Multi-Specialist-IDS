#!/usr/bin/env python
"""20_ingest_csv.py -- V2 Phase 1 ingest: V1's labelled CICFlowMeter flow tables -> validated, class-encoded
per-session parquet files, with a regression check against V1's own records.

Inputs (never modified), source v1_cicflowmeter = V1's flow tables, one session per file, in V1's order:
  the 8 sessions of config/split_plan.json via 08_build_datasets.load_sources (benign_night =
  data/interim/flows/benign/benign_flows_tagged.csv, the 7 attack stems = 07's <stem>_labelled.csv.gz), then
  BenignTraffic1-3 via 08b_extend_test.load_sessions (08b's extractor-sidecar and 07-report checks).
  Every input file's sha256 must equal its record in results/step8/manifest_v1.json or
  results/step8b/manifest_v1_1.json, and those manifests (and every other V1 input) their step10_prereg pin.
  benign_night has no label columns: it is ingested only with --assume-label benign_night=benign (recorded);
  a declaration for a file that has label columns, or a label-less file without one, fails.

Per chunk (08's iter_chunks: features float64 -- any non-numeric value is a parse error --, other columns
strings, "" kept), in this order:
  1 schema   common.schemas.validate_schema on the RAW chunk (all rows, before any filter): columns /
             order / extras (from the file header), dtypes, Timestamp parsing (explicit format, tz=UTC,
             justification: extractor TZ=UTC lock), raw label vocabulary (07's invariants)
  2 filter   V1's own filter, imported (never copied): 08.usable for the 8 V1 sessions, 08b.usable_day
             (08's filter + the unregistered-MAC -> GEN rule) for BenignTraffic1-3. Rejected rows are
             counted per reason (not_owned, exclude_reason, label_excluded, ungrouped); device, category
             and group come from the filter (device_table via owner MAC, V1 lock v1.0)
  3 rows     common.schemas.validate_rows on the kept rows: identity non-null (device MAC column =
             the filter's MAC), blank src/dst MAC only for off-LAN endpoints (counted per reason:
             public / broadcast / multicast / off_lan_private), labels encode, NaN / +-inf counted
  4 encode   encode_labels -> label_id, label_name; y = to_binary(label_id); per row: y == V1's binary
             label (08: label == "attack"; 08b: every daytime row y = 0) and the parsed Timestamp ==
             08.flow_start (epoch s)
  5 write    features cleaned by V1's policy (NaN / +-inf -> 0), metadata, row_in_file; rows stay in file
             order (21 reproduces 08's seeded caps, whose RNG streams follow plan order then file order)
Test-session rows are read, validated and COUNTED only (incl. NaN / inf counts): no feature-value
statistics are computed on any row here.

Regression (must pass; skipped with --limit-rows, partly with --sessions):
  per V1 session   rows, not_owned, exclude_reason, label_excluded, ungrouped, owner_device_name_mismatch
                   == manifest_v1 filter_drops; kept rows == train + val + test + gap_dropped (pre-cap usable)
  per daytime      rows, label_attack, not_owned, exclude_reason, label_excluded, ungrouped,
                   unregistered_mac_kept, owner_device_name_mismatch, added == manifest_v1_1 sessions;
                   kept rows per group == manifest_v1_1 by_group
  all V1 sessions  kept rows per (label, family) == sum over splits / groups of manifest_v1 before_caps
                   + gap drops; per (group, label, family) where that (label, family) had no gap drops
  every row        y == V1's binary label; parsed Timestamp == 08.flow_start
Any failure: exit 1, the parquet files are removed and only ingest_manifest.json (status FAIL) remains.

Outputs
  ~/lgids_cache/v2/ingest/<run_id>/flows/<session>.parquet   70 features (features_v1 order, float64,
        cleaned) + Flow ID, Src IP, Src Port, Dst IP, Dst Port (strings as extracted), Timestamp
        (timestamp[s, UTC]), start_ts (int64 epoch s), src_mac, dst_mac, owner_mac (raw), device_mac,
        device, device_category, group, session, row_in_file (int64, 0-based data row of the file),
        attack_family (raw), label_id (int8), label_name, y (int8)
  ~/lgids_cache/v2/ingest/<run_id>/ingest_manifest.json      hashes, counts, rejects, validation, regression
  results/20/  run_meta.json, run.log, summary.md, ingest_manifest.json (copy), figures/{class_counts,
        group_class_heatmap, validation_issues}.png (counts only; "all sessions, pre-split")
  --dry-run: ~/lgids_cache/v2/ingest_dry_run/<run_id>/ and results/20/dry_run/<run_id>/
Refuses to start if any target path exists. One run at a time: flock on <cache root>/.20_ingest.lock.

Exit status: 0 ok, 1 refused / validation or regression failed, 2 unexpected exception.
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
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from config.config import ATTACK_FLOWS_DIR, CACHE_DIR, CONFIG_DIR, DEVICE_TABLE, GROUPS, REPO_ROOT, RESULTS_DIR, sha256_file
from common import plot_style as PS
from common import schemas as S


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m08b = _load("extend_test", "08b_extend_test.py")
m08 = m08b.m08                                   # the one 08 module instance 08b itself uses

SCRIPT = "20_ingest_csv.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
SOURCES = ("v1_cicflowmeter",)
INGEST_ROOT = CACHE_DIR / "v2" / "ingest"
INGEST_DRY_ROOT = CACHE_DIR / "v2" / "ingest_dry_run"
RESULTS_OUT = RESULTS_DIR / "20"
MANIFEST_V1 = RESULTS_DIR / "step8" / "manifest_v1.json"
MANIFEST_V11 = RESULTS_DIR / "step8b" / "manifest_v1_1.json"
PREREG = CONFIG_DIR / "step10_prereg.json"
RUN_LOCK = ".20_ingest.lock"
EPOCH = pd.Timestamp(0, tz="UTC")
IDENT_OUT = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port"]
REJECT_REASONS = ("not_owned", "exclude_reason", "label_excluded", "ungrouped")
FIG_TAG = "all sessions, pre-split"
TEST_ROWS_POLICY = ("test-session rows are read, schema-validated and counted (incl. NaN / inf counts); "
                    "no feature-value statistics (means, distributions, correlations, histograms)")

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
    """Refusal before anything is written (existing target paths, lock held)."""
    print(f"FATAL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


class V1Fatal(RuntimeError):
    """A V1 helper (08 / 08b) refused: raised instead of its sys.exit so the FAIL report gets written."""


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
    """Write once (refuses to overwrite); returns the file's sha256."""
    data = (json.dumps(obj, indent=1, default=str) + "\n").encode("utf-8")
    with open(p, "xb") as fh:
        fh.write(data)
    return hashlib.sha256(data).hexdigest()


def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.20_ingest.lock for the whole run (V1 08 / 13c pattern)."""
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


def md_table(rows: list[dict], cols: list[str] | None = None) -> list[str]:
    if not rows:
        return ["(none)"]
    cols = cols or list(rows[0])
    fmt = lambda v: f"{v:,}" if isinstance(v, (int, np.integer)) and not isinstance(v, bool) else str(v)  # noqa: E731
    return (["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
            + ["| " + " | ".join(fmt(r.get(c, "")) for c in cols) + " |" for r in rows])


# --------------------------------------------------------------------------- inputs

def check_v1_frozen(M: dict) -> None:
    """Every V1 file the step 10 prereg pins (incl. both dataset manifests) is unchanged."""
    P = read_json(PREREG)
    for rel, want in P["inputs_sha256"].items():
        p = REPO_ROOT / rel
        got = sha256_file(p) if p.is_file() else None
        add_check(M, f"V1 frozen: {rel} sha256 == step10_prereg", got == want,
                  f"{(got or 'missing')[:16]}... vs {want[:16]}...")
    m1 = read_json(MANIFEST_V1)
    add_check(M, "V1 frozen: device_table.csv sha256 == manifest_v1", sha256_file(DEVICE_TABLE)
              == m1["config"]["device_table"]["sha256"], m1["config"]["device_table"]["sha256"][:16] + "...")


def add_check(M: dict, name: str, ok: bool, detail: str = "") -> bool:
    M["checks"].append({"check": name, "pass": bool(ok), "detail": detail})
    log(f"  {'PASS' if ok else 'FAIL'}  {name}  {detail}")
    return bool(ok)


def resolve_sessions(args, M: dict, feats: list[str], dropped_const: list[str]) -> list[dict]:
    """V1's sessions in V1's order, via V1's loaders, with declarations and input hashes checked."""
    aset = read_json(m08.ATTACK_SET)
    P = m08.load_plan(m08.SPLIT_PLAN, aset)
    v1src = m08.load_sources(P, aset, ATTACK_FLOWS_DIR)
    dev_sha = sha256_file(DEVICE_TABLE)
    ref_header = m08.read_header(m08.BENIGN_TAGGED)
    day_checks: dict = {}
    day = m08b.load_sessions(list(m08b.DAY_SESSIONS), m08b.DAY_FLOWS_DIR, m08b.DAY_LABELS, dev_sha, ref_header,
                             day_checks)
    for k, v in day_checks.items():
        add_check(M, f"08b: {k}", v["pass"], v["detail"])
    m1, m11 = read_json(MANIFEST_V1), read_json(MANIFEST_V11)
    rec1 = {r["session"]: r for r in m1["inputs"]}
    rec11 = {r["session"]: r for r in m11["inputs"]}
    sessions = []
    for s in v1src:
        sessions.append({"session": s["session"], "kind": s["kind"], "family": s["family"], "path": Path(s["path"]),
                         "src": s, "filter": "08_build_datasets.usable", "v1_set": "v1",
                         "expected_sha256": rec1[s["session"]]["sha256"], "expected_from": str(MANIFEST_V1.relative_to(REPO_ROOT))})
    for d in day:
        sessions.append({"session": d["session"], "kind": "daytime", "family": "", "path": Path(d["path"]),
                         "src": None, "filter": "08b_extend_test.usable_day", "v1_set": "v1_1",
                         "expected_sha256": rec11[d["session"]]["sha256"],
                         "expected_from": str(MANIFEST_V11.relative_to(REPO_ROOT)), "sha256_08b": d["input"]["sha256"]})
    M["source_order"] = [s["session"] for s in sessions]
    if args.sessions:
        want = args.sessions.split(",")
        unknown = [w for w in want if w not in M["source_order"]]
        if unknown:
            raise S.SchemaError(f"--sessions: unknown {unknown}; known {M['source_order']}")
        sessions = [s for s in sessions if s["session"] in want]
    # headers: 08's own consistency check, then features_v1 == 08's candidates minus the train-constant ones
    headers = {s["session"]: m08.read_header(s["path"]) for s in sessions}
    cand = m08.candidate_features({m08.BENIGN_SESSION: ref_header, **headers})
    add_check(M, "features_v1 == 08 candidate features minus dropped_constant_in_train",
              [c for c in cand if c not in dropped_const] == feats, f"{len(cand)} candidates, {len(feats)} features")
    # per-input label declarations
    decl = {}
    for item in args.assume_label or []:
        if "=" not in item:
            raise S.SchemaError(f"--assume-label {item!r}: expected SESSION=LABEL")
        k, v = item.split("=", 1)
        decl[k] = v
    unknown = [k for k in decl if k not in headers]
    if unknown:
        raise S.SchemaError(f"--assume-label for sessions not being ingested: {unknown}")
    M["declarations"] = {}
    for s in sessions:
        h = headers[s["session"]]
        has_label = all(c in h for c in S.LABEL_COLS)
        a = decl.get(s["session"])
        if not has_label and a is None:
            raise S.SchemaError(f"{s['session']}: no label columns and no --assume-label {s['session']}=<label>; "
                                "a label-less file is never defaulted silently")
        if has_label and a is not None:
            raise S.SchemaError(f"{s['session']}: --assume-label declared but the file has label columns")
        if a is not None:
            if a not in S.load_class_map().aliases[args.source]:
                raise S.SchemaError(f"--assume-label {s['session']}={a}: {a!r} is not an alias key of {args.source}")
            M["declarations"][s["session"]] = {
                "assume_label": a, "attack_family": "", "declared_by": f"--assume-label {s['session']}={a}",
                "reason": "file has no label / attack_family columns (04 tagged capture, no 07 labelling); V1's 08 "
                          "treats every row of it as benign (src kind 'benign')",
                "v1_kind": s["kind"]}
            if s["kind"] != "benign" or a != "benign":
                raise S.SchemaError(f"{s['session']}: declaration {a!r} contradicts V1's kind {s['kind']!r}")
        s["header"], s["assume_label"] = h, a
    # input hashes vs V1's manifests
    M["inputs"] = []
    for s in sessions:
        got = s.get("sha256_08b") or sha256_file(s["path"])
        ok = got == s["expected_sha256"]
        M["inputs"].append({"session": s["session"], "kind": s["kind"], "family": s["family"], "path": str(s["path"]),
                            "sha256": got, "sha256_expected": s["expected_sha256"], "expected_from": s["expected_from"],
                            "match": ok, "filter": s["filter"], "assume_label": s["assume_label"]})
        add_check(M, f"input sha256 == V1 record: {s['session']}", ok, f"{got[:16]}...")
        s["sha256"] = got
    return sessions


# --------------------------------------------------------------------------- per session

def out_schema(feats: list[str], meta: dict) -> pa.Schema:
    fields = [(c, pa.float64()) for c in feats] + [(c, pa.string()) for c in IDENT_OUT] + [
        ("Timestamp", pa.timestamp("s", tz="UTC")), ("start_ts", pa.int64()),
        ("src_mac", pa.string()), ("dst_mac", pa.string()), ("owner_mac", pa.string()), ("device_mac", pa.string()),
        ("device", pa.string()), ("device_category", pa.string()), ("group", pa.string()), ("session", pa.string()),
        ("row_in_file", pa.int64()), ("attack_family", pa.string()), ("label_id", pa.int8()),
        ("label_name", pa.string()), ("y", pa.int8())]
    return pa.schema(fields, metadata={k.encode(): str(v).encode() for k, v in meta.items()})


def strs(x) -> np.ndarray:
    return np.asarray(pd.Series(x).astype(object).where(pd.Series(x).notna(), "").astype(str).to_numpy(object))


def process_session(s: dict, args, cm: S.ClassMap, feats: list[str], schema: pa.Schema, flows_dir: Path,
                    t0: float) -> dict:
    sess, kind, assume = s["session"], s["kind"], s["assume_label"]
    want = set(S.ID_COLS + S.MAC_COLS + S.V1_META_COLS + feats
               + (S.LABEL_COLS if assume is None else []) + (m08b.SIDE_COLS if kind == "daytime" else []))
    cols = [c for c in s["header"] if c in want]
    D, U_mac = Counter(), defaultdict(Counter)
    R = {"session": sess, "kind": kind, "filter": s["filter"], "rows_in": 0, "rows_out": 0, "failure": None,
         "binary_mismatch": 0, "timestamp_mismatch": 0, "class_counts": Counter(), "group_class": Counter(),
         "v1_label_family": Counter(), "v1_group_label_family": Counter(), "group_counts": Counter()}
    sreps, rreps, W = [], [], None
    path = flows_dir / f"{sess}.parquet"
    names = cm.names
    try:
        for off, f in m08.iter_chunks(s["path"], cols, feats, args.chunk, args.block_mb, args.limit_rows):
            R["rows_in"] += len(f)
            sr = S.validate_schema(f, args.source, assume, columns=s["header"] + [S.SESSION_COL])
            sreps.append(sr)
            if not sr["ok"]:
                R["failure"] = "schema stage: " + "; ".join(c["check"] + ": " + c["detail"] for c in sr["checks"] if not c["pass"])
                break
            if kind == "daytime":
                t, pos, U = m08b.usable_day(f, m08b_dev, D, U_mac)
                v1y = np.zeros(len(pos), np.int8)                        # 08b writes y = 0 for every daytime row
                v1lab = np.full(len(pos), "benign", dtype=object)
            else:
                t, pos, U = m08.usable(f, s["src"], m08b_dev, D)
                v1lab = U["label"].to_numpy(object)
                v1y = (v1lab == "attack").astype(np.int8)               # 08: y == (label == "attack")
            kept = f.iloc[pos].reset_index(drop=True)
            kept[S.SESSION_COL] = sess
            kept["device_mac"] = U["mac"].to_numpy(object)
            rr = S.validate_rows(kept, args.source, assume, cm, args.lan_subnets, owner_col="device_mac")
            rreps.append(rr)
            if not rr["ok"]:
                R["failure"] = "row stage: " + "; ".join(c["check"] + ": " + c["detail"] for c in rr["checks"] if not c["pass"])
                break
            lab, fam = S.labels_for(kept, assume)
            ids = S.encode_labels(lab, fam, args.source, cm).to_numpy(np.int8)
            y = S.to_binary(ids, cm)
            R["binary_mismatch"] += int((y != v1y).sum())
            ts = S.parse_timestamps(kept["Timestamp"])
            epoch = ((ts - EPOCH) // pd.Timedelta(seconds=1)).to_numpy(np.int64)
            tk = t[pos].astype(np.int64)
            R["timestamp_mismatch"] += int((epoch != tk).sum())
            X = S.apply_nan_inf_policy(kept[feats], feats).to_numpy(np.float64)
            n = len(kept)
            famv = strs(fam)
            lname = np.array(names, dtype=object)[ids] if n else np.array([], dtype=object)
            grp, dev, cat = (U[c].to_numpy(object) for c in ("group", "device", "category"))
            out = {c: X[:, j] for j, c in enumerate(feats)}
            out.update({c: strs(kept[c]) for c in IDENT_OUT})
            out.update({"Timestamp": pa.array(epoch, type=pa.timestamp("s", tz="UTC")), "start_ts": tk,
                        "src_mac": strs(kept["src_mac"]), "dst_mac": strs(kept["dst_mac"]),
                        "owner_mac": strs(kept["owner_mac"]), "device_mac": strs(U["mac"]),
                        "device": strs(dev), "device_category": strs(cat), "group": strs(grp),
                        "session": np.full(n, sess, dtype=object), "row_in_file": (off + pos).astype(np.int64),
                        "attack_family": famv, "label_id": ids, "label_name": lname, "y": y})
            tab = pa.Table.from_pydict(out, schema=schema)
            if W is None:
                W = pq.ParquetWriter(path, schema, compression="zstd")
            W.write_table(tab, row_group_size=1 << 20)
            R["rows_out"] += n
            R["class_counts"].update(lname.tolist())
            R["group_class"].update(zip(grp.tolist(), lname.tolist()))
            R["group_counts"].update(grp.tolist())
            R["v1_label_family"].update(zip(v1lab.tolist(), famv.tolist()))
            R["v1_group_label_family"].update(zip(grp.tolist(), v1lab.tolist(), famv.tolist()))
            log(f"  [{sess}] rows {off + len(f):>11,}  kept {R['rows_out']:>11,}  {time.monotonic() - t0:7.1f} s")
    except pa.ArrowInvalid as e:
        R["failure"] = f"CSV parse / dtype (08 iter_chunks, features float64): {e}"
    except V1Fatal as e:
        R["failure"] = f"V1 filter refused: {e}"
    except S.SchemaError as e:
        R["failure"] = f"schema error: {e}"
    if W is None and R["failure"] is None:
        pq.write_table(schema.empty_table(), path, compression="zstd")
    elif W is not None:
        W.close()
    R["schema"] = S.merge_reports(sreps) if sreps else None
    R["rows"] = S.merge_reports(rreps) if rreps else None
    D = dict(D)
    R["filter_counters"] = D
    unreg = D.get("unregistered_mac_kept", 0)
    R["rejected"] = {"not_owned": D.get("not_owned", 0) - unreg, "exclude_reason": D.get("exclude_reason", 0),
                     "label_excluded": D.get("label_excluded", 0), "ungrouped": D.get("ungrouped", 0)}
    R["kept_by_rule"] = {"unregistered_mac_kept_as_GEN (08b)": unreg} if kind == "daytime" else {}
    R["accounting_ok"] = R["failure"] is not None or R["rows_in"] == R["rows_out"] + sum(R["rejected"].values())
    if R["failure"] is None:
        R["parquet"] = {"path": str(path), "rows": pq.read_metadata(path).num_rows, "bytes": path.stat().st_size}
    return R


# --------------------------------------------------------------------------- regression

def regression(results: dict, sessions: list[dict], args) -> dict:
    """Compare against V1's records. Returns {"status", "rows": [...], "aggregate": [...]}."""
    G = {"status": "PASS", "rows": [], "aggregate": [], "note": ""}

    def cmp(sess, field, ours, v1, where):
        ok = ours == v1
        G["rows"].append({"session": sess, "field": field, "ours": ours, "v1": v1, "v1_record": where,
                          "pass": "PASS" if ok else "FAIL"})
        if not ok:
            G["status"] = "FAIL"

    for sess, R in results.items():                                  # row-level checks always apply
        cmp(sess, "rows: y != V1 binary label", R["binary_mismatch"], 0, "08 label == attack / 08b y = 0")
        cmp(sess, "rows: Timestamp != 08.flow_start", R["timestamp_mismatch"], 0, "08.flow_start")
        cmp(sess, "accounting: rows_in == kept + rejected", R["accounting_ok"], True, "this run")
    if args.limit_rows is not None:
        G["note"] = "--limit-rows: count regression vs V1 manifests skipped (row-level checks above still apply)"
        G["status"] = G["status"] if G["status"] == "FAIL" else "PASS (row-level only; --limit-rows)"
        return G
    m1, m11 = read_json(MANIFEST_V1), read_json(MANIFEST_V11)
    ses1 = {r["session"]: r for r in m1["sessions"]}
    ses11 = {r["session"]: r for r in m11["sessions"]}
    rel1 = str(MANIFEST_V1.relative_to(REPO_ROOT))
    rel11 = str(MANIFEST_V11.relative_to(REPO_ROOT))
    for s in sessions:
        sess, R = s["session"], results[s["session"]]
        D = R["filter_counters"]
        if s["v1_set"] == "v1":
            fd, sr = m1["filter_drops"][sess], ses1[sess]
            for k in ("rows", "not_owned", "exclude_reason", "label_excluded", "ungrouped", "owner_device_name_mismatch"):
                cmp(sess, k, D.get(k, 0), fd[k], f"{rel1} filter_drops")
            cmp(sess, "kept (pre-cap usable)", R["rows_out"],
                sr["train"] + sr["val"] + sr["test"] + sr["gap_dropped"], f"{rel1} sessions train+val+test+gap_dropped")
        else:
            sr = ses11[sess]
            for k in ("rows", "label_attack", "not_owned", "exclude_reason", "label_excluded", "ungrouped",
                      "unregistered_mac_kept", "owner_device_name_mismatch"):
                cmp(sess, k, D.get(k, 0), sr[k], f"{rel11} sessions")
            cmp(sess, "kept", R["rows_out"], sr["added"], f"{rel11} sessions added")
            for g in m11["by_group"]:
                cmp(sess, f"kept group {g['group']}", R["group_counts"].get(g["group"], 0), g.get(sess, 0),
                    f"{rel11} by_group")
    v1_sessions = [s["session"] for s in sessions if s["v1_set"] == "v1"]
    if set(v1_sessions) != {r["session"] for r in m1["sessions"]}:
        G["note"] = "--sessions: aggregate checks over all V1 sessions skipped"
        return G
    ours_lf, ours_glf = Counter(), Counter()
    for sess in v1_sessions:
        ours_lf.update(results[sess]["v1_label_family"])
        ours_glf.update(results[sess]["v1_group_label_family"])
    v1_lf, v1_glf, gap_lf = Counter(), Counter(), Counter()
    for r in m1["by_split_group_label_family"]:
        v1_lf[(r["label"], r["family"])] += r["before_caps"]
        v1_glf[(r["group"], r["label"], r["family"])] += r["before_caps"]
    for r in m1["gap_drops"]:
        gap_lf[(r["label"], r["family"])] += r["n"]
    for key in sorted(set(ours_lf) | set(v1_lf)):
        ok = ours_lf[key] == v1_lf[key] + gap_lf[key]
        G["aggregate"].append({"key": "/".join(key) if key[1] else key[0], "ours": ours_lf[key],
                               "v1_before_caps": v1_lf[key], "v1_gap_drops": gap_lf[key],
                               "pass": "PASS" if ok else "FAIL"})
        G["status"] = G["status"] if ok else "FAIL"
    for key in sorted(set(ours_glf) | set(v1_glf)):
        if gap_lf[(key[1], key[2])]:
            continue                                                  # gap drops carry no group
        ok = ours_glf[key] == v1_glf[key]
        G["aggregate"].append({"key": "/".join(k for k in key if k), "ours": ours_glf[key],
                               "v1_before_caps": v1_glf[key], "v1_gap_drops": 0, "pass": "PASS" if ok else "FAIL"})
        G["status"] = G["status"] if ok else "FAIL"
    return G


# --------------------------------------------------------------------------- figures + summary

def figures(fig_dir: Path, cm: S.ClassMap, totals: dict) -> dict:
    import matplotlib.pyplot as plt
    from matplotlib.colors import LogNorm
    from matplotlib.ticker import FuncFormatter
    PS.apply()
    made = {}
    names = list(cm.names)
    # 1 flows per class
    counts = [totals["class_counts"].get(n, 0) for n in names]
    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    bars = ax.bar(names, [max(c, 0) for c in counts], color=[PS.class_color(i) for i in range(len(names))],
                  width=0.62, edgecolor=PS.SURFACE, linewidth=2)
    ax.set_yscale("log")
    ax.set_ylabel("flows (log scale)")
    ax.set_title(f"Flows per class ({FIG_TAG})", loc="left")
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    for b, c in zip(bars, counts):
        ax.annotate(f"{c:,}", (b.get_x() + b.get_width() / 2, max(c, 1)), ha="center", va="bottom",
                    xytext=(0, 2), textcoords="offset points", fontsize=8, color=PS.TEXT1)
    ax.set_ylim(top=max(counts) * 6 if max(counts) else 10)
    made["class_counts.png"] = PS.save(fig, fig_dir / "class_counts.png")
    # 2 group x class heatmap
    groups = list(GROUPS.labels)
    mat = np.array([[totals["group_class"].get((g, n), 0) for n in names] for g in groups], dtype=float)
    fig, ax = plt.subplots(figsize=(5.4, 2.6))
    masked = np.ma.masked_where(mat <= 0, mat)
    cmap = plt.get_cmap(PS.SEQUENTIAL_CMAP).copy()
    cmap.set_bad(PS.SURFACE)
    im = ax.imshow(masked, cmap=cmap, norm=LogNorm(vmin=1, vmax=max(mat.max(), 10)), aspect="auto")
    ax.set_xticks(range(len(names)), names)
    ax.set_yticks(range(len(groups)), groups)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    for i in range(len(groups)):
        for j in range(len(names)):
            v = int(mat[i, j])
            dark = v > 0 and np.log10(v) > 0.6 * np.log10(max(mat.max(), 10))
            ax.text(j, i, f"{v:,}" if v else "0", ha="center", va="center", fontsize=8,
                    color="#ffffff" if dark else (PS.TEXT2 if v == 0 else PS.TEXT1))
    ax.set_xticks(np.arange(-.5, len(names)), minor=True)
    ax.set_yticks(np.arange(-.5, len(groups)), minor=True)
    ax.grid(which="minor", color=PS.SURFACE, linewidth=2)
    ax.tick_params(which="minor", length=0)
    cb = fig.colorbar(im, ax=ax, fraction=0.05, pad=0.02)
    cb.set_label("flows (log)")
    cb.outline.set_visible(False)
    ax.set_title(f"Flows per group x class ({FIG_TAG})", loc="left")
    made["group_class_heatmap.png"] = PS.save(fig, fig_dir / "group_class_heatmap.png")
    # 3 NaN / inf per feature (counts only)
    issues = [(c, v["nan"], v["inf"]) for c, v in totals["nan_inf"].items() if v["nan"] or v["inf"]]
    if issues:
        issues.sort(key=lambda r: r[1] + r[2])
        fig, ax = plt.subplots(figsize=(5.6, 0.45 * len(issues) + 1.0))
        yv = np.arange(len(issues))
        h = 0.36
        # neutral inks, not class colours (these bars are not classes); lightness separates the two
        for k, (lab, col, off) in enumerate((("NaN", PS.TEXT2, -h / 2 - 0.02),
                                             ("+-inf", PS.NEUTRAL_LIGHT, h / 2 + 0.02))):
            vals = [r[1 + k] for r in issues]
            ax.barh(yv + off, [max(v, 0) for v in vals], height=h, color=col, label=lab)
            for y0, v in zip(yv, vals):
                if v:
                    ax.annotate(f"{v:,}", (v, y0 + off), xytext=(3, 0), textcoords="offset points",
                                va="center", fontsize=7.5, color=PS.TEXT1)
        ax.set_yticks(yv, [r[0] for r in issues])
        ax.set_xlabel("flows")                                        # linear from 0: bar length = count
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_xlim(0, max(max(r[1], r[2]) for r in issues) * 1.18)
        ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2)
        ax.set_title(f"NaN / inf per feature, replaced by 0 ({FIG_TAG})", loc="left")
        made["validation_issues.png"] = PS.save(fig, fig_dir / "validation_issues.png")
    return made


def write_summary(path: Path, M: dict) -> None:
    T, G = M.get("totals", {}), M.get("regression", {})
    L = [f"# Step 20 -- ingest ({M['source']}) -- {M['status']}", "",
         f"- run_id `{M['run_id']}`, {M['created_utc']}, git `{M['git_head'][:12]}` ({M['git_branch']}), "
         f"{SCRIPT} sha256 `{CODE_SHA256[:16]}...`, runtime {M.get('runtime_s', '?')} s, peak RSS {M.get('peak_rss_mb', '?')} MB",
         f"- args: `{' '.join(M['argv'])}`" + (" -- **DRY RUN**" if M["dry_run"] else ""),
         f"- class_map v{M['class_map'].get('version')} sha256 `{M['class_map'].get('sha256', '')[:16]}...`, "
         f"features_v1 file sha256 `{S.FEATURES_V1_SHA256[:16]}...`",
         f"- Timestamp: `{S.TS_FORMAT}`, tz=UTC attached explicitly -- {S.TS_JUSTIFICATION}",
         f"- LAN subnets for the MAC rule: {M['lan_subnets']['subnets']} ({M['lan_subnets']['from']})",
         f"- NaN / inf: {S.NAN_INF_POLICY}", f"- test-session rows: {TEST_ROWS_POLICY}", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    fails = [c for c in M["checks"] if not c["pass"]]
    L += ["## Checks", "", f"**{'PASS' if not fails else 'FAIL'}** ({len(M['checks'])} checks, {len(fails)} failed)", ""]
    L += md_table([{"check": c["check"], "pass": "PASS" if c["pass"] else "FAIL", "detail": c["detail"]}
                   for c in (fails or M["checks"])], ["check", "pass", "detail"]) + [""]
    if M.get("declarations"):
        L += ["## Per-input label declarations", ""]
        L += md_table([{"session": k, **{x: v[x] for x in ("assume_label", "declared_by", "reason")}}
                       for k, v in M["declarations"].items()]) + [""]
    SS = M.get("sessions", {})
    if SS:
        L += ["## Sessions: rows in / out, rejected by reason (V1 filter)", ""]
        L += md_table([{"session": k, "filter": R["filter"].split(".")[-1], "rows_in": R["rows_in"], "kept": R["rows_out"],
                        **R["rejected"], "kept_unreg_GEN": next(iter(R["kept_by_rule"].values()), 0),
                        "status": "ok" if R["failure"] is None else "FAIL"} for k, R in SS.items()]) + [""]
        L += ["## Blank src_mac / dst_mac per reason (kept rows)", "",
              "Allowed: public, broadcast, multicast, off_lan_private (04 resolves MACs from the LAN map only). "
              "lan_unicast / invalid_ip fail.", ""]
        rows = []
        for k, R in SS.items():
            if R.get("row_validation"):
                for m, v in R["row_validation"]["blank_mac"].items():
                    rows.append({"session": k, "column": m, **v})
        L += md_table(rows) + [""]
        L += ["## Labels per session (kept rows)", ""]
        L += md_table([{"session": k, **{n: R["class_counts"].get(n, 0) for n in M["class_map"]["classes"]}}
                       for k, R in SS.items()]) + [""]
    if T:
        L += [f"## Totals ({FIG_TAG})", "", f"- rows in {T['rows_in']:,}, kept {T['rows_out']:,}, rejected "
              + ", ".join(f"{k} {v:,}" for k, v in T["rejected"].items()), ""]
        L += md_table([{"group": g, **{n: T["group_class"].get((g, n), 0) for n in M["class_map"]["classes"]}}
                       for g in GROUPS.labels]) + [""]
        iss = {c: v for c, v in T["nan_inf"].items() if v["nan"] or v["inf"]}
        L += ["## NaN / inf per feature (kept rows; replaced by 0)", ""]
        L += (md_table([{"feature": c, **v} for c, v in iss.items()]) if iss
              else ["No NaN / inf in any feature: validation_issues.png not drawn."]) + [""]
    if G:
        L += [f"## Regression vs V1 -- {G['status']}", ""] + ([f"- {G['note']}", ""] if G.get("note") else [])
        bad = [r for r in G["rows"] if r["pass"] != "PASS"]
        L += ["Failed comparisons:" if bad else "All per-session comparisons PASS:", ""]
        L += md_table(bad or G["rows"], ["session", "field", "ours", "v1", "v1_record", "pass"]) + [""]
        if G["aggregate"]:
            L += ["Aggregates over all V1 sessions (before caps; gap drops have no group, so per-group rows "
                  "only for (label, family) without gap drops):", ""]
            L += md_table(G["aggregate"]) + [""]
    if M.get("outputs"):
        L += ["## Outputs", "", f"- dir `{M['outputs']['dir']}`", ""]
        L += md_table(M["outputs"]["parquets"], ["session", "rows", "bytes", "sha256"]) + [""]
        L += [f"- figures: {', '.join(M.get('figures', {})) or 'none'}", ""]
    path.write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- main

m08b_dev = None


def run(args, M: dict, partial: Path, t0: float) -> bool:
    global m08b_dev
    log("V2 lock + V1 frozen inputs:")
    lock = S.verify_v2_lock(strict=False)
    for n, o, d in lock["checks"]:
        add_check(M, f"lock: {n}", o, d)
    check_v1_frozen(M)
    cm = S.load_class_map()
    F = S.load_features()
    feats = list(F["features"])
    M["class_map"] = {"path": str(S.CLASS_MAP_PATH.relative_to(REPO_ROOT)), "sha256": cm.sha256, "version": cm.version,
                      "classes": list(cm.names)}
    M["features"] = {"path": str(S.FEATURES_PATH.relative_to(REPO_ROOT)), "file_sha256": S.FEATURES_V1_SHA256,
                     "list_sha256": S.FEATURES_V1_LIST_SHA256, "n": len(feats)}
    nets = S.lan_networks(args.source, args.lan_subnets)
    M["lan_subnets"] = {"subnets": [str(n) for n in nets],
                        "from": "--lan-subnets" if args.lan_subnets else S.SOURCE_RULES[args.source]["lan_subnets_from"]}
    log("sessions (V1 loaders):")
    sessions = resolve_sessions(args, M, feats, list(F["dropped_constant_in_train"]))
    if not all(c["pass"] for c in M["checks"]):
        return False
    m08b_dev = m08.load_device_map()
    schema = out_schema(feats, {"lgids.run_id": M["run_id"], "lgids.source": args.source,
                                "lgids.class_map_sha256": cm.sha256, "lgids.features_file_sha256": S.FEATURES_V1_SHA256,
                                "lgids.script_sha256": CODE_SHA256})
    flows_dir = partial / "flows"
    flows_dir.mkdir()
    results = {}
    for s in sessions:
        log(f"session {s['session']} ({s['kind']}, {s['filter']}, assume_label={s['assume_label']}):")
        R = process_session(s, args, cm, feats, schema, flows_dir, t0)
        results[s["session"]] = R
        add_check(M, f"validation + filter: {s['session']}", R["failure"] is None, R["failure"] or
                  f"in {R['rows_in']:,} kept {R['rows_out']:,}")
    M["sessions"] = {k: {**{x: R[x] for x in ("session", "kind", "filter", "rows_in", "rows_out", "rejected",
                                              "kept_by_rule", "filter_counters", "failure", "binary_mismatch",
                                              "timestamp_mismatch", "accounting_ok")},
                         "class_counts": dict(R["class_counts"]),
                         "group_class": {f"{g}|{c}": n for (g, c), n in R["group_class"].items()},
                         "schema_validation": R["schema"], "row_validation": R["rows"],
                         "blank_mac": R["rows"]["blank_mac"] if R["rows"] else None,
                         "parquet": R.get("parquet")} for k, R in results.items()}
    tot = {"rows_in": 0, "rows_out": 0, "rejected": Counter(), "class_counts": Counter(), "group_class": Counter(),
           "nan_inf": {c: {"nan": 0, "inf": 0} for c in feats}, "blank_mac": {}}
    for R in results.values():
        tot["rows_in"] += R["rows_in"]
        tot["rows_out"] += R["rows_out"]
        tot["rejected"].update(R["rejected"])
        tot["class_counts"].update(R["class_counts"])
        tot["group_class"].update(R["group_class"])
        if R["rows"]:
            for c, v in R["rows"]["nan_inf"].items():
                tot["nan_inf"][c]["nan"] += v["nan"]
                tot["nan_inf"][c]["inf"] += v["inf"]
            for m, v in R["rows"]["blank_mac"].items():
                tot["blank_mac"].setdefault(m, Counter()).update(v)
    M["_totals_raw"] = tot
    M["totals"] = {"rows_in": tot["rows_in"], "rows_out": tot["rows_out"], "rejected": dict(tot["rejected"]),
                   "class_counts": dict(tot["class_counts"]),
                   "group_class": {f"{g}|{c}": n for (g, c), n in tot["group_class"].items()},
                   "nan_inf": tot["nan_inf"], "blank_mac": {m: dict(v) for m, v in tot["blank_mac"].items()}}
    if not all(R["failure"] is None for R in results.values()):
        return False
    log("regression vs V1:")
    G = regression(results, sessions, args)
    M["regression"] = G
    add_check(M, "regression vs V1", G["status"].startswith("PASS"), G["status"] + (f" ({G['note']})" if G["note"] else ""))
    for r in G["rows"] + G["aggregate"]:
        if r["pass"] != "PASS":
            log(f"    MISMATCH {r}")
    return all(c["pass"] for c in M["checks"])


def main() -> int:
    global _LOG
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--source", required=True, choices=SOURCES, help="alias table / label rules / input resolver")
    ap.add_argument("--assume-label", action="append", metavar="SESSION=LABEL",
                    help="explicit label for a label-less input (V1: benign_night=benign); recorded in the manifest")
    ap.add_argument("--sessions", default=None, help="comma-separated subset (aggregate regression then skipped)")
    ap.add_argument("--run-id", default=None, help="default: UTC time stamp")
    ap.add_argument("--dry-run", action="store_true", help="outputs under ingest_dry_run/ and results/20/dry_run/")
    ap.add_argument("--limit-rows", type=int, default=None, help="first N rows per file (count regression skipped)")
    ap.add_argument("--chunk", type=int, default=500_000, help="rows per chunk (08's default)")
    ap.add_argument("--block-mb", type=int, default=32, help="Arrow CSV block size MB (08's default)")
    ap.add_argument("--lan-subnets", nargs="+", default=None, help="override the source's LAN subnets (MAC rule)")
    args = ap.parse_args()
    t0 = time.monotonic()
    if args.limit_rows is not None and not args.dry_run:
        fatal("--limit-rows needs --dry-run (a partial ingest must never land in v2/ingest/ or results/20/)")
    run_id = args.run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        fatal(f"--run-id {run_id!r}: letters, digits, _ . - only")
    root = INGEST_DRY_ROOT if args.dry_run else INGEST_ROOT
    final, partial = root / run_id, root / f".{run_id}.partial"
    res = RESULTS_OUT / "dry_run" / run_id if args.dry_run else RESULTS_OUT
    targets = [final, partial] + [res / x for x in ("run_meta.json", "run.log", "summary.md", "ingest_manifest.json",
                                                    "figures")]
    existing = [str(p) for p in targets if p.exists()]
    if existing:
        fatal(f"refusing: target path(s) already exist {existing} (never overwritten; move them or use another run id)")
    lock = run_lock(root)
    res.mkdir(parents=True, exist_ok=True)
    _LOG = open(res / "run.log", "x", encoding="utf-8")
    partial.mkdir()
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...  run_id {run_id}  -> {final}")
    M = {"manifest_version": 1, "run_id": run_id, "created_utc": now_utc(), "status": "RUNNING", "source": args.source,
         "dry_run": args.dry_run, "limit_rows": args.limit_rows, "script": SCRIPT, "code_sha256": CODE_SHA256,
         "argv": [SCRIPT, *sys.argv[1:]], "git_head": git("rev-parse", "HEAD"),
         "git_branch": git("branch", "--show-current"), "git_dirty": bool(git("status", "--porcelain")),
         "v1_code": {"08_build_datasets.py": sha256_file(REPO_ROOT / "08_build_datasets.py"),
                     "08b_extend_test.py": sha256_file(REPO_ROOT / "08b_extend_test.py"),
                     "used": ["08.load_plan", "08.load_sources", "08.load_device_map", "08.read_header",
                              "08.candidate_features", "08.iter_chunks", "08.usable", "08.flow_start",
                              "08b.load_sessions", "08b.usable_day"]},
         "timestamp": {"format": S.TS_FORMAT, "tz": S.TS_TZ, "justification": S.TS_JUSTIFICATION},
         "nan_inf_policy": S.NAN_INF_POLICY, "test_rows_policy": TEST_ROWS_POLICY,
         "lan_subnets": {"subnets": [], "from": ""}, "class_map": {}, "checks": []}
    code = 0
    try:
        ok = run(args, M, partial, t0)
    except (S.SchemaError, V1Fatal) as e:                              # validation / V1 refusal: exit 1
        ok, code = False, 1
        M["error"] = "".join(traceback.format_exception(e))
        log(f"VALIDATION FAILURE: {e}")
    except Exception as e:                                            # noqa: BLE001
        ok, code = False, 2
        M["error"] = "".join(traceback.format_exception(e))
        log(f"ERROR: {e!r}")
    M["status"] = "PASS" if ok else "FAIL"
    tot = M.pop("_totals_raw", None)
    flows = partial / "flows"
    if ok:
        parq = []
        for p in sorted(flows.glob("*.parquet"), key=lambda p: M["source_order"].index(p.stem)):
            parq.append({"session": p.stem, "path": str(final / "flows" / p.name), "rows": pq.read_metadata(p).num_rows,
                         "bytes": p.stat().st_size, "sha256": sha256_file(p)})
        M["outputs"] = {"dir": str(final), "parquets": parq, "columns": pq.read_schema(flows / parq[0]["path"].split("/")[-1]).names
                        if parq else []}
    else:
        if flows.exists():
            for p in flows.glob("*.parquet"):
                p.unlink()                                            # this run's own partial outputs only
            flows.rmdir()
        M["outputs"] = None
        log("FAIL: parquet files removed; only the report is kept")
    M["runtime_s"], M["peak_rss_mb"] = round(time.monotonic() - t0, 1), m08.peak_rss_mb()
    M["figures"] = {}
    if ok and tot is not None:
        M["figures"] = {k: str(Path(v).relative_to(REPO_ROOT)) for k, v in figures(res / "figures", S.load_class_map(), tot).items()}
    man_sha = write_json(partial / "ingest_manifest.json", M)
    partial.rename(final)
    shutil.copyfile(final / "ingest_manifest.json", res / "ingest_manifest.json")
    if tot is not None:
        M["totals"]["group_class"] = tot["group_class"]                # tuple keys for the summary tables
    write_summary(res / "summary.md", M)
    meta = {"script": SCRIPT, "code_sha256": CODE_SHA256, "run_utc": M["created_utc"], "argv": M["argv"],
            "git_head": M["git_head"], "git_branch": M["git_branch"], "git_dirty": M["git_dirty"], "run_id": run_id,
            "status": M["status"], "dry_run": args.dry_run, "limit_rows": args.limit_rows,
            "ingest_dir": str(final), "ingest_manifest_sha256": man_sha,
            "class_map_sha256": M["class_map"].get("sha256"), "features_file_sha256": S.FEATURES_V1_SHA256,
            "checks": M["checks"], "regression_status": (M.get("regression") or {}).get("status"),
            "figures": M["figures"], "test_rows_policy": TEST_ROWS_POLICY,
            "runtime_s": M["runtime_s"], "peak_rss_mb": M["peak_rss_mb"]}
    write_json(res / "run_meta.json", meta)
    log(f"{M['status']}  -> {final}  |  {res}  ({M['runtime_s']} s, peak RSS {M['peak_rss_mb']} MB)")
    _LOG.close()
    lock.close()
    return code or (0 if ok else 1)


if __name__ == "__main__":
    sys.exit(main())
