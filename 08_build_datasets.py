#!/usr/bin/env python
"""08_build_datasets.py -- build the v1 train / val / test master dataset from 04's tagged benign
flows and 07's labelled attack flows.

Inputs (never modified): config/split_plan.json (every tunable), config/attack_set.json,
config/device_table.csv (owner_mac -> device_name, paper_category, behaviour_group),
data/interim/flows/benign/benign_flows_tagged.csv (session benign_night) and
ATTACK_FLOWS_DIR/<stem>/<stem>_labelled.csv.gz (one session per attack stem; 07's report for the
stem must exist with hard_pass and be for the attack set's pcap SHA256).

Rules
  filter   owner_status == "owned" AND exclude_reason == "" AND label != "excluded" (the benign
           capture has no label column: every flow is benign). Owned flows whose owner MAC has
           no behaviour_group in the device table are dropped as "ungrouped" (reported).
  split    t = flow start (Timestamp, whole seconds, UTC). Session time is measured on ALL flows of
           the file (the capture, not just usable rows), per time_basis:
             active  (default) the capture's active segments: flow starts with no pause longer than
                     active_idle_gap_seconds between them form one segment; idle gaps between
                     segments do not count. Several captures are multi-segment (DDoS-SYN_Flood: 26 +
                     29 Aug; Recon-PortScan: two afternoons; Mirai-udpplain24: 7 + 14 Feb), and a
                     wall-clock fraction lands in the idle gap.
             range   wall clock from the first to the last flow start
           A fraction f of the session time maps to the wall-clock instant where f of it has
           elapsed.
             train       whole session train, except the last val_frac_of_train_sessions of its
                         time -> val
             test        whole session test
             time_split  cut at 70 % / 85 % of the session time (time_fracs; time, not rows)
           Flows starting in [cut, cut + gap_seconds) are dropped (timeout-chopped connections
           straddle the cut). Applies to every time_split cut and, with gap_on_train_val_cut,
           to the train -> val cut of train sessions. Background benign in an attack file
           inherits that file's split.
  hours    active benign hours per session per split = active segments that contain >= 1 usable
           benign flow start, clipped to the split's wall-clock window (gap windows excluded):
           the FP / hour denominator (val / test benign is never subsampled).
  clean    +-inf / NaN in feature columns -> 0, counted per column per split (rows written).
  features the 84 CICFlowMeter columns minus Flow ID, Src IP, Src Port, Dst IP, Dst Port,
           Timestamp, Label (04's tag and 07's label columns are metadata, never features), then
           minus the columns constant in the written TRAIN split. Ordered list + sha256 ->
           config/features_v1.json (the Pi's preprocessing contract).
  balance  pass 1 counts usable rows per (session, split, group, device, label, family); pass 2
           keeps each row with p = min(1, cap / count) of its cap key, drawn from a numpy RNG
           seeded with SeedSequence([seed, sha256(cap key)]). Rows of a key consume that key's
           stream in file order, so the sample does not depend on the block size.
             train benign   cap key (benign, train, group, device): train_benign_per_device
             attack         cap key (attack, split, group, family): attack_per_family_per_group
                            [split]; never_cap_families are never sampled
             val / test benign: never sampled

Outputs
  <out-dir>/{train,val,test}.parquet  features (features_v1 order, float64) + y (int8, 0 benign /
                                      1 attack) + attack_family ("" for benign) + group + device
                                      + device_category + session + split + start_ts (int64 epoch
                                      s). Metadata columns are for filtering / analysis only;
                                      Step 9 must not train on them.
  config/features_v1.json             feature contract (not written with --limit-rows: then
                                      <out-dir>/features_v1.json)
  <report-dir>/manifest_v1.json, summary.md      full build
  <report-dir>/dry_run_v1.json, dry_run.md       --dry-run (pass 1 + split plan only)
  With --limit-rows the default report dir is <out-dir>/report, so a test never touches
  results/step8 or config/.

Hard checks (exit 1, no final parquet written): no row in two splits; per session max(train t) <
min(val t) < ... < min(test t) across the splits it feeds; no identity column in features;
y == (label == "attack") and attack_family set iff y; pass-2 pre-sample counts == pass-1 counts.
Warnings (manifest + log): any (group, family) seen in any split with fewer than
min_test_attack_warn attack rows in test, or present in train but missing in test.

One run at a time: an exclusive flock on <out-dir>/.08_build.lock and <report-dir>/.08_build.lock.

Exit status: 0 ok, 1 bad input / lock / hard check failed / another run active, 2 unexpected
exception.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import gzip
import hashlib
import importlib.util
import json
import os
import re
import resource
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

from config.config import (ATTACK_FLOWS_DIR, BEHAVIOUR_GROUPS, CACHE_DIR, CONFIG_DIR, DEVICE_TABLE, FLOWS_DIR,
                           GROUPS, REPO_ROOT, RESULTS_DIR, LockError, sha256_file, verify_lock)


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m04 = _load("tag_flows", "04_tag_flows.py")
m02 = m04.m02
log, fatal, md_table, norm_mac = m02.log, m02.fatal, m02.md_table, m02.norm_mac

SPLIT_PLAN = CONFIG_DIR / "split_plan.json"
ATTACK_SET = CONFIG_DIR / "attack_set.json"
FEATURES_JSON = CONFIG_DIR / "features_v1.json"
LABEL_REPORTS = RESULTS_DIR / "step7" / "labels"
BENIGN_TAGGED = FLOWS_DIR / "benign" / "benign_flows_tagged.csv"
BENIGN_SESSION = "benign_night"
OUT_DIR = CACHE_DIR / "datasets" / "v1"
REPORT_DIR = RESULTS_DIR / "step8"
DATASET_VERSION = "v1"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()

SPLITS = ("train", "val", "test")
MODES = ("train", "test", "time_split")
TIME_BASES = ("active", "range")
N_ORIG = m04.EXPECTED_FLOW_COLS          # CICFlowMeter columns; everything after is metadata
IDENTITY_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp", "Label"]
IDENTITY_RE = re.compile(r"(?i)\b(ip|port|mac|id)\b|timestamp|label|owner|device|group")
META_COLS = ["owner_status", "exclude_reason", "owner_mac", "owner_device", "owner_category"]
LABEL_COLS = ["label", "attack_family"]  # of 07's label columns, the two used here
OUT_META = ["y", "attack_family", "group", "device", "device_category", "session", "split", "start_ts"]
KEY = ["session", "split", "group", "device", "label", "family"]
EPOCH = pd.Timestamp(0, tz="UTC")
ROW_BITS = 40                            # row id = source index << 40 | row in file


# --------------------------------------------------------------------------- inputs

def load_plan(path: Path, aset: dict) -> dict:
    P = json.loads(path.read_text(encoding="utf-8"))
    stems = {Path(e["path"]).stem: e for e in aset["pcaps"]}
    fams = {e["family"] for e in aset["pcaps"]}
    S = P["sessions"]
    unknown = [s for s in S if s != BENIGN_SESSION and s not in stems]
    missing = [s for s in [BENIGN_SESSION, *stems] if s not in S]
    if unknown or missing:
        fatal(f"{path.name}: sessions not in the attack set {unknown}, attack-set stems / benign "
              f"session missing from the plan {missing}")
    bad = {s: m for s, m in S.items() if m not in MODES}
    if bad:
        fatal(f"{path.name}: unknown session modes {bad} (allowed {MODES})")
    tf = P["time_fracs"]
    if abs(sum(tf[s] for s in SPLITS) - 1) > 1e-9 or min(tf.values()) <= 0:
        fatal(f"{path.name}: time_fracs must be > 0 and sum to 1: {tf}")
    P.setdefault("time_basis", "active")
    P.setdefault("active_idle_gap_seconds", 300)
    if P["time_basis"] not in TIME_BASES or P["active_idle_gap_seconds"] <= 0:
        fatal(f"{path.name}: time_basis must be one of {TIME_BASES} and active_idle_gap_seconds > 0")
    if not 0 < P["val_frac_of_train_sessions"] < 1 or P["gap_seconds"] < 0:
        fatal(f"{path.name}: val_frac_of_train_sessions must be in (0, 1) and gap_seconds >= 0")
    nc = set(P["caps"]["never_cap_families"])
    if not nc <= fams:
        fatal(f"{path.name}: never_cap_families {sorted(nc - fams)} are not attack-set families {sorted(fams)}")
    if set(P["caps"]["attack_per_family_per_group"]) != set(SPLITS):
        fatal(f"{path.name}: caps.attack_per_family_per_group needs exactly {SPLITS}")
    return P


def load_sources(P: dict, aset: dict, flows_dir: Path) -> list[dict]:
    """One source per session, in plan order (the RNG streams follow this order)."""
    by_stem = {Path(e["path"]).stem: e for e in aset["pcaps"]}
    out = []
    for i, (sess, mode) in enumerate(P["sessions"].items()):
        if sess == BENIGN_SESSION:
            out.append({"idx": i, "session": sess, "mode": mode, "kind": "benign", "family": "",
                        "path": BENIGN_TAGGED, "label_report": None})
            continue
        e = by_stem[sess]
        path = flows_dir / sess / f"{sess}_labelled.csv.gz"
        rpath = LABEL_REPORTS / f"{sess}_label_report.json"
        if not rpath.is_file():
            fatal(f"no 07 label report {rpath}: run 07_label_attacks.py for {sess}")
        R = json.loads(rpath.read_text(encoding="utf-8"))
        if not R.get("hard_pass"):
            fatal(f"{rpath.name}: 07 hard checks failed for {sess}")
        if R["completion_key"]["pcap_sha256"] != e["sha256"]:
            fatal(f"{rpath.name} is for pcap {R['completion_key']['pcap_sha256']}, attack set has {e['sha256']}")
        if R["family"] != e["family"]:
            fatal(f"{rpath.name}: family {R['family']} != attack set {e['family']}")
        out.append({"idx": i, "session": sess, "mode": mode, "kind": "attack", "family": e["family"],
                    "path": path, "label_report": {"path": str(rpath.relative_to(REPO_ROOT)),
                                                   "completion_key": R["completion_key"],
                                                   "flows": R["flows"], "by_label": R["by_label"]}})
    for s in out:
        if not s["path"].is_file():
            fatal(f"{s['session']}: input not found {s['path']}")
    return out


def load_device_map() -> pd.DataFrame:
    d = pd.read_csv(DEVICE_TABLE, dtype=str, keep_default_na=False)
    d["mac"] = d["mac"].map(norm_mac)
    if d["mac"].duplicated().any():
        fatal(f"{DEVICE_TABLE.name}: duplicate MACs {d.loc[d['mac'].duplicated(), 'mac'].tolist()}")
    iot = d[d["role"] == m04.SMART_HOME_ROLE]
    if iot["device_name"].duplicated().any():
        fatal(f"{DEVICE_TABLE.name}: duplicate smart-home device names "
              f"{iot.loc[iot['device_name'].duplicated(), 'device_name'].tolist()}")
    bad = sorted(set(d["behaviour_group"]) - set(GROUPS.labels) - {""})
    if bad:
        fatal(f"{DEVICE_TABLE.name}: behaviour_group values {bad} not in {GROUPS.labels}")
    return d.set_index("mac")[["device_name", "paper_category", "behaviour_group", "role"]]


def read_header(path: Path) -> list[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", newline="") as fh:
        return next(csv.reader([fh.readline().rstrip("\r\n")]))


def candidate_features(headers: dict[str, list[str]]) -> list[str]:
    ref_s, ref = next(iter(headers.items()))
    for s, h in headers.items():
        if h[:N_ORIG] != ref[:N_ORIG]:
            diff = [(a, b) for a, b in zip(h[:N_ORIG], ref[:N_ORIG]) if a != b][:5]
            fatal(f"{s}: CICFlowMeter columns differ from {ref_s}: {diff}")
        need = META_COLS + (LABEL_COLS if s != BENIGN_SESSION else [])
        miss = [c for c in need + IDENTITY_COLS if c not in h]
        if miss:
            fatal(f"{s}: missing columns {miss}")
    cand = [c for c in ref[:N_ORIG] if c not in IDENTITY_COLS]
    if len(cand) != N_ORIG - len(IDENTITY_COLS):
        fatal(f"identity columns not all among the {N_ORIG} CICFlowMeter columns")
    return cand


# --------------------------------------------------------------------------- chunked reading

def iter_chunks(path: Path, cols: list[str], feats: list[str], chunk: int, block_mb: int, limit: int | None):
    """(row offset, pandas frame of `cols`) per chunk of `chunk` rows of the CSV (gzip detected
    from the name). Feature columns float64 (empty / NaN / null -> NaN, "Infinity" -> inf), the
    rest strings with "" kept as "". Stops after `limit` rows. Arrow parses single-threaded in
    small blocks: on these gzip files that is faster than its threaded reader and peak RSS grows
    with the block size (~2.8 GB at 64 MB, ~6.4 GB at 256 MB on DDoS-SYN_Flood)."""
    types = {c: (pa.float64() if c in feats else pa.string()) for c in cols}
    reader = pacsv.open_csv(
        pa.input_stream(str(path)),
        read_options=pacsv.ReadOptions(block_size=block_mb << 20, use_threads=False),
        convert_options=pacsv.ConvertOptions(include_columns=cols, column_types=types,
                                             strings_can_be_null=False, quoted_strings_can_be_null=False))
    off, buf, nbuf = 0, [], 0
    for batch in reader:
        if limit is not None and off + nbuf + batch.num_rows > limit:
            batch = batch.slice(0, limit - off - nbuf)
        buf.append(batch)
        nbuf += batch.num_rows
        done = limit is not None and off + nbuf >= limit
        if nbuf >= chunk or done:
            yield off, pa.Table.from_batches(buf).to_pandas()
            off, buf, nbuf = off + nbuf, [], 0
        if done:
            return
    if nbuf:
        yield off, pa.Table.from_batches(buf).to_pandas()


def flow_start(ts: pd.Series) -> np.ndarray:
    t = pd.to_datetime(ts, format=m04.TS_FORMAT, utc=True, errors="coerce")
    if t.isna().any():
        fatal(f"{int(t.isna().sum())} unparseable Timestamps, e.g. {ts[t.isna()].head(3).tolist()}")
    return ((t - EPOCH) // pd.Timedelta(seconds=1)).to_numpy(dtype=np.int64)


def usable(f: pd.DataFrame, src: dict, dev: pd.DataFrame, drops: Counter) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """Shared filter of both passes: (start t of all rows, positions of usable rows, frame of
    the usable rows: t, mac, label, family, group, device, category). Updates drops."""
    t = flow_start(f["Timestamp"])
    n = len(f)
    if src["kind"] == "benign":
        label, fam = np.full(n, "benign", dtype=object), np.full(n, "", dtype=object)
    else:
        label, fam = f["label"].to_numpy(object), f["attack_family"].to_numpy(object)
    owned = f["owner_status"].to_numpy(object) == "owned"
    clean = f["exclude_reason"].to_numpy(object) == ""
    notexc = label != "excluded"
    drops["rows"] += n
    drops["not_owned"] += int((~owned).sum())
    drops["exclude_reason"] += int((owned & ~clean).sum())
    drops["label_excluded"] += int((owned & clean & ~notexc).sum())
    mac = f["owner_mac"].str.lower().to_numpy(object)
    group = pd.Series(mac).map(dev["behaviour_group"]).fillna("").to_numpy(object)
    keep = owned & clean & notexc
    ung = keep & ~np.isin(group, GROUPS.labels)
    drops["ungrouped"] += int(ung.sum())
    pos = np.flatnonzero(keep & ~ung)
    U = pd.DataFrame({"t": t[pos], "mac": mac[pos], "label": label[pos], "family": fam[pos],
                      "group": group[pos]})
    U["device"] = U["mac"].map(dev["device_name"])
    U["category"] = U["mac"].map(dev["paper_category"])
    odev = f["owner_device"].to_numpy(object)[pos]
    drops["owner_device_name_mismatch"] += int((odev != U["device"].to_numpy(object)).sum())
    lab = set(U["label"].unique())
    if not lab <= {"attack", "benign"}:
        fatal(f"{src['session']}: unexpected label values {sorted(lab - {'attack', 'benign'})}")
    is_att = U["label"].to_numpy(object) == "attack"
    fams = U["family"].to_numpy(object)
    if (fams[is_att] != src["family"]).any() or (fams[~is_att] != "").any():
        fatal(f"{src['session']}: attack_family must be {src['family']!r} on attack rows and blank on "
              f"benign rows; got {sorted(set(fams))}")
    return t, pos, U


# --------------------------------------------------------------------------- split plan

def active_segments(secs: np.ndarray, idle: float) -> np.ndarray:
    """[start, end) segments (n x 2, epoch s) of the flow-start seconds `secs`: a pause longer
    than `idle` s between consecutive flow starts ends a segment; a segment ends 1 s after its
    last flow start (Timestamps are truncated to whole seconds)."""
    secs = np.unique(secs)
    brk = np.flatnonzero(np.diff(secs) > idle)
    starts = np.r_[secs[0], secs[brk + 1]]
    ends = np.r_[secs[brk], secs[-1]] + 1
    return np.c_[starts, ends].astype(float)


def time_at(frac: float, seg: np.ndarray, basis: str) -> float:
    """Wall-clock instant at which `frac` of the session time has elapsed."""
    if basis == "range":
        return float(seg[0, 0] + frac * (seg[-1, 1] - 1 - seg[0, 0]))
    cum = np.r_[0.0, np.cumsum(seg[:, 1] - seg[:, 0])]
    a = frac * cum[-1]
    i = min(int(np.searchsorted(cum, a, side="right")) - 1, len(seg) - 1)
    return float(seg[i, 0] + (a - cum[i]))


def session_cuts(mode: str, seg: np.ndarray, P: dict) -> tuple[list[float], list[str]]:
    """Boundaries b and segment labels s for np.searchsorted(b, t, side='right'): t < b[0] ->
    s[0], b[0] <= t < b[1] -> s[1], ... Gap segments are labelled gap@<before>|<after>."""
    g = float(P["gap_seconds"])

    def at(frac: float) -> float:
        return time_at(frac, seg, P["time_basis"])

    if mode == "test":
        return [], ["test"]
    if mode == "train":
        c = at(1 - P["val_frac_of_train_sessions"])
        if P.get("gap_on_train_val_cut", True):
            return [c, c + g], ["train", "gap@train|val", "val"]
        return [c], ["train", "val"]
    c1 = at(P["time_fracs"]["train"])
    c2 = at(P["time_fracs"]["train"] + P["time_fracs"]["val"])
    b = [c1, c1 + g, c2, c2 + g]
    if b != sorted(b):   # session shorter than the gap: val empty, keep the order valid
        b = [c1, c1 + g, max(c2, c1 + g), max(c2 + g, c1 + g)]
    return b, ["train", "gap@train|val", "val", "gap@val|test", "test"]


def benign_hours(seg: np.ndarray, benign_t: np.ndarray, cuts: tuple[list[float], list[str]]) -> dict[str, float]:
    """Hours of the active segments holding >= 1 usable benign flow start, clipped to each
    split's wall-clock window (gap windows excluded)."""
    out = {sp: 0.0 for sp in SPLITS}
    if not len(benign_t):
        return out
    S = seg[np.unique(np.searchsorted(seg[:, 0], benign_t, side="right") - 1)]
    b, labels = cuts
    edges = np.r_[-np.inf, np.asarray(b, dtype=float), np.inf]
    for k, lab in enumerate(labels):
        if lab in out:
            ov = np.minimum(S[:, 1], edges[k + 1]) - np.maximum(S[:, 0], edges[k])
            out[lab] += float(np.clip(ov, 0, None).sum()) / 3600
    return out


def assign(t: np.ndarray, cuts: tuple[list[float], list[str]]) -> np.ndarray:
    b, s = cuts
    return np.asarray(s, dtype=object)[np.searchsorted(np.asarray(b, dtype=float), t, side="right")]


def stable_hash(key: str) -> int:
    return int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:8], "big")


def cap_keys(df: pd.DataFrame, P: dict) -> pd.Series:
    """Cap key per row of a frame with split / group / device / label / family; "" = never sampled."""
    caps = P["caps"]
    att = (df["label"] == "attack") & ~df["family"].isin(caps["never_cap_families"])
    ben = (df["label"] == "benign") & (df["split"] == "train")
    k = pd.Series("", index=df.index, dtype=object)
    k[att] = "attack|" + df.loc[att, "split"] + "|" + df.loc[att, "group"] + "|" + df.loc[att, "family"]
    k[ben] = "benign|train|" + df.loc[ben, "group"] + "|" + df.loc[ben, "device"]
    return k


def cap_of(key: str, P: dict) -> int:
    kind, split = key.split("|")[:2]
    return (P["caps"]["train_benign_per_device"] if kind == "benign"
            else P["caps"]["attack_per_family_per_group"][split])


def build_plan(hist: dict[str, pd.DataFrame], active: dict[str, np.ndarray], sources: list[dict],
               dev: pd.DataFrame, P: dict) -> dict:
    """From pass 1's per-second histograms and flow-start seconds: active segments, cut points,
    active benign hours, counts per KEY (gap rows separate) and the sampling probability of
    every cap key."""
    cuts, segs, bhours, rows = {}, {}, {}, []
    for s in sources:
        sess = s["session"]
        segs[sess] = active_segments(active[sess], P["active_idle_gap_seconds"])
        cuts[sess] = session_cuts(s["mode"], segs[sess], P)
        h = hist[sess]
        bhours[sess] = benign_hours(segs[sess], h.loc[h["label"] == "benign", "t"].to_numpy(), cuts[sess])
        if h.empty:
            continue
        h = h.assign(session=sess, split=assign(h["t"].to_numpy(), cuts[sess]))
        rows.append(h)
    H = pd.concat(rows, ignore_index=True)
    H["group"] = H["mac"].map(dev["behaviour_group"])
    H["device"] = H["mac"].map(dev["device_name"])
    H["category"] = H["mac"].map(dev["paper_category"])
    gap = H[H["split"].str.startswith("gap@")]
    C = (H[~H["split"].str.startswith("gap@")].groupby(KEY, sort=True)["n"].sum().reset_index())
    C["cap_key"] = cap_keys(C, P)
    K = C[C["cap_key"] != ""].groupby("cap_key")["n"].sum()
    probs = {k: {"count": int(n), "cap": cap_of(k, P), "p": min(1.0, cap_of(k, P) / n)} for k, n in K.items()}
    C["p"] = C["cap_key"].map(lambda k: probs[k]["p"] if k else 1.0)
    C["expected"] = C["n"] * C["p"]
    G = gap.groupby(["session", "split", "label", "family"])["n"].sum().reset_index()
    return {"cuts": cuts, "segments": segs, "benign_hours": bhours, "counts": C, "probs": probs, "gap": G,
            "categories": H.groupby("device")["category"].first().to_dict()}


# --------------------------------------------------------------------------- passes

def pass1(sources: list[dict], dev: pd.DataFrame, feats: list[str], args, t0: float) -> tuple[dict, dict, dict, dict]:
    hist, ranges, drops, active = {}, {}, {}, {}
    for s in sources:
        sess, D = s["session"], Counter()
        cols = ["Timestamp"] + META_COLS + (LABEL_COLS if s["kind"] == "attack" else [])
        parts, secs, tmin, tmax = [], [], None, None
        for off, f in iter_chunks(s["path"], cols, feats, args.chunk, args.block_mb, args.limit_rows):
            t, pos, U = usable(f, s, dev, D)
            tmin = int(t.min()) if tmin is None else min(tmin, int(t.min()))
            tmax = int(t.max()) if tmax is None else max(tmax, int(t.max()))
            secs.append(np.unique(t))
            parts.append(U.groupby(["t", "mac", "label", "family"]).size().rename("n").reset_index())
            log(f"  pass 1 [{sess}] rows {off + len(f):>11,}  usable {len(U):>8,}  {time.monotonic() - t0:7.1f} s")
        if tmin is None:
            fatal(f"{sess}: no rows in {s['path']}")
        h = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=["t", "mac", "label", "family", "n"])
        hist[sess] = h.groupby(["t", "mac", "label", "family"])["n"].sum().reset_index()
        ranges[sess], drops[sess], active[sess] = (tmin, tmax), dict(D), np.unique(np.concatenate(secs))
    return hist, ranges, drops, active


class Writers:
    """One ParquetWriter per split, lazily opened, on <out-dir>/<split>.all.parquet.tmp."""

    def __init__(self, out: Path, schema: pa.Schema):
        self.out, self.schema, self.w = out, schema, {}

    def path(self, split: str) -> Path:
        return self.out / f"{split}.all.parquet.tmp"

    def write(self, split: str, table: pa.Table) -> None:
        if split not in self.w:
            self.w[split] = pq.ParquetWriter(self.path(split), self.schema, compression="zstd")
        self.w[split].write_table(table, row_group_size=1 << 20)

    def close(self) -> None:
        for w in self.w.values():
            w.close()


def pass2(sources: list[dict], dev: pd.DataFrame, feats: list[str], plan: dict, P: dict, args, t0: float) -> dict:
    schema = pa.schema([*(pa.field(c, pa.float64()) for c in feats), pa.field("y", pa.int8()),
                        *(pa.field(c, pa.string()) for c in OUT_META[1:-1]), pa.field("start_ts", pa.int64())])
    W = Writers(args.out_dir, schema)
    probs = plan["probs"]
    rngs = {k: np.random.default_rng(np.random.SeedSequence([P["seed"], stable_hash(k)])) for k in probs}
    pre, post = Counter(), Counter()
    nan_n = {s: np.zeros(len(feats), np.int64) for s in SPLITS}
    inf_n = {s: np.zeros(len(feats), np.int64) for s in SPLITS}
    tr_min, tr_max = np.full(len(feats), np.inf), np.full(len(feats), -np.inf)
    ids = {s: [] for s in SPLITS}
    span = defaultdict(lambda: [np.iinfo(np.int64).max, np.iinfo(np.int64).min])
    bad_y, drops = 0, {}
    for s in sources:
        sess, D = s["session"], Counter()
        cols = ["Timestamp"] + META_COLS + (LABEL_COLS if s["kind"] == "attack" else []) + feats
        for off, f in iter_chunks(s["path"], cols, feats, args.chunk, args.block_mb, args.limit_rows):
            _, pos, U = usable(f, s, dev, D)
            U["session"] = sess
            U["split"] = assign(U["t"].to_numpy(), plan["cuts"][sess])
            U = U[~U["split"].str.startswith("gap@")].copy()
            pre.update(U.groupby(KEY).size().to_dict())
            U["cap_key"] = cap_keys(U, P)
            keep = np.ones(len(U), dtype=bool)
            for k, ix in U.groupby("cap_key", sort=True).indices.items():
                if k:   # ix ascending = file order: the key's stream is consumed in file order
                    keep[ix] = rngs[k].random(len(ix)) < probs[k]["p"]
            U = U[keep]
            post.update(U.groupby(KEY).size().to_dict())
            rows = pos[U.index.to_numpy()]
            X = f[feats].to_numpy(np.float64)[rows]
            y = (U["label"].to_numpy(object) == "attack").astype(np.int8)
            bad_y += int(((y == 1) != (U["family"].to_numpy(object) != "")).sum())
            for split, ix in U.reset_index(drop=True).groupby("split").indices.items():
                Xs = X[ix]
                nan_n[split] += np.isnan(Xs).sum(0)
                inf_n[split] += np.isinf(Xs).sum(0)
                Xs[~np.isfinite(Xs)] = 0.0
                if split == "train":
                    tr_min = np.minimum(tr_min, Xs.min(0))
                    tr_max = np.maximum(tr_max, Xs.max(0))
                us = U.iloc[ix]
                tt = us["t"].to_numpy(np.int64)
                sp = span[(sess, split)]
                sp[0], sp[1] = min(sp[0], int(tt.min())), max(sp[1], int(tt.max()))
                ids[split].append((np.int64(s["idx"]) << ROW_BITS) | (off + rows[ix]).astype(np.int64))
                cols_out = {c: Xs[:, j] for j, c in enumerate(feats)}
                cols_out.update({"y": y[ix], "attack_family": us["family"].to_numpy(object),
                                 "group": us["group"].to_numpy(object), "device": us["device"].to_numpy(object),
                                 "device_category": us["category"].to_numpy(object),
                                 "session": us["session"].to_numpy(object), "split": us["split"].to_numpy(object),
                                 "start_ts": tt})
                W.write(split, pa.Table.from_pydict(cols_out, schema=schema))
            log(f"  pass 2 [{sess}] rows {off + len(f):>11,}  usable {len(pos):>8,}  written {len(U):>8,}  "
                f"{time.monotonic() - t0:7.1f} s")
        drops[sess] = dict(D)
    W.close()
    return {"writers": W, "pre": pre, "post": post, "nan": nan_n, "inf": inf_n, "train_min": tr_min,
            "train_max": tr_max, "ids": ids, "span": dict(span), "bad_y": bad_y, "drops": drops}


def finalize(W: Writers, out: Path, columns: list[str]) -> dict:
    res = {}
    for split in SPLITS:
        tmp, final = W.path(split), out / f"{split}.parquet"
        part = out / f"{split}.parquet.partial"
        n = 0
        if tmp.is_file():
            pf = pq.ParquetFile(tmp)
            schema = pa.schema([pf.schema_arrow.field(c) for c in columns])
            with pq.ParquetWriter(part, schema, compression="zstd") as w:
                for b in pf.iter_batches(batch_size=500_000, columns=columns):
                    w.write_batch(b, row_group_size=1 << 20)
                    n += b.num_rows
            tmp.unlink()
        else:   # no rows reached this split: no file
            log(f"  WARNING: split {split} has no rows, no {final.name} written")
            continue
        os.replace(part, final)
        res[split] = {"path": str(final), "rows": n, "bytes": final.stat().st_size}
    return res


# --------------------------------------------------------------------------- checks / reports

def warnings_for(tab: pd.DataFrame, P: dict) -> list[str]:
    """tab: attack rows per (split, group, family), column n (written or expected)."""
    W = []
    a = tab.groupby(["group", "family", "split"])["n"].sum().unstack("split", fill_value=0)
    for s in SPLITS:
        if s not in a:
            a[s] = 0
    for (g, fam), r in a.iterrows():
        if r["train"] > 0 and r["test"] == 0:
            W.append(f"({g}, {fam}): {int(r['train']):,} attack rows in train but NONE in test")
        elif r["test"] < P["min_test_attack_warn"]:
            W.append(f"({g}, {fam}): only {int(r['test']):,} attack rows in test "
                     f"(< min_test_attack_warn {P['min_test_attack_warn']}; train {int(r['train']):,}, val {int(r['val']):,})")
    for g in GROUPS.labels:
        for fam in sorted({x for _, x in a.index}):
            if (g, fam) not in a.index:
                W.append(f"({g}, {fam}): no attack rows in any split")
    return W


def utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat(timespec="seconds")


def cuts_json(cuts: tuple[list[float], list[str]], seg: np.ndarray) -> dict:
    b, s = cuts
    return {"splits": s, "boundaries_epoch": [round(x, 3) for x in b], "boundaries_utc": [utc(x) for x in b],
            "active_segments_utc": [[utc(lo), utc(hi)] for lo, hi in seg]}


def hours_rows(plan: dict) -> list[dict]:
    H = plan["benign_hours"]
    rows = [{"session": k, **{sp: round(v[sp], 3) for sp in SPLITS}} for k, v in H.items()]
    rows.append({"session": "TOTAL", **{sp: round(sum(v[sp] for v in H.values()), 3) for sp in SPLITS}})
    return rows


def split_table(C: pd.DataFrame, col: str) -> list[dict]:
    t = C.groupby(["split", "group", "label", "family"])[col].sum().round().astype(int).reset_index()
    t["split"] = pd.Categorical(t["split"], SPLITS, ordered=True)
    return t.sort_values(["split", "group", "label", "family"]).astype({"split": str}).to_dict("records")


def totals(C: pd.DataFrame, col: str) -> list[dict]:
    t = C.groupby(["split", "label"])[col].sum().round().astype(int).unstack("label", fill_value=0)
    return [{"split": s, **{k: int(t.loc[s, k]) if s in t.index and k in t else 0 for k in ("benign", "attack")},
             "total": int(t.loc[s].sum()) if s in t.index else 0} for s in SPLITS]


def session_rows(sources: list[dict], ranges: dict, plan: dict, drops: dict, P: dict) -> list[dict]:
    C, G = plan["counts"], plan["gap"]
    out = []
    for s in sources:
        sess = s["session"]
        tmin, tmax = ranges[sess]
        seg, bh = plan["segments"][sess], plan["benign_hours"][sess]
        d = drops[sess]
        c = C[C["session"] == sess].groupby("split")["n"].sum()
        g = G[G["session"] == sess]["n"].sum()
        out.append({"session": sess, "alias": P.get("session_aliases", {}).get(sess, sess), "mode": s["mode"],
                    "start_utc": utc(tmin), "end_utc": utc(tmax), "span_h": round((tmax - tmin) / 3600, 2),
                    "active_h": round(float((seg[:, 1] - seg[:, 0]).sum()) / 3600, 2), "segments": len(seg),
                    "rows": d["rows"], "not_owned": d["not_owned"], "exclude_reason": d["exclude_reason"],
                    "label_excluded": d["label_excluded"], "ungrouped": d["ungrouped"],
                    **{sp: int(c.get(sp, 0)) for sp in SPLITS}, "gap_dropped": int(g),
                    **{f"benign_h_{sp}": round(bh[sp], 2) for sp in SPLITS},
                    "cuts_utc": ", ".join(f"{lab}@{utc(b)[5:19].replace('T', ' ')}" for b, lab in
                                          zip(plan["cuts"][sess][0], plan["cuts"][sess][1][1:]))})
    return out


def device_rows(C: pd.DataFrame, post: Counter | None) -> list[dict]:
    T = C[C["split"] == "train"]
    rows = []
    for (g, d), x in T.groupby(["group", "device"]):
        b, a = x[x["label"] == "benign"], x[x["label"] == "attack"]
        r = {"group": g, "device": d, "benign_before": int(b["n"].sum()), "benign_after": None,
             "attack_before": int(a["n"].sum()), "attack_after": None}
        if post is None:
            r["benign_after"] = int(round(b["expected"].sum()))
            r["attack_after"] = int(round(a["expected"].sum()))
        else:
            r["benign_after"] = sum(v for k, v in post.items() if k[1] == "train" and k[3] == d and k[4] == "benign")
            r["attack_after"] = sum(v for k, v in post.items() if k[1] == "train" and k[3] == d and k[4] == "attack")
        rows.append(r)
    return sorted(rows, key=lambda r: (r["group"], -r["benign_before"]))


def peak_rss_mb() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)


def write_md(path: Path, title: str, M: dict, written: bool) -> None:
    L = [f"# {title}", "", f"- run {M['run_utc']}, runtime {M['runtime_s']:,} s, peak RSS {M['peak_rss_mb']:,} MB",
         f"- args: `{' '.join(M['argv'])}`"]
    if M.get("limit_rows"):
        L.append(f"- **--limit-rows {M['limit_rows']:,}: TEST RUN on the first rows of each file only**")
    L += [f"- split plan {M['config']['split_plan']['version']} (sha256 {M['config']['split_plan']['sha256'][:16]}...), "
          f"groups {M['config']['behaviour_groups']['version']}, attack set v{M['config']['attack_set']['version']}, "
          f"seed {M['plan']['seed']}, gap {M['plan']['gap_seconds']} s, time_basis {M['plan']['time_basis']} "
          f"(a pause > {M['plan']['active_idle_gap_seconds']} s ends an active segment)", ""]
    if M["warnings"]:
        L += ["## !!! WARNINGS", ""] + [f"- **WARN** {w}" for w in M["warnings"]] + [""]
    if "checks" in M:
        L += ["## Hard checks", "", f"**{'PASS' if M['hard_pass'] else 'FAIL'}**", ""]
        L += md_table([{"check": k, "pass": "PASS" if v["pass"] else "FAIL", "detail": v["detail"]}
                       for k, v in M["checks"].items()], ["check", "pass", "detail"]) + [""]
    L += ["## Totals per split", "", f"rows {'written' if written else 'expected after caps (pass 1 counts x p)'}", ""]
    L += md_table(M["totals"], ["split", "benign", "attack", "total"]) + [""]
    if not written:
        L += ["before caps:", ""] + md_table(M["totals_before_caps"], ["split", "benign", "attack", "total"]) + [""]
    L += ["## Sessions", "", "rows = all flows in the file; train / val / test / gap_dropped = usable rows "
          "(owned, no exclude_reason, label != excluded, grouped) before caps", ""]
    L += md_table(M["sessions"], ["session", "alias", "mode", "start_utc", "end_utc", "span_h", "active_h",
                                  "segments", "rows", "not_owned", "exclude_reason", "label_excluded", "ungrouped",
                                  "train", "val", "test", "gap_dropped", "cuts_utc"]) + [""]
    L += ["## Active benign hours per session per split (FP/hour denominator)", "",
          M["benign_active_hours"]["definition"] + ". Train benign is subsampled by the caps; val / test "
          "benign never is.", ""]
    L += md_table(M["benign_hours_table"], ["session", *SPLITS]) + [""]
    L += ["## Gap drops (flows starting within gap_seconds after a cut)", ""]
    L += md_table(M["gap_drops"], ["session", "split", "label", "family", "n"]) + [""]
    L += ["## Rows per split x group x label x family", ""]
    L += md_table(M["by_split_group_label_family"], ["split", "group", "label", "family", "before_caps",
                                                     "written" if written else "expected"]) + [""]
    L += ["## Cap keys", ""]
    L += md_table([{"cap_key": k, **v, "p": f"{v['p']:.6f}"} for k, v in M["cap_keys"].items() if v["p"] < 1],
                  ["cap_key", "count", "cap", "p"]) + ["", f"({sum(v['p'] >= 1 for v in M['cap_keys'].values())} "
                                                       "more cap keys under their cap, p = 1)", ""]
    L += ["## Train rows per device (before / after caps)", ""]
    L += md_table(M["train_devices"], ["group", "device", "benign_before", "benign_after", "attack_before",
                                       "attack_after"]) + [""]
    if written:
        L += ["## Features", "", f"- {M['features']['n']} features, sha256 `{M['features']['sha256']}` -> "
              f"`{M['features']['path']}`",
              f"- dropped identity: {', '.join(M['features']['dropped_identity'])}",
              f"- dropped constant in train: {', '.join(M['features']['dropped_constant']) or 'none'}", ""]
        L += ["## NaN / Inf replaced by 0 (rows written)", ""]
        L += md_table(M["nan_inf"], ["split", "column", "nan", "inf"]) + [""]
        L += ["## Outputs", ""] + md_table([{"split": k, **v} for k, v in M["outputs"].items()],
                                           ["split", "rows", "bytes", "path"]) + [""]
    L += ["## Inputs", ""] + md_table(M["inputs"], ["session", "rows", "sha256", "path"]) + [""]
    L += ["## Filter drops", ""] + md_table(
        [{"session": k, **v} for k, v in M["filter_drops"].items()],
        ["session", "rows", "not_owned", "exclude_reason", "label_excluded", "ungrouped", "owner_device_name_mismatch"])
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- main

RUN_LOCK = ".08_build.lock"


def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.08_build.lock for the whole run (released by the
    kernel on exit). Two builds writing the same parquet files would corrupt each other."""
    d.mkdir(parents=True, exist_ok=True)
    path = d / RUN_LOCK
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another 08_build_datasets.py run is using {d} (lock {path} held by: {holder}); "
              "refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}"
             f" argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="pass 1 counts + split plan report only")
    ap.add_argument("--limit-rows", type=int, default=None, help="read only the first N rows of each file (testing)")
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR, help="parquet output dir")
    ap.add_argument("--report-dir", type=Path, default=None,
                    help=f"manifest / summary dir (default {REPORT_DIR.relative_to(REPO_ROOT)}; "
                         "<out-dir>/report with --limit-rows)")
    ap.add_argument("--plan", type=Path, default=SPLIT_PLAN)
    ap.add_argument("--flows-dir", type=Path, default=ATTACK_FLOWS_DIR)
    ap.add_argument("--chunk", type=int, default=500_000, help="rows per processing chunk")
    ap.add_argument("--block-mb", type=int, default=32, help="Arrow CSV parse block size (MB); peak RSS grows with it")
    args = ap.parse_args()
    t0 = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    if args.limit_rows is not None and args.limit_rows < 1:
        fatal("--limit-rows must be >= 1")
    if args.block_mb < 1 or args.chunk < 1000:
        fatal("--block-mb must be >= 1 and --chunk >= 1000")
    args.out_dir = (args.out_dir if args.out_dir.is_absolute() else REPO_ROOT / args.out_dir).expanduser()
    if args.report_dir is None:
        args.report_dir = args.out_dir / "report" if args.limit_rows else REPORT_DIR
    args.report_dir = args.report_dir if args.report_dir.is_absolute() else REPO_ROOT / args.report_dir
    features_path = args.out_dir / "features_v1.json" if args.limit_rows else FEATURES_JSON
    for d in (args.out_dir, args.report_dir):
        if d.resolve().is_relative_to(CONFIG_DIR.resolve()):
            fatal(f"{d} must not be under config/")

    try:
        lock = verify_lock()
    except LockError as e:
        fatal(str(e))
    locks = [run_lock(d) for d in dict.fromkeys([args.out_dir.resolve(), args.report_dir.resolve()])]

    aset = json.loads(ATTACK_SET.read_text(encoding="utf-8"))
    P = load_plan(args.plan, aset)
    sources = load_sources(P, aset, args.flows_dir)
    dev = load_device_map()
    headers = {s["session"]: read_header(s["path"]) for s in sources}
    cand = candidate_features(headers)
    log(f"08_build_datasets  plan {P['version']}  sessions {len(sources)}  candidate features {len(cand)}  "
        f"{'DRY RUN' if args.dry_run else 'BUILD'}"
        + (f"  LIMIT {args.limit_rows:,} rows/file" if args.limit_rows else ""))
    for s in sources:
        log(f"  {s['session']:<18} {s['mode']:<10} {s['path']}")
    if not args.dry_run:
        for split in SPLITS:   # a failed build must not leave an older build's files next to its manifest
            for p in (args.out_dir / f"{split}.parquet", args.out_dir / f"{split}.all.parquet.tmp"):
                p.unlink(missing_ok=True)

    log("hashing inputs")
    inputs = []
    for s in sources:
        inputs.append({"session": s["session"], "path": str(s["path"]), "sha256": sha256_file(s["path"]),
                       "label_report": s["label_report"]})
    config = {"split_plan": {"path": str(args.plan), "version": P["version"], "sha256": sha256_file(args.plan)},
              "behaviour_groups": {"version": json.loads(BEHAVIOUR_GROUPS.read_text(encoding="utf-8"))["version"],
                                   "sha256": sha256_file(BEHAVIOUR_GROUPS)},
              "device_table": {"sha256": sha256_file(DEVICE_TABLE)},
              "attack_set": {"version": aset["version"], "sha256": sha256_file(ATTACK_SET)},
              "verify_lock": [{"check": n, "pass": o, "detail": d} for n, o, d in lock["checks"]],
              "code_sha256": CODE_SHA256}

    log("pass 1: counts")
    hist, ranges, drops, active = pass1(sources, dev, cand, args, t0)
    plan = build_plan(hist, active, sources, dev, P)
    C = plan["counts"]
    for r in inputs:
        r["rows"] = drops[r["session"]]["rows"]
    att = C[C["label"] == "attack"]
    M = {"dataset_version": DATASET_VERSION, "run_utc": run_utc, "argv": sys.argv, "limit_rows": args.limit_rows,
         "dry_run": args.dry_run, "plan": P, "config": config, "inputs": inputs,
         "sessions": session_rows(sources, ranges, plan, drops, P),
         "session_cuts": {k: cuts_json(v, plan["segments"][k]) for k, v in plan["cuts"].items()},
         "benign_active_hours": {"definition": "active segments (a pause > active_idle_gap_seconds between "
                                               "flow starts ends one) holding >= 1 usable benign flow start, "
                                               "clipped to the split's wall-clock window, gap windows excluded; "
                                               "FP/hour denominator",
                                 "per_session": plan["benign_hours"],
                                 "per_split": {sp: round(sum(v[sp] for v in plan["benign_hours"].values()), 4)
                                               for sp in SPLITS}},
         "benign_hours_table": hours_rows(plan),
         "gap_drops": plan["gap"].to_dict("records"), "cap_keys": plan["probs"],
         "column_names": {"timestamp": "Timestamp", "owner_device": "owner_device (key owner_mac)",
                          "owner_group": "none in the flow files: device_table.csv behaviour_group via owner_mac",
                          "device_category": "owner_category (= device_table paper_category)"}}

    if args.dry_run:
        M["totals"] = totals(C, "expected")
        M["totals_before_caps"] = totals(C, "n")
        bs = split_table(C, "n")
        ex = split_table(C, "expected")
        M["by_split_group_label_family"] = [{**{k: a[k] for k in ("split", "group", "label", "family")},
                                             "before_caps": a["n"], "expected": e["expected"]} for a, e in zip(bs, ex)]
        M["train_devices"] = device_rows(C, None)
        M["filter_drops"] = drops
        M["warnings"] = warnings_for(att.assign(n=att["expected"]), P)
        M["runtime_s"], M["peak_rss_mb"] = round(time.monotonic() - t0, 1), peak_rss_mb()
        (args.report_dir / "dry_run_v1.json").write_text(json.dumps(M, indent=1, default=str), encoding="utf-8")
        write_md(args.report_dir / "dry_run.md", "Step 8 -- dataset build DRY RUN (pass 1 + split plan)", M, False)
        log_summary(M, False)
        log(f"dry-run report: {args.report_dir / 'dry_run.md'}")
        return 0

    log("pass 2: sample + write")
    R = pass2(sources, dev, cand, plan, P, args, t0)

    const = [c for j, c in enumerate(cand) if not R["train_max"][j] > R["train_min"][j]]
    feats = [c for c in cand if c not in const]
    leaked = [c for c in feats if c in IDENTITY_COLS or IDENTITY_RE.search(c)]
    ids = {s: np.concatenate(R["ids"][s]) if R["ids"][s] else np.zeros(0, np.int64) for s in SPLITS}
    dup_in = {s: int(len(v) - len(np.unique(v))) for s, v in ids.items()}
    overlap = {f"{a}&{b}": int(len(np.intersect1d(ids[a], ids[b]))) for i, a in enumerate(SPLITS) for b in SPLITS[i + 1:]}
    order_bad = []
    for s in sources:
        sp = [(x, R["span"][(s["session"], x)]) for x in SPLITS if (s["session"], x) in R["span"]]
        for (a, sa), (b, sb) in zip(sp, sp[1:]):
            if not sa[1] < sb[0]:
                order_bad.append(f"{s['session']}: max({a}) {utc(sa[1])} >= min({b}) {utc(sb[0])}")
    pre = {k: v for k, v in R["pre"].items()}
    p1 = {tuple(r[k] for k in KEY): int(r["n"]) for r in C.to_dict("records")}
    count_diff = {"|".join(k): (p1.get(k, 0), pre.get(k, 0)) for k in set(p1) | set(pre) if p1.get(k, 0) != pre.get(k, 0)}
    checks = {
        "no row in two splits": {"pass": not any(overlap.values()) and not any(dup_in.values()),
                                 "detail": f"overlaps {overlap}, duplicate ids within a split {dup_in}"},
        "per session max(t) of each split < min(t) of the next": {"pass": not order_bad,
                                                                   "detail": "; ".join(order_bad) or "ok"},
        "no identity column in features": {"pass": not leaked, "detail": f"{leaked or 'ok'}"},
        "y matches label (y == 1 iff attack, attack_family set iff y)": {"pass": R["bad_y"] == 0,
                                                                         "detail": f"{R['bad_y']} mismatches"},
        "pass-2 pre-sample counts == pass-1 counts": {"pass": not count_diff,
                                                      "detail": f"{len(count_diff)} keys differ "
                                                                f"{dict(list(count_diff.items())[:5])}"},
        "train split not empty": {"pass": len(ids["train"]) > 0, "detail": f"{len(ids['train']):,} rows"},
    }
    hard_pass = all(c["pass"] for c in checks.values())

    post = R["post"]
    W = pd.DataFrame([{**dict(zip(KEY, k)), "written": v} for k, v in post.items()]) if post else \
        pd.DataFrame(columns=KEY + ["written"])
    CC = C.merge(W, on=KEY, how="left").fillna({"written": 0})
    CC["written"] = CC["written"].astype(int)
    bs, wr = split_table(CC, "n"), split_table(CC, "written")
    M.update({
        "totals": totals(CC, "written"),
        "by_split_group_label_family": [{**{k: a[k] for k in ("split", "group", "label", "family")},
                                         "before_caps": a["n"], "written": w["written"]} for a, w in zip(bs, wr)],
        "train_devices": device_rows(C, post), "filter_drops": R["drops"],
        "nan_inf": [{"split": s, "column": c, "nan": int(R["nan"][s][j]), "inf": int(R["inf"][s][j])}
                    for s in SPLITS for j, c in enumerate(cand) if R["nan"][s][j] or R["inf"][s][j]],
        "checks": checks, "hard_pass": hard_pass,
    })
    attw = CC[CC["label"] == "attack"]
    M["warnings"] = warnings_for(attw.assign(n=attw["written"]), P)
    if R["drops"] != drops:
        M["warnings"].append(f"filter drop counts differ between pass 1 and pass 2: {drops} vs {R['drops']}")
    mism = sum(d.get("owner_device_name_mismatch", 0) for d in drops.values())
    if mism:
        M["warnings"].append(f"{mism:,} usable rows whose owner_device differs from device_table device_name "
                             "(device_table name used)")

    if hard_pass:
        log("finalize: dropping constant-in-train columns, writing parquet")
        F = {"version": DATASET_VERSION, "created_utc": run_utc, "n_features": len(feats), "features": feats,
             "sha256": hashlib.sha256(json.dumps(feats, separators=(",", ":")).encode("utf-8")).hexdigest(),
             "sha256_of": "json.dumps(features, separators=(',', ':')) utf-8",
             "dtype": "float64", "clean": "+-inf and NaN -> 0 before the model",
             "source": "CICFlowMeter (ahlashkari 98a5eba + guard_gt0 + idle_sweeper patches, 120 s / 5 s), "
                       "column names exactly as in its CSV header",
             "dropped_identity": IDENTITY_COLS, "dropped_constant_in_train": const,
             "split_plan_sha256": config["split_plan"]["sha256"], "limit_rows": args.limit_rows}
        features_path.write_text(json.dumps(F, indent=1) + "\n", encoding="utf-8")
        M["outputs"] = finalize(R["writers"], args.out_dir, feats + OUT_META)
        M["features"] = {"n": len(feats), "sha256": F["sha256"], "path": str(features_path),
                         "dropped_identity": IDENTITY_COLS, "dropped_constant": const}
    else:
        for split in SPLITS:
            R["writers"].path(split).unlink(missing_ok=True)
        M["outputs"] = {}
        M["features"] = {"n": len(feats), "sha256": "", "path": "(not written: hard checks failed)",
                         "dropped_identity": IDENTITY_COLS, "dropped_constant": const}
    M["runtime_s"], M["peak_rss_mb"] = round(time.monotonic() - t0, 1), peak_rss_mb()
    (args.report_dir / "manifest_v1.json").write_text(json.dumps(M, indent=1, default=str), encoding="utf-8")
    write_md(args.report_dir / "summary.md", "Step 8 -- dataset build v1", M, True)
    log_summary(M, True)
    log(f"manifest: {args.report_dir / 'manifest_v1.json'}  summary: {args.report_dir / 'summary.md'}")
    if not hard_pass:
        log("HARD CHECK FAILED: " + "; ".join(f"{k}: {v['detail']}" for k, v in checks.items() if not v["pass"]))
        return 1
    return 0


def log_summary(M: dict, written: bool) -> None:
    log("\n" + "=" * 100)
    log(f"{'BUILD' if written else 'DRY RUN'} SUMMARY   runtime {M['runtime_s']:,} s   peak RSS {M['peak_rss_mb']:,} MB")
    log(f"{'session':<18} {'mode':<10} {'span_h':>6} {'act_h':>6} {'seg':>3} {'rows':>11} {'train':>10} {'val':>9} "
        f"{'test':>10} {'gap':>6} {'bh_tr':>6} {'bh_val':>6} {'bh_te':>6}  cuts")
    for r in M["sessions"]:
        log(f"{r['session']:<18} {r['mode']:<10} {r['span_h']:>6} {r['active_h']:>6} {r['segments']:>3} "
            f"{r['rows']:>11,} {r['train']:>10,} {r['val']:>9,} {r['test']:>10,} {r['gap_dropped']:>6,} "
            f"{r['benign_h_train']:>6} {r['benign_h_val']:>6} {r['benign_h_test']:>6}  {r['cuts_utc']}")
    bh = M["benign_active_hours"]["per_split"]
    log(f"\nrows per split ({'written' if written else 'expected after caps'}):")
    for r in M["totals"]:
        log(f"  {r['split']:<6} benign {r['benign']:>10,}  attack {r['attack']:>10,}  total {r['total']:>10,}  "
            f"active benign h {bh[r['split']]:8.2f}")
    col = "written" if written else "expected"
    log(f"\n{'split':<6} {'group':<4} {'label':<7} {'family':<10} {'before_caps':>12} {col:>10}")
    for r in M["by_split_group_label_family"]:
        log(f"{r['split']:<6} {r['group']:<4} {r['label']:<7} {r['family']:<10} {r['before_caps']:>12,} {r[col]:>10,}")
    if written:
        log(f"\nfeatures {M['features']['n']}  sha256 {M['features']['sha256'][:16]}...  "
            f"constant dropped: {M['features']['dropped_constant']}")
        log("hard checks: " + ("PASS" if M["hard_pass"] else "FAIL"))
        for k, v in M["checks"].items():
            log(f"  {'PASS' if v['pass'] else 'FAIL'}  {k}: {v['detail']}")
    if M["warnings"]:
        log("\n" + "!" * 100)
        for w in M["warnings"]:
            log(f"!!! WARN {w}")
        log("!" * 100)
    log("=" * 100)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
