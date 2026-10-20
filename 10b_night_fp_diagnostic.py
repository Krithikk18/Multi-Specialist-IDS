#!/usr/bin/env python
"""10b_night_fp_diagnostic.py -- EXPLORATORY / POST-HOC diagnostic of the Step 10 test false alarms.

EXPLORATORY / POST-HOC -- not part of the pre-registered evaluation. It explains the Step 10 test FPs; it
changes no result: no training, no refit, no threshold search. Scores and flags come from the frozen
results/step10/test/predictions.parquet; thresholds (T_house per system, 0.5) from config/step10_prereg.json.

Question: why is night benign (3.018 h) ~30x worse than daytime benign (18.742 h)? Hypotheses tested:
  H1  night "benign" includes benign-labelled flows INSIDE attack-session captures (attack residue / label
      noise near 07's attack windows)
  H2  device behaviour present only in the night capture
  H3  testbed-Pi flows (kept in night benign: 04 never excludes them; excluded from daytime by 07's T1 rule)

Guards (abort on any failure, before test.parquet is read): results/step10/TEST_OPENED.json exists;
results/step10/test/predictions.parquet sha256 == PRED_SHA256; config/step10_prereg.json sha256 == the
marker's prereg_sha256; test.parquet sha256 == results/step8b/manifest_v1_1.json; features_v1.json sha256
== the prereg's. The stored flags are recomputed from the stored scores and the prereg thresholds and
must match, and the night FP counts must equal results/step10/test/false_alarms.csv.

Linking test rows to their CICFlowMeter flows (for IPs / MACs / roles, metadata only; never features):
08 writes val / test benign rows unsampled and in file order. For every night test session the source
file of 08 (data/interim/flows/benign/benign_flows_tagged.csv or ATTACK_FLOWS_DIR/<stem>_labelled.csv.gz,
sha256 checked against results/step8/manifest_v1.json inputs) is re-read with 08's own iter_chunks /
usable / assign and the manifest's cut points; its benign test rows must equal the test.parquet benign rows
of that session 1:1 in order (start_ts, device and all 70 cleaned feature values exactly), else abort.
Daytime rows (08b) are not linked (0 night-style questions there; their Pi flows were excluded by 07).

Analyses (FP = y == 0 AND flagged; per system FINAL / BASELINE; at T_house, counts repeated at 0.5)
  1 FP list           fp_rows.csv: one row per FP (any system, either point) with flags, scores, session,
                      device, group, routed model, start time, linked flow metadata, interpretable features
  2 overlap           both / FINAL-only / BASELINE-only per operating point
  3 H1 sessions       fp_by_session.csv: benign rows, active benign test hours (manifest), FP, FP/hour with
                      95% Garwood CI per session; capture kind pure-benign night / attack-session / daytime.
                      FPs inside attack sessions: |start_ts - nearest 07a burst window edge| (07's attack
                      windows, 07.parse_bursts), inside window / inside 07's padded window (pad_s of the
                      07 label report), src / dst MAC a 07a victim of that session
  4 H2 devices, time  fp_by_device.csv (night / daytime / train benign rows and FPs per device);
                      fp_time_bins.csv (benign rows and FPs per session x hour-of-capture bin)
  5 H3 testbed Pi     night benign rows / FPs with a testbed_pi endpoint (device_table role) or an
                      ATTACKER_MACS endpoint (config.config, 07's T1)
  6 duplicates        09b's row hash (70 float64 values, FNV fold of pd.util.hash_array) of each FP
                      against TRAIN, confirmed by exact equality: identical vector as a train attack row /
                      as a train benign row
  7 fingerprints      09b fingerprints.csv FINGERPRINT rows (exact value per feature / family) and the two
                      tool fingerprints: SYN FWD Init Win Bytes == 512; port scan FWD Init Win Bytes == 1024
                      AND Fwd Header Length == 24

Verdict rules (VERDICT below), on FINAL at T_house (BASELINE shown alongside)
  H1  SUPPORTED if the attack-session benign FP/hour 95% CI lower bound > pure-benign night FP/hour CI upper
      bound; NOT SUPPORTED if attack-session FP/hour <= pure-benign night FP/hour; else INCONCLUSIVE
  H2  SUPPORTED if the top 3 devices hold >= 80% of the night FPs and each has >= 1,000 daytime benign rows
      with 0 daytime FPs; NOT SUPPORTED if the top 3 hold < 50%; else INCONCLUSIVE
  H3  SUPPORTED if >= 50% of the night FPs have a testbed-Pi endpoint; NOT SUPPORTED if none has; else
      INCONCLUSIVE

Outputs -> results/step10b/: summary.md, fp_rows.csv, fp_by_session.csv, fp_by_device.csv,
fp_time_bins.csv, run_meta.json, run.log. Every file carries BANNER (CSV: first line "# <banner>", read
with pandas.read_csv(path, skiprows=1)). One run at a time: flock on results/step10b/.10b_diagnostic.lock.

Exit status: 0 ok, 1 guard / link check failed, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import platform
import signal
import subprocess
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from config.config import (ATTACK_FLOWS_DIR, ATTACKER_MACS, CACHE_DIR, CONFIG_DIR, REPO_ROOT, RESULTS_DIR,
                           sha256_file)


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m08 = _load("build_datasets", "08_build_datasets.py")
m07 = _load("label_attacks", "07_label_attacks.py")
m09b = _load("leakage_checks", "09b_leakage_checks.py")
m10 = _load("evaluate", "10_evaluate.py")

BANNER = "EXPLORATORY / POST-HOC — not part of the pre-registered evaluation."
SCRIPT = "10b_night_fp_diagnostic.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
PRED_SHA256 = "af9c2789a3e408c11fd2188c8d78243a6d93227bda80ef464a4859398506d8fe"
STEP10_TEST = RESULTS_DIR / "step10" / "test"
PRED = STEP10_TEST / "predictions.parquet"
FALSE_ALARMS = STEP10_TEST / "false_alarms.csv"
MARKER = RESULTS_DIR / "step10" / "TEST_OPENED.json"
PREREG = CONFIG_DIR / "step10_prereg.json"
MANIFEST_V1 = RESULTS_DIR / "step8" / "manifest_v1.json"
MANIFEST_V11 = RESULTS_DIR / "step8b" / "manifest_v1_1.json"
SPLIT_PLAN_V1 = CONFIG_DIR / "split_plan.json"
SPLIT_PLAN_V11 = CONFIG_DIR / "split_plan_v1_1.json"
ATTACK_SET = CONFIG_DIR / "attack_set.json"
FEATURES_JSON = CONFIG_DIR / "features_v1.json"
COVERAGE_DIR = RESULTS_DIR / "step7" / "coverage"
LABEL_REPORTS = RESULTS_DIR / "step7" / "labels"
FINGERPRINTS_CSV = RESULTS_DIR / "step9" / "leakage" / "fingerprints.csv"
DATASET_DIR = CACHE_DIR / "datasets" / "v1_1"
TEST_PARQUET, TRAIN_PARQUET = DATASET_DIR / "test.parquet", DATASET_DIR / "train.parquet"
OUT = RESULTS_DIR / "step10b"
RUN_LOCK = ".10b_diagnostic.lock"

SYSTEMS = ["FINAL", "BASELINE"]
OPS = ["T_house", "0.5"]
PRED_COL = {(s, op): f"pred_{s.lower()}_{op}" for s in SYSTEMS for op in OPS}
META = ["y", "attack_family", "group", "device", "device_category", "session", "start_ts"]
DIAG = ["Src IP", "Src Port", "Dst IP", "Dst Port", "src_mac", "src_role", "src_device", "dst_mac", "dst_role",
        "dst_device", "owner_rule"]
DIAG_ATTACK = ["label_tests", "pad_only"]
PI_ROLE = "testbed_pi"
INTERPRETABLE = ["Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
                 "Total Length of Bwd Packet", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
                 "ACK Flag Count", "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Header Length",
                 "Bwd Header Length", "Fwd Seg Size Min"]
TOOL_FP = {"syn_tool": {"FWD Init Win Bytes": 512.0},
           "portscan_tool": {"FWD Init Win Bytes": 1024.0, "Fwd Header Length": 24.0}}
VERDICT = {"basis": ("FINAL", "T_house"), "h2_top_k": 3, "h2_top_share_supported": 0.8, "h2_top_share_not": 0.5,
           "h2_min_daytime_rows": 1000, "h3_share_supported": 0.5}
CHUNK, BLOCK_MB = 500_000, 32          # 08's --chunk / --block-mb defaults


# --------------------------------------------------------------------------- helpers

_LOG_PATH: Path | None = None


def log(msg: str) -> None:
    line = f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    if _LOG_PATH is not None:
        with open(_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def fatal(msg: str) -> None:
    log(f"FATAL: {msg}")
    sys.exit(1)


def rel(p) -> str:
    return m10.rel(p)


def read_json(p: Path) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def utc(t) -> str:
    return dt.datetime.fromtimestamp(float(t), dt.timezone.utc).isoformat(timespec="seconds")


def write_csv(name: str, df: pd.DataFrame) -> None:
    with open(OUT / name, "w", encoding="utf-8", newline="") as fh:
        fh.write(f"# {BANNER}\n")
        df.to_csv(fh, index=False, lineterminator="\n")


# Origin: 10_evaluate.py run_lock() (same flock pattern, own lock file name).
def run_lock(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    fh = open(d / RUN_LOCK, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        fatal(f"another {SCRIPT} holds {rel(d / RUN_LOCK)}")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}\n")
    fh.flush()
    return fh


def git_head() -> str:
    r = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=60)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def rate_ci(k: int, hours: float) -> dict:
    lo, hi = m10.garwood(k)
    h = float(hours)
    return {"fp": int(k), "hours": h, "fp_per_hour": k / h if h > 0 else math.nan,
            "fph_ci_low": lo / h if h > 0 else math.nan, "fph_ci_high": hi / h if h > 0 else math.nan}


def f3(v, nd: int = 3) -> str:
    return "N/A" if v is None or (isinstance(v, float) and math.isnan(v)) else (f"{v:.{nd}f}" if isinstance(v, float) else str(v))


# --------------------------------------------------------------------------- guards + inputs

def guards() -> dict:
    g = []

    def ok(cond: bool, name: str, detail: str = "") -> None:
        log(f"GUARD {'PASS' if cond else 'FAIL'}  {name}{': ' + detail if detail else ''}")
        g.append({"guard": name, "pass": bool(cond), "detail": detail})
        if not cond:
            fatal(f"guard failed: {name}; test.parquet not read")

    ok(MARKER.is_file(), f"{rel(MARKER)} exists")
    marker = read_json(MARKER)
    psha = sha256_file(PRED)
    ok(psha == PRED_SHA256, "Step 10 predictions.parquet sha256", psha[:16] + "...")
    prereg_sha = sha256_file(PREREG)
    ok(prereg_sha == marker["prereg_sha256"], "step10_prereg.json sha256 == TEST_OPENED marker", prereg_sha[:16] + "...")
    P = read_json(PREREG)
    ok(sha256_file(FEATURES_JSON) == P["features"]["file_sha256"], "features_v1.json sha256 == prereg")
    M11 = read_json(MANIFEST_V11)
    want = M11["outputs"]["test.parquet"]["sha256"]
    tsha = sha256_file(TEST_PARQUET)
    ok(tsha == want, "test.parquet sha256 == manifest_v1_1", tsha[:16] + "...")
    return {"guards": g, "marker": marker, "prereg": P, "prereg_sha256": prereg_sha, "pred_sha256": psha,
            "test_sha256": tsha, "M11": M11}


def load_test(feats: list[str]) -> tuple[pd.DataFrame, np.ndarray]:
    t = pq.read_table(TEST_PARQUET, columns=feats + META)
    meta = t.select(META).to_pandas()
    for c in META:
        if c not in ("y", "start_ts"):
            meta[c] = meta[c].fillna("").astype(str)
    X = np.column_stack([t.column(c).to_numpy().astype(np.float64) + 0.0 for c in feats])
    return meta, X


def flags_from_prereg(pred: pd.DataFrame, P: dict) -> dict:
    """Recompute every flag from the stored scores and the frozen prereg thresholds; must equal the stored
    pred_* columns (no threshold search)."""
    out = {}
    for s in SYSTEMS:
        sc = pred["score_final" if s == "FINAL" else "score_global"].to_numpy()
        for op in OPS:
            thr = float(P["systems"][s]["thresholds"][op])
            f = sc >= thr
            if not np.array_equal(f.astype(np.int8), pred[PRED_COL[(s, op)]].to_numpy()):
                fatal(f"{PRED_COL[(s, op)]} != score >= prereg threshold {thr!r}; STOP")
            out[(s, op)] = f
    return out


# --------------------------------------------------------------------------- linking test rows to flows

def link_session(src: dict, cuts: dict, dev: pd.DataFrame, feats: list[str]) -> pd.DataFrame:
    """Benign TEST rows of one source, in file order, via 08's own iter_chunks / usable / assign and the
    manifest's cut points; returns t, device, source_row, the 70 cleaned features and DIAG columns."""
    attack = src["kind"] == "attack"
    cols = ["Timestamp"] + m08.META_COLS + (m08.LABEL_COLS if attack else []) + DIAG + \
        (DIAG_ATTACK if attack else []) + feats
    cols = list(dict.fromkeys(cols))
    b, labels = cuts["boundaries_epoch"], cuts["splits"]
    parts = []
    for off, f in m08.iter_chunks(src["path"], cols, feats, CHUNK, BLOCK_MB, None):
        _, pos, U = m08.usable(f, src, dev, Counter())
        split = m08.assign(U["t"].to_numpy(), (b, labels))
        k = np.flatnonzero((U["label"].to_numpy(object) == "benign") & (split == "test"))
        if not len(k):
            continue
        rows = pos[k]
        X = f[feats].to_numpy(np.float64)[rows]
        X[~np.isfinite(X)] = 0.0
        D = f[DIAG + (DIAG_ATTACK if attack else [])].iloc[rows].reset_index(drop=True)
        D.insert(0, "source_row", (off + rows).astype(np.int64))
        D.insert(1, "t", U["t"].to_numpy()[k])
        D.insert(2, "device_src", U["device"].to_numpy(object)[k])
        parts.append((D, X + 0.0))
    if not parts:
        return pd.DataFrame(), np.zeros((0, len(feats)))
    return pd.concat([p[0] for p in parts], ignore_index=True), np.vstack([p[1] for p in parts])


def link_night(meta: pd.DataFrame, X: np.ndarray, feats: list[str], night_sessions: list[str]) -> tuple[pd.DataFrame, dict]:
    """Per night test session: linked flow metadata for every benign test row (indexed by test row id)."""
    M1 = read_json(MANIFEST_V1)
    aset = read_json(ATTACK_SET)
    P1 = m08.load_plan(SPLIT_PLAN_V1, aset)
    sources = {s["session"]: s for s in m08.load_sources(P1, aset, ATTACK_FLOWS_DIR)}
    inputs = {i["session"]: i for i in M1["inputs"]}
    dev = m08.load_device_map()
    y, sess = meta["y"].to_numpy(), meta["session"].to_numpy(object)
    out, info = [], {}
    for s in night_sessions:
        ids = np.flatnonzero((y == 0) & (sess == s))
        if not len(ids):
            continue
        src = sources[s]
        t0 = time.monotonic()
        fsha = sha256_file(src["path"])
        if fsha != inputs[s]["sha256"]:
            fatal(f"{s}: source {src['path']} sha256 {fsha[:16]}... != manifest_v1 inputs {inputs[s]['sha256'][:16]}...")
        D, XL = link_session(src, M1["session_cuts"][s], dev, feats)
        okn = len(D) == len(ids)
        ok = okn and np.array_equal(D["t"].to_numpy(np.int64), meta["start_ts"].to_numpy(np.int64)[ids]) \
            and np.array_equal(D["device_src"].to_numpy(object), meta["device"].to_numpy(object)[ids]) \
            and np.array_equal(XL, X[ids])
        if not ok:
            fatal(f"{s}: re-derived benign test rows ({len(D):,}) do not match test.parquet ({len(ids):,}) 1:1 "
                  "(start_ts / device / 70 features); cannot link; STOP")
        D.insert(0, "row_id", ids)
        D["session"] = s
        out.append(D)
        info[s] = {"source": rel(src["path"]), "source_sha256": fsha, "benign_test_rows": int(len(ids)),
                   "linked_exactly": True, "seconds": round(time.monotonic() - t0, 1)}
        log(f"link {s}: {len(ids):,} benign test rows == re-derived source rows (start_ts, device, 70 features "
            f"exact)  {info[s]['seconds']:.0f} s")
    L = pd.concat(out, ignore_index=True).set_index("row_id")
    return L, info


# --------------------------------------------------------------------------- analyses

def attack_windows(night_attack_sessions: list[str]) -> dict:
    """07's attack windows: 07a overall burst windows (07.parse_bursts), 07's pad (label report), victims."""
    W = {}
    for s in night_attack_sessions:
        P = read_json(COVERAGE_DIR / f"{s}_stats.json")
        overall, _ = m07.parse_bursts(P)
        R = read_json(LABEL_REPORTS / f"{s}_label_report.json")
        vic = pd.read_csv(COVERAGE_DIR / f"{s}_victims.csv", dtype=str, keep_default_na=False)
        W[s] = {"windows": overall, "pad_s": float(R["completion_key"]["pad_s"]),
                "victims": set(vic["mac"].map(m07.norm_mac)),
                "stats_sha256": sha256_file(COVERAGE_DIR / f"{s}_stats.json")}
    return W


def window_cols(t: np.ndarray, dur_s: np.ndarray, W: dict) -> dict:
    """start_ts vs the session's 07a windows: inside (start in [ws, we)), inside 07's T2 padded test (flow
    lifetime [t, t + dur + 1] overlaps [ws - pad, we + pad)), |t - nearest window edge| in s."""
    ws = np.array([w[0] for w in W["windows"]])
    we = np.array([w[1] for w in W["windows"]])
    inside = ((t[:, None] >= ws) & (t[:, None] < we)).any(1)
    lo, hi = t, t + dur_s + 1.0
    padded = ((hi[:, None] >= ws - W["pad_s"]) & (lo[:, None] < we + W["pad_s"])).any(1)
    edge = np.minimum(np.abs(t[:, None] - ws), np.abs(t[:, None] - we)).min(1)
    return {"in_attack_window": inside, "in_padded_window": padded, "nearest_window_edge_s": edge}


def row_hash(X: np.ndarray) -> np.ndarray:
    """09b row_hashes(): FNV fold of pd.util.hash_array over the 70 float64 columns (-0.0 folded)."""
    h = np.zeros(len(X), dtype=np.uint64)
    with np.errstate(over="ignore"):
        for j in range(X.shape[1]):
            h = (h ^ pd.util.hash_array(X[:, j] + 0.0)) * m09b.FNV_PRIME
    return h


def train_duplicates(Xq: np.ndarray, feats: list[str]) -> pd.DataFrame:
    t = pq.read_table(TRAIN_PARQUET, columns=feats + ["y", "attack_family"])
    Xt = np.column_stack([t.column(c).to_numpy().astype(np.float64) + 0.0 for c in feats])
    yt = t.column("y").to_numpy()
    ft = t.column("attack_family").to_pandas().fillna("").astype(str).to_numpy(object)
    ht, hq = row_hash(Xt), row_hash(Xq)
    order = np.argsort(ht, kind="stable")
    hs = ht[order]
    rows = []
    for i in range(len(Xq)):
        a, b = np.searchsorted(hs, hq[i], "left"), np.searchsorted(hs, hq[i], "right")
        cand = order[a:b]
        cand = cand[(Xt[cand] == Xq[i]).all(1)] if len(cand) else cand          # exact, not just hash
        att = cand[yt[cand] == 1]
        rows.append({"train_equal_attack": int(len(att)), "train_equal_benign": int((yt[cand] == 0).sum()),
                     "train_equal_attack_families": ";".join(sorted(set(ft[att])))})
    return pd.DataFrame(rows)


def fingerprint_cols(Xq: np.ndarray, feats: list[str], fps: pd.DataFrame) -> pd.DataFrame:
    j = {c: i for i, c in enumerate(feats)}
    out = {}
    for name, cond in TOOL_FP.items():
        out[f"fp_{name}"] = np.logical_and.reduce([Xq[:, j[c]] == v for c, v in cond.items()])
    hits = [[] for _ in range(len(Xq))]
    for (feat, fam, val), _ in fps.groupby(["feature", "attack_family", "mode_value"]):
        m = Xq[:, j[feat]] == float(val)
        for i in np.flatnonzero(m):
            hits[i].append(f"{feat}={float(val):g} ({fam})")
    out["fingerprints_matched"] = ["; ".join(h) for h in hits]
    return pd.DataFrame(out)


def capture_kind(s: str, sinfo: dict) -> str:
    if s in sinfo["daytime_sessions"]:
        return "daytime (pure benign)"
    return "night pure-benign capture" if s == "benign_night" else "night attack-session capture"


# --------------------------------------------------------------------------- main

def main() -> int:
    global _LOG_PATH
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.parse_args()
    t_run = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lock = run_lock(OUT)
    (OUT / "run.log").unlink(missing_ok=True)
    _LOG_PATH = OUT / "run.log"
    log(f"# {BANNER}")
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...")
    G = guards()
    P, M11 = G["prereg"], G["M11"]
    feats = list(read_json(FEATURES_JSON)["features"])
    plan = read_json(SPLIT_PLAN_V11)
    M1 = read_json(MANIFEST_V1)
    sinfo = m10.session_info(plan, M1, "test")
    rt = {}

    # ---- test rows + frozen predictions
    t = time.monotonic()
    meta, X = load_test(feats)
    pred = pq.read_table(PRED).to_pandas()
    if not (np.array_equal(pred["row_id"].to_numpy(), np.arange(len(meta)))
            and np.array_equal(pred["y"].to_numpy(), meta["y"].to_numpy())
            and (pred["session"].to_numpy(object) == meta["session"].to_numpy(object)).all()
            and (pred["group"].to_numpy(object) == meta["group"].to_numpy(object)).all()):
        fatal("predictions.parquet rows do not line up with test.parquet (row_id / y / session / group); STOP")
    flags = flags_from_prereg(pred, P)
    period = m10.benign_period(meta, sinfo)
    y = meta["y"].to_numpy()
    ben = y == 0
    FP = {k: ben & f for k, f in flags.items()}
    fa = pd.read_csv(FALSE_ALARMS, dtype={"operating_point": str})
    for (s, op), m in FP.items():
        for p in ("night", "daytime"):
            want = fa[(fa.system == s) & (fa.operating_point == op) & (fa.breakdown == "period") & (fa.key == p)]["fp"]
            got = int((m & (period == p)).sum())
            if len(want) != 1 or int(want.iloc[0]) != got:
                fatal(f"{s} @ {op} {p} FP {got} != results/step10 false_alarms.csv {want.tolist()}; STOP")
    log("flags == score >= prereg thresholds; FP counts per period == results/step10/test/false_alarms.csv")
    rt["load_s"] = round(time.monotonic() - t, 1)

    # ---- link night benign rows to their flows
    t = time.monotonic()
    night_sessions = [s for s in sinfo["night_sessions"]]
    L, link_info = link_night(meta, X, feats, night_sessions)
    rt["link_s"] = round(time.monotonic() - t, 1)
    night_att = [s for s in link_info if s != "benign_night"]
    W = attack_windows(night_att)
    j = {c: i for i, c in enumerate(feats)}

    # ---- per-row diagnostics for every night benign row (context) + FP rows
    sess = meta["session"].to_numpy(object)
    nb_ids = np.flatnonzero(ben & (period == "night"))
    NB = L.loc[nb_ids].copy()
    NB["pi_involved"] = ((NB["src_role"] == PI_ROLE) | (NB["dst_role"] == PI_ROLE)
                         | NB["src_mac"].map(ATTACKER_MACS.matches) | NB["dst_mac"].map(ATTACKER_MACS.matches))
    for c in ("in_attack_window", "in_padded_window", "src_victim", "dst_victim"):
        NB[c] = False
    NB["nearest_window_edge_s"] = np.nan
    for s in night_att:
        ix = NB.index[NB["session"] == s].to_numpy()
        wc = window_cols(meta["start_ts"].to_numpy(float)[ix], X[ix, j["Flow Duration"]] / 1e6, W[s])
        for c, v in wc.items():
            NB.loc[ix, c] = v
        NB.loc[ix, "src_victim"] = NB.loc[ix, "src_mac"].map(m07.norm_mac).isin(W[s]["victims"]).to_numpy()
        NB.loc[ix, "dst_victim"] = NB.loc[ix, "dst_mac"].map(m07.norm_mac).isin(W[s]["victims"]).to_numpy()

    any_fp = np.logical_or.reduce(list(FP.values()))
    fp_ids = np.flatnonzero(any_fp)
    R = pd.DataFrame({"row_id": fp_ids})
    for (s, op) in FP:
        R[f"fp_{s.lower()}_{op}"] = FP[(s, op)][fp_ids]

    def who(op: str) -> np.ndarray:
        a, b = FP[("FINAL", op)][fp_ids], FP[("BASELINE", op)][fp_ids]
        return np.where(a & b, "both", np.where(a, "FINAL only", np.where(b, "BASELINE only", "-")))

    R["systems_T_house"], R["systems_0.5"] = who("T_house"), who("0.5")
    R["score_final"], R["score_global"] = pred["score_final"].to_numpy()[fp_ids], pred["score_global"].to_numpy()[fp_ids]
    for c in ("session", "device", "device_category", "group"):
        R[c] = meta[c].to_numpy(object)[fp_ids]
    R["routed_model"] = pred["routed_model"].to_numpy(object)[fp_ids]
    R["period"] = period[fp_ids]
    R["capture_kind"] = [capture_kind(s, sinfo) for s in R["session"]]
    R["start_ts"] = meta["start_ts"].to_numpy()[fp_ids]
    R["start_utc"] = [utc(x) for x in R["start_ts"]]
    lk = ["source_row", *DIAG, *DIAG_ATTACK, "pi_involved", "in_attack_window", "in_padded_window",
          "nearest_window_edge_s", "src_victim", "dst_victim"]
    J = NB.reindex(fp_ids)[lk].reset_index(drop=True)
    R = pd.concat([R, J], axis=1)
    t = time.monotonic()
    R = pd.concat([R, train_duplicates(X[fp_ids], feats), fingerprint_cols(X[fp_ids], feats,
                   (fpdf := pd.read_csv(FINGERPRINTS_CSV))[lambda d: d["flag"] == "FINGERPRINT"])], axis=1)
    rt["duplicates_s"] = round(time.monotonic() - t, 1)
    for c in INTERPRETABLE:
        R[c] = X[fp_ids, j[c]]
    write_csv("fp_rows.csv", R)

    # ---- overlap
    overlap = {op: {k: int(v) for k, v in pd.Series(who(op)).value_counts().items() if k != "-"} for op in OPS}
    log(f"overlap: {overlap}")

    # ---- H1: per session
    h_night = M1["benign_active_hours"]["per_session"]
    h_day = M11["hours"]["per_session"]
    S = []
    for s in list(sinfo["night_sessions"]) + list(sinfo["daytime_sessions"]):
        m = ben & (sess == s)
        if not m.any():
            continue
        hours = float(h_day[s]) if s in h_day else float(h_night[s]["test"])
        r = {"session": s, "alias": plan["session_aliases"].get(s, s), "capture_kind": capture_kind(s, sinfo),
             "period": period[m][0], "benign_rows": int(m.sum()), "active_benign_hours_test": hours}
        if s in link_info:
            nb = NB[NB["session"] == s]
            r.update({"pi_involved_rows": int(nb["pi_involved"].sum()),
                      "rows_in_attack_window": int(nb["in_attack_window"].sum()) if s in W else "N/A",
                      "rows_in_padded_window": int(nb["in_padded_window"].sum()) if s in W else "N/A",
                      "rows_touching_victim": int((nb["src_victim"] | nb["dst_victim"]).sum()) if s in W else "N/A"})
        for (sy, op), f in FP.items():
            q = rate_ci(int((f & m).sum()), hours)
            r.update({f"{k}_{sy.lower()}_{op}": v for k, v in q.items() if k != "hours"})
        S.append(r)
    S = pd.DataFrame(S)
    # pooled kinds (the H1 comparison)
    kinds = {}
    for kind in ("night pure-benign capture", "night attack-session capture", "daytime (pure benign)"):
        ss = S[S["capture_kind"] == kind]
        h = float(ss["active_benign_hours_test"].sum())
        kinds[kind] = {"sessions": ss["session"].tolist(), "benign_rows": int(ss["benign_rows"].sum()), "hours": h,
                       **{f"{sy}@{op}": rate_ci(int(ss[f"fp_{sy.lower()}_{op}"].sum()), h) for sy in SYSTEMS for op in OPS}}
    pooled = pd.DataFrame([{"session": f"POOLED: {k}", "alias": "", "capture_kind": k, "period": "",
                            "benign_rows": v["benign_rows"], "active_benign_hours_test": v["hours"],
                            **{f"{kk}_{sy.lower()}_{op}": vv for sy in SYSTEMS for op in OPS
                               for kk, vv in v[f"{sy}@{op}"].items() if kk != "hours"}}
                           for k, v in kinds.items()])
    write_csv("fp_by_session.csv", pd.concat([S, pooled], ignore_index=True))

    # ---- H2: devices + time bins
    tr = pq.read_table(TRAIN_PARQUET, columns=["y", "device"]).to_pandas()
    tr_ben = tr.loc[tr["y"] == 0, "device"].value_counts()
    devs = sorted(set(meta.loc[ben, "device"]))
    D = []
    for d in devs:
        md = ben & (meta["device"].to_numpy(object) == d)
        r = {"device": d, "device_category": meta.loc[md, "device_category"].iloc[0], "group": meta.loc[md, "group"].iloc[0],
             "train_benign_rows": int(tr_ben.get(d, 0)), "night_benign_rows": int((md & (period == "night")).sum()),
             "daytime_benign_rows": int((md & (period == "daytime")).sum())}
        for (sy, op), f in FP.items():
            r[f"night_fp_{sy.lower()}_{op}"] = int((f & md & (period == "night")).sum())
            r[f"daytime_fp_{sy.lower()}_{op}"] = int((f & md & (period == "daytime")).sum())
        D.append(r)
    D = pd.DataFrame(D)
    bs, bo = VERDICT["basis"]
    key = f"night_fp_{bs.lower()}_{bo}"
    D = D.sort_values([key, "night_benign_rows"], ascending=[False, False]).reset_index(drop=True)
    write_csv("fp_by_device.csv", D)

    sess_start = {x["session"]: x["start_utc"] for x in M1["sessions"]}
    sess_start.update({x["session"]: x["start_utc"] for x in M11["sessions"]})
    st0 = np.array([pd.Timestamp(sess_start[s]).timestamp() for s in sess], dtype=float)
    hb = np.floor((meta["start_ts"].to_numpy(float) - st0) / 3600).astype(np.int64)
    B = pd.DataFrame({"session": sess, "hour_bin": hb, "ben": ben, "period": period})
    for (sy, op), f in FP.items():
        B[f"fp_{sy.lower()}_{op}"] = f
    B = B[B["ben"]]
    TB = (B.groupby(["session", "period", "hour_bin"], sort=True)
          .agg(benign_rows=("ben", "size"), **{c: (c, "sum") for c in B.columns if c.startswith("fp_")}).reset_index())
    TB.insert(3, "bin_start_utc", [utc(pd.Timestamp(sess_start[s]).timestamp() + 3600 * h)
                                   for s, h in zip(TB["session"], TB["hour_bin"])])
    TB["capture_kind"] = [capture_kind(s, sinfo) for s in TB["session"]]
    write_csv("fp_time_bins.csv", TB)

    # ---- verdicts (FINAL @ T_house basis; BASELINE alongside)
    def verdicts(sy: str, op: str) -> dict:
        tag = f"{sy}@{op}"
        pure, att = kinds["night pure-benign capture"][tag], kinds["night attack-session capture"][tag]
        if att["fph_ci_low"] > pure["fph_ci_high"]:
            h1 = "SUPPORTED"
        elif att["fp_per_hour"] <= pure["fp_per_hour"]:
            h1 = "NOT SUPPORTED"
        else:
            h1 = "INCONCLUSIVE"
        k = f"night_fp_{sy.lower()}_{op}"
        n_night = int(D[k].sum())
        top = D.sort_values(k, ascending=False).head(VERDICT["h2_top_k"])
        share = float(top[k].sum() / n_night) if n_night else math.nan
        day_ok = bool(((top["daytime_benign_rows"] >= VERDICT["h2_min_daytime_rows"])
                       & (top[f"daytime_fp_{sy.lower()}_{op}"] == 0)).all())
        if n_night and share >= VERDICT["h2_top_share_supported"] and day_ok:
            h2 = "SUPPORTED"
        elif n_night and share < VERDICT["h2_top_share_not"]:
            h2 = "NOT SUPPORTED"
        else:
            h2 = "INCONCLUSIVE"
        fpn = FP[(sy, op)] & (period == "night")
        n_pi = int(NB.loc[np.flatnonzero(fpn), "pi_involved"].sum())
        pi_share = n_pi / n_night if n_night else math.nan
        h3 = ("SUPPORTED" if n_night and pi_share >= VERDICT["h3_share_supported"]
              else ("NOT SUPPORTED" if n_pi == 0 else "INCONCLUSIVE"))
        tb = TB[TB["period"] == "night"]
        mx = tb.loc[tb[f"fp_{sy.lower()}_{op}"].idxmax()] if n_night else None
        return {"n_night_fp": n_night, "H1": h1, "pure": pure, "attack_sessions": att,
                "daytime": kinds["daytime (pure benign)"][tag],
                "H2": h2, "top_devices": top[["device", "device_category", k, "night_benign_rows", "daytime_benign_rows",
                                              f"daytime_fp_{sy.lower()}_{op}", "train_benign_rows"]].to_dict("records"),
                "top_share": share, "n_devices_with_fp": int((D[k] > 0).sum()),
                "max_hour_bin": None if mx is None else {"session": mx["session"], "bin_start_utc": mx["bin_start_utc"],
                                                         "fp": int(mx[f"fp_{sy.lower()}_{op}"]),
                                                         "share": float(mx[f"fp_{sy.lower()}_{op}"] / n_night)},
                "H3": h3, "n_pi_fp": n_pi, "pi_share": pi_share}

    V = {f"{sy}@{op}": verdicts(sy, op) for sy in SYSTEMS for op in OPS}

    # ---- duplicates / fingerprints / H3 context summaries
    def counts(mask_rows: pd.DataFrame) -> dict:
        return {"n": int(len(mask_rows)), "train_equal_attack": int((mask_rows["train_equal_attack"] > 0).sum()),
                "train_equal_benign": int((mask_rows["train_equal_benign"] > 0).sum()),
                "train_equal_both": int(((mask_rows["train_equal_attack"] > 0) & (mask_rows["train_equal_benign"] > 0)).sum()),
                "fp_syn_tool": int(mask_rows["fp_syn_tool"].sum()), "fp_portscan_tool": int(mask_rows["fp_portscan_tool"].sum()),
                "any_09b_fingerprint": int((mask_rows["fingerprints_matched"] != "").sum())}

    DUP = {f"{sy}@{op}": counts(R[R[f"fp_{sy.lower()}_{op}"]]) for sy in SYSTEMS for op in OPS}
    Xn = X[nb_ids]
    fpc = fingerprint_cols(Xn, feats, fpdf[fpdf["flag"] == "FINGERPRINT"])
    ctx_fp = {"night_benign_rows": int(len(nb_ids)), "fp_syn_tool": int(fpc["fp_syn_tool"].sum()),
              "fp_portscan_tool": int(fpc["fp_portscan_tool"].sum())}
    dX = X[np.flatnonzero(ben & (period == "daytime"))]
    dfc = fingerprint_cols(dX, feats, fpdf[fpdf["flag"] == "FINGERPRINT"])
    ctx_fp.update({"daytime_benign_rows": int(len(dX)), "daytime_fp_syn_tool": int(dfc["fp_syn_tool"].sum()),
                   "daytime_fp_portscan_tool": int(dfc["fp_portscan_tool"].sum())})
    pi_ctx = {"night_benign_rows": int(len(NB)), "night_pi_rows": int(NB["pi_involved"].sum()),
              "by_session": {s: int(NB.loc[NB["session"] == s, "pi_involved"].sum()) for s in link_info},
              "daytime_07_excluded": {x["session"]: x["excluded_by_reason"] for x in M11["labels07"]}}
    pi_rate = {}
    for (sy, op), f in FP.items():
        fn = f[nb_ids]
        pi = NB["pi_involved"].to_numpy(bool)
        pi_rate[f"{sy}@{op}"] = {"fp_pi": int((fn & pi).sum()), "rows_pi": int(pi.sum()),
                                 "fp_non_pi": int((fn & ~pi).sum()), "rows_non_pi": int((~pi).sum())}
    att_fp = {}
    for sy in SYSTEMS:
        rr = R[R[f"fp_{sy.lower()}_T_house"] & (R["capture_kind"] == "night attack-session capture")]
        att_fp[sy] = {"n": int(len(rr)), "in_attack_window": int(rr["in_attack_window"].sum()),
                      "in_padded_window": int(rr["in_padded_window"].sum()),
                      "touching_victim": int((rr["src_victim"] | rr["dst_victim"]).sum()),
                      "edge_s_median": float(rr["nearest_window_edge_s"].median()) if len(rr) else math.nan,
                      "edge_s_min": float(rr["nearest_window_edge_s"].min()) if len(rr) else math.nan,
                      "edge_s_max": float(rr["nearest_window_edge_s"].max()) if len(rr) else math.nan}

    meta_out = {"banner": BANNER, "script": SCRIPT, "code_sha256": CODE_SHA256, "run_utc": run_utc, "git_head": git_head(),
                "argv": sys.argv, "guards": G["guards"],
                "inputs_sha256": {"predictions.parquet": G["pred_sha256"], "test.parquet": G["test_sha256"],
                                  "step10_prereg.json": G["prereg_sha256"],
                                  **{rel(p): sha256_file(p) for p in (MARKER, FALSE_ALARMS, MANIFEST_V1, MANIFEST_V11,
                                                                       SPLIT_PLAN_V1, SPLIT_PLAN_V11, ATTACK_SET, FEATURES_JSON,
                                                                       FINGERPRINTS_CSV, TRAIN_PARQUET,
                                                                       CONFIG_DIR / "device_table.csv")},
                                  "07a_stats": {s: w["stats_sha256"] for s, w in W.items()},
                                  "08_sources": {s: i["source_sha256"] for s, i in link_info.items()},
                                  "imported": {f: sha256_file(REPO_ROOT / f) for f in
                                               ("08_build_datasets.py", "07_label_attacks.py", "09b_leakage_checks.py",
                                                "10_evaluate.py", "config/config.py")}},
                "thresholds": {s: P["systems"][s]["thresholds"] for s in SYSTEMS}, "link": link_info,
                "attack_windows": {s: {"n_windows": len(w["windows"]), "pad_s": w["pad_s"], "victims": sorted(w["victims"]),
                                       "windows_utc": [[utc(a), utc(b)] for a, b in w["windows"]]} for s, w in W.items()},
                "overlap": overlap, "pooled": kinds, "verdicts": V, "verdict_rules": VERDICT, "duplicates_fingerprints": DUP,
                "fingerprint_context": ctx_fp, "pi_context": pi_ctx, "pi_rate": pi_rate, "attack_session_fps": att_fp,
                "versions": m10.lib_versions(), "platform": {"system": platform.system(), "release": platform.release()}}
    rt["total_s"] = round(time.monotonic() - t_run, 1)
    meta_out["runtimes_s"] = rt
    (OUT / "run_meta.json").write_text(json.dumps(meta_out, indent=1, default=lambda o: o.item() if hasattr(o, "item")
                                                  else str(o)) + "\n", encoding="utf-8")
    write_summary(meta_out, R, S, kinds, D)
    log(f"done in {rt['total_s']:.0f} s -> {rel(OUT)}/summary.md")
    lock.close()
    return 0


def write_summary(M: dict, R: pd.DataFrame, S: pd.DataFrame, kinds: dict, D: pd.DataFrame) -> None:
    md = m10.md_table
    V, bs = M["verdicts"], "FINAL@T_house"
    L = [f"# Step 10b -- night false-alarm diagnostic", "", f"**{BANNER}**", "",
         f"- run {M['run_utc']}, git HEAD `{M['git_head']}`, {SCRIPT} sha256 `{CODE_SHA256[:16]}...`; frozen inputs: "
         f"predictions.parquet `{M['inputs_sha256']['predictions.parquet'][:16]}...`, test.parquet "
         f"`{M['inputs_sha256']['test.parquet'][:16]}...`, prereg `{M['inputs_sha256']['step10_prereg.json'][:16]}...`",
         f"- thresholds (prereg, unchanged): " + "; ".join(f"{s} T_house {M['thresholds'][s]['T_house']!r}, 0.5"
                                                        for s in SYSTEMS),
         "- no training, no refit, no threshold search; every flag recomputed from the stored scores and checked "
         "against predictions.parquet; FP counts == results/step10/test/false_alarms.csv",
         "- night benign rows linked 1:1 to their CICFlowMeter flows via 08's own filter (" +
         ", ".join(f"{s} {i['benign_test_rows']:,}" for s, i in M["link"].items()) + "; start_ts, device and all 70 "
         "features equal); IP / MAC / role are diagnostic metadata only", ""]
    L += ["## Short answers (FINAL @ T_house; BASELINE @ T_house in brackets)", ""]
    v, b = V[bs], V["BASELINE@T_house"]
    p, a, d = v["pure"], v["attack_sessions"], v["daytime"]
    L += [f"- **H1 attack-session residue: {v['H1']}** [{b['H1']}]. Night pure-benign capture "
          f"(benign_night): {p['fp']} FP / {p['hours']:.3f} h = {f3(p['fp_per_hour'])}/h [{f3(p['fph_ci_low'])}, "
          f"{f3(p['fph_ci_high'])}]; night attack-session captures ({', '.join(kinds['night attack-session capture']['sessions'])}): "
          f"{a['fp']} FP / {a['hours']:.3f} h = {f3(a['fp_per_hour'])}/h [{f3(a['fph_ci_low'])}, {f3(a['fph_ci_high'])}]; "
          f"daytime: {d['fp']} FP / {d['hours']:.3f} h = {f3(d['fp_per_hour'])}/h [{f3(d['fph_ci_low'])}, "
          f"{f3(d['fph_ci_high'])}]. Attack-session FPs: {M['attack_session_fps']['FINAL']['n']} "
          f"(inside a 07a window {M['attack_session_fps']['FINAL']['in_attack_window']}, inside 07's padded window "
          f"{M['attack_session_fps']['FINAL']['in_padded_window']}, touching a 07a victim "
          f"{M['attack_session_fps']['FINAL']['touching_victim']}; |start - nearest window edge| median "
          f"{f3(M['attack_session_fps']['FINAL']['edge_s_median'], 0)} s, range "
          f"{f3(M['attack_session_fps']['FINAL']['edge_s_min'], 0)}-{f3(M['attack_session_fps']['FINAL']['edge_s_max'], 0)} s).",
          f"- **H2 night-only device behaviour: {v['H2']}** [{b['H2']}]. {v['n_night_fp']} night FPs on "
          f"{v['n_devices_with_fp']} devices; top {VERDICT['h2_top_k']} hold {f3(v['top_share'])} ("
          + "; ".join(f"{x['device']} ({x['device_category']}) {x[f'night_fp_final_T_house']} FP of "
                      f"{x['night_benign_rows']:,} night rows, daytime {x['daytime_benign_rows']:,} rows / "
                      f"{x['daytime_fp_final_T_house']} FP, train {x['train_benign_rows']:,}" for x in v["top_devices"])
          + f"). Busiest hour bin: {v['max_hour_bin']['session']} from {v['max_hour_bin']['bin_start_utc']} with "
            f"{v['max_hour_bin']['fp']} FP ({f3(v['max_hour_bin']['share'])} of night FPs).",
          f"- **H3 testbed-Pi flows: {v['H3']}** [{b['H3']}]. {v['n_pi_fp']} of {v['n_night_fp']} night FPs have a "
          f"testbed-Pi / attacker-MAC endpoint; night benign rows with one: {M['pi_context']['night_pi_rows']:,} of "
          f"{M['pi_context']['night_benign_rows']:,} (by session {M['pi_context']['by_session']}); FP rate Pi rows "
          f"{M['pi_rate'][bs]['fp_pi']}/{M['pi_rate'][bs]['rows_pi']:,} vs non-Pi {M['pi_rate'][bs]['fp_non_pi']}/"
          f"{M['pi_rate'][bs]['rows_non_pi']:,}. Daytime: 07 excluded Pi flows ({M['pi_context']['daytime_07_excluded']}).",
          ""]
    L += ["## Overlap of the two systems' FPs", ""]
    L += md(R_overlap := [{"operating point": op, **{k: M["overlap"][op].get(k, 0) for k in ("both", "FINAL only", "BASELINE only")}}
                          for op in OPS], ["operating point", "both", "FINAL only", "BASELINE only"])
    L += ["", "## H1: benign rows and FPs by session (test split)", ""]
    cols = ["session", "capture_kind", "benign_rows", "active_benign_hours_test", "pi_involved_rows",
            "rows_in_attack_window", "FINAL@T_house", "BASELINE@T_house", "FINAL@0.5", "BASELINE@0.5"]
    rows = []
    for _, r in S.iterrows():
        x = {c: r.get(c, "") for c in cols[:6]}
        x["active_benign_hours_test"] = f"{r['active_benign_hours_test']:.3f}"
        for c in ("pi_involved_rows", "rows_in_attack_window"):
            x[c] = "" if pd.isna(r.get(c, np.nan)) else r[c]
        for sy in SYSTEMS:
            for op in OPS:
                k = f"_{sy.lower()}_{op}"
                x[f"{sy}@{op}"] = (f"{int(r['fp' + k])} -> {f3(r['fp_per_hour' + k])}/h "
                                   f"[{f3(r['fph_ci_low' + k])}, {f3(r['fph_ci_high' + k])}]")
        rows.append(x)
    for kind, kv in kinds.items():
        x = {"session": f"**pooled**", "capture_kind": kind, "benign_rows": kv["benign_rows"],
             "active_benign_hours_test": f"{kv['hours']:.3f}"}
        for sy in SYSTEMS:
            for op in OPS:
                q = kv[f"{sy}@{op}"]
                x[f"{sy}@{op}"] = f"{q['fp']} -> {f3(q['fp_per_hour'])}/h [{f3(q['fph_ci_low'])}, {f3(q['fph_ci_high'])}]"
        rows.append(x)
    L += md(rows, cols)
    L += ["", "## H2: night FPs by device (FINAL @ T_house; full table fp_by_device.csv)", ""]
    dd = D[(D["night_fp_final_T_house"] > 0) | (D["night_fp_baseline_T_house"] > 0)]
    L += md(dd.to_dict("records"), ["device", "device_category", "group", "night_fp_final_T_house",
                                    "night_fp_baseline_T_house", "night_fp_final_0.5", "night_benign_rows",
                                    "daytime_benign_rows", "daytime_fp_final_0.5", "train_benign_rows"])
    L += ["", "Time: fp_time_bins.csv (benign rows and FPs per session x hour since capture start).", "",
          "## Duplicates (exact 70-feature vector in TRAIN, 09b row hash + exact check) and 09b fingerprints", ""]
    L += md([{"FPs of": k, **x} for k, x in M["duplicates_fingerprints"].items()],
            ["FPs of", "n", "train_equal_attack", "train_equal_benign", "train_equal_both", "fp_syn_tool",
             "fp_portscan_tool", "any_09b_fingerprint"])
    c = M["fingerprint_context"]
    L += ["", f"Context: night benign rows {c['night_benign_rows']:,} with the SYN tool value {c['fp_syn_tool']:,}, "
              f"port-scan tool value {c['fp_portscan_tool']:,}; daytime benign {c['daytime_benign_rows']:,} with "
              f"{c['daytime_fp_syn_tool']:,} / {c['daytime_fp_portscan_tool']:,}. Tool fingerprints: SYN = FWD Init Win "
              "Bytes 512; port scan = FWD Init Win Bytes 1024 AND Fwd Header Length 24 (09b fingerprints.csv).", "",
          "## FP rows (FINAL or BASELINE @ T_house)", ""]
    th = R[R["fp_final_T_house"] | R["fp_baseline_T_house"]]
    L += md(th.assign(score_final=th["score_final"].map(lambda v: f"{v:.4f}"),
                      score_global=th["score_global"].map(lambda v: f"{v:.4f}"),
                      edge=th["nearest_window_edge_s"].map(lambda v: "" if pd.isna(v) else f"{v:.0f}")).to_dict("records"),
            ["row_id", "systems_T_house", "score_final", "score_global", "session", "device", "start_utc", "src_role",
             "dst_role", "Dst Port", "Protocol", "pi_involved", "in_attack_window", "edge", "train_equal_attack",
             "train_equal_benign", "fp_syn_tool", "fp_portscan_tool"])
    L += ["", "## Verdict rules (fixed in the script, VERDICT)", "",
          "- H1 SUPPORTED if the pooled attack-session benign FP/h 95% CI lower bound > the pure-benign night FP/h CI upper "
          "bound; NOT SUPPORTED if attack-session FP/h <= pure-benign night FP/h; else INCONCLUSIVE.",
          f"- H2 SUPPORTED if the top {VERDICT['h2_top_k']} devices hold >= {VERDICT['h2_top_share_supported']:.0%} of night FPs "
          f"and each has >= {VERDICT['h2_min_daytime_rows']:,} daytime benign rows with 0 daytime FPs; NOT SUPPORTED if "
          f"they hold < {VERDICT['h2_top_share_not']:.0%}; else INCONCLUSIVE. Feature values alone cannot show that a "
          "behaviour is absent by day, so SUPPORTED means 'a few devices that are quiet by day'.",
          f"- H3 SUPPORTED if >= {VERDICT['h3_share_supported']:.0%} of night FPs have a testbed-Pi endpoint "
          "(device_table role testbed_pi or config ATTACKER_MACS); NOT SUPPORTED if none; else INCONCLUSIVE.",
          "- Hours: night per session = results/step8/manifest_v1.json benign_active_hours per_session test; daytime = "
          "manifest_v1_1 hours per_session. Small-count CIs are wide (Garwood 95%).",
          "", f"*{BANNER}*"]
    (OUT / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        log("UNEXPECTED ERROR\n" + traceback.format_exc())
        sys.exit(2)
