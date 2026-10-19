#!/usr/bin/env python
"""10_evaluate.py -- Step 10: the ONE-TIME test evaluation of the two pre-registered systems.

Systems (pre-registered; only these two are compared)
  FINAL     XGB specialists G1 + G2 (config/groupings/behaviour_k2.json = the v1.0 lock), each trained
            shared_attack (the group's TRAIN benign rows + every TRAIN attack row of every device), plus the
            GLOBAL XGB (every TRAIN row) as fallback. Routing by the row's group column: G1 -> G1, G2 -> G2,
            GEN -> GLOBAL (unregistered MACs of 08b are group GEN, device_category unregistered_mac).
  BASELINE  the same GLOBAL XGB scores every row.
  XGB = 09's build_model / fit_model (imported): library defaults + scale_pos_weight = n_benign / n_attack
  of the model's own training rows, random_state 42, n_jobs -1. Fit on TRAIN only. Training sets are
  09 strategies' fit_rows() for behaviour_k2 / shared_attack and global (copied, see train_models).

Operating points (per system, both fixed on VAL only)
  T_house   09 strategies' common threshold: the lowest observed house val score with <= STRAT max_fp (2)
            FP on the whole house's val benign (09 max_fp_threshold, imported)
  0.5       default threshold
  A row is flagged attack iff score >= threshold.

Modes
  --mode dryrun  Never opens a test file. Trains G1, G2, GLOBAL on TRAIN, saves them to
                 ~/lgids_cache/models/step10/ (sha256 recorded), picks T_house per system on VAL, runs the
                 full report with VAL standing in for test (same functions as test mode) into
                 results/step10/dryrun/, then the sanity checks (PASS / FAIL):
                   val FP at T_house <= 2 (both systems); val numbers == results/step9/strategies (global,
                   behaviour_k2 shared_attack; score sha256 exact); Garwood CI self-test; models reloaded
                   from disk reproduce the in-memory val scores exactly; routing coverage.
                 Only if every check passes: config/step10_prereg.json is written. Refuses to run once
                 results/step10/TEST_OPENED.json exists (the prereg is frozen from then on).
  --mode test    ONE run, started by hand. Guards, all before test.parquet is opened (any failure: exit 1):
                   results/step10/TEST_OPENED.json absent; run lock; git: no modified / staged tracked file,
                   config/step10_prereg.json tracked and identical to HEAD; sha256 of 10_evaluate.py, every
                   model file, features_v1.json and the other inputs listed in the prereg match; xgboost
                   version == prereg; verify_lock(); fitting disabled (XGBClassifier.fit, xgboost.train and
                   09's fit_model / build_model replaced by a function that raises).
                 Then TEST_OPENED.json is created (O_CREAT | O_EXCL; never deleted or overwritten), the
                 test.parquet sha256 is checked against manifest_v1_1.json, models and thresholds are loaded
                 from the prereg (no training, no threshold search) and the report goes to results/step10/test/.

Training filter: owner_status == "owned" AND exclude_reason == "" AND label != "excluded". 08 / 08b applied it
when the parquet files were built; they hold exactly features_v1 + 09 META_COLS (asserted per split), so, as in
09, no runtime filter exists and 0 rows are dropped per split (logged).

Reports (same functions for dryrun-on-val and test), in results/step10/<dryrun|test>/
  detection_by_family.csv        system x operating point x attack_family (+ ALL): n, detected, DR, flag
  detection_by_session.csv       ... x attack session (split_plan_v1_1 names): n, detected, DR, flag
  detection_by_family_group.csv  ... x attack_family x group (G1 / G2 / GEN): n, detected, DR, flag
                                 flag LOW_N when 0 < n < 50, N/A when n == 0
  false_alarms.csv               FP count, FP/hour and 95% exact (Garwood) Poisson CI for night / daytime /
                                 combined benign (active benign hours: manifest_v1_1.json for test, 09's val
                                 hours for val); FP counts by group and by device_category
  predictions.parquet            one row per evaluated row (row_id = position in the split parquet)
  run_meta.json, summary.md, run.log
Night vs daytime benign is told apart by session: split_plan_v1_1 test_only_sessions (BenignTraffic1-3) =
daytime, every other plan session = night; a benign row of any other session stops the run.

Exit status: 0 ok, 1 guard / check failed, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.metadata
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
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from scipy.stats import chi2

from config.config import CACHE_DIR, CONFIG_DIR, REPO_ROOT, RESULTS_DIR, LockError, sha256_file, verify_lock


# Step 9 code is imported, not re-implemented (file name starts with a digit -> load by path).
def _load_step09():
    spec = importlib.util.spec_from_file_location("step09_train_specialists", REPO_ROOT / "09_train_specialists.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s09 = _load_step09()

# --------------------------------------------------------------------------- CONFIG

STEP10 = {
    "seed": 42,
    "model": "XGB",
    "model_note": "09 build_model / fit_model: XGBoost library defaults + scale_pos_weight = n_benign / n_attack of "
                  "the model's own training rows, random_state 42, n_jobs -1; 70 features (features_v1.json order, "
                  "float32); no search",
    "models": ["G1", "G2", "GLOBAL"],
    "training_sets": {"G1": "shared_attack: TRAIN benign rows of group G1 (behaviour_k2) + every TRAIN attack row",
                      "G2": "shared_attack: TRAIN benign rows of group G2 (behaviour_k2) + every TRAIN attack row",
                      "GLOBAL": "every TRAIN row"},
    "systems": {"FINAL": {"models": ["G1", "G2", "GLOBAL"],
                          "note": "specialists G1 + G2 (shared_attack) + GLOBAL fallback"},
                "BASELINE": {"models": ["GLOBAL"], "note": "GLOBAL scores every row (same model file as FINAL's GLOBAL)"}},
    "route": {"G1": "G1", "G2": "G2", "GEN": "GLOBAL"},
    "routing_rule": "by the row's group column: G1 -> G1 model, G2 -> G2 model, GEN -> GLOBAL; unregistered MACs "
                    "(device 'unregistered:<mac>', device_category 'unregistered_mac') are group GEN -> GLOBAL. "
                    "BASELINE: GLOBAL for every row.",
    "groups": ["G1", "G2", "GEN"],
    "gen_group": "GEN",
    "unreg_category": "unregistered_mac",
    "unreg_device_prefix": "unregistered:",
    "operating_points": ["T_house", "0.5"],
    "default_threshold": 0.5,
    "max_val_fp": 2,
    "threshold_rule": "T_house: lowest observed house VAL score with <= 2 FP on the house's VAL benign rows "
                      "(09 strategies common_threshold_rule, 09 max_fp_threshold); 0.5 fixed. Flag iff score >= thr.",
    "filter": 'owner_status == "owned" AND exclude_reason == "" AND label != "excluded" (applied by 08 / 08b at '
              'build time; the parquet files hold no filter column, so 0 rows are dropped at runtime, as in 09)',
    "low_n": 50,
    "ci_level": 0.95,
    "ci_method": "exact (Garwood) Poisson: [chi2.ppf(a/2, 2k) / 2, chi2.ppf(1 - a/2, 2k + 2) / 2], lower 0 at k = 0; "
                 "FP/hour CI = count CI / hours",
    "ci_selftest": {"0": [0.0, 3.689], "2": [0.242, 7.225], "tol": 5e-4},
    "step9_compare": {"BASELINE": ("global", "both"), "FINAL": ("behaviour_k2", "shared_attack")},
    "step9_tol": 1e-9,
    "features_sha_prefix": "cf73976f",
}

SCRIPT = "10_evaluate.py"
SCRIPT_PATH = Path(__file__).resolve()
CODE_SHA256 = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
DATASET_DIR = CACHE_DIR / "datasets" / "v1_1"
SPLIT_PATH = {"train": DATASET_DIR / "train.parquet", "val": DATASET_DIR / "val.parquet",
              "test": DATASET_DIR / "test.parquet"}
# Display form of the test path, built without resolve() (resolve lstat()s every component).
TEST_REL = "~/" + SPLIT_PATH["test"].relative_to(Path.home()).as_posix()
MODELS_DIR = CACHE_DIR / "models" / "step10"
OUT_ROOT = RESULTS_DIR / "step10"
TEST_MARKER = OUT_ROOT / "TEST_OPENED.json"
PREREG = CONFIG_DIR / "step10_prereg.json"
MANIFEST_V11 = RESULTS_DIR / "step8b" / "manifest_v1_1.json"
SPLIT_PLAN_V11 = CONFIG_DIR / "split_plan_v1_1.json"
K2_JSON = CONFIG_DIR / "groupings" / "behaviour_k2.json"
STEP9_HOUSE = RESULTS_DIR / "step9" / "strategies" / "val_house.csv"
STEP9_GROUP = RESULTS_DIR / "step9" / "strategies" / "val_per_group.csv"
# Files whose bytes decide what test mode computes, besides this script, the models and features_v1.json.
PREREG_INPUTS = [REPO_ROOT / "09_train_specialists.py", CONFIG_DIR / "config.py", K2_JSON, SPLIT_PLAN_V11,
                 MANIFEST_V11, s09.MANIFEST, s09.ATTACK_SET, CONFIG_DIR / "behaviour_groups.json"]
RUN_LOCK = ".10_evaluate.lock"
EVAL_META = ["y", "attack_family", "group", "device", "device_category", "session"]
FILTER_COLS = ["owner_status", "exclude_reason", "label"]

FIT_FORBIDDEN = False
_TEST_UNLOCKED = False


# --------------------------------------------------------------------------- small helpers

_LOG_PATH: Path | None = None
_LOG_BUF: list[str] = []


def log(msg: str) -> None:
    line = f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    if _LOG_PATH is None:
        _LOG_BUF.append(line)
    else:
        with open(_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def set_log(path: Path) -> None:
    """From now on log to `path` too (lines logged before are written first); 09's log() follows."""
    global _LOG_PATH
    with open(path, "a", encoding="utf-8") as fh:
        fh.writelines(line + "\n" for line in _LOG_BUF)
    _LOG_BUF.clear()
    _LOG_PATH = path
    s09._LOG_PATH = path


def fatal(msg: str) -> None:
    log(f"FATAL: {msg}")
    sys.exit(1)


def rel(p: Path | str) -> str:
    return s09.rel(p)


def guard_read(path: Path) -> Path:
    """No test file is read unless test mode has passed every guard and created TEST_OPENED.json."""
    if "test" in Path(path).name.lower() and not _TEST_UNLOCKED:
        raise AssertionError(f"{SCRIPT} must not read {path} here (test split locked)")
    return path


def read_json(path: Path) -> dict:
    return json.loads(guard_read(path).read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=str) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def lib_versions() -> dict:
    out = {"python": platform.python_version()}
    for pkg in ("numpy", "pandas", "pyarrow", "scipy", "scikit-learn", "joblib", "xgboost"):
        try:
            out[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            out[pkg] = "not installed"
    return out


def git(*a: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(REPO_ROOT), *a], capture_output=True, text=True, timeout=60)


def git_head() -> str:
    r = git("rev-parse", "HEAD")
    if r.returncode != 0:
        fatal(f"git rev-parse HEAD failed: {r.stderr.strip()}")
    return r.stdout.strip()


def git_status(untracked: bool) -> list[str]:
    r = git("status", "--porcelain", f"--untracked-files={'normal' if untracked else 'no'}")
    if r.returncode != 0:
        fatal(f"git status failed: {r.stderr.strip()}")
    return [x for x in r.stdout.splitlines() if x.strip()]


# Origin: 09_train_specialists.py run_lock() (same flock pattern, own lock file name and message).
def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.10_evaluate.lock for the whole run."""
    d.mkdir(parents=True, exist_ok=True)
    path = d / RUN_LOCK
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another {SCRIPT} is using {rel(d)} (lock {RUN_LOCK} held by: {holder}); refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {utc_now()} argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


def md_table(rows: list[dict], cols: list[str]) -> list[str]:
    return s09.md_table(rows, cols)


def fnum(v, nd: int = 4) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    if isinstance(v, float) and math.isinf(v):
        return "inf"
    return f"{v:.{nd}f}" if isinstance(v, float) else str(v)


# --------------------------------------------------------------------------- inputs

def check_features(ctx: dict, M11: dict) -> None:
    """09 check_inputs() has checked features_v1.json against manifest_v1 (70, order, sha, no identity column)."""
    sha = ctx["sha"]
    if not sha.startswith(STEP10["features_sha_prefix"]):
        fatal(f"features_v1.json sha256 {sha[:16]}... does not start with {STEP10['features_sha_prefix']}; STOP")
    if M11["config"]["features"]["sha256"] != sha:
        fatal(f"manifest_v1_1 config.features sha256 {M11['config']['features']['sha256'][:16]}... != features_v1.json "
              f"{sha[:16]}...")
    log(f"features: {len(ctx['feats'])}, sha256 {sha[:16]}... (== manifest_v1 == manifest_v1_1)")


def check_schema(split: str, feats: list[str]) -> dict:
    """Parquet columns must be exactly features_v1 (in order) + 09 META_COLS; the training filter columns are
    therefore absent (08 / 08b applied the filter at build time) and the runtime filter drops 0 rows."""
    path = SPLIT_PATH[split]
    names = pq.read_schema(guard_read(path)).names
    if names != feats + s09.META_COLS:
        fatal(f"{path.name}: columns are not exactly features_v1 (70, in order) + {s09.META_COLS}: extra "
              f"{sorted(set(names) - set(feats) - set(s09.META_COLS))}, missing {sorted(set(feats + s09.META_COLS) - set(names))}")
    present = [c for c in FILTER_COLS if c in names]
    if present:
        fatal(f"{path.name}: filter columns {present} present; expected the build-time filter only")
    rows = pq.ParquetFile(path).metadata.num_rows
    log(f"{split}: training filter ({STEP10['filter'].split(' (')[0]}) applied at build time by 08 / 08b; "
        f"rows {rows:,}, dropped at runtime 0")
    return {"rows": rows, "rows_dropped_by_filter": 0, "filter_columns_present": present}


# Origin: 09_train_specialists.py load_matrix() (guard_read is this script's; rows default = every row).
def load_matrix(path: Path, feats: list[str], rows: np.ndarray | None = None) -> np.ndarray:
    """Rows `rows` of the 70 feature columns, in features_v1 order, as float32."""
    t = pq.read_table(guard_read(path), columns=feats)
    if t.column_names != feats:
        raise AssertionError(f"{path.name}: feature columns {t.column_names[:3]}... != features_v1 order")
    n = t.num_rows if rows is None else len(rows)
    X = np.empty((n, len(feats)), dtype=np.float32)
    for j, c in enumerate(feats):
        col = t.column(c).to_numpy()
        X[:, j] = col if rows is None else col[rows]
    del t
    if X.shape[1] != 70:
        raise AssertionError(f"feature matrix has {X.shape[1]} columns, expected 70")
    return X


# Origin: 09_train_specialists.py load_meta() checks (y in {0, 1}; y == 1 <=> attack_family set).
def load_eval_meta(split: str) -> pd.DataFrame:
    path = SPLIT_PATH[split]
    df = pq.read_table(guard_read(path), columns=EVAL_META).to_pandas()
    for c in ("attack_family", "group", "device", "device_category", "session"):
        df[c] = df[c].fillna("").astype(str)
    yv = set(np.unique(df["y"]).tolist())
    if not yv <= {0, 1}:
        fatal(f"{path.name}: y takes values {sorted(yv)}, expected 0 = benign / 1 = attack; STOP")
    bad = int(((df["y"] == 1) != (df["attack_family"] != "")).sum())
    if bad:
        fatal(f"{path.name}: {bad} rows where y == 1 disagrees with attack_family being set; STOP")
    return df


def k2_group_of() -> dict:
    """behaviour_k2.json -> device name -> group (via MAC), as 09 load_groupings() reads it."""
    J = read_json(K2_JSON)
    dev, info = J["devices"], J["device_info"]
    if J.get("strategy") != "behaviour_k2" or sorted(J["groups"]) != sorted(STEP10["groups"]) or set(dev) != set(info):
        fatal(f"{rel(K2_JSON)}: not the behaviour_k2 grouping over {STEP10['groups']}; STOP")
    lock_sha = sha256_file(CONFIG_DIR / "behaviour_groups.json")
    if lock_sha not in str(J.get("derived_from", "")):
        fatal(f"{rel(K2_JSON)} derived_from does not name behaviour_groups.json sha256 {lock_sha[:16]}... (v1.0 lock)")
    return {info[m]["device_name"]: g for m, g in dev.items()}


def session_info(plan: dict, M1: dict, split: str) -> dict:
    """Attack sessions expected in `split` (split_plan_v1_1 names; family from manifest_v1 inputs, as in 09
    resolve_syn_sessions) and the night / daytime benign session sets."""
    fam_of = {i["session"]: (i.get("label_report") or {}).get("completion_key", {}).get("attack_family")
              for i in M1["inputs"]}
    modes = plan["sessions"]
    want = {"val": ("train", "time_split"), "test": ("test", "time_split")}[split]
    attack = [s for s, m in modes.items() if m in want and fam_of.get(s)]
    daytime = list(plan["test_only_sessions"])
    if any(modes.get(s) != "test_only" for s in daytime):
        fatal("split_plan_v1_1: a test_only_sessions entry is not mode test_only in sessions; STOP")
    night = [s for s, m in modes.items() if m != "test_only"]
    return {"attack_sessions": attack, "family_of": {s: fam_of.get(s) for s in attack},
            "aliases": dict(plan["session_aliases"]), "night_sessions": night, "daytime_sessions": daytime}


def route(meta: pd.DataFrame, group_of: dict) -> tuple[np.ndarray, dict]:
    """Routed model per row (STEP10 route on the group column) after checking the group column against
    behaviour_k2 (registered devices) and the 08b unregistered-MAC rule."""
    grp, dev, cat = meta["group"].to_numpy(object), meta["device"].to_numpy(object), meta["device_category"].to_numpy(object)
    bad_g = sorted(set(grp) - set(STEP10["groups"]))
    if bad_g:
        fatal(f"groups outside {STEP10['groups']}: {bad_g}; STOP")
    unreg = cat == STEP10["unreg_category"]
    unreg_dev = np.array([str(d).startswith(STEP10["unreg_device_prefix"]) for d in dev], dtype=bool)
    if (unreg != unreg_dev).any():
        fatal(f"{int((unreg != unreg_dev).sum())} rows where device_category unregistered_mac disagrees with device "
              f"'{STEP10['unreg_device_prefix']}<mac>'; STOP")
    if (grp[unreg] != STEP10["gen_group"]).any():
        fatal("unregistered_mac rows outside group GEN; STOP")
    reg_dev = pd.Series(dev[~unreg])
    unknown = sorted(set(reg_dev) - set(group_of))
    if unknown:
        fatal(f"devices not in {rel(K2_JSON)}: {unknown}; STOP")
    mism = int((reg_dev.map(group_of).to_numpy(object) != grp[~unreg]).sum())
    if mism:
        fatal(f"{mism} rows whose group column != behaviour_k2 group of their device; STOP")
    routed = pd.Series(grp).map(STEP10["route"]).to_numpy(object)
    if pd.isna(routed).any():
        fatal("rows without a routed model; STOP")
    hits = np.zeros(len(grp), dtype=np.int64)
    for m in STEP10["models"]:
        hits += (routed == m)
    cov = {"rows": int(len(grp)), "routed_exactly_once": bool((hits == 1).all()),
           "by_group": {g: int((grp == g).sum()) for g in STEP10["groups"]},
           "by_routed_model": {m: int((routed == m).sum()) for m in STEP10["models"]},
           "unregistered_mac_rows": int(unreg.sum()),
           "group_to_model": {g: STEP10["route"][g] for g in STEP10["groups"]}}
    log(f"routing: {cov['rows']:,} rows, exactly once {cov['routed_exactly_once']}; by group {cov['by_group']}; "
        f"by model {cov['by_routed_model']}; unregistered_mac {cov['unregistered_mac_rows']}")
    return routed, cov


def benign_period(meta: pd.DataFrame, sinfo: dict) -> np.ndarray:
    """'night' / 'daytime' per row by session (attack rows too); any benign row of another session stops."""
    sess = meta["session"].to_numpy(object)
    per = np.full(len(sess), "", dtype=object)
    per[np.isin(sess, sinfo["night_sessions"])] = "night"
    per[np.isin(sess, sinfo["daytime_sessions"])] = "daytime"
    lost = (meta["y"].to_numpy() == 0) & (per == "")
    if lost.any():
        fatal(f"{int(lost.sum())} benign rows in sessions {sorted(set(sess[lost]))} are neither night nor daytime; STOP")
    return per


# --------------------------------------------------------------------------- models

def train_models(Xtr: np.ndarray, y_tr: np.ndarray, grp_tr: np.ndarray, dur_idx: int) -> tuple[dict, dict]:
    """G1, G2 (shared_attack) and GLOBAL. Training rows copied from 09 strategies() fit_rows() (behaviour_k2,
    shared_attack; GLOBAL = every train row); fit via 09 fit_model (XGB)."""
    if FIT_FORBIDDEN:
        raise AssertionError("fitting is disabled in this run")
    ben, att = y_tr == 0, y_tr == 1
    models, info = {}, {}
    for mid in STEP10["models"]:
        m = np.ones(len(y_tr), bool) if mid == "GLOBAL" else ((grp_tr == mid) & ben) | att
        rows = np.flatnonzero(m).astype(np.int32)
        np.random.seed(STEP10["seed"])
        model, cw, pre, fit_s, warn = s09.fit_model(STEP10["model"], Xtr[rows], y_tr[rows], dur_idx, STEP10["seed"])
        n_b, n_a = int(ben[rows].sum()), int(att[rows].sum())
        spw = float(model.get_params()["scale_pos_weight"])
        if spw != n_b / n_a:
            raise AssertionError(f"{mid}: scale_pos_weight {spw} != {n_b} / {n_a}")
        models[mid] = model
        info[mid] = {"training_set": STEP10["training_sets"][mid], "n_train": len(rows), "n_train_benign": n_b,
                     "n_train_attack": n_a, "scale_pos_weight": spw, "class_weight_handling": cw,
                     "preprocessing": pre, "fit_s": round(fit_s, 3), "fit_warnings": warn,
                     "rows_sha256_16": hashlib.sha256(rows.astype(np.int64).tobytes()).hexdigest()[:16],
                     "size_bytes_in_memory": s09.model_size(model)}
        log(f"fit {mid}: train {len(rows):,} (benign {n_b:,} / attack {n_a:,})  spw {spw:.6g}  {fit_s:.1f} s"
            + (f"  warnings {warn}" if warn else ""))
    return models, info


def attack_col(model) -> int:
    est = s09.final_estimator(model)
    classes = [int(c) for c in est.classes_]
    if classes != [0, 1]:
        raise AssertionError(f"classes_ {classes} != [0, 1]")
    if int(getattr(est, "n_features_in_", 70)) != 70:
        raise AssertionError(f"model expects {est.n_features_in_} features, not 70")
    return classes.index(1)


def score_systems(models: dict, X: np.ndarray, routed: np.ndarray) -> tuple[dict, dict]:
    """Every model scores every row (as in 09); FINAL takes each row's routed model, BASELINE = GLOBAL."""
    full = {m: models[m].predict_proba(X)[:, attack_col(models[m])].astype(np.float64) for m in STEP10["models"]}
    s_final = np.full(len(routed), np.nan)
    for m in STEP10["models"]:
        k = routed == m
        s_final[k] = full[m][k]
    if np.isnan(s_final).any():
        raise AssertionError("FINAL: rows not scored exactly once")
    return {"FINAL": s_final, "BASELINE": full["GLOBAL"]}, full


def choose_t_house(s: np.ndarray, y: np.ndarray) -> float:
    """09 strategies common threshold on VAL (09 max_fp_threshold, k = STRAT max_fp)."""
    if FIT_FORBIDDEN:
        raise AssertionError("threshold search is disabled in this run")
    k = STEP10["max_val_fp"]
    thr = s09.max_fp_threshold(np.unique(s), np.sort(s[y == 0])[::-1], k)
    if math.isinf(thr):
        fatal(f"T_house: only flagging nothing meets <= {k} val FP; STOP")
    return thr


def forbid_fitting() -> None:
    """Test mode: every fit path raises."""
    global FIT_FORBIDDEN
    import xgboost

    def _refuse(*a, **k):
        raise AssertionError(f"{SCRIPT} --mode test: fitting is disabled")

    FIT_FORBIDDEN = True
    xgboost.XGBClassifier.fit = _refuse
    xgboost.train = _refuse
    s09.fit_model = _refuse
    s09.build_model = _refuse
    assert xgboost.XGBClassifier.fit is _refuse and s09.fit_model is _refuse and FIT_FORBIDDEN


# --------------------------------------------------------------------------- statistics

def garwood(k: int, level: float = STEP10["ci_level"]) -> tuple[float, float]:
    a = 1 - level
    lo = 0.0 if k == 0 else float(chi2.ppf(a / 2, 2 * k) / 2)
    hi = float(chi2.ppf(1 - a / 2, 2 * k + 2) / 2)
    return lo, hi


def rate(flag: np.ndarray, mask: np.ndarray) -> dict:
    n = int(mask.sum())
    det = int((flag & mask).sum())
    return {"n": n, "detected": det, "detection_rate": det / n if n else math.nan,
            "flag": "N/A" if n == 0 else ("LOW_N" if n < STEP10["low_n"] else "")}


# --------------------------------------------------------------------------- reporting (val stand-in and test)

def report(out: Path, split: str, meta: pd.DataFrame, routed: np.ndarray, scores: dict, thr: dict, hours: dict,
           families: list[str], sinfo: dict) -> dict:
    """CSV tables + predictions.parquet for every (system, operating point). Returns the tables for summary.md."""
    y = meta["y"].to_numpy()
    fam, sess = meta["attack_family"].to_numpy(object), meta["session"].to_numpy(object)
    grp, cat = meta["group"].to_numpy(object), meta["device_category"].to_numpy(object)
    period = benign_period(meta, sinfo)
    att, ben = y == 1, y == 0
    observed = sorted(set(sess[att]))
    sess_list = list(sinfo["attack_sessions"]) + [s for s in observed if s not in sinfo["attack_sessions"]]
    det_fam, det_sess, det_fg, fa = [], [], [], []
    preds = {}
    for sysname in STEP10["systems"]:
        s = scores[sysname]
        for op in STEP10["operating_points"]:
            t = float(thr[sysname][op])
            flag = s >= t
            preds[(sysname, op)] = flag
            base = {"split": split, "system": sysname, "operating_point": op, "threshold": t}
            for f in families + ["ALL"]:
                det_fam.append({**base, "attack_family": f, **rate(flag, att & ((fam == f) if f != "ALL" else True))})
            for ss in sess_list:
                det_sess.append({**base, "session": ss, "alias": sinfo["aliases"].get(ss, ""),
                                 "attack_family": sinfo["family_of"].get(ss) or "/".join(sorted(set(fam[att & (sess == ss)]))),
                                 "expected": ss in sinfo["attack_sessions"], **rate(flag, att & (sess == ss))})
            for f in families:
                for g in STEP10["groups"]:
                    det_fg.append({**base, "attack_family": f, "group": g,
                                   "routed_model": STEP10["route"][g] if sysname == "FINAL" else "GLOBAL",
                                   **rate(flag, att & (fam == f) & (grp == g))})
            for p in ("night", "daytime", "combined"):
                m = ben & ((period == p) if p != "combined" else True)
                k = int((flag & m).sum())
                lo, hi = garwood(k)
                h = float(hours[p])
                fa.append({**base, "breakdown": "period", "key": p, "n_benign": int(m.sum()), "fp": k, "hours": h,
                           "fp_per_hour": k / h if h > 0 else math.nan, "fp_ci_low": lo, "fp_ci_high": hi,
                           "fph_ci_low": lo / h if h > 0 else math.nan, "fph_ci_high": hi / h if h > 0 else math.nan})
            for col, keys, arr in (("group", STEP10["groups"], grp), ("device_category", sorted(set(cat[ben])), cat)):
                for key in keys:
                    m = ben & (arr == key)
                    k = int((flag & m).sum())
                    lo, hi = garwood(k)
                    fa.append({**base, "breakdown": col, "key": key, "n_benign": int(m.sum()), "fp": k, "hours": math.nan,
                               "fp_per_hour": math.nan, "fp_ci_low": lo, "fp_ci_high": hi, "fph_ci_low": math.nan,
                               "fph_ci_high": math.nan})
    T = {"detection_by_family": pd.DataFrame(det_fam), "detection_by_session": pd.DataFrame(det_sess),
         "detection_by_family_group": pd.DataFrame(det_fg), "false_alarms": pd.DataFrame(fa)}
    for name, df in T.items():
        df.to_csv(out / f"{name}.csv", index=False, lineterminator="\n")
    pred = pa.table({"row_id": pa.array(np.arange(len(y), dtype=np.int64)),
                     "session": pa.array(sess.astype(str)), "group": pa.array(grp.astype(str)),
                     "routed_model": pa.array(routed.astype(str)), "y": pa.array(y.astype(np.int8)),
                     "score_final": pa.array(scores["FINAL"]), "score_global": pa.array(scores["BASELINE"]),
                     **{f"pred_{sysname.lower()}_{op}": pa.array(preds[(sysname, op)].astype(np.int8))
                        for sysname in STEP10["systems"] for op in STEP10["operating_points"]}})
    pq.write_table(pred, out / "predictions.parquet")
    pred_sha = sha256_file(out / "predictions.parquet")
    log(f"wrote {', '.join(f'{n}.csv' for n in T)}, predictions.parquet (sha256 {pred_sha[:16]}...) -> {rel(out)}")
    counts = {"rows": int(len(y)), "benign": int(ben.sum()), "attack": int(att.sum()),
              "benign_by_period": {p: int((ben & (period == p)).sum()) for p in ("night", "daytime")},
              "attack_by_family": {f: int((att & (fam == f)).sum()) for f in families},
              "attack_by_session": {ss: int((att & (sess == ss)).sum()) for ss in sess_list},
              "rows_by_group": {g: int((grp == g).sum()) for g in STEP10["groups"]},
              "benign_by_device_category": {c: int((ben & (cat == c)).sum()) for c in sorted(set(cat[ben]))}}
    return {"tables": T, "predictions_sha256": pred_sha, "counts": counts, "sessions": sess_list}


def cell(r: pd.Series) -> str:
    if r["flag"] == "N/A":
        return "N/A (n=0)"
    return f"{r['detection_rate']:.4f} ({r['detected']:,}/{r['n']:,})" + (" LOW_N" if r["flag"] == "LOW_N" else "")


def wide(df: pd.DataFrame, keys: list[str], fmt) -> tuple[list[dict], list[str]]:
    """One row per key, one column per system @ operating point."""
    cols = [f"{s} @ {op}" for s in STEP10["systems"] for op in STEP10["operating_points"]]
    rows = []
    for kv, d in df.groupby(keys, sort=False):
        kv = kv if isinstance(kv, tuple) else (kv,)
        r = dict(zip(keys, kv))
        for _, x in d.iterrows():
            r[f"{x['system']} @ {x['operating_point']}"] = fmt(x)
        rows.append(r)
    return rows, keys + cols


def fa_cell(x: pd.Series) -> str:
    ci = f"[{x['fp_ci_low']:.3f}, {x['fp_ci_high']:.3f}]"
    if x["breakdown"] != "period":
        return f"{x['fp']} of {x['n_benign']:,} (CI {ci})"
    if not x["hours"] > 0:
        return f"{x['fp']} of {x['n_benign']:,}; FP/h N/A (0 h)"
    return (f"{x['fp']} -> {x['fp_per_hour']:.3f}/h [{x['fph_ci_low']:.3f}, {x['fph_ci_high']:.3f}] "
            f"(n {x['n_benign']:,}, {x['hours']:.3f} h)")


def write_summary(out: Path, meta: dict, R: dict) -> None:
    dry = meta["mode"] == "dryrun"
    T = R["tables"]
    L = [f"# Step 10 -- {'DRY RUN (VAL stands in for test)' if dry else 'TEST evaluation (one-time)'}", "",
         f"- run {meta['run_utc']} -> {meta['finished_utc']}, git HEAD `{meta['git_head']}`, {SCRIPT} sha256 "
         f"`{CODE_SHA256[:16]}...`, prereg `{rel(PREREG)}` sha256 `{(meta.get('prereg_sha256') or 'not written')[:16]}`",
         f"- evaluated split: `{meta['split_file']['path']}` ({meta['split_file']['rows']:,} rows, sha256 "
         f"`{meta['split_file']['sha256'][:16]}...`); runtime filter dropped 0 rows (applied at build time by 08 / 08b)",
         f"- flag attack iff score >= threshold; LOW_N = 0 < n < {STEP10['low_n']}; N/A = n 0; FP/hour CI = 95% exact "
         "(Garwood) Poisson CI on the FP count / active benign hours"]
    if dry:
        L += ["- **Dry run**: T_house is chosen on VAL and every number here is read on the SAME val rows "
              "(optimistic, plumbing check only). Val holds no daytime benign (FP/h N/A)."]
    L += ["", "## Systems and operating points", ""]
    L += md_table([{"system": s, "models": " + ".join(STEP10["systems"][s]["models"]),
                    "T_house (val, <= 2 FP)": repr(meta["thresholds"][s]["T_house"]),
                    "0.5": meta["thresholds"][s]["0.5"]} for s in STEP10["systems"]],
                  ["system", "models", "T_house (val, <= 2 FP)", "0.5"])
    L += ["", f"Routing (FINAL): {STEP10['routing_rule']}", "", "## Models", ""]
    L += md_table([{"model": m, "training set": i["training_set"], "n_train": f"{i['n_train']:,}",
                    "benign / attack": f"{i['n_train_benign']:,} / {i['n_train_attack']:,}",
                    "scale_pos_weight": f"{i['scale_pos_weight']:.6g}", "file bytes": f"{i['file_bytes']:,}",
                    "sha256": f"`{i['sha256'][:16]}...`"} for m, i in meta["models"].items()],
                  ["model", "training set", "n_train", "benign / attack", "scale_pos_weight", "file bytes", "sha256"])
    c = meta["routing"]
    L += ["", f"Rows routed: by group {c['by_group']}; by model {c['by_routed_model']}; unregistered_mac "
              f"{c['unregistered_mac_rows']}; every row exactly once: {c['routed_exactly_once']}", ""]
    L += ["## Detection by attack family", ""]
    L += md_table(*wide(T["detection_by_family"], ["attack_family"], cell))
    L += ["", "## Detection by session", ""]
    ds = T["detection_by_session"].copy()
    ds["session"] = [f"{s} ({a})" if a else s for s, a in zip(ds["session"], ds["alias"])]
    L += md_table(*wide(ds, ["session", "attack_family"], cell))
    L += ["", "## Detection by attack family x group", ""]
    L += md_table(*wide(T["detection_by_family_group"], ["attack_family", "group"], cell))
    fa = T["false_alarms"]
    L += ["", "## False alarms (FP -> FP/hour [95% CI])", ""]
    L += md_table(*wide(fa[fa["breakdown"] == "period"], ["key"], fa_cell))
    L += ["", "Hours: " + "; ".join(f"{p} {meta['hours'][p]:.4f} h" for p in ("night", "daytime", "combined"))
          + f" ({meta['hours']['source']})", "", "### FPs by group", ""]
    L += md_table(*wide(fa[fa["breakdown"] == "group"], ["key"], fa_cell))
    L += ["", "### FPs by device_category", ""]
    L += md_table(*wide(fa[fa["breakdown"] == "device_category"], ["key"], fa_cell))
    if dry:
        L += ["", "## Sanity checks", ""]
        L += md_table([{"check": x["check"], "result": "PASS" if x["pass"] else "FAIL", "detail": x["detail"]}
                       for x in meta["checks"]], ["check", "result", "detail"])
        L += ["", "## Step 9 (results/step9/strategies, val) vs this dry run", ""]
        L += md_table([{**x, "step9": fnum(x["step9"], 6), "step10": fnum(x["step10"], 6),
                        "result": "PASS" if x["pass"] else "FAIL"} for x in meta["step9_comparison"]],
                      ["system", "scope", "metric", "step9", "step10", "result"])
    L += ["", "## Notes", "",
          f"- XGB: {STEP10['model_note']}.",
          f"- Threshold rule: {STEP10['threshold_rule']}",
          f"- Night / daytime: daytime = split_plan_v1_1 test_only sessions {meta['sessions']['daytime_sessions']}; "
          "night = every other plan session.",
          f"- predictions.parquet sha256 `{R['predictions_sha256']}`."]
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- dry-run checks

def compare_step9(scores: dict, meta_ev: pd.DataFrame, thr: dict, hours_val: float, families: list[str],
                  minfo: dict) -> list[dict]:
    """Side by side with results/step9/strategies val_house.csv / val_per_group.csv (evaluation val)."""
    house, per_g = s09.read_csv(STEP9_HOUSE), s09.read_csv(STEP9_GROUP)
    y, fam, grp = meta_ev["y"].to_numpy(), meta_ev["attack_family"].to_numpy(object), meta_ev["group"].to_numpy(object)
    tol, rows = STEP10["step9_tol"], []

    def add(sysname, scope, metric, a, b):
        if isinstance(a, str) or isinstance(b, str):
            ok = str(a) == str(b)
        else:
            a, b = float(a), float(b)
            ok = (math.isnan(a) and math.isnan(b)) or abs(a - b) <= tol
        rows.append({"system": sysname, "scope": scope, "metric": metric, "step9": a, "step10": b, "pass": bool(ok)})

    for sysname, (strat, mode) in STEP10["step9_compare"].items():
        h = house[(house["strategy"] == strat) & (house["mode"] == mode) & (house["evaluation"] == "val")]
        if len(h) != 1 or h["status"].iloc[0] != "OK":
            fatal(f"{rel(STEP9_HOUSE)}: {len(h)} OK rows for {strat}/{mode}/val; STOP")
        h = h.iloc[0]
        s = scores[sysname]
        row, frows = s09.robust_val(s, y, fam, families, hours_val, k=STEP10["max_val_fp"])
        row = s09.ren_common(row)
        for x in frows:
            tag = "05" if x["operating_point"] == "default_0.5" else "common"
            row[f"n_{x['attack_family']}"] = x["n"]
            row[f"dr_{tag}_{x['attack_family']}"] = x["detection_rate"]
        for k in ["n_attack_val", "n_benign_val", "val_benign_hours", "pr_auc", "roc_auc", "thr_05", "fp_05", "fph_05",
                  "dr_05", "thr_common", "fp_common", "fph_common", "dr_common"] + \
                [c for f in families for c in (f"n_{f}", f"dr_05_{f}", f"dr_common_{f}")]:
            add(sysname, "house", k, h[k], row[k])
        add(sysname, "house", "score_sha256", h["score_sha256"], s09.scores_sha(s))
        add(sysname, "house", "T_house == thr_common", h["thr_common"], thr[sysname]["T_house"])
        groups = ["GLOBAL"] if sysname == "BASELINE" else STEP10["groups"]
        for g in groups:
            p = per_g[(per_g["strategy"] == strat) & (per_g["mode"] == mode) & (per_g["evaluation"] == "val")
                      & (per_g["group"] == g)]
            if len(p) != 1:
                fatal(f"{rel(STEP9_GROUP)}: {len(p)} rows for {strat}/{mode}/val/{g}; STOP")
            p = p.iloc[0]
            m = np.ones(len(y), bool) if g == "GLOBAL" else grp == g
            mid = "GLOBAL" if g in ("GLOBAL", "GEN") else g
            vb = y == 0
            mine = {"n_val": int(m.sum()), "n_val_benign": int((m & vb).sum()),
                    "fp_05": int((m & vb & (s >= 0.5)).sum()),
                    "fp_common": int((m & vb & (s >= thr[sysname]["T_house"])).sum()),
                    "n_train": minfo[mid]["n_train"], "n_train_benign": minfo[mid]["n_train_benign"],
                    "n_train_attack": minfo[mid]["n_train_attack"], "size_bytes": minfo[mid]["size_bytes_in_memory"]}
            if p["scored_by"] != mid:
                fatal(f"step 9 {strat}/{mode} group {g} scored by {p['scored_by']}, here {mid}; STOP")
            for k, v in mine.items():
                add(sysname, f"group {g}", k, p[k], v)
    return rows


def ci_selftest() -> dict:
    st, tol, got = STEP10["ci_selftest"], STEP10["ci_selftest"]["tol"], {}
    ok = True
    for k in ("0", "2"):
        lo, hi = garwood(int(k))
        got[k] = [round(lo, 4), round(hi, 4)]
        ok &= abs(lo - st[k][0]) <= tol and abs(hi - st[k][1]) <= tol
    return {"check": "Poisson CI self-test (Garwood 95%)", "pass": bool(ok),
            "detail": f"0 FP -> {got['0']} (want upper 3.689); 2 FP -> {got['2']} (want [0.242, 7.225])"}


# --------------------------------------------------------------------------- modes

def common_inputs() -> dict:
    """Lock + feature contract (09 check_inputs), manifests, plan, grouping. No data file is read."""
    ctx = s09.check_inputs()
    M11 = read_json(MANIFEST_V11)
    check_features(ctx, M11)
    if s09.STRAT["max_fp"] != STEP10["max_val_fp"]:
        fatal(f"09 STRAT max_fp {s09.STRAT['max_fp']} != {STEP10['max_val_fp']}; STOP")
    return {"ctx": ctx, "M1": read_json(s09.MANIFEST), "M11": M11, "plan": read_json(SPLIT_PLAN_V11),
            "group_of": k2_group_of()}


def test_hours(M11: dict, plan: dict) -> dict:
    H = M11["hours"]
    night, day, comb = float(H["v1_test"]), float(H["added"]), float(H["v1_1_test"])
    if abs(night + day - comb) > 1e-6 or abs(sum(H["per_session"].values()) - day) > 1e-6 \
            or set(H["per_session"]) != set(plan["test_only_sessions"]):
        fatal(f"manifest_v1_1 hours do not add up: {H}; STOP")
    return {"night": night, "daytime": day, "combined": comb,
            "source": "results/step8b/manifest_v1_1.json hours: v1_test (night), added (daytime), v1_1_test (combined)"}


def run_meta_base(mode: str, run_utc: str, head: str) -> dict:
    return {"script": SCRIPT, "mode": mode, "run_utc": run_utc, "argv": sys.argv, "git_head": head,
            "git_dirty_tracked": git_status(untracked=False), "git_untracked": git_status(untracked=True),
            "code_sha256": CODE_SHA256, "config": STEP10, "versions": lib_versions(),
            "platform": {"machine": platform.machine(), "system": platform.system(), "release": platform.release(),
                         "cpu_count": os.cpu_count()}}


def dryrun(args) -> int:
    t0 = time.monotonic()
    rt = {}
    run_utc = utc_now()
    if TEST_MARKER.exists():
        fatal(f"{rel(TEST_MARKER)} exists: the test split has been opened; the prereg is frozen, no dry run")
    out = OUT_ROOT / "dryrun"
    lock_fh = run_lock(out)
    (out / "run.log").unlink(missing_ok=True)
    set_log(out / "run.log")
    head = git_head()
    log("=" * 100)
    log(f"{SCRIPT} --mode dryrun  pid {os.getpid()}  git HEAD {head}  code sha256 {CODE_SHA256[:16]}...")
    I = common_inputs()
    ctx, M1, M11, plan, group_of = I["ctx"], I["M1"], I["M11"], I["plan"], I["group_of"]
    feats, families = ctx["feats"], ctx["families"]

    ds = {}
    for sp in ("train", "val"):
        sha = sha256_file(guard_read(SPLIT_PATH[sp]))
        want = M11["outputs"][f"{sp}.parquet"]["sha256"]
        if sha != want or sha != M11["v1"][sp]["sha256"]:
            fatal(f"{SPLIT_PATH[sp]}: sha256 {sha[:16]}... != manifest_v1_1 {want[:16]}... / v1; STOP")
        ds[sp] = {"path": rel(SPLIT_PATH[sp]), "sha256": sha, **check_schema(sp, feats)}
    log(f"train / val sha256 == manifest_v1_1 outputs == v1 (byte-identical)")

    meta_tr = s09.load_meta(SPLIT_PATH["train"], s09.LOAD_META + ["device"])
    meta_va = s09.load_meta(SPLIT_PATH["val"], s09.LOAD_META + ["device"])
    G, _ = s09.load_groupings(["behaviour_k2"], meta_tr, meta_va)
    gcheck = s09.check_groupings(G, meta_tr, meta_va, families)
    if G["behaviour_k2"]["group_of"] != group_of:
        fatal("09 load_groupings behaviour_k2 != this script's device -> group map; STOP")
    hours_g, man_val, _ = s09.group_val_hours(M1, meta_tr, meta_va)
    hv = float(hours_g["GLOBAL"]["hours_full"])
    hours = {"night": hv, "daytime": 0.0, "combined": hv,
             "source": "val: 09 group_val_hours GLOBAL (08 rule on manifest_v1 session_cuts; == manifest per_split.val "
                       f"{man_val}); val has no daytime benign"}
    rt["inputs_s"] = round(time.monotonic() - t0, 1)

    # ---- train (TRAIN only)
    t = time.monotonic()
    Xtr = load_matrix(SPLIT_PATH["train"], feats)
    y_tr = meta_tr["y"].to_numpy().astype(np.int64)
    grp_tr = meta_tr["device"].map(group_of).to_numpy(dtype=object)
    models, minfo = train_models(Xtr, y_tr, grp_tr, ctx["dur_idx"])
    del Xtr
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    for m, model in models.items():
        p = MODELS_DIR / f"{m}.joblib"
        joblib.dump(model, p)
        minfo[m].update({"path": rel(p), "sha256": sha256_file(p), "file_bytes": p.stat().st_size})
        log(f"saved {m} -> {rel(p)}  {minfo[m]['file_bytes']:,} bytes  sha256 {minfo[m]['sha256'][:16]}...")
    rt["train_s"] = round(time.monotonic() - t, 1)

    # ---- val: route, score, reload test, thresholds
    t = time.monotonic()
    meta_ev = load_eval_meta("val")
    if not (meta_ev["y"].to_numpy() == meta_va["y"].to_numpy()).all() or \
            not (meta_ev["session"].to_numpy() == meta_va["session"].to_numpy()).all():
        fatal("val meta read twice disagrees; STOP")
    ds["val"]["meta_matches_09_load"] = True
    routed, cov = route(meta_ev, group_of)
    Xva = load_matrix(SPLIT_PATH["val"], feats)
    scores, full = score_systems(models, Xva, routed)
    loaded = {m: joblib.load(MODELS_DIR / f"{m}.joblib") for m in STEP10["models"]}
    scores2, full2 = score_systems(loaded, Xva, routed)
    reload_ok = all(np.array_equal(full[m], full2[m]) for m in STEP10["models"]) and \
        all(np.array_equal(scores[s], scores2[s]) for s in scores)
    y_va = meta_ev["y"].to_numpy()
    thr = {s: {"T_house": choose_t_house(scores[s], y_va), "0.5": STEP10["default_threshold"]} for s in STEP10["systems"]}
    for s in STEP10["systems"]:
        log(f"T_house {s}: {thr[s]['T_house']!r}  (val FP {int(((scores[s] >= thr[s]['T_house']) & (y_va == 0)).sum())})")
    rt["val_score_s"] = round(time.monotonic() - t, 1)

    # ---- report (val stands in for test)
    t = time.monotonic()
    sinfo = session_info(plan, M1, "val")
    R = report(out, "val", meta_ev, routed, scores, thr, hours, families, sinfo)
    rt["report_s"] = round(time.monotonic() - t, 1)

    # ---- checks
    vb = y_va == 0
    fp_t = {s: int(((scores[s] >= thr[s]["T_house"]) & vb).sum()) for s in STEP10["systems"]}
    comp = compare_step9(scores, meta_ev, thr, hv, families, minfo)
    n_bad = sum(not x["pass"] for x in comp)
    checks = [
        {"check": "val FP at T_house <= 2 (both systems)", "pass": all(v <= STEP10["max_val_fp"] for v in fp_t.values()),
         "detail": "; ".join(f"{s} {v}" for s, v in fp_t.items())},
        {"check": "val numbers == Step 9 (global, behaviour_k2 shared_attack)", "pass": n_bad == 0,
         "detail": f"{len(comp) - n_bad}/{len(comp)} metrics within {STEP10['step9_tol']:g} (score sha256 exact)"},
        ci_selftest(),
        {"check": "model reload reproduces in-memory val scores exactly", "pass": bool(reload_ok),
         "detail": "; ".join(f"{m} {'equal' if np.array_equal(full[m], full2[m]) else 'DIFFERENT'}" for m in STEP10["models"])},
        {"check": "routing coverage: every val row routed to exactly one model", "pass": cov["routed_exactly_once"]
         and sum(cov["by_routed_model"].values()) == cov["rows"],
         "detail": f"by group {cov['by_group']}; by model {cov['by_routed_model']}"},
    ]
    for x in checks:
        log(f"CHECK {'PASS' if x['pass'] else 'FAIL'}  {x['check']}: {x['detail']}")
    for x in comp:
        if not x["pass"]:
            log(f"  step9 mismatch {x['system']} {x['scope']} {x['metric']}: step9 {x['step9']} vs {x['step10']}")
    all_pass = all(x["pass"] for x in checks)

    # ---- prereg (only if every check passed)
    prereg_sha = None
    if all_pass:
        P = {"step": 10, "created_utc": utc_now(), "created_by": f"{SCRIPT} --mode dryrun",
             "git_head_at_dryrun": head, "git_dirty_tracked_at_dryrun": git_status(untracked=False),
             "script": {"path": SCRIPT, "sha256": CODE_SHA256},
             "inputs_sha256": {rel(p): sha256_file(p) for p in PREREG_INPUTS},
             "features": {"path": rel(s09.FEATURES_JSON), "n": len(feats), "sha256": ctx["sha"],
                          "file_sha256": ctx["file_sha"]},
             "xgboost_version": importlib.metadata.version("xgboost"),
             "datasets": {"train": {k: ds["train"][k] for k in ("path", "sha256", "rows")},
                          "val": {k: ds["val"][k] for k in ("path", "sha256", "rows")},
                          "test": {"path": TEST_REL,
                                   "expected_sha256": M11["outputs"]["test.parquet"]["sha256"],
                                   "expected_rows": M11["outputs"]["test.parquet"]["rows"],
                                   "source": "results/step8b/manifest_v1_1.json outputs (test file not read)"}},
             "filter": STEP10["filter"],
             "grouping": {"path": rel(K2_JSON), "sha256": sha256_file(K2_JSON), "groups": STEP10["groups"]},
             "routing": {"rule": STEP10["routing_rule"], "group_to_model": STEP10["route"]},
             "models": {m: {k: i[k] for k in ("path", "sha256", "file_bytes", "training_set", "n_train", "n_train_benign",
                                              "n_train_attack", "scale_pos_weight", "rows_sha256_16")}
                        for m, i in minfo.items()},
             "model_settings": STEP10["model_note"], "seed": STEP10["seed"],
             "systems": {s: {"models": STEP10["systems"][s]["models"], "note": STEP10["systems"][s]["note"],
                             "thresholds": {op: float(v) for op, v in thr[s].items()},
                             "thresholds_hex": {op: float(v).hex() for op, v in thr[s].items()},
                             "val_fp_at_T_house": fp_t[s]} for s in STEP10["systems"]},
             "threshold_rule": STEP10["threshold_rule"], "operating_points": STEP10["operating_points"],
             "test_sessions": {"source": "config/split_plan_v1_1.json (names only; no data file read)",
                               "plan_modes": {s: m for s, m in plan["sessions"].items()
                                              if m in ("test", "time_split", "test_only")},
                               **session_info(plan, M1, "test")},
             "test_hours": test_hours(M11, plan),
             "reporting": {"low_n": STEP10["low_n"], "ci": STEP10["ci_method"], "ci_level": STEP10["ci_level"]}}
        write_json(PREREG, P)
        prereg_sha = sha256_file(PREREG)
        if read_json(PREREG)["systems"] != json.loads(json.dumps(P["systems"])):
            fatal("prereg re-read differs; STOP")
        log(f"wrote {rel(PREREG)}  sha256 {prereg_sha[:16]}...")
    else:
        log(f"NOT writing {rel(PREREG)}: a check failed")

    meta = {**run_meta_base("dryrun", run_utc, head), "split": "val",
            "split_file": {"path": ds["val"]["path"], "sha256": ds["val"]["sha256"], "rows": ds["val"]["rows"]},
            "datasets": ds, "prereg": rel(PREREG), "prereg_sha256": prereg_sha, "all_checks_pass": all_pass,
            "checks": checks, "step9_comparison": comp, "thresholds": thr, "hours": hours, "routing": cov,
            "models": minfo, "groupings_check": gcheck, "sessions": sinfo, "row_counts": R["counts"],
            "rows_dropped_by_filter": {sp: ds[sp]["rows_dropped_by_filter"] for sp in ds},
            "predictions_sha256": R["predictions_sha256"], "test_split": "never opened"}
    meta["runtimes_s"] = {**rt, "total_s": round(time.monotonic() - t0, 1)}
    meta["finished_utc"] = utc_now()
    write_json(out / "run_meta.json", meta)
    write_summary(out, meta, R)
    log(f"{'ALL CHECKS PASS' if all_pass else 'CHECKS FAILED'}  done in {meta['runtimes_s']['total_s']:.0f} s -> "
        f"{rel(out)}/summary.md")
    lock_fh.close()
    return 0 if all_pass else 1


def guard(ok: bool, name: str, detail: str = "") -> None:
    log(f"GUARD {'PASS' if ok else 'FAIL'}  {name}{': ' + detail if detail else ''}")
    if not ok:
        fatal(f"guard failed: {name}; test split NOT opened")


def test(args) -> int:
    global _TEST_UNLOCKED
    t0 = time.monotonic()
    rt = {}
    run_utc = utc_now()
    guard(not TEST_MARKER.exists(), f"{rel(TEST_MARKER)} absent")
    out = OUT_ROOT / "test"
    lock_fh = run_lock(out)
    guard(True, "run lock", f"{rel(out / RUN_LOCK)}")
    set_log(out / "run.log")
    log("=" * 100)
    log(f"{SCRIPT} --mode test  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...")

    head = git_head()
    dirty = git_status(untracked=False)
    guard(not dirty, "git: no modified / staged tracked file", f"HEAD {head}" if not dirty else "; ".join(dirty[:20]))
    untracked = git_status(untracked=True)
    if untracked:
        log(f"note: {len(untracked)} untracked path(s) (not used by this script): {'; '.join(untracked[:10])}")
    prel = PREREG.relative_to(REPO_ROOT).as_posix()
    guard(git("ls-files", "--error-unmatch", prel).returncode == 0, f"{prel} tracked")
    guard(git("diff", "--quiet", "HEAD", "--", prel).returncode == 0, f"{prel} identical to HEAD")

    P = read_json(PREREG)
    prereg_sha = sha256_file(PREREG)
    guard(sha256_file(SCRIPT_PATH) == P["script"]["sha256"] == CODE_SHA256, f"{SCRIPT} sha256 == prereg",
          CODE_SHA256[:16] + "...")
    for m, i in P["models"].items():
        p = Path(i["path"]).expanduser()
        guard(p.is_file() and sha256_file(p) == i["sha256"], f"model {m} sha256 == prereg", f"{i['path']} {i['sha256'][:16]}...")
    guard(sha256_file(s09.FEATURES_JSON) == P["features"]["file_sha256"], "features_v1.json sha256 == prereg",
          P["features"]["file_sha256"][:16] + "...")
    for r_, sha in P["inputs_sha256"].items():
        guard(sha256_file(REPO_ROOT / r_) == sha, f"{r_} sha256 == prereg", sha[:16] + "...")
    guard(importlib.metadata.version("xgboost") == P["xgboost_version"], "xgboost version == prereg", P["xgboost_version"])
    try:
        lock = verify_lock()
        guard(lock["ok"], "verify_lock()", f"{len(lock['checks'])} checks")
    except LockError as e:
        guard(False, "verify_lock()", str(e))
    I = common_inputs()
    ctx, M11, plan, group_of = I["ctx"], I["M11"], I["plan"], I["group_of"]
    feats, families = ctx["feats"], ctx["families"]
    guard(ctx["sha"] == P["features"]["sha256"], "features list sha256 == prereg")

    forbid_fitting()
    guard(FIT_FORBIDDEN, "fitting disabled (XGBClassifier.fit, xgboost.train, 09 fit_model / build_model raise)")
    models = {m: joblib.load(Path(P["models"][m]["path"]).expanduser()) for m in STEP10["models"]}
    for m in models:
        attack_col(models[m])
    thr = {}
    for s in STEP10["systems"]:
        T = P["systems"][s]
        thr[s] = {op: float(T["thresholds"][op]) for op in STEP10["operating_points"]}
        guard(all(float.fromhex(T["thresholds_hex"][op]) == thr[s][op] for op in thr[s]), f"{s} thresholds from prereg",
              ", ".join(f"{op} {v!r}" for op, v in thr[s].items()))
    hours = P["test_hours"]
    guard(hours == test_hours(M11, plan), "test benign hours == prereg",
          ", ".join(f"{p} {hours[p]:.4f}" for p in ("night", "daytime", "combined")))
    sinfo = {k: P["test_sessions"][k] for k in ("attack_sessions", "family_of", "aliases", "night_sessions",
                                                 "daytime_sessions")}
    rt["guards_s"] = round(time.monotonic() - t0, 1)

    # ---- the one-time opening
    marker = {"opened_utc": utc_now(), "git_head": head, "pid": os.getpid(), "script_sha256": CODE_SHA256,
              "prereg_sha256": prereg_sha, "test_path": TEST_REL}
    try:
        fd = os.open(TEST_MARKER, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
    except FileExistsError:
        fatal(f"{rel(TEST_MARKER)} appeared during the guards; test split NOT opened")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(marker, indent=1) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    log(f"created {rel(TEST_MARKER)} ({marker['opened_utc']}); opening the test split")
    _TEST_UNLOCKED = True

    t = time.monotonic()
    test_sha = sha256_file(guard_read(SPLIT_PATH["test"]))
    if test_sha != P["datasets"]["test"]["expected_sha256"]:
        fatal(f"test.parquet sha256 {test_sha[:16]}... != prereg / manifest_v1_1 "
              f"{P['datasets']['test']['expected_sha256'][:16]}...; STOP")
    log(f"test.parquet sha256 == manifest_v1_1 ({test_sha[:16]}...)")
    sch = check_schema("test", feats)
    if sch["rows"] != P["datasets"]["test"]["expected_rows"]:
        fatal(f"test rows {sch['rows']} != {P['datasets']['test']['expected_rows']}; STOP")
    meta_ev = load_eval_meta("test")
    routed, cov = route(meta_ev, group_of)
    if not cov["routed_exactly_once"]:
        fatal("routing: a row is not routed exactly once; STOP")
    X = load_matrix(SPLIT_PATH["test"], feats)
    scores, _ = score_systems(models, X, routed)
    del X
    rt["test_score_s"] = round(time.monotonic() - t, 1)
    t = time.monotonic()
    R = report(out, "test", meta_ev, routed, scores, thr, hours, families, sinfo)
    rt["report_s"] = round(time.monotonic() - t, 1)
    for m, i in P["models"].items():
        if sha256_file(Path(i["path"]).expanduser()) != i["sha256"]:
            fatal(f"model {m} changed during the run; STOP")

    minfo = {m: dict(i) for m, i in P["models"].items()}
    meta = {**run_meta_base("test", run_utc, head), "split": "test",
            "split_file": {"path": TEST_REL, "sha256": test_sha, "rows": sch["rows"]},
            "rows_dropped_by_filter": {"test": sch["rows_dropped_by_filter"]},
            "prereg": rel(PREREG), "prereg_sha256": prereg_sha, "test_marker": marker, "thresholds": thr,
            "hours": hours, "routing": cov, "models": minfo, "sessions": sinfo, "row_counts": R["counts"],
            "predictions_sha256": R["predictions_sha256"], "fitting_disabled": FIT_FORBIDDEN}
    meta["runtimes_s"] = {**rt, "total_s": round(time.monotonic() - t0, 1)}
    meta["finished_utc"] = utc_now()
    write_json(out / "run_meta.json", meta)
    write_summary(out, meta, R)
    log(f"done in {meta['runtimes_s']['total_s']:.0f} s -> {rel(out)}/summary.md")
    lock_fh.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", required=True, choices=["dryrun", "test"],
                    help="dryrun: train, pick thresholds, report on val, write the prereg; test: the one-time run")
    args = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    try:
        return dryrun(args) if args.mode == "dryrun" else test(args)
    except SystemExit:
        raise
    except Exception:
        log("UNEXPECTED ERROR\n" + traceback.format_exc())
        return 2


if __name__ == "__main__":
    sys.exit(main())
