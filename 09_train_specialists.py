#!/usr/bin/env python
"""09_train_specialists.py -- Step 9: per-group specialist detectors (binary: 0 benign / 1 attack).

Subcommands
  bakeoff     round 1 model bake-off, train -> val
  robustness  shortlist x feature set x seed, val + unseen-session false alarms (train / val only)
  splits      split-strategy comparison                  (later; NotImplementedError)
  final       final fit + single test evaluation         (later; NotImplementedError)

bakeoff
  For every (group, model) in --groups x --models: fit on the group's TRAIN rows, score its VAL rows
  (predict_proba, attack column) and report
    threshold-free    PR-AUC (average precision, attack = positive class) and ROC-AUC on val
    operating points  flag attack iff score >= threshold. "default_0.5": threshold 0.5. "fph_<B>": the
                      LOWEST threshold, over the observed val scores, whose val FP/hour <= B (threshold
                      inf = the budget is only met by flagging nothing). Per point: threshold, FP count,
                      FP/hour, overall detection rate (DR) and DR per attack_family; a family DR on
                      < CONFIG low_n rows is LOW_N, a family absent from the group's val is N/A.
                      Thresholds are picked on val and DR is read on the same val (optimistic).
    Pi-cost proxies   LAPTOP numbers, not Pi numbers: joblib size in memory (scaler included),
                      single-flow predict latency median / p99 over 1000 one-row calls and batch
                      throughput on 10k val rows (both 1 thread: n_jobs=1 / thread_count=1 plus
                      threadpoolctl limit 1), fit time (all cores), child peak RSS.
  Groups: G1, G2 and GLOBAL (= every train / val row, GEN devices included, same splits).
  Round 1 = library defaults + class-weight handling only (CONFIG); no hyperparameter search.
  Preprocessing: tree models get the 70 raw features. LR / kNN / MLP get the 70 features plus
  zero_duration_flag ("Flow Duration" == 0: 08 replaced NaN / Inf with 0, so a 0 packets/s there
  means infinite), then a StandardScaler fitted on TRAIN only (pipeline: flag -> scaler -> model).

  FP/hour denominator = the group's ACTIVE benign hours in val. manifest_v1.json has no per-group
  value, so it is computed with 08_build_datasets.py's rule (benign_hours, copied below) on 08's own
  active segments and cut points (manifest session_cuts; a pause > 300 s ends a segment) and the
  group's benign flow starts in train + val (test.parquet is never opened). GLOBAL must reproduce
  the manifest's val total (benign_active_hours.per_split.val) or the run stops.

Inputs (read-only): ~/lgids_cache/datasets/v1/{train,val}.parquet (only the columns needed),
config/features_v1.json (sha256 must equal manifest features.sha256), results/step8/manifest_v1.json,
config/attack_set.json; config/config.py verify_lock() must pass. No path containing "test" is read.

Outputs (--out, default results/step9/bakeoff; --dry-run default results/step9/bakeoff/dry_run)
  metrics.csv      one row per (group, model, operating_point)
  per_family.csv   one row per (group, model, operating_point, attack_family) with n and LOW_N / N/A
  cost.csv         one row per (group, model): size, latency, throughput, fit time, params
  run_meta.json    features sha, verify_lock, versions, CONFIG, row counts, FP/hour denominators
  summary.md       per group, models ranked by PR-AUC with DR at FP/hour <= 1 and cost alongside,
                   plus every LOW_N / N/A / TIMEOUT caveat. No winner is declared.
  run.log          timestamped progress
  Rows are appended as each combo finishes (per_family, cost, then metrics last = commit marker).
  A restart skips combos with an OK or TIMEOUT row in metrics.csv (--retry-timeouts reruns
  TIMEOUT); ERROR / MISSING_LIB combos are always rerun. Models are not saved unless --save-models
  (-> ~/lgids_cache/models/bakeoff/, never the repo).

Each combo runs in a spawned child process: the per-model time limit (CONFIG time_limit_s) kills it
and records TIMEOUT, and all its memory is returned when it exits. One run per out dir: exclusive
flock on <out>/.09_bakeoff.lock.

robustness
  For every (group, model, feature_set, seed) in --groups x --models x --feature-sets x --seeds
  (ROBUST block below; same estimators, class weights and preprocessing as bakeoff, no search):
    A val        fit on the group's TRAIN rows, score its VAL rows: PR-AUC, ROC-AUC, DR / FP / FP/hour
                 at 0.5 and at the lowest observed val score with <= 1 val FP (same-set threshold,
                 optimistic), DR per attack_family with LOW_N / N/A flags.
    B unseen_<R> GLOBAL only, cross-capture rotation R (copied from 09b_leakage_checks.py check 5): fit
                 on TRAIN minus every row of the held-out SYN session; report DR on that session's
                 syn_flood rows (train + val) and FP / FP/hour at 0.5 and at a val-chosen <= 1 FP
                 threshold (chosen on the group's val rows outside the held-out session) on (i) the
                 group's val benign and (ii) the held-out session's own benign rows (train + val).
      benign_holdout  G1 / G2: fit on the group's TRAIN rows minus ONLY the benign rows of the session
                 whose SYN victims are in the group (G1 DDoS-SYN_Flood, G2 DDoS-SYN_Flood5; every attack
                 row kept); same FP numbers on (i) and (ii); held-out SYN DR is N/A (trained on).
    C cost       once per (group, model, feature_set), on the seed-42 val fit: bakeoff's cost proxies.
  FP/hour denominators: val = bakeoff's per-group value; unseen = 08's rule on exactly the benign rows
  evaluated (dry run: scaled by the benign sample fraction). Each (group, model, feature_set) runs in
  one spawned child that loads the data once and streams one result per (seed, evaluation); the
  parent writes it at once, so a restart resumes per (group, model, feature_set, seed, evaluation).
  Outputs (--out, default results/step9/robustness; --dry-run results/step9/robustness/dry_run):
  val_metrics.csv, per_family.csv, unseen_session.csv, cost.csv, run_meta.json, summary.md, run.log.
  Lock <out>/.09_robustness.lock. No winner is declared.

Exit status: 0 ok, 1 bad input / lock / check failed / another run active, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import gc
import hashlib
import importlib.metadata
import importlib.util
import inspect
import io
import json
import math
import multiprocessing as mp
import os
import platform
import re
import resource
import signal
import sys
import time
import traceback
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight
from threadpoolctl import threadpool_info, threadpool_limits

from config.config import CACHE_DIR, CONFIG_DIR, REPO_ROOT, RESULTS_DIR, LockError, verify_lock

# --------------------------------------------------------------------------- CONFIG

CONFIG = {
    "seed": 42,
    "groups": ["G1", "G2", "GLOBAL"],
    "global_group": "GLOBAL",
    "global_note": "GLOBAL = all train / val rows (G1 + G2 + GEN devices), same splits",
    "models": ["LR", "DT", "RF", "ET", "XGB", "LGBM", "CAT", "KNN", "MLP"],
    "model_names": {"LR": "LogisticRegression", "DT": "DecisionTree", "RF": "RandomForest",
                    "ET": "ExtraTrees", "XGB": "XGBoost", "LGBM": "LightGBM", "CAT": "CatBoost",
                    "KNN": "kNN", "MLP": "MLP (sklearn)"},
    "excluded_models": {"1D-CNN": "round 1 is per-flow input; windowed input is a separate design axis"},
    "round": 1,
    "hyperparameters": "library defaults + class-weight handling only; no search",
    # The only departures from library defaults; listed in run_meta.json "deviations" and summary.md.
    "deviations": {"LR": {"param": "max_iter", "value": 2000, "library_default": 100,
                          "reason": "convergence fix, not tuning (lbfgs stopped at 100 iterations with a "
                                    "ConvergenceWarning on GLOBAL)"}},
    "class_weight": {"LR": "class_weight='balanced'", "DT": "class_weight='balanced'",
                     "RF": "class_weight='balanced'", "ET": "class_weight='balanced'",
                     "LGBM": "class_weight='balanced'", "CAT": "auto_class_weights='Balanced'",
                     "XGB": "scale_pos_weight = n_benign / n_attack of the group's train",
                     "KNN": "none (kNN has no class weights)",
                     "MLP": "sample_weight=compute_sample_weight('balanced') if MLPClassifier.fit takes "
                            "sample_weight, else random oversampling of the minority class in TRAIN"},
    "non_hyperparameter_settings": {
        "n_jobs / thread_count": "fit and full-val scoring use all cores (fit_n_jobs); latency and "
                                 "throughput use 1 thread",
        "CAT allow_writing_files": False,
        "CAT verbose": False,
        "LGBM verbosity": -1,
    },
    "fit_n_jobs": -1,
    "scaled_models": ["LR", "KNN", "MLP"],
    "duration_feature_pattern": "duration",
    "zero_duration_flag": "zero_duration_flag",
    "scaler": "StandardScaler fitted on TRAIN only, applied to the 70 features + zero_duration_flag",
    "default_threshold": 0.5,
    "fph_budgets": [0.5, 1, 5],
    "threshold_rule": "flag attack iff score >= threshold; budget points pick the lowest observed val "
                      "score whose val FP/hour <= budget (allowed FP = floor(budget * hours))",
    "summary_fph": 1,
    "low_n": 50,
    "time_limit_s": {"default": 1800},
    "latency": {"single_calls": 1000, "warmup_calls": 20, "batch_rows": 10_000, "threads": 1},
    "dry_run_frac": 0.05,
    "dry_run_strata": ["group", "y", "attack_family"],
    "active_idle_gap_seconds": 300,
}

# Robustness round (subcommand "robustness"). Kept out of CONFIG so bakeoff's run_meta.json is unchanged.
ROBUST = {
    "models": ["XGB", "CAT", "LGBM", "MLP"],
    "groups": ["G1", "G2", "GLOBAL"],
    "hyperparameters": "same constructors / params as bakeoff (library defaults + class weights; MLP keeps "
                       "zero_duration_flag + StandardScaler); no search",
    # Feature set -> names removed from features_v1.json (each must occur exactly once there).
    "feature_sets": {"full70": [],
                     "tool_agnostic67": ["FWD Init Win Bytes", "Fwd Seg Size Min", "Fwd Header Length"]},
    "feature_set_note": "tool_agnostic67 drops the tool-artefact fingerprints of 09b check 2 (FWD Init Win Bytes "
                        "512 for SYN flood / 1024 for port scan; Fwd Seg Size Min / Fwd Header Length = headers "
                        "without TCP options)",
    "seeds": [42, 7, 123],
    "seed_use": "random_state / random_seed of the estimator, np.random.seed in the child and the MLP "
                "oversampling rng; the dry-run subsample keeps CONFIG seed 42 for every seed",
    "cost_seed": 42,
    "max_fp": 1,
    "max_fp_label": "same-set threshold, optimistic",
    "syn_family": "syn_flood",
    # Exact sessions of 09b check 5 (resolved from split_plan session_aliases and checked against these).
    "rotations": {"A": {"held_out_alias": "SYN 5", "session": "DDoS-SYN_Flood5", "victim_group": "G2"},
                  "B": {"held_out_alias": "SYN first part", "session": "DDoS-SYN_Flood", "victim_group": "G1"}},
    "rotation_rule": "GLOBAL runs every capture rotation (evaluation unseen_<R>, variant capture_rotation)",
    # G1 / G2: hold out only the benign rows of the session whose SYN victims are in the group (evaluation
    # benign_holdout). A capture rotation there would leave the group with no syn_flood training row at all.
    "benign_holdout": {"G1": "DDoS-SYN_Flood", "G2": "DDoS-SYN_Flood5"},
    "benign_holdout_train_rows": "the group's train rows minus ONLY the held-out session's benign rows (every attack "
                                 "row kept, that session's SYN rows included)",
    "benign_holdout_syn_dr": "N/A (the held-out session's SYN rows are in training)",
    "unseen_train_rows": "the group's train rows minus every row of the held-out session (attack and benign)",
    "unseen_threshold_rule": "lowest observed score of the group's val rows outside the held-out session with "
                             "<= max_fp FP on those val benign rows (the threshold never sees the held-out session)",
    "unseen_val_benign": "all of the group's val benign rows (09b check 5 definition); they include the held-out "
                         "session's own val benign rows, which are also part of held_session_benign",
    "unseen_held_benign": "the held-out session's benign rows of the group, train + val splits",
    "unseen_syn_rows": "the held-out session's syn_flood rows of the group, train + val splits",
    "time_limit_s_per_evaluation": CONFIG["time_limit_s"]["default"],
}

SCRIPT = "09_train_specialists.py"
TRAIN_PARQUET = CACHE_DIR / "datasets" / "v1" / "train.parquet"
VAL_PARQUET = CACHE_DIR / "datasets" / "v1" / "val.parquet"
FEATURES_JSON = CONFIG_DIR / "features_v1.json"
ATTACK_SET = CONFIG_DIR / "attack_set.json"
SPLIT_PLAN = CONFIG_DIR / "split_plan.json"
MANIFEST = RESULTS_DIR / "step8" / "manifest_v1.json"
OUT_DEFAULT = RESULTS_DIR / "step9" / "bakeoff"
ROBUST_OUT = RESULTS_DIR / "step9" / "robustness"
ROBUST_LOCK = ".09_robustness.lock"
MODELS_DIR = CACHE_DIR / "models" / "bakeoff"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()

META_COLS = ["y", "attack_family", "group", "device", "device_category", "session", "split", "start_ts"]
LOAD_META = ["y", "attack_family", "group", "session", "start_ts"]
IDENTITY_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp", "Label"]
IDENTITY_RE = re.compile(r"(?i)\b(ip|port|mac|id)\b|timestamp|label|owner|device|group|session")
LIBS = {"XGB": "xgboost", "LGBM": "lightgbm", "CAT": "catboost"}
STATUS_DONE = {"OK", "TIMEOUT"}
RUN_LOCK = ".09_bakeoff.lock"

METRIC_COLS = ["group", "model", "status", "operating_point", "fph_budget", "threshold", "allowed_fp", "fp",
               "fp_per_hour", "tp", "n_attack_val", "n_benign_val", "detection_rate", "pr_auc", "roc_auc",
               "val_benign_hours", "n_train", "n_train_benign", "n_train_attack", "preprocessing",
               "class_weight_handling", "note", "dry_run", "run_utc"]
FAMILY_COLS = ["group", "model", "operating_point", "threshold", "attack_family", "n", "detected",
               "detection_rate", "flag", "dry_run"]
COST_COLS = ["group", "model", "status", "size_bytes", "latency_median_us", "latency_p99_us", "latency_calls",
             "throughput_flows_s", "batch_rows", "fit_s", "val_score_s", "load_s", "wall_s", "child_peak_rss_mb",
             "fit_threads", "predict_threads", "fit_warnings", "n_iter", "params_json", "error", "proxy_note",
             "dry_run"]
PROXY_NOTE = "laptop proxy (WSL), not a Pi measurement"


# --------------------------------------------------------------------------- small helpers

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


def rel(p: Path | str) -> str:
    """Repo-relative path, or ~/... for the cache (run_meta holds relative paths only)."""
    p = Path(p).expanduser().resolve()
    for base, tag in ((REPO_ROOT.resolve(), ""), (Path.home().resolve(), "~/")):
        if p.is_relative_to(base):
            return tag + str(p.relative_to(base))
    return str(p)


def scrub(s: str) -> str:
    """Absolute repo / home prefixes in free text -> relative."""
    return str(s).replace(str(REPO_ROOT.resolve()) + "/", "").replace(str(Path.home().resolve()), "~")


def guard_read(path: Path) -> Path:
    """bakeoff never opens the test split: every file read goes through here."""
    if "test" in str(path).lower():
        raise AssertionError(f"bakeoff must not read {path} (path contains 'test')")
    return path


def read_json(path: Path) -> dict:
    return json.loads(guard_read(path).read_text(encoding="utf-8"))


def lib_versions() -> dict:
    out = {"python": platform.python_version()}
    for pkg in ("numpy", "pandas", "pyarrow", "scipy", "scikit-learn", "joblib", "threadpoolctl",
                "xgboost", "lightgbm", "catboost"):
        try:
            out[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            out[pkg] = "not installed"
    return out


def md_table(rows: list[dict], cols: list[str]) -> list[str]:
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(str(r.get(c, "")) for c in cols) + " |" for r in rows]
    return out


# Origin: 08_build_datasets.py run_lock() (same flock pattern, own lock file name).
def run_lock(d: Path, name: str = RUN_LOCK, stage: str = "bakeoff"):
    """Exclusive, non-blocking flock on <d>/<name> (.09_bakeoff.lock) for the whole run (released by
    the kernel on exit). Two runs appending to the same CSVs would corrupt each other."""
    d.mkdir(parents=True, exist_ok=True)
    path = d / name
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another {SCRIPT} {stage} is using {rel(d)} (lock {name} held by: {holder}); "
              "refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}"
             f" argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


# --------------------------------------------------------------------------- FP/hour denominator

# Origin: 08_build_datasets.py benign_hours() (verbatim apart from the SPLITS constant), so the
# per-group denominator follows the exact active-time rule the manifest's totals were built with.
SPLITS = ("train", "val", "test")


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


def val_hours(M: dict, benign: pd.DataFrame) -> tuple[float, dict]:
    """Active benign val hours of the benign flow starts in `benign` (columns session, start_ts),
    on 08's own active segments and cut points from the manifest."""
    per = {}
    for sess, c in M["session_cuts"].items():
        seg = np.array([[pd.Timestamp(a).timestamp(), pd.Timestamp(b).timestamp()]
                        for a, b in c["active_segments_utc"]], dtype=float)
        t = benign.loc[benign["session"] == sess, "start_ts"].to_numpy(dtype=float)
        per[sess] = benign_hours(seg, t, (c["boundaries_epoch"], c["splits"]))["val"]
    return float(sum(per.values())), per


# --------------------------------------------------------------------------- models (child side)

def add_zero_duration_flag(X: np.ndarray, col: int) -> np.ndarray:
    """Append zero_duration_flag = (Flow Duration == 0); 08 filled NaN / Inf with 0, so the rate
    features of those flows read 0 where the true value is infinite."""
    return np.hstack([X, (X[:, col] == 0).astype(X.dtype)[:, None]])


def oversample_minority(X: np.ndarray, y: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray, str]:
    """Random oversampling (with replacement) of the minority class up to the majority count."""
    rng = np.random.default_rng(seed)
    n0, n1 = int((y == 0).sum()), int((y == 1).sum())
    mino = 0 if n0 < n1 else 1
    idx = np.flatnonzero(y == mino)
    extra = rng.choice(idx, size=abs(n1 - n0), replace=True)
    note = f"random oversampling of class {mino} in TRAIN ({len(idx)} -> {len(idx) + len(extra)})"
    return np.vstack([X, X[extra]]), np.r_[y, y[extra]], note


# Origin: AI/src/stage1_models.py get_model_zoo() -- same estimators and class-weight wiring, but
# with LIBRARY DEFAULTS (the old zoo's 300 trees / depth 8 / lr 0.1 are not used in round 1) and
# kNN / MLP added; boosting libraries imported lazily (missing library -> MISSING_LIB, not a crash).
def build_model(code: str, y: np.ndarray, dur_idx: int, seed: int, n_jobs: int, n_feats: int = 70):
    """-> (model, class_weight note, preprocessing note, mlp_needs_oversampling)."""
    n_ben, n_att = int((y == 0).sum()), int((y == 1).sum())
    cw, oversample = CONFIG["class_weight"][code], False
    if code == "LR":
        est = LogisticRegression(class_weight="balanced", random_state=seed,
                                 max_iter=CONFIG["deviations"]["LR"]["value"])
    elif code == "DT":
        est = DecisionTreeClassifier(class_weight="balanced", random_state=seed)
    elif code == "RF":
        est = RandomForestClassifier(class_weight="balanced", random_state=seed, n_jobs=n_jobs)
    elif code == "ET":
        est = ExtraTreesClassifier(class_weight="balanced", random_state=seed, n_jobs=n_jobs)
    elif code == "XGB":
        from xgboost import XGBClassifier
        spw = n_ben / n_att
        est = XGBClassifier(scale_pos_weight=spw, random_state=seed, n_jobs=n_jobs)
        cw = f"scale_pos_weight = n_benign / n_attack = {n_ben} / {n_att} = {spw:.6g}"
    elif code == "LGBM":
        from lightgbm import LGBMClassifier
        est = LGBMClassifier(class_weight="balanced", random_state=seed, n_jobs=n_jobs, verbosity=-1)
    elif code == "CAT":
        from catboost import CatBoostClassifier
        est = CatBoostClassifier(auto_class_weights="Balanced", random_seed=seed, thread_count=n_jobs,
                                 verbose=False, allow_writing_files=False)
    elif code == "KNN":
        est = KNeighborsClassifier(n_jobs=n_jobs)
    elif code == "MLP":
        est = MLPClassifier(random_state=seed)
        if "sample_weight" in inspect.signature(MLPClassifier.fit).parameters:
            cw = "sample_weight = compute_sample_weight('balanced', y_train) (MLPClassifier.fit supports it)"
        else:
            oversample = True
    else:
        raise ValueError(f"unknown model code {code}")
    if code in CONFIG["scaled_models"]:
        model = Pipeline([("zero_duration_flag", FunctionTransformer(add_zero_duration_flag,
                                                                     kw_args={"col": dur_idx})),
                          ("scaler", StandardScaler()),
                          ("clf", est)])
        pre = f"{n_feats} raw + zero_duration_flag -> StandardScaler(train)"
    else:
        model, pre = est, f"{n_feats} raw features"
    return model, cw, pre, oversample


def fit_model(code: str, Xtr: np.ndarray, ytr: np.ndarray, dur_idx: int, seed: int):
    """build_model + class-weight wiring + fit -> (model, class_weight note, preprocessing note, fit_s,
    fit warnings)."""
    model, cw, pre, oversample = build_model(code, ytr, dur_idx, seed, CONFIG["fit_n_jobs"], Xtr.shape[1])
    fit_kw = {}
    if code == "MLP" and not oversample:
        fit_kw["clf__sample_weight"] = compute_sample_weight("balanced", ytr)
    if oversample:
        Xtr, ytr, cw = oversample_minority(Xtr, ytr, seed)
    with warnings.catch_warnings(record=True) as W:
        warnings.simplefilter("always")
        t = time.perf_counter()
        model.fit(Xtr, ytr, **fit_kw)
        fit_s = time.perf_counter() - t
    fit_warn = sorted({f"{w.category.__name__}: {str(w.message).splitlines()[0][:160]}" for w in W})
    return model, cw, pre, fit_s, fit_warn


def final_estimator(model):
    return model.steps[-1][1] if isinstance(model, Pipeline) else model


def params_of(model) -> dict:
    if isinstance(model, Pipeline):
        return {name: {"class": type(step).__name__, **step.get_params(deep=False)} for name, step in model.steps}
    return {"class": type(model).__name__, **model.get_params(deep=False)}


def load_matrix(path: Path, feats: list[str], rows: np.ndarray) -> np.ndarray:
    """Rows `rows` of the 70 feature columns, in features_v1 order, as float32."""
    t = pq.read_table(guard_read(path), columns=feats)
    if t.column_names != feats:
        raise AssertionError(f"{path.name}: feature columns {t.column_names[:3]}... != features_v1 order")
    X = np.empty((len(rows), len(feats)), dtype=np.float32)
    for j, c in enumerate(feats):
        X[:, j] = t.column(c).to_numpy()[rows]
    del t
    if X.shape[1] != 70:
        raise AssertionError(f"feature matrix has {X.shape[1]} columns, expected 70")
    return X


def single_thread_predictor(model, code: str, pos: int):
    """A 1-thread predict_proba(attack) callable (n_jobs=1 / thread_count=1)."""
    est = final_estimator(model)
    if code == "CAT":
        return lambda X: model.predict_proba(X, thread_count=1)[:, pos]
    if "n_jobs" in est.get_params(deep=False):
        est.set_params(n_jobs=1)
    return lambda X: model.predict_proba(X)[:, pos]


def model_size(model) -> int:
    """joblib size in memory (scaler included)."""
    buf = io.BytesIO()
    joblib.dump(model, buf)
    return int(buf.tell())


def cost_proxies(model, code: str, pos: int, Xva: np.ndarray, seed: int) -> dict:
    """1-thread single-flow latency over CONFIG latency single_calls one-row calls and batch throughput on
    batch_rows val rows. Leaves the model's estimator at n_jobs=1."""
    L = CONFIG["latency"]
    rng = np.random.default_rng(seed)
    lat_rows = rng.choice(len(Xva), size=min(L["single_calls"], len(Xva)), replace=False)
    Xl = np.ascontiguousarray(Xva[lat_rows])
    Xb = np.ascontiguousarray(Xva[rng.choice(len(Xva), size=min(L["batch_rows"], len(Xva)), replace=False)])
    predict1 = single_thread_predictor(model, code, pos)
    with threadpool_limits(limits=L["threads"]):
        for i in range(min(L["warmup_calls"], len(Xl))):
            predict1(Xl[i:i + 1])
        ns = np.empty(L["single_calls"], dtype=np.int64)
        for i in range(L["single_calls"]):
            x = Xl[i % len(Xl)][None, :]
            t0 = time.perf_counter_ns()
            predict1(x)
            ns[i] = time.perf_counter_ns() - t0
        t = time.perf_counter()
        predict1(Xb)
        batch_s = time.perf_counter() - t
    return {"latency_median_us": float(np.median(ns)) / 1e3, "latency_p99_us": float(np.percentile(ns, 99)) / 1e3,
            "latency_calls": int(len(ns)),
            "throughput_flows_s": len(Xb) / batch_s if batch_s > 0 else float("inf"), "batch_rows": len(Xb)}


def run_combo(job: dict) -> dict:
    """Child process body: load -> fit -> score val -> cost proxies."""
    t_all = time.perf_counter()
    code, seed = job["model"], CONFIG["seed"]
    np.random.seed(seed)
    feats = job["features"]
    t = time.perf_counter()
    Xtr = load_matrix(job["train_path"], feats, job["tr_rows"])
    ytr = job["y_tr"]
    Xva = load_matrix(job["val_path"], feats, job["va_rows"])
    load_s = time.perf_counter() - t

    model, cw, pre, fit_s, fit_warn = fit_model(code, Xtr, ytr, job["dur_idx"], seed)
    # LightGBM 4.6 stores auto feature names (Column_i) for numpy input, so sklearn warns on every
    # numpy predict: 1000s of lines in nohup.out and warning overhead inside the latency proxy.
    warnings.filterwarnings("ignore", message="X does not have valid feature names", category=UserWarning)
    del Xtr
    gc.collect()

    est = final_estimator(model)
    classes = [int(c) for c in est.classes_]
    if classes != [0, 1]:
        raise AssertionError(f"classes_ {classes} != [0, 1]")
    pos = classes.index(1)
    t = time.perf_counter()
    scores = model.predict_proba(Xva)[:, pos].astype(np.float64)
    val_score_s = time.perf_counter() - t

    size = model_size(model)
    params = params_of(model)
    n_iter = getattr(est, "n_iter_", None)
    if job["save_path"]:
        Path(job["save_path"]).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, job["save_path"])

    cost = cost_proxies(model, code, pos, Xva, seed)
    return {"status": "OK", "scores": scores, "fit_s": fit_s, "val_score_s": val_score_s, "load_s": load_s,
            "size_bytes": size, **cost,
            "fit_warnings": fit_warn, "n_iter": None if n_iter is None else np.asarray(n_iter).tolist(),
            "params": params, "class_weight_handling": cw, "preprocessing": pre,
            "child_peak_rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024,
            "wall_s": time.perf_counter() - t_all}


def worker(conn, job: dict) -> None:
    try:
        res = run_combo(job)
    except BaseException:
        res = {"status": "ERROR", "error": traceback.format_exc(limit=6)}
    try:
        conn.send(res)
    finally:
        conn.close()


# --------------------------------------------------------------------------- evaluation (parent side)

def max_fp_threshold(cand: np.ndarray, ben_desc: np.ndarray, k: int) -> float:
    """Lowest of the sorted unique observed scores `cand` that flags <= k of the benign scores
    `ben_desc` (sorted descending); inf = only flagging nothing meets it."""
    if k >= len(ben_desc):
        return float(cand[0])                          # budget allows every benign flow: flag all
    i = int(np.searchsorted(cand, ben_desc[k], side="right"))
    return float(cand[i]) if i < len(cand) else math.inf


def operating_points(score: np.ndarray, y: np.ndarray, fam: np.ndarray, families: list[str],
                     hours: float) -> tuple[list[dict], list[dict]]:
    """Rows of metrics.csv (op-point part) and per_family.csv for one scored combo."""
    ben_desc = np.sort(score[y == 0])[::-1]
    cand = np.unique(score)
    pts = [("default_0.5", None, float(CONFIG["default_threshold"]), None)]
    for B in CONFIG["fph_budgets"]:
        k = int(math.floor(B * hours + 1e-9))
        pts.append((f"fph_{B:g}", B, max_fp_threshold(cand, ben_desc, k), k))
    n_att, n_ben = int((y == 1).sum()), int((y == 0).sum())
    rows, frows = [], []
    for op, B, thr, k in pts:
        flag = score >= thr
        fp, tp = int((flag & (y == 0)).sum()), int((flag & (y == 1)).sum())
        if k is not None and fp > k:
            raise AssertionError(f"{op}: FP {fp} > allowed {k}")
        note = "budget met only by flagging nothing" if math.isinf(thr) else ""
        rows.append({"operating_point": op, "fph_budget": B, "threshold": thr, "allowed_fp": k, "fp": fp,
                     "fp_per_hour": fp / hours if hours > 0 else math.nan, "tp": tp, "n_attack_val": n_att,
                     "n_benign_val": n_ben, "detection_rate": tp / n_att if n_att else math.nan, "note": note})
        for f in families:
            m = (y == 1) & (fam == f)
            n = int(m.sum())
            det = int((flag & m).sum())
            frows.append({"operating_point": op, "threshold": thr, "attack_family": f, "n": n, "detected": det,
                          "detection_rate": det / n if n else math.nan,
                          "flag": "N/A" if n == 0 else ("LOW_N" if n < CONFIG["low_n"] else "")})
    return rows, frows


def stratified_sample(meta: pd.DataFrame, frac: float, seed: int) -> np.ndarray:
    """Sorted row positions: frac of every (group, y, attack_family) stratum, at least 1 row each."""
    rng = np.random.default_rng(seed)
    keep = []
    for _, idx in meta.groupby(CONFIG["dry_run_strata"], sort=True).indices.items():
        n = max(1, int(round(frac * len(idx))))
        keep.append(rng.choice(idx, size=n, replace=False))
    return np.sort(np.concatenate(keep))


def append_rows(path: Path, rows: list[dict], cols: list[str]) -> None:
    if rows:
        pd.DataFrame(rows, columns=cols).to_csv(path, mode="a", header=not path.exists(), index=False)


def read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(guard_read(path), keep_default_na=False) if path.exists() else pd.DataFrame()


def rewrite_without(path: Path, keep_mask_fn) -> int:
    """Rewrite a results CSV keeping only rows where keep_mask_fn(df) is True; returns rows dropped."""
    df = read_csv(path)
    if df.empty:
        return 0
    keep = keep_mask_fn(df)
    if keep.all():
        return 0
    tmp = path.with_suffix(".csv.tmp")
    df[keep].to_csv(tmp, index=False)
    os.replace(tmp, path)
    return int((~keep).sum())


def resume_state(out: Path, dry: bool, retry_timeouts: bool) -> set[tuple[str, str]]:
    """Combos already done (metrics.csv rows with a done status); stale per_family / cost rows of
    every other combo are dropped so the rerun's rows are the only ones."""
    m = read_csv(out / "metrics.csv")
    if m.empty:
        for name in ("per_family.csv", "cost.csv"):
            (out / name).unlink(missing_ok=True)
        return set()
    flags = set(m["dry_run"].astype(str))
    if flags != {str(dry)}:
        fatal(f"{rel(out)}/metrics.csv holds dry_run={sorted(flags)} rows but this run is dry_run={dry}; "
              "use another --out")
    ok = STATUS_DONE - ({"TIMEOUT"} if retry_timeouts else set())
    status = m.groupby(["group", "model"])["status"].first()
    done = {k for k, s in status.items() if s in ok}

    def keep(df):
        return pd.Series([(g, mo) in done for g, mo in zip(df["group"], df["model"])], index=df.index)

    for name in ("metrics.csv", "per_family.csv", "cost.csv"):
        n = rewrite_without(out / name, keep)
        if n:
            log(f"resume: dropped {n} stale / failed rows from {name}")
    return done


# --------------------------------------------------------------------------- summary

def fmt(v, nd=4) -> str:
    try:
        v = float(v)
    except (TypeError, ValueError):
        return str(v) if v not in (None, "") else "-"
    if math.isnan(v):
        return "-"
    if math.isinf(v):
        return "inf"
    return f"{v:.{nd}f}"


def fmt_size(b) -> str:
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "-"
    if math.isnan(b):
        return "-"
    return f"{b / 1e6:.2f} MB" if b >= 1e6 else f"{b / 1e3:.1f} kB"


def write_summary(out: Path, meta: dict) -> None:
    m, f, c = read_csv(out / "metrics.csv"), read_csv(out / "per_family.csv"), read_csv(out / "cost.csv")
    op = f"fph_{CONFIG['summary_fph']:g}"
    lab = f"FP/h<={CONFIG['summary_fph']:g}"
    families = meta["attack_families"]
    L = [f"# Step 9 bake-off (round 1){' -- DRY RUN (5 % stratified subsample)' if meta['dry_run'] else ''}", "",
         f"- run: {meta['run_utc']} | seed {CONFIG['seed']} | features sha256 {meta['features']['sha256'][:16]}... "
         f"| verify_lock {'PASS' if meta['verify_lock']['ok'] else 'FAIL'}",
         "- Round 1 = library defaults + class-weight handling only. Ranked by val PR-AUC; "
         "**no winner is declared**.",
         *[f"- Deviation from defaults: {m} {d['param']}={d['value']} (default {d['library_default']}): "
           f"{d['reason']}." for m, d in CONFIG["deviations"].items()],
         f"- DR@FP/h<={CONFIG['summary_fph']:g}: lowest val threshold with val FP/hour <= "
         f"{CONFIG['summary_fph']:g}; thresholds are chosen on val and DR is read on the same val, so it is "
         "optimistic.",
         "- Latency / throughput / size are laptop proxies (WSL, 1 thread), not Pi numbers. "
         "Fit time uses all cores.",
         f"- {CONFIG['global_note']}.", ""]
    L += ["## FP/hour denominators (active benign val hours)", ""]
    L += md_table([{"group": g, "hours": fmt(h["hours_used"], 4), "source": h["source"]}
                   for g, h in meta["fph_denominators"].items()], ["group", "hours", "source"]) + [""]
    caveats = []
    for g in meta["groups"]:
        L += [f"## {g}", ""]
        if m.empty or g not in set(m["group"]):
            L += ["_no finished combos_", ""]
            continue
        rows = []
        for mo in CONFIG["models"]:
            mm = m[(m["group"] == g) & (m["model"] == mo)]
            if mm.empty:
                continue
            st = mm["status"].iloc[0]
            cc = c[(c["group"] == g) & (c["model"] == mo)] if not c.empty else pd.DataFrame()
            cr = cc.iloc[0] if len(cc) else {}
            r = {"model": mo, "status": st}
            if st == "OK":
                a = mm[mm["operating_point"] == op].iloc[0]
                d = mm[mm["operating_point"] == "default_0.5"].iloc[0]
                r.update({"PR-AUC": fmt(a["pr_auc"]), "ROC-AUC": fmt(a["roc_auc"]),
                          f"thr@{lab}": fmt(a["threshold"], 6), f"FP/h@{lab}": fmt(a["fp_per_hour"], 2),
                          f"DR@{lab}": fmt(a["detection_rate"]), "DR@0.5": fmt(d["detection_rate"]),
                          "FP/h@0.5": fmt(d["fp_per_hour"], 2), "_sort": float(a["pr_auc"])})
                for fam in families:
                    ff = f[(f["group"] == g) & (f["model"] == mo) & (f["operating_point"] == op)
                           & (f["attack_family"] == fam)]
                    if len(ff):
                        x = ff.iloc[0]
                        r[f"DR {fam}"] = "N/A" if x["flag"] == "N/A" else (
                            fmt(x["detection_rate"]) + (" LOW_N" if x["flag"] == "LOW_N" else ""))
                if a["note"]:
                    caveats.append(f"{g} {mo}: at {lab} the {a['note']} (threshold inf, DR 0)")
            else:
                r["_sort"] = -1.0
                caveats.append(f"{g} {mo}: **{st}**" + (f" -- {str(cr.get('error', ''))[:200]}"
                                                       if st != "OK" and len(cc) else ""))
            if len(cc):
                r.update({"lat med us": fmt(cr["latency_median_us"], 1), "lat p99 us": fmt(cr["latency_p99_us"], 1),
                          "flows/s": fmt(cr["throughput_flows_s"], 0), "size": fmt_size(cr["size_bytes"]),
                          "fit s": fmt(cr["fit_s"], 1)})
                if cr.get("fit_warnings"):
                    caveats.append(f"{g} {mo}: fit warnings: {cr['fit_warnings']}")
            rows.append(r)
        rows.sort(key=lambda r: -r["_sort"])
        for i, r in enumerate(rows, 1):
            r["rank"] = i if r["status"] == "OK" else "-"
        cols = (["rank", "model", "status", "PR-AUC", "ROC-AUC", f"DR@{lab}", f"thr@{lab}", f"FP/h@{lab}"]
                + [f"DR {fam}" for fam in families]
                + ["DR@0.5", "FP/h@0.5", "lat med us", "lat p99 us", "flows/s", "size", "fit s"])
        L += md_table(rows, cols) + [""]
    L += ["## Small-sample / missing-family flags (val, per group)", ""]
    flag_rows = [r for r in meta["family_flags"] if r["flag"]]
    L += md_table(flag_rows, ["group", "attack_family", "n_val", "flag"]) + [""]
    L += ["## Caveats", ""]
    L += [f"- {r['group']} {r['attack_family']}: {r['flag']} (n={r['n_val']} val attack rows); its DR "
          + ("is not defined." if r["flag"] == "N/A" else f"rests on < {CONFIG['low_n']} rows.")
          for r in flag_rows]
    L += [f"- {x}" for x in caveats]
    L += [f"- {w}" for w in meta.get("warnings", [])]
    L += ["- GEN val holds benign rows only (no attacks), so GEN contributes FPs but no detections to GLOBAL.",
          "- kNN scores take only k+1 = 6 distinct values (k = 5), so its operating points are coarse."]
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- bakeoff

def check_inputs() -> dict:
    """Lock, feature contract and label checks. Returns the static context of the run."""
    try:
        lock = verify_lock()
    except LockError as e:
        fatal(str(e))
    for name, ok, detail in lock["checks"]:
        log(f"  verify_lock {'PASS' if ok else 'FAIL'}  {name}: {scrub(detail)}")

    M = read_json(MANIFEST)
    F = read_json(FEATURES_JSON)
    feats = list(F["features"])
    sha = hashlib.sha256(json.dumps(feats, separators=(",", ":")).encode("utf-8")).hexdigest()
    file_sha = hashlib.sha256(guard_read(FEATURES_JSON).read_bytes()).hexdigest()
    want = M["features"]["sha256"]
    if sha != want or F.get("sha256") != want:
        fatal(f"features_v1.json sha256 {sha} (its own field {F.get('sha256')}) != manifest features.sha256 "
              f"{want}; refusing to run")
    if len(feats) != 70 or len(set(feats)) != 70:
        fatal(f"features_v1.json lists {len(feats)} features ({len(set(feats))} unique), expected 70")
    leaked = [c for c in feats if c in IDENTITY_COLS or c in META_COLS or IDENTITY_RE.search(c)]
    if leaked:
        fatal(f"identity / metadata / IP / port columns in the feature list: {leaked}")
    dur = [c for c in feats if re.search(CONFIG["duration_feature_pattern"], c, re.I)]
    if len(dur) != 1:
        fatal(f"flow duration column ambiguous in features_v1.json: {dur}; STOP (ask which one)")
    plan_gap = M["plan"]["active_idle_gap_seconds"]
    if plan_gap != CONFIG["active_idle_gap_seconds"]:
        fatal(f"manifest active_idle_gap_seconds {plan_gap} != CONFIG {CONFIG['active_idle_gap_seconds']}")
    for path in (TRAIN_PARQUET, VAL_PARQUET):
        names = pq.read_schema(guard_read(path)).names
        if names != feats + META_COLS:
            fatal(f"{path.name}: columns are not exactly features_v1 (70, in order) + {META_COLS}: "
                  f"extra {sorted(set(names) - set(feats) - set(META_COLS))}, "
                  f"missing {sorted(set(feats + META_COLS) - set(names))}")
    families = sorted({p["family"] for p in read_json(ATTACK_SET)["pcaps"]})
    log(f"features: 70, sha256 {sha[:16]}... == manifest; duration column {dur[0]!r}; families {families}")
    return {"lock": lock, "M": M, "feats": feats, "sha": sha, "file_sha": file_sha, "dur": dur[0],
            "dur_idx": feats.index(dur[0]), "families": families}


def load_meta(path: Path, cols: list[str] = LOAD_META) -> pd.DataFrame:
    df = pq.read_table(guard_read(path), columns=cols).to_pandas()
    df["attack_family"] = df["attack_family"].fillna("").astype(str)
    df["group"] = df["group"].astype(str)
    df["session"] = df["session"].astype(str)
    for c in ("device", "split"):
        if c in df:
            df[c] = df[c].fillna("").astype(str)
    yv = set(np.unique(df["y"]).tolist())
    if not yv <= {0, 1}:
        fatal(f"{path.name}: y takes values {sorted(yv)}, expected 0 = benign / 1 = attack; STOP")
    bad = int(((df["y"] == 1) != (df["attack_family"] != "")).sum())
    if bad:
        fatal(f"{path.name}: {bad} rows where y == 1 disagrees with attack_family being set "
              "(expected 0 = benign with no family, 1 = attack with a family); STOP")
    return df


def group_mask(meta: pd.DataFrame, g: str) -> np.ndarray:
    return np.ones(len(meta), bool) if g == CONFIG["global_group"] else (meta["group"] == g).to_numpy()


def counts(meta: pd.DataFrame) -> dict:
    out = {"rows": int(len(meta)), "benign": int((meta["y"] == 0).sum()), "attack": int((meta["y"] == 1).sum())}
    out["attack_by_family"] = {k: int(v) for k, v in meta.loc[meta["y"] == 1, "attack_family"].value_counts()
                               .sort_index().items()}
    return out


def run_child(job: dict, limit: float) -> dict:
    ctx = mp.get_context("spawn")
    rx, tx = ctx.Pipe(duplex=False)
    # Not daemonic: joblib refuses parallel loops inside a daemon process (it would silently fit
    # RF / ET / kNN with n_jobs=1). The finally below kills the child on timeout / exit / SIGTERM.
    p = ctx.Process(target=worker, args=(tx, job), daemon=False)
    p.start()
    tx.close()
    try:
        if rx.poll(limit):
            try:
                res = rx.recv()
            except EOFError:
                p.join(10)
                res = {"status": "ERROR", "error": f"child exited without a result (exit code {p.exitcode}; "
                                                   "killed by the OOM killer?)"}
        else:
            res = {"status": "TIMEOUT", "error": f"exceeded the {limit:.0f} s per-model time limit"}
    finally:
        if p.is_alive():
            p.kill()
        p.join(30)
        rx.close()
    return res


def group_val_hours(M: dict, meta_tr: pd.DataFrame, meta_va: pd.DataFrame) -> tuple[dict, float, list[str]]:
    """FP/hour denominators: per group, 08's rule; GLOBAL must reproduce the manifest's val total."""
    man_val = float(M["benign_active_hours"]["per_split"]["val"])
    both = pd.concat([meta_tr, meta_va], ignore_index=True)
    hours = {}
    for g in ["G1", "G2", "GEN", CONFIG["global_group"]]:
        bt = both[(both["y"] == 0) & group_mask(both, g)]
        bv = meta_va[(meta_va["y"] == 0) & group_mask(meta_va, g)]
        h, per = val_hours(M, bt)
        h_valonly, _ = val_hours(M, bv)
        hours[g] = {"hours_full": h, "per_session": per, "hours_val_only_starts": h_valonly}
    gh = hours[CONFIG["global_group"]]["hours_full"]
    if abs(gh - man_val) > 1e-3:
        fatal(f"GLOBAL val benign hours {gh:.4f} != manifest per_split.val {man_val:.4f}: the copied 08 rule "
              "does not reproduce step 8; STOP")
    for g, h in hours.items():
        log(f"val active benign hours  {g:<6} {h['hours_full']:.4f} h  (val-only flow starts "
            f"{h['hours_val_only_starts']:.4f} h)   overall val total (manifest) {man_val:.4f} h")
    warns = [f"{g}: per-group hours from train+val flow starts ({h['hours_full']:.4f}) differ from val-only "
             f"starts ({h['hours_val_only_starts']:.4f})" for g, h in hours.items()
             if abs(h["hours_full"] - h["hours_val_only_starts"]) > 1e-9]
    for w in warns:
        log(f"WARNING {w}")
    return hours, man_val, warns


def select_rows(meta_tr: pd.DataFrame, meta_va: pd.DataFrame, dry: bool):
    """Row selection (dry run: 5 % stratified subsample of train and val)."""
    tr_pos, va_pos = np.arange(len(meta_tr)), np.arange(len(meta_va))
    if dry:
        tr_pos = stratified_sample(meta_tr, CONFIG["dry_run_frac"], CONFIG["seed"])
        va_pos = stratified_sample(meta_va, CONFIG["dry_run_frac"], CONFIG["seed"] + 1)
        log(f"DRY RUN: stratified {CONFIG['dry_run_frac']:.0%} subsample  train {len(tr_pos):,}  val {len(va_pos):,}")
    sub_tr, sub_va = meta_tr.iloc[tr_pos].reset_index(drop=True), meta_va.iloc[va_pos].reset_index(drop=True)
    return tr_pos, va_pos, sub_tr, sub_va


def group_context(groups: list[str], families: list[str], hours: dict, meta_tr: pd.DataFrame,
                  meta_va: pd.DataFrame, sub_tr: pd.DataFrame, sub_va: pd.DataFrame,
                  dry: bool) -> tuple[dict, dict, list[dict]]:
    """Per group: FP/hour denominator in use, row counts and val family flags."""
    fph, row_counts, fam_flags = {}, {}, []
    for g in groups:
        full_b = int(((meta_va["y"] == 0) & group_mask(meta_va, g)).sum())
        used_b = int(((sub_va["y"] == 0) & group_mask(sub_va, g)).sum())
        h = hours[g]["hours_full"]
        if dry:
            used = h * used_b / full_b if full_b else 0.0
            src = (f"computed (08 benign_hours rule on manifest segments) = {h:.4f} h, scaled by the dry-run "
                   f"val benign sample fraction {used_b}/{full_b}")
        else:
            used, src = h, "computed: 08 benign_hours rule on manifest session_cuts + group benign starts " \
                           "(manifest has no per-group value)"
        fph[g] = {"hours_used": used, "hours_full_val": h, "per_session": hours[g]["per_session"],
                  "hours_val_only_starts": hours[g]["hours_val_only_starts"], "source": src}
        row_counts[g] = {"train_full": counts(meta_tr[group_mask(meta_tr, g)]),
                         "val_full": counts(meta_va[group_mask(meta_va, g)]),
                         "train_used": counts(sub_tr[group_mask(sub_tr, g)]),
                         "val_used": counts(sub_va[group_mask(sub_va, g)])}
        for fam in families:
            n = row_counts[g]["val_used"]["attack_by_family"].get(fam, 0)
            fam_flags.append({"group": g, "attack_family": fam, "n_val": n,
                              "flag": "N/A" if n == 0 else ("LOW_N" if n < CONFIG["low_n"] else "")})
    for r in fam_flags:
        if r["flag"]:
            log(f"family flag  {r['group']:<6} {r['attack_family']:<10} n_val {r['n_val']:>5}  {r['flag']}")
    return fph, row_counts, fam_flags


def bakeoff(args) -> int:
    global _LOG_PATH
    t_run = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    out = args.out or (OUT_DEFAULT / "dry_run" if args.dry_run else OUT_DEFAULT)
    out = (out if out.is_absolute() else REPO_ROOT / out).resolve()
    if out.is_relative_to(CONFIG_DIR.resolve()):
        fatal(f"{out} must not be under config/")
    lock_fh = run_lock(out)
    _LOG_PATH = out / "run.log"
    groups = args.groups or CONFIG["groups"]
    models = [m.upper() for m in (args.models or CONFIG["models"])]
    for m in models:
        if m not in CONFIG["models"]:
            fatal(f"unknown model {m!r}; choose from {CONFIG['models']}")
    limit_default = float(args.time_limit or CONFIG["time_limit_s"]["default"])
    log("=" * 100)
    log(f"{SCRIPT} bakeoff  {'DRY RUN' if args.dry_run else 'FULL'}  groups {groups}  models {models}  "
        f"out {rel(out)}  pid {os.getpid()}  argv {' '.join(sys.argv[1:])}")

    ctx = check_inputs()
    M, feats, families = ctx["M"], ctx["feats"], ctx["families"]
    meta_tr, meta_va = load_meta(TRAIN_PARQUET), load_meta(VAL_PARQUET)
    log(f"train rows {len(meta_tr):,}  val rows {len(meta_va):,}  (y: 0 = benign, 1 = attack; checked)")

    hours, man_val, warns = group_val_hours(M, meta_tr, meta_va)
    tr_pos, va_pos, sub_tr, sub_va = select_rows(meta_tr, meta_va, args.dry_run)
    fph, row_counts, fam_flags = group_context(groups, families, hours, meta_tr, meta_va, sub_tr, sub_va,
                                               args.dry_run)

    meta = {"script": SCRIPT, "stage": "bakeoff", "run_utc": run_utc, "argv": sys.argv, "dry_run": args.dry_run,
            "code_sha256": CODE_SHA256, "out": rel(out), "groups": groups, "models": models,
            "features": {"path": rel(FEATURES_JSON), "n": len(feats), "sha256": ctx["sha"],
                         "sha256_of": "json.dumps(features, separators=(',', ':')) utf-8 (features_v1.json "
                                      "sha256_of; the value manifest_v1.json records)",
                         "manifest_sha256": M["features"]["sha256"], "file_bytes_sha256": ctx["file_sha"],
                         "duration_column": ctx["dur"]},
            "verify_lock": {"ok": ctx["lock"]["ok"],
                            "checks": [{"check": n, "pass": o, "detail": scrub(d)} for n, o, d in ctx["lock"]["checks"]]},
            "inputs": {"train": rel(TRAIN_PARQUET), "val": rel(VAL_PARQUET), "manifest": rel(MANIFEST),
                       "attack_set": rel(ATTACK_SET), "test_split": "never opened"},
            "versions": lib_versions(), "platform": {"machine": platform.machine(), "system": platform.system(),
                                                     "release": platform.release(), "cpu_count": os.cpu_count()},
            "threadpools": [{k: v for k, v in tp.items() if k in ("user_api", "internal_api", "num_threads", "version")}
                            for tp in threadpool_info()],
            "config": CONFIG, "deviations": CONFIG["deviations"], "seed": CONFIG["seed"],
            "attack_families": families,
            "row_counts": row_counts, "fph_denominators": fph,
            "fph_manifest_val_total": man_val, "family_flags": fam_flags, "warnings": warns,
            "time_limit_s": limit_default}
    (out / "run_meta.json").write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")

    done = resume_state(out, args.dry_run, args.retry_timeouts)
    combos = [(g, m) for g in groups for m in models]
    todo = [(g, m) for g, m in combos if (g, m) not in done]
    log(f"combos {len(combos)}  already done {len(combos) - len(todo)}  to run {len(todo)}  "
        f"time limit {limit_default:.0f} s each")

    y_va_all = meta_va["y"].to_numpy()
    fam_va_all = meta_va["attack_family"].to_numpy(dtype=object)
    y_tr_all = meta_tr["y"].to_numpy().astype(np.int64)
    for i, (g, code) in enumerate(todo, 1):
        tr_rows = tr_pos[group_mask(sub_tr, g)]
        va_rows = va_pos[group_mask(sub_va, g)]
        y_tr, y_va, fam_va = y_tr_all[tr_rows], y_va_all[va_rows], fam_va_all[va_rows]
        n_tb, n_ta = int((y_tr == 0).sum()), int((y_tr == 1).sum())
        base = {"group": g, "model": code, "n_train": len(tr_rows), "n_train_benign": n_tb, "n_train_attack": n_ta,
                "val_benign_hours": fph[g]["hours_used"], "dry_run": args.dry_run, "run_utc": run_utc}
        log(f"[{i}/{len(todo)}] {g} {code} ({CONFIG['model_names'][code]}): train {len(tr_rows):,} "
            f"(benign {n_tb:,} / attack {n_ta:,})  val {len(va_rows):,}")
        lib = LIBS.get(code)
        if lib and importlib.util.find_spec(lib) is None:
            res = {"status": "MISSING_LIB", "error": f"python package {lib!r} is not installed in this env"}
        else:
            save = None
            if args.save_models:
                save = str(MODELS_DIR / ("dry_run" if args.dry_run else "full") / f"{g}_{code}.joblib")
            job = {"model": code, "features": feats, "dur_idx": ctx["dur_idx"], "train_path": TRAIN_PARQUET,
                   "val_path": VAL_PARQUET, "tr_rows": tr_rows, "va_rows": va_rows, "y_tr": y_tr,
                   "save_path": save}
            limit = float(args.time_limit or CONFIG["time_limit_s"].get(code, limit_default))
            res = run_child(job, limit)
        st = res["status"]
        if st != "OK":
            log(f"    {st}: {res.get('error', '').strip().splitlines()[-1] if res.get('error') else ''}")
            append_rows(out / "cost.csv", [{"group": g, "model": code, "status": st, "error": res.get("error", ""),
                                            "proxy_note": PROXY_NOTE, "dry_run": args.dry_run}], COST_COLS)
            append_rows(out / "metrics.csv", [{**base, "status": st, "operating_point": "-",
                                               "note": res.get("error", "").strip().splitlines()[-1][:300]
                                               if res.get("error") else ""}], METRIC_COLS)
            continue

        s = res["scores"]
        if len(s) != len(y_va):
            raise AssertionError(f"{g} {code}: {len(s)} scores for {len(y_va)} val rows")
        both_cls = len(np.unique(y_va)) == 2
        pr = average_precision_score(y_va, s, pos_label=1) if both_cls else math.nan
        roc = roc_auc_score(y_va, s) if both_cls else math.nan
        rows, frows = operating_points(s, y_va, fam_va, families, fph[g]["hours_used"])
        common = {**base, "status": "OK", "pr_auc": pr, "roc_auc": roc, "preprocessing": res["preprocessing"],
                  "class_weight_handling": res["class_weight_handling"]}
        append_rows(out / "per_family.csv", [{"group": g, "model": code, **r, "dry_run": args.dry_run}
                                             for r in frows], FAMILY_COLS)
        append_rows(out / "cost.csv", [{
            "group": g, "model": code, "status": "OK",
            **{k: res[k] for k in ("size_bytes", "latency_median_us", "latency_p99_us", "latency_calls",
                                   "throughput_flows_s", "batch_rows", "fit_s", "val_score_s", "load_s", "wall_s",
                                   "child_peak_rss_mb")},
            "fit_threads": f"n_jobs={CONFIG['fit_n_jobs']} ({os.cpu_count()} cpus)",
            "predict_threads": "1 (n_jobs=1 / thread_count=1 + threadpoolctl limit 1)",
            "fit_warnings": "; ".join(res["fit_warnings"]), "n_iter": json.dumps(res["n_iter"]),
            "params_json": json.dumps(res["params"], default=str, sort_keys=True), "error": "",
            "proxy_note": PROXY_NOTE, "dry_run": args.dry_run}], COST_COLS)
        append_rows(out / "metrics.csv", [{**common, **r} for r in rows], METRIC_COLS)
        b1 = next(r for r in rows if r["operating_point"] == f"fph_{CONFIG['summary_fph']:g}")
        log(f"    fit {res['fit_s']:.1f} s  score {res['val_score_s']:.1f} s  PR-AUC {pr:.4f}  ROC-AUC {roc:.4f}  "
            f"DR@FP/h<={CONFIG['summary_fph']:g} {b1['detection_rate']:.4f} (thr {b1['threshold']:.6g}, FP {b1['fp']})  "
            f"lat {res['latency_median_us']:.0f}/{res['latency_p99_us']:.0f} us  size {fmt_size(res['size_bytes'])}  "
            f"rss {res['child_peak_rss_mb']} MB" + (f"  warnings {len(res['fit_warnings'])}" if res["fit_warnings"] else ""))
        del res, s
        gc.collect()

    meta["runtime_s"] = round(time.monotonic() - t_run, 1)
    meta["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    (out / "run_meta.json").write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")
    write_summary(out, meta)
    log(f"done in {meta['runtime_s']:.0f} s  ->  {rel(out)}/summary.md")
    lock_fh.close()
    return 0


# --------------------------------------------------------------------------- robustness

R_KEY = ["group", "model", "feature_set", "seed", "evaluation"]
R_VAL_COLS = R_KEY + ["n_features", "status", "pr_auc", "roc_auc", "thr_05", "fp_05", "fph_05", "dr_05", "max_fp",
                      "thr_1fp", "fp_1fp", "fph_1fp", "dr_1fp", "note_1fp", "n_attack_val", "n_benign_val",
                      "val_benign_hours", "n_train", "n_train_benign", "n_train_attack", "fit_s", "score_s",
                      "score_sha256", "preprocessing", "class_weight_handling", "fit_warnings", "error", "dry_run",
                      "run_utc"]
R_FAMILY_COLS = R_KEY + ["operating_point", "threshold", "attack_family", "n", "detected", "detection_rate", "flag",
                         "dry_run"]
R_UNSEEN_COLS = R_KEY + ["n_features", "variant", "rotation", "status", "held_out_session", "held_out_alias", "held_out_victims",
                         "held_out_victim_groups", "n_train", "n_train_benign", "n_train_attack", "n_train_syn",
                         "thr_05", "thr_1fp", "note_1fp", "n_thr_rows", "n_thr_benign", "syn_n", "syn_dr_05",
                         "syn_dr_1fp", "valben_n", "valben_hours", "valben_fp_05", "valben_fph_05", "valben_fp_1fp",
                         "valben_fph_1fp", "valben_n_from_held", "valben_fp_05_from_held", "valben_fp_1fp_from_held",
                         "heldben_n", "heldben_hours", "heldben_fp_05", "heldben_fph_05", "heldben_fp_1fp",
                         "heldben_fph_1fp", "fit_s", "score_sha256", "preprocessing", "class_weight_handling",
                         "fit_warnings", "note", "error", "dry_run", "run_utc"]
R_COST_COLS = ["group", "model", "feature_set", "n_features", "seed"] + COST_COLS[2:]
R_CSV = {"val": "val_metrics.csv", "family": "per_family.csv", "unseen": "unseen_session.csv", "cost": "cost.csv"}


def list_sha256(names: list[str]) -> str:
    return hashlib.sha256(json.dumps(names, separators=(",", ":")).encode("utf-8")).hexdigest()


def robust_feature_sets(feats: list[str], dur: str) -> dict:
    """ROBUST feature sets as features_v1 subsets (order kept). Every removed name must occur exactly once."""
    out = {}
    for name, drop in ROBUST["feature_sets"].items():
        for c in drop:
            if feats.count(c) != 1:
                fatal(f"feature set {name}: {c!r} occurs {feats.count(c)} times in features_v1.json "
                      "(expected exactly once); STOP")
        keep = [c for c in feats if c not in drop]
        want = re.search(r"(\d+)$", name)
        if len(keep) != len(feats) - len(drop) or (want and int(want.group(1)) != len(keep)):
            fatal(f"feature set {name}: {len(keep)} features left after removing {drop}; STOP")
        if dur not in keep:
            fatal(f"feature set {name} drops the duration column {dur!r} (zero_duration_flag needs it); STOP")
        out[name] = {"n": len(keep), "removed": list(drop), "sha256": list_sha256(keep),
                     "sha256_of": "json.dumps(features, separators=(',', ':')) utf-8 (as features_v1.json)",
                     "features": keep, "keep_idx": [feats.index(c) for c in keep], "dur_idx": keep.index(dur)}
        log(f"feature set {name}: {len(keep)} features, sha256 {out[name]['sha256'][:16]}..."
            + (f", removed {drop}" if drop else ""))
    return out


# Origin: 09b_leakage_checks.py check_inputs() (SYN session resolution from split_plan session_aliases), plus a
# check that the result is exactly the session 09b check 5 used.
def resolve_syn_sessions(M: dict, families: list[str]) -> str:
    """Checks every ROBUST rotation's held-out session; returns split_plan.json's sha256."""
    fam = ROBUST["syn_family"]
    if fam not in families:
        fatal(f"family {fam!r} not in attack_set.json {families}; STOP")
    plan = read_json(SPLIT_PLAN)
    if plan.get("version") != M["plan"].get("version") or plan.get("sessions") != M["plan"].get("sessions"):
        fatal("config/split_plan.json differs from the plan recorded in manifest_v1.json; STOP")
    fam_of = {i["session"]: (i.get("label_report") or {}).get("completion_key", {}).get("attack_family")
              for i in M["inputs"]}
    for r, spec in ROBUST["rotations"].items():
        alias = spec["held_out_alias"]
        hits = [s for s, a in plan["session_aliases"].items() if a == alias]
        if len(hits) != 1:
            fatal(f"split_plan session_aliases: {len(hits)} sessions named {alias!r} ({hits}); STOP (ambiguous)")
        s = hits[0]
        if plan["sessions"].get(s) != "train" or fam_of.get(s) != fam:
            fatal(f"session {s} ({alias}): mode {plan['sessions'].get(s)!r}, family {fam_of.get(s)!r}; expected a "
                  f"train-mode {fam} session; STOP")
        if s != spec["session"]:
            fatal(f"rotation {r}: alias {alias!r} resolves to {s!r}, but 09b check 5 used {spec['session']!r}; STOP")
        log(f"rotation {r}: hold out {s!r} = {alias!r} (09b check 5 session), victims expected in {spec['victim_group']}")
    return hashlib.sha256(guard_read(SPLIT_PLAN).read_bytes()).hexdigest()


# Origin: 09b_leakage_checks.py rows_benign_hours() (08's rule summed over the splits the rows come from).
def rows_benign_hours(M: dict, benign: pd.DataFrame) -> float:
    """Active benign hours of the benign rows `benign` (session, split, start_ts), on 08's own active
    segments and cut points (manifest session_cuts), summed over the splits those rows come from."""
    total = 0.0
    for sess, r in benign.groupby("session"):
        c = M["session_cuts"][sess]
        seg = np.array([[pd.Timestamp(a).timestamp(), pd.Timestamp(b).timestamp()]
                        for a, b in c["active_segments_utc"]], dtype=float)
        h = benign_hours(seg, r["start_ts"].to_numpy(dtype=float), (c["boundaries_epoch"], c["splits"]))
        total += sum(h[sp] for sp in set(r["split"]))
    return total


def unseen_hours(M: dict, full_tr: pd.DataFrame, full_va: pd.DataFrame, sub_tr: pd.DataFrame, sub_va: pd.DataFrame,
                 g: str, sess: str, dry: bool) -> dict:
    """FP/hour denominators of one (group, rotation): 08's rule on the FULL data's benign rows evaluated
    (valben = the group's val benign, heldben = the group's benign rows of session `sess`, train + val);
    dry run: scaled by the benign sample fraction (as 09b eval_hours)."""
    def ben(m):
        return (m["y"] == 0).to_numpy() & group_mask(m, g)

    def held(m):
        return (m["session"] == sess).to_numpy()

    sel = {"valben": (np.zeros(len(full_tr), bool), ben(full_va), np.zeros(len(sub_tr), bool), ben(sub_va)),
           "heldben": (ben(full_tr) & held(full_tr), ben(full_va) & held(full_va),
                       ben(sub_tr) & held(sub_tr), ben(sub_va) & held(sub_va))}
    out = {}
    for name, (ft, fv, st, sv) in sel.items():
        rows = pd.concat([full_tr[ft], full_va[fv]])
        h_full, n_full, n_used = rows_benign_hours(M, rows), len(rows), int(st.sum() + sv.sum())
        out[name] = {"benign_rows_full": n_full, "benign_rows_used": n_used, "hours_full": h_full,
                     "hours_used": h_full * n_used / n_full if (dry and n_full) else h_full,
                     "splits": sorted(set(rows["split"])),
                     "rule": "08 benign_hours on manifest session_cuts, summed over the rows' splits"
                             + ("; dry run: scaled by the benign sample fraction" if dry else "")}
    return out


def robust_eval(job: dict, ev: dict, Xtr: np.ndarray, Xva: np.ndarray) -> dict:
    """Child side, one (seed, evaluation): fit on train rows ev["fit_rows"] (None = every loaded row), score
    every loaded val row and the train rows ev["score_tr"]; bakeoff's cost proxies if ev["cost"]."""
    t_all = time.perf_counter()
    code, seed = job["model"], ev["seed"]
    np.random.seed(seed)
    fr = ev["fit_rows"]
    Xf = Xtr if fr is None else Xtr[fr]
    yf = job["y_tr"] if fr is None else job["y_tr"][fr]
    model, cw, pre, fit_s, fit_warn = fit_model(code, Xf, yf, job["dur_idx"], seed)
    del Xf
    gc.collect()
    est = final_estimator(model)
    classes = [int(c) for c in est.classes_]
    if classes != [0, 1]:
        raise AssertionError(f"classes_ {classes} != [0, 1]")
    pos = classes.index(1)
    t = time.perf_counter()
    s_va = model.predict_proba(Xva)[:, pos].astype(np.float64)
    score_s = time.perf_counter() - t
    st = ev["score_tr"]
    s_tr = model.predict_proba(Xtr[st])[:, pos].astype(np.float64) if len(st) else np.zeros(0, dtype=np.float64)
    res = {"status": "OK", "scores": s_va, "scores_tr": s_tr, "fit_s": fit_s, "score_s": score_s,
           "fit_warnings": fit_warn, "class_weight_handling": cw, "preprocessing": pre}
    if ev["cost"]:
        n_iter = getattr(est, "n_iter_", None)
        res.update({"size_bytes": model_size(model), "params": params_of(model),
                    "n_iter": None if n_iter is None else np.asarray(n_iter).tolist(),
                    **cost_proxies(model, code, pos, Xva, seed)})
    del model, est
    gc.collect()
    res["child_peak_rss_mb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
    res["wall_s"] = time.perf_counter() - t_all
    return res


def robust_worker(conn, job: dict) -> None:
    """Child process body for one (group, model, feature_set): load the float32 matrices once (70 columns,
    then the feature set's columns), then send one result per job["evals"] entry, in order."""
    try:
        try:
            t = time.perf_counter()
            Xtr = load_matrix(job["train_path"], job["features"], job["tr_rows"])
            Xva = load_matrix(job["val_path"], job["features"], job["va_rows"])
            if len(job["keep"]) != Xtr.shape[1]:
                Xtr = np.ascontiguousarray(Xtr[:, job["keep"]])
                Xva = np.ascontiguousarray(Xva[:, job["keep"]])
            load_s = time.perf_counter() - t
        except BaseException:
            conn.send({"status": "ERROR", "error": traceback.format_exc(limit=6)})
            return
        # See run_combo: LightGBM's auto feature names make sklearn warn on every numpy predict.
        warnings.filterwarnings("ignore", message="X does not have valid feature names", category=UserWarning)
        for ev in job["evals"]:
            try:
                res = robust_eval(job, ev, Xtr, Xva)
                res["load_s"] = load_s
            except BaseException:
                res = {"status": "ERROR", "error": traceback.format_exc(limit=6)}
            conn.send(res)
            del res
            gc.collect()
    finally:
        conn.close()


def run_child_stream(job: dict, limit: float):
    """Yields (index into job["evals"], result) in order. Spawned, non-daemonic child as run_child; the time
    limit applies per evaluation. A TIMEOUT / crash ends that child and a fresh one takes the rest."""
    ctx = mp.get_context("spawn")
    evals, i = job["evals"], 0
    while i < len(evals):
        rx, tx = ctx.Pipe(duplex=False)
        p = ctx.Process(target=robust_worker, args=(tx, {**job, "evals": evals[i:]}), daemon=False)
        p.start()
        tx.close()
        try:
            while i < len(evals):
                stop = False
                if rx.poll(limit):
                    try:
                        res = rx.recv()
                    except EOFError:
                        p.join(10)
                        res, stop = {"status": "ERROR", "error": f"child exited without a result (exit code "
                                                                 f"{p.exitcode}; killed by the OOM killer?)"}, True
                else:
                    res, stop = {"status": "TIMEOUT", "error": f"exceeded the {limit:.0f} s per-evaluation time "
                                                               "limit"}, True
                yield i, res
                i += 1
                if stop:
                    break
        finally:
            if p.is_alive():
                p.kill()
            p.join(30)
            rx.close()


def scores_sha(*arrays: np.ndarray) -> str:
    h = hashlib.sha256()
    for a in arrays:
        h.update(np.ascontiguousarray(a, dtype=np.float64).tobytes())
    return h.hexdigest()


def robust_val(s: np.ndarray, y: np.ndarray, fam: np.ndarray, families: list[str],
               hours: float) -> tuple[dict, list[dict]]:
    """Evaluation A: val_metrics.csv metric part and per_family.csv rows at 0.5 and at <= max_fp val FP."""
    k = ROBUST["max_fp"]
    n_att, n_ben = int((y == 1).sum()), int((y == 0).sum())
    both_cls = len(np.unique(y)) == 2
    row = {"pr_auc": average_precision_score(y, s, pos_label=1) if both_cls else math.nan,
           "roc_auc": roc_auc_score(y, s) if both_cls else math.nan, "max_fp": k,
           "n_attack_val": n_att, "n_benign_val": n_ben, "val_benign_hours": hours}
    thr1 = max_fp_threshold(np.unique(s), np.sort(s[y == 0])[::-1], k)
    frows = []
    for tag, op, thr in (("05", "default_0.5", float(CONFIG["default_threshold"])), ("1fp", f"le{k}fp", thr1)):
        flag = s >= thr
        fp, tp = int((flag & (y == 0)).sum()), int((flag & (y == 1)).sum())
        if tag == "1fp" and fp > k:
            raise AssertionError(f"<= {k} FP threshold gives {fp} FP")
        row.update({f"thr_{tag}": thr, f"fp_{tag}": fp, f"fph_{tag}": fp / hours if hours > 0 else math.nan,
                    f"dr_{tag}": tp / n_att if n_att else math.nan})
        for f in families:
            m = (y == 1) & (fam == f)
            n = int(m.sum())
            det = int((flag & m).sum())
            frows.append({"operating_point": op, "threshold": thr, "attack_family": f, "n": n, "detected": det,
                          "detection_rate": det / n if n else math.nan,
                          "flag": "N/A" if n == 0 else ("LOW_N" if n < CONFIG["low_n"] else "")})
    row["note_1fp"] = f"only flagging nothing meets <= {k} FP (threshold inf, DR 0)" if math.isinf(thr1) else ""
    return row, frows


def robust_unseen(s_va: np.ndarray, s_tr: np.ndarray, U: dict, y_va: np.ndarray, f_va: np.ndarray) -> dict:
    """Evaluation B metric part. s_va: every group val row; s_tr: the held-out session's group train rows."""
    k, syn = ROBUST["max_fp"], ROBUST["syn_family"]
    tm, vh, vb = U["thr_mask"], U["va_held"], y_va == 0
    thr1 = max_fp_threshold(np.unique(s_va[tm]), np.sort(s_va[tm & vb])[::-1], k)
    s_syn = np.r_[s_tr[U["ftr_held"] == syn], s_va[vh & (f_va == syn)]]
    s_vb, s_vb_h = s_va[vb], s_va[vb & vh]
    s_hb = np.r_[s_tr[U["ytr_held"] == 0], s_va[vb & vh]]
    hv, hh = U["hours"]["valben"]["hours_used"], U["hours"]["heldben"]["hours_used"]
    out = {"thr_05": float(CONFIG["default_threshold"]), "thr_1fp": thr1,
           "note_1fp": f"only flagging nothing meets <= {k} val FP (threshold inf)" if math.isinf(thr1) else "",
           "n_thr_rows": int(tm.sum()), "n_thr_benign": int((tm & vb).sum()), "syn_n": len(s_syn),
           "valben_n": len(s_vb), "valben_hours": hv, "valben_n_from_held": len(s_vb_h),
           "heldben_n": len(s_hb), "heldben_hours": hh}
    holdout = U["variant"] == "benign_holdout"
    if holdout:
        out["syn_n"] = "N/A"
    for tag in ("05", "1fp"):
        thr = out[f"thr_{tag}"]
        out[f"syn_dr_{tag}"] = "N/A" if holdout else (float((s_syn >= thr).mean()) if len(s_syn) else math.nan)
        fv, fh = int((s_vb >= thr).sum()), int((s_hb >= thr).sum())
        out.update({f"valben_fp_{tag}": fv, f"valben_fph_{tag}": fv / hv if hv > 0 else math.nan,
                    f"valben_fp_{tag}_from_held": int((s_vb_h >= thr).sum()),
                    f"heldben_fp_{tag}": fh, f"heldben_fph_{tag}": fh / hh if hh > 0 else math.nan})
    return out


def robust_resume(out: Path, dry: bool, retry_timeouts: bool) -> set[tuple]:
    """(group, model, feature_set, seed, evaluation) keys already done (val_metrics.csv / unseen_session.csv
    rows with a done status); stale per_family / cost rows of every other key are dropped."""
    for name, cols in ((R_CSV["val"], R_VAL_COLS), (R_CSV["unseen"], R_UNSEEN_COLS), (R_CSV["family"], R_FAMILY_COLS),
                       (R_CSV["cost"], R_COST_COLS)):
        p = out / name
        if p.exists() and p.stat().st_size and list(pd.read_csv(guard_read(p), nrows=0).columns) != cols:
            fatal(f"{rel(p)} has other columns than this version writes (older run?); fix it or use another --out")
    v, u = read_csv(out / R_CSV["val"]), read_csv(out / R_CSV["unseen"])
    if v.empty and u.empty:
        for name in (R_CSV["family"], R_CSV["cost"]):
            (out / name).unlink(missing_ok=True)
        return set()
    flags = set().union(*(set(d["dry_run"].astype(str)) for d in (v, u) if not d.empty))
    if flags != {str(dry)}:
        fatal(f"{rel(out)} holds dry_run={sorted(flags)} rows but this run is dry_run={dry}; use another --out")
    ok = STATUS_DONE - ({"TIMEOUT"} if retry_timeouts else set())

    def keys(df, ev=None):
        return [(g, m, fs, int(sd), ev or e) for g, m, fs, sd, e in
                zip(df["group"], df["model"], df["feature_set"], df["seed"],
                    df["evaluation"] if ev is None else [ev] * len(df))]

    done = {k for d in (v, u) if not d.empty for k, s in zip(keys(d), d["status"]) if s in ok}
    for name in (R_CSV["val"], R_CSV["unseen"], R_CSV["family"]):
        n = rewrite_without(out / name, lambda df: pd.Series([k in done for k in keys(df)], index=df.index))
        if n:
            log(f"resume: dropped {n} stale / failed rows from {name}")
    n = rewrite_without(out / R_CSV["cost"], lambda df: pd.Series([k in done for k in keys(df, "val")], index=df.index))
    if n:
        log(f"resume: dropped {n} stale / failed rows from {R_CSV['cost']}")
    return done


def fmt_spread(x, nd: int = 4) -> str:
    """mean (min-max) over the seeds' values; one value -> the value; none -> '-'."""
    x = pd.to_numeric(pd.Series(list(x), dtype=object), errors="coerce").dropna()
    if not len(x):
        return "-"
    return fmt(x.mean(), nd) if len(x) == 1 else f"{fmt(x.mean(), nd)} ({fmt(x.min(), nd)}-{fmt(x.max(), nd)})"


def fmt_delta(a, b, nd: int = 4) -> str:
    a = pd.to_numeric(pd.Series(list(a), dtype=object), errors="coerce").dropna()
    b = pd.to_numeric(pd.Series(list(b), dtype=object), errors="coerce").dropna()
    if not len(a) or not len(b):
        return "-"
    d = float(a.mean() - b.mean())
    return "inf" if math.isinf(d) else ("-" if math.isnan(d) else f"{d:+.{nd}f}")


def write_robust_summary(out: Path, meta: dict) -> None:
    v, u = read_csv(out / R_CSV["val"]), read_csv(out / R_CSV["unseen"])
    c = read_csv(out / R_CSV["cost"])
    vo = v[v["status"] == "OK"] if not v.empty else v
    uo = u[u["status"] == "OK"] if not u.empty else u
    co = c[c["status"] == "OK"] if not c.empty else c
    groups, models, fsets, seeds = meta["groups"], meta["models"], meta["feature_sets_run"], meta["seeds"]
    k, lab = ROBUST["max_fp"], f"DR@<={ROBUST['max_fp']}FP"

    def pick(df, **kw):
        if df.empty:
            return df
        m = np.ones(len(df), bool)
        for col, val in kw.items():
            m &= (df[col].astype(str) == str(val)).to_numpy()
        return df[m]

    def identical(df) -> str:
        if len(df) < 2:
            return "-"
        return "yes" if df["score_sha256"].nunique() == 1 else "no"

    n_done = len(vo) + len(uo)
    L = [f"# Step 9 robustness (shortlist x feature set x seed){' -- DRY RUN (5 % stratified subsample)' if meta['dry_run'] else ''}",
         "", f"- run: {meta['run_utc']} | seeds {seeds} | models {models} | feature sets {fsets} | features_v1 sha256 "
             f"{meta['features']['sha256'][:16]}... | verify_lock {'PASS' if meta['verify_lock']['ok'] else 'FAIL'}",
         f"- evaluations OK: {n_done} of {meta['n_evaluations']} planned (val: {len(vo)}, unseen-session: {len(uo)}).",
         f"- {ROBUST['hyperparameters']}. **No winner is declared.**",
         f"- Val: PR-AUC, FP/h and DR at 0.5, and {lab} = lowest observed val score with <= {k} val FP; that threshold "
         "is chosen on val and DR is read on the same val (same-set threshold, optimistic).",
         f"- Unseen session, variant **capture_rotation** (GLOBAL, evaluations unseen_A / unseen_B, 09b check 5): "
         f"train = {ROBUST['unseen_train_rows']}; SYN DR = {ROBUST['unseen_syn_rows']}.",
         f"- Unseen session, variant **benign_holdout** (G1 / G2, evaluation benign_holdout): train = "
         f"{ROBUST['benign_holdout_train_rows']}; held-out SYN DR = {ROBUST['benign_holdout_syn_dr']}. It measures false "
         "alarms on an unseen session's benign traffic only; it is not a capture rotation.",
         f"- Both variants: the <= {k} FP threshold is the {ROBUST['unseen_threshold_rule']}. "
         f"(i) val benign = {ROBUST['unseen_val_benign']}. (ii) held-out session benign = {ROBUST['unseen_held_benign']}.",
         "- FP/hour = FP / active benign hours (08 rule) of exactly the rows evaluated; one FP is worth 1 / hours "
         "FP/h (column 'FP/h per FP' below), so small denominators make FP/h coarse.",
         "- Table cells = mean (min-max) over the seeds that finished OK. Latency / size: seed 42 fit only; laptop "
         "proxies (WSL, 1 thread), not Pi numbers.",
         f"- {CONFIG['global_note']}.", ""]
    L += ["## Feature sets", ""]
    L += md_table([{"feature_set": n, "n": d["n"], "removed": ", ".join(d["removed"]) or "-",
                    "sha256": d["sha256"][:16] + "..."} for n, d in meta["feature_sets"].items()],
                  ["feature_set", "n", "removed", "sha256"]) + [""]
    L += ["## Unseen-session evaluations", ""]
    L += md_table([{"group": g, "evaluation": ev, "variant": sp["variant"], "held-out session": sp["session"],
                    "alias": sp["alias"], "removed from training": sp["removed"], "held-out SYN DR": sp["syn_dr"],
                    "SYN victims (group)": "; ".join(meta["rotations"][sp["rotation"]]["victims"]) + " ("
                    + ", ".join(meta["rotations"][sp["rotation"]]["victim_groups"]) + ")"}
                   for g in groups for ev, sp in meta["group_unseen"][g].items()],
                  ["group", "evaluation", "variant", "held-out session", "alias", "removed from training",
                   "held-out SYN DR", "SYN victims (group)"]) + [""]
    L += ["## FP/hour denominators", ""]
    def per_fp(h) -> str:
        return fmt(1 / h, 2) if h and h > 0 else "-"

    den = [{"evaluation": f"{g} val (A)", "benign rows": "-", "hours used": fmt(meta["fph_denominators"][g]["hours_used"]),
            "FP/h per FP": per_fp(meta["fph_denominators"][g]["hours_used"]),
            "source": meta["fph_denominators"][g]["source"]} for g in groups]
    for key, d in meta["unseen_fph_denominators"].items():
        for name, lab_ in (("valben", "(i) val benign"), ("heldben", "(ii) held-out session benign")):
            den.append({"evaluation": f"{key} {lab_}", "benign rows": d[name]["benign_rows_used"],
                        "hours used": fmt(d[name]["hours_used"]), "FP/h per FP": per_fp(d[name]["hours_used"]),
                        "source": d[name]["rule"]})
    L += md_table(den, ["evaluation", "benign rows", "hours used", "FP/h per FP", "source"]) + [""]

    def syn_cell(ev: str, g: str, x, nd: int = 4) -> str:
        return "N/A" if meta["group_unseen"][g][ev]["variant"] == "benign_holdout" else fmt_spread(x, nd)

    for g in groups:
        rots = list(meta["group_unseen"][g])          # evaluation names: unseen_A / unseen_B / benign_holdout
        L += [f"## {g}", ""]
        # 1. main table
        rows = []
        for mo in models:
            for fs in fsets:
                vv = pick(vo, group=g, model=mo, feature_set=fs)
                cc = pick(co, group=g, model=mo, feature_set=fs)
                r = {"model": mo, "feature_set": fs, "seeds OK (val)": f"{len(vv)}/{len(seeds)}",
                     "PR-AUC": fmt_spread(vv.get("pr_auc", []), 4), "FP/h@0.5": fmt_spread(vv.get("fph_05", []), 2),
                     lab: fmt_spread(vv.get("dr_1fp", []), 4)}
                same = [f"val {identical(vv)}"]
                for rot in rots:
                    uu = pick(uo, group=g, model=mo, feature_set=fs, evaluation=rot)
                    r[f"unseen-session benign FP/h@0.5 ({rot})"] = fmt_spread(uu.get("heldben_fph_05", []), 2)
                    r[f"held-out SYN DR@0.5 ({rot})"] = syn_cell(rot, g, uu.get("syn_dr_05", []))
                    same.append(f"{rot} {identical(uu)}")
                if len(cc):
                    x = cc.iloc[0]
                    r.update({"lat med us": fmt(x["latency_median_us"], 1), "lat p99 us": fmt(x["latency_p99_us"], 1),
                              "size": fmt_size(x["size_bytes"])})
                r["scores identical across seeds"] = ", ".join(same)
                rows.append(r)
        cols = (["model", "feature_set", "seeds OK (val)", "PR-AUC", "FP/h@0.5", lab]
                + [c_ for rot in rots for c_ in (f"unseen-session benign FP/h@0.5 ({rot})", f"held-out SYN DR@0.5 ({rot})")]
                + ["lat med us", "lat p99 us", "size", "scores identical across seeds"])
        L += [f"### {g} 1. model x feature set (mean (min-max) over seeds)", ""] + md_table(rows, cols) + [""]
        # 1b. unseen-session detail
        rows = []
        for rot in rots:
            for mo in models:
                for fs in fsets:
                    uu = pick(uo, group=g, model=mo, feature_set=fs, evaluation=rot)
                    if uu.empty:
                        continue
                    rows.append({"evaluation": rot, "model": mo, "feature_set": fs, "seeds OK": f"{len(uu)}/{len(seeds)}",
                                 "n_train_syn": fmt_spread(uu["n_train_syn"], 0), "SYN n": syn_cell(rot, g, uu["syn_n"], 0),
                                 "SYN DR@0.5": syn_cell(rot, g, uu["syn_dr_05"]),
                                 f"SYN DR@val<={k}FP": syn_cell(rot, g, uu["syn_dr_1fp"]),
                                 "val-chosen thr": fmt_spread(uu["thr_1fp"], 6),
                                 "(i) FP@0.5": fmt_spread(uu["valben_fp_05"], 1),
                                 "(i) FP@0.5 from held session": fmt_spread(uu["valben_fp_05_from_held"], 1),
                                 "(i) FP/h@0.5": fmt_spread(uu["valben_fph_05"], 2),
                                 "(i) FP@thr": fmt_spread(uu["valben_fp_1fp"], 1),
                                 "(ii) n": fmt_spread(uu["heldben_n"], 0),
                                 "(ii) FP@0.5": fmt_spread(uu["heldben_fp_05"], 1),
                                 "(ii) FP/h@0.5": fmt_spread(uu["heldben_fph_05"], 2),
                                 "(ii) FP@thr": fmt_spread(uu["heldben_fp_1fp"], 1),
                                 "(ii) FP/h@thr": fmt_spread(uu["heldben_fph_1fp"], 2)})
        L += [f"### {g} 1b. unseen-session detail ((i) = val benign, (ii) = held-out session benign; thr = val-chosen "
              f"<= {k} FP)", ""]
        L += md_table(rows, ["evaluation", "model", "feature_set", "seeds OK", "n_train_syn", "SYN n", "SYN DR@0.5",
                             f"SYN DR@val<={k}FP", "val-chosen thr", "(i) FP@0.5", "(i) FP@0.5 from held session",
                             "(i) FP/h@0.5", "(i) FP@thr", "(ii) n", "(ii) FP@0.5", "(ii) FP/h@0.5", "(ii) FP@thr",
                             "(ii) FP/h@thr"]) + [""]
        # 2. delta table
        L += [f"### {g} 2. tool_agnostic67 minus full70 (difference of seed means)", ""]
        if {"full70", "tool_agnostic67"} <= set(fsets):
            rows = []
            for mo in models:
                a, b = pick(vo, group=g, model=mo, feature_set="tool_agnostic67"), pick(vo, group=g, model=mo, feature_set="full70")
                r = {"model": mo, "d PR-AUC": fmt_delta(a.get("pr_auc", []), b.get("pr_auc", [])),
                     "d FP/h@0.5": fmt_delta(a.get("fph_05", []), b.get("fph_05", []), 2),
                     "d DR@0.5": fmt_delta(a.get("dr_05", []), b.get("dr_05", [])),
                     f"d {lab}": fmt_delta(a.get("dr_1fp", []), b.get("dr_1fp", []))}
                for rot in rots:
                    ua = pick(uo, group=g, model=mo, feature_set="tool_agnostic67", evaluation=rot)
                    ub = pick(uo, group=g, model=mo, feature_set="full70", evaluation=rot)
                    r[f"d unseen-session FP/h@0.5 ({rot})"] = fmt_delta(ua.get("heldben_fph_05", []), ub.get("heldben_fph_05", []), 2)
                    r[f"d held-out SYN DR@0.5 ({rot})"] = (
                        "N/A" if meta["group_unseen"][g][rot]["variant"] == "benign_holdout"
                        else fmt_delta(ua.get("syn_dr_05", []), ub.get("syn_dr_05", [])))
                rows.append(r)
            L += md_table(rows, ["model", "d PR-AUC", "d FP/h@0.5", "d DR@0.5", f"d {lab}"]
                          + [c_ for rot in rots for c_ in (f"d unseen-session FP/h@0.5 ({rot})", f"d held-out SYN DR@0.5 ({rot})")]) + [""]
        else:
            L += ["_needs both feature sets_", ""]
        # 3. seed spread vs between-model differences
        metrics = [("PR-AUC", vo, "pr_auc", {}), ("FP/h@0.5", vo, "fph_05", {}), (lab, vo, "dr_1fp", {})]
        metrics += [(f"unseen-session FP/h@0.5 ({rot})", uo, "heldben_fph_05", {"evaluation": rot}) for rot in rots]
        metrics += [(f"held-out SYN DR@0.5 ({rot})", uo, "syn_dr_05", {"evaluation": rot}) for rot in rots]
        rows = []
        for fs in fsets:
            for name, df, col, kw in metrics:
                st = {}
                for mo in models:
                    x = pd.to_numeric(pick(df, group=g, model=mo, feature_set=fs, **kw).get(col, pd.Series(dtype=float)),
                                      errors="coerce").dropna()
                    if len(x) >= 2 and np.isfinite(x).all():
                        st[mo] = (float(x.mean()), float(x.max() - x.min()))
                for mo, (m_, sp) in st.items():
                    close = [f"{o} ({abs(m_ - mo2):.4g})" for o, (mo2, _) in st.items() if o != mo and abs(m_ - mo2) < sp]
                    if close:
                        rows.append({"feature_set": fs, "metric": name, "model": mo, "mean": f"{m_:.4g}",
                                     "seed spread (max-min)": f"{sp:.4g}",
                                     "models whose mean differs by less (|diff|)": "; ".join(close)})
        L += [f"### {g} 3. between-model difference smaller than the model's own seed spread", ""]
        L += md_table(rows, ["feature_set", "metric", "model", "mean", "seed spread (max-min)",
                             "models whose mean differs by less (|diff|)"]) + [""]
        # 4. caveats
        cav = []
        for r in meta["family_flags"]:
            if r["group"] == g and r["flag"]:
                pc = ", ".join(meta["attack_pcaps"].get(r["attack_family"], []))
                cav.append(f"{r['attack_family']} ({pc}): {r['flag']}, n = {r['n_val']} val attack rows; its per-family "
                           + ("DR is not defined." if r["flag"] == "N/A" else f"DR rests on < {CONFIG['low_n']} rows."))
        cav.append(f"{lab} (val) and its per-family DRs use a same-set threshold (chosen and read on val): optimistic.")
        gu = pick(uo, group=g)
        for rot in rots:
            x = pick(gu, evaluation=rot)
            if len(x) and (pd.to_numeric(x["n_train_syn"], errors="coerce") == 0).all():
                cav.append(f"{rot}: the training rows hold no {ROBUST['syn_family']} row (n_train_syn = 0): "
                           f"the held-out SYN rows are an unseen attack family for this model, not only an unseen "
                           "capture of a known one.")
            sp = meta["group_unseen"][g][rot]
            if sp["variant"] == "benign_holdout":
                cav.append(f"{rot} ({sp['session']}): only that session's benign rows are held out; its SYN rows are "
                           "trained on, so held-out SYN DR is N/A. This is not a capture rotation (GLOBAL's "
                           "unseen_A / unseen_B are).")
        cav.append("(i) val benign includes the held-out session's own val benign rows; those rows are also part of (ii) "
                   "(column '(i) FP@0.5 from held session').")
        for df_, name in ((v, "val"), (u, "unseen")):
            bad = pick(df_, group=g)
            if len(bad):
                bad = bad[bad["status"] != "OK"]
            for _, x in bad.iterrows():
                cav.append(f"{x['model']} {x['feature_set']} seed {x['seed']} {x['evaluation']}: **{x['status']}** "
                           f"-- {str(x.get('error', ''))[:200]}")
        for df_ in (vo, uo):
            gg = pick(df_, group=g)
            if len(gg):
                for _, x in gg[gg["note_1fp"].astype(str) != ""].iterrows():
                    cav.append(f"{x['model']} {x['feature_set']} seed {x['seed']} {x['evaluation']}: {x['note_1fp']}")
        warn = {}
        for df_ in (vo, uo):
            for _, x in pick(df_, group=g).iterrows():
                if str(x.get("fit_warnings", "")):
                    warn.setdefault(x["model"], set()).update(str(x["fit_warnings"]).split("; "))
        cav += [f"{mo}: fit warnings: {sorted(w)}" for mo, w in warn.items()]
        L += [f"### {g} 4. caveats", ""] + [f"- {x}" for x in cav] + [""]
    L += ["## General caveats", ""]
    L += [f"- {w}" for w in meta.get("warnings", [])]
    L += ["- GEN val holds benign rows only (no attacks), so GEN contributes FPs but no detections to GLOBAL.",
          "- FP counts are small: FP/h moves in steps of 'FP/h per FP' (FP/hour denominators table); a between-seed "
          "or between-model difference of one or two FPs is one or two such steps."]
    if meta["dry_run"]:
        L += ["- DRY RUN: 5 % stratified subsample (strata group / y / attack_family); FP/hour denominators scaled by "
              "the benign sample fraction. Numbers check the plumbing, not the models."]
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def robustness(args) -> int:
    global _LOG_PATH
    t_run = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    out = args.out or (ROBUST_OUT / "dry_run" if args.dry_run else ROBUST_OUT)
    out = (out if out.is_absolute() else REPO_ROOT / out).resolve()
    if out.is_relative_to(CONFIG_DIR.resolve()):
        fatal(f"{out} must not be under config/")
    lock_fh = run_lock(out, ROBUST_LOCK, "robustness")
    _LOG_PATH = out / "run.log"
    groups = args.groups or ROBUST["groups"]
    models = [m.upper() for m in (args.models or ROBUST["models"])]
    for m in models:
        if m not in ROBUST["models"]:
            fatal(f"unknown model {m!r}; choose from {ROBUST['models']}")
    fsets = args.feature_sets or list(ROBUST["feature_sets"])
    seeds = args.seeds or ROBUST["seeds"]
    if len(set(seeds)) != len(seeds):
        fatal(f"duplicate seeds {seeds}")
    limit = float(args.time_limit or ROBUST["time_limit_s_per_evaluation"])
    log("=" * 100)
    log(f"{SCRIPT} robustness  {'DRY RUN' if args.dry_run else 'FULL'}  groups {groups}  models {models}  feature sets "
        f"{fsets}  seeds {seeds}  out {rel(out)}  pid {os.getpid()}  argv {' '.join(sys.argv[1:])}")

    ctx = check_inputs()
    M, feats, families = ctx["M"], ctx["feats"], ctx["families"]
    FS = robust_feature_sets(feats, ctx["dur"])
    plan_sha = resolve_syn_sessions(M, families)
    meta_tr = load_meta(TRAIN_PARQUET, LOAD_META + ["device", "split"])
    meta_va = load_meta(VAL_PARQUET, LOAD_META + ["device", "split"])
    log(f"train rows {len(meta_tr):,}  val rows {len(meta_va):,}  (y: 0 = benign, 1 = attack; checked)")
    hours, man_val, warns = group_val_hours(M, meta_tr, meta_va)
    tr_pos, va_pos, sub_tr, sub_va = select_rows(meta_tr, meta_va, args.dry_run)
    fph, row_counts, fam_flags = group_context(groups, families, hours, meta_tr, meta_va, sub_tr, sub_va,
                                               args.dry_run)

    syn = ROBUST["syn_family"]
    rot_info = {}
    for r, spec in ROBUST["rotations"].items():
        s = spec["session"]
        parts = [m[(m["session"] == s).to_numpy() & (m["attack_family"] == syn).to_numpy()] for m in (meta_tr, meta_va)]
        vic = pd.concat(parts)
        vg = sorted(set(vic["group"]))
        if vg != [spec["victim_group"]]:
            fatal(f"rotation {r}: {s} {syn} victims are in groups {vg}, expected [{spec['victim_group']!r}]; STOP")
        rot_info[r] = {"session": s, "alias": spec["held_out_alias"], "victims": sorted(set(vic["device"])),
                       "victim_groups": vg, "syn_rows_full": {"train": len(parts[0]), "val": len(parts[1])}}
    # Unseen-session evaluations per group: GLOBAL = capture rotations, G1 / G2 = benign holdout.
    group_unseen = {}
    for g in groups:
        if g == CONFIG["global_group"]:
            group_unseen[g] = {f"unseen_{r}": {"variant": "capture_rotation", "rotation": r, "session": d["session"],
                                               "alias": d["alias"], "removed": "every row of the session",
                                               "syn_dr": "held-out session's SYN rows (train + val)"}
                               for r, d in rot_info.items()}
            continue
        s = ROBUST["benign_holdout"].get(g)
        r = next((r for r, d in rot_info.items() if d["session"] == s), None)
        if r is None or rot_info[r]["victim_groups"] != [g]:
            fatal(f"benign_holdout {g}: session {s!r} is not the SYN session whose victims are in {g}; STOP")
        group_unseen[g] = {"benign_holdout": {"variant": "benign_holdout", "rotation": r, "session": s,
                                              "alias": rot_info[r]["alias"],
                                              "removed": "only the session's benign rows", "syn_dr": "N/A"}}
    unseen_h = {}
    for g in groups:
        for ev, sp in group_unseen[g].items():
            d = unseen_hours(M, meta_tr, meta_va, sub_tr, sub_va, g, sp["session"], args.dry_run)
            unseen_h[f"{g}/{ev}"] = d
            log(f"unseen hours {g}/{ev}: (i) val benign {d['valben']['benign_rows_used']:,} rows "
                f"{d['valben']['hours_used']:.4f} h   (ii) {sp['session']} benign "
                f"{d['heldben']['benign_rows_used']:,} rows {d['heldben']['hours_used']:.4f} h")

    evals_of = {g: [(sd, ev) for sd in seeds for ev in ["val"] + list(group_unseen[g])] for g in groups}
    n_eval = sum(len(evals_of[g]) for g in groups) * len(models) * len(fsets)
    pcaps = {}
    for p in read_json(ATTACK_SET)["pcaps"]:
        pcaps.setdefault(p["family"], []).append(Path(p["path"]).name)
    meta = {"script": SCRIPT, "stage": "robustness", "run_utc": run_utc, "argv": sys.argv, "dry_run": args.dry_run,
            "code_sha256": CODE_SHA256, "out": rel(out), "groups": groups, "models": models,
            "feature_sets_run": fsets, "seeds": seeds, "n_evaluations": n_eval,
            "features": {"path": rel(FEATURES_JSON), "n": len(feats), "sha256": ctx["sha"],
                         "manifest_sha256": M["features"]["sha256"], "file_bytes_sha256": ctx["file_sha"],
                         "duration_column": ctx["dur"]},
            "feature_sets": {n: {k_: d[k_] for k_ in ("n", "removed", "sha256", "sha256_of", "features")}
                             for n, d in FS.items()},
            "verify_lock": {"ok": ctx["lock"]["ok"],
                            "checks": [{"check": n, "pass": o, "detail": scrub(d)} for n, o, d in ctx["lock"]["checks"]]},
            "inputs": {"train": rel(TRAIN_PARQUET), "val": rel(VAL_PARQUET), "manifest": rel(MANIFEST),
                       "attack_set": rel(ATTACK_SET), "split_plan": rel(SPLIT_PLAN), "split_plan_sha256": plan_sha,
                       "test_split": "never opened"},
            "versions": lib_versions(), "platform": {"machine": platform.machine(), "system": platform.system(),
                                                     "release": platform.release(), "cpu_count": os.cpu_count()},
            "threadpools": [{k_: v_ for k_, v_ in tp.items() if k_ in ("user_api", "internal_api", "num_threads", "version")}
                            for tp in threadpool_info()],
            "robust_config": ROBUST, "config": CONFIG, "attack_families": families, "attack_pcaps": pcaps,
            "rotations": rot_info, "group_unseen": group_unseen,
            "row_counts": row_counts, "fph_denominators": fph, "fph_manifest_val_total": man_val,
            "unseen_fph_denominators": unseen_h, "family_flags": fam_flags, "warnings": warns,
            "time_limit_s_per_evaluation": limit}
    (out / "run_meta.json").write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")

    done = robust_resume(out, args.dry_run, args.retry_timeouts)
    plan = []
    for g in groups:
        for code in models:
            for fs in fsets:
                todo = [(sd, ev) for sd, ev in evals_of[g] if (g, code, fs, sd, ev) not in done]
                if todo:
                    plan.append((g, code, fs, todo))
    n_todo = sum(len(p[3]) for p in plan)
    log(f"evaluations {n_eval}  already done {n_eval - n_todo}  to run {n_todo} in {len(plan)} children  "
        f"time limit {limit:.0f} s per evaluation")

    k_run = 0
    for bi, (g, code, fs, todo) in enumerate(plan, 1):
        F = FS[fs]
        gm_tr, gm_va = group_mask(sub_tr, g), group_mask(sub_va, g)
        mt, mv = sub_tr[gm_tr].reset_index(drop=True), sub_va[gm_va].reset_index(drop=True)
        y_tr = mt["y"].to_numpy().astype(np.int64)
        f_tr = mt["attack_family"].to_numpy(dtype=object)
        y_va, f_va = mv["y"].to_numpy(), mv["attack_family"].to_numpy(dtype=object)
        U = {}
        for ev_, sp in group_unseen[g].items():
            held_tr = (mt["session"] == sp["session"]).to_numpy()
            va_held = (mv["session"] == sp["session"]).to_numpy()
            if sp["variant"] == "benign_holdout":           # drop only the session's benign rows
                held_tr = held_tr & (y_tr == 0)
            fit_rows, score_tr = np.flatnonzero(~held_tr), np.flatnonzero(held_tr)
            U[ev_] = {**sp, "fit_rows": fit_rows, "score_tr": score_tr, "ytr_held": y_tr[score_tr],
                      "ftr_held": f_tr[score_tr], "va_held": va_held, "thr_mask": ~va_held,
                      "hours": unseen_h[f"{g}/{ev_}"],
                    "n_train": len(fit_rows), "n_train_benign": int((y_tr[fit_rows] == 0).sum()),
                    "n_train_attack": int((y_tr[fit_rows] == 1).sum()),
                    "n_train_syn": int((f_tr[fit_rows] == syn).sum())}
        evals = []
        for sd, ev in todo:
            if ev == "val":
                evals.append({"seed": sd, "evaluation": ev, "fit_rows": None, "score_tr": np.zeros(0, np.int64),
                              "cost": sd == ROBUST["cost_seed"]})
            else:
                evals.append({"seed": sd, "evaluation": ev, "fit_rows": U[ev]["fit_rows"],
                              "score_tr": U[ev]["score_tr"], "cost": False})
        log(f"[{bi}/{len(plan)}] {g} {code} ({CONFIG['model_names'][code]}) {fs} ({F['n']} features): train "
            f"{len(y_tr):,} val {len(y_va):,}; evaluations {[f'{sd}:{ev}' for sd, ev in todo]}")
        lib = LIBS.get(code)
        if lib and importlib.util.find_spec(lib) is None:
            stream = ((i, {"status": "MISSING_LIB", "error": f"python package {lib!r} is not installed in this env"})
                      for i in range(len(evals)))
        else:
            job = {"model": code, "features": feats, "keep": F["keep_idx"], "dur_idx": F["dur_idx"],
                   "train_path": TRAIN_PARQUET, "val_path": VAL_PARQUET, "tr_rows": tr_pos[gm_tr],
                   "va_rows": va_pos[gm_va], "y_tr": y_tr, "evals": evals}
            stream = run_child_stream(job, limit)
        try:
            for i, res in stream:
                k_run += 1
                ev = evals[i]
                sd, evn = ev["seed"], ev["evaluation"]
                key = {"group": g, "model": code, "feature_set": fs, "seed": sd, "evaluation": evn}
                common = {**key, "n_features": F["n"], "dry_run": args.dry_run, "run_utc": run_utc}
                st = res["status"]
                err = res.get("error", "")
                err_line = err.strip().splitlines()[-1][:300] if err else ""
                tag = f"    ({k_run}/{n_todo}) {g} {code} {fs} seed {sd} {evn}:"
                if st != "OK":
                    log(f"{tag} {st}: {err_line}")
                    if evn == "val" and ev["cost"]:
                        append_rows(out / R_CSV["cost"], [{**key, "n_features": F["n"], "status": st, "error": err,
                                                           "proxy_note": PROXY_NOTE, "dry_run": args.dry_run}],
                                    R_COST_COLS)
                    if evn == "val":
                        append_rows(out / R_CSV["val"], [{**common, "status": st, "error": err_line}], R_VAL_COLS)
                    else:
                        append_rows(out / R_CSV["unseen"], [{**common, "variant": U[evn]["variant"],
                                                             "rotation": U[evn]["rotation"], "status": st,
                                                             "held_out_session": U[evn]["session"],
                                                             "error": err_line}], R_UNSEEN_COLS)
                    continue
                fitc = {"fit_s": res["fit_s"], "preprocessing": res["preprocessing"],
                        "class_weight_handling": res["class_weight_handling"],
                        "fit_warnings": "; ".join(res["fit_warnings"]), "error": ""}
                s = res["scores"]
                if len(s) != len(y_va):
                    raise AssertionError(f"{g} {code} {fs} {sd} {evn}: {len(s)} scores for {len(y_va)} val rows")
                if evn == "val":
                    row, frows = robust_val(s, y_va, f_va, families, fph[g]["hours_used"])
                    append_rows(out / R_CSV["family"], [{**key, **x, "dry_run": args.dry_run} for x in frows],
                                R_FAMILY_COLS)
                    if ev["cost"]:
                        append_rows(out / R_CSV["cost"], [{
                            **key, "n_features": F["n"], "status": "OK",
                            **{x: res[x] for x in ("size_bytes", "latency_median_us", "latency_p99_us", "latency_calls",
                                                   "throughput_flows_s", "batch_rows", "fit_s", "load_s", "wall_s",
                                                   "child_peak_rss_mb")},
                            "val_score_s": res["score_s"],
                            "fit_threads": f"n_jobs={CONFIG['fit_n_jobs']} ({os.cpu_count()} cpus)",
                            "predict_threads": "1 (n_jobs=1 / thread_count=1 + threadpoolctl limit 1)",
                            "fit_warnings": fitc["fit_warnings"], "n_iter": json.dumps(res["n_iter"]),
                            "params_json": json.dumps(res["params"], default=str, sort_keys=True), "error": "",
                            "proxy_note": PROXY_NOTE, "dry_run": args.dry_run}], R_COST_COLS)
                    append_rows(out / R_CSV["val"], [{
                        **common, "status": "OK", **row, **fitc, "score_s": res["score_s"],
                        "score_sha256": scores_sha(s), "n_train": len(y_tr), "n_train_benign": int((y_tr == 0).sum()),
                        "n_train_attack": int((y_tr == 1).sum())}], R_VAL_COLS)
                    log(f"{tag} fit {res['fit_s']:.1f} s  PR-AUC {row['pr_auc']:.4f}  DR@0.5 {row['dr_05']:.4f}  "
                        f"FP@0.5 {row['fp_05']}  {lab_dr(row)}  rss {res['child_peak_rss_mb']} MB"
                        + (f"  lat {res['latency_median_us']:.0f}/{res['latency_p99_us']:.0f} us  size "
                           f"{fmt_size(res['size_bytes'])}" if ev["cost"] else ""))
                else:
                    Ur = U[evn]
                    ri = rot_info[Ur["rotation"]]
                    if len(res["scores_tr"]) != len(Ur["score_tr"]):
                        raise AssertionError(f"{g} {code} {fs} {sd} {evn}: held-out train scores length mismatch")
                    m = robust_unseen(s, res["scores_tr"], Ur, y_va, f_va)
                    note = (f"no {syn} row in this training set: the held-out SYN rows are an unseen family here, not "
                            "only an unseen capture" if Ur["n_train_syn"] == 0 else "")
                    if Ur["variant"] == "benign_holdout":
                        note = ("benign_holdout: only the session's benign rows are held out; its SYN rows are in "
                                "training, so held-out SYN DR is N/A" + (f"; {note}" if note else ""))
                    append_rows(out / R_CSV["unseen"], [{
                        **common, "variant": Ur["variant"], "rotation": Ur["rotation"], "status": "OK",
                        "held_out_session": Ur["session"], "held_out_alias": Ur["alias"],
                        "held_out_victims": "; ".join(ri["victims"]), "held_out_victim_groups": "; ".join(ri["victim_groups"]),
                        **{x: Ur[x] for x in ("n_train", "n_train_benign", "n_train_attack", "n_train_syn")},
                        **m, **fitc, "score_sha256": scores_sha(s, res["scores_tr"]), "note": note}], R_UNSEEN_COLS)
                    syn_txt = ("SYN DR N/A (trained on)" if Ur["variant"] == "benign_holdout" else
                               f"SYN DR@0.5 {m['syn_dr_05']:.4f} on {m['syn_n']:,}")
                    log(f"{tag} fit {res['fit_s']:.1f} s  train syn {Ur['n_train_syn']:,}  {syn_txt}  (i) FP@0.5 "
                        f"{m['valben_fp_05']} ({m['valben_fp_05_from_held']} from held)  (ii) FP@0.5 "
                        f"{m['heldben_fp_05']} of {m['heldben_n']:,} = {m['heldben_fph_05']:.2f} FP/h  thr "
                        f"{m['thr_1fp']:.6g}: (ii) FP {m['heldben_fp_1fp']}")
                del res, s
                gc.collect()
        finally:
            stream.close()

    meta["runtime_s"] = round(time.monotonic() - t_run, 1)
    meta["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    (out / "run_meta.json").write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")
    write_robust_summary(out, meta)
    log(f"done in {meta['runtime_s']:.0f} s  ->  {rel(out)}/summary.md")
    lock_fh.close()
    return 0


def lab_dr(row: dict) -> str:
    return (f"DR@<={ROBUST['max_fp']}FP {row['dr_1fp']:.4f} (thr {row['thr_1fp']:.6g}, FP {row['fp_1fp']})")


def not_implemented(args) -> int:
    raise NotImplementedError(f"{SCRIPT} {args.cmd}: not implemented yet (only 'bakeoff' and 'robustness' exist)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bakeoff", help="round 1 model bake-off (train -> val)")
    b.add_argument("--groups", nargs="+", choices=CONFIG["groups"], default=None)
    b.add_argument("--models", nargs="+", default=None, help=f"subset of {CONFIG['models']}")
    b.add_argument("--dry-run", action="store_true", help="stratified 5%% subsample of train and val")
    b.add_argument("--out", type=Path, default=None,
                   help=f"output dir (default {rel(OUT_DEFAULT)}; {rel(OUT_DEFAULT / 'dry_run')} with --dry-run)")
    b.add_argument("--save-models", action="store_true", help=f"also save fitted models to {rel(MODELS_DIR)}")
    b.add_argument("--time-limit", type=float, default=None, help="seconds per (group, model); overrides CONFIG")
    b.add_argument("--retry-timeouts", action="store_true", help="rerun combos recorded as TIMEOUT")
    b.set_defaults(func=bakeoff)
    r = sub.add_parser("robustness", help="shortlist x feature set x seed: val + unseen-session false alarms")
    r.add_argument("--groups", nargs="+", choices=ROBUST["groups"], default=None)
    r.add_argument("--models", nargs="+", default=None, help=f"subset of {ROBUST['models']}")
    r.add_argument("--feature-sets", nargs="+", choices=list(ROBUST["feature_sets"]), default=None)
    r.add_argument("--seeds", nargs="+", type=int, default=None, help=f"default {ROBUST['seeds']}")
    r.add_argument("--dry-run", action="store_true", help="stratified 5%% subsample of train and val")
    r.add_argument("--out", type=Path, default=None,
                   help=f"output dir (default {rel(ROBUST_OUT)}; {rel(ROBUST_OUT / 'dry_run')} with --dry-run)")
    r.add_argument("--time-limit", type=float, default=None, help="seconds per (seed, evaluation); overrides ROBUST")
    r.add_argument("--retry-timeouts", action="store_true", help="rerun evaluations recorded as TIMEOUT")
    r.set_defaults(func=robustness)
    for name, hlp in (("splits", "split-strategy comparison (later)"), ("final", "final fit + test eval (later)")):
        sub.add_parser(name, help=hlp).set_defaults(func=not_implemented)
    args = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))   # run the finally blocks: kill the child
    try:
        return args.func(args)
    except SystemExit:
        raise
    except NotImplementedError:
        raise
    except Exception:
        log("UNEXPECTED ERROR\n" + traceback.format_exc())
        return 2


if __name__ == "__main__":
    sys.exit(main())
