#!/usr/bin/env python
"""09b_leakage_checks.py -- Step 9b: is the near-perfect val score leakage / shortcuts or easy attacks?

Facts only: every check reports numbers and the flags fixed in CONFIG before looking; nothing here
concludes "leakage" or "no leakage".

Checks (--checks, default all; numbers or names)
  1 auc               single-feature separability per group (G1, G2, GLOBAL) on train and on val:
                      ROC-AUC of each raw feature vs y as max(AUC, 1 - AUC) + direction, overall and per
                      attack family (benign vs that family). max-AUC >= 0.99 -> SHORTCUT_CANDIDATE.
                      XGBoost gain importance from the bake-off probe fitted on the group's train.
  2 fingerprints      per group (train), for every SHORTCUT_CANDIDATE (train, any scope) and top-15-gain
                      feature, per family: most common exact value, the family's share holding it and the
                      benign share holding it. >= 90 % of the family and <= 5 % of benign -> FINGERPRINT.
  3 ablation          GLOBAL probe refit without the SHORTCUT_CANDIDATE features (GLOBAL train, overall;
                      and, as an extra variant, any scope) and without the top-5 gain features; evaluated
                      on GLOBAL val next to the full-feature probe.
  4 duplicates        GLOBAL, 70 feature values hashed per row: duplicates within train / within val /
                      val rows equal to a train row, label conflicts (same row, different y), and the
                      share of 0-duration / 1-packet rows involved.
  5 cross_capture     GLOBAL, SYN captures "SYN first part" and "SYN 5" (split_plan session_aliases):
                      train on every train row except the held-out capture's session, evaluate on all of
                      the held-out capture's SYN rows (train + val) plus val benign; in-capture baseline =
                      probe on all train rows, evaluated on the held-out capture's val SYN rows + val benign.
  6 leave_victim_out  GLOBAL, syn_flood: per victim device with >= 1000 SYN rows (train + val): train on
                      the train split minus that victim's SYN rows, evaluate on the victim's SYN rows
                      (train + val) plus val benign.

Probe = the bake-off's XGBoost: library defaults + scale_pos_weight = n_benign / n_attack of its training
rows, random_state 42, n_jobs -1. Every evaluation reports DR at threshold 0.5 and at the lowest observed
score giving <= 1 FP on the evaluated benign rows ("same-set threshold, optimistic"). FP/hour denominator
= 08's active-benign-hours rule (benign_hours, copied) on exactly the benign rows evaluated.

Inputs (read-only): ~/lgids_cache/datasets/v1/{train,val}.parquet (never test: every read is asserted),
config/features_v1.json (sha256 == manifest), results/step8/manifest_v1.json, config/split_plan.json,
config/attack_set.json; config/config.py verify_lock() must pass.

Outputs (--out, default results/step9/leakage; --dry-run default results/step9/leakage/dry_run)
  single_feature_auc.csv fingerprints.csv ablation.csv duplicates.csv cross_capture.csv
  leave_victim_out.csv run_meta.json summary.md run.log
  Each check's CSV is written (atomically) as soon as the check finishes and recorded in done.json;
  a rerun skips finished checks. Checks 2 and 3 need check 1's CSV (check 1 is run first if missing).
One run per out dir: exclusive flock on <out>/.09b_leakage.lock.

Exit status: 0 ok, 1 bad input / lock / check failed / another run active, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import gc
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import signal
import sys
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.metrics import average_precision_score, roc_auc_score

from config.config import CACHE_DIR, CONFIG_DIR, REPO_ROOT, RESULTS_DIR, LockError, verify_lock

# --------------------------------------------------------------------------- CONFIG (fixed before looking)

CONFIG = {
    "seed": 42,
    "groups": ["G1", "G2", "GLOBAL"],
    "global_group": "GLOBAL",
    "global_note": "GLOBAL = all train / val rows (G1 + G2 + GEN devices), same splits",
    "probe": "XGBClassifier(scale_pos_weight=n_benign/n_attack of its training rows, random_state=42, "
             "n_jobs=-1), library defaults otherwise -- identical to 09_train_specialists.py bakeoff",
    "shortcut_auc": 0.99,
    "top_k_gain": 15,
    "ablation_top_n": 5,
    "fingerprint_family_share_min": 0.90,
    "fingerprint_benign_share_max": 0.05,
    "default_threshold": 0.5,
    "same_set_max_fp": 1,
    "same_set_label": "same-set threshold, optimistic",
    "threshold_rule": "flag attack iff score >= threshold; same-set = lowest observed score of the evaluated "
                      "rows with <= same_set_max_fp FP on the evaluated benign rows (inf = only flagging "
                      "nothing meets it)",
    "low_n": 50,
    "syn_family": "syn_flood",
    "syn_aliases": {"first": "SYN first part", "five": "SYN 5"},
    "victim_min_syn_rows": 1000,
    "zero_duration_feature": "Flow Duration",
    "packet_count_features": ["Total Fwd Packet", "Total Bwd packets"],
    "row_hash": "per column pandas.util.hash_array(float64 value + 0.0), combined h = (h ^ hc) * FNV prime "
                "(uint64); equal hash = equal row (64-bit: collision chance ~1e-8 at this size)",
    "dry_run_frac": 0.05,
    "dry_run_strata": ["group", "session", "device", "y", "attack_family"],
    "active_idle_gap_seconds": 300,
}

CHECKS = {1: "auc", 2: "fingerprints", 3: "ablation", 4: "duplicates", 5: "cross_capture", 6: "leave_victim_out"}
CSV = {1: "single_feature_auc.csv", 2: "fingerprints.csv", 3: "ablation.csv", 4: "duplicates.csv",
       5: "cross_capture.csv", 6: "leave_victim_out.csv"}

SCRIPT = "09b_leakage_checks.py"
TRAIN_PARQUET = CACHE_DIR / "datasets" / "v1" / "train.parquet"
VAL_PARQUET = CACHE_DIR / "datasets" / "v1" / "val.parquet"
FEATURES_JSON = CONFIG_DIR / "features_v1.json"
ATTACK_SET = CONFIG_DIR / "attack_set.json"
SPLIT_PLAN = CONFIG_DIR / "split_plan.json"
MANIFEST = RESULTS_DIR / "step8" / "manifest_v1.json"
OUT_DEFAULT = RESULTS_DIR / "step9" / "leakage"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
RUN_LOCK = ".09b_leakage.lock"

META_COLS = ["y", "attack_family", "group", "device", "device_category", "session", "split", "start_ts"]
LOAD_META = ["y", "attack_family", "group", "device", "session", "split", "start_ts"]
IDENTITY_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp", "Label"]
IDENTITY_RE = re.compile(r"(?i)\b(ip|port|mac|id)\b|timestamp|label|owner|device|group|session")
FNV_PRIME = np.uint64(0x100000001B3)


# --------------------------------------------------------------------------- small helpers
# Origin: 09_train_specialists.py (log, fatal, rel, scrub, guard_read, read_json, lib_versions, md_table).

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
    """09b never opens the test split: every file read goes through here."""
    if "test" in str(path).lower():
        raise AssertionError(f"{SCRIPT} must not read {path} (path contains 'test')")
    return path


def read_json(path: Path) -> dict:
    return json.loads(guard_read(path).read_text(encoding="utf-8"))


def lib_versions() -> dict:
    out = {"python": platform.python_version()}
    for pkg in ("numpy", "pandas", "pyarrow", "scipy", "scikit-learn", "xgboost"):
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


# Origin: 08_build_datasets.py run_lock() via 09_train_specialists.py (own lock file name).
def run_lock(d: Path):
    """Exclusive, non-blocking flock on <d>/.09b_leakage.lock for the whole run (released by the
    kernel on exit)."""
    d.mkdir(parents=True, exist_ok=True)
    path = d / RUN_LOCK
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        fatal(f"another {SCRIPT} run is using {rel(d)} (lock {RUN_LOCK} held by: {holder}); "
              "refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} since {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}"
             f" argv {' '.join(sys.argv[1:])}\n")
    fh.flush()
    return fh


def write_csv(path: Path, df: pd.DataFrame) -> None:
    tmp = path.with_suffix(".csv.tmp")
    df.to_csv(tmp, index=False)
    os.replace(tmp, path)


# --------------------------------------------------------------------------- FP/hour denominator

# Origin: 08_build_datasets.py benign_hours() (verbatim apart from the SPLITS constant), as in 09.
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


# --------------------------------------------------------------------------- data

def load_meta(path: Path) -> pd.DataFrame:
    """Origin: 09_train_specialists.py load_meta() (+ device and split columns)."""
    df = pq.read_table(guard_read(path), columns=LOAD_META).to_pandas()
    for c in ("attack_family", "group", "device", "session", "split"):
        df[c] = df[c].fillna("").astype(str)
    yv = set(np.unique(df["y"]).tolist())
    if not yv <= {0, 1}:
        fatal(f"{path.name}: y takes values {sorted(yv)}, expected 0 = benign / 1 = attack; STOP")
    bad = int(((df["y"] == 1) != (df["attack_family"] != "")).sum())
    if bad:
        fatal(f"{path.name}: {bad} rows where y == 1 disagrees with attack_family being set; STOP")
    return df


def load_matrix(path: Path, feats: list[str], rows: np.ndarray) -> np.ndarray:
    """Origin: 09_train_specialists.py load_matrix(): rows of the 70 features, features_v1 order, float32."""
    t = pq.read_table(guard_read(path), columns=feats)
    if t.column_names != feats:
        raise AssertionError(f"{path.name}: feature columns != features_v1 order")
    X = np.empty((len(rows), len(feats)), dtype=np.float32)
    for j, c in enumerate(feats):
        X[:, j] = t.column(c).to_numpy()[rows]
    del t
    return X


def stratified_sample(meta: pd.DataFrame, frac: float, seed: int) -> np.ndarray:
    """Origin: 09_train_specialists.py stratified_sample() (strata from CONFIG)."""
    rng = np.random.default_rng(seed)
    keep = []
    for _, idx in meta.groupby(CONFIG["dry_run_strata"], sort=True).indices.items():
        n = max(1, int(round(frac * len(idx))))
        keep.append(rng.choice(idx, size=n, replace=False))
    return np.sort(np.concatenate(keep))


class Ctx:
    """Everything the checks share. tr / va are the rows in use (dry run: the subsample); full_tr /
    full_va are all rows (only for FP/hour scaling and row counts)."""

    def __init__(self, args, inputs: dict):
        self.args, self.dry = args, args.dry_run
        self.M, self.feats, self.families = inputs["M"], inputs["feats"], inputs["families"]
        self.syn = inputs["syn"]
        self.full_tr, self.full_va = load_meta(TRAIN_PARQUET), load_meta(VAL_PARQUET)
        self.tr_pos, self.va_pos = np.arange(len(self.full_tr)), np.arange(len(self.full_va))
        if self.dry:
            self.tr_pos = stratified_sample(self.full_tr, CONFIG["dry_run_frac"], CONFIG["seed"])
            self.va_pos = stratified_sample(self.full_va, CONFIG["dry_run_frac"], CONFIG["seed"] + 1)
        self.tr = self.full_tr.iloc[self.tr_pos].reset_index(drop=True)
        self.va = self.full_va.iloc[self.va_pos].reset_index(drop=True)
        t = time.perf_counter()
        self.Xtr = load_matrix(TRAIN_PARQUET, self.feats, self.tr_pos)
        self.Xva = load_matrix(VAL_PARQUET, self.feats, self.va_pos)
        log(f"loaded train {self.Xtr.shape} val {self.Xva.shape} float32 in {time.perf_counter() - t:.1f} s"
            + (f"  (DRY RUN {CONFIG['dry_run_frac']:.0%} stratified of {len(self.full_tr):,} / "
               f"{len(self.full_va):,})" if self.dry else ""))
        self.ytr = self.tr["y"].to_numpy().astype(np.int64)
        self.yva = self.va["y"].to_numpy().astype(np.int64)
        self.ftr = self.tr["attack_family"].to_numpy(dtype=object)
        self.fva = self.va["attack_family"].to_numpy(dtype=object)
        self._full_model = None
        self.hours_log: list[dict] = []

    def col64(self, split: str, c: str) -> np.ndarray:
        """Exact float64 values of one feature for the rows in use (-0.0 folded into 0.0)."""
        path, pos = (TRAIN_PARQUET, self.tr_pos) if split == "train" else (VAL_PARQUET, self.va_pos)
        return pq.read_table(guard_read(path), columns=[c]).column(c).to_numpy()[pos].astype(np.float64) + 0.0

    def group_mask(self, meta: pd.DataFrame, g: str) -> np.ndarray:
        return np.ones(len(meta), bool) if g == CONFIG["global_group"] else (meta["group"] == g).to_numpy()

    def eval_hours(self, label: str, sel) -> float:
        """FP/hour denominator for the benign rows sel(train_meta, val_meta) -> (mask_tr, mask_va) picks:
        08's rule on the FULL data's matching benign rows; dry run: scaled by the benign sample fraction."""
        mt, mv = sel(self.full_tr, self.full_va)
        ben = pd.concat([self.full_tr[mt & (self.full_tr["y"] == 0).to_numpy()],
                         self.full_va[mv & (self.full_va["y"] == 0).to_numpy()]])
        h_full, n_full = rows_benign_hours(self.M, ben), len(ben)
        st, sv = sel(self.tr, self.va)
        n_sub = int((st & (self.ytr == 0)).sum() + (sv & (self.yva == 0)).sum())
        h = h_full * n_sub / n_full if (self.dry and n_full) else h_full
        self.hours_log.append({"evaluation": label, "benign_rows_full": n_full, "benign_rows_used": n_sub,
                               "hours_full": round(h_full, 4), "hours_used": round(h, 6),
                               "rule": "08 benign_hours on manifest session_cuts" + (
                                   "; dry run: scaled by the benign sample fraction" if self.dry else "")})
        return h

    def full_model(self):
        """GLOBAL probe on every train row in use (shared by checks 3 and 5)."""
        if self._full_model is None:
            self._full_model = fit_probe(self.Xtr, self.ytr, "GLOBAL full")
        return self._full_model


# --------------------------------------------------------------------------- probe + evaluation

def fit_probe(X: np.ndarray, y: np.ndarray, tag: str):
    """Origin: 09_train_specialists.py build_model("XGB") -- same estimator and class-weight wiring."""
    from xgboost import XGBClassifier
    n_ben, n_att = int((y == 0).sum()), int((y == 1).sum())
    m = XGBClassifier(scale_pos_weight=n_ben / n_att, random_state=CONFIG["seed"], n_jobs=-1)
    t = time.perf_counter()
    m.fit(X, y)
    if [int(c) for c in m.classes_] != [0, 1]:
        raise AssertionError(f"probe classes_ {m.classes_} != [0, 1]")
    log(f"    probe [{tag}] fit on {len(y):,} rows (benign {n_ben:,} / attack {n_att:,}, scale_pos_weight "
        f"{n_ben / n_att:.4g}) in {time.perf_counter() - t:.1f} s")
    return m


def score(model, X: np.ndarray) -> np.ndarray:
    if not len(X):   # e.g. a victim with no SYN rows in train: xgboost returns shape (0, 0)
        return np.zeros(0, dtype=np.float64)
    return model.predict_proba(X)[:, 1].astype(np.float64)


def same_set_threshold(s: np.ndarray, y: np.ndarray, k: int) -> float:
    """Origin: 09_train_specialists.py operating_points(): lowest observed score with <= k FP."""
    ben_desc = np.sort(s[y == 0])[::-1]
    cand = np.unique(s)
    if k >= len(ben_desc):
        return float(cand[0])
    i = int(np.searchsorted(cand, ben_desc[k], side="right"))
    return float(cand[i]) if i < len(cand) else math.inf


def evaluate(s: np.ndarray, y: np.ndarray, fam: np.ndarray, families: list[str], hours: float) -> dict:
    both = len(np.unique(y)) == 2
    out = {"n_attack_eval": int((y == 1).sum()), "n_benign_eval": int((y == 0).sum()),
           "benign_hours_eval": hours,
           "pr_auc": average_precision_score(y, s) if both else math.nan,
           "roc_auc": roc_auc_score(y, s) if both else math.nan}
    k = CONFIG["same_set_max_fp"]
    for tag, thr in (("t05", float(CONFIG["default_threshold"])), ("t1fp", same_set_threshold(s, y, k))):
        flag = s >= thr
        fp, tp = int((flag & (y == 0)).sum()), int((flag & (y == 1)).sum())
        out.update({f"thr_{tag}": thr, f"fp_{tag}": fp, f"fph_{tag}": fp / hours if hours > 0 else math.nan,
                    f"dr_{tag}": tp / out["n_attack_eval"] if out["n_attack_eval"] else math.nan})
        for f in families:
            m = (y == 1) & (fam == f)
            n = int(m.sum())
            out[f"n_{f}"] = n
            out[f"dr_{tag}_{f}"] = int((flag & m).sum()) / n if n else math.nan
    return out


# --------------------------------------------------------------------------- check 1

def check_auc(ctx: Ctx) -> pd.DataFrame:
    gains = []
    for g in CONFIG["groups"]:
        m = ctx.group_mask(ctx.tr, g)
        model = fit_probe(ctx.Xtr[m], ctx.ytr[m], f"{g} train (importance)")
        gs = model.get_booster().get_score(importance_type="gain")
        gain = np.array([gs.get(f"f{j}", 0.0) for j in range(len(ctx.feats))])
        rank = pd.Series(-gain).rank(method="first").astype(int).to_numpy()
        gains += [{"group": g, "feature": c, "xgb_gain": gain[j], "xgb_gain_rank": int(rank[j]),
                   "top15_gain": bool(rank[j] <= CONFIG["top_k_gain"] and gain[j] > 0)}
                  for j, c in enumerate(ctx.feats)]
        del model
        gc.collect()

    rows = []
    for split, meta, y, fam in (("train", ctx.tr, ctx.ytr, ctx.ftr), ("val", ctx.va, ctx.yva, ctx.fva)):
        gm = {g: ctx.group_mask(meta, g) for g in CONFIG["groups"]}
        scopes = {g: [("all", gm[g])] + [(f, gm[g] & ((y == 0) | (fam == f))) for f in ctx.families]
                  for g in CONFIG["groups"]}
        t = time.perf_counter()
        for c in ctx.feats:
            x = ctx.col64(split, c)
            for g in CONFIG["groups"]:
                for scope, m in scopes[g]:
                    yy = y[m]
                    n_att, n_ben = int(yy.sum()), int(len(yy) - yy.sum())
                    r = {"group": g, "split": split, "scope": scope, "feature": c, "n_benign": n_ben,
                         "n_attack": n_att}
                    if n_att == 0 or n_ben == 0:
                        r.update({"auc": math.nan, "max_auc": math.nan, "direction": "", "flag": "N/A"})
                    else:
                        a = roc_auc_score(yy, x[m])
                        r.update({"auc": a, "max_auc": max(a, 1 - a),
                                  "direction": "attack higher" if a >= 0.5 else "attack lower",
                                  "flag": "SHORTCUT_CANDIDATE" if max(a, 1 - a) >= CONFIG["shortcut_auc"] else ""})
                    r["low_n"] = "LOW_N" if 0 < n_att < CONFIG["low_n"] else ""
                    rows.append(r)
        log(f"    single-feature AUC on {split}: {len(ctx.feats)} features x {len(CONFIG['groups'])} groups x "
            f"{1 + len(ctx.families)} scopes in {time.perf_counter() - t:.1f} s")
    df = pd.DataFrame(rows).merge(pd.DataFrame(gains), on=["group", "feature"], how="left")
    for g in CONFIG["groups"]:
        for split in ("train", "val"):
            d = df[(df["group"] == g) & (df["split"] == split) & (df["flag"] == "SHORTCUT_CANDIDATE")]
            log(f"    {g:<6} {split:<5} SHORTCUT_CANDIDATE: overall {int((d['scope'] == 'all').sum())}, "
                + ", ".join(f"{f} {int((d['scope'] == f).sum())}" for f in ctx.families))
    return df


def load_check1(ctx: Ctx) -> pd.DataFrame:
    return pd.read_csv(guard_read(ctx.out / CSV[1]), keep_default_na=False)


def shortcut_set(df1: pd.DataFrame, group: str, split: str, overall_only: bool) -> list[str]:
    d = df1[(df1["group"] == group) & (df1["split"] == split) & (df1["flag"] == "SHORTCUT_CANDIDATE")]
    if overall_only:
        d = d[d["scope"] == "all"]
    return sorted(set(d["feature"]))


def top_gain(df1: pd.DataFrame, group: str, n: int) -> list[str]:
    d = df1[(df1["group"] == group) & (df1["split"] == "train") & (df1["scope"] == "all")].copy()
    d["xgb_gain"] = pd.to_numeric(d["xgb_gain"])
    d = d[d["xgb_gain"] > 0].sort_values("xgb_gain", ascending=False)
    return list(d["feature"].head(n))


# --------------------------------------------------------------------------- check 2

def check_fingerprints(ctx: Ctx) -> pd.DataFrame:
    df1 = load_check1(ctx)
    sel = {}
    for g in CONFIG["groups"]:
        cand = set(shortcut_set(df1, g, "train", overall_only=False))
        top = set(top_gain(df1, g, CONFIG["top_k_gain"]))
        sel[g] = {c: "+".join(s for s, ok in (("shortcut", c in cand), ("top15_gain", c in top)) if ok)
                  for c in ctx.feats if c in cand or c in top}
        log(f"    {g}: {len(sel[g])} features ({len(cand)} SHORTCUT_CANDIDATE on train, {len(top)} top-gain)")
    rows = []
    gm = {g: ctx.group_mask(ctx.tr, g) for g in CONFIG["groups"]}
    for c in ctx.feats:
        if not any(c in sel[g] for g in CONFIG["groups"]):
            continue
        x = ctx.col64("train", c)
        for g in CONFIG["groups"]:
            if c not in sel[g]:
                continue
            xg, yg, fg = x[gm[g]], ctx.ytr[gm[g]], ctx.ftr[gm[g]]
            ben = xg[yg == 0]
            for f in ctx.families:
                xf = xg[(yg == 1) & (fg == f)]
                r = {"group": g, "feature": c, "selected_as": sel[g][c], "attack_family": f, "n_family": len(xf),
                     "n_benign": len(ben)}
                if not len(xf):
                    r.update({"mode_value": "", "family_share": math.nan, "benign_share": math.nan, "flag": "N/A"})
                else:
                    vals, cnt = np.unique(xf, return_counts=True)
                    mode = vals[int(np.argmax(cnt))]
                    fs, bs = cnt.max() / len(xf), float((ben == mode).mean()) if len(ben) else math.nan
                    r.update({"mode_value": repr(float(mode)), "family_share": fs, "benign_share": bs,
                              "flag": "FINGERPRINT" if (fs >= CONFIG["fingerprint_family_share_min"]
                                                        and bs <= CONFIG["fingerprint_benign_share_max"]) else ""})
                r["low_n"] = "LOW_N" if 0 < len(xf) < CONFIG["low_n"] else ""
                rows.append(r)
    df = pd.DataFrame(rows)
    for g in CONFIG["groups"]:
        d = df[(df["group"] == g) & (df["flag"] == "FINGERPRINT")]
        log(f"    {g}: FINGERPRINT rows {len(d)} ({', '.join(f'{f} {int((d.attack_family == f).sum())}' for f in ctx.families)})")
    return df


# --------------------------------------------------------------------------- check 3

def check_ablation(ctx: Ctx) -> pd.DataFrame:
    df1 = load_check1(ctx)
    g = CONFIG["global_group"]
    cand_all = shortcut_set(df1, g, "train", overall_only=True)
    cand_any = shortcut_set(df1, g, "train", overall_only=False)
    top = top_gain(df1, g, CONFIG["ablation_top_n"])
    variants = [("full", []), ("minus_shortcut_overall", cand_all)]
    if set(cand_any) != set(cand_all):
        variants.append(("minus_shortcut_any_scope", cand_any))
    variants.append((f"minus_top{CONFIG['ablation_top_n']}_gain", top))
    hours = ctx.eval_hours("check3 GLOBAL val benign",
                           lambda tr, va: (np.zeros(len(tr), bool), np.ones(len(va), bool)))
    rows = []
    for name, drop in variants:
        keep = [j for j, c in enumerate(ctx.feats) if c not in set(drop)]
        r = {"variant": name, "n_features": len(keep), "n_removed": len(drop), "removed": "; ".join(drop),
             "removed_rule": {"full": "-", "minus_shortcut_overall": "SHORTCUT_CANDIDATE on GLOBAL train, overall "
                              "scope (benign vs all attacks)",
                              "minus_shortcut_any_scope": "SHORTCUT_CANDIDATE on GLOBAL train, overall or any "
                              "per-family scope"}.get(name, f"top-{CONFIG['ablation_top_n']} XGBoost gain, GLOBAL "
                                                             "train full-feature probe"),
             "n_train": len(ctx.ytr)}
        if not keep:
            r["status"] = "SKIPPED: no feature left"
            rows.append(r)
            continue
        model = ctx.full_model() if name == "full" else fit_probe(
            np.ascontiguousarray(ctx.Xtr[:, keep]), ctx.ytr, f"GLOBAL {name}")
        s = score(model, ctx.Xva if name == "full" else np.ascontiguousarray(ctx.Xva[:, keep]))
        r.update({"status": "OK", **evaluate(s, ctx.yva, ctx.fva, ctx.families, hours)})
        rows.append(r)
        log(f"    {name:<26} features {len(keep):>2}  PR-AUC {r['pr_auc']:.4f}  DR@0.5 {r['dr_t05']:.4f}  "
            f"DR@<=1FP {r['dr_t1fp']:.4f} (thr {r['thr_t1fp']:.6g})")
        if name != "full":
            del model
        gc.collect()
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- check 4

def row_hashes(ctx: Ctx, split: str) -> np.ndarray:
    h = np.zeros(len(ctx.tr) if split == "train" else len(ctx.va), dtype=np.uint64)
    with np.errstate(over="ignore"):
        for c in ctx.feats:
            h = (h ^ pd.util.hash_array(ctx.col64(split, c))) * FNV_PRIME
    return h


def check_duplicates(ctx: Ctx) -> pd.DataFrame:
    H = {"train": row_hashes(ctx, "train"), "val": row_hashes(ctx, "val")}
    meta = {"train": ctx.tr, "val": ctx.va}
    pk = CONFIG["packet_count_features"]
    zero = {sp: ctx.col64(sp, CONFIG["zero_duration_feature"]) == 0 for sp in H}
    onep = {sp: (ctx.col64(sp, pk[0]) + ctx.col64(sp, pk[1])) == 1 for sp in H}
    rows = []

    def add(item: str, scope: str, mask: np.ndarray, split: str, note: str = "", groups: int | None = None):
        m = meta[split]
        lab = m["y"].astype(str) + "|" + m["attack_family"]
        for key in ["all"] + sorted(lab.unique()):
            sub = np.ones(len(m), bool) if key == "all" else (lab == key).to_numpy()
            y, f = ("all", "all") if key == "all" else key.split("|")
            den = int(sub.sum())
            n = int((mask & sub).sum())
            rows.append({"item": item, "scope": scope, "rows_of": split, "y": y, "attack_family": f or "(benign)",
                         "n_rows": n, "denominator": den, "fraction": n / den if den else math.nan,
                         "n_zero_duration": int((mask & sub & zero[split]).sum()),
                         "n_one_packet": int((mask & sub & onep[split]).sum()),
                         "zero_duration_rows_in_denominator": int((sub & zero[split]).sum()),
                         "one_packet_rows_in_denominator": int((sub & onep[split]).sum()),
                         "n_groups": groups if key == "all" else "", "note": note})

    for sp in ("train", "val"):
        add("all_rows", sp, np.ones(len(H[sp]), bool), sp, "reference counts")
        u, inv, cnt = np.unique(H[sp], return_inverse=True, return_counts=True)
        dup = cnt[inv] > 1
        add("duplicate_within_split", sp, dup, sp, "row shares its 70 feature values with >= 1 other row of the "
            "same split", groups=int((cnt > 1).sum()))
        yy = meta[sp]["y"].to_numpy()
        ymin = np.full(len(u), 2)
        ymax = np.full(len(u), -1)
        np.minimum.at(ymin, inv, yy)
        np.maximum.at(ymax, inv, yy)
        conf = (ymin != ymax)[inv]
        add("label_conflict_within_split", sp, conf, sp, "identical feature row carries both y = 0 and y = 1 "
            "within the split", groups=int((ymin != ymax).sum()))
    in_tr = np.isin(H["val"], H["train"])
    add("val_row_equals_a_train_row", "train->val", in_tr, "val", "val row whose 70 values also occur in train",
        groups=int(len(np.unique(H["val"][in_tr]))))
    add("train_row_equals_a_val_row", "train->val", np.isin(H["train"], H["val"]), "train",
        "train row whose 70 values also occur in val")
    # Label conflicts over train + val together.
    hh = np.r_[H["train"], H["val"]]
    yy = np.r_[ctx.ytr, ctx.yva]
    u, inv = np.unique(hh, return_inverse=True)
    ymin, ymax = np.full(len(u), 2), np.full(len(u), -1)
    np.minimum.at(ymin, inv, yy)
    np.maximum.at(ymax, inv, yy)
    conf = (ymin != ymax)[inv]
    ng = int((ymin != ymax).sum())
    add("label_conflict_train_plus_val", "train+val", conf[:len(H["train"])], "train",
        "train rows in a feature-row group that has both labels across train + val", groups=ng)
    add("label_conflict_train_plus_val", "train+val", conf[len(H["train"]):], "val",
        "val rows in a feature-row group that has both labels across train + val", groups=ng)
    df = pd.DataFrame(rows)
    for it in ("duplicate_within_split", "label_conflict_within_split", "val_row_equals_a_train_row",
               "label_conflict_train_plus_val"):
        for _, r in df[(df["item"] == it) & (df["y"] == "all")].iterrows():
            log(f"    {it:<30} {r['rows_of']:<5} {r['n_rows']:>8,} / {r['denominator']:>8,} rows "
                f"({r['fraction']:.2%}); of them 0-duration {r['n_zero_duration']:,}, 1-packet {r['n_one_packet']:,}")
    return df


# --------------------------------------------------------------------------- check 5

def check_cross_capture(ctx: Ctx) -> pd.DataFrame:
    fam = CONFIG["syn_family"]
    first, five = ctx.syn["first"], ctx.syn["five"]
    hours = ctx.eval_hours("check5/6 val benign", lambda tr, va: (np.zeros(len(tr), bool), np.ones(len(va), bool)))
    full = ctx.full_model()
    s_full_va = score(full, ctx.Xva)
    rows = []
    for rot, held, kept in (("A", five, first), ("B", first, five)):
        tr_held = (ctx.tr["session"] == held).to_numpy()
        va_held = (ctx.va["session"] == held).to_numpy()
        att_tr = tr_held & (ctx.ftr == fam)
        att_va = va_held & (ctx.fva == fam)
        ben_va = ctx.yva == 0
        victims = sorted(set(ctx.tr.loc[att_tr, "device"]) | set(ctx.va.loc[att_va, "device"]))
        vgroups = sorted(set(ctx.tr.loc[att_tr, "group"]) | set(ctx.va.loc[att_va, "group"]))
        trm = ~tr_held
        model = fit_probe(ctx.Xtr[trm], ctx.ytr[trm], f"rotation {rot}: hold out {held}")
        s = np.r_[score(model, ctx.Xtr[att_tr]), score(model, ctx.Xva[att_va | ben_va])]
        y = np.r_[ctx.ytr[att_tr], ctx.yva[att_va | ben_va]]
        f = np.r_[ctx.ftr[att_tr], ctx.fva[att_va | ben_va]]
        r = evaluate(s, y, f, [fam], hours)
        # Extra: FP on the held-out session's own background benign (train + val), never trained on.
        hb_tr, hb_va = tr_held & (ctx.ytr == 0), va_held & (ctx.yva == 0)
        sb = np.r_[score(model, ctx.Xtr[hb_tr]), score(model, ctx.Xva[hb_va])]
        base = {"rotation": rot, "held_out_session": held, "held_out_alias": ctx.syn["alias"][held],
                "held_out_victims": "; ".join(victims), "held_out_victim_groups": "; ".join(vgroups)}
        rows.append({**base, "setting": "held_out_capture",
                     "train_rows": f"train split minus every row of session {held} (attack and background benign)",
                     "n_train": int(trm.sum()), "n_train_syn": int((trm & (ctx.ftr == fam)).sum()),
                     "eval_attack": f"{held} {fam} rows, train + val splits", "eval_benign": "all val benign",
                     **r, "held_session_benign_rows": len(sb),
                     "held_session_benign_fp_t05": int((sb >= r["thr_t05"]).sum()),
                     "held_session_benign_fp_t1fp": int((sb >= r["thr_t1fp"]).sum())})
        log(f"    rotation {rot} hold out {held}: DR@0.5 {r['dr_t05']:.4f}  DR@<=1FP {r['dr_t1fp']:.4f} "
            f"(thr {r['thr_t1fp']:.6g})  FP@0.5 {r['fp_t05']}  on {r['n_attack_eval']:,} SYN rows")
        del model
        gc.collect()
        sv = s_full_va[att_va | ben_va]
        rb = evaluate(sv, ctx.yva[att_va | ben_va], ctx.fva[att_va | ben_va], [fam], hours)
        rows.append({**base, "setting": "in_capture_baseline", "train_rows": "all train rows (both SYN captures)",
                     "n_train": len(ctx.ytr), "n_train_syn": int((ctx.ftr == fam).sum()),
                     "eval_attack": f"{held} {fam} rows, val split only", "eval_benign": "all val benign", **rb})
        log(f"    rotation {rot} baseline (in-capture, {held} val): DR@0.5 {rb['dr_t05']:.4f}  "
            f"DR@<=1FP {rb['dr_t1fp']:.4f}  on {rb['n_attack_eval']:,} SYN rows")
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- check 6

def victims(ctx: Ctx) -> tuple[pd.DataFrame, int]:
    fam = CONFIG["syn_family"]
    need = CONFIG["victim_min_syn_rows"]
    if ctx.dry:
        need = max(1, int(round(need * CONFIG["dry_run_frac"])))
    parts = [m[m["attack_family"] == fam].assign(_split=sp) for sp, m in (("train", ctx.tr), ("val", ctx.va))]
    v = pd.concat(parts).groupby(["device", "group", "_split"]).size().unstack("_split", fill_value=0)
    for sp in ("train", "val"):
        if sp not in v:
            v[sp] = 0
    v["total"] = v["train"] + v["val"]
    return v.reset_index().sort_values("total", ascending=False), need


def check_leave_victim_out(ctx: Ctx) -> pd.DataFrame:
    fam = CONFIG["syn_family"]
    hours = ctx.eval_hours("check5/6 val benign", lambda tr, va: (np.zeros(len(tr), bool), np.ones(len(va), bool)))
    V, need = victims(ctx)
    ben_va = ctx.yva == 0
    rows = []
    for _, v in V.iterrows():
        base = {"victim": v["device"], "group": v["group"], "syn_rows_train": int(v["train"]),
                "syn_rows_val": int(v["val"]), "syn_rows_total": int(v["total"]), "min_syn_rows": need}
        if v["total"] < need:
            rows.append({**base, "status": f"SKIPPED: < {need} SYN rows"})
            continue
        vt = ((ctx.tr["device"] == v["device"]).to_numpy()) & (ctx.ftr == fam)
        vv = ((ctx.va["device"] == v["device"]).to_numpy()) & (ctx.fva == fam)
        sess = sorted(set(ctx.tr.loc[vt, "session"]) | set(ctx.va.loc[vv, "session"]))
        model = fit_probe(ctx.Xtr[~vt], ctx.ytr[~vt], f"leave out {v['device']} SYN")
        s = np.r_[score(model, ctx.Xtr[vt]), score(model, ctx.Xva[vv | ben_va])]
        y = np.r_[ctx.ytr[vt], ctx.yva[vv | ben_va]]
        f = np.r_[ctx.ftr[vt], ctx.fva[vv | ben_va]]
        r = evaluate(s, y, f, [fam], hours)
        note = ("victim has no SYN rows in train: this probe equals the full-train probe" if not vt.any() else "")
        rows.append({**base, "status": "OK", "victim_sessions": "; ".join(sess),
                     "n_train": int((~vt).sum()), "n_train_syn": int(((~vt) & (ctx.ftr == fam)).sum()),
                     **r, "note": note})
        log(f"    leave out {v['device']:<38} DR@0.5 {r['dr_t05']:.4f}  DR@<=1FP {r['dr_t1fp']:.4f}  "
            f"FP@0.5 {r['fp_t05']}  on {r['n_attack_eval']:,} SYN rows" + (f"  ({note})" if note else ""))
        del model
        gc.collect()
    return pd.DataFrame(rows)


RUNNERS = {1: check_auc, 2: check_fingerprints, 3: check_ablation, 4: check_duplicates, 5: check_cross_capture,
           6: check_leave_victim_out}


# --------------------------------------------------------------------------- summary

def read_out(out: Path, k: int) -> pd.DataFrame:
    p = out / CSV[k]
    return pd.read_csv(guard_read(p), keep_default_na=False) if p.exists() else pd.DataFrame()


def rec(df: pd.DataFrame, cols: list[str], nd: dict | None = None) -> list[dict]:
    nd = nd or {}
    return [{c: (fmt(r[c], nd[c]) if c in nd else r[c]) for c in cols} for _, r in df.iterrows()]


def write_summary(out: Path, meta: dict, families: list[str]) -> None:
    L = [f"# Step 9b leakage / shortcut checks{' -- DRY RUN (5 % stratified subsample)' if meta['dry_run'] else ''}",
         "", f"- run: {meta['run_utc']} | seed {CONFIG['seed']} | features sha256 {meta['features']['sha256'][:16]}... "
             f"| verify_lock {'PASS' if meta['verify_lock']['ok'] else 'FAIL'}",
         f"- Probe: {CONFIG['probe']}.",
         f"- Thresholds: 0.5 and the {CONFIG['same_set_label']} (lowest observed score with <= "
         f"{CONFIG['same_set_max_fp']} FP on the evaluated benign rows). FP/hour = 08 active-benign-hours rule "
         "on the evaluated benign rows.",
         f"- Pre-set flags: SHORTCUT_CANDIDATE max-AUC >= {CONFIG['shortcut_auc']}; FINGERPRINT family share >= "
         f"{CONFIG['fingerprint_family_share_min']:.0%} and benign share <= {CONFIG['fingerprint_benign_share_max']:.0%}; "
         f"LOW_N < {CONFIG['low_n']} attack rows.",
         f"- {CONFIG['global_note']}. Facts only; no conclusion is drawn here.", ""]

    d1 = read_out(out, 1)
    L += ["## 1. Single-feature separability", ""]
    if d1.empty:
        L += ["_not run_", ""]
    else:
        d1["max_auc"] = pd.to_numeric(d1["max_auc"], errors="coerce")
        cnt = []
        for g in CONFIG["groups"]:
            for sp in ("train", "val"):
                d = d1[(d1["group"] == g) & (d1["split"] == sp) & (d1["flag"] == "SHORTCUT_CANDIDATE")]
                cnt.append({"group": g, "split": sp, "overall": int((d["scope"] == "all").sum()),
                            **{f: int((d["scope"] == f).sum()) for f in families}})
        L += ["SHORTCUT_CANDIDATE counts (of 70 features) per scope:", ""]
        L += md_table(cnt, ["group", "split", "overall"] + families) + [""]
        d = d1[(d1["flag"] == "SHORTCUT_CANDIDATE") & (d1["scope"] == "all")].sort_values(
            ["group", "split", "max_auc"], ascending=[True, True, False])
        L += ["SHORTCUT_CANDIDATE, overall scope (benign vs all attacks):", ""]
        L += md_table(rec(d, ["group", "split", "feature", "max_auc", "direction", "xgb_gain_rank"],
                          {"max_auc": 4}), ["group", "split", "feature", "max_auc", "direction", "xgb_gain_rank"]) + [""]
        L += [f"Top-{CONFIG['top_k_gain']} XGBoost gain (probe fitted on the group's train) with that feature's "
              "overall max-AUC on train / val:", ""]
        for g in CONFIG["groups"]:
            t = d1[(d1["group"] == g) & (d1["scope"] == "all")]
            tt = t[t["split"] == "train"].set_index("feature")
            tv = t[t["split"] == "val"].set_index("feature")
            top = tt[tt["top15_gain"].astype(str) == "True"].copy()
            top["xgb_gain_rank"] = pd.to_numeric(top["xgb_gain_rank"])
            top = top.sort_values("xgb_gain_rank")
            L += [f"**{g}**", ""]
            L += md_table([{"rank": int(r["xgb_gain_rank"]), "feature": c, "gain": fmt(r["xgb_gain"], 1),
                            "max_auc train": fmt(r["max_auc"]), "max_auc val": fmt(tv.loc[c, "max_auc"]),
                            "flag train": r["flag"], "flag val": tv.loc[c, "flag"]} for c, r in top.iterrows()],
                          ["rank", "feature", "gain", "max_auc train", "max_auc val", "flag train", "flag val"]) + [""]
        lown = d1[(d1["low_n"] == "LOW_N")][["group", "split", "scope", "n_attack"]].drop_duplicates()
        if len(lown):
            L += ["LOW_N scopes (AUC on < 50 attack rows): " + "; ".join(
                f"{r.group} {r.split} {r.scope} (n={r.n_attack})" for r in lown.itertuples()), ""]

    d2 = read_out(out, 2)
    L += ["## 2. Constant-value fingerprints (train)", ""]
    if d2.empty:
        L += ["_not run_", ""]
    else:
        fp = d2[d2["flag"] == "FINGERPRINT"]
        L += [f"{len(d2)} (group, feature, family) rows checked; {len(fp)} flagged FINGERPRINT:", ""]
        L += md_table(rec(fp, ["group", "feature", "selected_as", "attack_family", "n_family", "mode_value",
                               "family_share", "benign_share", "low_n"], {"family_share": 4, "benign_share": 4}),
                      ["group", "feature", "selected_as", "attack_family", "n_family", "mode_value",
                       "family_share", "benign_share", "low_n"]) + [""]

    d3 = read_out(out, 3)
    L += ["## 3. Ablation (GLOBAL train -> GLOBAL val)", ""]
    if d3.empty:
        L += ["_not run_", ""]
    else:
        cols = ["variant", "status", "n_features", "pr_auc", "dr_t05", "fph_t05", "thr_t1fp", "dr_t1fp", "fp_t1fp"]
        cols += [f"dr_t1fp_{f}" for f in families]
        nd = {"pr_auc": 4, "dr_t05": 4, "fph_t05": 2, "thr_t1fp": 6, "dr_t1fp": 4,
              **{f"dr_t1fp_{f}": 4 for f in families}}
        L += md_table(rec(d3, [c for c in cols if c in d3], nd), [c for c in cols if c in d3]) + [""]
        L += [f"- {r['variant']}: removed {r['n_removed']} ({r['removed_rule']}): {r['removed'] or '-'}"
              for _, r in d3.iterrows()]
        if "n_udp_flood" in d3:
            L += [f"- val udp_flood n = {d3['n_udp_flood'].iloc[0]} (LOW_N if < {CONFIG['low_n']})."]
        L += [""]

    d4 = read_out(out, 4)
    L += ["## 4. Duplicates / label conflicts (GLOBAL, 70 feature values)", ""]
    if d4.empty:
        L += ["_not run_", ""]
    else:
        d = d4[(d4["y"] == "all") & (d4["item"] != "all_rows")]
        L += md_table(rec(d, ["item", "rows_of", "n_rows", "denominator", "fraction", "n_groups", "n_zero_duration",
                              "zero_duration_rows_in_denominator", "n_one_packet"], {"fraction": 4}),
                      ["item", "rows_of", "n_rows", "denominator", "fraction", "n_groups", "n_zero_duration",
                       "zero_duration_rows_in_denominator", "n_one_packet"]) + [""]
        d = d4[(d4["item"].isin(["val_row_equals_a_train_row", "label_conflict_train_plus_val"]))
               & (d4["y"] != "all")]
        L += ["By y / family:", ""]
        L += md_table(rec(d, ["item", "rows_of", "y", "attack_family", "n_rows", "denominator", "fraction",
                              "n_zero_duration"], {"fraction": 4}),
                      ["item", "rows_of", "y", "attack_family", "n_rows", "denominator", "fraction",
                       "n_zero_duration"]) + [""]

    d5 = read_out(out, 5)
    L += ["## 5. Cross-capture generalisation (SYN, GLOBAL)", ""]
    if d5.empty:
        L += ["_not run_", ""]
    else:
        cols = ["rotation", "setting", "held_out_session", "held_out_victim_groups", "n_attack_eval", "pr_auc",
                "dr_t05", "fp_t05", "fph_t05", "thr_t1fp", "dr_t1fp", "fp_t1fp", "held_session_benign_fp_t05"]
        L += md_table(rec(d5, cols, {"pr_auc": 4, "dr_t05": 4, "fph_t05": 2, "thr_t1fp": 6, "dr_t1fp": 4}), cols)
        L += [""] + [f"- rotation {r['rotation']} held-out victims: {r['held_out_victims']}"
                     for _, r in d5[d5["setting"] == "held_out_capture"].iterrows()] + [""]

    d6 = read_out(out, 6)
    L += ["## 6. Leave-victim-out (syn_flood, GLOBAL)", ""]
    if d6.empty:
        L += ["_not run_", ""]
    else:
        cols = ["victim", "group", "status", "syn_rows_train", "syn_rows_val", "n_attack_eval", "dr_t05", "fp_t05",
                "fph_t05", "thr_t1fp", "dr_t1fp", "fp_t1fp", "note"]
        cols = [c for c in cols if c in d6]
        L += md_table(rec(d6, cols, {"dr_t05": 4, "fph_t05": 2, "thr_t1fp": 6, "dr_t1fp": 4}), cols) + [""]

    L += ["## FP/hour denominators used", ""]
    L += md_table(meta.get("fph_denominators", []), ["evaluation", "benign_rows_used", "hours_full", "hours_used", "rule"])
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- main

def check_inputs() -> dict:
    """Origin: 09_train_specialists.py check_inputs() (+ split_plan SYN session resolution)."""
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
    want = M["features"]["sha256"]
    if sha != want or F.get("sha256") != want:
        fatal(f"features_v1.json sha256 {sha} (its own field {F.get('sha256')}) != manifest {want}; refusing to run")
    if len(feats) != 70 or len(set(feats)) != 70:
        fatal(f"features_v1.json lists {len(feats)} features, expected 70 unique")
    leaked = [c for c in feats if c in IDENTITY_COLS or c in META_COLS or IDENTITY_RE.search(c)]
    if leaked:
        fatal(f"identity / metadata / IP / port columns in the feature list: {leaked}")
    for c in [CONFIG["zero_duration_feature"]] + CONFIG["packet_count_features"]:
        if c not in feats:
            fatal(f"feature {c!r} (CONFIG) not in features_v1.json; STOP")
    if M["plan"]["active_idle_gap_seconds"] != CONFIG["active_idle_gap_seconds"]:
        fatal("manifest active_idle_gap_seconds != CONFIG")
    for path in (TRAIN_PARQUET, VAL_PARQUET):
        if pq.read_schema(guard_read(path)).names != feats + META_COLS:
            fatal(f"{path.name}: columns are not exactly features_v1 (70, in order) + {META_COLS}")
    families = sorted({p["family"] for p in read_json(ATTACK_SET)["pcaps"]})
    if CONFIG["syn_family"] not in families:
        fatal(f"family {CONFIG['syn_family']!r} not in attack_set.json {families}; STOP")
    plan = read_json(SPLIT_PLAN)
    if plan.get("version") != M["plan"].get("version") or plan.get("sessions") != M["plan"].get("sessions"):
        fatal("config/split_plan.json differs from the plan recorded in manifest_v1.json; STOP")
    fam_of = {i["session"]: (i.get("label_report") or {}).get("completion_key", {}).get("attack_family")
              for i in M["inputs"]}
    syn = {"alias": {}}
    for key, alias in CONFIG["syn_aliases"].items():
        hits = [s for s, a in plan["session_aliases"].items() if a == alias]
        if len(hits) != 1:
            fatal(f"split_plan session_aliases: {len(hits)} sessions named {alias!r} ({hits}); STOP (ambiguous)")
        s = hits[0]
        if plan["sessions"].get(s) != "train" or fam_of.get(s) != CONFIG["syn_family"]:
            fatal(f"session {s} ({alias}): mode {plan['sessions'].get(s)!r}, family {fam_of.get(s)!r}; expected a "
                  f"train-mode {CONFIG['syn_family']} session; STOP")
        syn[key], syn["alias"][s] = s, alias
    log(f"features: 70, sha256 {sha[:16]}... == manifest; families {families}; SYN sessions "
        f"{syn['first']!r} = {CONFIG['syn_aliases']['first']!r}, {syn['five']!r} = {CONFIG['syn_aliases']['five']!r}")
    return {"lock": lock, "M": M, "feats": feats, "sha": sha, "families": families, "syn": syn,
            "plan_sha256": hashlib.sha256(guard_read(SPLIT_PLAN).read_bytes()).hexdigest()}


def parse_checks(vals: list[str] | None) -> list[int]:
    if not vals:
        return sorted(CHECKS)
    by_name = {v: k for k, v in CHECKS.items()}
    out = []
    for v in vals:
        k = int(v) if v.isdigit() else by_name.get(v)
        if k not in CHECKS:
            fatal(f"unknown check {v!r}; choose from {CHECKS}")
        out.append(k)
    return sorted(set(out))


def run(args) -> int:
    global _LOG_PATH
    t0 = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    out = args.out or (OUT_DEFAULT / "dry_run" if args.dry_run else OUT_DEFAULT)
    out = (out if out.is_absolute() else REPO_ROOT / out).resolve()
    if out.is_relative_to(CONFIG_DIR.resolve()):
        fatal(f"{out} must not be under config/")
    lock_fh = run_lock(out)
    _LOG_PATH = out / "run.log"
    checks = parse_checks(args.checks)
    log("=" * 100)
    log(f"{SCRIPT}  {'DRY RUN' if args.dry_run else 'FULL'}  checks {[f'{k}:{CHECKS[k]}' for k in checks]}  "
        f"out {rel(out)}  pid {os.getpid()}")
    inp = check_inputs()

    done_path = out / "done.json"
    done = json.loads(done_path.read_text(encoding="utf-8")) if done_path.exists() else {}
    if done and (done.get("dry_run") != args.dry_run or done.get("features_sha256") != inp["sha"]):
        fatal(f"{rel(done_path)} is from a run with dry_run={done.get('dry_run')} / features "
              f"{str(done.get('features_sha256'))[:16]}; use another --out")
    done.setdefault("dry_run", args.dry_run)
    done.setdefault("features_sha256", inp["sha"])
    done.setdefault("checks", {})
    for k in list(done["checks"]):
        if not (out / CSV[int(k)]).exists():
            del done["checks"][k]
    todo = [k for k in checks if str(k) not in done["checks"]]
    if any(k in todo for k in (2, 3)) and "1" not in done["checks"] and 1 not in todo:
        log("checks 2 / 3 need check 1's SHORTCUT_CANDIDATE and gain columns: running check 1 first")
        todo = [1] + todo
    log(f"checks requested {checks}; already done {sorted(int(k) for k in done['checks'])}; to run {todo}")

    ctx = Ctx(args, inp)
    ctx.out = out
    meta_path = out / "run_meta.json"
    old = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    V, need = victims(ctx)

    def counts(m: pd.DataFrame) -> dict:
        return {"rows": len(m), "benign": int((m["y"] == 0).sum()),
                "attack_by_family": {k: int(v) for k, v in m.loc[m["y"] == 1, "attack_family"].value_counts()
                                     .sort_index().items()}}

    meta = {"script": SCRIPT, "run_utc": run_utc, "argv": sys.argv, "dry_run": args.dry_run, "code_sha256": CODE_SHA256,
            "out": rel(out), "checks_requested": checks,
            "features": {"path": rel(FEATURES_JSON), "n": 70, "sha256": inp["sha"],
                         "manifest_sha256": inp["M"]["features"]["sha256"],
                         "sha256_of": "json.dumps(features, separators=(',', ':')) utf-8"},
            "verify_lock": {"ok": inp["lock"]["ok"], "checks": [{"check": n, "pass": o, "detail": scrub(d)}
                                                                for n, o, d in inp["lock"]["checks"]]},
            "inputs": {"train": rel(TRAIN_PARQUET), "val": rel(VAL_PARQUET), "manifest": rel(MANIFEST),
                       "split_plan": rel(SPLIT_PLAN), "split_plan_sha256": inp["plan_sha256"],
                       "attack_set": rel(ATTACK_SET), "test_split": "never opened"},
            "versions": lib_versions(), "platform": {"machine": platform.machine(), "cpu_count": os.cpu_count()},
            "config": CONFIG, "seed": CONFIG["seed"], "attack_families": inp["families"],
            "syn_sessions": {"first_part": inp["syn"]["first"], "syn5": inp["syn"]["five"],
                             "aliases": inp["syn"]["alias"]},
            "victims": {"min_syn_rows_used": need, "table": V.to_dict("records")},
            "thresholds": {"shortcut_auc": CONFIG["shortcut_auc"], "default": CONFIG["default_threshold"],
                           "same_set_max_fp": CONFIG["same_set_max_fp"],
                           "fingerprint": [CONFIG["fingerprint_family_share_min"], CONFIG["fingerprint_benign_share_max"]],
                           "low_n": CONFIG["low_n"], "victim_min_syn_rows": need},
            "row_counts": {g: {"train_full": counts(ctx.full_tr[ctx.group_mask(ctx.full_tr, g)]),
                               "val_full": counts(ctx.full_va[ctx.group_mask(ctx.full_va, g)]),
                               "train_used": counts(ctx.tr[ctx.group_mask(ctx.tr, g)]),
                               "val_used": counts(ctx.va[ctx.group_mask(ctx.va, g)])} for g in CONFIG["groups"]},
            "fph_denominators": old.get("fph_denominators", []),
            "check_runtime_s": old.get("check_runtime_s", {})}
    log("SYN victims (" + ", ".join(f"{r['device']} [{r['group']}] train {r['train']:,} val {r['val']:,}"
                                     for _, r in V.iterrows()) + f"); min rows {need}")

    for k in todo:
        log(f"check {k} ({CHECKS[k]}) ...")
        t = time.monotonic()
        df = RUNNERS[k](ctx)
        write_csv(out / CSV[k], df)
        done["checks"][str(k)] = {"finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                                  "csv": CSV[k], "rows": len(df)}
        done_path.write_text(json.dumps(done, indent=1), encoding="utf-8")
        meta["check_runtime_s"][str(k)] = round(time.monotonic() - t, 1)
        log(f"check {k} ({CHECKS[k]}) done in {time.monotonic() - t:.0f} s -> {rel(out / CSV[k])} ({len(df):,} rows)")
        gc.collect()
    seen = {d["evaluation"]: d for d in meta["fph_denominators"]}
    seen.update({d["evaluation"]: d for d in ctx.hours_log})
    meta["fph_denominators"] = list(seen.values())
    meta["runtime_s"] = round(time.monotonic() - t0, 1)
    meta["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    meta["checks_done"] = sorted(int(k) for k in done["checks"])
    meta_path.write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")
    write_summary(out, meta, inp["families"])
    log(f"ALL DONE in {meta['runtime_s']:.0f} s; checks done {meta['checks_done']} -> {rel(out)}/summary.md")
    lock_fh.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--checks", nargs="+", default=None,
                    help="subset of checks, by number or name: " + ", ".join(f"{k}={v}" for k, v in CHECKS.items()))
    ap.add_argument("--dry-run", action="store_true", help="stratified 5%% subsample of train and val")
    ap.add_argument("--out", type=Path, default=None,
                    help=f"output dir (default {rel(OUT_DEFAULT)}; {rel(OUT_DEFAULT / 'dry_run')} with --dry-run)")
    args = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    try:
        return run(args)
    except SystemExit:
        raise
    except Exception:
        log("UNEXPECTED ERROR\n" + traceback.format_exc())
        return 2


if __name__ == "__main__":
    sys.exit(main())
