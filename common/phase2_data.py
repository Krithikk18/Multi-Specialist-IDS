"""common/phase2_data.py -- the only way Phase 2 reads data. TRAIN and VAL only.

    df = load_split(cfg, "train", columns=[...])        # load_split(cfg, "test") raises TestSplitAccessError

Also the pre-registered training-set rules (docs/V2_PREREG_PHASE2.md section 2) shared by steps 22-26:
  pooled_mask        own-benign + every attack row (specialist / ablation training and val sets)
  class_weights      none | sqrt (primary) | balanced, from a training set's own counts
  stratified_split   seeded per-class split (the 10 % inner early-stopping split of TRAIN)
  stratified_sample  seeded per-stratum sample (dry runs: 5 % of train / val)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from common import schemas as S
from common.phase2_config import expand

ALLOWED_SPLITS = ("train", "val")
_VERIFIED: dict = {}


class TestSplitAccessError(RuntimeError):
    """Phase 2 must never read the test split (docs/V2_PREREG_PHASE2.md section 1)."""


def _refuse_test(split: str, path: Path | None = None) -> None:
    if split not in ALLOWED_SPLITS or (path is not None and "test" in Path(path).name.lower()):
        raise TestSplitAccessError(f"Phase 2 reads train / val only; refused split={split!r} path={path}")


def dataset_dir(cfg: dict) -> Path:
    return expand(cfg["paths"]["datasets_root"]) / cfg["dataset_version"]


def load_dataset_manifest(cfg: dict) -> dict:
    """The dataset version's manifest; must be PASS, the configured version, and carry the current pins."""
    p = dataset_dir(cfg) / "dataset_manifest.json"
    M = json.loads(p.read_text(encoding="utf-8"))
    problems = []
    if M.get("status") != "PASS" or M.get("dry_run"):
        problems.append(f"status {M.get('status')}, dry_run {M.get('dry_run')}")
    if M.get("dataset_version") != cfg["dataset_version"]:
        problems.append(f"version {M.get('dataset_version')} != {cfg['dataset_version']}")
    if M.get("class_map", {}).get("sha256") != S.CLASS_MAP_SHA256:
        problems.append("class_map sha256 differs from the current pin")
    if M.get("features", {}).get("file_sha256") != S.FEATURES_V1_SHA256:
        problems.append("features_v1 sha256 differs from the current pin")
    if problems:
        raise RuntimeError(f"{p}: " + "; ".join(problems))
    M["_sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
    return M


def split_file(cfg: dict, split: str) -> Path:
    _refuse_test(split)
    p = dataset_dir(cfg) / f"{split}.parquet"
    _refuse_test(split, p)
    return p


def verify_split_file(cfg: dict, split: str) -> str:
    """sha256 of the split file == dataset manifest record (once per process); returns it."""
    p = split_file(cfg, split)
    if str(p) not in _VERIFIED:
        want = load_dataset_manifest(cfg)["files"][split]["file_sha256"]
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for b in iter(lambda: fh.read(1 << 20), b""):
                h.update(b)
        if h.hexdigest() != want:
            raise RuntimeError(f"{p}: sha256 {h.hexdigest()} != dataset manifest {want}")
        _VERIFIED[str(p)] = want
    return _VERIFIED[str(p)]


def load_split(cfg: dict, split: str, columns: list[str] | None = None, sample: bool = False,
               verify: bool = True) -> pd.DataFrame:
    """TRAIN or VAL rows (raises TestSplitAccessError for anything else). sample=True: the dry-run stratified
    sample (cfg dry_run.frac / seed, strata = group x label_id). Row order = file order (V1 order)."""
    p = split_file(cfg, split)
    if verify:
        verify_split_file(cfg, split)
    cols = None if columns is None else list(dict.fromkeys(columns))
    df = pq.read_table(p, columns=cols).to_pandas()
    if sample:
        c = cfg["columns"]
        idx = stratified_sample(df[c["group"]].astype(str) + "|" + df[c["label_id"]].astype(str),
                                cfg["dry_run"]["frac"], cfg["dry_run"]["seed"])
        df = df.iloc[idx].reset_index(drop=True)
    return df


def feature_matrix(df: pd.DataFrame, feats: list[str]) -> np.ndarray:
    """float32 matrix of the features in features_v1 order (V1 fed float32 to XGBoost)."""
    return np.ascontiguousarray(df[feats].to_numpy(np.float32))


# --------------------------------------------------------------------------- training-set rules
def pooled_mask(label_id: np.ndarray, benign_subset: np.ndarray, benign_id: int = 0) -> np.ndarray:
    """Rows of a pooled set: benign rows inside benign_subset + every attack row (any group)."""
    label_id = np.asarray(label_id)
    return ((label_id == benign_id) & np.asarray(benign_subset, dtype=bool)) | (label_id != benign_id)


def class_counts(y: np.ndarray, n_classes: int) -> np.ndarray:
    return np.bincount(np.asarray(y, dtype=np.int64), minlength=n_classes)[:n_classes]


def class_weights(counts: np.ndarray, mode: str, benign_id: int = 0) -> np.ndarray:
    """Per-class weight from a training set's own counts.
    none: 1. sqrt (primary): benign 1; attack c: sqrt(n_benign / n_c) if 0 < n_c < n_benign else 1.
    balanced: N / (K_present * n_c) for classes present (sklearn 'balanced'); absent classes 0 rows -> weight 1."""
    counts = np.asarray(counts, dtype=np.float64)
    w = np.ones(len(counts))
    if mode == "none":
        return w
    if mode == "sqrt":
        nb = counts[benign_id]
        for c in range(len(counts)):
            if c != benign_id and 0 < counts[c] < nb:
                w[c] = np.sqrt(nb / counts[c])
        return w
    if mode == "balanced":
        present = counts > 0
        k = int(present.sum())
        w[present] = counts.sum() / (k * counts[present])
        return w
    raise ValueError(f"unknown class weight mode {mode!r}")


def stratified_split(y: np.ndarray, frac: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """(fit_idx, inner_idx), both ascending: per class, round(frac * n_c) seeded-random rows go to inner."""
    y = np.asarray(y)
    rng = np.random.default_rng(seed)
    inner = []
    for c in np.unique(y):
        ix = np.flatnonzero(y == c)
        k = int(round(frac * len(ix)))
        if k:
            inner.append(np.sort(rng.permutation(ix)[:k]))
    inner = np.sort(np.concatenate(inner)) if inner else np.zeros(0, np.int64)
    mask = np.ones(len(y), dtype=bool)
    mask[inner] = False
    return np.flatnonzero(mask), inner


def stratified_sample(strata, frac: float, seed: int) -> np.ndarray:
    """Ascending row positions: per stratum max(1, round(frac * n)) seeded-random rows (every stratum kept)."""
    strata = pd.Series(np.asarray(strata, dtype=object))
    rng = np.random.default_rng(seed)
    out = []
    for _, ix in sorted(strata.groupby(strata, sort=True).indices.items()):
        k = max(1, int(round(frac * len(ix))))
        out.append(np.sort(rng.permutation(ix)[:k]))
    return np.sort(np.concatenate(out)) if out else np.zeros(0, np.int64)


def specialist_groups(groups, fallback: str) -> list[str]:
    """Groups that get a specialist: every group seen in the data except the fallback group (sorted)."""
    return sorted(g for g in set(map(str, groups)) if g != fallback)
