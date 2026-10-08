"""
Shared metric / resource-profiling helpers used by every stage.
Kept in one place so Stage 1, Stage 3, and Stage 5 report numbers the
same way and results are directly comparable.
"""

import os
import time
import tracemalloc
from contextlib import contextmanager

import numpy as np
import psutil
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    cohen_kappa_score,
    confusion_matrix,
    f1_score,
    fbeta_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
)


# ----------------------------------------------------------------------
# RESOURCE PROFILING
# ----------------------------------------------------------------------
class ResourceProfiler:
    """
    Measures wall-clock time and peak RAM (via tracemalloc for Python-side
    allocations, plus RSS delta from psutil which also captures native
    library allocations e.g. inside XGBoost/LightGBM/CatBoost C++ code).
    Use as a context manager:

        with ResourceProfiler() as prof:
            model.fit(X, y)
        prof.elapsed_seconds, prof.peak_ram_mb
    """

    def __enter__(self):
        self.process = psutil.Process(os.getpid())
        self._rss_start = self.process.memory_info().rss
        tracemalloc.start()
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed_seconds = time.perf_counter() - self._t0
        _, peak_traced = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss_end = self.process.memory_info().rss
        # Peak RAM estimate: max of (traced Python allocations, RSS delta),
        # both converted to MB. Native (C++) allocations inside boosting
        # libraries won't show in tracemalloc, so RSS delta is the more
        # reliable number for those models; tracemalloc is more reliable
        # for pure sklearn/numpy models.
        rss_delta_mb = max(rss_end - self._rss_start, 0) / (1024 ** 2)
        traced_mb = peak_traced / (1024 ** 2)
        self.peak_ram_mb = max(rss_delta_mb, traced_mb)
        return False


@contextmanager
def timer():
    t0 = time.perf_counter()
    yield lambda: time.perf_counter() - t0


# ----------------------------------------------------------------------
# CLASSIFICATION METRICS (multiclass, macro-averaged unless noted)
# ----------------------------------------------------------------------
def classification_metrics(y_true, y_pred, y_proba=None, labels=None) -> dict:
    """
    Returns a flat dict of scalar metrics plus a confusion matrix and
    per-class precision/recall/F1 tables. y_proba, if given, should be
    shape (n_samples, n_classes) aligned to `labels` (or sorted unique
    labels if not given) for ROC-AUC / PR-AUC (one-vs-rest, macro).
    """
    if labels is None:
        labels = sorted(np.unique(np.concatenate([y_true, y_pred])))

    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "precision_macro": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "precision_weighted": precision_score(y_true, y_pred, average="weighted", zero_division=0),
        "recall_macro": recall_score(y_true, y_pred, average="macro", zero_division=0),
        "recall_weighted": recall_score(y_true, y_pred, average="weighted", zero_division=0),
        "f1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "f2_macro": fbeta_score(y_true, y_pred, beta=2, average="macro", zero_division=0),
        "f2_weighted": fbeta_score(y_true, y_pred, beta=2, average="weighted", zero_division=0),
        "mcc": matthews_corrcoef(y_true, y_pred),
        "cohen_kappa": cohen_kappa_score(y_true, y_pred),
    }

    if y_proba is not None:
        try:
            metrics["roc_auc_ovr_macro"] = roc_auc_score(
                y_true, y_proba, multi_class="ovr", average="macro", labels=labels
            )
        except ValueError:
            metrics["roc_auc_ovr_macro"] = None
        try:
            y_true_bin = np.zeros((len(y_true), len(labels)))
            for i, lab in enumerate(labels):
                y_true_bin[:, i] = (np.asarray(y_true) == lab).astype(int)
            metrics["pr_auc_macro"] = average_precision_score(y_true_bin, y_proba, average="macro")
        except ValueError:
            metrics["pr_auc_macro"] = None
    else:
        metrics["roc_auc_ovr_macro"] = None
        metrics["pr_auc_macro"] = None

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    per_class_precision = precision_score(y_true, y_pred, average=None, labels=labels, zero_division=0)
    per_class_recall = recall_score(y_true, y_pred, average=None, labels=labels, zero_division=0)
    per_class_f1 = f1_score(y_true, y_pred, average=None, labels=labels, zero_division=0)

    return {
        "scalar_metrics": metrics,
        "confusion_matrix": cm,
        "labels": labels,
        "per_class": {
            "precision": per_class_precision,
            "recall": per_class_recall,
            "f1": per_class_f1,
        },
    }


def binary_metrics(y_true_bin, y_pred_bin, y_score=None) -> dict:
    """For Stage 3 (known=0 / unknown=1 style binary evaluation)."""
    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0.0  # = recall on the "unknown" class
    out = {
        "accuracy": accuracy_score(y_true_bin, y_pred_bin),
        "precision": precision_score(y_true_bin, y_pred_bin, zero_division=0),
        "recall": recall_score(y_true_bin, y_pred_bin, zero_division=0),
        "f1": f1_score(y_true_bin, y_pred_bin, zero_division=0),
        "f2": fbeta_score(y_true_bin, y_pred_bin, beta=2, zero_division=0),
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "detection_rate": detection_rate,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }
    if y_score is not None:
        try:
            out["roc_auc"] = roc_auc_score(y_true_bin, y_score)
        except ValueError:
            out["roc_auc"] = None
        try:
            out["pr_auc"] = average_precision_score(y_true_bin, y_score)
        except ValueError:
            out["pr_auc"] = None
    return out


def model_size_mb(model_path) -> float:
    from pathlib import Path
    p = Path(model_path)
    if p.is_file():
        return p.stat().st_size / (1024 ** 2)
    if p.is_dir():
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / (1024 ** 2)
    return 0.0
