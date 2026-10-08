"""
Stage 2 — Probability / Confidence Calibration
================================================
Spec restricts this to "tree-ensemble-native methods only" -- i.e. no
Dirichlet calibration or generic Platt/Isotonic wrappers around
non-tree models. In practice this means:

  - Temperature Scaling      (works on any model's logits/probabilities;
                               included because it's the simplest and
                               cheapest native option for boosted trees)
  - Platt Scaling             (sklearn CalibratedClassifierCV, method="sigmoid",
                               applied on top of the already-fitted tree model
                               via cv="prefit"-style refit on validation)
  - Isotonic Regression       (CalibratedClassifierCV, method="isotonic")

Dirichlet calibration is skipped: it is a full generalization of Platt
scaling to the multiclass simplex and is normally implemented via a
dedicated library (e.g. `dirichletcal`) which is not part of the
sklearn/tree-ensemble stack this project standardizes on; noted here
rather than silently omitted.

All three methods are fit on the VALIDATION set (never test) and
compared using calibration-quality metrics. The best is applied to
produce final calibrated probabilities, which then drive the
confidence-based routing (Stage 2 -> Stage 3 handoff).

Run
---
    python src/stage2_calibration.py
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss, log_loss

try:
    # sklearn >= 1.6: cv="prefit" was removed in favor of wrapping the
    # already-fitted estimator in FrozenEstimator.
    from sklearn.frozen import FrozenEstimator
    _HAS_FROZEN_ESTIMATOR = True
except ImportError:
    _HAS_FROZEN_ESTIMATOR = False


def make_prefit_calibrator(base_model, method: str) -> CalibratedClassifierCV:
    """Builds a CalibratedClassifierCV around an ALREADY-FITTED base_model,
    compatible with both old (cv='prefit') and new (FrozenEstimator) sklearn."""
    if _HAS_FROZEN_ESTIMATOR:
        return CalibratedClassifierCV(FrozenEstimator(base_model), method=method)
    return CalibratedClassifierCV(base_model, method=method, cv="prefit")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (
    HIGH_CONF_THRESHOLD,
    PROCESSED_DIR,
    STAGE1_MODELS_DIR,
    STAGE2_MODELS_DIR,
    STAGE2_RESULTS,
)


def log(msg: str) -> None:
    print(msg, flush=True)


def load_split(name: str):
    X = pd.read_csv(PROCESSED_DIR / f"X_{name}.csv")
    y = pd.read_csv(PROCESSED_DIR / f"y_{name}.csv")["Attack_type"].values
    return X, y


# ----------------------------------------------------------------------
# TEMPERATURE SCALING (multiclass, fit via simple 1-D search on val NLL)
# ----------------------------------------------------------------------
class TemperatureScaler:
    """
    Multiclass temperature scaling. Takes the model's predicted
    probabilities, converts to logits (log of prob), divides by a
    learned scalar T, and re-softmaxes. T > 1 softens (reduces)
    over-confidence, T < 1 sharpens.
    """

    def __init__(self):
        self.temperature = 1.0

    @staticmethod
    def _to_logits(proba, eps=1e-12):
        p = np.clip(proba, eps, 1 - eps)
        return np.log(p)

    @staticmethod
    def _softmax(logits):
        z = logits - logits.max(axis=1, keepdims=True)
        e = np.exp(z)
        return e / e.sum(axis=1, keepdims=True)

    def fit(self, proba_val, y_val, labels):
        logits = self._to_logits(proba_val)
        label_to_idx = {lab: i for i, lab in enumerate(labels)}
        y_idx = np.array([label_to_idx[y] for y in y_val])

        best_T, best_nll = 1.0, np.inf
        for T in np.arange(0.25, 5.01, 0.05):
            scaled = self._softmax(logits / T)
            nll = log_loss(y_idx, scaled, labels=list(range(len(labels))))
            if nll < best_nll:
                best_nll, best_T = nll, T
        self.temperature = best_T
        return self

    def transform(self, proba):
        logits = self._to_logits(proba)
        return self._softmax(logits / self.temperature)


# ----------------------------------------------------------------------
# CALIBRATION QUALITY METRICS
# ----------------------------------------------------------------------
def expected_calibration_error(y_true_idx, proba, n_bins=15):
    """ECE over the model's top-1 (max) predicted probability."""
    confidences = proba.max(axis=1)
    predictions = proba.argmax(axis=1)
    accuracies = (predictions == y_true_idx).astype(float)

    bin_edges = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    bin_records = []
    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        mask = (confidences > lo) & (confidences <= hi) if i > 0 else (confidences >= lo) & (confidences <= hi)
        if mask.sum() == 0:
            bin_records.append({"bin_lo": lo, "bin_hi": hi, "count": 0, "avg_conf": None, "avg_acc": None})
            continue
        avg_conf = confidences[mask].mean()
        avg_acc = accuracies[mask].mean()
        weight = mask.sum() / len(confidences)
        ece += weight * abs(avg_conf - avg_acc)
        bin_records.append({
            "bin_lo": lo, "bin_hi": hi, "count": int(mask.sum()),
            "avg_conf": float(avg_conf), "avg_acc": float(avg_acc),
        })
    return ece, bin_records


def max_calibration_error(bin_records):
    gaps = [abs(b["avg_conf"] - b["avg_acc"]) for b in bin_records if b["count"] > 0]
    return max(gaps) if gaps else 0.0


def multiclass_brier_score(y_true_idx, proba, n_classes):
    y_onehot = np.zeros((len(y_true_idx), n_classes))
    y_onehot[np.arange(len(y_true_idx)), y_true_idx] = 1
    return np.mean(np.sum((proba - y_onehot) ** 2, axis=1))


def evaluate_calibration(name, proba, y_true_idx, n_classes):
    ece, bins = expected_calibration_error(y_true_idx, proba)
    mce = max_calibration_error(bins)
    brier = multiclass_brier_score(y_true_idx, proba, n_classes)
    nll = log_loss(y_true_idx, proba, labels=list(range(n_classes)))
    confidences = proba.max(axis=1)
    return {
        "method": name,
        "ece": ece,
        "mce": mce,
        "brier_score": brier,
        "nll": nll,
        "mean_confidence": float(confidences.mean()),
        "pct_high_confidence": float((confidences >= HIGH_CONF_THRESHOLD).mean() * 100),
    }, bins, confidences


def main():
    log("Loading validation + test data and Stage 1 model...")
    X_val, y_val = load_split("val")
    X_test, y_test = load_split("test")

    with open(STAGE1_MODELS_DIR / "best_model_metadata.json") as f:
        stage1_meta = json.load(f)
    model_path = stage1_meta["model_path"]
    labels = stage1_meta["labels"]
    label_to_idx = {lab: i for i, lab in enumerate(labels)}

    base_model = joblib.load(model_path)
    log(f"Loaded base model: {stage1_meta['model_name']} from {model_path}")

    raw_proba_val = base_model.predict_proba(X_val)
    raw_proba_test = base_model.predict_proba(X_test)
    y_val_idx = np.array([label_to_idx[y] for y in y_val])
    y_test_idx = np.array([label_to_idx[y] for y in y_test])
    n_classes = len(labels)

    # ------------------------------------------------------------
    # BASELINE (uncalibrated)
    # ------------------------------------------------------------
    log("\nEvaluating uncalibrated (baseline) probabilities on TEST set...")
    all_results = []
    baseline_result, baseline_bins, _ = evaluate_calibration("Uncalibrated", raw_proba_test, y_test_idx, n_classes)
    all_results.append(baseline_result)
    log(f"  {baseline_result}")

    calibrated_test_probas = {"Uncalibrated": raw_proba_test}

    # ------------------------------------------------------------
    # TEMPERATURE SCALING (fit on val, apply to test)
    # ------------------------------------------------------------
    log("\nFitting Temperature Scaling on validation set...")
    temp_scaler = TemperatureScaler().fit(raw_proba_val, y_val, labels)
    log(f"  Learned temperature T = {temp_scaler.temperature:.3f}")
    temp_test_proba = temp_scaler.transform(raw_proba_test)
    temp_result, temp_bins, _ = evaluate_calibration("TemperatureScaling", temp_test_proba, y_test_idx, n_classes)
    all_results.append(temp_result)
    calibrated_test_probas["TemperatureScaling"] = temp_test_proba
    log(f"  {temp_result}")
    joblib.dump(temp_scaler, STAGE2_MODELS_DIR / "temperature_scaler.pkl")

    # ------------------------------------------------------------
    # PLATT SCALING (sigmoid) -- CalibratedClassifierCV with prefit base
    # ------------------------------------------------------------
    log("\nFitting Platt Scaling (sigmoid) on validation set...")
    platt = make_prefit_calibrator(base_model, method="sigmoid")
    platt.fit(X_val, y_val)
    platt_test_proba = platt.predict_proba(X_test)
    platt_result, platt_bins, _ = evaluate_calibration("PlattScaling", platt_test_proba, y_test_idx, n_classes)
    all_results.append(platt_result)
    calibrated_test_probas["PlattScaling"] = platt_test_proba
    log(f"  {platt_result}")
    joblib.dump(platt, STAGE2_MODELS_DIR / "platt_calibrator.pkl")

    # ------------------------------------------------------------
    # ISOTONIC REGRESSION -- CalibratedClassifierCV with prefit base
    # ------------------------------------------------------------
    log("\nFitting Isotonic Regression on validation set...")
    isotonic = make_prefit_calibrator(base_model, method="isotonic")
    isotonic.fit(X_val, y_val)
    isotonic_test_proba = isotonic.predict_proba(X_test)
    isotonic_result, isotonic_bins, _ = evaluate_calibration("IsotonicRegression", isotonic_test_proba, y_test_idx, n_classes)
    all_results.append(isotonic_result)
    calibrated_test_probas["IsotonicRegression"] = isotonic_test_proba
    log(f"  {isotonic_result}")
    joblib.dump(isotonic, STAGE2_MODELS_DIR / "isotonic_calibrator.pkl")

    # ------------------------------------------------------------
    # DIRICHLET CALIBRATION -- explicitly noted as not implemented
    # ------------------------------------------------------------
    all_results.append({
        "method": "DirichletCalibration",
        "ece": None, "mce": None, "brier_score": None, "nll": None,
        "mean_confidence": None, "pct_high_confidence": None,
        "note": "Not implemented: requires a dedicated library (e.g. dirichletcal) "
                "outside the tree-ensemble/sklearn stack this project standardizes on.",
    })

    # ------------------------------------------------------------
    # COMPARE + PICK BEST (lowest ECE on test)
    # ------------------------------------------------------------
    results_df = pd.DataFrame(all_results)
    results_df.to_csv(STAGE2_RESULTS / "calibration_comparison.csv", index=False)
    log("\nCalibration comparison (lower ECE/MCE/Brier/NLL = better):")
    log(results_df.to_string(index=False))

    scored = results_df.dropna(subset=["ece"])
    best_method = scored.sort_values("ece").iloc[0]["method"]
    log(f"\nBest calibration method (lowest ECE): {best_method}")

    best_test_proba = calibrated_test_probas[best_method]

    # ------------------------------------------------------------
    # RELIABILITY DIAGRAM + CONFIDENCE HISTOGRAM DATA (saved as CSV,
    # since we cannot use notebooks -- plotting is left to the user via
    # any plotting tool of choice, but the underlying binned data that a
    # reliability diagram is built from is fully computed and saved here)
    # ------------------------------------------------------------
    _, best_bins = expected_calibration_error(y_test_idx, best_test_proba)
    pd.DataFrame(best_bins).to_csv(STAGE2_RESULTS / "reliability_diagram_data.csv", index=False)

    conf_hist, edges = np.histogram(best_test_proba.max(axis=1), bins=20, range=(0, 1))
    pd.DataFrame({"bin_left": edges[:-1], "bin_right": edges[1:], "count": conf_hist}).to_csv(
        STAGE2_RESULTS / "confidence_histogram_data.csv", index=False
    )

    # ------------------------------------------------------------
    # CONFIDENCE-BASED ROUTING
    # ------------------------------------------------------------
    log(f"\nApplying confidence routing at threshold={HIGH_CONF_THRESHOLD} ...")
    confidences = best_test_proba.max(axis=1)
    predictions_idx = best_test_proba.argmax(axis=1)
    high_conf_mask = confidences >= HIGH_CONF_THRESHOLD
    low_conf_mask = ~high_conf_mask

    routing_summary = {
        "threshold": HIGH_CONF_THRESHOLD,
        "n_total": int(len(confidences)),
        "n_high_confidence": int(high_conf_mask.sum()),
        "n_low_confidence": int(low_conf_mask.sum()),
        "pct_high_confidence": float(high_conf_mask.mean() * 100),
        "pct_low_confidence": float(low_conf_mask.mean() * 100),
        "best_calibration_method": best_method,
    }
    with open(STAGE2_RESULTS / "routing_summary.json", "w") as f:
        json.dump(routing_summary, f, indent=2)
    log(f"  {routing_summary}")

    # Save routed test-set outputs for Stage 3 to consume directly.
    routing_df = pd.DataFrame({
        "row_index": np.arange(len(y_test)),
        "true_label": y_test,
        "predicted_label_idx": predictions_idx,
        "confidence": confidences,
        "routed_to": np.where(high_conf_mask, "known_final", "zero_day_detector"),
    })
    routing_df.to_csv(STAGE2_RESULTS / "test_set_routing.csv", index=False)

    with open(STAGE2_MODELS_DIR / "calibration_metadata.json", "w") as f:
        json.dump({
            "best_method": best_method,
            "high_conf_threshold": HIGH_CONF_THRESHOLD,
            "labels": labels,
        }, f, indent=2)

    log("\nSTAGE 2 COMPLETE.")


if __name__ == "__main__":
    main()
