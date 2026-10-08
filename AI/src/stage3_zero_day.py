"""
Stage 3 — Zero-Day Detection
==============================
Anomaly detectors are trained ONLY on known-class training data (one-class
setup: they never see zero-day samples during fit). Evaluation combines:

  - "known"   = low-confidence-routed KNOWN test flows (from Stage 2's
                 test_set_routing.csv, routed_to == "zero_day_detector")
                 -- these are known-class traffic the classifier itself
                 was unsure about, so they're the realistic population
                 this stage actually has to work on in production.
  - "unknown" = the true zero-day holdout (MITM + Fingerprinting),
                 which Stage 1 never saw at all.

This mirrors the intended pipeline: only low-confidence flows enter
Stage 3, and the detector's job is to separate genuinely novel attacks
from known attacks the classifier merely hesitated on.

Binary label convention: 0 = known, 1 = unknown/zero-day.

Run
---
    python src/stage3_zero_day.py
"""

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import PROCESSED_DIR, STAGE2_RESULTS, STAGE3_MODELS_DIR, STAGE3_RESULTS, ZERO_DAY_DIR
from stage3_models import SKLEARN_STYLE_LABEL_MODELS, get_anomaly_zoo
from utils_metrics import ResourceProfiler, binary_metrics, model_size_mb


def log(msg: str) -> None:
    print(msg, flush=True)


def get_scores_and_labels(model, name, X):
    """
    Returns (anomaly_score, binary_pred) where:
      - anomaly_score: higher = more anomalous (so ROC-AUC uses this directly
        against y_true where 1=unknown)
      - binary_pred: 0=known, 1=unknown, derived from the model's native
        {-1, 1} predict() output or (for LOF/OCSVM/etc via sklearn) .predict()
    """
    raw_pred = model.predict(X)  # -1 = outlier(unknown), 1 = inlier(known)
    binary_pred = np.where(raw_pred == -1, 1, 0)

    if hasattr(model, "decision_function"):
        raw_score = model.decision_function(X)  # higher = more normal
        anomaly_score = -raw_score
    elif hasattr(model, "score_samples"):
        raw_score = model.score_samples(X)
        anomaly_score = -raw_score
    else:
        anomaly_score = binary_pred.astype(float)

    return anomaly_score, binary_pred


def main():
    log("Loading data for Stage 3...")
    X_train = pd.read_csv(PROCESSED_DIR / "X_train.csv")  # known-class only, one-class fit

    routing = pd.read_csv(STAGE2_RESULTS / "test_set_routing.csv")
    low_conf_idx = routing.loc[routing["routed_to"] == "zero_day_detector", "row_index"].values
    X_test_full = pd.read_csv(PROCESSED_DIR / "X_test.csv")
    X_known_eval = X_test_full.iloc[low_conf_idx].reset_index(drop=True)
    log(f"Low-confidence KNOWN flows routed into Stage 3: {X_known_eval.shape}")

    X_zero_day = pd.read_csv(ZERO_DAY_DIR / "X_zero_day.csv")
    y_zero_day_raw = pd.read_csv(ZERO_DAY_DIR / "y_zero_day.csv")["Attack_type"]
    log(f"True zero-day holdout flows: {X_zero_day.shape}  ({y_zero_day_raw.value_counts().to_dict()})")

    if len(X_known_eval) == 0:
        log("WARNING: no low-confidence known flows were routed by Stage 2 "
            "(threshold may be too permissive, or Stage 1 is very confident "
            "on this validation run). Falling back to using the full test "
            "set's known flows for the 'known' side of Stage 3 evaluation.")
        X_known_eval = X_test_full

    X_eval = pd.concat([X_known_eval, X_zero_day], axis=0, ignore_index=True)
    y_eval = np.array([0] * len(X_known_eval) + [1] * len(X_zero_day))
    log(f"Stage 3 evaluation set: {X_eval.shape}, known={ (y_eval==0).sum() }, unknown={ (y_eval==1).sum() }")

    # ------------------------------------------------------------
    # TRAIN + EVALUATE EACH ANOMALY DETECTOR
    # ------------------------------------------------------------
    zoo = get_anomaly_zoo()
    all_results = []
    fitted_models = {}

    for name, model in zoo.items():
        log(f"\nTraining {name} on known-class training data ({X_train.shape})...")
        with ResourceProfiler() as train_prof:
            model.fit(X_train)

        with ResourceProfiler() as infer_prof:
            anomaly_score, binary_pred = get_scores_and_labels(model, name, X_eval)
        n_eval = len(X_eval)
        inference_time = infer_prof.elapsed_seconds

        metrics = binary_metrics(y_eval, binary_pred, y_score=anomaly_score)
        result = {
            "model": name,
            **metrics,
            "train_time_seconds": train_prof.elapsed_seconds,
            "inference_time_seconds_total": inference_time,
            "inference_time_ms_per_sample": (inference_time / n_eval) * 1000 if n_eval else None,
            "peak_ram_train_mb": train_prof.peak_ram_mb,
            "peak_ram_inference_mb": infer_prof.peak_ram_mb,
        }
        all_results.append(result)
        fitted_models[name] = model

        model_path = STAGE3_MODELS_DIR / f"{name}.joblib"
        try:
            joblib.dump(model, model_path)
            result["model_size_mb"] = model_size_mb(model_path)
        except Exception as e:
            log(f"  (could not serialize {name} with joblib: {e})")
            result["model_size_mb"] = None

        log(f"  -> detection_rate(recall on unknown)={result['detection_rate']:.4f}  "
            f"FPR={result['false_positive_rate']:.4f}  "
            f"F1={result['f1']:.4f}  "
            f"ROC-AUC={result.get('roc_auc')}")

    results_df = pd.DataFrame(all_results)
    results_df.to_csv(STAGE3_RESULTS / "zero_day_detector_comparison.csv", index=False)
    log("\nStage 3 detector comparison:")
    log(results_df[["model", "detection_rate", "false_positive_rate", "false_negative_rate",
                     "f1", "f2", "roc_auc", "train_time_seconds"]].to_string(index=False))

    # Best = highest F2 (recall-weighted; missing a zero-day is worse than a
    # false alarm in an IDS context) among detectors with valid ROC-AUC.
    best_row = results_df.sort_values("f2", ascending=False).iloc[0]
    best_name = best_row["model"]
    log(f"\nBest zero-day detector (by F2): {best_name}")

    with open(STAGE3_MODELS_DIR / "best_detector_metadata.json", "w") as f:
        json.dump({
            "model_name": best_name,
            "model_path": str(STAGE3_MODELS_DIR / f"{best_name}.joblib"),
            "detection_rate": float(best_row["detection_rate"]),
            "false_positive_rate": float(best_row["false_positive_rate"]),
            "f2": float(best_row["f2"]),
        }, f, indent=2)

    # Save the eval set + best model's per-sample predictions for Stage 4.
    best_model = fitted_models[best_name]
    anomaly_score, binary_pred = get_scores_and_labels(best_model, best_name, X_eval)
    stage3_output = X_eval.copy()
    stage3_output["true_binary_label"] = y_eval  # 0=known, 1=unknown
    stage3_output["predicted_binary_label"] = binary_pred
    stage3_output["anomaly_score"] = anomaly_score
    stage3_output.to_csv(STAGE3_RESULTS / "stage3_predictions_for_stage4.csv", index=False)

    log("\nSTAGE 3 COMPLETE.")


if __name__ == "__main__":
    main()
