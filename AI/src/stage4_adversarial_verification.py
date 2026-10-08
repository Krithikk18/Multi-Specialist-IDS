"""
Stage 4 — Adversarial Verification (Lightweight)
==================================================
NOT another IDS. This stage verifies samples that Stage 3 flagged as
zero-day (predicted_binary_label == 1), using two lightweight,
complementary techniques:

  1. TreeSHAP
     Explains the Stage 1 classifier's prediction on the flagged
     sample using exact tree-based SHAP values (fast, exact for tree
     ensembles). A verification heuristic: if the top contributing
     features for a "flagged as unknown" sample look wildly different
     in magnitude/direction from the typical SHAP profile of its
     nearest known class, that supports the zero-day call. We quantify
     this via the cosine distance between the sample's SHAP vector and
     the centroid SHAP vector of its nearest known class (computed on
     a reference sample of the training set).

  2. Input Perturbation
     Small random perturbations (Gaussian noise scaled to each
     feature's training-set std) are applied to the flagged sample.
     If the Stage 1 classifier's predicted class flips easily under
     tiny perturbations, or confidence swings wildly, that instability
     is itself evidence the sample sits in an unfamiliar region of
     feature space -- consistent with genuine novelty rather than a
     borderline-but-known sample.

Both signals are combined into a simple verification decision: a
flagged sample is CONFIRMED zero-day if both signals agree (high SHAP
divergence AND high prediction instability), else it is marked
UNCERTAIN (kept as zero-day per Stage 3, but flagged for human review
in the output) or REJECTED (sent back to the known-class prediction)
if both signals disagree with the zero-day call.

Only triggered flows (Stage 3's predicted_binary_label == 1) are
processed here -- this is intentionally lightweight and NOT run over
the full traffic stream.

Run
---
    python src/stage4_adversarial_verification.py
"""

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (
    PROCESSED_DIR,
    RANDOM_STATE,
    STAGE1_MODELS_DIR,
    STAGE3_RESULTS,
    STAGE4_RESULTS,
)
from utils_metrics import ResourceProfiler


def log(msg: str) -> None:
    print(msg, flush=True)


N_PERTURBATIONS = 20
PERTURBATION_SCALE = 0.15  # fraction of each feature's training std
SHAP_REFERENCE_SAMPLE_SIZE = 500
SHAP_DIVERGENCE_THRESHOLD = 0.5   # cosine distance above this = "diverges from known class"
INSTABILITY_THRESHOLD = 0.3       # fraction of perturbations that flip predicted class


def cosine_distance(a, b):
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 1.0
    return 1.0 - float(np.dot(a, b) / denom)


def main():
    log("Loading Stage 1 model, training reference data, and Stage 3 flagged samples...")
    with open(STAGE1_MODELS_DIR / "best_model_metadata.json") as f:
        stage1_meta = json.load(f)
    model = joblib.load(stage1_meta["model_path"])
    labels = stage1_meta["labels"]

    X_train = pd.read_csv(PROCESSED_DIR / "X_train.csv")
    y_train = pd.read_csv(PROCESSED_DIR / "y_train.csv")["Attack_type"].values
    feature_std = X_train.std(axis=0).replace(0, 1e-6)

    stage3_df = pd.read_csv(STAGE3_RESULTS / "stage3_predictions_for_stage4.csv")
    feature_cols = [c for c in stage3_df.columns if c not in
                    ("true_binary_label", "predicted_binary_label", "anomaly_score")]

    flagged = stage3_df[stage3_df["predicted_binary_label"] == 1].reset_index(drop=True)
    log(f"Samples flagged by Stage 3 as zero-day (entering Stage 4): {len(flagged)}")

    if len(flagged) == 0:
        log("No flagged samples to verify. Writing empty results and exiting.")
        pd.DataFrame(columns=["row_index", "verification_decision"]).to_csv(
            STAGE4_RESULTS / "verification_results.csv", index=False
        )
        return

    # ------------------------------------------------------------
    # BUILD TREESHAP EXPLAINER + REFERENCE CLASS-CENTROID SHAP PROFILES
    # ------------------------------------------------------------
    try:
        import shap
    except ImportError:
        log("shap is not installed. Install with: pip install shap. Aborting Stage 4.")
        return

    log("Building TreeSHAP explainer...")
    explainer = shap.TreeExplainer(model)

    ref_sample_n = min(SHAP_REFERENCE_SAMPLE_SIZE, len(X_train))
    ref_idx = np.random.RandomState(RANDOM_STATE).choice(len(X_train), ref_sample_n, replace=False)
    X_ref = X_train.iloc[ref_idx]
    y_ref = y_train[ref_idx]

    log(f"Computing reference SHAP profiles on {ref_sample_n} training samples "
        f"(per known class centroid)...")
    t0 = time.perf_counter()
    ref_shap = explainer.shap_values(X_ref)
    # shap_values for multiclass tree models: list-of-arrays (older SHAP) or
    # a single 3D array (n_samples, n_features, n_classes) (newer SHAP).
    if isinstance(ref_shap, list):
        ref_shap = np.stack(ref_shap, axis=-1)  # -> (n_samples, n_features, n_classes)
    shap_ref_time = time.perf_counter() - t0

    class_centroids = {}
    for lab in labels:
        mask = (y_ref == lab)
        if mask.sum() == 0:
            continue
        class_idx = labels.index(lab)
        class_centroids[lab] = ref_shap[mask, :, class_idx].mean(axis=0)

    # ------------------------------------------------------------
    # PER-FLAGGED-SAMPLE VERIFICATION
    # ------------------------------------------------------------
    log(f"\nVerifying {len(flagged)} flagged samples (TreeSHAP + perturbation)...")
    results = []
    shap_gen_times = []
    verify_start = time.perf_counter()

    with ResourceProfiler() as verify_prof:
        for i in range(len(flagged)):
            row = flagged.loc[i, feature_cols]
            X_sample = pd.DataFrame([row.values], columns=feature_cols)

            # --- Model's own prediction for this sample ---
            base_pred = model.predict(X_sample)[0]
            base_proba = model.predict_proba(X_sample)[0]
            pred_class_idx = labels.index(base_pred)

            # --- 1. TreeSHAP divergence from nearest known-class centroid ---
            t_shap0 = time.perf_counter()
            sample_shap = explainer.shap_values(X_sample)
            if isinstance(sample_shap, list):
                sample_shap = np.stack(sample_shap, axis=-1)
            shap_gen_times.append(time.perf_counter() - t_shap0)

            sample_vec = sample_shap[0, :, pred_class_idx]
            nearest_class = base_pred
            divergence = cosine_distance(sample_vec, class_centroids.get(nearest_class, sample_vec))
            explanation_length = int(np.sum(np.abs(sample_vec) > 1e-6))  # # of "active" features

            # --- 2. Input perturbation stability ---
            rng = np.random.RandomState(RANDOM_STATE + i)
            noise = rng.normal(
                loc=0.0, scale=PERTURBATION_SCALE * feature_std[feature_cols].values,
                size=(N_PERTURBATIONS, len(feature_cols)),
            )
            perturbed = X_sample.values + noise
            perturbed_df = pd.DataFrame(perturbed, columns=feature_cols)
            perturbed_preds = model.predict(perturbed_df)
            flip_rate = float(np.mean(perturbed_preds != base_pred))

            # --- Combine into verification decision ---
            shap_flags_novel = divergence > SHAP_DIVERGENCE_THRESHOLD
            perturbation_flags_novel = flip_rate > INSTABILITY_THRESHOLD

            if shap_flags_novel and perturbation_flags_novel:
                decision = "CONFIRMED_ZERO_DAY"
            elif not shap_flags_novel and not perturbation_flags_novel:
                decision = "REJECTED_LIKELY_KNOWN"
            else:
                decision = "UNCERTAIN_FLAG_FOR_REVIEW"

            results.append({
                "row_index": i,
                "stage1_predicted_class": int(base_pred),
                "stage1_confidence": float(base_proba.max()),
                "shap_divergence": divergence,
                "explanation_length": explanation_length,
                "perturbation_flip_rate": flip_rate,
                "verification_decision": decision,
                "true_binary_label": int(flagged.loc[i, "true_binary_label"]),
            })

    total_verify_time = verify_prof.elapsed_seconds

    # ------------------------------------------------------------
    # SAVE RESULTS + METRICS
    # ------------------------------------------------------------
    results_df = pd.DataFrame(results)
    results_df.to_csv(STAGE4_RESULTS / "verification_results.csv", index=False)

    # Verification accuracy: does the final decision (kept-as-zero-day vs
    # rejected-back-to-known) match ground truth?
    results_df["final_is_unknown"] = results_df["verification_decision"].isin(
        ["CONFIRMED_ZERO_DAY", "UNCERTAIN_FLAG_FOR_REVIEW"]
    ).astype(int)
    verification_accuracy = float((results_df["final_is_unknown"] == results_df["true_binary_label"]).mean())
    false_verification_rate = float(
        ((results_df["final_is_unknown"] == 0) & (results_df["true_binary_label"] == 1)).mean()
    )  # true zero-days incorrectly rejected back to "known"

    summary = {
        "n_flagged_samples": len(flagged),
        "n_confirmed_zero_day": int((results_df["verification_decision"] == "CONFIRMED_ZERO_DAY").sum()),
        "n_rejected_likely_known": int((results_df["verification_decision"] == "REJECTED_LIKELY_KNOWN").sum()),
        "n_uncertain": int((results_df["verification_decision"] == "UNCERTAIN_FLAG_FOR_REVIEW").sum()),
        "verification_accuracy": verification_accuracy,
        "false_verification_rate": false_verification_rate,
        "verification_latency_seconds_total": total_verify_time,
        "verification_latency_ms_per_sample": (total_verify_time / len(flagged)) * 1000,
        "shap_generation_time_seconds_total": float(np.sum(shap_gen_times)) + shap_ref_time,
        "shap_generation_time_ms_per_sample": float(np.mean(shap_gen_times)) * 1000,
        "average_explanation_length": float(results_df["explanation_length"].mean()),
        "memory_usage_mb": verify_prof.peak_ram_mb,
    }
    with open(STAGE4_RESULTS / "verification_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    log("\nStage 4 verification summary:")
    for k, v in summary.items():
        log(f"  {k}: {v}")

    log("\nSTAGE 4 COMPLETE.")


if __name__ == "__main__":
    main()
