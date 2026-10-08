"""
Stage 1 — Known Attack Classification
======================================
Trains every candidate model on the known-attack training set, evaluates
each on the validation set with the full metric suite + resource
profiling, then:

  1. Picks the single best base model architecture (by macro-F1 on val).
  2. Re-fits that architecture under each imbalance-handling strategy
     (class weights only / random oversampling / SMOTE / ADASYN) and
     compares on validation, to choose the final imbalance strategy.
  3. Refits the winning (model, imbalance-strategy) combo on train,
     reports final numbers on the held-out TEST set (touched only once).
  4. Persists the winning model + a full results table (CSV) + JSON
     summary for every model that was tried.

Run
---
    python src/stage1_train.py
"""

import json
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import PROCESSED_DIR, RANDOM_STATE, STAGE1_MODELS_DIR, STAGE1_RESULTS
from stage1_imbalance import get_resamplers
from stage1_models import get_model_zoo
from utils_metrics import ResourceProfiler, classification_metrics, model_size_mb

warnings.filterwarnings("ignore", category=UserWarning)


def log(msg: str) -> None:
    print(msg, flush=True)


def load_split(name: str):
    X = pd.read_csv(PROCESSED_DIR / f"X_{name}.csv")
    y = pd.read_csv(PROCESSED_DIR / f"y_{name}.csv")["Attack_type"].values
    return X, y


def evaluate_model(model, X_train, y_train, X_eval, y_eval, labels, model_name, tag):
    """Fit + evaluate a single model, return a flat result dict + the fitted model."""
    log(f"  [{tag}] Training {model_name} ...")

    with ResourceProfiler() as train_prof:
        model.fit(X_train, y_train)

    with ResourceProfiler() as infer_prof:
        y_pred = model.predict(X_eval)
    n_eval = len(X_eval)
    inference_time_total = infer_prof.elapsed_seconds
    throughput = n_eval / inference_time_total if inference_time_total > 0 else float("inf")

    y_proba = None
    if hasattr(model, "predict_proba"):
        try:
            y_proba = model.predict_proba(X_eval)
        except Exception:
            y_proba = None

    metrics = classification_metrics(y_eval, y_pred, y_proba=y_proba, labels=labels)

    result = {
        "model": model_name,
        "tag": tag,
        **metrics["scalar_metrics"],
        "train_time_seconds": train_prof.elapsed_seconds,
        "inference_time_seconds_total": inference_time_total,
        "inference_time_ms_per_sample": (inference_time_total / n_eval) * 1000,
        "prediction_throughput_per_sec": throughput,
        "peak_ram_train_mb": train_prof.peak_ram_mb,
        "peak_ram_inference_mb": infer_prof.peak_ram_mb,
    }
    return result, model, metrics


def save_confusion_and_per_class(metrics: dict, target_encoder, out_prefix: Path):
    labels = metrics["labels"]
    class_names = [target_encoder.inverse_transform([l])[0] for l in labels]

    cm_df = pd.DataFrame(metrics["confusion_matrix"], index=class_names, columns=class_names)
    cm_df.to_csv(out_prefix.with_name(out_prefix.name + "_confusion_matrix.csv"))

    per_class_df = pd.DataFrame({
        "class": class_names,
        "precision": metrics["per_class"]["precision"],
        "recall": metrics["per_class"]["recall"],
        "f1": metrics["per_class"]["f1"],
    })
    per_class_df.to_csv(out_prefix.with_name(out_prefix.name + "_per_class.csv"), index=False)


def main():
    log("Loading processed data...")
    X_train, y_train = load_split("train")
    X_val, y_val = load_split("val")
    X_test, y_test = load_split("test")
    target_encoder = joblib.load(PROCESSED_DIR / "target_encoder.pkl")
    labels = sorted(np.unique(np.concatenate([y_train, y_val, y_test])))
    log(f"Train: {X_train.shape}  Val: {X_val.shape}  Test: {X_test.shape}  Classes: {len(labels)}")

    # ------------------------------------------------------------
    # PHASE A: all candidate models, base (class-weight-only) training
    # ------------------------------------------------------------
    log("\n" + "=" * 70)
    log("PHASE A -- Evaluating all candidate models on validation set")
    log("=" * 70)

    zoo = get_model_zoo()
    phase_a_results = []
    fitted_models = {}
    metrics_by_model = {}

    for name, model in zoo.items():
        result, fitted, metrics = evaluate_model(
            model, X_train, y_train, X_val, y_val, labels, name, tag="phase_a_base"
        )
        phase_a_results.append(result)
        fitted_models[name] = fitted
        metrics_by_model[name] = metrics
        log(f"    -> val macro-F1={result['f1_macro']:.4f}  "
            f"balanced_acc={result['balanced_accuracy']:.4f}  "
            f"train_time={result['train_time_seconds']:.1f}s")

    phase_a_df = pd.DataFrame(phase_a_results).sort_values("f1_macro", ascending=False)
    phase_a_df.to_csv(STAGE1_RESULTS / "phase_a_model_comparison.csv", index=False)
    log("\nPhase A results saved to results/stage1/phase_a_model_comparison.csv")
    log(phase_a_df[["model", "f1_macro", "balanced_accuracy", "mcc", "train_time_seconds"]]
        .to_string(index=False))

    best_model_name = phase_a_df.iloc[0]["model"]
    log(f"\nBest base model architecture: {best_model_name}")

    for name, metrics in metrics_by_model.items():
        save_confusion_and_per_class(metrics, target_encoder, STAGE1_RESULTS / f"phase_a_{name}")

    # ------------------------------------------------------------
    # PHASE B: imbalance-handling strategies on the winning architecture
    # ------------------------------------------------------------
    log("\n" + "=" * 70)
    log(f"PHASE B -- Imbalance strategies on {best_model_name}")
    log("=" * 70)

    resamplers = get_resamplers()
    phase_b_results = []
    phase_b_models = {}

    for strat_name, sampler in resamplers.items():
        model = get_model_zoo()[best_model_name]  # fresh unfitted instance
        if sampler is None:
            X_res, y_res = X_train, y_train
        else:
            log(f"  Resampling with {strat_name} ...")
            try:
                X_res, y_res = sampler.fit_resample(X_train, y_train)
                log(f"    resampled shape: {X_res.shape}")
            except (RuntimeError, ValueError) as e:
                log(f"    {strat_name} failed on this data ({e}); skipping this strategy.")
                continue

        result, fitted, metrics = evaluate_model(
            model, X_res, y_res, X_val, y_val, labels, best_model_name, tag=f"phase_b_{strat_name}"
        )
        result["imbalance_strategy"] = strat_name
        phase_b_results.append(result)
        phase_b_models[strat_name] = fitted
        log(f"    -> val macro-F1={result['f1_macro']:.4f}")

    phase_b_df = pd.DataFrame(phase_b_results).sort_values("f1_macro", ascending=False)
    phase_b_df.to_csv(STAGE1_RESULTS / "phase_b_imbalance_comparison.csv", index=False)
    log("\nPhase B results saved to results/stage1/phase_b_imbalance_comparison.csv")
    log(phase_b_df[["imbalance_strategy", "f1_macro", "balanced_accuracy", "mcc"]]
        .to_string(index=False))

    best_strategy = phase_b_df.iloc[0]["imbalance_strategy"]
    log(f"\nBest imbalance strategy: {best_strategy}")

    # ------------------------------------------------------------
    # PHASE C: final refit of (best_model, best_strategy) on train,
    #          reported ONCE on the untouched test set.
    # ------------------------------------------------------------
    log("\n" + "=" * 70)
    log(f"PHASE C -- Final model ({best_model_name} + {best_strategy}) on TEST set")
    log("=" * 70)

    final_model = get_model_zoo()[best_model_name]
    sampler = resamplers[best_strategy]
    if sampler is None:
        X_final, y_final = X_train, y_train
    else:
        X_final, y_final = sampler.fit_resample(X_train, y_train)

    final_result, final_model, final_metrics = evaluate_model(
        final_model, X_final, y_final, X_test, y_test, labels,
        best_model_name, tag="final_test"
    )
    final_result["imbalance_strategy"] = best_strategy
    log(f"\nFINAL TEST RESULTS ({best_model_name} + {best_strategy}):")
    for k, v in final_result.items():
        log(f"  {k}: {v}")

    save_confusion_and_per_class(final_metrics, target_encoder, STAGE1_RESULTS / "final_test")

    # ------------------------------------------------------------
    # SAVE FINAL MODEL + METADATA
    # ------------------------------------------------------------
    model_path = STAGE1_MODELS_DIR / f"best_model_{best_model_name}.joblib"
    joblib.dump(final_model, model_path)
    final_result["model_size_mb"] = model_size_mb(model_path)

    with open(STAGE1_RESULTS / "final_test_result.json", "w") as f:
        json.dump(final_result, f, indent=2, default=str)

    with open(STAGE1_MODELS_DIR / "best_model_metadata.json", "w") as f:
        json.dump({
            "model_name": best_model_name,
            "imbalance_strategy": best_strategy,
            "model_path": str(model_path),
            "labels": [int(l) for l in labels],
            "val_f1_macro": float(phase_b_df.iloc[0]["f1_macro"]),
            "test_f1_macro": float(final_result["f1_macro"]),
        }, f, indent=2)

    log(f"\nSaved best model to {model_path}")
    log("\nSTAGE 1 COMPLETE.")


if __name__ == "__main__":
    main()
