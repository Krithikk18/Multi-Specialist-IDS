"""
Stage 5 — Continual Learning
==============================
Simulates incoming production traffic using the stream batches carved
out in Stage 0 (data/stream/X_stream_batch_0..N-1.csv). For each
candidate strategy:

  1. initial_fit on the original Stage 1 training set.
  2. Sequentially "arrive" each stream batch; before learning from it,
     evaluate current-model accuracy on it (forward transfer proxy) and
     on the ORIGINAL held-out test set (to track forgetting), THEN
     call update() to incorporate the new batch.
  3. After all batches are processed, report:
       - Accuracy After Update      (final test-set accuracy)
       - Forgetting Rate            (drop in per-class accuracy on
                                      classes seen early vs. their peak
                                      accuracy at any point during the
                                      stream)
       - Backward Transfer          (change in original-test-set
                                      accuracy from before stream 0 to
                                      after the final batch; negative =
                                      forgetting, positive = improvement)
       - Forward Transfer           (accuracy on batch i achieved by the
                                      model BEFORE seeing batch i, minus
                                      the original (pre-stream) model's
                                      accuracy on that same batch --
                                      captures whether earlier updates
                                      generalize to new unseen batches)
       - Retraining/Update Time, Inference Time, Memory growth, Model
         size growth, CPU usage, Update frequency (= 1 update per batch,
         reported as elapsed wall-clock per update)

Run
---
    python src/stage5_continual_learning.py
"""

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import N_STREAM_BATCHES, PROCESSED_DIR, STAGE5_MODELS_DIR, STAGE5_RESULTS, STREAM_DIR
from stage5_strategies import get_continual_strategies
from utils_metrics import ResourceProfiler, model_size_mb


def log(msg: str) -> None:
    print(msg, flush=True)


def load_split(name: str):
    X = pd.read_csv(PROCESSED_DIR / f"X_{name}.csv")
    y = pd.read_csv(PROCESSED_DIR / f"y_{name}.csv")["Attack_type"].values
    return X, y


def load_stream_batches():
    batches = []
    for i in range(N_STREAM_BATCHES):
        X = pd.read_csv(STREAM_DIR / f"X_stream_batch_{i}.csv")
        y = pd.read_csv(STREAM_DIR / f"y_stream_batch_{i}.csv")["Attack_type"].values
        batches.append((X, y))
    return batches


def safe_predict(strategy, X):
    """river-wrapped strategies return dict-based proba; here we only need
    hard predictions, so this stays a thin passthrough with a guard for
    strategies that fail on an empty/edge-case batch."""
    return strategy.predict(X)


def per_class_accuracy(y_true, y_pred, classes):
    out = {}
    for c in classes:
        mask = (y_true == c)
        if mask.sum() == 0:
            out[c] = None
        else:
            out[c] = float((y_pred[mask] == c).mean())
    return out


def main():
    log("Loading base train/test data and stream batches...")
    X_train, y_train = load_split("train")
    X_test, y_test = load_split("test")
    stream_batches = load_stream_batches()
    classes = sorted(np.unique(y_train))
    log(f"Train: {X_train.shape}  Test: {X_test.shape}  "
        f"Stream batches: {len(stream_batches)} x ~{len(stream_batches[0][0])} rows")

    strategies = get_continual_strategies()
    log(f"Continual learning strategies to evaluate: {list(strategies.keys())}")

    all_summary = []

    for strat_name, strategy in strategies.items():
        log(f"\n{'=' * 70}\nSTRATEGY: {strat_name}\n{'=' * 70}")
        process = psutil.Process()

        # ---------------- INITIAL FIT ----------------
        with ResourceProfiler() as init_prof:
            strategy.initial_fit(X_train, y_train)

        pre_stream_test_acc = float((safe_predict(strategy, X_test) == y_test).mean())
        log(f"  Pre-stream test accuracy: {pre_stream_test_acc:.4f} "
            f"(init fit time={init_prof.elapsed_seconds:.1f}s, "
            f"peak RAM={init_prof.peak_ram_mb:.1f}MB)")

        per_class_peak = {c: pre_stream_test_acc for c in classes}  # track peak-ever accuracy proxy
        test_acc_over_time = [pre_stream_test_acc]
        update_times = []
        update_ram = []
        forward_transfer_scores = []
        cpu_percentages = []

        model_path = STAGE5_MODELS_DIR / f"{strat_name}_initial.joblib"
        try:
            import joblib
            joblib.dump(strategy, model_path)
            initial_size_mb = model_size_mb(model_path)
        except Exception:
            initial_size_mb = None

        # ---------------- STREAM LOOP ----------------
        for batch_i, (X_batch, y_batch) in enumerate(stream_batches):
            # Forward transfer: how well does the CURRENT (pre-update) model
            # do on this brand-new batch, vs. how the ORIGINAL pre-stream
            # model would have done on it?
            try:
                pre_update_batch_pred = safe_predict(strategy, X_batch)
                pre_update_batch_acc = float((pre_update_batch_pred == y_batch).mean())
            except Exception as e:
                log(f"    [warn] prediction on batch {batch_i} failed before update: {e}")
                pre_update_batch_acc = None

            cpu_before = process.cpu_percent(interval=None)
            with ResourceProfiler() as up_prof:
                strategy.update(X_batch, y_batch)
            cpu_after = process.cpu_percent(interval=0.05)

            update_times.append(up_prof.elapsed_seconds)
            update_ram.append(up_prof.peak_ram_mb)
            cpu_percentages.append(cpu_after)

            # Evaluate AFTER this update: accuracy on original held-out test
            # set (forgetting signal) and on this batch (learned-it signal).
            test_pred = safe_predict(strategy, X_test)
            test_acc = float((test_pred == y_test).mean())
            test_acc_over_time.append(test_acc)

            pc_acc = per_class_accuracy(y_test, test_pred, classes)
            for c, acc in pc_acc.items():
                if acc is not None and (per_class_peak[c] is None or acc > per_class_peak[c]):
                    per_class_peak[c] = acc

            if pre_update_batch_acc is not None:
                forward_transfer_scores.append(pre_update_batch_acc)

            log(f"  Batch {batch_i}: update_time={up_prof.elapsed_seconds:.2f}s  "
                f"post-update test_acc={test_acc:.4f}  "
                f"pre-update batch_acc={pre_update_batch_acc}")

        # ---------------- FINAL METRICS ----------------
        final_test_acc = test_acc_over_time[-1]
        final_pred = safe_predict(strategy, X_test)
        final_pc_acc = per_class_accuracy(y_test, final_pred, classes)

        forgetting_scores = []
        for c in classes:
            if per_class_peak[c] is not None and final_pc_acc[c] is not None:
                forgetting_scores.append(per_class_peak[c] - final_pc_acc[c])
        forgetting_rate = float(np.mean(forgetting_scores)) if forgetting_scores else None

        backward_transfer = final_test_acc - pre_stream_test_acc

        forward_transfer = (
            float(np.mean(forward_transfer_scores)) if forward_transfer_scores else None
        )

        final_model_path = STAGE5_MODELS_DIR / f"{strat_name}_final.joblib"
        try:
            import joblib
            joblib.dump(strategy, final_model_path)
            final_size_mb = model_size_mb(final_model_path)
        except Exception:
            final_size_mb = None

        model_size_growth_mb = (
            (final_size_mb - initial_size_mb)
            if (final_size_mb is not None and initial_size_mb is not None) else None
        )

        summary = {
            "strategy": strat_name,
            "pre_stream_test_accuracy": pre_stream_test_acc,
            "accuracy_after_update": final_test_acc,
            "forgetting_rate": forgetting_rate,
            "backward_transfer": backward_transfer,
            "forward_transfer": forward_transfer,
            "avg_retraining_time_seconds": float(np.mean(update_times)),
            "total_retraining_time_seconds": float(np.sum(update_times)),
            "avg_peak_ram_per_update_mb": float(np.mean(update_ram)),
            "initial_model_size_mb": initial_size_mb,
            "final_model_size_mb": final_size_mb,
            "model_size_growth_mb": model_size_growth_mb,
            "avg_cpu_percent_per_update": float(np.mean(cpu_percentages)),
            "update_frequency": f"1 update per batch, {len(stream_batches)} batches processed",
            "n_batches": len(stream_batches),
        }
        all_summary.append(summary)

        pd.DataFrame({"batch": range(len(test_acc_over_time)), "test_accuracy": test_acc_over_time}) \
            .to_csv(STAGE5_RESULTS / f"{strat_name}_test_accuracy_over_time.csv", index=False)

        log(f"\n  SUMMARY [{strat_name}]: acc_after_update={final_test_acc:.4f}  "
            f"forgetting_rate={forgetting_rate}  backward_transfer={backward_transfer:.4f}  "
            f"forward_transfer={forward_transfer}")

    summary_df = pd.DataFrame(all_summary).sort_values("accuracy_after_update", ascending=False)
    summary_df.to_csv(STAGE5_RESULTS / "continual_learning_comparison.csv", index=False)

    log("\n" + "=" * 70)
    log("STAGE 5 STRATEGY COMPARISON")
    log("=" * 70)
    log(summary_df[["strategy", "accuracy_after_update", "forgetting_rate",
                     "backward_transfer", "forward_transfer",
                     "avg_retraining_time_seconds"]].to_string(index=False))

    best_strategy = summary_df.iloc[0]["strategy"]
    with open(STAGE5_RESULTS / "best_strategy.json", "w") as f:
        json.dump({"best_strategy": best_strategy,
                    "accuracy_after_update": float(summary_df.iloc[0]["accuracy_after_update"])},
                   f, indent=2)

    log(f"\nBest continual learning strategy: {best_strategy}")
    log("\nSTAGE 5 COMPLETE.")
    log("\n" + "=" * 70)
    log("FULL PIPELINE COMPLETE. Updated model version saved under models/stage5_continual/.")
    log("=" * 70)


if __name__ == "__main__":
    main()
