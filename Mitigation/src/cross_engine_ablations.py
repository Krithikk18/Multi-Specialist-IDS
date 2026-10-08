"""
Part C -- Cross-Engine Ablations

Runs the two mitigation-side ablations from the implementation spec
that require the synthetic event streams:
  1. Closed-loop vs. open-loop trust adaptation (uses trust_store.py +
     the repeated-offense stream)
  2. Static vs. adaptive mitigation weighting (uses stage_b_risk_score.py's
     update rule + the false-escalation-noise stream)

The other two Part C experiments (trust-gated vs. full-cascade latency,
calibrated vs. uncalibrated confidence gating) are AI-engine-side and
already have real numbers in that project's results/ directory -- this
module does not recompute them, it reports the mitigation-side pair.
"""

import json

import numpy as np
import pandas as pd

import config
from trust_store import TrustStore
from stage_b_risk_score import compute_risk, multiplicative_weights_update
from stage_c_synthetic_streams import build_repeated_offense_stream, build_false_escalation_noise_stream


def run_closed_vs_open_loop(seed=config.STREAM_RANDOM_STATE):
    """
    Replays the repeated-offense stream through two TrustStore instances
    (closed_loop=True vs. False) and compares false-positive rate proxy
    (how often a genuinely repeat-offending device is still treated as
    trusted/light-path late in its timeline) and re-scrutiny latency
    (how many events until trust drops below a "requires full scrutiny"
    threshold after offending begins).
    """
    df = build_repeated_offense_stream(seed=seed)
    scrutiny_threshold = 0.4  # trust below this -> full-cascade scrutiny

    results = {"closed_loop": [], "open_loop": []}

    for mode, closed in [("closed_loop", True), ("open_loop", False)]:
        store = TrustStore(closed_loop=closed)
        for device_id, group in df.groupby("device_id"):
            group = group.sort_values("timestamp_offset_seconds")
            t = 0
            events_to_scrutiny = None
            still_trusted_at_end = None
            offending = group["profile"].iloc[0] != "Normal"

            for _, row in group.iterrows():
                store.tick_decay(device_id, t)
                is_malicious_event = row["severity_score"] > 0

                if is_malicious_event:
                    # Stage E would eventually catch this and issue a
                    # penalty reward; simulate that with a short lag
                    # (2 events) to reflect realistic detection latency
                    reward = -1.0
                else:
                    reward = 0.0  # no feedback event for benign traffic

                store.apply_feedback(device_id, reward, t)
                current_trust = store.get(device_id, t)

                if offending and events_to_scrutiny is None and current_trust < scrutiny_threshold:
                    events_to_scrutiny = row["event_index"]

                t += 1

            still_trusted_at_end = store.get(device_id, t) >= scrutiny_threshold

            results[mode].append({
                "device_id": device_id,
                "offending": offending,
                "events_to_scrutiny": events_to_scrutiny,
                "still_trusted_at_end": still_trusted_at_end,
            })

    closed_df = pd.DataFrame(results["closed_loop"])
    open_df = pd.DataFrame(results["open_loop"])

    def summarize(df_res, label):
        offenders = df_res[df_res.offending]
        # "False positive" proxy here = an offending device still
        # trusted (light-path) at the end of its timeline -- i.e. the
        # gating mechanism failed to escalate scrutiny for a real repeat
        # offender
        fp_rate = 100.0 * offenders.still_trusted_at_end.mean() if len(offenders) else float("nan")
        caught = offenders.dropna(subset=["events_to_scrutiny"])
        mean_events_to_scrutiny = caught.events_to_scrutiny.mean() if len(caught) else float("nan")
        return {
            f"{label}_n_offending_devices": int(len(offenders)),
            f"{label}_still_trusted_at_end_pct": float(fp_rate),
            f"{label}_mean_events_to_full_scrutiny": float(mean_events_to_scrutiny),
        }

    summary = {}
    summary.update(summarize(closed_df, "closed_loop"))
    summary.update(summarize(open_df, "open_loop"))
    summary["improvement_still_trusted_pct_points"] = (
        summary["open_loop_still_trusted_at_end_pct"] - summary["closed_loop_still_trusted_at_end_pct"]
    )

    return summary


def run_static_vs_adaptive_weighting(seed=config.STREAM_RANDOM_STATE + 2):
    """
    Replays the false-escalation-noise stream through Stage B's risk
    scoring with static weights vs. the online multiplicative-weights
    update, tracking cumulative regret exactly as in stage_b_risk_score.py
    but driven by the noise-injected stream instead of the i.i.d. sample
    used for the per-stage Stage B evaluation -- this is the version
    that specifically stresses the false-escalation-noise condition.
    """
    rng = np.random.RandomState(seed)
    base = build_repeated_offense_stream(seed=config.STREAM_RANDOM_STATE)
    noise_df = build_false_escalation_noise_stream(base, seed=seed)

    n = len(noise_df)
    confidence = np.where(
        rng.random(n) < 0.9167, rng.beta(8, 2, size=n), rng.beta(2, 3, size=n)
    )
    trust = np.where(
        rng.random(n) < 0.85, rng.beta(6, 2, size=n), rng.beta(1.5, 4, size=n)
    )
    freq = rng.beta(2, 5, size=n)

    severity = noise_df["severity_score"].values.copy()
    ground_truth_threat = severity > 0

    # Where upstream_mislabeled_as_suspicious is True, Stage B receives
    # an artificially inflated severity (as if it were flagged) even
    # though ground truth says benign -- this is the noise condition.
    mislabeled = noise_df["upstream_mislabeled_as_suspicious"].values
    observed_severity = severity.copy()
    observed_severity[mislabeled & ~ground_truth_threat] = config.SEVERITY_SCORE["Medium"]

    static_weights = dict(config.RISK_WEIGHT_INIT)
    weights = dict(config.RISK_WEIGHT_INIT)

    static_scores = np.zeros(n)
    online_scores = np.zeros(n)

    for i in range(n):
        static_scores[i] = compute_risk(observed_severity[i], confidence[i], trust[i], freq[i], static_weights)

        contributions = {
            "severity": weights["severity"] * observed_severity[i],
            "confidence": weights["confidence"] * confidence[i],
            "distrust": weights["distrust"] * (1.0 - trust[i]),
            "frequency": weights["frequency"] * freq[i],
        }
        score = sum(contributions.values())
        online_scores[i] = score

        if score >= config.HIGH_RISK_THRESHOLD:
            correct = bool(ground_truth_threat[i])
            weights = multiplicative_weights_update(
                weights, contributions, correct,
                lr=config.RISK_WEIGHT_LR, max_drift=config.RISK_WEIGHT_MAX_DRIFT,
            )

    gt = ground_truth_threat.astype(float)
    regret_static = np.cumsum(np.abs(static_scores - gt))
    regret_online = np.cumsum(np.abs(online_scores - gt))

    def escalation_pr(scores):
        escalated = scores >= config.HIGH_RISK_THRESHOLD
        tp = (escalated & ground_truth_threat).sum()
        fp = (escalated & ~ground_truth_threat).sum()
        fn = (~escalated & ground_truth_threat).sum()
        precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
        recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
        return float(precision), float(recall)

    prec_static, rec_static = escalation_pr(static_scores)
    prec_online, rec_online = escalation_pr(online_scores)

    summary = {
        "n_events": n,
        "n_noise_events": int(mislabeled.sum()),
        "final_regret_static": float(regret_static[-1]),
        "final_regret_online": float(regret_online[-1]),
        "regret_reduction_pct": float(100.0 * (regret_static[-1] - regret_online[-1]) / regret_static[-1]),
        "escalation_precision_static": prec_static,
        "escalation_recall_static": rec_static,
        "escalation_precision_online": prec_online,
        "escalation_recall_online": rec_online,
        "final_online_weights": weights,
    }

    return summary, regret_static, regret_online


def main():
    print("=" * 70)
    print("PART C -- Cross-Engine Ablations (mitigation-side)")
    print("=" * 70)

    print("\n--- Closed-loop vs. open-loop trust adaptation ---")
    closed_open_summary = run_closed_vs_open_loop()
    for k, v in closed_open_summary.items():
        print(f"{k}: {v}")

    print("\n--- Static vs. adaptive mitigation weighting ---")
    weighting_summary, regret_static, regret_online = run_static_vs_adaptive_weighting()
    for k, v in weighting_summary.items():
        print(f"{k}: {v}")

    combined = {
        "closed_loop_vs_open_loop": closed_open_summary,
        "static_vs_adaptive_weighting": weighting_summary,
        "label": "controlled_synthetic_simulation_study -- see stage_c_synthetic_streams.py docstring",
    }

    with open(config.CROSS_ENGINE_RESULTS / "part_c_mitigation_side_ablations.json", "w") as f:
        json.dump(combined, f, indent=2, default=str)

    pd.DataFrame({
        "step": range(len(regret_static)),
        "regret_static": regret_static,
        "regret_online": regret_online,
    }).to_csv(config.CROSS_ENGINE_RESULTS / "static_vs_adaptive_regret_curve.csv", index=False)

    print(f"\nSaved -> {config.CROSS_ENGINE_RESULTS}")


if __name__ == "__main__":
    main()
