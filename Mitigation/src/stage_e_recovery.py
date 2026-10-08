"""
Stage E -- Recovery Loop

Type: sequential post-action monitor, evaluated as a monitoring/decision
process over a window, not a single-shot classifier.

Model: a rolling anomaly score over RECOVERY_MONITOR_WINDOW_EVENTS
post-containment events; if the rolling score stays below
RECOVERY_REOFFEND_THRESHOLD for the full window -> restore; otherwise
-> escalate to admin. This module's output is exactly the
reward/penalty signal specified for the Stage 0 <-> Stage E feedback
channel (see feedback_channel.py) and the Stage B weight update.
"""

import json

import numpy as np
import pandas as pd

import config


def simulate_post_containment_behavior(was_genuinely_malicious, rng):
    """
    Simulates a device's rolling anomaly score during the monitoring
    window. Genuinely malicious devices re-offend (score stays elevated)
    with high probability; falsely-escalated (actually benign) devices
    settle quickly. Not a real network signal -- a controlled synthetic
    model of the *shape* of the outcome distribution, stated as such.
    """
    window = config.RECOVERY_MONITOR_WINDOW_EVENTS
    if was_genuinely_malicious:
        # 75% chance of clear re-offense, 25% chance it goes quiet
        # (attacker paused, or containment was actually effective)
        reoffends = rng.random() < 0.75
        if reoffends:
            return rng.uniform(0.6, 0.95, size=window)
        else:
            return rng.uniform(0.05, 0.3, size=window)
    else:
        # False escalation: settles quickly, small chance of noisy
        # false re-trigger (5%)
        noisy = rng.random() < 0.05
        if noisy:
            return rng.uniform(0.4, 0.7, size=window)
        return rng.uniform(0.0, 0.25, size=window)


def recovery_decision(rolling_scores):
    mean_score = float(np.mean(rolling_scores))
    reoffended = mean_score >= config.RECOVERY_REOFFEND_THRESHOLD
    decision = "escalate" if reoffended else "restore"
    return decision, mean_score


def run_stage_e_evaluation(n_contained_devices=2000, seed=config.RANDOM_STATE):
    rng = np.random.RandomState(seed)

    # Ground truth: was the original containment action actually
    # justified (genuine threat) or a false escalation from Stage B?
    # Matches Stage B's escalation-precision rate roughly, drawn fresh
    # here for an independently-seeded evaluation set.
    was_genuine = rng.random(n_contained_devices) < 0.7  # ~70% justified, consistent with Stage B's expected precision range

    false_restore = 0     # restored but was actually genuine (re-offended after restore -- worst case)
    false_escalation = 0  # escalated but was actually benign
    correct_restore = 0
    correct_escalation = 0
    oscillations = 0
    time_to_recovery_events = []

    trust_updates = []  # for downstream trust-trajectory correlation check

    for i in range(n_contained_devices):
        genuine = was_genuine[i]
        scores = simulate_post_containment_behavior(genuine, rng)
        decision, mean_score = recovery_decision(scores)

        if decision == "restore":
            if genuine:
                false_restore += 1
                reward = -1.0  # premature recovery of a real threat -- penalize trust
            else:
                correct_restore += 1
                reward = +1.0  # correctly cleared a false alarm -- restore trust
            time_to_recovery_events.append(config.RECOVERY_MONITOR_WINDOW_EVENTS)
        else:  # escalate
            if genuine:
                correct_escalation += 1
                reward = -1.0  # confirmed threat -- lower trust further
            else:
                false_escalation += 1
                reward = -0.25  # false escalation -- mild trust penalty (annoyance cost, not a real event)

        # Oscillation: simple proxy -- a device that gets a NEGATIVE
        # reward but was decided "restore" is flagged as a likely future
        # oscillation candidate (will probably be re-flagged soon)
        if decision == "restore" and reward < 0:
            oscillations += 1

        trust_updates.append({
            "device_idx": i,
            "genuine_threat": bool(genuine),
            "decision": decision,
            "mean_rolling_score": mean_score,
            "reward": reward,
        })

    n = n_contained_devices
    summary = {
        "n_contained_devices": n,
        "false_restore_rate_pct": 100.0 * false_restore / n,
        "false_escalation_to_admin_rate_pct": 100.0 * false_escalation / n,
        "oscillation_rate_pct": 100.0 * oscillations / n,
        "mean_time_to_recovery_events": float(np.mean(time_to_recovery_events)) if time_to_recovery_events else float("nan"),
        "correct_restore_count": correct_restore,
        "correct_escalation_count": correct_escalation,
        "note": (
            "Ground-truth genuineness and post-containment behavior are "
            "both synthetic (see module docstring) -- results describe "
            "recovery-logic behavior under a stated outcome-distribution "
            "model, not empirically observed device behavior."
        ),
    }

    return summary, pd.DataFrame(trust_updates)


def main():
    print("=" * 70)
    print("STAGE E -- Recovery Loop")
    print("=" * 70)

    summary, trust_updates_df = run_stage_e_evaluation()
    for k, v in summary.items():
        print(f"{k}: {v}")

    with open(config.STAGE_E_RESULTS / "stage_e_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    trust_updates_df.to_csv(config.STAGE_E_RESULTS / "stage_e_outcomes.csv", index=False)

    # This outcomes file is exactly what feedback_channel.py consumes
    # to drive Stage 0's trust store and Stage B's weight update.
    print(f"\nSaved -> {config.STAGE_E_RESULTS}")


if __name__ == "__main__":
    main()
