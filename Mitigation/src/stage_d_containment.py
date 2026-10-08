"""
Stage D -- Immediate Containment

Type: deterministic action trigger mapping a high-risk verdict to a
containment action. Calls stage_a_criticality.is_auto_isolation_eligible
as the single choke point before ever issuing an auto-isolate action --
Stage A2's safety-critical devices can never reach this branch, by
construction, not by policy discipline.

Actions: "isolate" (full network isolation), "rate_limit" (throttle,
for medium-confidence high-risk cases), "block_flow" (block only the
offending flow/port, least disruptive of the three high-risk actions).
"""

import json

import numpy as np
import pandas as pd

import config
from stage_a_criticality import build_tier_lookup, classify_device, is_auto_isolation_eligible


ACTION_POLICY = {
    # (risk_band, tier) -> action
    # risk_band in {"high"} only -- Stage D only fires on Stage B's
    # high-risk branch (>= HIGH_RISK_THRESHOLD)
    "safety_critical": "notify_admin_only",   # A2 -- never auto-act
    "privacy_critical": "isolate",
    "convenience": "isolate",
}


def determine_action(tier, risk_score):
    """
    Stage D decision. Safety-critical devices are structurally routed
    to notify_admin_only via ACTION_POLICY and is_auto_isolation_eligible
    is checked as a hard assertion, not a soft preference -- if it ever
    disagrees with ACTION_POLICY for a safety_critical device, that is
    a bug, and this function raises rather than silently isolating.
    """
    eligible = is_auto_isolation_eligible(tier)
    action = ACTION_POLICY[tier]

    if tier == "safety_critical":
        assert not eligible, "structural violation: safety_critical device marked isolation-eligible"
        assert action == "notify_admin_only", "structural violation: safety_critical device has an auto-action policy"
    else:
        assert eligible, f"non-safety-critical tier '{tier}' unexpectedly ineligible for isolation"

    # Within eligible devices, moderate the action by risk magnitude --
    # a flow just over threshold gets a lighter action than an extreme one
    if action == "isolate" and risk_score < config.HIGH_RISK_THRESHOLD + 0.15:
        action = "rate_limit"

    return action


def run_stage_d_evaluation(n_events=3000, seed=config.RANDOM_STATE):
    rng = np.random.RandomState(seed)
    tier_lookup = build_tier_lookup()
    device_names = [n for n, _, _ in config.DEVICE_CATALOG]

    correctness = []
    time_to_containment_ms = []
    containment_success = []

    for _ in range(n_events):
        device = device_names[rng.randint(0, len(device_names))]
        tier = classify_device(device, tier_lookup)
        risk_score = rng.uniform(config.HIGH_RISK_THRESHOLD, 1.0)

        import time
        t0 = time.perf_counter()
        action = determine_action(tier, risk_score)
        t1 = time.perf_counter()
        time_to_containment_ms.append((t1 - t0) * 1000)

        expected = ACTION_POLICY[tier]
        # rate_limit is an acceptable moderation of "isolate" near the
        # threshold boundary; only flag a mismatch if the branch (auto
        # vs. notify-only) itself is wrong
        branch_correct = (
            (action == "notify_admin_only") == (tier == "safety_critical")
        )
        correctness.append(branch_correct)

        # Containment success: simulated -- isolate/rate_limit/block_flow
        # assumed effective with high probability (95%), notify_admin_only
        # has no direct network effect so "success" isn't applicable the
        # same way; scored separately below
        if action != "notify_admin_only":
            containment_success.append(rng.random() < 0.95)

    summary = {
        "n_events": n_events,
        "containment_action_correctness_pct": 100.0 * np.mean(correctness),
        "time_to_containment_ms_mean": float(np.mean(time_to_containment_ms)),
        "time_to_containment_ms_p95": float(np.percentile(time_to_containment_ms, 95)),
        "containment_success_rate_pct": 100.0 * np.mean(containment_success) if containment_success else float("nan"),
        "n_auto_actions": len(containment_success),
        "n_notify_admin_only": n_events - len(containment_success),
    }
    return summary


def main():
    print("=" * 70)
    print("STAGE D -- Immediate Containment")
    print("=" * 70)

    summary = run_stage_d_evaluation()
    for k, v in summary.items():
        print(f"{k}: {v}")

    with open(config.STAGE_D_RESULTS / "stage_d_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {config.STAGE_D_RESULTS}")


if __name__ == "__main__":
    main()
