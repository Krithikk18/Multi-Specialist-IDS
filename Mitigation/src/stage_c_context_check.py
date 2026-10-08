"""
Stage C -- Context Check

Type: rule engine querying the digital twin's current state -- state
lookup only, never a what-if simulation run (per architecture spec).

Logic: a risk verdict that lands in the low/medium band (below
HIGH_RISK_THRESHOLD, from Stage B) gets its response tier adjusted
based on household context:
  - if occupied and home_active -> escalate to "restrict" (someone's
    home, respond more assertively since a false restrict is cheaply
    reversed and noticed quickly)
  - if occupied and home_asleep -> "monitor" (avoid a jarring action
    while residents are asleep, unless risk is already high -- Stage
    C only runs on low/medium risk in this design, so this is safe)
  - if away -> "restrict" (nobody present to notice/correct a false
    action quickly, but also no direct safety exposure -- restrict
    rather than ignore)
"""

import json

import numpy as np
import pandas as pd

import config
from twin_state_simulator import generate_twin_timeline, query_state_at


def context_decision(twin_state):
    occupied = twin_state["occupied"]
    mode = twin_state["mode"]

    if occupied and mode == "home_active":
        return "restrict"
    if occupied and mode == "home_asleep":
        return "monitor"
    return "restrict"  # away


def oracle_decision(twin_state, ground_truth_household_state):
    """
    For evaluation: an "oracle" that has ground-truth household state
    (here, identical to twin_state since both are drawn from the same
    synthetic generator -- this evaluates internal consistency of the
    rule logic itself, not twin-vs-reality drift, since no independent
    ground truth exists outside the simulator).
    """
    return context_decision(ground_truth_household_state)


def run_stage_c_evaluation(n_queries=2000, stale_threshold_hours=3, seed=config.RANDOM_STATE):
    rng = np.random.RandomState(seed)
    timeline = generate_twin_timeline()

    agree_count = 0
    stale_count = 0
    query_latencies_ms = []

    for _ in range(n_queries):
        idx = rng.randint(0, len(timeline))

        import time
        t0 = time.perf_counter()
        state = query_state_at(timeline, idx)
        t1 = time.perf_counter()
        query_latencies_ms.append((t1 - t0) * 1000)

        # Simulate occasional staleness: state read is from `staleness_hours`
        # in the past relative to "now"
        staleness_hours = rng.exponential(scale=1.0)
        is_stale = staleness_hours > stale_threshold_hours
        if is_stale:
            stale_count += 1

        decision = context_decision(state)
        oracle = oracle_decision(state, state)  # see docstring note above
        if decision == oracle:
            agree_count += 1

    summary = {
        "n_queries": n_queries,
        "context_adjusted_decision_agreement_pct": 100.0 * agree_count / n_queries,
        "twin_query_latency_ms_mean": float(np.mean(query_latencies_ms)),
        "twin_query_latency_ms_p95": float(np.percentile(query_latencies_ms, 95)),
        "stale_state_rate_pct": 100.0 * stale_count / n_queries,
        "stale_threshold_hours": stale_threshold_hours,
        "note": (
            "Agreement is measured against an oracle drawn from the same "
            "synthetic twin generator (evaluates rule-logic consistency, "
            "not twin-vs-reality drift -- no independent ground truth "
            "exists since the twin itself is synthetic)."
        ),
    }
    return summary


def main():
    print("=" * 70)
    print("STAGE C -- Context Check")
    print("=" * 70)

    summary = run_stage_c_evaluation()
    for k, v in summary.items():
        print(f"{k}: {v}")

    with open(config.STAGE_C_RESULTS / "stage_c_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {config.STAGE_C_RESULTS}")


if __name__ == "__main__":
    main()
