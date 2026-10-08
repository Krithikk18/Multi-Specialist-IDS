"""
Stage A -- Device Criticality Classifier (+ Stage A2 manual-mode fallback)

Type: configuration lookup, NOT a trained model (per the implementation
spec). This module implements the lookup, the structural safety-critical
branch (Stage A2 -- unreachable from auto-isolation by construction), and
the two Stage-A metrics: tier assignment coverage and a misclassification
audit-rate proxy.

Because Edge-IIoTset carries no device-identity/type column, devices for
evaluation are drawn from the synthetic DEVICE_CATALOG in config.py --
stated explicitly as config data, not learned or extracted from the
dataset. See config.py's module docstring.
"""

import json
import random

import config


def build_tier_lookup():
    """dict: device_name -> criticality_tier, from the config catalog."""
    return {name: tier for name, _, tier in config.DEVICE_CATALOG}


def classify_device(device_name, tier_lookup):
    """
    Stage A decision. Falls back to DEFAULT_UNKNOWN_TIER (safety_critical)
    for any device type not in the catalog -- fail toward caution, never
    toward convenience, per the spec.
    """
    return tier_lookup.get(device_name, config.DEFAULT_UNKNOWN_TIER)


def is_auto_isolation_eligible(tier):
    """
    Stage A2 structural constraint: safety_critical devices have NO path
    to auto-isolation. This function is the single choke point Stage D
    must call before ever issuing an auto-isolate action -- it is not a
    policy check that could be skipped, it is the only way Stage D is
    allowed to decide eligibility.
    """
    return tier != "safety_critical"


def run_stage_a_evaluation(n_unknown_device_probes=50, seed=config.RANDOM_STATE):
    """
    Evaluates:
      - tier assignment coverage: % of catalog devices with a tier
        (always 100% by construction here, reported for completeness
        and as a template for when the catalog grows)
      - misclassification audit rate proxy: simulates admin overrides
        by probing devices NOT in the catalog and confirming every one
        of them falls back to safety_critical (never silently defaults
        to convenience), since that is the property that actually
        matters for Stage A2 to hold
    """
    rng = random.Random(seed)
    tier_lookup = build_tier_lookup()

    coverage = sum(1 for _, _, t in config.DEVICE_CATALOG if t in config.CRITICALITY_TIERS)
    coverage_pct = 100.0 * coverage / len(config.DEVICE_CATALOG)

    # Probe unknown device names -> must ALWAYS resolve to safety_critical
    unknown_names = [f"unregistered_device_{i}" for i in range(n_unknown_device_probes)]
    fallback_correct = sum(
        1 for name in unknown_names
        if classify_device(name, tier_lookup) == config.DEFAULT_UNKNOWN_TIER
    )
    fallback_correct_pct = 100.0 * fallback_correct / len(unknown_names)

    # Stage A2 structural proof: verify the isolation-eligibility function
    # returns False for every safety_critical device in the catalog, and
    # only for those -- this is checked programmatically as a design
    # proof, not sampled as a runtime statistic (per the spec).
    safety_critical_devices = [n for n, _, t in config.DEVICE_CATALOG if t == "safety_critical"]
    non_safety_devices = [n for n, _, t in config.DEVICE_CATALOG if t != "safety_critical"]

    structural_proof_holds = (
        all(not is_auto_isolation_eligible(tier_lookup[n]) for n in safety_critical_devices)
        and all(is_auto_isolation_eligible(tier_lookup[n]) for n in non_safety_devices)
    )

    summary = {
        "n_catalog_devices": len(config.DEVICE_CATALOG),
        "tier_assignment_coverage_pct": coverage_pct,
        "unknown_device_probes": len(unknown_names),
        "unknown_device_fallback_correct_pct": fallback_correct_pct,
        "safety_critical_device_count": len(safety_critical_devices),
        "stage_a2_structural_proof_holds": structural_proof_holds,
        "note": (
            "stage_a2_structural_proof_holds is a design proof (verified "
            "by exhaustive check over the catalog), not a sampled runtime "
            "statistic -- per the implementation spec's treatment of the "
            "zero-auto-action guarantee."
        ),
    }
    return summary


def main():
    print("=" * 70)
    print("STAGE A -- Device Criticality Classifier")
    print("=" * 70)

    summary = run_stage_a_evaluation()
    for k, v in summary.items():
        print(f"{k}: {v}")

    out_path = config.STAGE_A_RESULTS / "stage_a_summary.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {out_path}")

    # Also persist the tier lookup itself, since Stages B/C/D read it
    lookup_path = config.SYNTHETIC_DIR / "device_tier_lookup.json"
    with open(lookup_path, "w") as f:
        json.dump(build_tier_lookup(), f, indent=2)
    print(f"Saved -> {lookup_path}")


if __name__ == "__main__":
    main()
