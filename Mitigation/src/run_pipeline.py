"""
Full Mitigation Engine Pipeline Orchestrator
==============================================
Runs Stage A through Stage E, the gateway<->hub feedback channel
evaluation, the Part-C synthetic stream construction, and the Part-C
mitigation-side cross-engine ablations, in sequence.

Each stage is also fully runnable standalone (python src/stage_X_*.py).

Run
---
    python src/run_pipeline.py
"""

import subprocess
import sys
import time
from pathlib import Path

STAGES = [
    ("Stage 0 - Preprocessing (real Edge-IIoTset)", "stage0_preprocessing.py"),
    ("Stage A - Device Criticality Classifier", "stage_a_criticality.py"),
    ("Stage B - Adaptive Risk Score", "stage_b_risk_score.py"),
    ("Stage C - Context Check", "stage_c_context_check.py"),
    ("Stage D - Immediate Containment", "stage_d_containment.py"),
    ("Stage E - Recovery Loop", "stage_e_recovery.py"),
    ("Feedback Channel - Gateway<->Hub evaluation", "feedback_channel.py"),
    ("Part C - Synthetic Stream Construction", "stage_c_synthetic_streams.py"),
    ("Part C - Cross-Engine Ablations", "cross_engine_ablations.py"),
]


def main():
    src_dir = Path(__file__).resolve().parent
    overall_start = time.perf_counter()

    for title, script in STAGES:
        print("\n" + "#" * 74)
        print(f"# {title}")
        print("#" * 74 + "\n")
        t0 = time.perf_counter()

        result = subprocess.run([sys.executable, str(src_dir / script)])

        elapsed = time.perf_counter() - t0
        if result.returncode != 0:
            print(f"\n[run_pipeline] {title} FAILED after {elapsed:.1f}s "
                  f"(exit code {result.returncode}). Stopping pipeline.")
            sys.exit(result.returncode)
        print(f"\n[run_pipeline] {title} completed in {elapsed:.1f}s")

    total = time.perf_counter() - overall_start
    print("\n" + "#" * 74)
    print(f"# FULL MITIGATION PIPELINE COMPLETE in {total / 60:.1f} minutes")
    print("#" * 74)


if __name__ == "__main__":
    main()
