"""
Full IDS Pipeline Orchestrator
================================
Runs Stage 0 through Stage 5 in sequence. Each stage is also fully
runnable standalone (python src/stageN_*.py) since they all read their
inputs from disk (data/, models/, results/) rather than passing objects
in memory -- useful if you want to re-run just one stage after tweaking
it, without re-running everything before it.

Run
---
    python src/run_pipeline.py

    # or run an individual stage, e.g.:
    python src/stage1_train.py
"""

import subprocess
import sys
import time
from pathlib import Path

STAGES = [
    ("Stage 0 - Preprocessing", "stage0_preprocessing.py"),
    ("Stage 1 - Known Attack Classification", "stage1_train.py"),
    ("Stage 2 - Confidence Calibration", "stage2_calibration.py"),
    ("Stage 3 - Zero-Day Detection", "stage3_zero_day.py"),
    ("Stage 4 - Adversarial Verification", "stage4_adversarial_verification.py"),
    ("Stage 5 - Continual Learning", "stage5_continual_learning.py"),
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
    print(f"# FULL PIPELINE COMPLETE in {total / 60:.1f} minutes")
    print("#" * 74)


if __name__ == "__main__":
    main()
