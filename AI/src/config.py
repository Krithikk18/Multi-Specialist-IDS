"""
Central configuration for the IDS pipeline.
All paths are resolved relative to the project root so the code
runs the same way on WSL / Linux / any machine, as long as the
folder structure below is preserved.

Project layout expected:

IDS/
  data/
    raw/ML-EdgeIIoT-dataset.csv
    processed/            <- Stage 0 output (train/val/test, known classes only)
    zero_day_holdout/     <- Stage 0 output (MITM + Fingerprinting, held out)
    stream/                <- Stage 5 simulated incoming-data chunks
  models/                 <- persisted trained models (joblib / native formats)
  results/
    stage1/ ... stage5/   <- metrics, tables, plots per stage
  logs/
  src/                    <- all code
"""

from pathlib import Path

# ------------------------------------------------------------------
# PATHS
# ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DATA_PATH = PROJECT_ROOT / "data" / "raw" / "ML-EdgeIIoT-dataset.csv"

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
ZERO_DAY_DIR = PROJECT_ROOT / "data" / "zero_day_holdout"
STREAM_DIR = PROJECT_ROOT / "data" / "stream"

MODELS_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"
LOGS_DIR = PROJECT_ROOT / "logs"

STAGE1_MODELS_DIR = MODELS_DIR / "stage1_known_attack"
STAGE2_MODELS_DIR = MODELS_DIR / "stage2_calibration"
STAGE3_MODELS_DIR = MODELS_DIR / "stage3_zero_day"
STAGE5_MODELS_DIR = MODELS_DIR / "stage5_continual"

STAGE1_RESULTS = RESULTS_DIR / "stage1"
STAGE2_RESULTS = RESULTS_DIR / "stage2"
STAGE3_RESULTS = RESULTS_DIR / "stage3"
STAGE4_RESULTS = RESULTS_DIR / "stage4"
STAGE5_RESULTS = RESULTS_DIR / "stage5"

for d in [
    PROCESSED_DIR, ZERO_DAY_DIR, STREAM_DIR,
    STAGE1_MODELS_DIR, STAGE2_MODELS_DIR, STAGE3_MODELS_DIR, STAGE5_MODELS_DIR,
    STAGE1_RESULTS, STAGE2_RESULTS, STAGE3_RESULTS, STAGE4_RESULTS, STAGE5_RESULTS,
    LOGS_DIR,
]:
    d.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------------
# COLUMNS DROPPED DURING PREPROCESSING (leakage / free-text / identifiers)
# ------------------------------------------------------------------
DROP_COLS = [
    "http.file_data",
    "http.request.uri.query",
    "http.request.method",
    "http.referer",
    "http.request.full_uri",
    "http.request.version",
    "dns.qry.name",
    "mqtt.msg_decoded_as",
    "mqtt.msg",
    "mqtt.protoname",
    "mqtt.topic",
    "frame.time",
    "tcp.options",
    "tcp.payload",
    "Attack_label",  # binary label not needed; multiclass Attack_type is the target
]

TARGET_COL = "Attack_type"

# ------------------------------------------------------------------
# ZERO-DAY SIMULATION
# ------------------------------------------------------------------
# These two classes are removed entirely from Stage 1 training/val/test.
# They are the smallest classes in the dataset and act as genuine
# "never seen before" attacks for Stage 3 (Zero-Day Detection) evaluation.
ZERO_DAY_CLASSES = ["MITM", "Fingerprinting"]

# ------------------------------------------------------------------
# SPLIT / REPRODUCIBILITY
# ------------------------------------------------------------------
RANDOM_STATE = 42
TRAIN_FRAC = 0.70
VAL_FRAC = 0.15
TEST_FRAC = 0.15

# ------------------------------------------------------------------
# STAGE 5 — STREAM SIMULATION
# ------------------------------------------------------------------
# Fraction of the *training* data carved out and hidden from Stage 1,
# then replayed later as sequential "incoming" batches for continual
# learning. Kept separate from train so the base model never sees it
# in its original form.
STREAM_FRAC_OF_TRAIN = 0.15
N_STREAM_BATCHES = 5

# ------------------------------------------------------------------
# CONFIDENCE ROUTING THRESHOLDS (Stage 2 -> Stage 3 routing)
# ------------------------------------------------------------------
HIGH_CONF_THRESHOLD = 0.80   # >= this -> route directly to "Final Known Attack"
LOW_CONF_THRESHOLD = 0.80    # < this  -> route to Zero-Day Detector

N_JOBS = 2  # kept modest by default to avoid OOM on memory-constrained
            # machines when many parallel workers each hold a copy of a
            # large tree ensemble in memory; raise to -1 if you have
            # plenty of RAM (16GB+) for faster training.
