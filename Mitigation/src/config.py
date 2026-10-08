"""
Central configuration for the Mitigation Engine (P10, home hub).
All paths resolved relative to project root, same pattern as the
AI Inference Engine's config.py.

Project layout:

Mitigation/
  data/
    raw/ML-EdgeIIoT-dataset.csv     <- same source file as the AI engine
    processed/                       <- Stage 0 output (features/labels, train/test)
    synthetic/                       <- device inventory, severity map, twin-state
                                         generator, config files (NOT learned --
                                         see README for what's real vs. synthetic)
    streams/                         <- Part-C synthetic event streams for the
                                         closed-loop / adaptive-weighting ablations
  models/
    stage_b_risk/                    <- persisted risk-score weights (static + online)
  results/
    stage_a/ ... stage_e/            <- per-stage metrics
    cross_engine/                    <- Part C ablation results
  src/
  logs/

IMPORTANT — read before treating any result here as empirical:
Stages A, C, D operate over a synthetic device inventory and synthetic
digital-twin state, because Edge-IIoTset (a static network-flow capture)
contains none of that information. Stage B's severity input is REAL,
derived deterministically from Edge-IIoTset's Attack_type column. Stage
E's outcomes and the Part-C event streams are synthetic, constructed per
an explicit, documented method (see stage_c_synthetic_streams.py and the
README) so results are reproducible and clearly labeled -- not fabricated
silently. This mirrors the "controlled synthetic simulation study"
labeling specified in the implementation spec.
"""

from pathlib import Path

# ------------------------------------------------------------------
# PATHS
# ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DATA_PATH = PROJECT_ROOT / "data" / "raw" / "ML-EdgeIIoT-dataset.csv"

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
SYNTHETIC_DIR = PROJECT_ROOT / "data" / "synthetic"
STREAMS_DIR = PROJECT_ROOT / "data" / "streams"

MODELS_DIR = PROJECT_ROOT / "models"
STAGE_B_MODELS_DIR = MODELS_DIR / "stage_b_risk"

RESULTS_DIR = PROJECT_ROOT / "results"
STAGE_A_RESULTS = RESULTS_DIR / "stage_a"
STAGE_B_RESULTS = RESULTS_DIR / "stage_b"
STAGE_C_RESULTS = RESULTS_DIR / "stage_c"
STAGE_D_RESULTS = RESULTS_DIR / "stage_d"
STAGE_E_RESULTS = RESULTS_DIR / "stage_e"
CROSS_ENGINE_RESULTS = RESULTS_DIR / "cross_engine"

LOGS_DIR = PROJECT_ROOT / "logs"

for d in [
    PROCESSED_DIR, SYNTHETIC_DIR, STREAMS_DIR,
    STAGE_B_MODELS_DIR,
    STAGE_A_RESULTS, STAGE_B_RESULTS, STAGE_C_RESULTS,
    STAGE_D_RESULTS, STAGE_E_RESULTS, CROSS_ENGINE_RESULTS,
    LOGS_DIR,
]:
    d.mkdir(parents=True, exist_ok=True)

TARGET_COL = "Attack_type"
RANDOM_STATE = 42

# ------------------------------------------------------------------
# STAGE B -- SEVERITY MAPPING (derived from real Attack_type labels)
# ------------------------------------------------------------------
# Justification for each tier:
#   Critical -- destructive or covert full-control compromise
#   High     -- active data compromise / credential theft / code injection
#   Medium   -- availability disruption (denial of service family)
#   Low      -- reconnaissance / precursor activity, no direct damage
#   None     -- benign traffic
SEVERITY_MAP = {
    "Ransomware":            "Critical",
    "Backdoor":               "Critical",
    "MITM":                   "Critical",
    "SQL_injection":          "High",
    "XSS":                     "High",
    "Uploading":               "High",
    "Password":                "High",
    "DDoS_TCP":                "Medium",
    "DDoS_UDP":                "Medium",
    "DDoS_ICMP":               "Medium",
    "DDoS_HTTP":               "Medium",
    "Port_Scanning":           "Low",
    "Vulnerability_scanner":   "Low",
    "Fingerprinting":          "Low",
    "Normal":                  "None",
}

SEVERITY_SCORE = {
    "Critical": 1.00,
    "High":     0.75,
    "Medium":   0.50,
    "Low":      0.25,
    "None":     0.00,
}

# ------------------------------------------------------------------
# STAGE A -- DEVICE CRITICALITY TIERS (synthetic config, stated as such)
# ------------------------------------------------------------------
# Edge-IIoTset has no device-identity or device-type column usable for
# a smart-home inventory, so this catalog is a stated design artifact --
# a plausible smart-home device mix built from the protocols actually
# present in the dataset (MQTT, Modbus/mbtcp, HTTP, DNS), each assigned
# a tier. This is config data (per the implementation spec, Stage A is
# "configuration lookup, not a trained model"), not something learned
# or claimed to be extracted from the dataset.
DEVICE_CATALOG = [
    # name, protocol_hint, criticality_tier
    ("smart_door_lock",       "mqtt",  "safety_critical"),
    ("gas_leak_sensor",       "mqtt",  "safety_critical"),
    ("smoke_alarm",           "mqtt",  "safety_critical"),
    ("security_camera",       "http",  "privacy_critical"),
    ("baby_monitor",          "http",  "privacy_critical"),
    ("voice_assistant_hub",   "mqtt",  "privacy_critical"),
    ("smart_thermostat",      "mbtcp", "convenience"),
    ("smart_plug",            "mqtt",  "convenience"),
    ("smart_bulb",            "mqtt",  "convenience"),
    ("robot_vacuum",          "mqtt",  "convenience"),
    ("smart_tv",              "http",  "convenience"),
    ("weather_station",       "mqtt",  "convenience"),
]

CRITICALITY_TIERS = ["safety_critical", "privacy_critical", "convenience"]

# tier a device falls back to if its type isn't in the catalog --
# fail toward caution, not toward convenience (per the spec)
DEFAULT_UNKNOWN_TIER = "safety_critical"

# ------------------------------------------------------------------
# STAGE C -- DIGITAL TWIN STATE SIMULATION (synthetic, stated as such)
# ------------------------------------------------------------------
# No twin exists; this generates a plausible household occupancy /
# time-of-day state stream so Stage C has something real to query
# against. Seeded for reproducibility.
TWIN_SIM_RANDOM_STATE = 7
TWIN_SIM_DAYS = 14

# ------------------------------------------------------------------
# STAGE B -- ADAPTIVE RISK SCORE
# ------------------------------------------------------------------
# Risk(d,e) = w1*severity + w2*confidence + w3*(1-trust) + w4*frequency
RISK_WEIGHT_INIT = {
    "severity":  0.35,
    "confidence": 0.25,
    "distrust":  0.25,
    "frequency": 0.15,
}
RISK_WEIGHT_LR = 0.05          # multiplicative-weights update learning rate
RISK_WEIGHT_MAX_DRIFT = 0.10   # per-update cap on any single weight's change

HIGH_RISK_THRESHOLD = 0.65     # Risk >= this -> Stage D immediate containment
LOW_RISK_THRESHOLD = 0.35      # Risk <  this -> Stage C monitor/restrict only

# ------------------------------------------------------------------
# STAGE E -- RECOVERY LOOP
# ------------------------------------------------------------------
RECOVERY_MONITOR_WINDOW_EVENTS = 5   # events observed post-containment
                                       # before a restore/escalate decision
RECOVERY_REOFFEND_THRESHOLD = 0.5    # rolling anomaly score above this
                                       # during monitoring -> re-offended

# ------------------------------------------------------------------
# PART C -- SYNTHETIC EVENT STREAM CONSTRUCTION
# ------------------------------------------------------------------
# See stage_c_synthetic_streams.py docstring for the full method.
# This is a controlled synthetic simulation study, not empirical
# longitudinal data -- Edge-IIoTset has no persistent per-device
# behavioral trace. Explicitly labeled per the implementation spec.
STREAM_N_DEVICES = 40
STREAM_N_TIMELINE_EVENTS_PER_DEVICE = 25
STREAM_INTER_EVENT_MEAN_SECONDS = 1800   # 30 min mean re-probe interval;
                                           # chosen for tractable simulation
                                           # length, stated explicitly, not
                                           # claimed empirical
STREAM_RANDOM_STATE = 11

# False-escalation noise fraction for the Stage B/E ablation stream --
# grounded against Part A's ACTUAL measured false-positive rate, not
# picked arbitrarily.
#
# Derivation (see AI engine results/stage3/zero_day_detector_comparison.csv
# and results/stage2/routing_summary.json):
#   - Stage 3's best detector by F2 (selection rule) is the Autoencoder,
#     measured false_positive_rate = 0.01262 on known-benign traffic
#     that reached it.
#   - Only ~8.33% of all traffic is routed to Stage 3 at all (the rest
#     is high-confidence and never reaches this path); false positives
#     from Stage 3 are therefore a fraction of a fraction of total flow.
#   - We use the Stage-3-local FPR (0.01262) directly as the noise
#     fraction for flows THAT REACH Stage B via the suspicious path,
#     since that is the relevant conditional rate for this ablation
#     (Stage B only ever sees flows that already passed through
#     Stage 3/4 flagging, not the full unconditioned traffic mix).
FALSE_ESCALATION_NOISE_FRACTION = 0.01262
