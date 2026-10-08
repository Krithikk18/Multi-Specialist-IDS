# Codebase Audit — AI Inference Engine + Mitigation Engine

> **Read-only audit. Nothing was modified, run, or refactored.**

---

## 1. FILE MAP

### `AI/` — AI Inference Engine

| File / Folder | Description | Status |
|---|---|---|
| [`README.md`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/README.md) | Project documentation, quick start, design decisions | Working |
| [`requirements.txt`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/requirements.txt) | Python dependencies (core + optional) | Working |
| [`results.zip`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/results.zip) | Zipped copy of results dir | Working |
| `data/raw/ML-EdgeIIoT-dataset.csv` | Raw Edge-IIoTset CSV (~82 MB) | Present |
| `data/processed/` | Stage 0 output: X/y train/val/test CSVs + scaler/encoder PKLs + feature_columns.json + class_mapping.json | Working (populated) |
| `data/zero_day_holdout/` | MITM + Fingerprinting held-out data | Working (populated) |
| `data/stream/` | 5 stream batches for Stage 5 | Working (populated) |
| `models/stage1_known_attack/` | Best model (XGBoost) `.joblib` + metadata JSON | Working (populated) |
| `models/stage2_calibration/` | Calibrators (temp scaler, Platt, isotonic) `.pkl` + metadata | Working (dir exists, files unclear — depends on Stage 2 having been run) |
| `models/stage3_zero_day/` | Anomaly detector `.joblib` files + metadata | Working (dir exists) |
| `models/stage5_continual/` | Initial + final strategy `.joblib` files | Working (dir exists) |
| `results/stage1/` | Phase A/B comparison CSVs, final test JSON, confusion matrices, per-class CSVs | Working (populated, 19 real files) |
| `results/stage2/` through `results/stage5/` | Per-stage metric outputs | Working (dirs exist) |
| `logs/` | Empty | Unused |
| [`src/config.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/config.py) | All paths, DROP_COLS, TARGET_COL, split fractions, thresholds, ZERO_DAY_CLASSES | Working |
| [`src/run_pipeline.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/run_pipeline.py) | Orchestrator: runs Stage 0→5 sequentially via subprocess | Working |
| [`src/stage0_preprocessing.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage0_preprocessing.py) | Load raw CSV, clean, encode, stratified split, scale, save | Working |
| [`src/stage1_models.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage1_models.py) | Model zoo: RF, ExtraTrees, DT, LogReg, XGBoost, LightGBM, CatBoost | Working |
| [`src/stage1_imbalance.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage1_imbalance.py) | Resamplers: ClassWeightOnly, RandomOverSampler, SMOTE, ADASYN | Working |
| [`src/stage1_train.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage1_train.py) | 3-phase training: model selection → imbalance → final test eval | Working |
| [`src/stage2_calibration.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage2_calibration.py) | Temperature/Platt/Isotonic calibration + confidence routing | Working |
| [`src/stage3_models.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage3_models.py) | Anomaly detector zoo: IF, LOF, OCSVM, EllipticEnvelope + deep (optional) | Working |
| [`src/stage3_deep_models.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage3_deep_models.py) | PyTorch AE, VAE, DeepSVDD with sklearn-like API | Working (requires torch) |
| [`src/stage3_zero_day.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage3_zero_day.py) | Zero-day detection: one-class fit on known, eval on low-conf + holdout | Working |
| [`src/stage4_adversarial_verification.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage4_adversarial_verification.py) | TreeSHAP + input perturbation verification of flagged zero-day samples | Working (requires shap) |
| [`src/stage5_strategies.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage5_strategies.py) | Continual learning strategies: IncrementalRF, LightGBM warm, XGBoost retrain, ReplayBuffer, river wrappers | Working |
| [`src/stage5_continual_learning.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage5_continual_learning.py) | Stream replay simulation + metrics (forgetting, backward/forward transfer) | Working |
| [`src/utils_metrics.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/utils_metrics.py) | Shared: ResourceProfiler, classification_metrics, binary_metrics, model_size_mb | Working |
| `src/original_reference/preprocessing.py` | User's original preprocessing script (preserved, not used by pipeline) | Unused (reference only) |
| `src/original_reference/inspect_dataset.py` | User's original EDA script | Unused (reference only) |
| `src/catboost_info/` | CatBoost training artifacts auto-generated | Working (auto-created) |
| `src/__pycache__/` | Python bytecode cache | Auto-generated |

### `Mitigation/` — Mitigation Engine

| File / Folder | Description | Status |
|---|---|---|
| [`README.md`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/README.md) | Detailed docs, what's real vs. synthetic, design decisions | Working |
| [`requirements.txt`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/requirements.txt) | Lightweight: pandas, numpy, sklearn, joblib only | Working |
| `data/raw/ML-EdgeIIoT-dataset.csv` | Same raw dataset (~82 MB) | Present |
| `data/processed/` | Stage 0 output (80/20 split, no val set, no zero-day holdout) | Working (populated) |
| `data/synthetic/` | Device tier lookup JSON (Stage A config output) | Working (dir exists) |
| `data/streams/` | Part-C synthetic event stream CSVs | Working (dir exists) |
| `models/stage_b_risk/` | Static + online-adapted risk weights `.pkl` | Working (populated) |
| `results/stage_a/` through `results/cross_engine/` | Per-stage/ablation JSON + CSV metrics | Working (dirs exist) |
| `logs/` | Empty | Unused |
| [`src/config.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/config.py) | Paths, SEVERITY_MAP, DEVICE_CATALOG, risk weights, thresholds, stream params | Working |
| [`src/run_pipeline.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/run_pipeline.py) | Orchestrator: Stage 0 → A → B → C → D → E → feedback → streams → ablations | Working |
| [`src/stage0_preprocessing.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage0_preprocessing.py) | User's original preprocessing (80/20, median impute, all 15 classes) | Working |
| [`src/stage_a_criticality.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_a_criticality.py) | Device tier lookup + Stage A2 structural safety proof | Working |
| [`src/stage_b_risk_score.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_b_risk_score.py) | Weighted risk score: static baseline + online multiplicative-weights adaptation | Working |
| [`src/stage_c_context_check.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_c_context_check.py) | Rule engine querying synthetic twin state | Working |
| [`src/stage_d_containment.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_d_containment.py) | Deterministic action trigger (isolate/rate_limit/notify_admin_only) | Working |
| [`src/stage_e_recovery.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_e_recovery.py) | Post-containment rolling-score monitor, restore vs. escalate | Working |
| [`src/feedback_channel.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/feedback_channel.py) | HMAC-signed, sequence-numbered gateway↔hub message transport | Working |
| [`src/trust_store.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/trust_store.py) | Per-device trust with exponential decay toward neutral prior + passive reward | Working |
| [`src/twin_state_simulator.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/twin_state_simulator.py) | Synthetic household occupancy/time-of-day timeline generator | Working |
| [`src/stage_c_synthetic_streams.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_c_synthetic_streams.py) | Builds repeated-offense + false-escalation-noise event streams | Working |
| [`src/cross_engine_ablations.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/cross_engine_ablations.py) | Closed-loop vs. open-loop trust + static vs. adaptive weighting ablations | Working |
| [`src/inspect_dataset.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/inspect_dataset.py) | Simple EDA script (standalone, not part of pipeline) | Working (standalone utility) |
| `*.Zone.Identifier` files (many) | Windows download-zone markers | Ignorable metadata |

---

## 2. DATA INPUT

### Entry Point
- **AI engine**: CSV file at `data/raw/ML-EdgeIIoT-dataset.csv` (~82 MB). Loaded in [`stage0_preprocessing.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage0_preprocessing.py) lines 71-73.
- **Mitigation engine**: Same CSV at its own `data/raw/`. Loaded in [`stage0_preprocessing.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage0_preprocessing.py) lines 66-76. Also consumes AI engine's `data/processed/` outputs indirectly (Stage B reads `y_test.csv` + `target_encoder.pkl`).
- **No pcap, live interface, API, or streaming source.** Everything is offline CSV.

### Feature Columns (47 total)
Defined at runtime by dropping `DROP_COLS` + `TARGET_COL` from the raw CSV's column list, then saved to [`AI/data/processed/feature_columns.json`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/data/processed/feature_columns.json):

```
ip.src_host, ip.dst_host, arp.dst.proto_ipv4, arp.opcode, arp.hw.size,
arp.src.proto_ipv4, icmp.checksum, icmp.seq_le, icmp.transmit_timestamp,
icmp.unused, http.content_length, http.response, http.tls_port, tcp.ack,
tcp.ack_raw, tcp.checksum, tcp.connection.fin, tcp.connection.rst,
tcp.connection.syn, tcp.connection.synack, tcp.dstport, tcp.flags,
tcp.flags.ack, tcp.len, tcp.seq, tcp.srcport, udp.port, udp.stream,
udp.time_delta, dns.qry.name.len, dns.qry.qu, dns.qry.type,
dns.retransmission, dns.retransmit_request, dns.retransmit_request_in,
mqtt.conack.flags, mqtt.conflag.cleansess, mqtt.conflags, mqtt.hdrflags,
mqtt.len, mqtt.msgtype, mqtt.proto_len, mqtt.topic_len, mqtt.ver,
mbtcp.len, mbtcp.trans_id, mbtcp.unit_id
```

### Columns Dropped (AI engine)
Defined in [`AI/src/config.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/config.py) lines 61-77 (`DROP_COLS`):
`http.file_data`, `http.request.uri.query`, `http.request.method`, `http.referer`, `http.request.full_uri`, `http.request.version`, `dns.qry.name`, `mqtt.msg_decoded_as`, `mqtt.msg`, `mqtt.protoname`, `mqtt.topic`, `frame.time`, `tcp.options`, `tcp.payload`, `Attack_label`

### Label Column
- **Name**: `Attack_type` (defined as `TARGET_COL` in both `config.py` files)
- **AI engine (Stage 1) known classes** (13, from [`class_mapping.json`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/data/processed/class_mapping.json)):
  `Backdoor(0)`, `DDoS_HTTP(1)`, `DDoS_ICMP(2)`, `DDoS_TCP(3)`, `DDoS_UDP(4)`, `Normal(5)`, `Password(6)`, `Port_Scanning(7)`, `Ransomware(8)`, `SQL_injection(9)`, `Uploading(10)`, `Vulnerability_scanner(11)`, `XSS(12)`
- **Zero-day holdout classes** (2): `MITM`, `Fingerprinting`
- **Mitigation engine** uses the original 15 classes (its Stage 0 doesn't hold out zero-day classes)

### Preprocessing Steps

**AI engine** ([`stage0_preprocessing.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage0_preprocessing.py)):
1. Drop `DROP_COLS` at load time (line 72)
2. Deduplicate (line 81)
3. Hold out MITM + Fingerprinting entirely (line 88-91)
4. Replace `inf`/`-inf` → `NaN` (line 107-108)
5. Numeric NaN → `-1`; Categorical NaN → `"Unknown"` (lines 121-125)
6. LabelEncoder per categorical feature column, fit on known+zero-day union (lines 140-146)
7. LabelEncoder on target (known classes only) (line 158)
8. Stratified 70/15/15 train/val/test split (lines 168-180)
9. Carve 15% of train for Stage 5 stream batches (lines 189-194)
10. StandardScaler fit on train_core only, transform all splits (lines 205-209)

**Saved artifacts**: `scaler.pkl`, `target_encoder.pkl`, `feature_encoders.pkl`, `feature_columns.json`, `class_mapping.json` — all in `data/processed/`

**Mitigation engine** ([`stage0_preprocessing.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage0_preprocessing.py)):
- Differs: 80/20 split (no val), median imputation (not -1), no zero-day holdout, no stream carve-out, LabelEncoder fit per-column independently (not on union)
- Saved: `scaler.pkl`, `target_encoder.pkl`, `feature_encoders.pkl`

---

## 3. MODEL

### AI Engine — Stage 1 (Known Attack Classification)
- **Algorithm**: 7 candidates compared: RandomForest, ExtraTrees, DecisionTree, LogisticRegression, XGBoost, LightGBM, CatBoost. Defined in [`stage1_models.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage1_models.py) `get_model_zoo()`.
- **Winner** (from existing results): **XGBoost** (`best_model_XGBoost.joblib`, 8.6 MB)
- **Key hyperparams**: `n_estimators=300`, `max_depth=8` (XGBoost); `max_depth=None` (RF/ET); `class_weight="balanced"` on sklearn models; `auto_class_weights="Balanced"` on CatBoost.
- **Classification**: **Multiclass, 13 classes** (listed above).
- **Imbalance handling**: 4 strategies compared per winning architecture: ClassWeightOnly, RandomOverSampler, SMOTE, ADASYN. Defined in [`stage1_imbalance.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/stage1_imbalance.py).
- **Train/test split**: Stratified random 70/15/15 (train/val/test) with `RANDOM_STATE=42`. **Not** by time or file.
- **Reported metrics**: accuracy, balanced_accuracy, precision/recall/F1/F2 (macro + weighted), MCC, Cohen's kappa, ROC-AUC (OVR macro), PR-AUC (macro), plus per-class precision/recall/F1, confusion matrix. Also: train time, inference time, throughput (samples/sec), peak RAM, model size. Computed in [`utils_metrics.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/utils_metrics.py) `classification_metrics()`.
- **Model save format**: `joblib` (`.joblib`) to `models/stage1_known_attack/best_model_{name}.joblib`.

### AI Engine — Stage 3 (Zero-Day Detection)
- **Algorithms**: IsolationForest, LOF (novelty mode), OneClassSVM, EllipticEnvelope, plus Autoencoder/VAE/DeepSVDD (PyTorch, optional). One-class fit on known-class train only.
- **Classification**: **Binary** (0=known, 1=unknown/zero-day).
- **Best chosen by**: F2 score (recall-weighted).
- **Model save format**: `joblib` to `models/stage3_zero_day/`.

### AI Engine — Stage 5 (Continual Learning)
- **Strategies**: IncrementalRF (warm_start), PeriodicXGBoostRetraining (full retrain), LightGBMWarmStart (fresh refit per window), ReplayBufferWrapper (wraps any base), plus river-based (ARF, HoeffdingTree, OnlineBagging) if `river` installed.
- **Save format**: `joblib` to `models/stage5_continual/`.

### Mitigation Engine — Stage B (Adaptive Risk Score)
- **Algorithm**: Weighted linear sum `Risk = w1*severity + w2*confidence + w3*(1-trust) + w4*frequency` with online multiplicative-weights adaptation.
- **Not a classifier** — produces a continuous risk score, thresholded for escalation.
- **Save format**: `joblib` (weight dicts) to `models/stage_b_risk/`.

---

## 4. AI INFERENCE ENGINE

- **Input format**: **Batch** — entire CSVs loaded via `pd.read_csv()`. No single-row or streaming API.
- **Output format**: Hard class labels from `model.predict()`. Probabilities from `model.predict_proba()` are used internally for calibration routing and metrics (ROC-AUC, PR-AUC) but are **not exposed as an output API**. Stage 4 produces SHAP explanations for flagged samples only.
- **Batch or streaming**: **Batch only.** Stage 5 simulates streaming by replaying pre-carved CSV batches sequentially from disk — no queue, no polling, no micro-batches over a network. Each batch is a full DataFrame loaded and processed at once.
- **Latency/performance measurement**: Yes — [`utils_metrics.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/utils_metrics.py) `ResourceProfiler` measures:
  - Wall-clock train time
  - Wall-clock inference time (total + per-sample ms)
  - Prediction throughput (samples/sec)
  - Peak RAM (tracemalloc + RSS delta)
  - Model size on disk (MB)
  - Stage 4 additionally measures SHAP generation time per sample and verification latency.

---

## 5. MITIGATION ENGINE

### What triggers it
- **Stage B** computes a risk score per event. Events with `risk >= HIGH_RISK_THRESHOLD (0.65)` → Stage D (immediate containment). Events with `risk < LOW_RISK_THRESHOLD (0.35)` → Stage C (monitor/restrict only). Between thresholds → unclear (Stage C's code receives medium-risk events but the exact routing between B→C vs B→D is implicit in the evaluation loops, not an explicit routing module).
- **There is no live connection from the AI engine to the mitigation engine.** Stage B constructs its own synthetic inputs grounded in AI engine metrics.

### What actions it takes
- Defined in [`stage_d_containment.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_d_containment.py) `ACTION_POLICY` + `determine_action()`:
  - `safety_critical` → **`notify_admin_only`** (never auto-acts)
  - `privacy_critical` / `convenience` → **`isolate`** (or `rate_limit` if risk is close to threshold, within +0.15)
- **All actions are simulated.** No iptables, no real network isolation. Containment "success" is drawn from `rng.random() < 0.95` (line 93 of stage_d).
- Stage C context check outputs: `restrict` or `monitor` based on synthetic twin state.

### Automatic or human approval
- **Automatic** for non-safety-critical devices. Safety-critical devices → `notify_admin_only` (requires human). Enforced structurally via `is_auto_isolation_eligible()` with a hard `assert` in Stage D.

### Rollback / unblock / false-positive handling
- **Stage E** is the recovery loop. It monitors post-containment behavior over a 5-event window. Mean rolling anomaly score < 0.5 → **restore** (unblock). Mean ≥ 0.5 → **escalate to admin**. All outcomes are synthetic (simulated post-containment distributions in [`stage_e_recovery.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage_e_recovery.py) `simulate_post_containment_behavior()`).
- Stage E's restore/escalate reward signal feeds back into the trust store and Stage B weight updates.

### How AI inference communicates with mitigation
- **They don't communicate at runtime.** There is no direct function call, REST API, message queue, or file-based IPC between the two engines. The mitigation engine reads the AI engine's *results files* offline (e.g. `y_test.csv`, `target_encoder.pkl`) and uses grounded synthetic proxies for AI engine outputs (confidence, trust).
- The **feedback channel** ([`feedback_channel.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/feedback_channel.py)) models an HMAC-signed, sequence-numbered in-memory message queue (standing in for MQTT). It is **authenticated** (HMAC-SHA256 with a placeholder shared secret key at line 35). It rejects unsigned and replayed messages. But it is evaluated in isolation, not wired to the AI engine.

### What it logs and where
- JSON summaries per stage to `results/stage_a/` through `results/cross_engine/`.
- CSV detailed outputs: risk scores, weight history, regret curves, recovery outcomes, synthetic stream events.
- `logs/` directory exists but is **empty** — no runtime logging beyond stdout prints.

---

## 6. DEVICE AWARENESS

- **The AI engine has zero device awareness.** No IP, MAC, or device-type column is used. Features are protocol-level packet fields. One model classifies everything.
- **The mitigation engine has synthetic device awareness** via [`config.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/config.py) `DEVICE_CATALOG` (12 synthetic smart-home devices, each with a name, protocol hint, and criticality tier). This is **configuration data, not extracted from the dataset.** Edge-IIoTset has no device identity column.
- **No concept of device groups or per-device models.** The AI engine runs one model for all traffic. The mitigation engine has device tiers (safety_critical / privacy_critical / convenience) for action policy, but these affect containment decisions, not model selection.

---

## 7. EDGE-IIOTSET COUPLING

Everything below is hardcoded to Edge-IIoTset and would need to change for a different dataset:

| Item | Location | Details |
|---|---|---|
| Raw file path | Both `config.py` | `ML-EdgeIIoT-dataset.csv` |
| `DROP_COLS` list | [AI config.py L61-77](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/config.py#L61-L77), [Mitigation stage0 L34-54](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/stage0_preprocessing.py#L34-L54) | 16 Edge-IIoTset-specific columns (http.*, dns.*, mqtt.*, tcp.*, frame.time, Attack_label) |
| `TARGET_COL` | Both `config.py` | `"Attack_type"` — Edge-IIoTset's label column name |
| `ZERO_DAY_CLASSES` | [AI config.py L87](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/config.py#L87) | `["MITM", "Fingerprinting"]` — chosen because they're the smallest classes in this specific dataset |
| `SEVERITY_MAP` | [Mitigation config.py L84-100](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/config.py#L84-L100) | Maps all 15 Edge-IIoTset attack class names to severity tiers |
| Feature columns | [`feature_columns.json`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/data/processed/feature_columns.json) | 47 columns all Edge-IIoTset protocol fields (ip.*, arp.*, icmp.*, http.*, tcp.*, udp.*, dns.*, mqtt.*, mbtcp.*) |
| Class mapping | [`class_mapping.json`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/data/processed/class_mapping.json) | 13 Edge-IIoTset attack type names |
| NaN handling rationale | AI `stage0_preprocessing.py` L112-116 | `-1` fill for "absence of a protocol field" — specific to Edge-IIoTset's sparse protocol-field encoding |
| Categorical encoding rationale | AI `stage0_preprocessing.py` L127-136 | LabelEncoder chosen because Edge-IIoTset's `ip.src_host`, `ip.dst_host`, `arp.*proto_ipv4`, `tcp.srcport` are high-cardinality |
| All `y_*` CSV reads | Multiple files | Hardcoded column name `"Attack_type"` in `pd.read_csv(...)[\"Attack_type\"]` |

> [!IMPORTANT]
> **For the smart-home CICFlowMeter migration**: the 47 feature columns are all Edge-IIoTset protocol-level fields (packet header dissections from Wireshark/tshark). CICFlowMeter produces an entirely different feature set (~80 flow-level statistics like `Flow Duration`, `Total Fwd Packets`, `Flow Bytes/s`, etc.). **Zero overlap.** The preprocessing, feature lists, encoders, scalers, and trained models are all incompatible. Only the pipeline structure (stages 0–5) and the metric utilities are reusable.

---

## 8. INTERFACES & CONFIG

### Config Files
- [AI `src/config.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/src/config.py) — paths, splits, thresholds, column lists, N_JOBS
- [Mitigation `src/config.py`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/config.py) — paths, severity map, device catalog, risk weights, stream params
- **No environment variables.** No CLI arguments. No `.env` files. All configuration is Python-module-level constants.

### External Dependencies

**AI engine** ([`requirements.txt`](file:///d:/Projects/Company%20Project/Paper_Implemetation/AI/requirements.txt)):
| Package | Version | Required by | Optional? |
|---|---|---|---|
| pandas | ≥2.0 | All stages | No |
| numpy | ≥1.24 | All stages | No |
| scikit-learn | ≥1.4 | All stages | No |
| joblib | ≥1.3 | Model save/load | No |
| psutil | ≥5.9 | Resource profiling | No |
| xgboost | ≥2.0 | Stage 1 | No (pipeline needs it) |
| lightgbm | ≥4.0 | Stage 1, 5 | Semi (auto-skips) |
| catboost | ≥1.2 | Stage 1 | Yes (auto-skips) |
| imbalanced-learn | ≥0.12 | Stage 1 | No |
| shap | ≥0.45 | Stage 4 | No (Stage 4 aborts without it) |
| torch | ≥2.0 | Stage 3 deep models | Yes (auto-skips) |
| river | ≥0.21 | Stage 5 online | Yes (auto-skips) |

**Mitigation engine** ([`requirements.txt`](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/requirements.txt)):
| Package | Version | Required by |
|---|---|---|
| pandas | ≥2.0 | All |
| numpy | ≥1.24 | All |
| scikit-learn | ≥1.4 | Stage B metrics |
| joblib | ≥1.3 | Weight save/load |

### External Services
- **None.** No databases, dashboards, APIs, MQTT brokers, or external services. Entirely self-contained filesystem-based pipeline.

---

## 9. CURRENT STATE

### What runs end-to-end today

**AI engine Stage 0** has run successfully — processed data, encoders, and splits are populated on disk. Stage 1 has also run successfully — XGBoost selected as winner, model + metrics saved.

```bash
cd AI
python src/run_pipeline.py          # full pipeline (Stages 0-5)
python src/stage0_preprocessing.py  # or individual stages
python src/stage1_train.py
# ... etc
```

```bash
cd Mitigation
python src/run_pipeline.py          # full pipeline (Stage 0 → ablations)
```

**Stages 2-5 (AI)** and **Stages A-E + ablations (Mitigation)**: the code is complete and appears structurally correct from reading, but whether they have been run to completion on the full dataset on this machine is **unclear** — Stage 2+ output directories exist but their contents weren't checked exhaustively. The README documents that Stage 1 was OOM-killed partway through on a 4GB-RAM machine, so later stages may not have completed on constrained hardware.

### What is half-built, broken, or TODO

- **Dirichlet calibration** (Stage 2): explicitly not implemented. A placeholder row with `None` values is inserted in the comparison table. Documented.
- **SVM and KNN** (Stage 1): intentionally excluded (too slow). Documented.
- **No live inference path.** There is no server, API, or listener. No way to classify a single incoming flow in real-time.
- **No connection between AI and Mitigation engines.** They are two independent pipelines sharing a raw CSV. The mitigation engine synthesizes AI engine outputs from AI engine *result files* — not a live feed.
- **Mitigation actions are 100% simulated.** No iptables calls, no network control. The `isolate`/`rate_limit`/`block_flow` actions are string labels in a DataFrame.
- **Feedback channel** is an in-memory queue, not MQTT. The HMAC signing and sequence checking are real code; the transport is a placeholder.
- **Trust store secret key** is a placeholder constant: `b"REPLACE_WITH_PROVISIONED_HUB_KEY_AT_DEPLOYMENT"` ([feedback_channel.py L35](file:///d:/Projects/Company%20Project/Paper_Implemetation/Mitigation/src/feedback_channel.py#L35)).

### Known bugs / limitations

- **8 GB+ RAM required** for full AI pipeline (300-tree ensembles × 7 models × ~90k rows). Documented in README. `N_JOBS=2` by default to mitigate.
- **LightGBM warm-start instability** was found and fixed. The `init_model` continuation approach was abandoned in favor of fresh refit per window. Documented in both READMEs and code docstrings.
- **Trust model decay-to-zero bug** for benign devices was found and fixed. Decay now relaxes toward a neutral prior (0.5), not toward 0. Documented.
- **Online weight collapse bug** (Stage B multiplicative weights converging to ~100% severity) was found and fixed. Contributions are now un-weighted before comparing shares, with a hard floor (`min_weight_floor=0.05`). Documented.
- **Mitigation Stage 0 differs from AI Stage 0**: 80/20 vs 70/15/15 split, median imputation vs -1, includes MITM/Fingerprinting, no stream carve-out. This means the two preprocessed datasets are **not interchangeable** — the mitigation engine's Stage B reads from its own `data/processed/`, which has a different target encoding (15 classes vs 13).
