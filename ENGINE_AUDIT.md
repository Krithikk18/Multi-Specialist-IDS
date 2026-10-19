# ENGINE_AUDIT — AI Inference Engine + Mitigation Engine (Edge-IIoTset)

Read-only audit. Nothing was modified, run, trained or installed. Findings come from reading the code in `AI/src/`, `Mitigation/src/`, their metadata JSONs, results files and artifact sizes on disk. Anything I could not confirm is marked **UNSURE**.

(`codebase_audit.md` in this folder is an earlier audit. This file was done from the code independently and goes further on I/O contracts, Edge-IIoTset hard-coding, Pi suitability and glue.)

---

## 0. Headline findings

1. **Neither engine is an inference service.** There is no `predict(flow) -> alert` function, no server, no CLI that takes a flow, and no streaming loop. Every stage is a batch script (`python src/stageN_*.py`) that reads CSVs from disk, evaluates on a held-out test split and writes CSV/JSON. "Inference" only exists as `model.predict(X_csv)` calls inside evaluation scripts.
2. **The glue is files on disk.** `AI/src/run_pipeline.py` runs the stage scripts in order with `subprocess.run`. Stage 2→3 passes `test_set_routing.csv` (row indices) and Stage 3→4 passes `stage3_predictions_for_stage4.csv`. Nothing is passed in memory, and no router decides at runtime where a live flow goes.
3. **The AI engine and the Mitigation engine are not connected.** `Mitigation/` never imports or loads anything from `AI/`. Its inputs (confidence, trust, frequency, outcomes) are simulated from distributions whose parameters were copied by hand from AI-engine results (91.67 %/8.33 % routing split, 3.90 % error rate, 1.262 % FPR). Only the severity map and `Attack_type` labels come from real data.
4. **The Mitigation engine takes no real actions.** `isolate`, `rate_limit`, `notify_admin_only` and `block_flow` are returned as Python strings. There is no iptables/nftables, router/AP/SDN API, MQTT client, socket, HTTP server or queue anywhere in `Mitigation/src` (grep confirmed). "Containment success" is `rng.random() < 0.95`.
5. **Absolute paths are baked into artifact metadata.** `best_model_metadata.json` stores `"/home/laasya/AI/models/stage1_known_attack/best_model_XGBoost.joblib"`, and `best_detector_metadata.json` stores the same style of path for the Autoencoder. Stage 2 and Stage 4 load the model through that path, so they fail on any other machine/layout unless the metadata is regenerated.
6. **One artifact is corrupt/empty.** `models/stage3_zero_day/VariationalAutoencoder.joblib` is 2 bytes. The VAE was scored in the comparison CSV, but its saved file is unusable.
7. **Models were trained elsewhere.** Metadata points to a WSL home dir (`/home/laasya/`). This machine has Python 3.13.7, scikit-learn 1.7.2, xgboost 3.1.2, torch 2.7.1, numpy 2.3.3 and pandas 2.3.2, with **no** shap, lightgbm, imblearn, catboost or river. The versions used to create the `.joblib`/`.pkl` files are not recorded: **UNSURE**. Pickles from sklearn, xgboost and torch are version-sensitive.

---

## 1. Data / feature contract (shared by all AI stages)

| Item | Value | Where |
|---|---|---|
| Raw input | `data/raw/ML-EdgeIIoT-dataset.csv` (~82 MB) | `AI/src/config.py:29` |
| Dropped columns | 15 (`http.*`, `dns.qry.name`, `mqtt.msg*`, `mqtt.topic`, `frame.time`, `tcp.options`, `tcp.payload`, `Attack_label`) | `config.py:61-77` |
| Target | `Attack_type`, 15 classes in the raw data; 13 known after the zero-day holdout | `config.py:79` |
| Zero-day classes | `MITM`, `Fingerprinting`, removed entirely from Stage 1 training | `config.py:87` |
| Features | **47**, in `data/processed/feature_columns.json`, all hard-coded Wireshark/tshark field names (`ip.src_host`, `tcp.srcport`, `mqtt.len`, `mbtcp.trans_id`, …) | `feature_columns.json` |
| Preprocessing | dedupe; ±inf→NaN; numeric NaN→−1; categorical NaN→"Unknown"; **LabelEncoder per categorical column** (fit on known+zero-day union); StandardScaler fit on train core only | `stage0_preprocessing.py` |
| Split | stratified 70/15/15, then 15 % of train carved off as the Stage 5 stream (5 batches), `RANDOM_STATE=42` | `config.py:92-105` |
| Class map | Backdoor 0, DDoS_HTTP 1, DDoS_ICMP 2, DDoS_TCP 3, DDoS_UDP 4, Normal 5, Password 6, Port_Scanning 7, Ransomware 8, SQL_injection 9, Uploading 10, Vulnerability_scanner 11, XSS 12 | `class_mapping.json` |
| Dtypes at inference | float64 DataFrame with named columns, scaled; models take pandas DataFrames, so column order/names matter | `stage*.py` |

Notes that matter for reuse:
- Some of the 47 features are identifiers or near-identifiers (`ip.src_host`, `ip.dst_host`, `tcp.srcport`, `tcp.seq`, `tcp.ack_raw`, `arp.*proto_ipv4`). They are label-encoded and fed to the models. The stage 0 comments admit the quasi-identifier risk. This is Edge-IIoTset testbed-specific and will not transfer.
- `feature_encoders.pkl` (763 KB) is a dict of fitted LabelEncoders keyed by Wireshark column name. It has no meaning for a CICFlowMeter dataset.

---

## 2. AI engine, stage by stage

### Stage 0 — Preprocessing
- **Files / entry:** `AI/src/stage0_preprocessing.py` → `main()`; paths and constants in `AI/src/config.py`.
- **Does:** cleans, encodes, scales and splits the raw CSV; writes train/val/test, zero-day holdout and stream batches.
- **Library:** pandas, sklearn `LabelEncoder`, `StandardScaler`, `train_test_split`.
- **In → out:** raw CSV → `X_{train,val,test}.csv` (47 scaled float cols), `y_*.csv` (int-encoded `Attack_type`), `X/y_zero_day.csv`, `X/y_stream_batch_{0..4}.csv`.
- **Edge-IIoTset hard-coding:** everything (§1).
- **Artifacts written:** `scaler.pkl` 2.7 KB, `target_encoder.pkl` 637 B, `feature_encoders.pkl` 763 KB.
- **Deps:** pandas, numpy, sklearn, joblib. Offline only; does not run on the device.
- **Gap for inference:** the transform (encode → fill → scale) is not packaged as a function. A live flow would need `feature_encoders.pkl` + `scaler.pkl` + `feature_columns.json` re-assembled by hand.

### Stage 1 — Known-attack classifier
- **Files / entry:** `stage1_train.py` (`main()`), `stage1_models.py` (`get_model_zoo()`), `stage1_imbalance.py`.
- **Does:** trains 7 candidates (RF, ExtraTrees, DT, LogReg, XGBoost, LightGBM, CatBoost) on val macro-F1, compares imbalance strategies, refits the winner and reports it once on test.
- **Winner:** **XGBoost** (`n_estimators=300, max_depth=8, lr=0.1, tree_method=hist`) with `ClassWeightOnly`. Test accuracy 0.9610, macro-F1 0.9550, 0.044 ms/sample, 8.6 MB.
- **Inputs:** DataFrame, 47 scaled float columns. **Outputs:** class index 0–12 via `predict`, 13-way probability vector via `predict_proba`. No alert object.
- **Hard-coded:** `Attack_type` column name, 13-class label set (`labels` list in metadata), `config.py` paths.
- **Artifacts:** `best_model_XGBoost.joblib` **9.0 MB**, `best_model_metadata.json` (contains the `/home/laasya/...` absolute path).
- **Deps:** xgboost ≥2.0, sklearn ≥1.4, joblib. LightGBM, CatBoost and imblearn are only needed for retraining.
- **Pi:** the XGBoost model is fine on ARM (9 MB, ~0.04 ms/row batched). Training the full zoo is not Pi work.

### Stage 2 — Calibration + confidence routing
- **Files / entry:** `stage2_calibration.py` → `main()`.
- **Does:** loads the Stage 1 model through metadata, fits Temperature, Platt and Isotonic calibrators on the **val** set, picks the lowest ECE, and routes by `max prob ≥ 0.80`.
- **Algorithm:** custom `TemperatureScaler` (grid search on NLL); `CalibratedClassifierCV` with `FrozenEstimator` (sklearn ≥1.6) or `cv="prefit"`, methods `sigmoid` and `isotonic`. **Best = IsotonicRegression.** Dirichlet calibration is not implemented.
- **Inputs:** `X_val/X_test.csv` and the Stage 1 model. **Outputs:** calibrated 13-way probs, `routing_summary.json`, `test_set_routing.csv` with `row_index, true_label, predicted_label_idx, confidence, routed_to ∈ {known_final, zero_day_detector}`.
- **Hard-coded:** `HIGH_CONF_THRESHOLD = LOW_CONF_THRESHOLD = 0.80` (`config.py:110-111`). On the test set 91.67 % of rows route to "known", 8.33 % go to Stage 3.
- **Artifacts:** `isotonic_calibrator.pkl` **9.0 MB**, `platt_calibrator.pkl` **9.0 MB** (each embeds a full copy of the XGBoost model), `temperature_scaler.pkl` 171 B, `calibration_metadata.json`.
- **Deps:** sklearn ≥1.6 for `sklearn.frozen` (falls back for older versions).
- **Issue:** the best method is picked by ECE **on the test set**, not val. The calibrator is also never applied on a live path, because no inference code calls it.

### Stage 3 — Zero-day / anomaly detection
- **Files / entry:** `stage3_zero_day.py` → `main()`; `stage3_models.py` (`get_anomaly_zoo()`); `stage3_deep_models.py`.
- **Does:** fits 7 one-class detectors on the **whole known-class training set** (Normal and all 12 attack classes together), then scores "low-confidence known test rows" vs the MITM+Fingerprinting holdout. Binary labels: 0 = known, 1 = unknown.
- **Algorithms:** IsolationForest (300 trees), LOF (`novelty=True`, k=35), OneClassSVM (rbf, nu=0.05), EllipticEnvelope (contamination 0.05), plus PyTorch `AutoencoderDetector` (MLP 47→32→16→8→16→32→47, 30 epochs, MSE), `VAEDetector` and `DeepSVDDDetector`.
- **Winner:** **Autoencoder** (best F2 0.721, detection rate 0.677, FPR 0.0126). Anomaly threshold = 95th percentile of training reconstruction error (hard-coded "~5 % contamination").
- **Inputs:** 47 scaled floats. **Outputs:** `predict` → {−1, 1}, `decision_function` (higher = more normal); saved as `anomaly_score` and `predicted_binary_label` in the CSV handed to Stage 4.
- **Hard-coded:** `ZERO_DAY_CLASSES`, the `Stage 2` routing CSV path, contamination values, F2 as the selection rule.
- **Artifacts (joblib):** Autoencoder 24 KB, DeepSVDD 12.7 KB, IsolationForest 3.0 MB, EllipticEnvelope 1.0 MB, OneClassSVM 1.8 MB, LocalOutlierFactor **60.9 MB** (stores the train set), **VariationalAutoencoder 2 bytes (broken)**.
- **Deps:** sklearn; torch ≥2 for the deep detectors.
- **Pi:** the Autoencoder is tiny (24 KB, ~0.008 ms/sample) and ARM-friendly **if torch is available**. torch is the heavy part (see §5). A numpy re-implementation of the 3-layer MLP is feasible, but I did not check the weight layout, so the effort is **UNSURE**. LOF (61 MB, 0.59 ms/sample) and OCSVM (0.62 ms/sample) are the unattractive ones.
- **Issues:**
  - The detector is chosen using the holdout classes, so the reported detection rate is optimistic.
  - Training on attack classes as "known" is not a benign-baseline anomaly detector. That matters for the per-group design.
  - Pickling torch objects with joblib ties the artifact to the exact class definitions in `stage3_deep_models.py`.

### Stage 4 — Adversarial / SHAP verification
- **Files / entry:** `stage4_adversarial_verification.py` → `main()` (per-sample loop inside).
- **Does:** for rows Stage 3 flagged (`predicted_binary_label == 1`), computes (a) a SHAP vector from the Stage 1 XGBoost and its cosine distance from the per-class mean SHAP vector of the predicted class, and (b) the prediction flip rate under 20 Gaussian perturbations. It then decides CONFIRMED_ZERO_DAY, REJECTED_LIKELY_KNOWN or UNCERTAIN_FLAG_FOR_REVIEW.
- **Explainer:** `shap.TreeExplainer(model)` (exact TreeSHAP) on the **uncalibrated** Stage 1 XGBoost. The reference profile uses 500 training samples.
- **Constants:** `N_PERTURBATIONS=20`, `PERTURBATION_SCALE=0.15`×train std, `SHAP_DIVERGENCE_THRESHOLD=0.5`, `INSTABILITY_THRESHOLD=0.3`.
- **Inputs:** `stage3_predictions_for_stage4.csv` (47 features + 3 columns) and the Stage 1 model. **Outputs:** `verification_results.csv` (per-row decision, divergence, flip rate) and `verification_summary.json`.
- **Measured:** 853 flagged rows → 464 confirmed, 51 rejected, 338 uncertain; accuracy 0.912; **126 ms/sample** total (45 ms of that is SHAP); working memory only ~1.3 MB.
- **Deps:** `shap ≥0.45` (not installed on this machine). Handles both the old list-style and new 3-D SHAP return shapes.
- **Pi:** 126 ms/row is acceptable only for the rare flagged flows. `shap` and its numba/llvmlite chain is the risky dependency on ARM (**UNSURE** whether wheels exist for the Pi's Python version).
- **Issue:** there is no new learned model. The centroid is a SHAP mean from 500 samples, so with 13 classes some classes may have very few reference samples (`class_centroids` silently skips empty classes and falls back to the sample itself, giving distance 0). The "label" truth in the output (`true_binary_label`) is offline-only.

### Stage 5 — Continual learning
- **Files / entry:** `stage5_continual_learning.py` → `main()`; `stage5_strategies.py` (`get_continual_strategies()`).
- **Does:** simulation. For each strategy it fits on the original train set, replays 5 labelled stream batches, updates after each, and tracks accuracy, forgetting, backward/forward transfer, time and RAM.
- **Strategies:** `IncrementalRandomForest` (`warm_start`, +40 trees per batch), `LightGBMWarmStart` (actually refits a fresh booster on the window; its docstring says native continuation was unstable), `PeriodicXGBoostRetraining` (full retrain on **all data seen**), a `ReplayBufferWrapper` (2000-row reservoir) around the RF and LightGBM variants, and optional `river` ARF/HoeffdingTree/OnlineBagging.
- **Winner:** `PeriodicXGBoostRetraining` (accuracy after update 0.9619).
- **Inputs:** labelled batches (47 scaled features + label). It **requires ground-truth labels** for every update.
- **Artifacts (`models/stage5_continual/`):** `_initial` and `_final` joblibs of each strategy. The sizes are large: IncrementalRF **258 / 281 MB**, ReplayBuffer_IncrementalRF **258 / 291 MB**, PeriodicXGBoost 41 / 47 MB, LightGBM 5.5–8.4 MB.
- **Deps:** psutil, xgboost, lightgbm, sklearn; river optional.
- **Pi:** the RF variants (hundreds of MB) and the retrain-on-everything strategy (memory grows each update) will not fit a low-RAM Pi. The LightGBM and replay-buffer designs are the plausible ones.
- **Gap:** nothing promotes a Stage 5 model into the Stage 1/2/4 path. Stage 2/4 still load the original Stage 1 model.

### Router / glue
- **`AI/src/run_pipeline.py`:** `subprocess.run` of the 6 scripts in order, stops on a nonzero exit. There is no runtime router.
- **Data contract between stages:** all through `data/…`, `models/…`, `results/…` files, using relative row indices (`row_index`) that only make sense inside the offline test set.
- **Call order (offline):** Stage 0 → 1 (`best_model_*.joblib` + metadata) → 2 (reads metadata and val/test, writes calibrators and routing CSV) → 3 (reads routing CSV + train/zero-day sets) → 4 (reads Stage 3 CSV + Stage 1 model) → 5 (reads train/test/stream).
- **Intended runtime flow (from the code and READMEs, not implemented):** classify → calibrate → if confidence ≥ 0.80 report the known label; else run the anomaly detector → if flagged, verify with SHAP/perturbation.

---

## 3. Mitigation engine, stage by stage

The module docstrings state that most of this is a **synthetic simulation study**. I agree with that characterization.

### Stage 0 (Mitigation copy) — Preprocessing
- `Mitigation/src/stage0_preprocessing.py`. A near-duplicate of the AI Stage 0 with an 80/20 split and no zero-day holdout. Writes its own `scaler.pkl`, `feature_encoders.pkl` (763 KB) and `target_encoder.pkl`. **Only `target_encoder.pkl` and `y_test.csv`/`X_test.csv` are consumed downstream** (to recover `Attack_type` strings for the severity map and the sampling pools). The feature pipeline itself is unused by the mitigation logic.
- The class encoding differs from the AI engine's (`target_encoder.pkl` is 661 B vs 637 B). Whether the integer mapping is identical is **UNSURE**; I didn't diff them.

### Stage A — Device criticality (`stage_a_criticality.py`)
- **Type:** configuration lookup, no model. `classify_device(name, lookup)` → one of `safety_critical`, `privacy_critical`, `convenience`; unknown devices fall back to `safety_critical`. `is_auto_isolation_eligible(tier)` is the only gate: `tier != "safety_critical"`.
- **Hard-coded:** `DEVICE_CATALOG` in `config.py` is 12 **made-up** smart-home device names (door lock, gas sensor, camera, thermostat, …). Edge-IIoTset has no device identity.
- **Artifact:** writes `data/synthetic/device_tier_lookup.json`.

### Stage B — Adaptive risk score (`stage_b_risk_score.py`)
- **Algorithm:** `Risk = w1·severity + w2·confidence + w3·(1−trust) + w4·frequency`, initial weights 0.35/0.25/0.25/0.15, with a multiplicative-weights online update (`lr=0.05`, drift cap 0.10, weight floor 0.05). A numpy/pandas weighted sum; the only "learned" part.
- **Inputs (function):** `compute_risk(severity, confidence, trust, frequency, weights)`, all floats in [0,1]. **Output:** a float score.
- **Thresholds:** `HIGH_RISK_THRESHOLD=0.65`. `LOW_RISK_THRESHOLD=0.35` is **defined but never used** anywhere in `src`.
- **Real vs simulated:** severity comes from `SEVERITY_MAP[Attack_type]` (real labels). Confidence (Beta draws), trust, frequency and the "genuine threat" ground truth are all synthetic.
- **Hard-coded to Edge-IIoTset:** `SEVERITY_MAP` keys (all 15 class names), plus the 0.0390 and 0.9167 constants (copied from AI-engine results).
- **Artifacts:** `static_weights.pkl` 99 B, `online_weights_final.pkl` 225 B (small dicts).

### Stage C — Context check (`stage_c_context_check.py`, `twin_state_simulator.py`)
- **Type:** rule engine. `context_decision(twin_state)` → `restrict` (occupied+active, or away) or `monitor` (occupied+asleep). The "twin" is a 14-day synthetic hourly occupancy generator; `query_state_at` is a list lookup. **No real twin or Home Assistant integration.**
- **Evaluation caveat:** the "oracle" is the same generator, so the 100 %-style agreement metric is tautological.

### Stage D — Immediate containment (`stage_d_containment.py`)
- **Type:** deterministic. `determine_action(tier, risk_score)`: `safety_critical` → `notify_admin_only` (asserted unreachable by auto-isolation); the others → `isolate`, downgraded to `rate_limit` if `risk < 0.80`. `block_flow` appears in the docstring but is **not returned by any code path**.
- **Trigger:** meant to fire when Stage B risk ≥ 0.65. The only call site is the evaluation loop, which draws `risk_score` from `uniform(0.65, 1)`.
- **Effect:** none on a network. Returns a string and times it.

### Stage E — Recovery (`stage_e_recovery.py`)
- **Type:** after containment, average 5 "rolling anomaly scores"; mean ≥ 0.5 → `escalate`, else `restore`. The scores are **randomly generated** by `simulate_post_containment_behavior` (not a network signal).
- **Output:** reward ∈ {+1, −1, −0.25} written to `stage_e_outcomes.csv`, the shape the feedback channel consumes.

### Trust store + feedback channel (`trust_store.py`, `feedback_channel.py`)
- `TrustStore`: trust relaxes toward 0.5 with λ=0.08, +0.02 passive reward, +β·reward (β=0.35) when closed-loop.
- `feedback_channel.py` is the only channel-like code. Messages are `OutcomeMessage{device_id, reward, seq, timestamp}`, JSON with sorted keys, HMAC-SHA256 signed, with a per-device monotonic `seq` replay check. The transport is a **Python list** (`queue.append`) standing in for MQTT.
- **Auth:** HMAC key is a hard-coded placeholder, `b"REPLACE_WITH_PROVISIONED_HUB_KEY_AT_DEPLOYMENT"`, and the signature covers only the body. A single shared key is used for both sides, so this offers integrity but no per-device identity. Timestamps are not checked for freshness, so replay protection is sequence-only and the `last_seq` state is in memory (lost on restart).

### Part C ablations (`stage_c_synthetic_streams.py`, `cross_engine_ablations.py`)
- Builds synthetic repeated-offense and false-escalation streams from real `X_test` rows, then compares closed- vs open-loop trust and static vs adaptive risk weights. All simulation.

### Mitigation: actions, triggers, alert intake

| Question | Answer |
|---|---|
| Actions that exist | `isolate`, `rate_limit`, `notify_admin_only`, `monitor`, `restrict`, `restore`, `escalate`. `block_flow` is documented but unused. All are returned strings with **no enforcement code**. |
| What triggers them | B ≥ 0.65 → D. C is described for "below high" risk (the unused 0.35 low threshold is not enforced). E runs after D. No code chains B→C/D→E. They run independently on synthetic data. |
| How alerts arrive | **They don't.** There is no function, socket, queue, API or MQTT listener that accepts an AI-engine alert. The only inter-component "channel" is the in-memory list in `feedback_channel.py`. |
| Alert format expected | **UNSURE / undefined.** The implied tuple is (device, `Attack_type`→severity, calibrated confidence, trust, frequency), but no schema exists. |
| Auth on the channel | HMAC-SHA256 + sequence number on the feedback messages only, with a placeholder hard-coded key. Nothing on the AI→mitigation direction (it doesn't exist). |

---

## 4. Hard-coded-to-Edge-IIoTset inventory

| Where | What |
|---|---|
| `AI/src/config.py` | `RAW_DATA_PATH`, `DROP_COLS` (15 Wireshark fields), `TARGET_COL="Attack_type"`, `ZERO_DAY_CLASSES=["MITM","Fingerprinting"]`, split fractions, stream settings, routing threshold 0.80 |
| `AI/data/processed/*` | 47 Wireshark feature names, 13-class map, per-column LabelEncoders, scaler fit on Edge-IIoTset |
| `Mitigation/src/config.py` | `SEVERITY_MAP` (15 Edge-IIoTset class names), `DEVICE_CATALOG` (synthetic), `FALSE_ESCALATION_NOISE_FRACTION=0.01262`, other thresholds |
| `stage_b_risk_score.py` | `0.0390` error rate and `0.9167` routing split from AI results; reads `target_encoder.pkl` to turn ints into class names |
| `Mitigation/src/stage0_preprocessing.py`, `inspect_dataset.py` | duplicate of `DROP_COLS` and dataset path |
| `.joblib`/`.pkl` | Every model was trained on those 47 columns in that order, so all are unusable on other features |
| Metadata JSONs | absolute `/home/laasya/...` paths |

---

## 5. Dependencies and Raspberry Pi risk

`AI/requirements.txt` has `pandas>=2.0, numpy>=1.24, scikit-learn>=1.4, joblib, psutil, xgboost>=2.0, lightgbm>=4.0, catboost>=1.2, imbalanced-learn>=0.12, shap>=0.45, torch>=2.0, river>=0.21` — all lower bounds, no pins. `Mitigation/requirements.txt` has only pandas/numpy/sklearn/joblib. Stage 2 needs sklearn ≥1.6 for `FrozenEstimator` (otherwise it takes the older `cv="prefit"` path).

| Item | Pi concern |
|---|---|
| torch (Autoencoder/VAE/DeepSVDD) | Large install (hundreds of MB) and slow import, and aarch64 wheels exist only for some Python versions. Overkill for a 24 KB MLP. |
| shap | Needs numba/llvmlite. ARM wheel availability is **UNSURE**. |
| xgboost | aarch64 wheels exist for recent versions. Model is 9 MB, so this is fine. |
| lightgbm / catboost / imblearn / river | Training-time only. They are not needed to run the chosen models. |
| Stage 5 RF strategies | 260–290 MB model files and RAM growth per update. Not Pi-suitable. |
| LocalOutlierFactor | 61 MB and the slowest per-sample inference. Not a Pi candidate. |
| Per-sample latency | Stage 1 ~0.04 ms and AE ~0.008 ms are fine. Stage 4 ~126 ms. Measured on the development machine, not a Pi, so Pi numbers are **UNSURE**. |
| Pickle portability | The saved artifacts depend on the sklearn/xgboost/torch versions used to create them (unrecorded). Expect to re-export rather than copy to a Pi. |
| Stage 0-style preprocessing | LabelEncoder dict + StandardScaler per flow is cheap. |

---

## 6. How the stages connect (summary)

```
Raw CSV
  └─ Stage 0 ──► X/y train,val,test │ zero_day │ stream │ scaler/encoders (pkl)
        ├─ Stage 1 (XGBoost) ──► best_model.joblib + metadata(abs path)
        │      ├─ Stage 2 (Isotonic) ──► calibrators, test_set_routing.csv  (conf ≥ 0.80 → known)
        │      │        └─ Stage 3 (Autoencoder on rows routed low-conf + holdout) ──► stage3_predictions_for_stage4.csv
        │      │                  └─ Stage 4 (TreeSHAP + perturbation on flagged rows; uses Stage 1 raw model) ──► verification_results.csv
        │      └─ (Stage 4 reads Stage 1 directly)
        └─ Stage 5 (stream replay) ──► strategy joblibs, best_strategy.json   (nothing consumes them)

Mitigation (separate tree; no import from AI/):
  synthetic confidence/trust/frequency + real Attack_type→severity ─► B ─► C / D ─► E ─► feedback_channel (in-memory) ─► trust_store
```

---

## 7. Reuse table

New target: 70 CICFlowMeter features per flow (`config/features_v1.json`), with models trained **per behaviour group** (`config/behaviour_groups.json`: G1, G2, plus a GEN fallback).

| Module | Reusable as code? | What must change for a 70-feature CICFlowMeter dataset with per-group models |
|---|---|---|
| `config.py` (AI) | partly | Replace `RAW_DATA_PATH`, `DROP_COLS`, `TARGET_COL`, `ZERO_DAY_CLASSES`. Make paths parametric per group (`models/<group>/…`) and remove the machine-specific absolute paths. Take the feature list from `config/features_v1.json` (70, with sha256) instead of `feature_columns.json`. The routing threshold 0.80 should be re-tuned per group. |
| Stage 0 preprocessing | partly | Logic pattern (dedupe, ±inf→NaN, split, train-only scaler) is reusable. Drop the LabelEncoder block entirely (CICFlowMeter features are numeric). Replace −1 NaN fill with a deliberate choice. Replace the random stratified split with the existing `split_plan.json` / active-time session split already built in `08_build_datasets.py`. Fit one scaler per group. Save a single `transform(flow_dict)` function. Likely superseded by `08_build_datasets.py`. |
| Stage 1 classifier | yes | The zoo and the evaluate/select loop are generic. Change input width to 70, class list to the new attack set (`config/attack_set.json`), and train one model per group (G1, G2, and GEN). Save metadata with relative paths and library versions. XGBoost is a fine Pi-sized choice, but check model size with 70 features. |
| Stage 2 calibration | yes | Fully generic (temperature, Platt, isotonic). Refit per group on that group's val set and choose the method on val, not test. Avoid saving a full model copy in each calibrator (9 MB each). Store the threshold per group. Needs sklearn ≥1.6 or the `prefit` fallback. |
| Stage 3 zero-day | partly | The detector zoo is generic. Retrain per group. Strongly consider fitting on **benign-only** data of that group (current code fits on all known classes), and replace `ZERO_DAY_CLASSES` with whatever attacks are held out in the new set (`attack_set.json`). Do not select the detector using the holdout used for reporting. Rebuild the broken VAE artifact or drop it. Prefer a numpy/ONNX export of the Autoencoder over joblib-pickled torch for the Pi. |
| Stage 4 SHAP / perturbation | partly | Method is generic for tree models. Needs `feature_cols` of 70, per-group reference profiles (500 samples per group, check every class has samples), and thresholds `0.5/0.3` re-tuned. Runs only on flagged rows. `shap` on ARM is the risk, so a precomputed-reference or lighter alternative may be needed. Uses the raw, not calibrated, model, so decide which one should be explained. |
| Stage 5 continual learning | partly | Strategy classes are reusable, the simulation harness is not a runtime. Needs an online labelled-feedback source (it assumes labels for every batch). Drop the RF variants (hundreds of MB). Add a promote-to-production step that doesn't exist today. Per group. |
| Run pipeline / router (glue) | no | `run_pipeline.py` is a subprocess chain over files, and there is no runtime router. A real inference module is needed: `flow(70 floats) → group assignment → group model → calibrate → route → (anomaly → verify) → alert dict`. Group assignment itself is not in this code (it lives in `06_*`/`config/behaviour_groups.json` as per-**device** fingerprints), so per-flow routing by device→group table is a new component. |
| `utils_metrics.py` | yes | Generic metrics / profiler. Not checked in detail (**UNSURE** about every edge case). |
| Mitigation Stage A | partly | Tier lookup logic and the safety-critical gate are reusable. Replace the synthetic `DEVICE_CATALOG` with the real device table (`config/device_table.csv`: MAC, device_name, category, role). Keys must be MAC/IP, not made-up names. |
| Mitigation Stage B | partly | `compute_risk` and the weight update are generic. Replace `SEVERITY_MAP` with the new attack labels. Feed real confidence/trust/frequency instead of Beta draws. Fix or remove the unused `LOW_RISK_THRESHOLD`. Online weight updating needs real outcome labels. |
| Mitigation Stage C | partly | The 3-rule logic is trivial and reusable. The twin is a stand-in, so it needs a real occupancy/state source (**UNSURE** what the real system provides). |
| Mitigation Stage D | partly | The decision function is reusable. It needs real actuators (router/firewall/AP API, ARP/DHCP quarantine, MAC/IP targeting), implementations for `block_flow`/`rate_limit`, idempotency, rollback and logging. Nothing exists today. |
| Mitigation Stage E | partly | Restore/escalate rule is reusable. Replace simulated rolling scores with the AI engine's real post-action scores for that device. |
| Trust store | yes | Pure math, no dataset dependency. Persist state to disk. |
| Feedback channel | partly | HMAC + sequence message format is reusable. Replace the list with a real transport (MQTT/socket), provision per-hub keys instead of the hard-coded placeholder, add timestamp-freshness checks and persist `last_seq`. |
| Mitigation Stage 0 / streams / ablations | no | These exist to reproduce paper-style simulation results from Edge-IIoTset. Not needed for a live system. |
| Artifacts (`.joblib`/`.pkl`) | no | All tied to the 47 Edge-IIoTset columns and 13 classes. They must be regenerated. The metadata JSONs need relative paths. |
| AI → Mitigation interface | no (missing) | Define an alert schema (e.g. `device_mac, group, label, calibrated_conf, anomaly_score, verification, ts`) and a transport with authentication. This contract does not exist in the code. |
