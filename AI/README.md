# Edge-IIoT Intrusion Detection Pipeline

Implementation of the 6-stage workflow (Preprocessing -> Known Attack
Classification -> Confidence Calibration -> Zero-Day Detection ->
Adversarial Verification -> Continual Learning) over the Edge-IIoTset
dataset.

## Quick start (WSL / conda)

**Memory note**: Stage 1 trains several tree ensembles (300 estimators
each, `class_weight="balanced"`) on ~90k rows in parallel. This was
validated end-to-end on a representative subsample and individually
smoke-tested on the full dataset, but comfortably needs **8GB+ RAM**
to run all models back-to-back without swapping or being OOM-killed --
a machine with only ~4GB free (as this environment had) will kill the
process partway through Phase A. If you hit this, lower `N_JOBS` in
`src/config.py` (already defaults to 2, not -1, for this reason), or
reduce `n_estimators` in `stage1_models.py`.

```bash
conda create -n ids python=3.11 -y
conda activate ids
cd IDS
pip install -r requirements.txt

# Full pipeline (Stage 0 -> Stage 5), ~10-40 min depending on hardware
python src/run_pipeline.py

# Or run stages individually (each reads/writes disk, so they can be
# re-run independently once Stage 0 has produced data/processed/):
python src/stage0_preprocessing.py
python src/stage1_train.py
python src/stage2_calibration.py
python src/stage3_zero_day.py
python src/stage4_adversarial_verification.py
python src/stage5_continual_learning.py
```

`xgboost`, `lightgbm`, `imbalanced-learn`, and `shap` are required for
Stages 1, 2 and 4. `catboost`, `torch`, and `river` are optional --
if not installed, the corresponding models (CatBoost in Stage 1;
Autoencoder/VAE/DeepSVDD in Stage 3; Adaptive Random Forest/Hoeffding
Tree/Online Bagging in Stage 5) are skipped with a printed warning
rather than crashing the run.

## Folder structure

```
IDS/
  data/
    raw/ML-EdgeIIoT-dataset.csv       <- your original file, untouched
    processed/                        <- Stage 0 output: train/val/test (known classes)
    zero_day_holdout/                 <- Stage 0 output: MITM + Fingerprinting (true unknowns)
    stream/                           <- Stage 0 output: 5 batches for Stage 5 simulation
  models/
    stage1_known_attack/
    stage2_calibration/
    stage3_zero_day/
    stage5_continual/
  results/
    stage1/ ... stage5/               <- CSV/JSON metrics, confusion matrices, comparisons
  src/                                 <- all code (see below)
  logs/
  requirements.txt
  README.md
```

## What each stage does, and where results land

### Stage 0 -- `stage0_preprocessing.py`
Loads the raw CSV, drops leakage/free-text columns, deduplicates,
**holds out MITM and Fingerprinting entirely** (they never appear in
train/val/test -- they are the "genuine zero-day attacks" Stage 3 is
evaluated against), encodes categoricals (LabelEncoder, consistent with
your original preprocessing.py), encodes the target, then produces a
stratified **70/15/15 train/val/test split** over the remaining 13
known classes. A further 15% slice of the training data is carved out
*before* scaling is fit and saved separately as 5 sequential "stream"
batches for Stage 5. The `StandardScaler` is fit only on the final
training core to avoid leakage into val/test/stream/zero-day.

Why MITM + Fingerprinting: they are the two smallest classes in the raw
data (1214 and 1001 rows respectively out of ~153k), so holding them
out costs the least classification signal while still giving Stage 3 a
realistic, never-before-seen attack family to detect.

### Stage 1 -- `stage1_train.py` (+ `stage1_models.py`, `stage1_imbalance.py`)
Trains and compares **RandomForest, ExtraTrees, DecisionTree,
LogisticRegression, XGBoost, LightGBM, CatBoost** (SVM and KNN were
excluded by design -- too slow at this row count on CPU-only hardware).
Three phases:
- **Phase A**: all models, base training, ranked by macro-F1 on
  validation -> `results/stage1/phase_a_model_comparison.csv`
- **Phase B**: the winning architecture re-trained under each imbalance
  strategy (class weights only / RandomOverSampler / SMOTE / ADASYN),
  compared on validation -> `results/stage1/phase_b_imbalance_comparison.csv`
- **Phase C**: final (model, strategy) combo refit on train, scored
  once on the untouched test set -> `results/stage1/final_test_result.json`

Full metric suite (accuracy, precision/recall/F1/F2 macro+weighted,
MCC, Cohen's kappa, balanced accuracy, ROC-AUC, PR-AUC) plus resource
profiling (train/inference time, throughput, peak RAM, model size) is
recorded for every model tried, not just the winner. Confusion matrices
and per-class precision/recall/F1 are saved per model.

### Stage 2 -- `stage2_calibration.py`
Per the spec, restricted to **tree-ensemble-native methods**:
Temperature Scaling, Platt Scaling (`CalibratedClassifierCV`,
sigmoid), Isotonic Regression (`CalibratedClassifierCV`, isotonic).
**Dirichlet calibration is not implemented** -- it requires a dedicated
library outside the sklearn/tree-ensemble stack this project uses; this
is called out explicitly in the results rather than silently skipped.
All three fit on validation, scored on test via ECE, MCE, Brier score,
NLL. The best (lowest ECE) is used to compute final calibrated
probabilities and drive **confidence-based routing**: samples with
top-1 probability >= 0.80 are routed to "Final Known Attack", the rest
go to Stage 3. Reliability-diagram and confidence-histogram *data*
(binned counts/averages) are saved as CSV since plotting isn't done
in-pipeline (no notebooks) -- plot them with any tool you like.

### Stage 3 -- `stage3_zero_day.py` (+ `stage3_models.py`, `stage3_deep_models.py`)
Anomaly detectors (**Isolation Forest, Local Outlier Factor,
One-Class SVM, Elliptic Envelope**, plus **Autoencoder, Variational
Autoencoder, Deep SVDD** if `torch` is installed) are trained
one-class-style on known-class training data only -- they never see a
zero-day sample during fit. Evaluation set = low-confidence known test
flows (from Stage 2's routing) **+** the true MITM/Fingerprinting
zero-day holdout, labeled known=0/unknown=1. Full binary metric suite
(precision/recall/F1/F2, FPR, FNR, detection rate, ROC-AUC, PR-AUC)
plus resource profiling per detector ->
`results/stage3/zero_day_detector_comparison.csv`. Best detector chosen
by F2 (recall-weighted, since missing a zero-day is worse than a false
alarm for an IDS).

### Stage 4 -- `stage4_adversarial_verification.py`
Runs **only** on samples Stage 3 flagged as zero-day (not the full
stream, per spec -- "triggered flows only"). Two lightweight, explicitly
non-classifier techniques:
- **TreeSHAP**: computes the flagged sample's SHAP vector under the
  Stage 1 model and measures its cosine divergence from that class's
  typical SHAP profile (centroid over a training reference sample).
- **Input Perturbation**: applies 20 small Gaussian perturbations
  (scaled to each feature's training std) and measures how often the
  Stage 1 model's prediction flips -- an unstable neighborhood is
  itself evidence of novelty.

The two signals combine into CONFIRMED_ZERO_DAY / REJECTED_LIKELY_KNOWN
/ UNCERTAIN_FLAG_FOR_REVIEW. Verification accuracy, false verification
rate, latency, SHAP generation time, explanation length, and memory use
are all reported -> `results/stage4/verification_summary.json`.

### Stage 5 -- `stage5_continual_learning.py` (+ `stage5_strategies.py`)
Since only one static dataset exists, "incoming production traffic" is
simulated by replaying the 5 stream batches carved out in Stage 0.
Strategies compared: **Incremental Random Forest** (warm_start,
grows the forest per update), **Periodic XGBoost Retraining** (full
refit from scratch each update -- the accuracy/cost upper bound),
**LightGBM Warm Start**, **Replay Buffer** (wraps any strategy with a
capped reservoir buffer so old classes stay represented every update),
and -- if `river` is installed -- **Adaptive Random Forest**,
**Hoeffding Tree**, **Online Bagging**.

**Design note on LightGBM warm start**: LightGBM's native `init_model`
continuation (loading a previous booster and boosting further rounds on
top of it) was tested and found numerically unstable for this dataset's
multiclass setting -- training loss diverged after only a few
continuation rounds regardless of learning rate, and the model
collapsed to predicting a single dominant class. Rather than ship a
silently broken strategy, `LightGBMWarmStart` here always re-fits a
fresh booster on the current window (new batch alone, or replay
buffer + new batch when wrapped) -- still cheap since the window size
is bounded, and numerically stable. This is documented in the
docstring of `stage5_strategies.LightGBMWarmStart`.

Metrics per strategy: accuracy after update, **forgetting rate** (drop
from each class's peak-ever test accuracy to its final accuracy,
averaged), **backward transfer** (change in original test-set accuracy
from before the stream to after the last batch), **forward transfer**
(how well the model does on each new batch *before* training on it,
averaged across batches), retraining time, peak RAM per update, model
size growth, CPU%, update frequency -> `results/stage5/continual_learning_comparison.csv`.

## Validation performed before delivery

Every stage (0-5) was run end-to-end on a real, representative
subsample of your actual dataset (~3000 rows/split, all 13 known
classes + the zero-day holdout + stream batches) to confirm correctness
of the full data flow between stages, not just each script in
isolation. This caught and fixed one real bug worth knowing about:

**LightGBM warm-start instability (found and fixed):** the first
implementation of `LightGBMWarmStart` used LightGBM's native
`init_model` continuation (loading a previous booster and adding more
boosting rounds on top of it). Under repeated continuation across
multiple stream batches, training loss diverged and the model collapsed
to predicting a single class (~8-17% accuracy). Root-caused via
`lgb.record_evaluation` showing `multi_logloss` exploding from ~0.3 to
30+ within a handful of continuation rounds, confirmed to be independent
of batch composition (a fresh fit on the identical data was fine).
Fixed by re-fitting a bounded window (replay buffer + new batch) fresh
each update instead of chaining `init_model` -- see the docstring in
`stage5_strategies.LightGBMWarmStart` for the full explanation. All 5
Stage 5 strategies now produce stable, sensible, well-differentiated
results with no collapses.

Full-scale training on the complete ~90k-row training set was also
smoke-tested directly (RandomForest: 27.8s train time, 0.9463 val
macro-F1 on real data) before this environment's ~4GB RAM ceiling
caused the process to be killed partway through Phase A of Stage 1 --
this is a sandbox resource constraint, not a bug in the code (see
memory note above).

## Design decisions and deviations from the spec (and why)

| Spec item | What was done | Why |
|---|---|---|
| SVM, KNN in Stage 1 | Excluded | Explicit project decision -- too slow at ~90k rows x 47 features on CPU-only WSL |
| Zero-day simulation | MITM + Fingerprinting held out entirely from Stage 1 | Explicit project decision -- gives Stage 3 genuine unseen attacks instead of only confidence-based routing |
| Train/val/test split | 70/15/15 stratified (was 80/20 in your original script) | Matches the workflow diagram; your original script is preserved unmodified for reference, not deleted |
| Missing numeric values | -1 (was median in your original script) | Matches workflow spec ("Replace: NaN -> -1"); absence of a protocol field is informative and shouldn't be blurred into a typical value |
| Categorical encoding | LabelEncoder (spec says One-Hot) | Several categorical columns (`ip.src_host`, `ip.dst_host`, `arp.*proto_ipv4`, `tcp.srcport`) are high-cardinality quasi-identifiers; one-hot would blow up dimensionality and re-introduce host-fingerprint-like leakage. Kept consistent with your original project's approach. |
| Dirichlet calibration | Not implemented | Requires a dedicated library outside the sklearn/tree-ensemble stack; explicitly reported as skipped rather than silently omitted |
| Stage 5 "incoming data" | Carved from existing training data (5 batches, held out before Stage 1 ever trains) | No real streaming source exists; this was an explicit project decision over building a synthetic-only demo |

## Re-running after changing something

Every stage reads its inputs from disk and writes its outputs to disk,
so if you tweak, say, `stage3_models.py`'s anomaly detector
hyperparameters, you only need to re-run `python src/stage3_zero_day.py`
-- no need to redo Stage 0-2 first, as long as their outputs already
exist in `data/processed/`, `data/zero_day_holdout/`, and
`results/stage2/`.
