# LG-IDS V2 -- Phase 2 pre-registration (offline multiclass, steps 22-26)

Status: fixed before any Phase 2 model is trained. Its sha256 is pinned in `common/schemas.py`
(`PREREG_PHASE2_SHA256`) and checked by `verify_v2_lock()`, which every Phase 2 script calls at start-up.
Any change to this file requires a new pin and is visible in git history. Tunables live in
`config/v2_phase2.json` (sha256 recorded in every run manifest); implementation choices that this document
does not fix are logged one per line in `docs/V2_DECISIONS.md`.

## 1. Data and the val-only rule

- Dataset version `v2_0_v1equiv` (Phase 1): V1's train / val / test rows, identical row by row.
- Phase 2 uses **train and val only**. Every Phase 2 script loads data through `common/phase2_data.load_split`,
  which raises on any request for the test split. All model fitting, early stopping, calibration fitting and
  every comparison in Phase 2 use train / val only. No Phase 2 number is a test number.
- The test split is evaluated **once, later**, in a separate pre-registered run. Its sessions are V1's test
  sessions, which V1 already evaluated once (step 10); that reuse is disclosed in the paper.
- Classes come from `config/class_map.json` (`num_class = len(class_map)`), features from
  `config/features_v1.json`, groups from the data's `group` column (fallback group from the config).
  Nothing about classes, groups, features or subnets is hard-coded.

## 2. Models (primary configuration, fixed in advance)

- **Specialists**: one XGBoost `multi:softprob` model per behaviour group except the fallback group (`GEN`).
  Training set of the specialist for group g = g's benign train rows + ALL attack train rows of ALL groups
  (shared attack pool). Its val set = g's benign val rows + ALL attack val rows.
- **GLOBAL**: all train rows, no grouping. It is (a) the flat multiclass baseline and (b) the runtime model for
  fallback-group flows.
- **Routed system (primary system)**: each flow is scored by the specialist of its group; fallback-group flows
  by GLOBAL. Headline numbers are the routed system on the full val split.
- `num_class = len(class_map)` always. A class with 0 rows in a training set is warned about and logged, never
  a crash.
- **Class weights (primary)**: benign weight 1; attack class c gets `sqrt(n_benign / n_c)` if `n_c < n_benign`,
  else 1; counts of that model's own training set at train time.
- **Hyperparameters**: V1's step 9 values (XGBoost 3.4.2 library defaults), pinned explicitly in the config,
  `tree_method = hist`. No hyperparameter search.
- **Early stopping**: on a stratified 10 % inner split carved from TRAIN (seeded by the model seed), never on
  val. The model is the booster at the best inner-split iteration.
- **Seeds**: 0, 1, 2, 3, 4. Every model x configuration is trained for all five seeds.

## 3. Ablations (reported; never used to select anything)

- **A1 class weights**: none / sqrt (primary) / fully balanced, for every primary model.
- **A2 fallback handling**: GEN -> GLOBAL (primary) vs a GEN specialist (GEN benign + pooled attacks), compared on
  GEN val benign false alarms.
- **A3 per-device-category specialists** (same pooling rule) if a device-category column exists; categories
  with < 100 benign train flows fall back to GLOBAL. Skipped and logged if no such column exists.

## 4. Metrics (val only)

Per model, per routed / flat system, overall and per group of the flow; per seed, then **mean +- 95 % t-CI over
the 5 seeds** (t with 4 degrees of freedom):

- per-class precision, recall, F1; confusion matrix (counts and row-normalised)
- **macro-F1 reported twice**: over all classes with >= 1 val flow in the evaluation set, and over non-rare
  classes only. A class is **rare** in an evaluation set if it has fewer than `min_val_flows` (default 50) val
  flows there. Rare classes always get exact **Clopper-Pearson 95 % CIs on recall**. Classes with 0 val flows
  in an evaluation set are reported as N/A, not as 0.
- weighted F1, Matthews correlation coefficient (multiclass), balanced accuracy
- one-vs-rest ROC-AUC and PR-AUC per class (classes with >= 1 positive)
- **false alarms / hour** = benign flows predicted as any attack class / benign val hours, with an **exact
  (Garwood) Poisson 95 % CI**. Benign val hours from the timestamps: per session, active segments of the val
  flow starts (a pause > 300 s ends a segment; a segment ends 1 s after its last start, V1 08's rule), keeping
  the segments that hold >= 1 benign flow of the evaluated rows.
- inference ms / flow at batch 1 and batch 1024 (single thread, labelled "dev machine", not the Pi); model
  size on disk
- **binary collapse**: P(attack) = 1 - P(benign); compared with V1's frozen binary specialists (read-only,
  sha256 == step 10 prereg) on the same val rows: PR-AUC, ROC-AUC, detection rate and false alarms at 0.5, and
  at each system's own lowest val threshold with <= 2 false alarms (V1's T_house rule; same-set, optimistic).
- **calibration (Stage 2)**: temperature scaling (one parameter per model). 2-fold stratified cross-fit on val
  (seeded) for the reported numbers; the deployment calibrator is fitted on all of val. ECE (15 equal-width
  bins; top-label and per-class one-vs-rest), Brier score; before / after.
- **explanations**: TreeSHAP on the seed-0 primary models, up to `shap_per_class` (default 2000) val flows per
  class per model (stratified, seeded; all if fewer). Leakage check: no identifier-like feature (IP, MAC, port,
  timestamp, flow id) in the feature set; flag any feature with > 50 % of a model's total mean |SHAP|.

## 5. Figures (all via `common/plot_style.py`; each listed with a caption in its summary.md)

- 22: class counts per training set (log scale, pooled attacks visible); mlogloss train vs inner split per
  specialist (seed 0).
- 23: normalised confusion matrix per group; per-class P / R / F1 with CI error bars; V2 binary collapse vs V1;
  macro-F1 with CI for every model / system / ablation (dot plot); false alarms / hour with CI; one-vs-rest PR
  curves per class; macro-F1 vs ms / flow (point size = model size).
- 24: reliability diagrams per class before / after; ECE and Brier before / after.
- 25: beeswarm per class per specialist; global mean |SHAP| per model; top-20 features x group heatmap.
- 26: none (registry table in summary.md).

## 6. Registry

Seed-0 primary models are registered as **candidate** only, with an Ed25519 signature over the manifest and
file hashes. Approval and promotion are manual steps by the author. `load_model` refuses a bad signature, a
class-map or feature-list hash mismatch, or a non-promoted state (unless explicitly allowed for offline
evaluation).

## 7. Out of scope here

Published-method baselines (TODO, logged in `docs/V2_DECISIONS.md`); any test-split number; streaming and
continual learning (later phases).
