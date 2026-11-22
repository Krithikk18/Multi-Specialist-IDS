# LG-IDS V2 -- Phase 5A pre-registration: zero-day test (leave-one-attack-out + model of normal, per-group vs global)

Status: written and pinned (`PREREG_PHASE5_SHA256` in `common/schemas.py`, checked by `verify_v2_lock()`) together with
`config/v2_phase5.json` (`V2_PHASE5_CONFIG_SHA256`) **before** any leave-one-attack-out retrain and before any model of
normal is fitted on project data. Every parameter named here lives in `config/v2_phase5.json`. Implementation choices
this document does not fix are logged in `docs/V2_DECISIONS.md` (D151+). Phase 5A reads the **train** and **val**
splits only (full val; the Phase 4 val-A / val-B split is not used); the test split is never opened.

Phase 5A is an **offline evaluation**. It changes nothing in the runtime or its configs, writes no registry entry of
any kind, and promotes nothing. Models of normal are plain files under `~/lgids_cache/v2/zeroday/` with a hashed
manifest.

## 0. Glossary (names, not stage numbers)

- **Stage 1** = the supervised multiclass GLOBAL classifier only (the promoted v2_1 FLAT_GLOBAL seed 0,
  `GLOBAL__none__s0__20261121T075821Z`, and its retrains). No other component is given a stage number here.
- **continual learning** = the Phase 4 loop (review queue, labels, retrain, gate).
- **zero-day / model of normal** = this phase: benign-only anomaly detectors that flag flows Stage 1 calls benign.
- **rate guard** = the packet-level flood guard (Phase 3).
- Naming note: Amendment 2 section 2 calls continual learning "Stage 3" and zero-day "Stage 5"; `config/class_map.json`
  (notes) and older context documents call unknown / zero-day detection "Stage 3". These numbers conflict, so from this
  pre-registration on, components are named, not numbered. The pinned documents are not edited.

## 1. Limitations, stated before any result

1. **Few held-out classes.** The class map has 3 attack classes, all floods or scans. Held-out classes for the verdict
   are those with >= 50 val flows (the Phase 2 rare rule); the val class counts were looked at when this document was
   written (no result was): 2 classes qualify (one SYN-flood class, one port-scan class), the UDP-flood class has 17 val
   flows and is report-only. The CI over seeds x classes covers **seed noise, not attack variety**: two classes cannot
   say how the arms handle attacks in general.
2. **Detector bias.** Isolation Forest isolates globally extreme points (floods, fast scans) quickly and is weak on
   "local" anomalies inside dense benign regions. The test cannot say how either arm handles stealthy attacks.
3. **Flow level only.** In the deployed hybrid the rate guard would likely catch these floods anyway; this test
   isolates the flow path.
4. **val is not fully held out.** It was used for the Phase 2 weighting choice (Amendment 1), for Amendment 2's
   FLAT_GLOBAL choice, and for the deployed temperature fit (step 24); the Phase 4 disclosure applies. Nothing in this
   phase is tuned on val (thresholds come from train benign only).
5. **The model of normal is benign-only**, so it does not depend on which attack is held out: the same fitted models
   score every held-out class; only the miss set changes with the held-out class (and the seed).
6. Train-benign and val-benign flows are separable (Phase 3.1 drift check, adversarial AUC 0.81), so val benign flag
   rates may exceed the nominal 0.1 %; this is reported (section 6), never corrected.
7. **Out-of-range points** (seen while writing the synthetic tests, before any project data was scored): an isolation
   tree sends a point beyond the training range down the edge branch, so it scores about like the most extreme
   training rows, not higher. Extreme floods are therefore not guaranteed to score above a 99.9th-percentile threshold.
   In the synthetic tests, models trained on fewer rows (per-group, and random groups of the same sizes) flagged more
   such points even when the groups did not differ. So a per-group gain must be read together with the RANDOM_GROUP
   control (section 4). The verdict rule itself is Amendment 2's and does not use the control.

## 2. Amendment 2 rules, copied verbatim

From `docs/V2_PREREG_PHASE2_AMENDMENT_2.md` (pinned, unchanged):

> ## 3. Pre-registered routing test, Phase 5 (zero-day)
>
> - **Compared**: a per-group model of normal traffic (one anomaly detector per group, trained on that group's train
>   benign flows only) vs one global model of normal traffic (trained on all train benign flows). A group without
>   enough train benign for its own detector uses the global detector (the Phase 5 prereg states the minimum).
> - **Leave-one-attack-out**: for each attack class k, the Stage 1 model is retrained without class k (same data,
>   weights, hyperparameters, seeds). A **Stage 1 miss** is a val flow of class k that the retrained Stage 1 model
>   predicts benign (a flow predicted as another attack class already raises an alert).
> - **Metric**: held-out-attack recall = (Stage 1 misses of class k flagged by the anomaly detector) / (Stage 1 misses
>   of class k), per detector, per seed, per held-out class.
> - **Threshold rule**: each detector's threshold is the 99.9th percentile of its own anomaly score on its own train
>   benign flows. Nothing is tuned on val.
> - **Verdict**: per-group **WINS** iff (a) the paired difference (per-group - global) in held-out-attack recall, over
>   the 5 seeds x held-out classes, has a 95 % bootstrap CI (percentile, 10,000 resamples of the (seed, class) pairs,
>   seed 0) entirely above 0, AND (b) the per-group detector's benign val false alarms / h are not worse than the
>   global detector's by more than 0.5 / h (upper bound of the 95 % CI of the difference <= 0.5 / h).
> - The detector family is fixed in the Phase 5 pre-registration before Phase 5 runs. This amendment fixes the
>   comparison, the metric, the threshold rule and the verdict.

> ## 5. Kill rule
>
> If neither test favours per-group, routing is reported as an operational feature only (logging, per-group rates,
> incident keys), with no novelty claim. If only one test favours it, the claim is limited to that stage.

Every rule below agrees with these. Where this document adds detail that Amendment 2 leaves open, the rule is marked
**[added in the Phase 5 prereg, not in Amendment 2]**.

## 3. Leave-one-attack-out Stage 1 (script `36_loao_stage1.py`, module `common/loao.py`)

- **Held-out classes.** Every attack class of the class map (ids != benign). A class with < `loao.rare_min_val_flows`
  (50) val flows is **rare** (Phase 2 rule): it is retrained and reported, but its pairs never enter the verdict
  (`rare_classes_report_only`). **[added: the restriction of the verdict to non-rare classes]** Amendment 2 section 6
  keeps every Phase 2 metric convention, and Phase 2 reports rare classes without using them in non-rare metrics.
  Section 5.6 checks that this restriction cannot change the verdict.
- **Retrain.** For held-out k and seed s in `loao.seeds` {0..4}: the Stage 1 training set = every `v2_1_oriented` train
  row whose class != k (class k removed entirely; nothing else changes). Labels are remapped to a contiguous local
  mapping (the remaining class ids in ascending order -> 0..K-2; benign stays 0); the class map is never edited.
  Training = the promoted model's configuration exactly: XGBoost `multi:softprob` with the `config/v2_phase2_v2_1.json`
  parameters, class weights `none` (the Amendment 1 rule's outcome), early stopping (10 rounds) on a seeded 10 %
  per-class stratified inner split of this training set (seed = s), booster sliced at the best iteration
  (`common/cl_retrain.fit`, tested identical to step 22's `train_one`), fixed `loao.nthread` (4).
- **Control (report-only).** The same code without removing a class, seed `control_full_refit_seed` (0), is compared
  with the step 22 `GLOBAL__none` seed-0 model (= the deployed entry, sha256 checked against the registry): model
  bytes and val argmax agreement. A difference is reported, not fixed (thread count may differ from step 22's).
- **Prediction.** Full val, argmax of the softprob output, mapped back to class-map ids. The temperature does not
  change argmax, so no calibration is used.
- **Stage 1 miss** = a val flow with true class k predicted benign. **Caught by Stage 1** = a val flow of class k
  predicted as any other attack class (it would still alert). Reported per (k, s): val k flows, misses, caught (and as
  which class), and the LOAO model's benign recall and flow-level FA / h on val (sanity: removing k must not break
  benign).

## 4. Models of normal (script `37_fit_normal_models.py`, module `common/normal_model.py`)

- **Detector family (fixed here, as Amendment 2 requires).** scikit-learn `IsolationForest`, `n_estimators` 200,
  `max_samples` = min(256, n), `max_features` 1.0, `bootstrap` false, `random_state` = the seed, fixed `n_jobs` 4 for
  every fit and every score. `contamination` is not used (no `predict`). **Anomaly score** = `-score_samples(x)`
  (higher = more anomalous).
- **Input.** All 70 pinned features (`config/features_v1.json`), in that order. Non-finite values: the V1 / Stage 1 data
  policy (`common/schemas.apply_nan_inf_policy`: NaN and +-inf -> 0), counted per feature and reported; no new rule.
- **Transform (both arms): `sign(x) * log1p(|x|)`**, element-wise. Rationale, from first principles: an isolation tree
  picks a feature and a split point uniformly between that feature's min and max in the node. On raw heavy-tailed
  features (byte counts, rates, inter-arrival times spanning many orders of magnitude) almost every uniform split
  falls in the sparse tail, so the dense benign bulk -- exactly where a tighter per-group "normal" would differ from a
  global one -- is barely resolved, and any per-group advantage would be hidden by the feature scale. A linear
  rescaling changes nothing for IF (uniform splits are scale-equivariant); what matters is the distribution's shape.
  The signed log compresses tails while keeping order and sign, is parameter-free (nothing fitted, so nothing can leak
  from val or differ between arms) and is dataset-agnostic. **[added]**
- **Threshold.** The 99.9th percentile (`threshold_quantile` 0.999, numpy `linear` interpolation) of the model's anomaly
  scores on **all of its own** training benign flows (not only the 256-row sub-samples). A flow is **flagged** iff its
  score > the threshold of the model that scored it.
- **GLOBAL_NORMAL** (Amendment 2 arm): one model per seed on all train-benign flows.
- **PER_GROUP_NORMAL** (Amendment 2 arm): per seed, one model per group (the dataset's `group` column, the offline
  equivalent of runtime routing -- Phase 3 parity showed they match 100 %) on that group's train-benign flows, each with
  its own threshold; a flow is scored by its group's model. **Minimum (Amendment 2 leaves it to this prereg):** a group
  with < `min_group_benign` (1,000) train-benign flows uses GLOBAL_NORMAL's same-seed model and threshold; every
  fallback is logged (group, n). A val group absent from train benign also uses the global model (logged).
- **RANDOM_GROUP_NORMAL** (report-only control, never in the verdict): per seed, the train-benign rows' group labels are
  randomly permuted (numpy `default_rng(random_group_perm_seed_base + seed)`, so the group sizes are unchanged), and the
  per-group rule is applied to the permuted groups; at scoring time a val flow uses the model of its real group's
  label. If this arm "wins" too, a per-group gain comes from smaller training sets, not from device-group structure.
  **[added]**
- **Seeds** {0..4} for every arm. Scoring runs in chunks of `score_chunk_rows` rows (memory).
- **Threshold check (report-only):** per arm x seed, each of the arm's models is refitted (same hyperparameters, same
  random_state) on a seeded 90 % of its own training rows (`default_rng(split_seed_base + seed)`), its threshold set on
  that 90 %, and the flag rate on the held-out 10 % compared with the nominal 0.1 % (pooled over the arm's models, and
  per model). This tells whether an in-sample threshold is biased low. It does not change the primary arms.
- **Determinism check:** seed 0 of each arm is refitted; its anomaly scores on the train-benign rows must be identical.

## 5. Evaluation and verdict (script `38_zeroday_eval.py`, module `common/zeroday_metrics.py`)

1. **Unit of analysis** = a (held-out class k, seed s) pair. For each pair, both arms use their seed-s models and the
   same miss set, from LOAO(k, s).
2. **Primary metric (Amendment 2):** miss-recall = share of the pair's Stage 1 misses flagged by the arm. Paired
   difference d(k, s) = PER_GROUP_NORMAL - GLOBAL_NORMAL.
3. **Eligibility [added]:** a pair with < `min_misses` (30) Stage 1 misses is reported but excluded from the verdict.
   The number of eligible pairs per class is reported.
4. **Recall CI (Amendment 2, made precise [added: equal weights, the resampling unit]):** mean of d over the eligible
   pairs, each pair weighted equally; 95 % percentile bootstrap over pairs (resample the pairs with replacement,
   10,000 resamples, numpy `default_rng(bootstrap_seed = 0)`, percentiles by numpy `linear` interpolation).
   Report-only: the t-interval. Disclosed: the bootstrap treats pairs as independent although pairs share seeds
   (models of normal) and classes.
5. **False alarms [added: the CI method for condition (b)]:** on val benign flows (all val benign rows), flagged by the
   arm = false alarms; FA / h = count / benign hours, benign hours = the Phases 3-4 definition
   (`common/phase2_metrics.benign_hours`: per-session active segments of all val flow starts, a pause >
   `benign_hours_idle_gap_s` (300 s) ends a segment, segments holding >= 1 benign flow). FA does not depend on k, so
   condition (b) pairs over seeds only (5 pairs): difference = PER_GROUP_NORMAL - GLOBAL_NORMAL in FA / h, 95 %
   percentile bootstrap over the 5 seed pairs (10,000 resamples, seed 0). Absolute FA / h, flagged-flow counts and
   benign hours are reported for every arm x seed (one flagged flow can move FA / h by ~0.5-1).
6. **Verdict (Amendment 2 section 3).** (a) lower 95 % CI bound of mean d > 0; (b) upper 95 % CI bound of the FA / h
   difference <= `fa_margin_per_h` (0.5 / h). **PER_GROUP_WINS iff (a) AND (b)**, otherwise **DOES_NOT_WIN**.
   - No eligible pair: the CI does not exist, so (a) cannot hold: DOES_NOT_WIN (insufficient support). Amendment 2
     says "wins iff", so no support means no win.
   - **Support condition [added]:** if fewer than `min_support_classes` (2) held-out classes have >= 1 eligible pair,
     the result is DOES_NOT_WIN (insufficient support).
   - **Conflict guard [added].** Two of the rules above are stricter than Amendment 2's letter (the verdict
     restricted to non-rare classes and eligible pairs; the support condition). The script also computes the verdict
     under the **Amendment 2 literal reading**: every attack class (rare included), every pair whose recall is defined
     (>= 1 miss), no support condition, the same (a) and (b). If the two readings give the same verdict, it is the
     verdict. If they differ, the status is **CONFLICT**: no verdict is declared and Phase 5A stops for a human
     decision (Amendment 2 wins over this document, but which reading is "Amendment 2" is then a judgement, not a
     rule).
7. **Kill rule (Amendment 2 section 5).** Phase 4's section 4 result is a pinned fact: **DOES_NOT_WIN**
   (`pinned_facts`). If section 3 = DOES_NOT_WIN, print exactly
   `Kill rule §5 FIRES: routing is operational only; no novelty claim.`
   If section 3 = PER_GROUP_WINS, print exactly
   `Kill rule §5 does not fire: the routing novelty claim rests on the zero-day result (§3) alone.`
   On CONFLICT, the kill rule is not evaluated.

## 6. Report-only (never in the verdict)

- recall of each arm on ALL val flows of class k (the detector alone, not only Stage 1 misses);
- combined system on k: Stage 1 alert (LOAO argmax != benign) OR model-of-normal flag, per arm; combined FA / h and
  counts on val benign;
- RANDOM_GROUP_NORMAL vs GLOBAL_NORMAL with the same paired analysis (recall CI, FA CI, the same (a) / (b) tests);
- drift: val-benign flag rate per arm x seed and per group vs the nominal 0.1 %;
- per-group miss-recall where a group has misses;
- scoring cost: microseconds per flow for each arm (fixed `n_jobs`; batch over full val and single-flow calls),
  model sizes on disk (Pi relevance);
- the threshold check and the determinism check (section 4); the LOAO control (section 3).

## 7. Outputs and guards

- `results/phase5a/36/`, `37/`, `38/` (summary.md, json, run_manifest.json, run_meta.json; run.log is git-ignored);
  figures under `results/phase5a/figures/`, the phase summary `results/phase5a/summary.md`. Dry runs (5 % stratified
  sample, seed 0 only) go to `results/phase5a/<step>/dry_run/<run_id>/` (git-ignored). Nothing is overwritten.
- Models, predictions and scores: `~/lgids_cache/v2/zeroday/<kind>/<run_id>/` with manifests holding every file's
  sha256. No registry entry, no runtime config change.
- Every script runs `verify_v2_lock()` at start and end and logs the sha256 of `config/config.py` and
  `config/class_map.json` both times.
