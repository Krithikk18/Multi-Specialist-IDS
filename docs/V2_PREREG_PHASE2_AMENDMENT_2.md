# LG-IDS V2 -- Phase 2 pre-registration, Amendment 2 (Stage 1 primary model + pre-registered routing tests)

Status: written and pinned (`PREREG_PHASE2_AMENDMENT_2_SHA256` in `common/schemas.py`, checked by
`verify_v2_lock()`) **before** any test-split run and before any Phase 3 runtime evaluation. It amends
`docs/V2_PREREG_PHASE2.md` and `docs/V2_PREREG_PHASE2_AMENDMENT_1.md` (both unchanged, both still pinned); where they
differ, this document wins. Implementation choices it does not fix are logged in `docs/V2_DECISIONS.md` (D57+).

## 0. Disclosure: this amendment is made AFTER seeing the v2_1 val results

It is not a pre-registration in the strict sense. The v2_1_oriented val results (step 23 run `20261121T080839Z`,
compared in `results/phase2_v2_1_compare/rerun_fig_fix/`, run `20261121T081216Z`) were seen before it was written.
No test-split data has been read by Phase 2 or by this amendment; the test split is still opened exactly once, at the
final test run.

Numbers that decided section 1 (Amendment 1 weighting `none`, full val split, mean [95 % t-CI] over the 5 seeds):

| system | macro-F1 all | macro-F1 non-rare | false alarms / h | seed-0 false alarms |
|---|---|---|---|---|
| ROUTED (`ROUTED_A1_none`) | 0.9102 [0.8971, 0.9232] | 0.9974 [0.9974, 0.9975] | 1.741 [1.393, 2.089] | 4 FP / 1.953 h |
| FLAT_GLOBAL (`GLOBAL__none`) | 0.9144 [0.8984, 0.9305] | 0.9978 [0.9972, 0.9984] | 1.024 [0.575, 1.474] | 2 FP / 1.953 h |

ROUTED - FLAT_GLOBAL, paired by seed: non-rare macro-F1 -0.00037 [-0.00099, 0.00025] (CI contains 0: a tie on
known-attack classification); false alarms / h +0.717 [-0.008, 1.442] (ROUTED raises more, CI just touches 0).

## 1. Stage 1 primary model = FLAT_GLOBAL

- The Stage 1 primary (deployed) model is **FLAT_GLOBAL**: the GLOBAL model trained on `v2_1_oriented` with class
  weights `none` (the Amendment 1 rule's choice), applied to every flow. **Seed 0 is the deployed model**
  (registry entry `GLOBAL__none__s0__20261121T075821Z`, promoted under this amendment).
- **ROUTED** (`ROUTED_A1_none`: per-group specialists, fallback group -> GLOBAL) is reported alongside it as the
  secondary comparison at the final test run, with the same metrics.
- Reason: a tie on non-rare macro-F1 (paired CI contains 0), fewer false alarms, and one model instead of three
  (simpler to deploy, calibrate, explain and update).

## 2. Routing stays in the architecture

Every flow is still assigned MAC -> device -> group at runtime (the ingest rule, unknown -> the fallback group).
The group is used for logging, per-group false-alarm rates, and by Stages 3 (continual learning) and 5 (zero-day).
It no longer selects the Stage 1 classifier in the primary configuration.

## 3. Pre-registered routing test, Phase 5 (zero-day)

- **Compared**: a per-group model of normal traffic (one anomaly detector per group, trained on that group's train
  benign flows only) vs one global model of normal traffic (trained on all train benign flows). A group without
  enough train benign for its own detector uses the global detector (the Phase 5 prereg states the minimum).
- **Leave-one-attack-out**: for each attack class k, the Stage 1 model is retrained without class k (same data,
  weights, hyperparameters, seeds). A **Stage 1 miss** is a val flow of class k that the retrained Stage 1 model
  predicts benign (a flow predicted as another attack class already raises an alert).
- **Metric**: held-out-attack recall = (Stage 1 misses of class k flagged by the anomaly detector) / (Stage 1 misses
  of class k), per detector, per seed, per held-out class.
- **Threshold rule**: each detector's threshold is the 99.9th percentile of its own anomaly score on its own train
  benign flows. Nothing is tuned on val.
- **Verdict**: per-group **WINS** iff (a) the paired difference (per-group - global) in held-out-attack recall, over
  the 5 seeds x held-out classes, has a 95 % bootstrap CI (percentile, 10,000 resamples of the (seed, class) pairs,
  seed 0) entirely above 0, AND (b) the per-group detector's benign val false alarms / h are not worse than the
  global detector's by more than 0.5 / h (upper bound of the 95 % CI of the difference <= 0.5 / h).
- The detector family is fixed in the Phase 5 pre-registration before Phase 5 runs. This amendment fixes the
  comparison, the metric, the threshold rule and the verdict.

## 4. Pre-registered routing test, Phase 4 (continual learning)

- **Setting**: new labelled data arrives for ONE group. Compared: (a) retraining only that group's specialist vs
  (b) retraining GLOBAL.
- **Metrics**: forgetting = drop in non-rare macro-F1 on the OTHER groups' val flows (before vs after the update);
  affected-group non-rare macro-F1 after the update; retrain wall time.
- **Verdict**: per-group **WINS** iff [forgetting is lower (paired CI over 5 seeds excludes 0), OR forgetting is
  equal within 0.002 with >= 2x lower retrain time] AND affected-group macro-F1 is not worse by more than 0.005.

## 5. Kill rule

If neither test favours per-group, routing is reported as an operational feature only (logging, per-group rates,
incident keys), with no novelty claim. If only one test favours it, the claim is limited to that stage.

## 6. Everything else is unchanged

Data (`v2_1_oriented`), the orientation normaliser, the Amendment 1 weighting rule and its outcome, hyperparameters,
seeds, every metric and CI, calibration, SHAP, the registry rules, and the val-only rule are exactly as in
`docs/V2_PREREG_PHASE2.md` and `docs/V2_PREREG_PHASE2_AMENDMENT_1.md`.
