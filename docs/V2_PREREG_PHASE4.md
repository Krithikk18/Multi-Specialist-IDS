# LG-IDS V2 -- Phase 4 pre-registration: continual learning loop + Amendment 2 section 4 routing test

Status: written and pinned (`PREREG_PHASE4_SHA256` in `common/schemas.py`, checked by `verify_v2_lock()`) together with
`config/v2_phase4.json` (`V2_PHASE4_CONFIG_SHA256`) **before** any val-A runtime run, any labelling and any retraining.
Every parameter named here lives in `config/v2_phase4.json`. Implementation choices it does not fix are logged in
`docs/V2_DECISIONS.md` (D116+). Phase 4 reads the **train** and **val** splits only; the test split is never opened.

## 0. Scope and disclosure

- The loop: runtime scores val-A -> review queue -> simulated operator labels -> signed label batch -> validator ->
  retraining arms -> regression gate on val-B -> gate-passing seed-0 models registered as signed **CANDIDATE** entries.
- **The Pi never trains.** It only scores, logs and loads signed, promoted models. All retraining is offline. Promotion
  stays a human step; this phase approves and promotes nothing, and the promoted entry
  (`GLOBAL__none__s0__20261121T075821Z`) is not changed.
- Disclosure: val is not pristine. Phase 2 chose the class weighting on val (Amendment 1), Amendment 2 chose FLAT_GLOBAL
  after seeing val, and the deployed model's temperature was fitted on all val rows (step 24), so val-B rows were seen
  by that fit. The gate and every headline metric use argmax predictions, which the temperature does not change; the
  validator's confidence rule (section 3) uses the calibrated probabilities. Phase 4 numbers are **val evidence for the
  loop's mechanics**, not a held-out estimate.
- The operator is simulated from ground truth. Phase 4 can show what the loop does with correct (or uniformly noisy, or
  deliberately poisoned) labels; it cannot show how real operators label, how fast, or with which biases.

## 1. val-A / val-B split

- Each val session's window is the interval the split definition (`split_definition.json` of the dataset) labels
  `val`. Its extent on the data is [max(window start, first val `start_ts`), min(window end, last val `start_ts`)]
  (an open window has no end of its own, and a window may open long before its first flow). Cut at the time midpoint
  of that extent: `start_ts` < midpoint -> **val-A** (the "live period" the operator labels); otherwise **val-B** (where
  every model is judged). The same rows of `v2_0_v1equiv` (runtime replay input) and `v2_1_oriented` (offline
  reference) get the same part (identical session / row order).
- Reported: flows per class x group in val-A and val-B. A class with < `gate.min_val_flows` (50) flows in val-B is
  **rare for the gate** (the Phase 2 rule): reported, never gated.

## 2. Runtime on val-A and the review queue

- The Phase 3 runtime (`common/runtime.Runtime`), CSV replay of the val-A rows at max speed, the latest pinned Phase 3
  config (`config/v2_phase3_1.json`: `v2_phase3_2.json` does not exist), mode GLOBAL, the promoted model loaded the
  deployment way (promoted only). Flow path only (the packet rate guard raises no flow labels). **Parity** against the
  offline predictions of the same model for the same rows must be exact as in Phase 3 (every flow matched 1:1,
  0 quarantined / dropped; runtime-normalised features == v2_1 features exactly; predicted class 100 %; calibrated
  probabilities within 1e-6; routing group and device 100 %). A parity failure stops Phase 4.
- Queue (`common/review_queue.py`): every alerted flow (runtime `alert`: predicted attack with calibrated max-probability
  >= the policy threshold), reason `alert`, + a seeded uniform random sample of exactly round(`random_review_rate` x
  n_non_alerted) non-alerted flows (`random_review_rate` 0.05, seed 0), reason `random`.

## 3. Simulated operator, signed label store, validator

- Operator (`common/operator_sim.py`): labels each queued flow with its ground-truth class. **Primary: noise 0,
  unlimited budget** (the whole queue). Report-only sweeps: noise 0.02 (an item's label becomes a uniformly random
  OTHER class with probability 0.02); budget 1,000 and 10,000 items (alerts and random kept at their queue proportions,
  uniform within reason). One seeded stream (seed 0).
- Label store (`common/label_store.py`): append-only batches (parquet + manifest). Each label holds the flow key (Flow
  ID + start time + run id, plus the runtime's flow uid for uniqueness), the label, the reason, the operator id and the
  time. The manifest (counts per class / reason, file + content hashes, class map sha256) is Ed25519-signed with the
  operator key (`~/lgids_cache/keys/operator/`, never in the repo); a signed, hash-chained index lists every batch.
  Training reads labels only through the store, which refuses unsigned, re-signed, edited or un-indexed batches.
- **Validator** (`common/cl_validator.py`). A batch is **QUARANTINED** (not used for training; needs human review) if
  any of: (a) bad signature or hash; (b) a label not in the class map; (c) among the items the deployed model scored
  with calibrated max-probability >= `confident_pmax` (0.99), the share whose label differs from its prediction is
  > `max_confident_disagreement` (0.05) (no such items -> (c) passes). Every check is evaluated and the checks that
  fired are reported. Only VALID batches enter the primary arms.

## 4. Replay buffer

One fixed, seeded, stratified sample of the ORIGINAL training data (v2_1 train): strata = class x group; a class with
< `min_class_rows` (1,000) train rows keeps all its rows; otherwise each stratum keeps max(1, round(`frac` x n))
(`frac` 0.25, seed 0) uniformly drawn rows. Written once with a manifest (strata counts, positions sha256, train file
sha256); the same buffer is used by every arm that replays.

## 5. Retraining arms

All arms: 5 seeds (0-4), the Amendment 1 primary configuration (class weights `none`, step 22's hyperparameters and
early stopping: patience 10 on the weighted mlogloss of a seeded stratified 10 % inner split **of that arm's own
training set**, booster sliced at the best iteration), a fixed thread count (`retrain.nthread` 4) on one machine.
Label rows enter training with the **operator's** label and the v2_1 (normalised) features of the labelled flow.

Scenario **S1** -- valid val-A labels for all groups:
- **R0 no retrain**: the existing v2_1 FLAT_GLOBAL models (`GLOBAL__none`, seeds 0-4, step 22 run 20261121T075821Z).
- **R1 full retrain**: GLOBAL on full train + all valid val-A labels (reference: best accuracy, highest cost).
- **R2 warm start with replay**: continue boosting the same-seed v2_1 GLOBAL (`xgb_model`) for up to
  `warm_start_rounds` (100) new trees, same early stopping, on replay buffer + labels.
- **R3 warm start, labels only**: R2 without replay (expected to forget).

Scenario **S2** -- labels for ONE group only (Amendment 2 section 4), group `s2.label_group` = G1 (Phase 3.1 D: the only
group with enough data); the labels of S2 are the valid val-A labels whose runtime-routed group is that group:
- **S2-GLOBAL**: full retrain of GLOBAL on full train + the group's labels; evaluated as FLAT_GLOBAL.
- **S2-G1**: full retrain of that group's specialist on its original training set (the group's train benign + the shared
  attack pool, step 22's pooled rule) + the group's labels. The other specialists and the fallback group -> GLOBAL stay
  the unchanged v2_1 models; evaluated as the **ROUTED** system (routing by the flow's group).
- References: the unchanged v2_1 FLAT_GLOBAL (= R0) and v2_1 ROUTED (same seeds).

Cost per arm x seed: wall-clock seconds of DMatrix construction + boosting, and the process peak RSS during the fit
(high-water mark reset before it) plus its increase over the RSS before the fit. A retrained model's temperature is
fitted on its own inner split (bounds [0.05, 20]); it is stored with the candidate and affects no gated metric.

## 6. Metrics on val-B

Per model / system: per-class recall and F1, macro-F1 (all classes with support; non-rare), flow-level false alarms / h
(benign val-B flows predicted as an attack class / benign hours of val-B: per-session active segments of the val-B
flow starts, pause > 300 s ends one, holding >= 1 benign flow), all from argmax predictions; 5-seed means with paired
95 % t-CIs (4 df) of (arm - R0) by seed. **Forgetting** = before - after (positive = performance lost), paired by seed:
S1 per class (F1 of R0 - F1 of the arm, non-rare classes); S2 = drop in non-rare macro-F1 on the val-B flows of the
groups that received NO labels (pooled; non-rare = >= 50 flows in that subset), "before" = the same v2_1 system and
seed (S2-GLOBAL: v2_1 FLAT_GLOBAL; S2-G1: v2_1 ROUTED); per-group values reported. Affected-group non-rare macro-F1 =
the labelled group's val-B flows. Retrain time and memory per arm.

## 7. Regression gate, registration, rejection

Gate (`common/cl_gate.py`), candidate vs the **deployed** configuration on all val-B rows, per seed (seed s vs the
v2_1 FLAT_GLOBAL seed s; for S2-G1 the candidate is its ROUTED system): **(i)** no non-rare class's recall drops by
more than 0.01; **(ii)** non-rare macro-F1 drops by no more than 0.002; **(iii)** flow-level false alarms / h rise by no
more than 0.5. All three -> **PASS**. Non-rare = >= 50 val-B flows.
- Gate-passing **seed-0** models of R1, R2, R3, S2-GLOBAL and S2-G1 (its retrained specialist) are registered as signed
  CANDIDATE entries (the existing registry, the registry key), tagged `phase4` + arm + this prereg's sha256 + the
  label-batch manifest / file hashes (+ the replay manifest sha256 and the base entry for warm starts). Nothing is
  approved or promoted. R0 is the deployed model and is not re-registered.
- Every gate-failing arm x seed is logged **REJECTED** with the failing condition(s). Seeds 1-4 that pass are logged
  as passing, not registered. Experiment arms (poisoning, feedback bias, sweeps) are never registered.

## 8. Amendment 2 section 4 verdict

**In the per-group arm, the other groups' specialists are unchanged, so their forgetting is zero by construction. The
real question of Amendment 2 §4 is whether retraining GLOBAL causes forgetting on the other groups. If it doesn't,
per-group can win only on cost.**

Per-group (S2-G1) **WINS** iff [forgetting is lower: the paired 95 % t-CI over the 5 seeds of (forgetting S2-G1 -
forgetting S2-GLOBAL) lies entirely below 0, OR forgetting is equal: |mean of that difference| <= 0.002 AND mean
S2-GLOBAL retrain time / mean S2-G1 retrain time >= 2] AND the affected group's non-rare macro-F1 is not worse: mean over
seeds of (S2-G1 - S2-GLOBAL) >= -0.005. Otherwise DOES_NOT_WIN. The zero-by-construction note is printed next to the
verdict. Kill rule (Amendment 2 section 5): a DOES_NOT_WIN here means the Phase 4 test does not favour per-group.

## 9. Poisoning test

Two poisoned batches built from the primary batch, signed with the operator key (an insider / compromised-operator
model; a validator check (a) failure is therefore not expected), stored in a separate store that no primary arm reads:
- **P1**: round(10 %) seeded-random labels of the batch's most frequent attack class (by count) flipped to benign.
- **P2**: 100 % of the labels of the batch's least frequent NON-RARE attack class (non-rare = section 7) flipped to benign.

For each: the validator's result (which check fired), and -- used anyway -- R2 retrained on it (5 seeds) through the
gate. Verdict per batch: **CAUGHT_BY_VALIDATOR** if quarantined; else **CAUGHT_BY_GATE** if the seed-0 R2 model fails
the gate (only seed 0 would be registered); else **NOT_CAUGHT** (a finding to report, not a stop).

## 10. Feedback bias (report-only)

The queue rebuilt WITHOUT the random sample (alerts only) -> labelled (noise 0, unlimited) -> R2 (5 seeds). Compared with
the primary R2: how many of val-A's missed attack flows (attack flows the deployed model did not alert on) were labelled
with vs without the random sample, and val-B recall of the attack classes that have such misses in val-A (also recall on
the val-B flows of those classes the same-seed R0 misses).

## 11. Operator sweeps (report-only)

Noise 0.02, budget 1,000, budget 10,000: each batch is signed, validated and used by R2 (5 seeds, through the gate);
reported next to the primary R2. Never registered.

## 12. Stop conditions

A guard fails; this file or `config/v2_phase4.json` is not pinned before the first retrain; a test still fails after two
honest fix attempts; a step would need test data; the val-A runtime run fails parity.
