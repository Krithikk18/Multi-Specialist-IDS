# LG-IDS V2 -- Phase 5B pre-registration: orientation-free host / host-pair context features (H-C1, H-C2, H-C3) + TreeSHAP perturbation check

Status: written and pinned (`PREREG_PHASE5B_SHA256` in `common/schemas.py`, checked by `verify_v2_lock()`) together with
`config/v2_phase5b.json` (`V2_PHASE5B_CONFIG_SHA256`) and the feature list `config/features_v2_2_context.json`
(`FEATURES_V2_2_CONTEXT_SHA256`) **before** the context dataset is built (step B) and before any model is trained on it.
Every parameter named here lives in `config/v2_phase5b.json`. Implementation choices this document does not fix are logged
in `docs/V2_DECISIONS.md` (D164+; D164 = the stop at step A, D165 = the H-C3 detector change, section 1b). Phase 5B reads the **train** and **val** splits only; the test split is never built
or opened.

Phase 5B is **offline**. It changes nothing in the runtime or its configs, writes no registry entry, promotes nothing.
Models go under `~/lgids_cache/v2/phase5b/<kind>/<run_id>/` with hashed manifests.

## 0. Glossary and standing decisions

- The Phase 5 glossary applies (`docs/V2_PREREG_PHASE5.md` section 0): **Stage 1** = the supervised multiclass GLOBAL
  classifier only; other components are named, not numbered (continual learning, zero-day / model of normal, rate guard,
  and here **context features**).
- **D163 holds**: Amendment 2 kill rule §5 fired; routing is operational only and no routing-novelty claim is made. Any
  per-group arm in this phase (step E) is **report-only and not a routing claim**.

## 1. Limitations, stated before any result

1. Same CICIoT2023 testbed: few hosts, attackers are testbed Raspberry Pis; context statistics describe this network.
2. val is not fully held out (Phase 2 selection, Amendment 2, the deployed temperature; the Phase 4 disclosure applies).
3. Context features may partly re-encode what the packet-level rate guard already sees (counts per host per window);
   a comparison with the rate guard is out of scope.
4. The held-out classes for the zero-day test are still only floods and scans (syn_flood, port_scan; udp_flood is rare).
5. Benign flows of a host under attack inherit attack-looking context (its host window is full of attack flows). This is
   **measured, not fixed** (contamination, section 5).
6. Timestamps have 1-second resolution (start_ts); flow end = start + duration (microseconds), so sub-second order of
   flows starting in the same second comes from their durations, not from packet times.
7. **CTX_TAIL (the H-C3 primary detector, section 5) only detects attacks that push some context feature above the
   benign upper tail** (volume, fan-out, port spread). A low-and-slow attack inside the benign range is invisible to it.
   Contaminated benign flows (hosts under attack) will raise false alarms; these are measured, not fixed.
8. The flip test (section 4) can only swap TCP flows (the R3 normaliser's TCP-only guard), so H-C1 is a TCP result.

## 1b. Detector change before any data (D165)

The first draft of this pre-registration used the Phase 5A IsolationForest recipe as the H-C3 model of normal. Before
any project data was read, the synthetic end-to-end test showed three failure mechanisms of that recipe on context
features (D164): (i) rows beyond the benign training range follow the edge branch of every isolation tree and score
only like the most extreme benign rows (Phase 5A limitation 7); (ii) the in-sample 99.9th-percentile threshold sits on
that extreme benign tail (warm-up ramps, heavy hosts), above the attack scores; (iii) sign(x) log1p|x| compresses count
gaps (1,000 vs 2,000 flows / 10 s -> 6.9 vs 7.6). **D165 (human decision, Krithikk, 23 Nov 2026): the H-C3 primary
detector is a per-feature upper-tail rule with a held-out-benign threshold (CTX_TAIL); the 5A recipe is kept as the
report-only arm CTX_IF_GLOBAL.** The change was chosen after a synthetic sanity check and before any project data was
read, so it is still pre-registration.

## 2. Context features (module `common/context_features.py`, one streaming implementation)

- **Availability.** A flow is available when it ends: `t_end = start x start_unit_us + duration x duration_unit_us`
  (integer microseconds; column names and units from the config). The context of flow f uses only flows with `t_end` in
  `[t_end(f) - w, t_end(f))`: strictly earlier, f itself excluded (flows with exactly the same `t_end` never see each
  other). Flows are processed in `t_end` order; ties are broken deterministically by (t_end, start, canonical Flow ID,
  row position) where the canonical Flow ID sorts the two `ip:port` endpoints (so the order does not depend on which end
  CICFlowMeter called "source"; the prompt's raw Flow ID would change under a swap).
- **Windows.** `windows_s` = [10, 60] s, fixed sliding windows (decaying statistics: future work).
- **Inputs** (direction-symmetric only): the two endpoint IPs (host key), the two ports (as an unordered pair), total
  packets = fwd + bwd, total bytes = fwd + bwd payload, SYN and ACK flag counts (CICFlowMeter counts flags over BOTH
  directions: `config/orientation_map.json` classifies every flag count `direction_free`, from the reviewed BasicFlow.java
  `checkFlags()` on every packet), the duration. All are integers in v2_1 (checked when this document was written), so
  every sum is exact.
- **Per host H** (every flow where H is either endpoint): `n_flows`, `n_peers` (distinct other endpoints), `n_port_pairs`
  (distinct unordered {port_A, port_B}), `sum_pkts`, `sum_bytes`, `share_short` (total packets <= `short_flow_max_pkts` =
  2), `share_syn_no_ack` (SYN count > 0 and ACK count = 0). Per flow, the endpoints' values are combined per statistic as
  `max(h(A), h(B))` and `min(h(A), h(B))`.
- **Per unordered pair {A, B}**: the same 7 + `mean_duration` (seconds). Empty window -> every statistic 0.
- **44 features** = (7 x 2 + 8) x 2 windows; names `<prefix>_<hostmax|hostmin|pair>_<stat>_<w>s`, generated from the
  config; the pinned list `config/features_v2_2_context.json` = the 70 V1 features then the 44 in that order.
- **Bounded state.** At most `max_tracked_hosts` 4,096 hosts and `max_tracked_pairs` 16,384 pairs; when a new key would
  exceed the cap the least-recently-updated key (last insert) is evicted with all its window state; evictions counted.
- **Split hygiene.** State is reset at the start of every segment = (session, split) as the dataset and its split
  definition define them (sessions are separate captures). `ctx_warmup` = 1 for a flow whose `t_end` is within the
  largest window of its segment's start; the segment start = max(split-window start, first flow start of the segment)
  (a window may open long before its first flow, D117). Sensitivity analyses exclude warm-up flows.
- **Construction checks.** Streaming == a naive O(n^2) reference, exactly, on synthetic streams (tests) and on a
  seeded 10,000-flow contiguous val slice (step B). A mismatch stops the phase. Orientation invariance is by
  construction and is tested (a flow and its forward/backward-swapped copy give identical features).

## 3. Stage 1 arms (step C), 5 seeds, Amendment 1 primary configuration

Weights `none`, step 22 hyperparameters, early stopping on a seeded 10 % inner split (`common/cl_retrain.fit`, fixed
nthread 4). **GLOBAL** = the v2_1 step 22 GLOBAL__none models (reused, not retrained). **GLOBAL_CTX** (70 + 44),
**CTX_ONLY** (44), **GLOBAL_NOFP** and **GLOBAL_CTX_NOFP** = the first two minus `fingerprint_features` = FWD / Bwd Init
Win Bytes and Fwd / Bwd Header Length (source: `results/phase3_1/initwin_ablation/summary.md`: FWD Init Win Bytes then
Fwd Header Length carry the port_scan SHAP mass; each is removed with its orientation partner).
Evaluated on full val (argmax): per-class recall / F1, non-rare macro-F1 (>= 50 val flows), flow-level false alarms
(count and FA / h, Phases 3-4 benign hours), paired differences vs GLOBAL with 95 % percentile bootstrap CIs over the 5
seeds (10,000 resamples, seed 0); repeated with warm-up flows excluded (sensitivity).
**Non-inferiority (PASS / FAIL):** PASS iff the lower 95 % CI bound of (GLOBAL_CTX - GLOBAL) non-rare macro-F1 > -0.002
AND the median over seeds of the per-seed false-alarm-count difference (GLOBAL_CTX - GLOBAL) <= 2 flows.

## 4. H-C1: orientation robustness (step D)

- **Flip test.** On val, every flow's forward / backward features are swapped with the R3 normaliser's own mapping
  (`common/orientation.swap` with an all-true mask; the normaliser's TCP-only guard applies, so non-TCP flows are
  unchanged -- reported). Context features are recomputed on the flipped stream and must be identical (checked).
  Agreement = share of flows whose predicted class is unchanged. **CTX_ONLY must agree exactly (1.0); otherwise the
  construction is broken and the phase stops.**
- **H-C1 HOLDS** iff (GLOBAL_CTX agreement - GLOBAL agreement) has a 95 % bootstrap CI lower bound > 0 over the 5 seeds
  (paired by seed), on all val **TCP** flows AND separately on val **TCP** benign flows (only TCP flows are swapped; the
  agreement of UDP and other flows is 1 by construction, reported separately and not counted as evidence). Per class
  reported.
- **Real reversals.** The diag_03 B saved flows (`results/diag_03/B_flows.csv`, hypothesis H1) are scored by each arm
  (error rate on exactly those flows; an incident of `B_incidents.csv` counts as still false if any of its contributing
  flows is still mispredicted by the same-seed arm). If the file did not exist this would be skipped (it exists).
- **Contamination (report-only).** A val benign flow is contaminated iff one of its hosts had >= 1 attack flow with
  t_end in its causal 60 s window. Share reported; each arm's FA on contaminated vs clean benign.

## 5. H-C2 and H-C3 (step E)

- **H-C2 (fingerprint independence).** Drop in port_scan recall from removing the fingerprint features:
  Δ_flow = GLOBAL_NOFP - GLOBAL, Δ_ctx = GLOBAL_CTX_NOFP - GLOBAL_CTX (per seed). **HOLDS** iff (Δ_ctx - Δ_flow) has a
  95 % bootstrap CI lower bound > 0 over the 5 seeds. Reported for every attack class.
- **H-C3 (zero-day with context).** Stage 1 misses = the Phase 5A LOAO predictions (runs in the config; loaded, sha256
  checked, not retrained): the 70-feature Stage 1, i.e. the deployed setting. Primary model of normal
  **CTX_TAIL_GLOBAL** (D165; module `common/tail_rule.py`, parameters `tail` in the config), per seed s:
  - input: the 44 context features, raw (no transform);
  - split train benign (warm-up rows kept: they only lower counts) into a fit part (`fit_share` 0.8) and a held-out part,
    seeded with s;
  - for a quantile level q, t_j(q) = the q-quantile of feature j on the fit part, taken as an **order statistic** (numpy
    method "higher": t_j is an observed value), upper tail only; a flow is flagged iff x_j > t_j(q) for ANY j (strictly
    greater). Because the thresholds are order statistics and the comparison is strict, the flags are exactly the same
    after any strictly increasing transform of the features, so no transform is needed;
  - one shared q is calibrated: the smallest q of the pinned grid (`q_grid`: 241 values from 0.99 to 0.999999,
    log-spaced in 1 - q) whose flag rate on the held-out part is <= `target_flag_rate` 0.001; the chosen q, the held-out
    flag rate and every t_j are reported; for each flagged flow the features that fired and x_j / t_j (top firing
    features per class reported).
  Primary metric as Phase 5A: miss-recall over eligible (k, seed) pairs (non-rare held-out classes, >= 30 misses), equal
  weight per pair, 95 % bootstrap CI (10,000, seed 0). **H-C3 HOLDS** iff the lower CI bound of mean miss-recall
  >= 0.5 AND the upper 95 % bootstrap CI bound (over the 5 seeds) of its val FA / h <= the Phase 5A GLOBAL_NORMAL mean
  FA / h (from the 5A step 38 eval). FA counts, benign hours, contaminated vs clean reported.
- Report-only (never in the verdict): **CTX_IF_GLOBAL** = the pinned Phase 5A recipe (`config/v2_phase5.json`
  normal_model: sign(x) log1p|x|, IsolationForest n_estimators 200, max_samples min(256, n), max_features 1.0, no
  bootstrap, random_state = seed, fixed n_jobs, anomaly = -score_samples, own-train 99.9th-percentile threshold) on the
  44 context features -- it shows whether a CTX_TAIL result comes from the detector; **CTX_TAIL_PER_GROUP** (the same
  rule per group, min_group_benign 10,000, smaller groups -> the global rule, logged) -- **report-only, not a routing
  claim (D163)**; **FLOWCTX_TAIL_GLOBAL** (the tail rule on 70 + 44); detector alone on all held-out flows; combined
  system (Stage 1 alert OR flag) recall and FA; drift flag rate per group; the out-of-range diagnostic = share of
  held-out attack flows (and of val benign flows) with at least one context feature above the train-benign maximum.
  udp_flood (rare) is report-only, as in 5A.

## 6. Part B: TreeSHAP perturbation check (step F)

- Models: GLOBAL s0 (the deployed model; deployed temperature from its registry calibrator) and GLOBAL_CTX s0
  (temperature fitted on its own inner split by `common/cl_retrain.fit` -> `phase2_metrics.fit_temperature`).
- Sample: per predicted non-benign class up to 1,000 val alerts, plus 1,000 benign predictions (seeded, without
  replacement). TreeSHAP = XGBoost `pred_contribs` for the predicted class. Perturb the **top-k** (k = 5, largest |SHAP|)
  features to the per-feature train-benign median; compare with **random-k** (5 seeded draws of k features outside the
  top-k; drops averaged) and **bottom-k** (smallest |SHAP|). Drop = predicted class's calibrated probability before -
  after; flip = argmax changes.
- **FAITHFUL** (per predicted class, per model) iff mean(top-k drop - random-k drop) has a 95 % bootstrap CI lower
  bound > 0 (bootstrap over flows, 10,000 resamples, seed 0); otherwise NOT_FAITHFUL.
- Disclosed: median replacement can create out-of-distribution rows; the result describes the model, not the attack.
- Report-only: share of |SHAP| mass on context vs flow features per class (GLOBAL_CTX); share of flows with a
  fingerprint feature in the top-5.

## 7. Outputs and guards

results/phase5b/<step>/ (summary.md, json, manifests; run.log git-ignored), figures and the phase summary under
results/phase5b/; dry runs under results/phase5b/<step>/dry_run/. The dataset `v2_2_context` (train + val parquet,
manifest, split definition copied byte-for-byte from v2_1) is written once; the dataset index of `21_version_dataset.py`
is not touched. Every script runs `verify_v2_lock()` at start and end and logs the sha256 of config/config.py and
config/class_map.json.
