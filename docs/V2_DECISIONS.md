# V2 decisions log

One line per choice the Phase 2 prompt / `docs/V2_PREREG_PHASE2.md` does not spell out: **what** -- why.

## Phase 2 (offline multiclass, steps 22-26)

### Environment and repository
- D01 **No `shap` in the lgids env: TreeSHAP via XGBoost `pred_contribs=True`** -- the prompt's named fallback; exact TreeSHAP values (same algorithm), no new dependency; additivity (contributions + bias == margin) checked in every run (max error 1.9e-05).
- D02 **No `cryptography` in the lgids env (py3.11; the conda cache only has a py3.13 build): `common/registry.py` uses `cryptography` when importable, else the RFC 8032 section 6 Ed25519 reference algorithm** -- no network install / environment change (environment.yml stays as frozen); Ed25519 is deterministic, so both give byte-identical signatures; passes the RFC 8032 test vectors 1-3 and matched the system python3's cryptography 41.0.7 on 60/60 random keys + messages (public key, signature, cross-verification).
- D03 **Phase 2 scripts never call git** (Phase 1's 20 / 21 call `git rev-parse`) -- guard 2; run manifests record the sha256 of every code / config file used instead of a commit id.
- D04 **`common/schemas.py` gains the pin `PREREG_PHASE2_SHA256` (+ an LF check) and `verify_v2_lock()` checks it** -- step 0; schemas.py's own sha256 therefore differs from the value recorded in the Phase 1 dataset manifest (that record matched the Phase 1 commit and stays valid for it).
- D05 **Full runs write `results/<step>/` (refused if it exists); dry runs `results/<step>/dry_run/<run_id>/` (gitignored by `results/**/dry_run/`); data / models / calibrators / SHAP arrays in `~/lgids_cache/v2/<kind>/<run_id>/` (`<kind>_dry_run` for dry runs)** -- Phase 1's convention; nothing is overwritten.
- D06 **Run ids are UTC stamps `YYYYmmddTHHMMSSZ`** -- Phase 1 convention (20261120T133357Z).
- D07 **Downstream scripts take the upstream run id explicitly or default to the full run recorded in `results/<upstream>/run_meta.json`, whose manifest sha256 is re-checked** -- no "latest" guessing.
- D08 **Every Phase 2 script refuses an upstream run made with a different config / prereg / class map / feature list** -- the chain of runs is one configuration.
- D09 **A failed run is kept as `<run_id>.FAILED` (never deleted) with its report** -- guard 3; no full run failed.
- D10 **Dry runs: a seeded 5 % stratified sample (strata = group x label_id; every stratum keeps >= 1 row) of train and, with the same rule, of val** -- config `dry_run`; the dry upstream run ids are passed explicitly.
- D11 **The test split is never opened, hashed or stat'ed in Phase 2: `load_split` refuses any split but train / val and any file named test; a static test scans every Phase 2 script for `test.parquet` / direct parquet reads** -- guard 5.
- D12 **`.gitignore` gains `keys/`, `*.key`, `*.pem`, `*_ed25519*`, `*.ubj`, `*.npz`** -- keys and artifacts already live outside the repo; belt and braces.

### Training (step 22)
- D13 **Groups are read from the train `group` column; specialists = every group except `fallback_group` (config, "GEN"); a group without a specialist routes to GLOBAL** -- data-agnostic rule.
- D14 **Hyperparameters = V1 step 9's (XGBoost 3.4.2 library defaults), written out explicitly: eta 0.3, max_depth 6, min_child_weight 1, subsample 1, colsample_bytree 1, lambda 1, alpha 0, gamma 0, max_bin 256, hist, 100 rounds (V1's n_estimators); V1's scale_pos_weight is replaced by the pre-registered class weights; native `xgb.train`** -- comparability with V1.
- D15 **Early stopping: patience 10 rounds on the weighted mlogloss of the inner split; the model is fitted on the remaining 90 % (no refit on 100 %) and saved sliced at the best iteration** -- "never on val" and a saved model that needs no iteration_range; on the full data the best iteration was 10-75 (mean per spec in results/22).
- D16 **Inner split: per class round(10 % x n_c) rows, seeded by the model seed** -- stratified, deterministic; udp_flood (95 train rows) gets 10 inner rows.
- D17 **Class weights are computed on the whole training set (before the inner split) and applied to both the fit and the inner rows** -- the early-stopping loss is weighted like the training loss.
- D18 **A1 "fully balanced" = sklearn 'balanced': N / (K_present x n_c) for every present class, benign included** -- the standard definition.
- D19 **A1 applies to the three primary models (both specialists and GLOBAL), all seeds** -- "every primary model".
- D20 **A3 uses the `device_category` column; all 8 train categories have >= 100 benign train rows, so none fell back to GLOBAL; model ids are slugged category names** -- prereg rule.

### Evaluation (step 23)
- D21 **Each model is evaluated on its own val set (its training pooling rule applied to val); systems (ROUTED, FLAT_GLOBAL, ROUTED_A1_*, ROUTED_A2, ROUTED_A3) on every val row; per-group results by the flow's own group** -- what each model is responsible for vs what the deployed system sees.
- D22 **Headline = ROUTED (primary routing) on the full val split** -- it is the system that would be deployed.
- D23 **Macro-F1 "all" = classes with >= 1 val flow in the evaluation set; "non-rare" = classes with >= min_val_flows; a 0-support class is N/A; precision of a class with support but no predictions = 0** -- prereg wording; sklearn's zero_division=0 convention.
- D24 **False-alarm denominator per evaluation set: per session, active segments of the dataset's val flow starts (pause > 300 s ends one; end = last start + 1 s), keeping segments with >= 1 benign flow of the evaluated rows. Full val: 1.9528 h vs V1's 1.9676 h** -- "from timestamps", data-agnostic; V1 also counted flows its filter removed, hence 0.75 % fewer hours here.
- D25 **False alarms / hour: seed 0 with an exact (Garwood) Poisson CI, plus mean +- t-CI over seeds; rare-class recall: Clopper-Pearson CI of seed 0, plus the mean recall over seeds** -- counts of one model are Poisson / binomial; the seeds are not independent samples of the val rows.
- D26 **t-CIs (t with 4 df) are not clipped to [0, 1]** -- shown as computed; a CI beyond 1 signals seed-to-seed instability.
- D27 **Latency: `inplace_predict`, 1 thread; batch 1 = median of 1000 single-row calls; batch 1024 = median of 20 calls / 1024; labelled "dev machine"** -- not a Pi number.
- D28 **V1 comparison: V1's FINAL system (step 10 G1 / G2 / GLOBAL joblib files, sha256 == prereg, V1's routing from the prereg) scored on the V2 val rows (row-identical to V1 val, Phase 1), read-only; sanity check: V1 FINAL at its prereg T_house reproduces the prereg's 2 val false alarms (passed)** -- same rows, same artifacts, proof that loading / routing is right.
- D29 **Binary-collapse figure uses dots + CI, not bars** -- every value sits next to 1.0; bars on a truncated axis would mislead.

### Calibration (step 24)
- D30 **Calibrators are saved in their own run folder (`~/lgids_cache/v2/calibrators/<run>/<model key>.temperature.json`, carrying the model file's sha256), not written into the step 22 folder** -- run folders stay immutable; the registry pairs model and calibrator.
- D31 **Temperature: bounded Brent search on log T in [0.05, 20]; NLL computed relative to the true-class logit with log1p** -- a unit test showed the naive log-sum-exp rounds the loss of very confident rows to exactly 0 and flattens the objective; fixed before any full calibration run.
- D32 **Cross-fit folds stratified by class, seeded by the model seed; the reported numbers are the mean over the 2 held-out folds** -- no row is scored by a temperature fitted on it.
- D33 **ECE: 15 equal-width bins on the top-label confidence; per-class ECE = one-vs-rest; Brier = mean over rows of sum_c (p_c - 1[y = c])^2** -- standard definitions.

### Explanations (step 25)
- D34 **SHAP sample seed = config seeds[0]; rows from each model's own val set; beeswarm plots up to 1,500 of the sampled rows, colour = the flow's within-feature value rank** -- readable plots, every class represented.
- D35 **Leakage pattern = V1 08's IDENTITY_RE + "flow id" + "session", plus every non-feature column name of the dataset** -- same rule V1 used to build the feature set.
- D36 **The > 50 % dominance flag is computed per model and per class output** -- a class-specific shortcut would hide in the model average.

### Registry (step 26)
- D37 **Entry id `<model_id>__s<seed>__<train run>`; model + calibrator copied (not moved); manifest = canonical JSON (sort_keys), Ed25519-signed; states in an append-only, signed, hash-chained `state.log`; only candidate -> approved -> promoted, via `26_model_registry.py transition` (author only, never run by the pipeline)** -- any edit to an entry or its history is detected.
- D38 **Key = 32-byte seed in `~/lgids_cache/v2/keys/registry_ed25519.key` (file 600, dir 700) + public key; `ensure_keys` refuses a key dir inside the repo; the key is never printed** -- guard 6.

### TODO / open items
- T1 **Published-method baselines** -- out of scope for this run (prompt); to implement in a later phase against the same val protocol.
- T2 **`pip install cryptography` into the lgids env** -- then the registry uses the library path (identical signatures, D02).
- T3 **port_scan -> syn_flood confusion on G1 val flows (43 % of G1's val port scans under SPEC_G1, identical in all 5 seeds; GLOBAL shows it in some seeds)** -- reported, not acted on: the primary configuration is fixed in advance and ablations select nothing.
- T4 **GEN val holds 291 benign flows and no attacks** -- A2 can only be compared on false alarms; GEN attack detection is untestable on this dataset.
- T5 **port_scan relies on FWD Init Win Bytes (64 % / 61 % of the port_scan output's mean |SHAP| in SPEC_G1 / GLOBAL)** -- a TCP-stack property of the attacking host; a different scanner host may not share it. To probe in the streaming / new-capture phase.

## Phase 2 closeout (orientation normaliser R3 -> v2_1_oriented -> Amendment 1 -> re-run 22-26)

### Gate, map, normaliser
- D39 **The R3 gate is its own read-only script (`diagnostics/orient_gate_r3.py`); its first full run (`results/orient_gate/`, run 20261121T074211Z) printed the % columns over the split's rows instead of the cell's; the corrected rerun is `results/orient_gate/rerun_pct_fix/` (run 20261121T074502Z, `--rerun-tag`), the first run is kept** -- guard 3 (never overwrite); flag COUNTS and every gate decision are identical in both; 21b cross-checks its flips against the corrected run.
- D40 **`config/orientation_map.json` = the diag_02 proposal with every per-feature entry, identity, dropped-feature notes, counts and limits unchanged; changed: `status`, `rule` (R3 adopted; R1 / R2 kept under `rule.history`); added: `map_version`, `copied_from` (proposal sha256), and a `machine` block (rule clauses, `protocol_guard`, count columns, one handler per derived / unpaired feature with its columns, identity pairs, Flow ID format, flag column, unchanged metadata columns)** -- "everything comes from the map" needs machine-readable entries; the proposal's prose is kept verbatim beside them. Step A forced no content change.
- D41 **`swap()` applies `machine.protocol_guard` (Protocol == 6) to whatever mask it is given; NaN / non-numeric in any rule column -> not reversed; `normalise()` refuses a frame / flow that already has `orientation_flipped`** -- "never touches non-TCP rows" holds even for a caller that bypasses the rule; double normalisation is impossible by construction (and a swapped row no longer satisfies R3 anyway).
- D42 **The dict API is pure Python (no pandas / numpy) with its own scalar handlers; equality with the vectorised API is a test on 306 random + R3 rows** -- the Pi runtime normalises one flow at a time.

### Dataset v2_1_oriented (21b)
- D43 **21b reads v2_0 through `load_split` with config/v2_phase2.json (train + val only) and writes `~/lgids_cache/v2/datasets/v2_1_oriented/` via a `.partial` dir renamed at the end (refused if it exists); dry runs go to `datasets_dry_run/v2_1_oriented__<run_id>/`** -- same atomic, never-overwrite pattern as step 21.
- D44 **`validate_frame` cannot pass on a dataset parquet (its layout is the dataset's, not V1's raw-CSV contract: 10 extra columns, 5 V1 meta / label columns absent), so 21b requires (i) identical check results on the source and the normalised rows and (ii) the content checks (features present / ordered / numeric, NaN-inf policy, blank-MAC rule) to pass; the 3 layout checks fail identically on both and are listed in the summary** -- the question is whether normalising introduced a problem.
- D45 **The shared `datasets/index.jsonl` is not appended for v2_1 (the dataset manifest is the record)** -- guard 3, leave existing files untouched. **The manifest's `counts` / `caps` are copied from v2_0 for train / val only; `content_sha256` is 21b's own definition (per-column digests, stated in the manifest), not 08b's ColumnHasher.**

### Running 22-26 on a new config
- D46 **`--config <file>` on 22-26 (`common/phase2_config.config_from_arg`; default = config/v2_phase2.json); the optional config key `results_subdir` sends a config's runs to `results/<subdir>/<step>/` (v2_1 -> `results/v2_1/22` ... `26`) and upstream runs are looked up there; cache run dirs keep their kinds (`models/<run_id>` ...), unique by run id** -- the v2_0 runs in `results/22-26` stay untouched and the new chain cannot pick a v2_0 run by accident.
- D47 **Optional config keys `prereg_amendments`, `orientation`, `primary_selection`, `results_subdir` are validated only when present; `base_manifest` records the real config path, the amendment files' sha256 and the orientation map's sha256, and adds the config / amendment / `common/amendment.py` / `common/orientation.py` / map to `code_sha256` only when they are used** -- with config/v2_phase2.json every manifest field and the code list are as before (tested).
- D48 **Amendment 1 selection: "false alarms (5-seed mean)" = the mean of the per-seed false-alarm COUNTS on the full val split (the benign-hours denominator is the same for every weighting, so counts and per-hour rates rank identically); if `none` is not among the tied, the first tied in the order none, sqrt, balanced** -- the amendment fixes both before any v2_1 result exists.
- D49 **Under the amendment 23 adds the systems `FLAT_GLOBAL_A1_<mode>` (GLOBAL of that weighting on every flow) so the chosen weighting has a flat baseline with the same metrics; it writes the decision table + the chosen ROUTED / FLAT_GLOBAL headline at the top of its summary, into its manifest and metrics_summary.json; its pre-existing figures are unchanged (they still show the sqrt ROUTED and every system)** -- minimal change to 23; step F has the chosen-vs-v2_0 figures.
- D50 **24 still calibrates every model; under the amendment 24 / 25 / 26 read the choice from the step 23 run (`--eval-run`, default the full run) and use the chosen weighting's models (reliability figures, SHAP, registry); 26 tags the new entries with the amendment and orientation-map sha256 and states in `runtime_contract` that flows are normalised first** -- one choice, made once, in 23.
- D51 **A2 and A3 keep sqrt weights** -- the amendment re-weights the specialists + GLOBAL only.
- D52 **The v2_1 registry entries live in the same registry root as the v2_0 candidates (entry ids carry the step 22 run id, so nothing collides); no state of any entry is changed** -- guard 6.

### Comparison (step F)
- D53 **`diagnostics/phase2_v2_1_compare.py` compares 2 weightings (sqrt = pre-registered, the Amendment 1 choice) x 2 datasets, so the effect of the data and of the weighting can be told apart; FLAT_GLOBAL of a weighting = the GLOBAL model of that weighting on every flow (its step 23 model entity, identical to the flat system); ROUTED - FLAT_GLOBAL is paired by seed (t-CI, 4 df)** -- a 2-row comparison would confound the two changes.
- D55 **The first step F run (`results/phase2_v2_1_compare/`, run 20261121T081112Z) had overlapping labels in two figures (x tick labels; ROUTED / FLAT_GLOBAL values side by side); the figure-fix rerun (`results/phase2_v2_1_compare/rerun_fig_fix/`, run 20261121T081216Z, `--rerun-tag`) puts ROUTED labels above and FLAT_GLOBAL labels below their points, on a surface-coloured box; numbers identical (diffed), first run kept** -- guard 3; the prompt asks for non-overlapping labels.
- D56 **Amendment 1 outcome on v2_1 (step 23 run 20261121T080839Z): all three weightings within 0.005 of the best non-rare macro-F1 (none 0.99742, sqrt 0.99711, balanced 0.99689); fewest mean false alarms `none` (3.4 vs 17.6 sqrt, 36.4 balanced) -> primary = `none`; no tie-break used** -- recorded here because the rule, not a person, made the choice.
- D54 **The FWD Init Win Bytes SHAP share is recomputed for every weighting x dataset with step 25's own helpers (same seeded per-class sample) and cross-checked against the two step 25 runs for the models they covered** -- step 25 only explains the primary weighting of its run.
