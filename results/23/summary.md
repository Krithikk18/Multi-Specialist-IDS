# Step 23 -- evaluation (VAL only) -- PASS

- run `20261120T183529Z`, models from step 22 run `20261120T144232Z`, dataset `v2_0_v1equiv`, config `ee4bfdea8b1cf270...`, prereg `ba6993e98b96a575...`, seeds [0, 1, 2, 3, 4]
- val rows 157,558; benign val hours (all benign val flows, 08 active-segment rule) 1.9528 h (V1 manifest: 1.9676 h, from all flows of the files)
- CIs: mean +- 95 % t-CI over the 5 seeds unless stated; false alarms / hour: seed 0 with an exact Poisson 95 % CI; rare-class recall: Clopper-Pearson 95 % (seed 0).

## Headline: ROUTED (primary) on the full val split

- macro-F1 (all classes with val flows): **0.8360 [0.7939, 0.8781]**
- macro-F1 (non-rare classes, >= 50 val flows): **0.9579 [0.9578, 0.9580]**
- weighted F1 0.9761 [0.9759, 0.9762], MCC 0.9557 [0.9554, 0.9560], balanced accuracy 0.8530 [0.8377, 0.8683]
- false alarms / hour (seed 0): **5.121** (10 FP / 1.953 h; Poisson 95 % CI [2.456, 9.418]); over seeds 5.735 [3.656, 7.815]

| class | val flows | precision | recall | F1 | recall CP 95 % (seed 0) | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| benign | 39,185 | 0.9994 [0.9992, 0.9995] | 0.9997 [0.9996, 0.9998] | 0.9995 [0.9994, 0.9996] | [0.9995, 0.9999] | 0.9999 [0.9999, 1.0000] | 0.9999 [0.9998, 1.0000] |
| syn_flood | 100,177 | 0.9674 [0.9674, 0.9674] | 0.9975 [0.9973, 0.9977] | 0.9822 [0.9821, 0.9823] | [0.9972, 0.9979] | 0.9998 [0.9998, 0.9999] | 0.9999 [0.9999, 0.9999] |
| udp_flood (rare) | 17 | 0.4002 [0.2112, 0.5891] | 0.6000 [0.5389, 0.6611] | 0.4703 [0.3021, 0.6385] | [0.3833, 0.8579] | 0.9654 [0.9358, 0.9951] | 0.5323 [0.4710, 0.5936] |
| port_scan | 18,179 | 0.9852 [0.9847, 0.9857] | 0.8148 [0.8147, 0.8148] | 0.8919 [0.8917, 0.8921] | [0.8091, 0.8204] | 0.9997 [0.9997, 0.9997] | 0.9975 [0.9974, 0.9977] |

### ROUTED per group of the flow

| group | rows | macro-F1 all | macro-F1 non-rare | false alarms (seed 0) | FA / h (seed 0) |
|---|---|---|---|---|---|
| G1 | 93,716 | 0.7953 [0.7524, 0.8381] | 0.8915 [0.8913, 0.8918] | 6 | 3.073 |
| G2 | 63,551 | 0.9997 [0.9995, 1.0000] | 0.9997 [0.9995, 1.0000] | 4 | 2.048 |
| GEN | 291 | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] | 0 | 0.000 |

## Systems and ablations (full val; reported, never used to select)

| system | note | macro-F1 all | macro-F1 non-rare | MCC | FA count seed 0 | FA / h seed 0 [Poisson CI] |
|---|---|---|---|---|---|---|
| ROUTED | primary | 0.8360 [0.7939, 0.8781] | 0.9579 [0.9578, 0.9580] | 0.9557 [0.9554, 0.9560] | 10 | 5.121 [2.456, 9.418] |
| FLAT_GLOBAL | flat multiclass baseline | 0.8650 [0.8327, 0.8974] | 0.9853 [0.9638, 1.0067] | 0.9840 [0.9615, 1.0065] | 7 | 3.585 [1.441, 7.386] |
| ROUTED_A1_none | A1 weights none | 0.8962 [0.8661, 0.9264] | 0.9806 [0.9517, 1.0096] | 0.9812 [0.9543, 1.0081] | 3 | 1.536 [0.317, 4.490] |
| ROUTED_A1_balanced | A1 weights balanced | 0.8004 [0.7692, 0.8315] | 0.9892 [0.9678, 1.0107] | 0.9875 [0.9650, 1.0101] | 30 | 15.363 [10.365, 21.931] |
| ROUTED_A2 | A2: GEN -> GENSPEC_GEN__sqrt | 0.8282 [0.7872, 0.8691] | 0.9579 [0.9578, 0.9580] | 0.9557 [0.9554, 0.9560] | 12 | 6.145 [3.175, 10.734] |
| ROUTED_A3 | A3: device category -> category model, else GLOBAL | 0.7824 [0.7798, 0.7851] | 0.9752 [0.9681, 0.9824] | 0.9726 [0.9655, 0.9797] | 58 | 29.701 [22.553, 38.396] |

### A2: GEN val benign false alarms (GLOBAL vs GEN specialist)

- GEN val benign flows: 291; their benign hours 1.953 h

| model | FP per seed | mean FP | FA / h seed 0 [Poisson CI] |
|---|---|---|---|
| GLOBAL__sqrt | [0, 0, 0, 0, 0] | 0.0 | 0.000 [0.000, 1.889] |
| GENSPEC_GEN__sqrt | [2, 2, 4, 7, 2] | 3.4 | 1.024 [0.124, 3.700] |

## Binary collapse vs V1 (frozen step 10 FINAL; same val rows; read-only)

- thresholds at <= 2 val FP are chosen and read on val (same-set, optimistic), V1's rule; V1 at its prereg T_house 0.568308: 2 FP, DR 0.99984

| metric | V1 FINAL | V2 ROUTED (mean [t-CI]) |
|---|---|---|
| pr_auc | 0.999999 | 0.99997 [0.99995, 0.99999] |
| roc_auc | 0.999996 | 0.99995 [0.99994, 0.99996] |
| dr_at_0.5 | 0.999839 | 0.99981 [0.99978, 0.99984] |
| fp_at_0.5 | 3 | 11.20000 [7.13841, 15.26159] |
| fa_per_hour_at_0.5 | 1.53627 | 5.73542 [3.65552, 7.81532] |
| thr_le2fp | 0.568308 | 0.99722 [0.99484, 0.99960] |
| dr_at_le2fp | 0.999839 | 0.96780 [0.96561, 0.97000] |
| fp_at_le2fp | 2 | 2.00000 [2.00000, 2.00000] |

## Cost per model (seed 0; 1 thread; dev machine, NOT the Pi)

| model | ms / flow batch 1 | ms / flow batch 1024 | size on disk (bytes) |
|---|---|---|---|
| CAT_Audio__sqrt | 0.0806 | 0.00164 | 194,834 |
| CAT_Camera__sqrt | 0.1062 | 0.00322 | 403,755 |
| CAT_Home_Automation__sqrt | 0.1775 | 0.00126 | 215,581 |
| CAT_Hub__sqrt | 0.0927 | 0.00235 | 262,117 |
| CAT_Lighting__sqrt | 0.0849 | 0.00200 | 220,198 |
| CAT_Power_Outlet__sqrt | 0.0849 | 0.00171 | 189,330 |
| CAT_Unidentified_Amazon__sqrt | 0.0787 | 0.00150 | 170,387 |
| CAT_Unidentified_Espressif__sqrt | 0.0855 | 0.00217 | 241,786 |
| GENSPEC_GEN__sqrt | 0.1026 | 0.00313 | 362,436 |
| GLOBAL__balanced | 0.0725 | 0.00069 | 98,666 |
| GLOBAL__none | 0.0957 | 0.00319 | 432,595 |
| GLOBAL__sqrt | 0.0912 | 0.00139 | 213,671 |
| SPEC_G1__balanced | 0.0830 | 0.00237 | 338,540 |
| SPEC_G1__none | 0.0875 | 0.00290 | 395,262 |
| SPEC_G1__sqrt | 0.0833 | 0.00219 | 243,420 |
| SPEC_G2__balanced | 0.0712 | 0.00078 | 101,947 |
| SPEC_G2__none | 0.0956 | 0.00339 | 401,358 |
| SPEC_G2__sqrt | 0.1633 | 0.00160 | 280,110 |

## Figures

- `figures/confusion_per_group.png` -- ROUTED row-normalised confusion matrices, all val and per group of the flow (mean over seeds).
- `figures/per_class_prf.png` -- ROUTED per-class precision / recall / F1 with 95 % t-CI error bars; rare classes marked.
- `figures/binary_collapse_vs_v1.png` -- V2 ROUTED as a binary detector (1 - P(benign)) vs V1's frozen binary FINAL on the same val rows.
- `figures/macro_f1_dotplot.png` -- both macro-F1s with t-CIs for every system, model and ablation, each on its own val set.
- `figures/false_alarms_per_hour.png` -- benign val false alarms per hour, seed 0 with exact Poisson CI, other seeds as ticks.
- `figures/pr_curves_per_class.png` -- one-vs-rest PR curves per class, ROUTED seed 0, with the prevalence line.
- `figures/macro_f1_vs_latency.png` -- macro-F1 vs single-flow latency per model, point area ~ size on disk.

## Warnings / caveats

- rare classes on the full val split (< 50 flows): udp_flood (17)
- group G2: classes with 0 val flows (N/A, excluded from its macro-F1): ['udp_flood']
- group GEN: classes with 0 val flows (N/A, excluded from its macro-F1): ['syn_flood', 'udp_flood', 'port_scan']
