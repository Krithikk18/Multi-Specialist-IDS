# Step 23 -- evaluation (VAL only) -- PASS

- run `20261121T080839Z`, models from step 22 run `20261121T075821Z`, dataset `v2_1_oriented`, config `e9dc754e9379d62e...`, prereg `ba6993e98b96a575...`, seeds [0, 1, 2, 3, 4]
- val rows 157,558; benign val hours (all benign val flows, 08 active-segment rule) 1.9528 h (V1 manifest: 1.9676 h, from all flows of the files)
- CIs: mean +- 95 % t-CI over the 5 seeds unless stated; false alarms / hour: seed 0 with an exact Poisson 95 % CI; rare-class recall: Clopper-Pearson 95 % (seed 0).

## Primary configuration chosen by Amendment 1 (section 2)

- rule: ROUTED non-rare macro-F1 (5-seed mean) within 0.005 of the best -> fewest ROUTED false alarms (5-seed mean) -> ties: first of ['none', 'sqrt', 'balanced']

| weighting | ROUTED system | non-rare macro-F1 mean [t-CI] | all-class macro-F1 mean | within tolerance | false alarms per seed | mean | FA / h mean |
|---|---|---|---|---|---|---|---|
| sqrt | ROUTED | 0.99711 [0.99694, 0.99729] | 0.84984 | yes | [15, 28, 14, 19, 12] | 17.6 | 9.013 |
| none | ROUTED_A1_none | 0.99742 [0.99736, 0.99747] | 0.91017 | yes | [4, 3, 3, 4, 3] | 3.4 | 1.741 |
| balanced | ROUTED_A1_balanced | 0.99689 [0.99673, 0.99704] | 0.80656 | yes | [31, 34, 28, 24, 65] | 36.4 | 18.640 |

- best non-rare macro-F1 mean 0.99742; within tolerance ['sqrt', 'none', 'balanced']; fewest mean false alarms 3.4 -> ['none']
- **chosen: `none`** -> primary system `ROUTED_A1_none`, flat baseline `FLAT_GLOBAL_A1_none`; 24 / 25 / 26 use the `A1_none` models

### ROUTED_A1_none (chosen weighting) on the full val split

- macro-F1 all **0.9102 [0.8971, 0.9232]**, non-rare **0.9974 [0.9974, 0.9975]**; false alarms / h over seeds 1.741 [1.393, 2.089]; seed 0 2.048 (4 FP / 1.953 h; Poisson 95 % CI [0.558, 5.245])

| class | val flows | precision | recall | F1 |
|---|---|---|---|---|
| benign | 39,185 | 0.9993 [0.9992, 0.9993] | 0.9999 [0.9999, 0.9999] | 0.9996 [0.9996, 0.9996] |
| syn_flood | 100,177 | 0.9999 [0.9999, 0.9999] | 0.9977 [0.9977, 0.9978] | 0.9988 [0.9988, 0.9988] |
| udp_flood (rare) | 17 | 0.7695 [0.6760, 0.8631] | 0.5647 [0.4994, 0.6300] | 0.6484 [0.5962, 0.7006] |
| port_scan | 18,179 | 0.9886 [0.9883, 0.9889] | 0.9992 [0.9992, 0.9992] | 0.9939 [0.9937, 0.9940] |

### FLAT_GLOBAL_A1_none (chosen weighting) on the full val split

- macro-F1 all **0.9144 [0.8984, 0.9305]**, non-rare **0.9978 [0.9972, 0.9984]**; false alarms / h over seeds 1.024 [0.575, 1.474]; seed 0 1.024 (2 FP / 1.953 h; Poisson 95 % CI [0.124, 3.700])

| class | val flows | precision | recall | F1 |
|---|---|---|---|---|
| benign | 39,185 | 0.9993 [0.9991, 0.9995] | 0.9999 [0.9999, 1.0000] | 0.9996 [0.9995, 0.9997] |
| syn_flood | 100,177 | 0.9999 [0.9999, 0.9999] | 0.9980 [0.9975, 0.9986] | 0.9989 [0.9987, 0.9992] |
| udp_flood (rare) | 17 | 0.7484 [0.6298, 0.8670] | 0.6000 [0.5673, 0.6327] | 0.6643 [0.6005, 0.7281] |
| port_scan | 18,179 | 0.9905 [0.9876, 0.9933] | 0.9992 [0.9992, 0.9992] | 0.9948 [0.9934, 0.9962] |

## ROUTED with the originally pre-registered weighting (sqrt) on the full val split; see the Amendment 1 section above for the chosen primary

- macro-F1 (all classes with val flows): **0.8498 [0.8268, 0.8729]**
- macro-F1 (non-rare classes, >= 50 val flows): **0.9971 [0.9969, 0.9973]**
- weighted F1 0.9981 [0.9979, 0.9983], MCC 0.9963 [0.9960, 0.9967], balanced accuracy 0.8990 [0.8909, 0.9072]
- false alarms / hour (seed 0): **7.681** (15 FP / 1.953 h; Poisson 95 % CI [4.299, 12.669]); over seeds 9.013 [4.976, 13.049]

| class | val flows | precision | recall | F1 | recall CP 95 % (seed 0) | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| benign | 39,185 | 0.9991 [0.9984, 0.9997] | 0.9996 [0.9993, 0.9998] | 0.9993 [0.9990, 0.9996] | [0.9994, 0.9998] | 0.9999 [0.9999, 1.0000] | 0.9999 [0.9998, 0.9999] |
| syn_flood | 100,177 | 0.9999 [0.9998, 0.9999] | 0.9974 [0.9971, 0.9977] | 0.9986 [0.9985, 0.9988] | [0.9973, 0.9979] | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] |
| udp_flood (rare) | 17 | 0.3161 [0.2118, 0.4205] | 0.6000 [0.5673, 0.6327] | 0.4080 [0.3160, 0.5001] | [0.3292, 0.8156] | 0.9635 [0.9333, 0.9937] | 0.5071 [0.4405, 0.5736] |
| port_scan | 18,179 | 0.9877 [0.9873, 0.9881] | 0.9992 [0.9992, 0.9992] | 0.9934 [0.9932, 0.9936] | [0.9987, 0.9996] | 1.0000 [1.0000, 1.0000] | 1.0000 [0.9999, 1.0000] |

### ROUTED per group of the flow

| group | rows | macro-F1 all | macro-F1 non-rare | false alarms (seed 0) | FA / h (seed 0) |
|---|---|---|---|---|---|
| G1 | 93,716 | 0.8539 [0.8281, 0.8797] | 0.9938 [0.9935, 0.9941] | 11 | 5.633 |
| G2 | 63,551 | 0.9997 [0.9996, 0.9999] | 0.9997 [0.9996, 0.9999] | 4 | 2.048 |
| GEN | 291 | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] | 0 | 0.000 |

## Systems and ablations (full val; A1 used to select the primary weighting under Amendment 1, the rest reported only)

| system | note | macro-F1 all | macro-F1 non-rare | MCC | FA count seed 0 | FA / h seed 0 [Poisson CI] |
|---|---|---|---|---|---|---|
| ROUTED | primary | 0.8498 [0.8268, 0.8729] | 0.9971 [0.9969, 0.9973] | 0.9963 [0.9960, 0.9967] | 15 | 7.681 [4.299, 12.669] |
| FLAT_GLOBAL | flat multiclass baseline | 0.8783 [0.8478, 0.9088] | 0.9975 [0.9974, 0.9975] | 0.9968 [0.9967, 0.9970] | 10 | 5.121 [2.456, 9.418] |
| ROUTED_A1_none | A1 weights none | 0.9102 [0.8971, 0.9232] | 0.9974 [0.9974, 0.9975] | 0.9969 [0.9968, 0.9970] | 4 | 2.048 [0.558, 5.245] |
| ROUTED_A1_balanced | A1 weights balanced | 0.8066 [0.7864, 0.8268] | 0.9969 [0.9967, 0.9970] | 0.9955 [0.9951, 0.9959] | 31 | 15.875 [10.786, 22.533] |
| ROUTED_A2 | A2: GEN -> GENSPEC_GEN__sqrt | 0.8434 [0.8216, 0.8653] | 0.9971 [0.9969, 0.9973] | 0.9963 [0.9959, 0.9966] | 17 | 8.706 [5.071, 13.938] |
| ROUTED_A3 | A3: device category -> category model, else GLOBAL | 0.7963 [0.7939, 0.7987] | 0.9975 [0.9973, 0.9977] | 0.9965 [0.9963, 0.9967] | 57 | 29.189 [22.108, 37.818] |
| FLAT_GLOBAL_A1_none | flat baseline, A1 weights none (Amendment 1) | 0.9144 [0.8984, 0.9305] | 0.9978 [0.9972, 0.9984] | 0.9973 [0.9967, 0.9980] | 2 | 1.024 [0.124, 3.700] |
| FLAT_GLOBAL_A1_balanced | flat baseline, A1 weights balanced (Amendment 1) | 0.7998 [0.7873, 0.8122] | 0.9971 [0.9967, 0.9974] | 0.9956 [0.9949, 0.9962] | 32 | 16.387 [11.209, 23.133] |

### A2: GEN val benign false alarms (GLOBAL vs GEN specialist)

- GEN val benign flows: 291; their benign hours 1.953 h

| model | FP per seed | mean FP | FA / h seed 0 [Poisson CI] |
|---|---|---|---|
| GLOBAL__sqrt | [0, 0, 0, 0, 0] | 0.0 | 0.000 [0.000, 1.889] |
| GENSPEC_GEN__sqrt | [2, 2, 2, 7, 4] | 3.4 | 1.024 [0.124, 3.700] |

## Binary collapse vs V1 (frozen step 10 FINAL; same val rows; read-only)

- thresholds at <= 2 val FP are chosen and read on val (same-set, optimistic), V1's rule; V1 at its prereg T_house 0.568308: 2 FP, DR 0.99984

| metric | V1 FINAL | V2 ROUTED (mean [t-CI]) |
|---|---|---|
| pr_auc | 0.999999 | 0.99995 [0.99993, 0.99998] |
| roc_auc | 0.999996 | 0.99994 [0.99992, 0.99996] |
| dr_at_0.5 | 0.999839 | 0.99971 [0.99949, 0.99993] |
| fp_at_0.5 | 3 | 17.60000 [9.71763, 25.48237] |
| fa_per_hour_at_0.5 | 1.53627 | 9.01280 [4.97631, 13.04929] |
| thr_le2fp | 0.667451 | 0.99711 [0.99302, 1.00119] |
| dr_at_le2fp | 0.999839 | 0.99665 [0.99481, 0.99850] |
| fp_at_le2fp | 2 | 2.00000 [2.00000, 2.00000] |

## Cost per model (seed 0; 1 thread; dev machine, NOT the Pi)

| model | ms / flow batch 1 | ms / flow batch 1024 | size on disk (bytes) |
|---|---|---|---|
| CAT_Audio__sqrt | 0.0814 | 0.00184 | 216,123 |
| CAT_Camera__sqrt | 0.0980 | 0.00335 | 422,742 |
| CAT_Home_Automation__sqrt | 0.0790 | 0.00156 | 183,346 |
| CAT_Hub__sqrt | 0.0986 | 0.00377 | 447,480 |
| CAT_Lighting__sqrt | 0.1055 | 0.00271 | 377,554 |
| CAT_Power_Outlet__sqrt | 0.0811 | 0.00178 | 196,823 |
| CAT_Unidentified_Amazon__sqrt | 0.0847 | 0.00204 | 221,315 |
| CAT_Unidentified_Espressif__sqrt | 0.1007 | 0.00209 | 375,523 |
| GENSPEC_GEN__sqrt | 0.0887 | 0.00228 | 233,430 |
| GLOBAL__balanced | 0.1469 | 0.00150 | 223,873 |
| GLOBAL__none | 0.1007 | 0.00277 | 409,678 |
| GLOBAL__sqrt | 0.0763 | 0.00141 | 198,830 |
| SPEC_G1__balanced | 0.0831 | 0.00252 | 266,330 |
| SPEC_G1__none | 0.0863 | 0.00300 | 366,242 |
| SPEC_G1__sqrt | 0.0777 | 0.00152 | 234,946 |
| SPEC_G2__balanced | 0.1410 | 0.00082 | 101,063 |
| SPEC_G2__none | 0.1023 | 0.00306 | 366,753 |
| SPEC_G2__sqrt | 0.0792 | 0.00172 | 211,807 |

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
