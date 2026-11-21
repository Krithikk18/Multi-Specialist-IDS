# Phase 2: v2_0_v1equiv vs v2_1_oriented (val only) -- PASS

- run `20261121T081216Z`; READ-ONLY; inputs: v2_0 22 `20261120T144232Z`, 23 `20261120T183529Z`, 25 `20261120T183817Z`; v2_1 22 `20261121T075821Z`, 23 `20261121T080839Z`, 25 `20261121T081050Z`
- FLAT_GLOBAL = GLOBAL of the same weighting on every flow; CIs: mean +- 95 % t-CI over the 5 seeds; ROUTED - FLAT_GLOBAL paired by seed.
- **figure-fix rerun** (`--rerun-tag rerun_fig_fix`): same inputs and numbers as the first run in `results/phase2_v2_1_compare/` (kept, not overwritten), whose macro-F1 / false-alarm and SHAP figures had overlapping labels.

- Amendment 1 chose weighting **`none`** on v2_1.

## Systems

| configuration | system | macro-F1 all | macro-F1 non-rare | false alarms / h | seed-0 FA / h [Garwood] |
|---|---|---|---|---|---|
| v2_0, sqrt (pre-registered primary) | ROUTED (`ROUTED`) | 0.8360 [0.7939, 0.8781] | 0.9579 [0.9578, 0.9580] | 5.735 [3.656, 7.815] | 5.121 [2.456, 9.418] (10 FP / 1.953 h) |
| v2_0, sqrt (pre-registered primary) | FLAT_GLOBAL (`GLOBAL__sqrt`) | 0.8650 [0.8327, 0.8974] | 0.9853 [0.9638, 1.0067] | 5.735 [2.607, 8.863] | 3.585 [1.441, 7.386] (7 FP / 1.953 h) |
| v2_0, none | ROUTED (`ROUTED_A1_none`) | 0.8962 [0.8661, 0.9264] | 0.9806 [0.9517, 1.0096] | 1.741 [1.393, 2.089] | 1.536 [0.317, 4.490] (3 FP / 1.953 h) |
| v2_0, none | FLAT_GLOBAL (`GLOBAL__none`) | 0.9084 [0.8939, 0.9229] | 0.9975 [0.9973, 0.9977] | 1.229 [0.660, 1.798] | 1.536 [0.317, 4.490] (3 FP / 1.953 h) |
| v2_1, sqrt | ROUTED (`ROUTED`) | 0.8498 [0.8268, 0.8729] | 0.9971 [0.9969, 0.9973] | 9.013 [4.976, 13.049] | 7.681 [4.299, 12.669] (15 FP / 1.953 h) |
| v2_1, sqrt | FLAT_GLOBAL (`GLOBAL__sqrt`) | 0.8783 [0.8478, 0.9088] | 0.9975 [0.9974, 0.9975] | 4.609 [3.419, 5.798] | 5.121 [2.456, 9.418] (10 FP / 1.953 h) |
| v2_1, none (Amendment 1 primary) | ROUTED (`ROUTED_A1_none`) | 0.9102 [0.8971, 0.9232] | 0.9974 [0.9974, 0.9975] | 1.741 [1.393, 2.089] | 2.048 [0.558, 5.245] (4 FP / 1.953 h) |
| v2_1, none (Amendment 1 primary) | FLAT_GLOBAL (`GLOBAL__none`) | 0.9144 [0.8984, 0.9305] | 0.9978 [0.9972, 0.9984] | 1.024 [0.575, 1.474] | 1.024 [0.124, 3.700] (2 FP / 1.953 h) |

## ROUTED - FLAT_GLOBAL (paired by seed)

| configuration | macro-F1 all | macro-F1 non-rare | false alarms / h | false alarms (count) |
|---|---|---|---|---|
| v2_0, sqrt (pre-registered primary) | -0.02904 [-0.08731, 0.02923] | -0.02739 [-0.04878, -0.00599] | 0.000 [-3.815, 3.815] | 0.0 [-7.4, 7.4] |
| v2_0, none | -0.01215 [-0.03727, 0.01296] | -0.01686 [-0.04582, 0.01211] | 0.512 [-0.267, 1.291] | 1.0 [-0.5, 2.5] |
| v2_1, sqrt | -0.02844 [-0.06788, 0.01099] | -0.00034 [-0.00052, -0.00016] | 4.404 [0.469, 8.339] | 8.6 [0.9, 16.3] |
| v2_1, none (Amendment 1 primary) | -0.00425 [-0.02853, 0.02002] | -0.00037 [-0.00099, 0.00025] | 0.717 [-0.008, 1.442] | 1.4 [-0.0, 2.8] |

## Per-class recall and F1

### ROUTED

| configuration | recall benign | recall syn_flood | recall udp_flood | recall port_scan | F1 benign | F1 syn_flood | F1 udp_flood | F1 port_scan |
|---|---|---|---|---|---|---|---|---|
| v2_0, sqrt (pre-registered primary) | 0.9997 [0.9996, 0.9998] | 0.9975 [0.9973, 0.9977] | 0.6000 [0.5389, 0.6611] (rare) | 0.8148 [0.8147, 0.8148] | 0.9995 [0.9994, 0.9996] | 0.9822 [0.9821, 0.9823] | 0.4703 [0.3021, 0.6385] | 0.8919 [0.8917, 0.8921] |
| v2_0, none | 0.9999 [0.9999, 0.9999] | 0.9978 [0.9977, 0.9979] | 0.5529 [0.4876, 0.6183] (rare) | 0.9275 [0.8055, 1.0495] | 0.9917 [0.9695, 1.0138] | 0.9956 [0.9867, 1.0045] | 0.6431 [0.6004, 0.6858] | 0.9546 [0.8875, 1.0217] |
| v2_1, sqrt | 0.9996 [0.9993, 0.9998] | 0.9974 [0.9971, 0.9977] | 0.6000 [0.5673, 0.6327] (rare) | 0.9992 [0.9992, 0.9992] | 0.9993 [0.9990, 0.9996] | 0.9986 [0.9985, 0.9988] | 0.4080 [0.3160, 0.5001] | 0.9934 [0.9932, 0.9936] |
| v2_1, none (Amendment 1 primary) | 0.9999 [0.9999, 0.9999] | 0.9977 [0.9977, 0.9978] | 0.5647 [0.4994, 0.6300] (rare) | 0.9992 [0.9992, 0.9992] | 0.9996 [0.9996, 0.9996] | 0.9988 [0.9988, 0.9988] | 0.6484 [0.5962, 0.7006] | 0.9939 [0.9937, 0.9940] |

### FLAT_GLOBAL

| configuration | recall benign | recall syn_flood | recall udp_flood | recall port_scan | F1 benign | F1 syn_flood | F1 udp_flood | F1 port_scan |
|---|---|---|---|---|---|---|---|---|
| v2_0, sqrt (pre-registered primary) | 0.9997 [0.9996, 0.9999] | 0.9977 [0.9976, 0.9978] | 0.6118 [0.5464, 0.6771] (rare) | 0.9413 [0.8399, 1.0428] | 0.9995 [0.9994, 0.9996] | 0.9936 [0.9845, 1.0027] | 0.5043 [0.3673, 0.6412] | 0.9628 [0.9075, 1.0180] |
| v2_0, none | 0.9999 [0.9999, 1.0000] | 0.9977 [0.9976, 0.9979] | 0.5882 [0.5366, 0.6399] (rare) | 0.9992 [0.9992, 0.9992] | 0.9996 [0.9995, 0.9996] | 0.9988 [0.9987, 0.9989] | 0.6411 [0.5834, 0.6989] | 0.9941 [0.9936, 0.9945] |
| v2_1, sqrt | 0.9998 [0.9997, 0.9998] | 0.9977 [0.9976, 0.9978] | 0.6235 [0.5835, 0.6635] (rare) | 0.9992 [0.9992, 0.9992] | 0.9995 [0.9993, 0.9997] | 0.9988 [0.9987, 0.9988] | 0.5208 [0.3985, 0.6430] | 0.9941 [0.9938, 0.9944] |
| v2_1, none (Amendment 1 primary) | 0.9999 [0.9999, 1.0000] | 0.9980 [0.9975, 0.9986] | 0.6000 [0.5673, 0.6327] (rare) | 0.9992 [0.9992, 0.9992] | 0.9996 [0.9995, 0.9997] | 0.9989 [0.9987, 0.9992] | 0.6643 [0.6005, 0.7281] | 0.9948 [0.9934, 0.9962] |

## Scanner-fingerprint shortcut: share of the port_scan output's mean |SHAP| carried by FWD Init Win Bytes

| configuration | GLOBAL | SPEC_G1 | SPEC_G2 |
|---|---|---|---|
| v2_0, sqrt | 60.6 % | 64.4 % | 36.1 % |
| v2_0, none | 47.3 % | 57.2 % | 33.9 % |
| v2_1, sqrt | 65.6 % | 69.0 % | 68.0 % |
| v2_1, none | 61.8 % | 66.6 % | 51.5 % |

Top-5 features of the port_scan output (seed-0 models):

- v2_0, sqrt GLOBAL__sqrt: FWD Init Win Bytes 60.6 %, Fwd Header Length 20.9 %, SYN Flag Count 9.3 %, Bwd Packets/s 4.9 %, Bwd Header Length 2.9 %
- v2_0, sqrt SPEC_G1__sqrt: FWD Init Win Bytes 64.4 %, Fwd Header Length 19.8 %, SYN Flag Count 6.3 %, Bwd Packets/s 6.0 %, Flow IAT Std 1.5 %
- v2_0, sqrt SPEC_G2__sqrt: FWD Init Win Bytes 36.1 %, Flow Duration 23.7 %, Fwd Header Length 15.2 %, Bwd Packets/s 5.4 %, Flow IAT Min 5.0 %
- v2_0, none GLOBAL__none: FWD Init Win Bytes 47.3 %, Fwd Header Length 12.8 %, Bwd Packets/s 11.3 %, SYN Flag Count 7.5 %, RST Flag Count 7.0 %
- v2_0, none SPEC_G1__none: FWD Init Win Bytes 57.2 %, Fwd Header Length 13.8 %, Bwd Packets/s 7.6 %, SYN Flag Count 6.0 %, Fwd IAT Total 2.8 %
- v2_0, none SPEC_G2__none: FWD Init Win Bytes 33.9 %, Flow Duration 21.0 %, Flow IAT Max 13.5 %, Flow IAT Min 6.3 %, Bwd Packets/s 6.1 %
- v2_1, sqrt GLOBAL__sqrt: FWD Init Win Bytes 65.6 %, Fwd Header Length 21.9 %, SYN Flag Count 8.5 %, Bwd Header Length 3.1 %, Flow Packets/s 0.4 %
- v2_1, sqrt SPEC_G1__sqrt: FWD Init Win Bytes 69.0 %, Fwd Header Length 21.4 %, SYN Flag Count 5.5 %, Flow IAT Std 1.5 %, Flow Packets/s 0.7 %
- v2_1, sqrt SPEC_G2__sqrt: FWD Init Win Bytes 68.0 %, Flow Duration 10.8 %, Flow IAT Std 6.7 %, SYN Flag Count 4.6 %, Bwd Packets/s 3.7 %
- v2_1, none GLOBAL__none: FWD Init Win Bytes 61.8 %, Fwd Header Length 14.0 %, Bwd Packets/s 6.1 %, SYN Flag Count 5.6 %, Flow Duration 5.6 %
- v2_1, none SPEC_G1__none: FWD Init Win Bytes 66.6 %, Fwd Header Length 14.7 %, Bwd Packets/s 5.3 %, SYN Flag Count 3.9 %, Flow IAT Max 1.8 %
- v2_1, none SPEC_G2__none: FWD Init Win Bytes 51.5 %, Flow Duration 17.4 %, Flow IAT Min 8.3 %, Bwd Packets/s 4.7 %, SYN Flag Count 4.2 %

## Checks

- PASS  per-seed recomputation == step 23 aggregates (v2_1 chosen ROUTED / FLAT_GLOBAL)  max |diff| 0
- PASS  SHAP shares reproduce the step 25 runs for the models they covered  6 models, max |diff| 5.7e-08
- PASS  config.py / class_map.json unchanged  

## Figures

- `figures/per_class_recall_v2_0_vs_v2_1.png` -- per-class recall (mean, 95 % t-CI) of ROUTED and FLAT_GLOBAL for each weighting x dataset; hollow = v2_0, filled = v2_1.
- `figures/routed_vs_flat_macro_f1_and_false_alarms.png` -- ROUTED vs FLAT_GLOBAL macro-F1 (all / non-rare) and false alarms / hour per weighting x dataset (mean, 95 % t-CI).
- `figures/init_win_shap_share.png` -- share of the port_scan output's mean |SHAP| carried by FWD Init Win Bytes per seed-0 model, per weighting x dataset (50 % = the prereg's dominance flag).
