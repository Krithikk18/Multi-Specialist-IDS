# Phase 3.1 part C -- Init Win shortcut ablation (report-only) -- PASS

## Rule (fixed before any number)

With FWD Init Win Bytes and Bwd Init Win Bytes removed, the model is **shortcut-DEPENDENT** iff port_scan recall drops by more than 0.02 (5-seed mean of the paired per-seed difference) AND the paired-by-seed 95 % t-CI of that difference lies entirely below 0. Otherwise it is **shortcut-CONVENIENT** (an alternative signal exists).

- FLAT_GLOBAL, weights `none` (Amendment 1 primary), v2_1_oriented, seeds [0, 1, 2, 3, 4]; dropped at train and predict time only: ['FWD Init Win Bytes', 'Bwd Init Win Bytes']; baseline = step 22 run `20261121T075821Z` GLOBAL boosters scored by the same code; models in the ablations cache only (no registry entry).

## VERDICT: **shortcut-CONVENIENT**

- port_scan recall change (ablated - baseline, paired by seed): -0.0115 [-0.0150, -0.0079] (per seed [-0.01254, -0.00941, -0.00985, -0.00946, -0.01601])

## Per class (5-seed mean [95 % t-CI]; diff paired by seed)

| class | support | recall with | recall without | diff | F1 with | F1 without | diff |
|---|---|---|---|---|---|---|---|
| benign | 39,185 | 0.9999 [0.9999, 1.0000] | 0.9999 [0.9999, 1.0000] | -0.0000 [-0.0000, 0.0000] | 0.9996 [0.9995, 0.9997] | 0.9997 [0.9997, 0.9998] | 0.0001 [0.0000, 0.0002] |
| syn_flood | 100,177 | 0.9980 [0.9975, 0.9986] | 0.9980 [0.9980, 0.9980] | -0.0000 [-0.0006, 0.0005] | 0.9989 [0.9987, 0.9992] | 0.9979 [0.9975, 0.9982] | -0.0011 [-0.0014, -0.0007] |
| udp_flood (rare) | 17 | 0.6000 [0.5673, 0.6327] | 0.5059 [0.4659, 0.5459] | -0.0941 [-0.1341, -0.0541] | 0.6643 [0.6005, 0.7281] | 0.6562 [0.6197, 0.6927] | -0.0081 [-0.0921, 0.0758] |
| port_scan | 18,179 | 0.9992 [0.9992, 0.9992] | 0.9877 [0.9842, 0.9913] | -0.0115 [-0.0150, -0.0079] | 0.9948 [0.9934, 0.9962] | 0.9885 [0.9868, 0.9903] | -0.0063 [-0.0083, -0.0043] |

| measure | with Init Win | without | diff (paired) |
|---|---|---|---|
| macro-F1 non-rare | 0.9978 [0.9972, 0.9984] | 0.9954 [0.9947, 0.9961] | -0.0024 [-0.0032, -0.0016] |
| macro-F1 all | 0.9144 [0.8984, 0.9305] | 0.9106 [0.9014, 0.9198] | -0.0038 [-0.0252, 0.0176] |
| flow-level false alarms / h | 1.0242 [0.5746, 1.4738] | 1.2290 [0.8808, 1.5773] | 0.2048 [-0.3639, 0.7736] |
| false-alarm count | 2.0000 [1.1220, 2.8780] | 2.4000 [1.7199, 3.0801] | 0.4000 [-0.7106, 1.5106] |

## port_scan output: share of mean |SHAP| (seed-0 models, step 25's sample)

- with Init Win (v2_1 primary): FWD Init Win Bytes 61.8 %, Fwd Header Length 14.0 %, Bwd Packets/s 6.1 %, SYN Flag Count 5.6 %, Flow Duration 5.6 %, Bwd Header Length 1.7 %, RST Flag Count 1.6 %, Fwd IAT Min 0.8 %, Subflow Fwd Packets 0.6 %, Flow Packets/s 0.5 %
- without Init Win: Fwd Header Length 31.4 %, SYN Flag Count 13.9 %, RST Flag Count 11.7 %, Flow Duration 9.9 %, ACK Flag Count 8.2 %, Bwd Packets/s 7.9 %, Fwd Seg Size Min 6.3 %, Flow IAT Max 2.0 %, Flow IAT Mean 1.4 %, Flow IAT Min 1.4 %

## Figures

- `figures/recall_with_without_initwin.png`
- `figures/shap_share_before_after.png`

## Checks

- PASS  baseline weighting == step 23's Amendment 1 choice  none
- PASS  baseline reproduces step 23 FLAT_GLOBAL_A1_none (FA counts per seed, mean recall, mean non-rare macro-F1)  FA [2, 2, 2, 1, 3] vs [2, 2, 2, 1, 3]
- PASS  config.py / class_map.json unchanged  {'config/config.py': 'c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf', 'config/class_map.json': '64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580'}
