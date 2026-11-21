# Step 25 -- TreeSHAP explanations (VAL only) -- PASS

- run `20261121T081050Z`, models: seed-0 primary models of step 22 run `20261121T075821Z` -- Amendment 1 primary weighting `none` (amendment selection in step 23 run 20261121T080839Z)
- method: xgboost Booster.predict(pred_contribs=True): exact TreeSHAP (shap library not installed; D01)
- sample: up to 2000 val flows per class per model (seeded; all if fewer)

## Leakage check

- leakage: no identifier-like / metadata column in the feature set: **PASS** -- clean (70 features vs identifier pattern + 22 metadata columns)
- TreeSHAP additivity SPEC_G1__none__s0: contributions + bias == margin: **PASS** -- max |error| 5.72e-06 over 6,017 rows
- TreeSHAP additivity SPEC_G2__none__s0: contributions + bias == margin: **PASS** -- max |error| 7.63e-06 over 6,017 rows
- TreeSHAP additivity GLOBAL__none__s0: contributions + bias == margin: **PASS** -- max |error| 4.77e-06 over 6,017 rows

## Dominance flags (> 50% of total mean |SHAP|)

- SPEC_G1__none__s0: feature(s) above 50% of total mean |SHAP|: ; per class: port_scan: FWD Init Win Bytes 66.6%
- SPEC_G2__none__s0: feature(s) above 50% of total mean |SHAP|: ; per class: syn_flood: FWD Init Win Bytes 51.5%; port_scan: FWD Init Win Bytes 51.5%
- GLOBAL__none__s0: feature(s) above 50% of total mean |SHAP|: ; per class: port_scan: FWD Init Win Bytes 61.8%

## SPEC_G1__none__s0 (serves G1; 6,017 rows, per class [2000, 2000, 17, 2000])

| rank | feature | mean abs SHAP | share |
|---|---|---|---|
| 1 | FWD Init Win Bytes | 1.7878 | 24.8% |
| 2 | SYN Flag Count | 1.1206 | 15.5% |
| 3 | Flow IAT Min | 0.8408 | 11.7% |
| 4 | Fwd Header Length | 0.4594 | 6.4% |
| 5 | Packet Length Max | 0.4317 | 6.0% |
| 6 | Fwd Seg Size Min | 0.3976 | 5.5% |
| 7 | Packet Length Min | 0.3807 | 5.3% |
| 8 | Bwd Packets/s | 0.3513 | 4.9% |
| 9 | Flow IAT Mean | 0.1688 | 2.3% |
| 10 | Flow IAT Max | 0.1231 | 1.7% |

## SPEC_G2__none__s0 (serves G2; 6,017 rows, per class [2000, 2000, 17, 2000])

| rank | feature | mean abs SHAP | share |
|---|---|---|---|
| 1 | FWD Init Win Bytes | 2.3469 | 33.3% |
| 2 | SYN Flag Count | 1.1370 | 16.1% |
| 3 | Flow Bytes/s | 0.3960 | 5.6% |
| 4 | Flow Duration | 0.3481 | 4.9% |
| 5 | Packet Length Max | 0.3127 | 4.4% |
| 6 | Flow IAT Min | 0.3064 | 4.3% |
| 7 | Fwd Packets/s | 0.2345 | 3.3% |
| 8 | Flow IAT Mean | 0.2239 | 3.2% |
| 9 | Fwd Header Length | 0.1953 | 2.8% |
| 10 | Bwd Packets/s | 0.1690 | 2.4% |

## GLOBAL__none__s0 (serves GEN; 6,017 rows, per class [2000, 2000, 17, 2000])

| rank | feature | mean abs SHAP | share |
|---|---|---|---|
| 1 | FWD Init Win Bytes | 1.9028 | 25.2% |
| 2 | SYN Flag Count | 1.2368 | 16.3% |
| 3 | Flow IAT Min | 0.8650 | 11.4% |
| 4 | Fwd Header Length | 0.4214 | 5.6% |
| 5 | Packet Length Max | 0.4085 | 5.4% |
| 6 | Fwd Seg Size Min | 0.4031 | 5.3% |
| 7 | Packet Length Min | 0.3834 | 5.1% |
| 8 | Flow Duration | 0.3322 | 4.4% |
| 9 | Bwd Packets/s | 0.2405 | 3.2% |
| 10 | Flow IAT Mean | 0.1877 | 2.5% |

## Figures

- `figures/beeswarm_GLOBAL.png` -- beeswarm per class output: SHAP value per sampled flow for the top features, colour = the flow's feature value rank.
- `figures/beeswarm_SPEC_G1.png` -- beeswarm per class output: SHAP value per sampled flow for the top features, colour = the flow's feature value rank.
- `figures/beeswarm_SPEC_G2.png` -- beeswarm per class output: SHAP value per sampled flow for the top features, colour = the flow's feature value rank.
- `figures/global_mean_abs_shap.png` -- global mean |SHAP| (mean over class outputs), top features per model.
- `figures/top20_features_by_group_heatmap.png` -- mean |SHAP| of the top features x the model serving each group (GLOBAL serves the fallback group).
