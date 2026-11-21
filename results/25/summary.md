# Step 25 -- TreeSHAP explanations (VAL only) -- PASS

- run `20261120T183817Z`, models: seed-0 primary models of step 22 run `20261120T144232Z`
- method: xgboost Booster.predict(pred_contribs=True): exact TreeSHAP (shap library not installed; D01)
- sample: up to 2000 val flows per class per model (seeded; all if fewer)

## Leakage check

- leakage: no identifier-like / metadata column in the feature set: **PASS** -- clean (70 features vs identifier pattern + 21 metadata columns)
- TreeSHAP additivity SPEC_G1__sqrt__s0: contributions + bias == margin: **PASS** -- max |error| 5.72e-06 over 6,017 rows
- TreeSHAP additivity SPEC_G2__sqrt__s0: contributions + bias == margin: **PASS** -- max |error| 1.91e-05 over 6,017 rows
- TreeSHAP additivity GLOBAL__sqrt__s0: contributions + bias == margin: **PASS** -- max |error| 7.63e-06 over 6,017 rows

## Dominance flags (> 50% of total mean |SHAP|)

- SPEC_G1__sqrt__s0: feature(s) above 50% of total mean |SHAP|: ; per class: syn_flood: Flow IAT Min 53.1%; port_scan: FWD Init Win Bytes 64.4%
- SPEC_G2__sqrt__s0: feature(s) above 50% of total mean |SHAP|: ; per class: benign: SYN Flag Count 50.8%
- GLOBAL__sqrt__s0: feature(s) above 50% of total mean |SHAP|: ; per class: benign: SYN Flag Count 53.1%; port_scan: FWD Init Win Bytes 60.6%

## SPEC_G1__sqrt__s0 (serves G1; 6,017 rows, per class [2000, 2000, 17, 2000])

| rank | feature | mean abs SHAP | share |
|---|---|---|---|
| 1 | FWD Init Win Bytes | 1.0504 | 22.1% |
| 2 | SYN Flag Count | 0.9178 | 19.3% |
| 3 | Flow IAT Min | 0.8760 | 18.4% |
| 4 | Packet Length Max | 0.4163 | 8.8% |
| 5 | Fwd Header Length | 0.3426 | 7.2% |
| 6 | Bwd Packets/s | 0.2813 | 5.9% |
| 7 | Fwd Seg Size Min | 0.2585 | 5.4% |
| 8 | Flow Packets/s | 0.0542 | 1.1% |
| 9 | Flow Duration | 0.0444 | 0.9% |
| 10 | Fwd IAT Min | 0.0420 | 0.9% |

## SPEC_G2__sqrt__s0 (serves G2; 6,017 rows, per class [2000, 2000, 17, 2000])

| rank | feature | mean abs SHAP | share |
|---|---|---|---|
| 1 | SYN Flag Count | 1.6871 | 24.1% |
| 2 | FWD Init Win Bytes | 1.6059 | 23.0% |
| 3 | Flow Duration | 0.4569 | 6.5% |
| 4 | Fwd Header Length | 0.3694 | 5.3% |
| 5 | Flow IAT Mean | 0.3280 | 4.7% |
| 6 | Bwd Packets/s | 0.2602 | 3.7% |
| 7 | ACK Flag Count | 0.2500 | 3.6% |
| 8 | Packet Length Max | 0.2402 | 3.4% |
| 9 | Flow IAT Min | 0.2333 | 3.3% |
| 10 | Flow Packets/s | 0.1908 | 2.7% |

## GLOBAL__sqrt__s0 (serves GEN; 6,017 rows, per class [2000, 2000, 17, 2000])

| rank | feature | mean abs SHAP | share |
|---|---|---|---|
| 1 | SYN Flag Count | 0.9845 | 23.1% |
| 2 | FWD Init Win Bytes | 0.8785 | 20.6% |
| 3 | Flow IAT Min | 0.7451 | 17.5% |
| 4 | Fwd Header Length | 0.3094 | 7.3% |
| 5 | Fwd Seg Size Min | 0.2331 | 5.5% |
| 6 | Bwd Packets/s | 0.2135 | 5.0% |
| 7 | Packet Length Max | 0.2026 | 4.8% |
| 8 | Bwd Init Win Bytes | 0.0874 | 2.1% |
| 9 | ACK Flag Count | 0.0738 | 1.7% |
| 10 | Fwd IAT Min | 0.0690 | 1.6% |

## Figures

- `figures/beeswarm_GLOBAL.png` -- beeswarm per class output: SHAP value per sampled flow for the top features, colour = the flow's feature value rank.
- `figures/beeswarm_SPEC_G1.png` -- beeswarm per class output: SHAP value per sampled flow for the top features, colour = the flow's feature value rank.
- `figures/beeswarm_SPEC_G2.png` -- beeswarm per class output: SHAP value per sampled flow for the top features, colour = the flow's feature value rank.
- `figures/global_mean_abs_shap.png` -- global mean |SHAP| (mean over class outputs), top features per model.
- `figures/top20_features_by_group_heatmap.png` -- mean |SHAP| of the top features x the model serving each group (GLOBAL serves the fallback group).
