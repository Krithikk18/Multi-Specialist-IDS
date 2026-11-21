# Step 22 -- multiclass training -- PASS

- run `20261120T144232Z`, dataset `v2_0_v1equiv`, config sha256 `ee4bfdea8b1cf270...`, prereg sha256 `ba6993e98b96a575...`, seeds [0, 1, 2, 3, 4], runtime 1228.0 s
- train rows used: 636,193
- specialist groups (from the data): ['G1', 'G2']; fallback `GEN` -> GLOBAL

- A3: {'category_models': {'Audio': 'CAT_Audio__sqrt', 'Camera': 'CAT_Camera__sqrt', 'Home Automation': 'CAT_Home_Automation__sqrt', 'Hub': 'CAT_Hub__sqrt', 'Lighting': 'CAT_Lighting__sqrt', 'Power Outlet': 'CAT_Power_Outlet__sqrt', 'Unidentified (Amazon)': 'CAT_Unidentified_Amazon__sqrt', 'Unidentified (Espressif)': 'CAT_Unidentified_Espressif__sqrt'}, 'fallback_to_global': {}, 'min_benign_train': 100}

## Figures

- `figures/class_counts_per_training_set.png` -- training rows per class for every primary / A2 / A3 training set (log scale); the attack bars are identical across sets because attacks are pooled.
- `figures/mlogloss_curves_seed0.png` -- weighted mlogloss on the fit part vs the 10 % inner split per primary model (seed 0); the dotted line is the early-stopping best iteration.

## Models (training-set counts and class weights are seed-independent)

| model | config | weights | benign | syn_flood | udp_flood | port_scan | w_benign | w_syn_flood | w_udp_flood | w_port_scan | best_iter (mean, seeds) | fit s (mean) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SPEC_G1__sqrt | primary | sqrt | 120,028 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 35.545 | 1.106 | 27.6 | 5.9 |
| SPEC_G2__sqrt | primary | sqrt | 16,279 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 13.09 | 1.0 | 60.2 | 7.0 |
| GLOBAL__sqrt | primary | sqrt | 137,462 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 38.039 | 1.184 | 43.2 | 9.2 |
| SPEC_G1__none | A1_none | none | 120,028 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 1.0 | 1.0 | 52.2 | 10.5 |
| SPEC_G2__none | A1_none | none | 16,279 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 1.0 | 1.0 | 65.8 | 8.0 |
| GLOBAL__none | A1_none | none | 137,462 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 1.0 | 1.0 | 65.8 | 36.7 |
| SPEC_G1__balanced | A1_balanced | balanced | 120,028 | 400,590 | 95 | 98,046 | 1.289 | 0.386 | 1628.313 | 1.578 | 16.6 | 23.5 |
| SPEC_G2__balanced | A1_balanced | balanced | 16,279 | 400,590 | 95 | 98,046 | 7.909 | 0.321 | 1355.289 | 1.313 | 35.2 | 13.2 |
| GLOBAL__balanced | A1_balanced | balanced | 137,462 | 400,590 | 95 | 98,046 | 1.157 | 0.397 | 1674.192 | 1.622 | 10.4 | 9.9 |
| GENSPEC_GEN__sqrt | A2 | sqrt | 1,155 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 3.487 | 1.0 | 75.2 | 31.5 |
| CAT_Audio__sqrt | A3 | sqrt | 29,037 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 17.483 | 1.0 | 24.2 | 10.9 |
| CAT_Camera__sqrt | A3 | sqrt | 53,399 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 23.709 | 1.0 | 44.0 | 21.0 |
| CAT_Home_Automation__sqrt | A3 | sqrt | 5,889 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 7.873 | 1.0 | 42.2 | 17.5 |
| CAT_Hub__sqrt | A3 | sqrt | 30,696 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 17.975 | 1.0 | 34.8 | 10.5 |
| CAT_Lighting__sqrt | A3 | sqrt | 3,424 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 6.004 | 1.0 | 60.6 | 5.9 |
| CAT_Power_Outlet__sqrt | A3 | sqrt | 10,741 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 10.633 | 1.0 | 50.2 | 4.8 |
| CAT_Unidentified_Amazon__sqrt | A3 | sqrt | 1,829 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 4.388 | 1.0 | 47.6 | 5.5 |
| CAT_Unidentified_Espressif__sqrt | A3 | sqrt | 2,447 | 400,590 | 95 | 98,046 | 1.0 | 1.0 | 5.075 | 1.0 | 56.4 | 5.1 |
