# Step 10 -- DRY RUN (VAL stands in for test)

- run 2026-10-19T20:21:15+00:00 -> 2026-10-19T20:21:37+00:00, git HEAD `1fb1cfe8a161b18132f2824374615dc886a5353f`, 10_evaluate.py sha256 `a44ee0e8d28ec368...`, prereg `config/step10_prereg.json` sha256 `17f627f841263e94`
- evaluated split: `~/lgids_cache/datasets/v1_1/val.parquet` (157,558 rows, sha256 `f992fc82ed8cd34f...`); runtime filter dropped 0 rows (applied at build time by 08 / 08b)
- flag attack iff score >= threshold; LOW_N = 0 < n < 50; N/A = n 0; FP/hour CI = 95% exact (Garwood) Poisson CI on the FP count / active benign hours
- **Dry run**: T_house is chosen on VAL and every number here is read on the SAME val rows (optimistic, plumbing check only). Val holds no daytime benign (FP/h N/A).

## Systems and operating points

| system | models | T_house (val, <= 2 FP) | 0.5 |
|---|---|---|---|
| FINAL | G1 + G2 + GLOBAL | 0.568307638168335 | 0.5 |
| BASELINE | GLOBAL | 0.5927605032920837 | 0.5 |

Routing (FINAL): by the row's group column: G1 -> G1 model, G2 -> G2 model, GEN -> GLOBAL; unregistered MACs (device 'unregistered:<mac>', device_category 'unregistered_mac') are group GEN -> GLOBAL. BASELINE: GLOBAL for every row.

## Models

| model | training set | n_train | benign / attack | scale_pos_weight | file bytes | sha256 |
|---|---|---|---|---|---|---|
| G1 | shared_attack: TRAIN benign rows of group G1 (behaviour_k2) + every TRAIN attack row | 618,759 | 120,028 / 498,731 | 0.240667 | 147,178 | `94451ede65092a4e...` |
| G2 | shared_attack: TRAIN benign rows of group G2 (behaviour_k2) + every TRAIN attack row | 515,010 | 16,279 / 498,731 | 0.0326408 | 103,316 | `9f63a62dfb50675f...` |
| GLOBAL | every TRAIN row | 636,193 | 137,462 / 498,731 | 0.275624 | 154,316 | `d7408f5073182cf0...` |

Rows routed: by group {'G1': 93716, 'G2': 63551, 'GEN': 291}; by model {'G1': 93716, 'G2': 63551, 'GLOBAL': 291}; unregistered_mac 0; every row exactly once: True

## Detection by attack family

| attack_family | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| port_scan | 1.0000 (18,179/18,179) | 1.0000 (18,179/18,179) | 1.0000 (18,179/18,179) | 1.0000 (18,179/18,179) |
| syn_flood | 0.9999 (100,167/100,177) | 0.9999 (100,167/100,177) | 0.9999 (100,168/100,177) | 0.9999 (100,168/100,177) |
| udp_flood | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N |
| ALL | 0.9998 (118,354/118,373) | 0.9998 (118,354/118,373) | 0.9998 (118,355/118,373) | 0.9998 (118,355/118,373) |

## Detection by session

| session | attack_family | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|---|
| DDoS-SYN_Flood (SYN first part) | syn_flood | 0.9998 (50,093/50,103) | 0.9998 (50,093/50,103) | 0.9998 (50,094/50,103) | 0.9998 (50,094/50,103) |
| DDoS-SYN_Flood5 (SYN 5) | syn_flood | 1.0000 (50,074/50,074) | 1.0000 (50,074/50,074) | 1.0000 (50,074/50,074) | 1.0000 (50,074/50,074) |
| Recon-PortScan (Recon-PortScan) | port_scan | 1.0000 (18,179/18,179) | 1.0000 (18,179/18,179) | 1.0000 (18,179/18,179) | 1.0000 (18,179/18,179) |
| Mirai-udpplain (Mirai first part) | udp_flood | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N |

## Detection by attack family x group

| attack_family | group | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|---|
| port_scan | G1 | 1.0000 (7,763/7,763) | 1.0000 (7,763/7,763) | 1.0000 (7,763/7,763) | 1.0000 (7,763/7,763) |
| port_scan | G2 | 1.0000 (10,416/10,416) | 1.0000 (10,416/10,416) | 1.0000 (10,416/10,416) | 1.0000 (10,416/10,416) |
| port_scan | GEN | N/A (n=0) | N/A (n=0) | N/A (n=0) | N/A (n=0) |
| syn_flood | G1 | 0.9998 (50,093/50,103) | 0.9998 (50,093/50,103) | 0.9998 (50,094/50,103) | 0.9998 (50,094/50,103) |
| syn_flood | G2 | 1.0000 (50,074/50,074) | 1.0000 (50,074/50,074) | 1.0000 (50,074/50,074) | 1.0000 (50,074/50,074) |
| syn_flood | GEN | N/A (n=0) | N/A (n=0) | N/A (n=0) | N/A (n=0) |
| udp_flood | G1 | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N | 0.4706 (8/17) LOW_N |
| udp_flood | G2 | N/A (n=0) | N/A (n=0) | N/A (n=0) | N/A (n=0) |
| udp_flood | GEN | N/A (n=0) | N/A (n=0) | N/A (n=0) | N/A (n=0) |

## False alarms (FP -> FP/hour [95% CI])

| key | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| night | 2 -> 1.016/h [0.123, 3.672] (n 39,185, 1.968 h) | 3 -> 1.525/h [0.314, 4.456] (n 39,185, 1.968 h) | 2 -> 1.016/h [0.123, 3.672] (n 39,185, 1.968 h) | 3 -> 1.525/h [0.314, 4.456] (n 39,185, 1.968 h) |
| daytime | 0 of 0; FP/h N/A (0 h) | 0 of 0; FP/h N/A (0 h) | 0 of 0; FP/h N/A (0 h) | 0 of 0; FP/h N/A (0 h) |
| combined | 2 -> 1.016/h [0.123, 3.672] (n 39,185, 1.968 h) | 3 -> 1.525/h [0.314, 4.456] (n 39,185, 1.968 h) | 2 -> 1.016/h [0.123, 3.672] (n 39,185, 1.968 h) | 3 -> 1.525/h [0.314, 4.456] (n 39,185, 1.968 h) |

Hours: night 1.9676 h; daytime 0.0000 h; combined 1.9676 h (val: 09 group_val_hours GLOBAL (08 rule on manifest_v1 session_cuts; == manifest per_split.val 1.9676); val has no daytime benign)

### FPs by group

| key | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| G1 | 2 of 35,833 (CI [0.242, 7.225]) | 2 of 35,833 (CI [0.242, 7.225]) | 1 of 35,833 (CI [0.025, 5.572]) | 2 of 35,833 (CI [0.242, 7.225]) |
| G2 | 0 of 3,061 (CI [0.000, 3.689]) | 1 of 3,061 (CI [0.025, 5.572]) | 1 of 3,061 (CI [0.025, 5.572]) | 1 of 3,061 (CI [0.025, 5.572]) |
| GEN | 0 of 291 (CI [0.000, 3.689]) | 0 of 291 (CI [0.000, 3.689]) | 0 of 291 (CI [0.000, 3.689]) | 0 of 291 (CI [0.000, 3.689]) |

### FPs by device_category

| key | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| Audio | 2 of 5,905 (CI [0.242, 7.225]) | 2 of 5,905 (CI [0.242, 7.225]) | 1 of 5,905 (CI [0.025, 5.572]) | 2 of 5,905 (CI [0.242, 7.225]) |
| Camera | 0 of 10,131 (CI [0.000, 3.689]) | 0 of 10,131 (CI [0.000, 3.689]) | 0 of 10,131 (CI [0.000, 3.689]) | 0 of 10,131 (CI [0.000, 3.689]) |
| Home Automation | 0 of 1,883 (CI [0.000, 3.689]) | 1 of 1,883 (CI [0.025, 5.572]) | 1 of 1,883 (CI [0.025, 5.572]) | 1 of 1,883 (CI [0.025, 5.572]) |
| Hub | 0 of 17,049 (CI [0.000, 3.689]) | 0 of 17,049 (CI [0.000, 3.689]) | 0 of 17,049 (CI [0.000, 3.689]) | 0 of 17,049 (CI [0.000, 3.689]) |
| Lighting | 0 of 600 (CI [0.000, 3.689]) | 0 of 600 (CI [0.000, 3.689]) | 0 of 600 (CI [0.000, 3.689]) | 0 of 600 (CI [0.000, 3.689]) |
| Power Outlet | 0 of 2,748 (CI [0.000, 3.689]) | 0 of 2,748 (CI [0.000, 3.689]) | 0 of 2,748 (CI [0.000, 3.689]) | 0 of 2,748 (CI [0.000, 3.689]) |
| Unidentified (Amazon) | 0 of 381 (CI [0.000, 3.689]) | 0 of 381 (CI [0.000, 3.689]) | 0 of 381 (CI [0.000, 3.689]) | 0 of 381 (CI [0.000, 3.689]) |
| Unidentified (Espressif) | 0 of 488 (CI [0.000, 3.689]) | 0 of 488 (CI [0.000, 3.689]) | 0 of 488 (CI [0.000, 3.689]) | 0 of 488 (CI [0.000, 3.689]) |

## Sanity checks

| check | result | detail |
|---|---|---|
| val FP at T_house <= 2 (both systems) | PASS | FINAL 2; BASELINE 2 |
| val numbers == Step 9 (global, behaviour_k2 shared_attack) | PASS | 80/80 metrics within 1e-09 (score sha256 exact) |
| Poisson CI self-test (Garwood 95%) | PASS | 0 FP -> [0.0, 3.6889] (want upper 3.689); 2 FP -> [0.2422, 7.2247] (want [0.242, 7.225]) |
| model reload reproduces in-memory val scores exactly | PASS | G1 equal; G2 equal; GLOBAL equal |
| routing coverage: every val row routed to exactly one model | PASS | by group {'G1': 93716, 'G2': 63551, 'GEN': 291}; by model {'G1': 93716, 'G2': 63551, 'GLOBAL': 291} |

## Step 9 (results/step9/strategies, val) vs this dry run

| system | scope | metric | step9 | step10 | result |
|---|---|---|---|---|---|
| BASELINE | house | n_attack_val | 118373.000000 | 118373.000000 | PASS |
| BASELINE | house | n_benign_val | 39185.000000 | 39185.000000 | PASS |
| BASELINE | house | val_benign_hours | 1.967583 | 1.967583 | PASS |
| BASELINE | house | pr_auc | 0.999999 | 0.999999 | PASS |
| BASELINE | house | roc_auc | 0.999998 | 0.999998 | PASS |
| BASELINE | house | thr_05 | 0.500000 | 0.500000 | PASS |
| BASELINE | house | fp_05 | 3.000000 | 3.000000 | PASS |
| BASELINE | house | fph_05 | 1.524713 | 1.524713 | PASS |
| BASELINE | house | dr_05 | 0.999848 | 0.999848 | PASS |
| BASELINE | house | thr_common | 0.592761 | 0.592761 | PASS |
| BASELINE | house | fp_common | 2.000000 | 2.000000 | PASS |
| BASELINE | house | fph_common | 1.016475 | 1.016475 | PASS |
| BASELINE | house | dr_common | 0.999848 | 0.999848 | PASS |
| BASELINE | house | n_port_scan | 18179.000000 | 18179.000000 | PASS |
| BASELINE | house | dr_05_port_scan | 1.000000 | 1.000000 | PASS |
| BASELINE | house | dr_common_port_scan | 1.000000 | 1.000000 | PASS |
| BASELINE | house | n_syn_flood | 100177.000000 | 100177.000000 | PASS |
| BASELINE | house | dr_05_syn_flood | 0.999910 | 0.999910 | PASS |
| BASELINE | house | dr_common_syn_flood | 0.999910 | 0.999910 | PASS |
| BASELINE | house | n_udp_flood | 17.000000 | 17.000000 | PASS |
| BASELINE | house | dr_05_udp_flood | 0.470588 | 0.470588 | PASS |
| BASELINE | house | dr_common_udp_flood | 0.470588 | 0.470588 | PASS |
| BASELINE | house | score_sha256 | 379f2401e1ceacc797191343dc6581155998ed05165982e5bddd2b7e822bb521 | 379f2401e1ceacc797191343dc6581155998ed05165982e5bddd2b7e822bb521 | PASS |
| BASELINE | house | T_house == thr_common | 0.592761 | 0.592761 | PASS |
| BASELINE | group GLOBAL | n_val | 157558.000000 | 157558.000000 | PASS |
| BASELINE | group GLOBAL | n_val_benign | 39185.000000 | 39185.000000 | PASS |
| BASELINE | group GLOBAL | fp_05 | 3.000000 | 3.000000 | PASS |
| BASELINE | group GLOBAL | fp_common | 2.000000 | 2.000000 | PASS |
| BASELINE | group GLOBAL | n_train | 636193.000000 | 636193.000000 | PASS |
| BASELINE | group GLOBAL | n_train_benign | 137462.000000 | 137462.000000 | PASS |
| BASELINE | group GLOBAL | n_train_attack | 498731.000000 | 498731.000000 | PASS |
| BASELINE | group GLOBAL | size_bytes | 154316.000000 | 154316.000000 | PASS |
| FINAL | house | n_attack_val | 118373.000000 | 118373.000000 | PASS |
| FINAL | house | n_benign_val | 39185.000000 | 39185.000000 | PASS |
| FINAL | house | val_benign_hours | 1.967583 | 1.967583 | PASS |
| FINAL | house | pr_auc | 0.999999 | 0.999999 | PASS |
| FINAL | house | roc_auc | 0.999996 | 0.999996 | PASS |
| FINAL | house | thr_05 | 0.500000 | 0.500000 | PASS |
| FINAL | house | fp_05 | 3.000000 | 3.000000 | PASS |
| FINAL | house | fph_05 | 1.524713 | 1.524713 | PASS |
| FINAL | house | dr_05 | 0.999839 | 0.999839 | PASS |
| FINAL | house | thr_common | 0.568308 | 0.568308 | PASS |
| FINAL | house | fp_common | 2.000000 | 2.000000 | PASS |
| FINAL | house | fph_common | 1.016475 | 1.016475 | PASS |
| FINAL | house | dr_common | 0.999839 | 0.999839 | PASS |
| FINAL | house | n_port_scan | 18179.000000 | 18179.000000 | PASS |
| FINAL | house | dr_05_port_scan | 1.000000 | 1.000000 | PASS |
| FINAL | house | dr_common_port_scan | 1.000000 | 1.000000 | PASS |
| FINAL | house | n_syn_flood | 100177.000000 | 100177.000000 | PASS |
| FINAL | house | dr_05_syn_flood | 0.999900 | 0.999900 | PASS |
| FINAL | house | dr_common_syn_flood | 0.999900 | 0.999900 | PASS |
| FINAL | house | n_udp_flood | 17.000000 | 17.000000 | PASS |
| FINAL | house | dr_05_udp_flood | 0.470588 | 0.470588 | PASS |
| FINAL | house | dr_common_udp_flood | 0.470588 | 0.470588 | PASS |
| FINAL | house | score_sha256 | 7fbaac98d029ebfc6853e3cd50d070b806d9e0eeef79a8b52bd7b2e563de0821 | 7fbaac98d029ebfc6853e3cd50d070b806d9e0eeef79a8b52bd7b2e563de0821 | PASS |
| FINAL | house | T_house == thr_common | 0.568308 | 0.568308 | PASS |
| FINAL | group G1 | n_val | 93716.000000 | 93716.000000 | PASS |
| FINAL | group G1 | n_val_benign | 35833.000000 | 35833.000000 | PASS |
| FINAL | group G1 | fp_05 | 2.000000 | 2.000000 | PASS |
| FINAL | group G1 | fp_common | 2.000000 | 2.000000 | PASS |
| FINAL | group G1 | n_train | 618759.000000 | 618759.000000 | PASS |
| FINAL | group G1 | n_train_benign | 120028.000000 | 120028.000000 | PASS |
| FINAL | group G1 | n_train_attack | 498731.000000 | 498731.000000 | PASS |
| FINAL | group G1 | size_bytes | 147178.000000 | 147178.000000 | PASS |
| FINAL | group G2 | n_val | 63551.000000 | 63551.000000 | PASS |
| FINAL | group G2 | n_val_benign | 3061.000000 | 3061.000000 | PASS |
| FINAL | group G2 | fp_05 | 1.000000 | 1.000000 | PASS |
| FINAL | group G2 | fp_common | 0.000000 | 0.000000 | PASS |
| FINAL | group G2 | n_train | 515010.000000 | 515010.000000 | PASS |
| FINAL | group G2 | n_train_benign | 16279.000000 | 16279.000000 | PASS |
| FINAL | group G2 | n_train_attack | 498731.000000 | 498731.000000 | PASS |
| FINAL | group G2 | size_bytes | 103316.000000 | 103316.000000 | PASS |
| FINAL | group GEN | n_val | 291.000000 | 291.000000 | PASS |
| FINAL | group GEN | n_val_benign | 291.000000 | 291.000000 | PASS |
| FINAL | group GEN | fp_05 | 0.000000 | 0.000000 | PASS |
| FINAL | group GEN | fp_common | 0.000000 | 0.000000 | PASS |
| FINAL | group GEN | n_train | 636193.000000 | 636193.000000 | PASS |
| FINAL | group GEN | n_train_benign | 137462.000000 | 137462.000000 | PASS |
| FINAL | group GEN | n_train_attack | 498731.000000 | 498731.000000 | PASS |
| FINAL | group GEN | size_bytes | 154316.000000 | 154316.000000 | PASS |

## Notes

- XGB: 09 build_model / fit_model: XGBoost library defaults + scale_pos_weight = n_benign / n_attack of the model's own training rows, random_state 42, n_jobs -1; 70 features (features_v1.json order, float32); no search.
- Threshold rule: T_house: lowest observed house VAL score with <= 2 FP on the house's VAL benign rows (09 strategies common_threshold_rule, 09 max_fp_threshold); 0.5 fixed. Flag iff score >= thr.
- Night / daytime: daytime = split_plan_v1_1 test_only sessions ['BenignTraffic1', 'BenignTraffic2', 'BenignTraffic3']; night = every other plan session.
- predictions.parquet sha256 `0fb8d63e4f1bce9ca45f7b2d8aa4cbb92a03c1867717e5ef5005bfb5c259b511`.
