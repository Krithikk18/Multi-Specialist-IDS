# Step 10 -- TEST evaluation (one-time)

- run 2026-10-19T20:32:02+00:00 -> 2026-10-19T20:32:13+00:00, git HEAD `279a8a742b10c9d6663e12abea7df2ffb6c03850`, 10_evaluate.py sha256 `a44ee0e8d28ec368...`, prereg `config/step10_prereg.json` sha256 `17f627f841263e94`
- evaluated split: `~/lgids_cache/datasets/v1_1/test.parquet` (694,169 rows, sha256 `0650b0fd0dcc01d8...`); runtime filter dropped 0 rows (applied at build time by 08 / 08b)
- flag attack iff score >= threshold; LOW_N = 0 < n < 50; N/A = n 0; FP/hour CI = 95% exact (Garwood) Poisson CI on the FP count / active benign hours

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

Rows routed: by group {'G1': 452338, 'G2': 241077, 'GEN': 754}; by model {'G1': 452338, 'G2': 241077, 'GLOBAL': 754}; unregistered_mac 8; every row exactly once: True

## Detection by attack family

| attack_family | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| port_scan | 1.0000 (20,506/20,506) | 1.0000 (20,506/20,506) | 1.0000 (20,506/20,506) | 1.0000 (20,506/20,506) |
| syn_flood | 0.9998 (398,469/398,532) | 0.9998 (398,469/398,532) | 0.9997 (398,429/398,532) | 0.9998 (398,434/398,532) |
| udp_flood | 0.4483 (26/58) | 0.4655 (27/58) | 0.4655 (27/58) | 0.4828 (28/58) |
| ALL | 0.9998 (419,001/419,096) | 0.9998 (419,002/419,096) | 0.9997 (418,962/419,096) | 0.9997 (418,968/419,096) |

## Detection by session

| session | attack_family | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|---|
| DDoS-SYN_Flood10 (SYN 10) | syn_flood | 0.9998 (265,567/265,616) | 0.9998 (265,567/265,616) | 0.9997 (265,528/265,616) | 0.9997 (265,530/265,616) |
| DDoS-SYN_Flood15 (SYN 15) | syn_flood | 0.9999 (132,902/132,916) | 0.9999 (132,902/132,916) | 0.9999 (132,901/132,916) | 0.9999 (132,904/132,916) |
| Recon-PortScan (Recon-PortScan) | port_scan | 1.0000 (20,506/20,506) | 1.0000 (20,506/20,506) | 1.0000 (20,506/20,506) | 1.0000 (20,506/20,506) |
| Mirai-udpplain24 (Mirai 24) | udp_flood | 0.4483 (26/58) | 0.4655 (27/58) | 0.4655 (27/58) | 0.4828 (28/58) |

## Detection by attack family x group

| attack_family | group | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|---|
| port_scan | G1 | 1.0000 (11,791/11,791) | 1.0000 (11,791/11,791) | 1.0000 (11,791/11,791) | 1.0000 (11,791/11,791) |
| port_scan | G2 | 1.0000 (8,715/8,715) | 1.0000 (8,715/8,715) | 1.0000 (8,715/8,715) | 1.0000 (8,715/8,715) |
| port_scan | GEN | N/A (n=0) | N/A (n=0) | N/A (n=0) | N/A (n=0) |
| syn_flood | G1 | 0.9999 (199,759/199,774) | 0.9999 (199,759/199,774) | 0.9999 (199,759/199,774) | 0.9999 (199,761/199,774) |
| syn_flood | G2 | 0.9998 (198,709/198,755) | 0.9998 (198,709/198,755) | 0.9996 (198,670/198,755) | 0.9996 (198,672/198,755) |
| syn_flood | GEN | 0.3333 (1/3) LOW_N | 0.3333 (1/3) LOW_N | 0.0000 (0/3) LOW_N | 0.3333 (1/3) LOW_N |
| udp_flood | G1 | 0.1143 (4/35) LOW_N | 0.1429 (5/35) LOW_N | 0.1143 (4/35) LOW_N | 0.1429 (5/35) LOW_N |
| udp_flood | G2 | 0.9565 (22/23) LOW_N | 0.9565 (22/23) LOW_N | 1.0000 (23/23) LOW_N | 1.0000 (23/23) LOW_N |
| udp_flood | GEN | N/A (n=0) | N/A (n=0) | N/A (n=0) | N/A (n=0) |

## False alarms (FP -> FP/hour [95% CI])

| key | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| night | 19 -> 6.296/h [3.790, 9.832] (n 54,714, 3.018 h) | 21 -> 6.958/h [4.307, 10.637] (n 54,714, 3.018 h) | 23 -> 7.621/h [4.831, 11.436] (n 54,714, 3.018 h) | 28 -> 9.278/h [6.165, 13.409] (n 54,714, 3.018 h) |
| daytime | 0 -> 0.000/h [0.000, 0.197] (n 220,359, 18.742 h) | 0 -> 0.000/h [0.000, 0.197] (n 220,359, 18.742 h) | 0 -> 0.000/h [0.000, 0.197] (n 220,359, 18.742 h) | 0 -> 0.000/h [0.000, 0.197] (n 220,359, 18.742 h) |
| combined | 19 -> 0.873/h [0.526, 1.364] (n 275,073, 21.760 h) | 21 -> 0.965/h [0.597, 1.475] (n 275,073, 21.760 h) | 23 -> 1.057/h [0.670, 1.586] (n 275,073, 21.760 h) | 28 -> 1.287/h [0.855, 1.860] (n 275,073, 21.760 h) |

Hours: night 3.0179 h; daytime 18.7422 h; combined 21.7601 h (results/step8b/manifest_v1_1.json hours: v1_test (night), added (daytime), v1_1_test (combined))

### FPs by group

| key | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| G1 | 13 of 240,738 (CI [6.922, 22.230]) | 13 of 240,738 (CI [6.922, 22.230]) | 10 of 240,738 (CI [4.795, 18.390]) | 15 of 240,738 (CI [8.395, 24.740]) |
| G2 | 6 of 33,584 (CI [2.202, 13.059]) | 8 of 33,584 (CI [3.454, 15.763]) | 13 of 33,584 (CI [6.922, 22.230]) | 13 of 33,584 (CI [6.922, 22.230]) |
| GEN | 0 of 751 (CI [0.000, 3.689]) | 0 of 751 (CI [0.000, 3.689]) | 0 of 751 (CI [0.000, 3.689]) | 0 of 751 (CI [0.000, 3.689]) |

### FPs by device_category

| key | FINAL @ T_house | FINAL @ 0.5 | BASELINE @ T_house | BASELINE @ 0.5 |
|---|---|---|---|---|
| Audio | 6 of 60,320 (CI [2.202, 13.059]) | 6 of 60,320 (CI [2.202, 13.059]) | 6 of 60,320 (CI [2.202, 13.059]) | 6 of 60,320 (CI [2.202, 13.059]) |
| Camera | 0 of 125,657 (CI [0.000, 3.689]) | 0 of 125,657 (CI [0.000, 3.689]) | 2 of 125,657 (CI [0.242, 7.225]) | 2 of 125,657 (CI [0.242, 7.225]) |
| Home Automation | 0 of 16,148 (CI [0.000, 3.689]) | 0 of 16,148 (CI [0.000, 3.689]) | 0 of 16,148 (CI [0.000, 3.689]) | 2 of 16,148 (CI [0.242, 7.225]) |
| Hub | 0 of 44,593 (CI [0.000, 3.689]) | 0 of 44,593 (CI [0.000, 3.689]) | 0 of 44,593 (CI [0.000, 3.689]) | 0 of 44,593 (CI [0.000, 3.689]) |
| Lighting | 6 of 7,115 (CI [2.202, 13.059]) | 6 of 7,115 (CI [2.202, 13.059]) | 9 of 7,115 (CI [4.115, 17.085]) | 9 of 7,115 (CI [4.115, 17.085]) |
| Power Outlet | 0 of 14,267 (CI [0.000, 3.689]) | 2 of 14,267 (CI [0.242, 7.225]) | 2 of 14,267 (CI [0.242, 7.225]) | 2 of 14,267 (CI [0.242, 7.225]) |
| Unidentified (Amazon) | 7 of 1,718 (CI [2.814, 14.423]) | 7 of 1,718 (CI [2.814, 14.423]) | 4 of 1,718 (CI [1.090, 10.242]) | 7 of 1,718 (CI [2.814, 14.423]) |
| Unidentified (Espressif) | 0 of 5,247 (CI [0.000, 3.689]) | 0 of 5,247 (CI [0.000, 3.689]) | 0 of 5,247 (CI [0.000, 3.689]) | 0 of 5,247 (CI [0.000, 3.689]) |
| unregistered_mac | 0 of 8 (CI [0.000, 3.689]) | 0 of 8 (CI [0.000, 3.689]) | 0 of 8 (CI [0.000, 3.689]) | 0 of 8 (CI [0.000, 3.689]) |

## Notes

- XGB: 09 build_model / fit_model: XGBoost library defaults + scale_pos_weight = n_benign / n_attack of the model's own training rows, random_state 42, n_jobs -1; 70 features (features_v1.json order, float32); no search.
- Threshold rule: T_house: lowest observed house VAL score with <= 2 FP on the house's VAL benign rows (09 strategies common_threshold_rule, 09 max_fp_threshold); 0.5 fixed. Flag iff score >= thr.
- Night / daytime: daytime = split_plan_v1_1 test_only sessions ['BenignTraffic1', 'BenignTraffic2', 'BenignTraffic3']; night = every other plan session.
- predictions.parquet sha256 `af9c2789a3e408c11fd2188c8d78243a6d93227bda80ef464a4859398506d8fe`.
