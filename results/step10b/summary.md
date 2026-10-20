# Step 10b -- night false-alarm diagnostic

**EXPLORATORY / POST-HOC — not part of the pre-registered evaluation.**

- run 2026-10-20T04:51:21+00:00, git HEAD `d42fc4e1e9f1887ece0919aa8afa4aba163369c9`, 10b_night_fp_diagnostic.py sha256 `035ad5086c85f5cd...`; frozen inputs: predictions.parquet `af9c2789a3e408c1...`, test.parquet `0650b0fd0dcc01d8...`, prereg `17f627f841263e94...`
- thresholds (prereg, unchanged): FINAL T_house 0.568307638168335, 0.5; BASELINE T_house 0.5927605032920837, 0.5
- no training, no refit, no threshold search; every flag recomputed from the stored scores and checked against predictions.parquet; FP counts == results/step10/test/false_alarms.csv
- night benign rows linked 1:1 to their CICFlowMeter flows via 08's own filter (benign_night 16,104, DDoS-SYN_Flood10 16,251, DDoS-SYN_Flood15 7,452, Recon-PortScan 9,629, Mirai-udpplain24 5,278; start_ts, device and all 70 features equal); IP / MAC / role are diagnostic metadata only

## Short answers (FINAL @ T_house; BASELINE @ T_house in brackets)

- **H1 attack-session residue: SUPPORTED** [SUPPORTED]. Night pure-benign capture (benign_night): 0 FP / 1.355 h = 0.000/h [0.000, 2.722]; night attack-session captures (DDoS-SYN_Flood10, DDoS-SYN_Flood15, Recon-PortScan, Mirai-udpplain24): 19 FP / 1.663 h = 11.428/h [6.881, 17.847]; daytime: 0 FP / 18.742 h = 0.000/h [0.000, 0.197]. Attack-session FPs: 19 (inside a 07a window 12, inside 07's padded window 13, touching a 07a victim 7; |start - nearest window edge| median 310 s, range 50-1059 s).
- **H2 night-only device behaviour: INCONCLUSIVE** [INCONCLUSIVE]. 19 night FPs on 3 devices; top 3 hold 1.000 (Unidentified Amazon device (1c:12:b0) (Unidentified (Amazon)) 7 FP of 1,718 night rows, daytime 0 rows / 0 FP, train 1,829; Amazon Alexa Echo Dot 2 (Audio) 6 FP of 1,037 night rows, daytime 1,192 rows / 0 FP, train 1,254; Teckin Light Strip (Lighting) 6 FP of 380 night rows, daytime 1,242 rows / 0 FP, train 981). Busiest hour bin: DDoS-SYN_Flood10 from 2022-08-30T13:10:09+00:00 with 11 FP (0.579 of night FPs).
- **H3 testbed-Pi flows: NOT SUPPORTED** [NOT SUPPORTED]. 0 of 19 night FPs have a testbed-Pi / attacker-MAC endpoint; night benign rows with one: 290 of 54,714 (by session {'benign_night': 290, 'DDoS-SYN_Flood10': 0, 'DDoS-SYN_Flood15': 0, 'Recon-PortScan': 0, 'Mirai-udpplain24': 0}); FP rate Pi rows 0/290 vs non-Pi 19/54,424. Daytime: 07 excluded Pi flows ({'BenignTraffic1': 'attacker_offwindow 1,985', 'BenignTraffic2': 'attacker_offwindow 1,915, attacker_normal_traffic 18, attack_normal_service_ambiguous 12', 'BenignTraffic3': 'attacker_offwindow 761'}).

## Overlap of the two systems' FPs

| operating point | both | FINAL only | BASELINE only |
|---|---|---|---|
| T_house | 15 | 4 | 8 |
| 0.5 | 20 | 1 | 8 |

## H1: benign rows and FPs by session (test split)

| session | capture_kind | benign_rows | active_benign_hours_test | pi_involved_rows | rows_in_attack_window | FINAL@T_house | BASELINE@T_house | FINAL@0.5 | BASELINE@0.5 |
|---|---|---|---|---|---|---|---|---|---|
| benign_night | night pure-benign capture | 16104 | 1.355 | 290.0 | N/A | 0 -> 0.000/h [0.000, 2.722] | 0 -> 0.000/h [0.000, 2.722] | 0 -> 0.000/h [0.000, 2.722] | 0 -> 0.000/h [0.000, 2.722] |
| DDoS-SYN_Flood10 | night attack-session capture | 16251 | 0.587 | 0.0 | 16251 | 11 -> 18.741/h [9.356, 33.533] | 13 -> 22.149/h [11.793, 37.875] | 11 -> 18.741/h [9.356, 33.533] | 13 -> 22.149/h [11.793, 37.875] |
| DDoS-SYN_Flood15 | night attack-session capture | 7452 | 0.362 | 0.0 | 5318 | 8 -> 22.086/h [9.535, 43.518] | 8 -> 22.086/h [9.535, 43.518] | 10 -> 27.607/h [13.239, 50.771] | 11 -> 30.368/h [15.160, 54.337] |
| Recon-PortScan | night attack-session capture | 9629 | 0.462 | 0.0 | 6850 | 0 -> 0.000/h [0.000, 7.985] | 0 -> 0.000/h [0.000, 7.985] | 0 -> 0.000/h [0.000, 7.985] | 2 -> 4.329/h [0.524, 15.638] |
| Mirai-udpplain24 | night attack-session capture | 5278 | 0.251 | 0.0 | 5274 | 0 -> 0.000/h [0.000, 14.674] | 2 -> 7.956/h [0.963, 28.739] | 0 -> 0.000/h [0.000, 14.674] | 2 -> 7.956/h [0.963, 28.739] |
| BenignTraffic1 | daytime (pure benign) | 85321 | 7.248 |  |  | 0 -> 0.000/h [0.000, 0.509] | 0 -> 0.000/h [0.000, 0.509] | 0 -> 0.000/h [0.000, 0.509] | 0 -> 0.000/h [0.000, 0.509] |
| BenignTraffic2 | daytime (pure benign) | 94284 | 8.033 |  |  | 0 -> 0.000/h [0.000, 0.459] | 0 -> 0.000/h [0.000, 0.459] | 0 -> 0.000/h [0.000, 0.459] | 0 -> 0.000/h [0.000, 0.459] |
| BenignTraffic3 | daytime (pure benign) | 40754 | 3.461 |  |  | 0 -> 0.000/h [0.000, 1.066] | 0 -> 0.000/h [0.000, 1.066] | 0 -> 0.000/h [0.000, 1.066] | 0 -> 0.000/h [0.000, 1.066] |
| **pooled** | night pure-benign capture | 16104 | 1.355 |  |  | 0 -> 0.000/h [0.000, 2.722] | 0 -> 0.000/h [0.000, 2.722] | 0 -> 0.000/h [0.000, 2.722] | 0 -> 0.000/h [0.000, 2.722] |
| **pooled** | night attack-session capture | 38610 | 1.663 |  |  | 19 -> 11.428/h [6.881, 17.847] | 23 -> 13.834/h [8.770, 20.758] | 21 -> 12.631/h [7.819, 19.308] | 28 -> 16.842/h [11.191, 24.341] |
| **pooled** | daytime (pure benign) | 220359 | 18.742 |  |  | 0 -> 0.000/h [0.000, 0.197] | 0 -> 0.000/h [0.000, 0.197] | 0 -> 0.000/h [0.000, 0.197] | 0 -> 0.000/h [0.000, 0.197] |

## H2: night FPs by device (FINAL @ T_house; full table fp_by_device.csv)

| device | device_category | group | night_fp_final_T_house | night_fp_baseline_T_house | night_fp_final_0.5 | night_benign_rows | daytime_benign_rows | daytime_fp_final_0.5 | train_benign_rows |
|---|---|---|---|---|---|---|---|---|---|
| Unidentified Amazon device (1c:12:b0) | Unidentified (Amazon) | G1 | 7 | 4 | 7 | 1718 | 0 | 0 | 1829 |
| Amazon Alexa Echo Dot 2 | Audio | G1 | 6 | 6 | 6 | 1037 | 1192 | 0 | 1254 |
| Teckin Light Strip | Lighting | G2 | 6 | 6 | 6 | 380 | 1242 | 0 | 981 |
| Lumiman Bulb | Lighting | G2 | 0 | 3 | 0 | 553 | 1256 | 0 | 917 |
| HeimVision Smart WiFi Camera | Camera | G2 | 0 | 2 | 0 | 391 | 1662 | 0 | 973 |
| GoSund Power Strip (1) | Power Outlet | G2 | 0 | 1 | 1 | 221 | 1102 | 0 | 613 |
| GoSund Smart Plug WP2 (2) | Power Outlet | G2 | 0 | 1 | 1 | 208 | 1087 | 0 | 622 |

Time: fp_time_bins.csv (benign rows and FPs per session x hour since capture start).

## Duplicates (exact 70-feature vector in TRAIN, 09b row hash + exact check) and 09b fingerprints

| FPs of | n | train_equal_attack | train_equal_benign | train_equal_both | fp_syn_tool | fp_portscan_tool | any_09b_fingerprint |
|---|---|---|---|---|---|---|---|
| FINAL@T_house | 19 | 0 | 0 | 0 | 0 | 0 | 19 |
| FINAL@0.5 | 21 | 0 | 0 | 0 | 0 | 0 | 21 |
| BASELINE@T_house | 23 | 0 | 0 | 0 | 0 | 0 | 23 |
| BASELINE@0.5 | 28 | 0 | 0 | 0 | 0 | 0 | 28 |

Context: night benign rows 54,714 with the SYN tool value 3, port-scan tool value 0; daytime benign 220,359 with 11 / 0. Tool fingerprints: SYN = FWD Init Win Bytes 512; port scan = FWD Init Win Bytes 1024 AND Fwd Header Length 24 (09b fingerprints.csv).

## FP rows (FINAL or BASELINE @ T_house)

| row_id | systems_T_house | score_final | score_global | session | device | start_utc | src_role | dst_role | Dst Port | Protocol | pi_involved | in_attack_window | edge | train_equal_attack | train_equal_benign | fp_syn_tool | fp_portscan_tool |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 16356 | both | 0.9829 | 0.9591 | DDoS-SYN_Flood10 | Amazon Alexa Echo Dot 2 | 2022-08-30T13:11:10+00:00 | iot | iot | 55443 | 6.0 | False | True | 70 | 0 | 0 | False | False |
| 53931 | both | 0.9878 | 0.9810 | DDoS-SYN_Flood10 | Amazon Alexa Echo Dot 2 | 2022-08-30T13:14:10+00:00 | iot | iot | 55443 | 6.0 | False | True | 250 | 0 | 0 | False | False |
| 80039 | both | 0.9620 | 0.9878 | DDoS-SYN_Flood10 | Amazon Alexa Echo Dot 2 | 2022-08-30T13:17:20+00:00 | iot | iot | 55443 | 6.0 | False | True | 440 | 0 | 0 | False | False |
| 117966 | BASELINE only | 0.1761 | 0.8852 | DDoS-SYN_Flood10 | Lumiman Bulb | 2022-08-30T13:19:59+00:00 | iot | external | 20443 | 6.0 | False | True | 599 | 0 | 0 | False | False |
| 119634 | both | 0.9818 | 0.8356 | DDoS-SYN_Flood10 | Teckin Light Strip | 2022-08-30T13:24:43+00:00 | iot | external | 8886 | 6.0 | False | True | 883 | 0 | 0 | False | False |
| 119707 | both | 0.8822 | 0.8661 | DDoS-SYN_Flood10 | Amazon Alexa Echo Dot 2 | 2022-08-30T13:24:54+00:00 | iot | iot | 55443 | 6.0 | False | True | 894 | 0 | 0 | False | False |
| 119774 | both | 0.9988 | 0.9954 | DDoS-SYN_Flood10 | Teckin Light Strip | 2022-08-30T13:25:00+00:00 | iot | external | 8886 | 6.0 | False | True | 900 | 0 | 0 | False | False |
| 136465 | both | 0.9978 | 0.9943 | DDoS-SYN_Flood10 | Teckin Light Strip | 2022-08-30T13:26:25+00:00 | iot | external | 8886 | 6.0 | False | True | 985 | 0 | 0 | False | False |
| 142454 | both | 0.9978 | 0.9934 | DDoS-SYN_Flood10 | Teckin Light Strip | 2022-08-30T13:27:39+00:00 | iot | external | 8886 | 6.0 | False | True | 1059 | 0 | 0 | False | False |
| 163915 | both | 0.9978 | 0.9934 | DDoS-SYN_Flood10 | Teckin Light Strip | 2022-08-30T13:29:43+00:00 | iot | external | 8886 | 6.0 | False | True | 977 | 0 | 0 | False | False |
| 164551 | both | 0.9978 | 0.9943 | DDoS-SYN_Flood10 | Teckin Light Strip | 2022-08-30T13:29:56+00:00 | iot | external | 8886 | 6.0 | False | True | 964 | 0 | 0 | False | False |
| 242794 | both | 0.9280 | 0.7874 | DDoS-SYN_Flood10 | Amazon Alexa Echo Dot 2 | 2022-08-30T13:40:50+00:00 | iot | iot | 55443 | 6.0 | False | True | 310 | 0 | 0 | False | False |
| 284049 | BASELINE only | 0.1972 | 0.9274 | DDoS-SYN_Flood10 | Lumiman Bulb | 2022-08-30T13:45:20+00:00 | iot | external | 20443 | 6.0 | False | True | 40 | 0 | 0 | False | False |
| 316845 | BASELINE only | 0.1429 | 0.8793 | DDoS-SYN_Flood15 | HeimVision Smart WiFi Camera | 2022-11-29T19:22:27+00:00 | external | iot | 49954 | 6.0 | False | False | 27 | 0 | 0 | False | False |
| 319286 | BASELINE only | 0.1390 | 0.8719 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:22:49+00:00 | iot | external | 80 | 6.0 | False | False | 49 | 0 | 0 | False | False |
| 319424 | both | 0.6583 | 0.8504 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:22:50+00:00 | iot | external | 443 | 6.0 | False | False | 50 | 0 | 0 | False | False |
| 332123 | both | 0.9918 | 0.9788 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:23:07+00:00 | iot | external | 80 | 6.0 | False | False | 67 | 0 | 0 | False | False |
| 332124 | both | 0.9325 | 0.6413 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:23:08+00:00 | iot | external | 80 | 6.0 | False | False | 68 | 0 | 0 | False | False |
| 332127 | FINAL only | 0.6706 | 0.2440 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:23:10+00:00 | iot | external | 80 | 6.0 | False | False | 70 | 0 | 0 | False | False |
| 332883 | FINAL only | 0.9169 | 0.5187 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:23:15+00:00 | iot | external | 80 | 6.0 | False | False | 75 | 0 | 0 | False | False |
| 332887 | FINAL only | 0.9169 | 0.5187 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:23:17+00:00 | iot | external | 80 | 6.0 | False | False | 77 | 0 | 0 | False | False |
| 332974 | FINAL only | 0.9169 | 0.5187 | DDoS-SYN_Flood15 | Unidentified Amazon device (1c:12:b0) | 2022-11-29T19:23:20+00:00 | iot | external | 80 | 6.0 | False | False | 80 | 0 | 0 | False | False |
| 376392 | both | 0.9829 | 0.8568 | DDoS-SYN_Flood15 | Amazon Alexa Echo Dot 2 | 2022-12-01T14:37:38+00:00 | iot | iot | 55443 | 6.0 | False | True | 338 | 0 | 0 | False | False |
| 425151 | BASELINE only | 0.5447 | 0.9589 | DDoS-SYN_Flood15 | GoSund Power Strip (1) | 2022-12-01T14:42:59+00:00 | external | iot | 4426 | 6.0 | False | True | 61 | 0 | 0 | False | False |
| 436663 | BASELINE only | 0.5447 | 0.9589 | DDoS-SYN_Flood15 | GoSund Smart Plug WP2 (2) | 2022-12-01T14:42:59+00:00 | external | iot | 27274 | 6.0 | False | True | 61 | 0 | 0 | False | False |
| 471814 | BASELINE only | 0.1879 | 0.9335 | Mirai-udpplain24 | HeimVision Smart WiFi Camera | 2023-02-14T17:35:53+00:00 | external | iot | 49904 | 6.0 | False | True | 127 | 0 | 0 | False | False |
| 472256 | BASELINE only | 0.1761 | 0.8852 | Mirai-udpplain24 | Lumiman Bulb | 2023-02-14T17:34:04+00:00 | iot | external | 20443 | 6.0 | False | True | 236 | 0 | 0 | False | False |

## Verdict rules (fixed in the script, VERDICT)

- H1 SUPPORTED if the pooled attack-session benign FP/h 95% CI lower bound > the pure-benign night FP/h CI upper bound; NOT SUPPORTED if attack-session FP/h <= pure-benign night FP/h; else INCONCLUSIVE.
- H2 SUPPORTED if the top 3 devices hold >= 80% of night FPs and each has >= 1,000 daytime benign rows with 0 daytime FPs; NOT SUPPORTED if they hold < 50%; else INCONCLUSIVE. Feature values alone cannot show that a behaviour is absent by day, so SUPPORTED means 'a few devices that are quiet by day'.
- H3 SUPPORTED if >= 50% of night FPs have a testbed-Pi endpoint (device_table role testbed_pi or config ATTACKER_MACS); NOT SUPPORTED if none; else INCONCLUSIVE.
- Hours: night per session = results/step8/manifest_v1.json benign_active_hours per_session test; daytime = manifest_v1_1 hours per_session. Small-count CIs are wide (Garwood 95%).

*EXPLORATORY / POST-HOC — not part of the pre-registered evaluation.*
