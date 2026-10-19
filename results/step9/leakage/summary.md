# Step 9b leakage / shortcut checks

- run: 2026-10-19T14:51:46+00:00 | seed 42 | features sha256 cf73976fd384a466... | verify_lock PASS
- Probe: XGBClassifier(scale_pos_weight=n_benign/n_attack of its training rows, random_state=42, n_jobs=-1), library defaults otherwise -- identical to 09_train_specialists.py bakeoff.
- Thresholds: 0.5 and the same-set threshold, optimistic (lowest observed score with <= 1 FP on the evaluated benign rows). FP/hour = 08 active-benign-hours rule on the evaluated benign rows.
- Pre-set flags: SHORTCUT_CANDIDATE max-AUC >= 0.99; FINGERPRINT family share >= 90% and benign share <= 5%; LOW_N < 50 attack rows.
- GLOBAL = all train / val rows (G1 + G2 + GEN devices), same splits. Facts only; no conclusion is drawn here.

## 1. Single-feature separability

SHORTCUT_CANDIDATE counts (of 70 features) per scope:

| group | split | overall | port_scan | syn_flood | udp_flood |
|---|---|---|---|---|---|
| G1 | train | 0 | 0 | 0 | 0 |
| G1 | val | 0 | 0 | 0 | 0 |
| G2 | train | 0 | 0 | 0 | 0 |
| G2 | val | 0 | 0 | 0 | 0 |
| GLOBAL | train | 0 | 0 | 0 | 0 |
| GLOBAL | val | 0 | 0 | 0 | 0 |

SHORTCUT_CANDIDATE, overall scope (benign vs all attacks):

_none_

Top-15 XGBoost gain (probe fitted on the group's train) with that feature's overall max-AUC on train / val:

**G1**

| rank | feature | gain | max_auc train | max_auc val | flag train | flag val |
|---|---|---|---|---|---|---|
| 1 | SYN Flag Count | 7625.4 | 0.9425 | 0.9194 |  |  |
| 2 | Fwd Seg Size Min | 2461.8 | 0.6548 | 0.5270 |  |  |
| 3 | ACK Flag Count | 423.5 | 0.5957 | 0.6890 |  |  |
| 4 | Packet Length Max | 161.0 | 0.9170 | 0.8944 |  |  |
| 5 | Subflow Fwd Packets | 22.9 | 0.7118 | 0.7573 |  |  |
| 6 | FWD Init Win Bytes | 19.5 | 0.7421 | 0.6635 |  |  |
| 7 | Total Bwd packets | 12.9 | 0.7904 | 0.8067 |  |  |
| 8 | Bwd IAT Total | 9.7 | 0.6381 | 0.6563 |  |  |
| 9 | Fwd Header Length | 6.7 | 0.6848 | 0.6230 |  |  |
| 10 | Total Length of Fwd Packet | 6.7 | 0.9115 | 0.8804 |  |  |
| 11 | Bwd Packet Length Min | 5.5 | 0.7561 | 0.7093 |  |  |
| 12 | Packet Length Mean | 3.9 | 0.9169 | 0.8944 |  |  |
| 13 | Bwd Header Length | 3.9 | 0.7466 | 0.7815 |  |  |
| 14 | Fwd Act Data Pkts | 3.5 | 0.6728 | 0.6812 |  |  |
| 15 | Active Mean | 3.4 | 0.5723 | 0.5547 |  |  |

**G2**

| rank | feature | gain | max_auc train | max_auc val | flag train | flag val |
|---|---|---|---|---|---|---|
| 1 | SYN Flag Count | 1423.0 | 0.9372 | 0.9587 |  |  |
| 2 | Bwd Header Length | 847.9 | 0.7447 | 0.7413 |  |  |
| 3 | Fwd Seg Size Min | 33.6 | 0.7289 | 0.7366 |  |  |
| 4 | Fwd IAT Total | 13.8 | 0.5283 | 0.8568 |  |  |
| 5 | Flow IAT Std | 13.7 | 0.5203 | 0.8547 |  |  |
| 6 | Packet Length Max | 8.7 | 0.9427 | 0.9691 |  |  |
| 7 | ACK Flag Count | 6.5 | 0.7215 | 0.7294 |  |  |
| 8 | Flow Duration | 4.0 | 0.5255 | 0.8568 |  |  |
| 9 | Bwd Packets/s | 2.3 | 0.6674 | 0.6859 |  |  |
| 10 | FWD Init Win Bytes | 1.9 | 0.5083 | 0.5030 |  |  |
| 11 | Flow IAT Min | 1.9 | 0.8727 | 0.7498 |  |  |
| 12 | Fwd Header Length | 1.6 | 0.6074 | 0.8625 |  |  |
| 13 | Flow Packets/s | 0.9 | 0.7580 | 0.7098 |  |  |
| 14 | Active Mean | 0.4 | 0.8160 | 0.8335 |  |  |
| 15 | Bwd Init Win Bytes | 0.4 | 0.6813 | 0.6876 |  |  |

**GLOBAL**

| rank | feature | gain | max_auc train | max_auc val | flag train | flag val |
|---|---|---|---|---|---|---|
| 1 | SYN Flag Count | 12102.7 | 0.9487 | 0.9014 |  |  |
| 2 | FWD Init Win Bytes | 1123.9 | 0.7167 | 0.6672 |  |  |
| 3 | ACK Flag Count | 239.6 | 0.6132 | 0.6896 |  |  |
| 4 | Fwd Header Length | 100.0 | 0.6620 | 0.5691 |  |  |
| 5 | Packet Length Max | 89.1 | 0.9205 | 0.9009 |  |  |
| 6 | Total Bwd packets | 41.1 | 0.7913 | 0.7993 |  |  |
| 7 | Total Fwd Packet | 26.3 | 0.6127 | 0.5108 |  |  |
| 8 | Flow IAT Mean | 20.9 | 0.8259 | 0.7684 |  |  |
| 9 | Subflow Fwd Packets | 12.3 | 0.6712 | 0.7277 |  |  |
| 10 | Fwd Seg Size Min | 11.8 | 0.6659 | 0.5460 |  |  |
| 11 | Flow Packets/s | 4.1 | 0.7486 | 0.7459 |  |  |
| 12 | Flow IAT Max | 3.6 | 0.7616 | 0.7167 |  |  |
| 13 | Flow IAT Std | 2.6 | 0.7006 | 0.5171 |  |  |
| 14 | Bwd Bulk Rate Avg | 2.2 | 0.5655 | 0.5548 |  |  |
| 15 | Bwd IAT Total | 2.1 | 0.6564 | 0.6623 |  |  |

LOW_N scopes (AUC on < 50 attack rows): G1 val udp_flood (n=17); GLOBAL val udp_flood (n=17)

## 2. Constant-value fingerprints (train)

135 (group, feature, family) rows checked; 11 flagged FINGERPRINT:

| group | feature | selected_as | attack_family | n_family | mode_value | family_share | benign_share | low_n |
|---|---|---|---|---|---|---|---|---|
| G1 | Fwd Header Length | top15_gain | port_scan | 50472 | 24.0 | 0.9471 | 0.0166 |  |
| G1 | SYN Flag Count | top15_gain | port_scan | 50472 | 1.0 | 0.9996 | 0.0022 |  |
| G2 | SYN Flag Count | top15_gain | port_scan | 43218 | 1.0 | 0.9995 | 0.0020 |  |
| GLOBAL | SYN Flag Count | top15_gain | port_scan | 98046 | 1.0 | 0.9996 | 0.0022 |  |
| G2 | ACK Flag Count | top15_gain | port_scan | 43218 | 1.0 | 0.9239 | 0.0246 |  |
| G1 | FWD Init Win Bytes | top15_gain | port_scan | 50472 | 1024.0 | 0.9487 | 0.0001 |  |
| G1 | FWD Init Win Bytes | top15_gain | syn_flood | 200605 | 512.0 | 0.9825 | 0.0000 |  |
| G2 | FWD Init Win Bytes | top15_gain | syn_flood | 199985 | 512.0 | 1.0000 | 0.0001 |  |
| GLOBAL | FWD Init Win Bytes | top15_gain | syn_flood | 400590 | 512.0 | 0.9912 | 0.0000 |  |
| G1 | Fwd Seg Size Min | top15_gain | port_scan | 50472 | 24.0 | 0.9471 | 0.0000 |  |
| G1 | Fwd Seg Size Min | top15_gain | syn_flood | 200605 | 20.0 | 0.9847 | 0.0398 |  |

## 3. Ablation (GLOBAL train -> GLOBAL val)

| variant | status | n_features | pr_auc | dr_t05 | fph_t05 | thr_t1fp | dr_t1fp | fp_t1fp | dr_t1fp_port_scan | dr_t1fp_syn_flood | dr_t1fp_udp_flood |
|---|---|---|---|---|---|---|---|---|---|---|---|
| full | OK | 70 | 1.0000 | 0.9998 | 1.52 | 0.805388 | 0.9998 | 1 | 1.0000 | 0.9999 | 0.4118 |
| minus_shortcut_overall | OK | 70 | 1.0000 | 0.9998 | 1.52 | 0.805388 | 0.9998 | 1 | 1.0000 | 0.9999 | 0.4118 |
| minus_top5_gain | OK | 65 | 0.9999 | 0.9997 | 44.22 | 0.975217 | 0.8360 | 1 | 1.0000 | 0.8063 | 0.4118 |

- full: removed 0 (-): -
- minus_shortcut_overall: removed 0 (SHORTCUT_CANDIDATE on GLOBAL train, overall scope (benign vs all attacks)): -
- minus_top5_gain: removed 5 (top-5 XGBoost gain, GLOBAL train full-feature probe): SYN Flag Count; FWD Init Win Bytes; ACK Flag Count; Fwd Header Length; Packet Length Max
- val udp_flood n = 17 (LOW_N if < 50).

## 4. Duplicates / label conflicts (GLOBAL, 70 feature values)

| item | rows_of | n_rows | denominator | fraction | n_groups | n_zero_duration | zero_duration_rows_in_denominator | n_one_packet |
|---|---|---|---|---|---|---|---|---|
| duplicate_within_split | train | 95212 | 636193 | 0.1497 | 20316 | 47636 | 47995 | 47501 |
| label_conflict_within_split | train | 598 | 636193 | 0.0009 | 2 | 518 | 47995 | 518 |
| duplicate_within_split | val | 41922 | 157558 | 0.2661 | 7553 | 25538 | 25688 | 25510 |
| label_conflict_within_split | val | 33 | 157558 | 0.0002 | 1 | 33 | 25688 | 33 |
| val_row_equals_a_train_row | val | 27126 | 157558 | 0.1722 | 1289 | 25519 | 25688 | 25485 |
| train_row_equals_a_val_row | train | 48515 | 636193 | 0.0763 |  | 46438 | 47995 | 46364 |
| label_conflict_train_plus_val | train | 686 | 636193 | 0.0011 | 3 | 606 | 47995 | 606 |
| label_conflict_train_plus_val | val | 131 | 157558 | 0.0008 | 3 | 105 | 25688 | 105 |

By y / family:

| item | rows_of | y | attack_family | n_rows | denominator | fraction | n_zero_duration |
|---|---|---|---|---|---|---|---|
| val_row_equals_a_train_row | val | 0 | (benign) | 7112 | 39185 | 0.1815 | 6530 |
| val_row_equals_a_train_row | val | 1 | port_scan | 3805 | 18179 | 0.2093 | 2800 |
| val_row_equals_a_train_row | val | 1 | syn_flood | 16208 | 100177 | 0.1618 | 16188 |
| val_row_equals_a_train_row | val | 1 | udp_flood | 1 | 17 | 0.0588 | 1 |
| label_conflict_train_plus_val | train | 0 | (benign) | 681 | 137462 | 0.0050 | 603 |
| label_conflict_train_plus_val | train | 1 | port_scan | 0 | 98046 | 0.0000 | 0 |
| label_conflict_train_plus_val | train | 1 | syn_flood | 4 | 400590 | 0.0000 | 3 |
| label_conflict_train_plus_val | train | 1 | udp_flood | 1 | 95 | 0.0105 | 0 |
| label_conflict_train_plus_val | val | 0 | (benign) | 130 | 39185 | 0.0033 | 104 |
| label_conflict_train_plus_val | val | 1 | port_scan | 0 | 18179 | 0.0000 | 0 |
| label_conflict_train_plus_val | val | 1 | syn_flood | 0 | 100177 | 0.0000 | 0 |
| label_conflict_train_plus_val | val | 1 | udp_flood | 1 | 17 | 0.0588 | 1 |

## 5. Cross-capture generalisation (SYN, GLOBAL)

| rotation | setting | held_out_session | held_out_victim_groups | n_attack_eval | pr_auc | dr_t05 | fp_t05 | fph_t05 | thr_t1fp | dr_t1fp | fp_t1fp | held_session_benign_fp_t05 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | held_out_capture | DDoS-SYN_Flood5 | G2 | 250059 | 1.0000 | 1.0000 | 2 | 1.02 | 0.762627 | 1.0000 | 1 | 2.0 |
| A | in_capture_baseline | DDoS-SYN_Flood5 | G2 | 50074 | 1.0000 | 1.0000 | 3 | 1.52 | 0.809187 | 1.0000 | 1 |  |
| B | held_out_capture | DDoS-SYN_Flood | G1 | 250708 | 1.0000 | 0.9976 | 20 | 10.16 | 0.886561 | 0.9971 | 1 | 19.0 |
| B | in_capture_baseline | DDoS-SYN_Flood | G1 | 50103 | 1.0000 | 0.9998 | 3 | 1.52 | 0.805388 | 0.9998 | 1 |  |

- rotation A held-out victims: GoSund Smart Plug WP2 (1); Unidentified ESP plug (2); Unidentified ESP plug (3)
- rotation B held-out victims: AMCREST WiFi Camera; Amazon Alexa Echo Dot 1; Google Nest Mini Speaker; Unidentified Amazon device (1c:12:b0)

## 6. Leave-victim-out (syn_flood, GLOBAL)

| victim | group | status | syn_rows_train | syn_rows_val | n_attack_eval | dr_t05 | fp_t05 | fph_t05 | thr_t1fp | dr_t1fp | fp_t1fp | note |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GoSund Smart Plug WP2 (1) | G2 | OK | 116443 | 0 | 116443 | 1.0000 | 1 | 0.51 | 0.923891 | 1.0000 | 1 |  |
| Unidentified ESP plug (2) | G2 | OK | 83542 | 22411 | 105953 | 1.0000 | 2 | 1.02 | 0.941280 | 1.0000 | 1 |  |
| Amazon Alexa Echo Dot 1 | G1 | OK | 70558 | 0 | 70558 | 0.9999 | 2 | 1.02 | 0.582725 | 0.9999 | 1 |  |
| Unidentified Amazon device (1c:12:b0) | G1 | OK | 70487 | 0 | 70487 | 0.9997 | 1 | 0.51 | 0.502227 | 0.9997 | 1 |  |
| Google Nest Mini Speaker | G1 | OK | 59560 | 0 | 59560 | 1.0000 | 3 | 1.52 | 0.915299 | 1.0000 | 1 |  |
| AMCREST WiFi Camera | G1 | OK | 0 | 50103 | 50103 | 0.9998 | 3 | 1.52 | 0.805388 | 0.9998 | 1 | victim has no SYN rows in train: this probe equals the full-train probe |
| Unidentified ESP plug (3) | G2 | OK | 0 | 27663 | 27663 | 1.0000 | 3 | 1.52 | 0.809187 | 1.0000 | 1 | victim has no SYN rows in train: this probe equals the full-train probe |

## FP/hour denominators used

| evaluation | benign_rows_used | hours_full | hours_used | rule |
|---|---|---|---|---|
| check3 GLOBAL val benign | 39185 | 1.9676 | 1.967583 | 08 benign_hours on manifest session_cuts |
| check5/6 val benign | 39185 | 1.9676 | 1.967583 | 08 benign_hours on manifest session_cuts |
