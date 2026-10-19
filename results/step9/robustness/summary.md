# Step 9 robustness (shortlist x feature set x seed)

- run: 2026-10-19T16:20:11+00:00 | seeds [42, 7, 123] | models ['XGB', 'CAT', 'LGBM', 'MLP'] | feature sets ['full70', 'tool_agnostic67'] | features_v1 sha256 cf73976fd384a466... | verify_lock PASS
- evaluations OK: 168 of 168 planned (val: 72, unseen-session: 96).
- same constructors / params as bakeoff (library defaults + class weights; MLP keeps zero_duration_flag + StandardScaler); no search. **No winner is declared.**
- Val: PR-AUC, FP/h and DR at 0.5, and DR@<=1FP = lowest observed val score with <= 1 val FP; that threshold is chosen on val and DR is read on the same val (same-set threshold, optimistic).
- Unseen session, variant **capture_rotation** (GLOBAL, evaluations unseen_A / unseen_B, 09b check 5): train = the group's train rows minus every row of the held-out session (attack and benign); SYN DR = the held-out session's syn_flood rows of the group, train + val splits.
- Unseen session, variant **benign_holdout** (G1 / G2, evaluation benign_holdout): train = the group's train rows minus ONLY the held-out session's benign rows (every attack row kept, that session's SYN rows included); held-out SYN DR = N/A (the held-out session's SYN rows are in training). It measures false alarms on an unseen session's benign traffic only; it is not a capture rotation.
- Both variants: the <= 1 FP threshold is the lowest observed score of the group's val rows outside the held-out session with <= max_fp FP on those val benign rows (the threshold never sees the held-out session). (i) val benign = all of the group's val benign rows (09b check 5 definition); they include the held-out session's own val benign rows, which are also part of held_session_benign. (ii) held-out session benign = the held-out session's benign rows of the group, train + val splits.
- FP/hour = FP / active benign hours (08 rule) of exactly the rows evaluated; one FP is worth 1 / hours FP/h (column 'FP/h per FP' below), so small denominators make FP/h coarse.
- Table cells = mean (min-max) over the seeds that finished OK. Latency / size: seed 42 fit only; laptop proxies (WSL, 1 thread), not Pi numbers.
- GLOBAL = all train / val rows (G1 + G2 + GEN devices), same splits.

## Feature sets

| feature_set | n | removed | sha256 |
|---|---|---|---|
| full70 | 70 | - | cf73976fd384a466... |
| tool_agnostic67 | 67 | FWD Init Win Bytes, Fwd Seg Size Min, Fwd Header Length | cb8989bf0c218314... |

## Unseen-session evaluations

| group | evaluation | variant | held-out session | alias | removed from training | held-out SYN DR | SYN victims (group) |
|---|---|---|---|---|---|---|---|
| G1 | benign_holdout | benign_holdout | DDoS-SYN_Flood | SYN first part | only the session's benign rows | N/A | AMCREST WiFi Camera; Amazon Alexa Echo Dot 1; Google Nest Mini Speaker; Unidentified Amazon device (1c:12:b0) (G1) |
| G2 | benign_holdout | benign_holdout | DDoS-SYN_Flood5 | SYN 5 | only the session's benign rows | N/A | GoSund Smart Plug WP2 (1); Unidentified ESP plug (2); Unidentified ESP plug (3) (G2) |
| GLOBAL | unseen_A | capture_rotation | DDoS-SYN_Flood5 | SYN 5 | every row of the session | held-out session's SYN rows (train + val) | GoSund Smart Plug WP2 (1); Unidentified ESP plug (2); Unidentified ESP plug (3) (G2) |
| GLOBAL | unseen_B | capture_rotation | DDoS-SYN_Flood | SYN first part | every row of the session | held-out session's SYN rows (train + val) | AMCREST WiFi Camera; Amazon Alexa Echo Dot 1; Google Nest Mini Speaker; Unidentified Amazon device (1c:12:b0) (G1) |

## FP/hour denominators

| evaluation | benign rows | hours used | FP/h per FP | source |
|---|---|---|---|---|
| G1 val (A) | - | 1.9676 | 0.51 | computed: 08 benign_hours rule on manifest session_cuts + group benign starts (manifest has no per-group value) |
| G2 val (A) | - | 1.9676 | 0.51 | computed: 08 benign_hours rule on manifest session_cuts + group benign starts (manifest has no per-group value) |
| GLOBAL val (A) | - | 1.9676 | 0.51 | computed: 08 benign_hours rule on manifest session_cuts + group benign starts (manifest has no per-group value) |
| G1/benign_holdout (i) val benign | 35833 | 1.9676 | 0.51 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| G1/benign_holdout (ii) held-out session benign | 16799 | 0.6574 | 1.52 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| G2/benign_holdout (i) val benign | 3061 | 1.9676 | 0.51 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| G2/benign_holdout (ii) held-out session benign | 1476 | 0.4439 | 2.25 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| GLOBAL/unseen_A (i) val benign | 39185 | 1.9676 | 0.51 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| GLOBAL/unseen_A (ii) held-out session benign | 7690 | 0.4439 | 2.25 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| GLOBAL/unseen_B (i) val benign | 39185 | 1.9676 | 0.51 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| GLOBAL/unseen_B (ii) held-out session benign | 19238 | 0.6574 | 1.52 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |

## G1

### G1 1. model x feature set (mean (min-max) over seeds)

| model | feature_set | seeds OK (val) | PR-AUC | FP/h@0.5 | DR@<=1FP | unseen-session benign FP/h@0.5 (benign_holdout) | held-out SYN DR@0.5 (benign_holdout) | lat med us | lat p99 us | size | scores identical across seeds |
|---|---|---|---|---|---|---|---|---|---|---|---|
| XGB | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 1.02 (1.02-1.02) | 0.9997 (0.9997-0.9997) | 0.00 (0.00-0.00) | N/A | 125.6 | 906.3 | 156.4 kB | val yes, benign_holdout yes |
| XGB | tool_agnostic67 | 3/3 | 0.9999 (0.9999-0.9999) | 13.72 (13.72-13.72) | 0.8262 (0.8262-0.8262) | 85.18 (85.18-85.18) | N/A | 130.0 | 768.1 | 186.8 kB | val yes, benign_holdout yes |
| CAT | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 0.34 (0.00-0.51) | 0.9997 (0.9997-0.9997) | 21.30 (15.21-31.94) | N/A | 108.9 | 264.6 | 1.12 MB | val no, benign_holdout no |
| CAT | tool_agnostic67 | 3/3 | 0.9999 (0.9999-0.9999) | 14.74 (14.74-14.74) | 0.8223 (0.8195-0.8237) | 122.20 (120.17-124.73) | N/A | 116.3 | 294.9 | 1.12 MB | val no, benign_holdout no |
| LGBM | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 0.51 (0.51-0.51) | 0.9997 (0.9997-0.9997) | 28.39 (22.82-38.03) | N/A | 370.8 | 1094.4 | 353.4 kB | val no, benign_holdout no |
| LGBM | tool_agnostic67 | 3/3 | 0.9999 (0.9999-0.9999) | 14.23 (13.72-14.74) | 0.8260 (0.8162-0.8318) | 97.35 (91.27-103.44) | N/A | 375.2 | 896.8 | 353.7 kB | val no, benign_holdout no |
| MLP | full70 | 3/3 | 0.9999 (0.9999-1.0000) | 4.24 (0.51-11.18) | 0.3332 (0.0000-0.9997) | 41.58 (38.03-44.11) | N/A | 240.5 | 602.7 | 128.2 kB | val no, benign_holdout no |
| MLP | tool_agnostic67 | 3/3 | 0.9999 (0.9998-0.9999) | 13.89 (13.21-15.25) | 0.7111 (0.6857-0.7616) | 131.83 (126.25-138.42) | N/A | 224.6 | 599.7 | 123.4 kB | val no, benign_holdout no |

### G1 1b. unseen-session detail ((i) = val benign, (ii) = held-out session benign; thr = val-chosen <= 1 FP)

| evaluation | model | feature_set | seeds OK | n_train_syn | SYN n | SYN DR@0.5 | SYN DR@val<=1FP | val-chosen thr | (i) FP@0.5 | (i) FP@0.5 from held session | (i) FP/h@0.5 | (i) FP@thr | (ii) n | (ii) FP@0.5 | (ii) FP/h@0.5 | (ii) FP@thr | (ii) FP/h@thr |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign_holdout | XGB | full70 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | 0.669960 (0.669960-0.669960) | 2.0 (2.0-2.0) | 0.0 (0.0-0.0) | 1.02 (1.02-1.02) | 1.0 (1.0-1.0) | 16799 (16799-16799) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) |
| benign_holdout | XGB | tool_agnostic67 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | 0.998021 (0.998021-0.998021) | 28.0 (28.0-28.0) | 3.0 (3.0-3.0) | 14.23 (14.23-14.23) | 0.0 (0.0-0.0) | 16799 (16799-16799) | 56.0 (56.0-56.0) | 85.18 (85.18-85.18) | 6.0 (6.0-6.0) | 9.13 (9.13-9.13) |
| benign_holdout | CAT | full70 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | 0.686648 (0.630770-0.769150) | 5.7 (1.0-15.0) | 1.0 (0.0-3.0) | 2.88 (0.51-7.62) | 1.0 (1.0-1.0) | 16799 (16799-16799) | 14.0 (10.0-21.0) | 21.30 (15.21-31.94) | 7.7 (1.0-12.0) | 11.66 (1.52-18.25) |
| benign_holdout | CAT | tool_agnostic67 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | 0.996779 (0.996301-0.997226) | 30.0 (30.0-30.0) | 5.0 (5.0-5.0) | 15.25 (15.25-15.25) | 0.7 (0.0-1.0) | 16799 (16799-16799) | 80.3 (79.0-82.0) | 122.20 (120.17-124.73) | 1.0 (1.0-1.0) | 1.52 (1.52-1.52) |
| benign_holdout | LGBM | full70 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | 0.990246 (0.984377-0.996044) | 17.0 (17.0-17.0) | 4.0 (4.0-4.0) | 8.64 (8.64-8.64) | 0.7 (0.0-1.0) | 16799 (16799-16799) | 18.7 (15.0-25.0) | 28.39 (22.82-38.03) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) |
| benign_holdout | LGBM | tool_agnostic67 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | 0.997557 (0.997341-0.997742) | 29.3 (27.0-33.0) | 3.7 (3.0-4.0) | 14.91 (13.72-16.77) | 0.7 (0.0-1.0) | 16799 (16799-16799) | 64.0 (60.0-68.0) | 97.35 (91.27-103.44) | 6.7 (6.0-7.0) | 10.14 (9.13-10.65) |
| benign_holdout | MLP | full70 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | inf (0.999760-inf) | 19.7 (18.0-21.0) | 3.0 (3.0-3.0) | 10.00 (9.15-10.67) | 0.3 (0.0-1.0) | 16799 (16799-16799) | 27.3 (25.0-29.0) | 41.58 (38.03-44.11) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) |
| benign_holdout | MLP | tool_agnostic67 | 3/3 | 200605 (200605-200605) | N/A | N/A | N/A | 0.997840 (0.996444-0.999325) | 27.0 (26.0-28.0) | 5.0 (5.0-5.0) | 13.72 (13.21-14.23) | 0.7 (0.0-1.0) | 16799 (16799-16799) | 86.7 (83.0-91.0) | 131.83 (126.25-138.42) | 2.7 (2.0-3.0) | 4.06 (3.04-4.56) |

### G1 2. tool_agnostic67 minus full70 (difference of seed means)

| model | d PR-AUC | d FP/h@0.5 | d DR@0.5 | d DR@<=1FP | d unseen-session FP/h@0.5 (benign_holdout) | d held-out SYN DR@0.5 (benign_holdout) |
|---|---|---|---|---|---|---|
| XGB | -0.0001 | +12.71 | -0.0004 | -0.1735 | +85.18 | N/A |
| CAT | -0.0001 | +14.40 | -0.0003 | -0.1774 | +100.90 | N/A |
| LGBM | -0.0001 | +13.72 | -0.0004 | -0.1737 | +68.96 | N/A |
| MLP | -0.0001 | +9.66 | -0.0001 | +0.3778 | +90.25 | N/A |

### G1 3. between-model difference smaller than the model's own seed spread

| feature_set | metric | model | mean | seed spread (max-min) | models whose mean differs by less (|diff|) |
|---|---|---|---|---|---|
| full70 | PR-AUC | CAT | 1 | 7.888e-06 | LGBM (4.529e-06) |
| full70 | PR-AUC | MLP | 0.9999 | 0.0001126 | XGB (7.058e-05); CAT (6.164e-05); LGBM (6.617e-05) |
| full70 | FP/h@0.5 | CAT | 0.3388 | 0.5082 | LGBM (0.1694) |
| full70 | FP/h@0.5 | MLP | 4.235 | 10.67 | XGB (3.219); CAT (3.896); LGBM (3.727) |
| full70 | DR@<=1FP | LGBM | 0.9997 | 5.183e-05 | XGB (2.879e-05); CAT (1.728e-05) |
| full70 | DR@<=1FP | MLP | 0.3332 | 0.9997 | XGB (0.6665); CAT (0.6665); LGBM (0.6665) |
| full70 | unseen-session FP/h@0.5 (benign_holdout) | CAT | 21.3 | 16.73 | LGBM (7.099) |
| full70 | unseen-session FP/h@0.5 (benign_holdout) | LGBM | 28.39 | 15.21 | CAT (7.099); MLP (13.18) |
| tool_agnostic67 | PR-AUC | LGBM | 0.9999 | 4.315e-06 | XGB (3.032e-06) |
| tool_agnostic67 | FP/h@0.5 | LGBM | 14.23 | 1.016 | XGB (0.5082); CAT (0.5082); MLP (0.3388) |
| tool_agnostic67 | FP/h@0.5 | MLP | 13.89 | 2.033 | XGB (0.1694); CAT (0.8471); LGBM (0.3388) |
| tool_agnostic67 | DR@<=1FP | CAT | 0.8223 | 0.004198 | XGB (0.00395); LGBM (0.003726) |
| tool_agnostic67 | DR@<=1FP | LGBM | 0.826 | 0.01562 | XGB (0.0002246); CAT (0.003726) |
| tool_agnostic67 | unseen-session FP/h@0.5 (benign_holdout) | LGBM | 97.35 | 12.17 | XGB (12.17) |
| tool_agnostic67 | unseen-session FP/h@0.5 (benign_holdout) | MLP | 131.8 | 12.17 | CAT (9.634) |

### G1 4. caveats

- udp_flood (Mirai-udpplain.pcap, Mirai-udpplain24.pcap): LOW_N, n = 17 val attack rows; its per-family DR rests on < 50 rows.
- DR@<=1FP (val) and its per-family DRs use a same-set threshold (chosen and read on val): optimistic.
- benign_holdout (DDoS-SYN_Flood): only that session's benign rows are held out; its SYN rows are trained on, so held-out SYN DR is N/A. This is not a capture rotation (GLOBAL's unseen_A / unseen_B are).
- (i) val benign includes the held-out session's own val benign rows; those rows are also part of (ii) (column '(i) FP@0.5 from held session').
- MLP full70 seed 7 val: only flagging nothing meets <= 1 FP (threshold inf, DR 0)
- MLP full70 seed 123 val: only flagging nothing meets <= 1 FP (threshold inf, DR 0)
- MLP full70 seed 42 benign_holdout: only flagging nothing meets <= 1 val FP (threshold inf)
- MLP full70 seed 123 benign_holdout: only flagging nothing meets <= 1 val FP (threshold inf)

## G2

### G2 1. model x feature set (mean (min-max) over seeds)

| model | feature_set | seeds OK (val) | PR-AUC | FP/h@0.5 | DR@<=1FP | unseen-session benign FP/h@0.5 (benign_holdout) | held-out SYN DR@0.5 (benign_holdout) | lat med us | lat p99 us | size | scores identical across seeds |
|---|---|---|---|---|---|---|---|---|---|---|---|
| XGB | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | N/A | 145.0 | 601.6 | 93.9 kB | val yes, benign_holdout yes |
| XGB | tool_agnostic67 | 3/3 | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | 1.0000 (1.0000-1.0000) | 22.53 (22.53-22.53) | N/A | 142.7 | 434.7 | 117.8 kB | val yes, benign_holdout yes |
| CAT | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | 1.0000 (1.0000-1.0000) | 1.50 (0.00-4.51) | N/A | 118.4 | 268.6 | 345.6 kB | val no, benign_holdout no |
| CAT | tool_agnostic67 | 3/3 | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | 1.0000 (1.0000-1.0000) | 19.52 (15.77-22.53) | N/A | 108.3 | 167.2 | 835.8 kB | val no, benign_holdout no |
| LGBM | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | N/A | 348.4 | 735.5 | 349.9 kB | val no, benign_holdout no |
| LGBM | tool_agnostic67 | 3/3 | 1.0000 (1.0000-1.0000) | 0.00 (0.00-0.00) | 1.0000 (1.0000-1.0000) | 51.81 (51.81-51.81) | N/A | 348.4 | 567.8 | 353.2 kB | val no, benign_holdout no |
| MLP | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 1.02 (0.00-2.03) | 0.9595 (0.8831-1.0000) | 2.25 (0.00-4.51) | N/A | 206.5 | 397.8 | 128.6 kB | val no, benign_holdout no |
| MLP | tool_agnostic67 | 3/3 | 1.0000 (1.0000-1.0000) | 0.34 (0.00-1.02) | 0.9874 (0.9854-0.9901) | 20.28 (20.28-20.28) | N/A | 214.2 | 367.1 | 124.2 kB | val no, benign_holdout no |

### G2 1b. unseen-session detail ((i) = val benign, (ii) = held-out session benign; thr = val-chosen <= 1 FP)

| evaluation | model | feature_set | seeds OK | n_train_syn | SYN n | SYN DR@0.5 | SYN DR@val<=1FP | val-chosen thr | (i) FP@0.5 | (i) FP@0.5 from held session | (i) FP/h@0.5 | (i) FP@thr | (ii) n | (ii) FP@0.5 | (ii) FP/h@0.5 | (ii) FP@thr | (ii) FP/h@thr |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign_holdout | XGB | full70 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.126406 (0.126406-0.126406) | 0.0 (0.0-0.0) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 2.0 (2.0-2.0) | 1476 (1476-1476) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 1.0 (1.0-1.0) | 2.25 (2.25-2.25) |
| benign_holdout | XGB | tool_agnostic67 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.142090 (0.142090-0.142090) | 0.0 (0.0-0.0) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 0.0 (0.0-0.0) | 1476 (1476-1476) | 10.0 (10.0-10.0) | 22.53 (22.53-22.53) | 10.0 (10.0-10.0) | 22.53 (22.53-22.53) |
| benign_holdout | CAT | full70 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.069063 (0.056255-0.080598) | 0.0 (0.0-0.0) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 1.7 (1.0-2.0) | 1476 (1476-1476) | 0.7 (0.0-2.0) | 1.50 (0.00-4.51) | 5.7 (1.0-9.0) | 12.77 (2.25-20.28) |
| benign_holdout | CAT | tool_agnostic67 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.254761 (0.130216-0.480725) | 0.3 (0.0-1.0) | 0.3 (0.0-1.0) | 0.17 (0.00-0.51) | 1.3 (1.0-2.0) | 1476 (1476-1476) | 8.7 (7.0-10.0) | 19.52 (15.77-22.53) | 16.3 (13.0-23.0) | 36.80 (29.29-51.81) |
| benign_holdout | LGBM | full70 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.662022 (0.000043-0.993035) | 0.0 (0.0-0.0) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 1.0 (0.0-3.0) | 1476 (1476-1476) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 2.3 (0.0-7.0) | 5.26 (0.00-15.77) |
| benign_holdout | LGBM | tool_agnostic67 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.008824 (0.000928-0.023051) | 0.0 (0.0-0.0) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 1.0 (1.0-1.0) | 1476 (1476-1476) | 23.0 (23.0-23.0) | 51.81 (51.81-51.81) | 23.0 (23.0-23.0) | 51.81 (51.81-51.81) |
| benign_holdout | MLP | full70 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.690265 (0.199108-0.992817) | 1.7 (1.0-2.0) | 0.7 (0.0-1.0) | 0.85 (0.51-1.02) | 1.3 (1.0-2.0) | 1476 (1476-1476) | 1.0 (0.0-2.0) | 2.25 (0.00-4.51) | 0.7 (0.0-2.0) | 1.50 (0.00-4.51) |
| benign_holdout | MLP | tool_agnostic67 | 3/3 | 199985 (199985-199985) | N/A | N/A | N/A | 0.088391 (0.003374-0.140698) | 0.0 (0.0-0.0) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) | 1.0 (1.0-1.0) | 1476 (1476-1476) | 9.0 (9.0-9.0) | 20.28 (20.28-20.28) | 11.3 (10.0-14.0) | 25.53 (22.53-31.54) |

### G2 2. tool_agnostic67 minus full70 (difference of seed means)

| model | d PR-AUC | d FP/h@0.5 | d DR@0.5 | d DR@<=1FP | d unseen-session FP/h@0.5 (benign_holdout) | d held-out SYN DR@0.5 (benign_holdout) |
|---|---|---|---|---|---|---|
| XGB | -0.0000 | +0.00 | +0.0000 | +0.0000 | +22.53 | N/A |
| CAT | -0.0000 | +0.00 | -0.0000 | +0.0000 | +18.02 | N/A |
| LGBM | +0.0000 | +0.00 | -0.0001 | +0.0000 | +51.81 | N/A |
| MLP | -0.0000 | -0.68 | +0.0351 | +0.0279 | +18.02 | N/A |

### G2 3. between-model difference smaller than the model's own seed spread

| feature_set | metric | model | mean | seed spread (max-min) | models whose mean differs by less (|diff|) |
|---|---|---|---|---|---|
| full70 | PR-AUC | CAT | 1 | 5.465e-10 | XGB (9.109e-11) |
| full70 | PR-AUC | MLP | 1 | 4.385e-06 | XGB (1.662e-06); CAT (1.662e-06); LGBM (1.661e-06) |
| full70 | FP/h@0.5 | MLP | 1.016 | 2.033 | XGB (1.016); CAT (1.016); LGBM (1.016) |
| full70 | DR@<=1FP | MLP | 0.9595 | 0.1169 | XGB (0.04046); CAT (0.04046); LGBM (0.04046) |
| full70 | unseen-session FP/h@0.5 (benign_holdout) | CAT | 1.502 | 4.506 | XGB (1.502); LGBM (1.502); MLP (0.7509) |
| full70 | unseen-session FP/h@0.5 (benign_holdout) | MLP | 2.253 | 4.506 | XGB (2.253); CAT (0.7509); LGBM (2.253) |
| tool_agnostic67 | PR-AUC | CAT | 1 | 6.556e-09 | XGB (9.159e-11); LGBM (1.821e-09) |
| tool_agnostic67 | PR-AUC | LGBM | 1 | 1.913e-09 | XGB (1.913e-09); CAT (1.821e-09) |
| tool_agnostic67 | PR-AUC | MLP | 1 | 1.077e-05 | XGB (7.98e-06); CAT (7.98e-06); LGBM (7.982e-06) |
| tool_agnostic67 | FP/h@0.5 | MLP | 0.3388 | 1.016 | XGB (0.3388); CAT (0.3388); LGBM (0.3388) |
| tool_agnostic67 | unseen-session FP/h@0.5 (benign_holdout) | CAT | 19.52 | 6.758 | XGB (3.004); MLP (0.7509) |

### G2 4. caveats

- udp_flood (Mirai-udpplain.pcap, Mirai-udpplain24.pcap): N/A, n = 0 val attack rows; its per-family DR is not defined.
- DR@<=1FP (val) and its per-family DRs use a same-set threshold (chosen and read on val): optimistic.
- benign_holdout (DDoS-SYN_Flood5): only that session's benign rows are held out; its SYN rows are trained on, so held-out SYN DR is N/A. This is not a capture rotation (GLOBAL's unseen_A / unseen_B are).
- (i) val benign includes the held-out session's own val benign rows; those rows are also part of (ii) (column '(i) FP@0.5 from held session').

## GLOBAL

### GLOBAL 1. model x feature set (mean (min-max) over seeds)

| model | feature_set | seeds OK (val) | PR-AUC | FP/h@0.5 | DR@<=1FP | unseen-session benign FP/h@0.5 (unseen_A) | held-out SYN DR@0.5 (unseen_A) | unseen-session benign FP/h@0.5 (unseen_B) | held-out SYN DR@0.5 (unseen_B) | lat med us | lat p99 us | size | scores identical across seeds |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| XGB | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 1.52 (1.52-1.52) | 0.9998 (0.9998-0.9998) | 4.51 (4.51-4.51) | 1.0000 (1.0000-1.0000) | 28.90 (28.90-28.90) | 0.9976 (0.9976-0.9976) | 239.3 | 537.2 | 154.3 kB | val yes, unseen_A yes, unseen_B yes |
| XGB | tool_agnostic67 | 3/3 | 1.0000 (1.0000-1.0000) | 13.72 (13.72-13.72) | 0.8132 (0.8132-0.8132) | 108.14 (108.14-108.14) | 0.9914 (0.9914-0.9914) | 69.97 (69.97-69.97) | 0.9957 (0.9957-0.9957) | 132.2 | 286.2 | 173.0 kB | val yes, unseen_A yes, unseen_B yes |
| CAT | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 1.02 (1.02-1.02) | 0.9998 (0.9997-0.9998) | 8.26 (6.76-9.01) | 1.0000 (1.0000-1.0000) | 4.56 (4.56-4.56) | 0.9884 (0.9840-0.9921) | 107.9 | 179.4 | 1.12 MB | val no, unseen_A no, unseen_B no |
| CAT | tool_agnostic67 | 3/3 | 1.0000 (1.0000-1.0000) | 14.06 (13.72-14.23) | 0.7975 (0.7780-0.8165) | 155.44 (150.94-162.20) | 1.0000 (1.0000-1.0000) | 102.93 (101.92-104.96) | 0.9853 (0.9843-0.9866) | 107.0 | 179.6 | 1.12 MB | val no, unseen_A no, unseen_B no |
| LGBM | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 1.02 (1.02-1.02) | 0.9998 (0.9998-0.9998) | 4.51 (4.51-4.51) | 1.0000 (1.0000-1.0000) | 40.56 (30.42-50.20) | 0.9971 (0.9968-0.9974) | 347.4 | 566.1 | 352.7 kB | val no, unseen_A no, unseen_B no |
| LGBM | tool_agnostic67 | 3/3 | 1.0000 (1.0000-1.0000) | 14.23 (13.72-14.74) | 0.8169 (0.8124-0.8250) | 99.87 (99.12-101.38) | 0.9885 (0.9885-0.9885) | 70.48 (69.97-71.49) | 0.9918 (0.9870-0.9969) | 345.7 | 463.8 | 353.8 kB | val no, unseen_A no, unseen_B no |
| MLP | full70 | 3/3 | 1.0000 (1.0000-1.0000) | 4.07 (0.51-10.16) | 0.9996 (0.9996-0.9997) | 12.02 (6.76-18.02) | 1.0000 (1.0000-1.0000) | 50.70 (39.55-60.85) | 0.9328 (0.9120-0.9470) | 230.7 | 622.6 | 128.1 kB | val no, unseen_A no, unseen_B no |
| MLP | tool_agnostic67 | 3/3 | 0.9999 (0.9999-0.9999) | 14.23 (13.21-15.76) | 0.7337 (0.6269-0.7964) | 159.20 (153.19-162.20) | 0.9892 (0.9884-0.9906) | 105.47 (103.44-108.00) | 0.9247 (0.8981-0.9399) | 243.5 | 529.1 | 123.4 kB | val no, unseen_A no, unseen_B no |

### GLOBAL 1b. unseen-session detail ((i) = val benign, (ii) = held-out session benign; thr = val-chosen <= 1 FP)

| evaluation | model | feature_set | seeds OK | n_train_syn | SYN n | SYN DR@0.5 | SYN DR@val<=1FP | val-chosen thr | (i) FP@0.5 | (i) FP@0.5 from held session | (i) FP/h@0.5 | (i) FP@thr | (ii) n | (ii) FP@0.5 | (ii) FP/h@0.5 | (ii) FP@thr | (ii) FP/h@thr |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unseen_A | XGB | full70 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 1.0000 (1.0000-1.0000) | 1.0000 (1.0000-1.0000) | 0.466953 (0.466953-0.466953) | 2.0 (2.0-2.0) | 1.0 (1.0-1.0) | 1.02 (1.02-1.02) | 2.0 (2.0-2.0) | 7690 (7690-7690) | 2.0 (2.0-2.0) | 4.51 (4.51-4.51) | 2.0 (2.0-2.0) | 4.51 (4.51-4.51) |
| unseen_A | XGB | tool_agnostic67 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 0.9914 (0.9914-0.9914) | 0.9424 (0.9424-0.9424) | 0.998812 (0.998812-0.998812) | 27.0 (27.0-27.0) | 5.0 (5.0-5.0) | 13.72 (13.72-13.72) | 0.0 (0.0-0.0) | 7690 (7690-7690) | 48.0 (48.0-48.0) | 108.14 (108.14-108.14) | 7.0 (7.0-7.0) | 15.77 (15.77-15.77) |
| unseen_A | CAT | full70 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 1.0000 (1.0000-1.0000) | 1.0000 (1.0000-1.0000) | 0.432560 (0.259423-0.578143) | 3.3 (3.0-4.0) | 2.0 (2.0-2.0) | 1.69 (1.52-2.03) | 3.0 (3.0-3.0) | 7690 (7690-7690) | 3.7 (3.0-4.0) | 8.26 (6.76-9.01) | 4.0 (4.0-4.0) | 9.01 (9.01-9.01) |
| unseen_A | CAT | tool_agnostic67 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 1.0000 (1.0000-1.0000) | 0.9309 (0.9123-0.9419) | 0.998030 (0.997694-0.998200) | 32.0 (32.0-32.0) | 5.0 (5.0-5.0) | 16.26 (16.26-16.26) | 0.3 (0.0-1.0) | 7690 (7690-7690) | 69.0 (67.0-72.0) | 155.44 (150.94-162.20) | 6.0 (6.0-6.0) | 13.52 (13.52-13.52) |
| unseen_A | LGBM | full70 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 1.0000 (1.0000-1.0000) | 1.0000 (1.0000-1.0000) | 0.476615 (0.427626-0.552491) | 2.0 (2.0-2.0) | 1.0 (1.0-1.0) | 1.02 (1.02-1.02) | 2.0 (2.0-2.0) | 7690 (7690-7690) | 2.0 (2.0-2.0) | 4.51 (4.51-4.51) | 2.0 (2.0-2.0) | 4.51 (4.51-4.51) |
| unseen_A | LGBM | tool_agnostic67 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 0.9885 (0.9885-0.9885) | 0.9417 (0.9416-0.9419) | 0.998625 (0.998451-0.998777) | 26.3 (26.0-27.0) | 5.0 (5.0-5.0) | 13.38 (13.21-13.72) | 0.0 (0.0-0.0) | 7690 (7690-7690) | 44.3 (44.0-45.0) | 99.87 (99.12-101.38) | 6.0 (6.0-6.0) | 13.52 (13.52-13.52) |
| unseen_A | MLP | full70 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 1.0000 (1.0000-1.0000) | 0.9689 (0.9081-1.0000) | 0.877452 (0.635084-0.999999) | 6.3 (2.0-9.0) | 0.0 (0.0-0.0) | 3.22 (1.02-4.57) | 1.0 (1.0-1.0) | 7690 (7690-7690) | 5.3 (3.0-8.0) | 12.02 (6.76-18.02) | 1.7 (0.0-3.0) | 3.75 (0.00-6.76) |
| unseen_A | MLP | tool_agnostic67 | 3/3 | 200605 (200605-200605) | 250059 (250059-250059) | 0.9892 (0.9884-0.9906) | 0.9361 (0.9361-0.9362) | 0.997761 (0.995697-0.998998) | 29.7 (27.0-35.0) | 7.0 (5.0-10.0) | 15.08 (13.72-17.79) | 1.0 (1.0-1.0) | 7690 (7690-7690) | 70.7 (68.0-72.0) | 159.20 (153.19-162.20) | 11.0 (11.0-11.0) | 24.78 (24.78-24.78) |
| unseen_B | XGB | full70 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9976 (0.9976-0.9976) | 0.9961 (0.9961-0.9961) | 0.920877 (0.920877-0.920877) | 20.0 (20.0-20.0) | 7.0 (7.0-7.0) | 10.16 (10.16-10.16) | 1.0 (1.0-1.0) | 19238 (19238-19238) | 19.0 (19.0-19.0) | 28.90 (28.90-28.90) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) |
| unseen_B | XGB | tool_agnostic67 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9957 (0.9957-0.9957) | 0.8910 (0.8910-0.8910) | 0.998826 (0.998826-0.998826) | 28.0 (28.0-28.0) | 3.0 (3.0-3.0) | 14.23 (14.23-14.23) | 0.0 (0.0-0.0) | 19238 (19238-19238) | 46.0 (46.0-46.0) | 69.97 (69.97-69.97) | 4.0 (4.0-4.0) | 6.08 (6.08-6.08) |
| unseen_B | CAT | full70 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9884 (0.9840-0.9921) | 0.9894 (0.9852-0.9931) | 0.380884 (0.267973-0.590692) | 0.3 (0.0-1.0) | 0.0 (0.0-0.0) | 0.17 (0.00-0.51) | 1.0 (1.0-1.0) | 19238 (19238-19238) | 3.0 (3.0-3.0) | 4.56 (4.56-4.56) | 3.0 (3.0-3.0) | 4.56 (4.56-4.56) |
| unseen_B | CAT | tool_agnostic67 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9853 (0.9843-0.9866) | 0.8602 (0.8593-0.8618) | 0.997976 (0.997403-0.998340) | 29.7 (29.0-30.0) | 4.0 (4.0-4.0) | 15.08 (14.74-15.25) | 0.7 (0.0-1.0) | 19238 (19238-19238) | 67.7 (67.0-69.0) | 102.93 (101.92-104.96) | 1.0 (1.0-1.0) | 1.52 (1.52-1.52) |
| unseen_B | LGBM | full70 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9971 (0.9968-0.9974) | 0.9826 (0.9723-0.9885) | 0.989407 (0.985093-0.996691) | 21.3 (21.0-22.0) | 8.0 (8.0-8.0) | 10.84 (10.67-11.18) | 0.7 (0.0-1.0) | 19238 (19238-19238) | 26.7 (20.0-33.0) | 40.56 (30.42-50.20) | 0.0 (0.0-0.0) | 0.00 (0.00-0.00) |
| unseen_B | LGBM | tool_agnostic67 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9918 (0.9870-0.9969) | 0.8690 (0.8626-0.8731) | 0.999019 (0.998781-0.999212) | 26.7 (26.0-27.0) | 3.0 (3.0-3.0) | 13.55 (13.21-13.72) | 0.3 (0.0-1.0) | 19238 (19238-19238) | 46.3 (46.0-47.0) | 70.48 (69.97-71.49) | 3.7 (3.0-5.0) | 5.58 (4.56-7.61) |
| unseen_B | MLP | full70 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9328 (0.9120-0.9470) | 0.8656 (0.8402-0.8992) | 0.969685 (0.945687-0.982646) | 23.7 (22.0-26.0) | 7.3 (7.0-8.0) | 12.03 (11.18-13.21) | 1.0 (1.0-1.0) | 19238 (19238-19238) | 33.3 (26.0-40.0) | 50.70 (39.55-60.85) | 3.3 (1.0-5.0) | 5.07 (1.52-7.61) |
| unseen_B | MLP | tool_agnostic67 | 3/3 | 199985 (199985-199985) | 250708 (250708-250708) | 0.9247 (0.8981-0.9399) | 0.7584 (0.7273-0.7953) | 0.998226 (0.996855-0.999026) | 28.3 (28.0-29.0) | 5.0 (5.0-5.0) | 14.40 (14.23-14.74) | 1.0 (1.0-1.0) | 19238 (19238-19238) | 69.3 (68.0-71.0) | 105.47 (103.44-108.00) | 2.3 (2.0-3.0) | 3.55 (3.04-4.56) |

### GLOBAL 2. tool_agnostic67 minus full70 (difference of seed means)

| model | d PR-AUC | d FP/h@0.5 | d DR@0.5 | d DR@<=1FP | d unseen-session FP/h@0.5 (unseen_A) | d held-out SYN DR@0.5 (unseen_A) | d unseen-session FP/h@0.5 (unseen_B) | d held-out SYN DR@0.5 (unseen_B) |
|---|---|---|---|---|---|---|---|---|
| XGB | -0.0000 | +12.20 | -0.0002 | -0.1866 | +103.63 | -0.0086 | +41.07 | -0.0019 |
| CAT | -0.0000 | +13.04 | -0.0002 | -0.2023 | +147.18 | +0.0000 | +98.37 | -0.0030 |
| LGBM | -0.0000 | +13.21 | -0.0002 | -0.1829 | +95.37 | -0.0115 | +29.92 | -0.0052 |
| MLP | -0.0001 | +10.16 | -0.0051 | -0.2660 | +147.18 | -0.0108 | +54.76 | -0.0081 |

### GLOBAL 3. between-model difference smaller than the model's own seed spread

| feature_set | metric | model | mean | seed spread (max-min) | models whose mean differs by less (|diff|) |
|---|---|---|---|---|---|
| full70 | PR-AUC | CAT | 1 | 1.457e-06 | LGBM (1.065e-06) |
| full70 | PR-AUC | LGBM | 1 | 1.132e-06 | CAT (1.065e-06) |
| full70 | FP/h@0.5 | MLP | 4.066 | 9.657 | XGB (2.541); CAT (3.049); LGBM (3.049) |
| full70 | DR@<=1FP | CAT | 0.9998 | 0.0001267 | XGB (7.603e-05); LGBM (7.321e-05); MLP (0.0001126) |
| full70 | DR@<=1FP | LGBM | 0.9998 | 2.534e-05 | XGB (2.816e-06) |
| full70 | unseen-session FP/h@0.5 (unseen_A) | MLP | 12.02 | 11.26 | XGB (7.509); CAT (3.755); LGBM (7.509) |
| full70 | unseen-session FP/h@0.5 (unseen_B) | LGBM | 40.56 | 19.77 | XGB (11.66); MLP (10.14) |
| full70 | unseen-session FP/h@0.5 (unseen_B) | MLP | 50.7 | 21.3 | LGBM (10.14) |
| full70 | held-out SYN DR@0.5 (unseen_B) | LGBM | 0.9971 | 0.0005784 | XGB (0.0005691) |
| tool_agnostic67 | PR-AUC | CAT | 1 | 1.043e-05 | LGBM (7.286e-06) |
| tool_agnostic67 | PR-AUC | MLP | 0.9999 | 3.58e-05 | CAT (2.42e-05); LGBM (3.148e-05) |
| tool_agnostic67 | FP/h@0.5 | CAT | 14.06 | 0.5082 | XGB (0.3388); LGBM (0.1694); MLP (0.1694) |
| tool_agnostic67 | FP/h@0.5 | LGBM | 14.23 | 1.016 | XGB (0.5082); CAT (0.1694); MLP (0) |
| tool_agnostic67 | FP/h@0.5 | MLP | 14.23 | 2.541 | XGB (0.5082); CAT (0.1694); LGBM (0) |
| tool_agnostic67 | DR@<=1FP | CAT | 0.7975 | 0.03845 | XGB (0.01568); LGBM (0.0194) |
| tool_agnostic67 | DR@<=1FP | LGBM | 0.8169 | 0.01261 | XGB (0.003723) |
| tool_agnostic67 | DR@<=1FP | MLP | 0.7337 | 0.1695 | XGB (0.0795); CAT (0.06382); LGBM (0.08322) |
| tool_agnostic67 | unseen-session FP/h@0.5 (unseen_A) | CAT | 155.4 | 11.26 | MLP (3.755) |
| tool_agnostic67 | unseen-session FP/h@0.5 (unseen_A) | MLP | 159.2 | 9.011 | CAT (3.755) |
| tool_agnostic67 | unseen-session FP/h@0.5 (unseen_B) | CAT | 102.9 | 3.042 | MLP (2.535) |
| tool_agnostic67 | unseen-session FP/h@0.5 (unseen_B) | LGBM | 70.48 | 1.521 | XGB (0.507) |
| tool_agnostic67 | unseen-session FP/h@0.5 (unseen_B) | MLP | 105.5 | 4.563 | CAT (2.535) |
| tool_agnostic67 | held-out SYN DR@0.5 (unseen_A) | MLP | 0.9892 | 0.002191 | LGBM (0.0006718) |
| tool_agnostic67 | held-out SYN DR@0.5 (unseen_B) | LGBM | 0.9918 | 0.009924 | XGB (0.00389); CAT (0.006515) |

### GLOBAL 4. caveats

- udp_flood (Mirai-udpplain.pcap, Mirai-udpplain24.pcap): LOW_N, n = 17 val attack rows; its per-family DR rests on < 50 rows.
- DR@<=1FP (val) and its per-family DRs use a same-set threshold (chosen and read on val): optimistic.
- (i) val benign includes the held-out session's own val benign rows; those rows are also part of (ii) (column '(i) FP@0.5 from held session').

## General caveats

- GEN val holds benign rows only (no attacks), so GEN contributes FPs but no detections to GLOBAL.
- FP counts are small: FP/h moves in steps of 'FP/h per FP' (FP/hour denominators table); a between-seed or between-model difference of one or two FPs is one or two such steps.
