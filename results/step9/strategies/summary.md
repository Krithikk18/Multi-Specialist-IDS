# Step 9 grouping strategies (house level)

- run: 2026-10-19T17:49:21+00:00 | model XGB seed 42 | features_v1 sha256 cf73976fd384a466... | verify_lock PASS | strategies ['global', 'category', 'behaviour_k2', 'behaviour_k3', 'behaviour_k4'] | modes ['pure', 'shared_attack'] | evaluations ['val', 'benign_holdout_A', 'benign_holdout_B', 'rotation_A', 'rotation_B']
- XGBoost library defaults + scale_pos_weight = n_benign / n_attack of EACH model's own training rows (build_model); features_v1.json (70, float32); no search. **Facts only; no winner is declared.**
- Modes: pure = the group's own train rows (benign + attack); shared_attack = the group's own train BENIGN rows + every train attack row of every device (08's caps as built, no resampling). The GLOBAL model trains on every train row, so pure == shared_attack; strategy global runs once (mode 'both'). GEN devices are scored by the GLOBAL model (every train row) in every strategy.
- Scoring: every row is scored exactly once, by the model that owns its device under the strategy; every metric is computed on the combined (house-level) scores.
- Operating points: t = 0.5 in every model, and the common threshold = ONE threshold for every model of the strategy: the lowest observed house val score with <= max_fp FP on the whole house's val benign (budget per HOUSE, not per group) (same-set, optimistic). Benign holdout / rotation threshold: the same rule on the house's val rows outside the held-out session (the threshold never sees that session).
- Benign holdout: every model of the strategy refit on its training rows minus the held-out session's benign rows (every device; every attack row kept). Capture rotation: every model of the strategy refit on its training rows minus every row of the held-out session (attack + benign, every device). A = DDoS-SYN_Flood5, B = DDoS-SYN_Flood. (i) the held-out session's benign rows, train + val splits, every device; (ii) every val benign row of the house (includes the held-out session's own val benign rows).
- FP/hour = FP / active benign hours (08 rule) of exactly the rows evaluated (denominators below). Fits: a fit is keyed by its exact training row positions; identical training sets (e.g. behaviour_k2 G1 == behaviour_k3 G1, GLOBAL in every strategy) share one fit (XGB is deterministic here).

## 1. Strategy x mode (house level, val unless named)

| strategy | mode | n models | total size | PR-AUC | FP/h@0.5 (FP) | DR@0.5 | thr (<= 2 FP) | FP/h@thr (FP) | DR@thr | DR port_scan 0.5 / thr | DR syn_flood 0.5 / thr | DR udp_flood 0.5 / thr | holdout A session-benign FP/h@0.5 (FP) | holdout B session-benign FP/h@0.5 (FP) | rotation A SYN DR@0.5 | rotation B SYN DR@0.5 | lat med us | fit s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| global | both | 1 | 154.3 kB | 1.0000 | 1.52 (3) | 0.9998 | 0.592761 | 1.02 (2) | 0.9998 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.4706 / 0.4706 LOW_N | 4.51 (2) | 27.38 (18) | 1.0000 | 0.9976 | 98.8 | 8.6 |
| category | pure | 8 | 846.6 kB | 0.9999 | 0.00 (0) | 0.6628 | 0.338072 | 1.02 (2) | 0.6628 | 0.6885 / 0.6886 | 0.6581 / 0.6581 | 0.4118 / 0.4118 LOW_N | 24.78 (11) | 24.34 (16) | 0.0461 | 0.8505 | 98.5 | 12.4 |
| category | shared_attack | 8 | 881.1 kB | 1.0000 | 1.02 (2) | 0.9998 | 0.357884 | 1.02 (2) | 0.9998 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.4118 / 0.4118 LOW_N | 38.30 (17) | 36.51 (24) | 1.0000 | 0.9902 | 97.4 | 25.8 |
| behaviour_k2 | pure | 3 | 404.7 kB | 1.0000 | 1.02 (2) | 0.9999 | 0.516681 | 1.02 (2) | 0.9999 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.5294 / 0.5294 LOW_N | 2.25 (1) | 13.69 (9) | 0.1744 | 0.9981 | 99.2 | 13.1 |
| behaviour_k2 | shared_attack | 3 | 404.8 kB | 1.0000 | 1.52 (3) | 0.9998 | 0.568308 | 1.02 (2) | 0.9998 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.4706 / 0.4706 LOW_N | 20.28 (9) | 27.38 (18) | 1.0000 | 0.9980 | 98.3 | 15.5 |
| behaviour_k3 | pure | 4 | 488.8 kB | 1.0000 | 1.02 (2) | 0.9999 | 0.467818 | 1.02 (2) | 0.9999 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.5294 / 0.5294 LOW_N | 13.52 (6) | 13.69 (9) | 0.1744 | 0.9981 | 99.9 | 12.6 |
| behaviour_k3 | shared_attack | 4 | 490.8 kB | 1.0000 | 1.52 (3) | 0.9998 | 0.672026 | 1.02 (2) | 0.9998 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.4706 / 0.4706 LOW_N | 42.80 (19) | 27.38 (18) | 1.0000 | 0.9980 | 101.6 | 17.1 |
| behaviour_k4 | pure | 5 | 584.1 kB | 1.0000 | 1.52 (3) | 0.9999 | 0.626595 | 1.02 (2) | 0.9999 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.5294 / 0.5294 LOW_N | 15.77 (7) | 31.94 (21) | 0.1744 | 0.7896 | 98.6 | 11.6 |
| behaviour_k4 | shared_attack | 5 | 591.9 kB | 1.0000 | 0.51 (1) | 0.9999 | 0.556158 | 0.51 (1) | 0.9999 | 1.0000 / 1.0000 | 0.9999 / 0.9999 | 0.4118 / 0.4118 LOW_N | 47.31 (21) | 15.21 (10) | 1.0000 | 0.9977 | 101.8 | 19.1 |

## 2. shared_attack minus pure (per strategy)

| strategy | d PR-AUC | d FP@0.5 | d FP/h@0.5 | d DR@0.5 | d DR@thr | d DR port_scan 0.5 | d DR port_scan thr | d DR syn_flood 0.5 | d DR syn_flood thr | d DR udp_flood 0.5 | d DR udp_flood thr | d holdout A session-benign FP@0.5 | d holdout B session-benign FP@0.5 | d rotation A SYN DR@0.5 | d rotation B SYN DR@0.5 | d size | d fit s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| category | +0.0001 | +2 | +1.02 | +0.3371 | +0.3371 | +0.3115 | +0.3114 | +0.3418 | +0.3418 | +0.0000 | +0.0000 | +6 | +8 | +0.9539 | +0.1397 | +34.5 kB | +13.4 |
| behaviour_k2 | -0.0000 | +1 | +0.51 | -0.0000 | -0.0000 | +0.0000 | +0.0000 | -0.0000 | -0.0000 | -0.0588 | -0.0588 | +8 | +9 | +0.8256 | -0.0002 | +0.1 kB | +2.5 |
| behaviour_k3 | -0.0000 | +1 | +0.51 | -0.0000 | -0.0000 | +0.0000 | +0.0000 | -0.0000 | -0.0000 | -0.0588 | -0.0588 | +13 | +9 | +0.8256 | -0.0002 | +2.0 kB | +4.5 |
| behaviour_k4 | -0.0000 | -2 | -1.02 | +0.0000 | +0.0000 | +0.0000 | +0.0000 | +0.0000 | +0.0000 | -0.1176 | -0.1176 | +14 | -11 | +0.8256 | +0.2081 | +7.8 kB | +7.6 |

## 3. Unseen-family-in-group (val)

Val attack rows whose owning model has 0 training rows of that family; DR on exactly those rows.

| strategy | mode | family | val rows of family | scored by a model with 0 train rows of it | groups (rows) | DR@0.5 on those | DR@thr on those |
|---|---|---|---|---|---|---|---|
| category | pure | syn_flood | 100177 | 50103 | Camera (50103) | 0.3164 | 0.3165 |

Every other (strategy, mode, family) in unseen_family.csv: 0 such rows (26 rows).

## 4. Caveats

- udp_flood (Mirai-udpplain.pcap, Mirai-udpplain24.pcap): LOW_N, n = 17 val attack rows in the whole house; its DR rests on < 50 rows (one row = 6 percentage points).
- Common threshold: chosen on the house's val benign and DR read on the same val (same-set, optimistic); the holdout / rotation thresholds never see the held-out session, but (ii) all val benign includes the val rows the threshold was chosen on (<= 2 FP there by construction).
- FP/h steps: one val FP = 0.51 FP/h (house val 1.9676 h); held-out session benign denominators are smaller, so one FP there is a larger step (table below).
- GEN val holds benign rows only, so GEN contributes FPs but no detections; GEN is scored by GLOBAL in every strategy.
- shared_attack trains every group model on the other groups' attack rows too: the victims of an attack session are few devices, and 08's attack caps were drawn per (v1.0 group, family, split).
- Fits shared between strategies are fitted once (a fit is keyed by its exact training row positions; identical training sets (e.g. behaviour_k2 G1 == behaviour_k3 G1, GLOBAL in every strategy) share one fit (XGB is deterministic here)); fit time totals count a shared fit in every strategy that uses it.
- Latency / size are laptop proxies (WSL, 1 thread), not Pi numbers; the latency rows are a house-level val sample (mostly syn_flood rows).
- category pure rotation_A: 250059 of 250059 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (Power Outlet (116443); Unidentified (Espressif) (133616)): an unseen family there, not only an unseen capture.
- behaviour_k2 pure rotation_A: 250059 of 250059 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (G2 (250059)): an unseen family there, not only an unseen capture.
- behaviour_k3 pure rotation_A: 250059 of 250059 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (G2 (250059)): an unseen family there, not only an unseen capture.
- behaviour_k4 pure rotation_A: 250059 of 250059 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (G3 (250059)): an unseen family there, not only an unseen capture.
- category pure rotation_B: 250708 of 250708 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (Audio (200605); Camera (50103)): an unseen family there, not only an unseen capture.
- behaviour_k2 pure rotation_B: 250708 of 250708 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (G1 (250708)): an unseen family there, not only an unseen capture.
- behaviour_k3 pure rotation_B: 250708 of 250708 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (G1 (250708)): an unseen family there, not only an unseen capture.
- behaviour_k4 pure rotation_B: 250708 of 250708 held-out SYN rows are scored by a model with 0 train syn_flood rows after the holdout (G1 (180221); G2 (70487)): an unseen family there, not only an unseen capture.

## Detail: per-group breakdown (val; thr = the strategy's common threshold)

| strategy | mode | group | scored by | devices | val n | val benign | FP@0.5 | FP@thr | port_scan: n val / DR@0.5 / DR@thr / n train | syn_flood: n val / DR@0.5 / DR@thr / n train | udp_flood: n val / DR@0.5 / DR@thr / n train | n train (benign / attack) | fit shared with |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| global | both | GLOBAL | GLOBAL | 56 | 157558 | 39185 | 3 | 2 | 18179 / 1.0000 / 1.0000 / 98046 | 100177 / 0.9999 / 0.9999 / 400590 | 17 / 0.4706 / 0.4706 / 95 | 636193 (137462 / 498731) | category/GLOBAL/pure; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/pure; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/pure; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/pure; behaviour_k4/GLOBAL/shared_attack |
| category | pure | Audio | Audio | 8 | 12068 | 6286 | 0 | 2 | 5765 / 0.5650 / 0.5650 / 16963 | 0 / - / - / 200605 | 17 / 0.4118 / 0.4118 / 79 | 248513 (30866 / 217647) | - |
| category | pure | Camera | Camera | 14 | 60234 | 10131 | 0 | 0 | 0 / - / - / 34848 | 50103 / 0.3164 / 0.3165 / 0 | 0 / - / - / 0 | 88247 (53399 / 34848) | - |
| category | pure | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/pure; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/pure; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/pure; behaviour_k4/GLOBAL/shared_attack |
| category | pure | Home Automation | Home Automation | 6 | 7695 | 1599 | 0 | 0 | 6096 / 0.9977 / 0.9977 / 6221 | 0 / - / - / 0 | 0 / - / - / 0 | 11165 (4944 / 6221) | - |
| category | pure | Hub | Hub | 6 | 17049 | 17049 | 0 | 0 | 0 / - / - / 4111 | 0 / - / - / 0 | 0 / - / - / 16 | 34823 (30696 / 4127) | - |
| category | pure | Lighting | Lighting | 5 | 6918 | 600 | 0 | 0 | 6318 / 0.5030 / 0.5032 / 1151 | 0 / - / - / 0 | 0 / - / - / 0 | 4575 (3424 / 1151) | - |
| category | pure | Power Outlet | Power Outlet | 10 | 2741 | 2741 | 0 | 0 | 0 / - / - / 22282 | 0 / - / - / 116443 | 0 / - / - / 0 | 149256 (10531 / 138725) | - |
| category | pure | Unidentified (Espressif) | Unidentified (Espressif) | 4 | 50562 | 488 | 0 | 0 | 0 / - / - / 8114 | 50074 / 1.0000 / 1.0000 / 83542 | 0 / - / - / 0 | 94103 (2447 / 91656) | - |
| category | shared_attack | Audio | Audio | 8 | 12068 | 6286 | 0 | 0 | 5765 / 1.0000 / 1.0000 / 98046 | 0 / - / - / 400590 | 17 / 0.4118 / 0.4118 / 95 | 529597 (30866 / 498731) | - |
| category | shared_attack | Camera | Camera | 14 | 60234 | 10131 | 0 | 0 | 0 / - / - / 98046 | 50103 / 0.9998 / 0.9998 / 400590 | 0 / - / - / 95 | 552130 (53399 / 498731) | - |
| category | shared_attack | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/pure; behaviour_k2/GLOBAL/pure; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/pure; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/pure; behaviour_k4/GLOBAL/shared_attack |
| category | shared_attack | Home Automation | Home Automation | 6 | 7695 | 1599 | 1 | 1 | 6096 / 1.0000 / 1.0000 / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 503675 (4944 / 498731) | - |
| category | shared_attack | Hub | Hub | 6 | 17049 | 17049 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 529427 (30696 / 498731) | - |
| category | shared_attack | Lighting | Lighting | 5 | 6918 | 600 | 0 | 0 | 6318 / 1.0000 / 1.0000 / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 502155 (3424 / 498731) | - |
| category | shared_attack | Power Outlet | Power Outlet | 10 | 2741 | 2741 | 1 | 1 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 509262 (10531 / 498731) | - |
| category | shared_attack | Unidentified (Espressif) | Unidentified (Espressif) | 4 | 50562 | 488 | 0 | 0 | 0 / - / - / 98046 | 50074 / 1.0000 / 1.0000 / 400590 | 0 / - / - / 95 | 501178 (2447 / 498731) | - |
| behaviour_k2 | pure | G1 | G1 | 26 | 93716 | 35833 | 2 | 2 | 7763 / 1.0000 / 1.0000 / 50472 | 50103 / 0.9998 / 0.9998 / 200605 | 17 / 0.5294 / 0.5294 / 95 | 371200 (120028 / 251172) | behaviour_k3/G1/pure |
| behaviour_k2 | pure | G2 | G2 | 27 | 63551 | 3061 | 0 | 0 | 10416 / 1.0000 / 1.0000 / 43218 | 50074 / 1.0000 / 1.0000 / 199985 | 0 / - / - / 0 | 259482 (16279 / 243203) | - |
| behaviour_k2 | pure | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/pure; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/pure; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/pure; behaviour_k4/GLOBAL/shared_attack |
| behaviour_k2 | shared_attack | G1 | G1 | 26 | 93716 | 35833 | 2 | 2 | 7763 / 1.0000 / 1.0000 / 98046 | 50103 / 0.9998 / 0.9998 / 400590 | 17 / 0.4706 / 0.4706 / 95 | 618759 (120028 / 498731) | behaviour_k3/G1/shared_attack |
| behaviour_k2 | shared_attack | G2 | G2 | 27 | 63551 | 3061 | 1 | 0 | 10416 / 1.0000 / 1.0000 / 98046 | 50074 / 1.0000 / 1.0000 / 400590 | 0 / - / - / 95 | 515010 (16279 / 498731) | - |
| behaviour_k2 | shared_attack | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/pure; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/pure; behaviour_k3/GLOBAL/pure; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/pure; behaviour_k4/GLOBAL/shared_attack |
| behaviour_k3 | pure | G1 | G1 | 26 | 93716 | 35833 | 2 | 2 | 7763 / 1.0000 / 1.0000 / 50472 | 50103 / 0.9998 / 0.9999 / 200605 | 17 / 0.5294 / 0.5294 / 95 | 371200 (120028 / 251172) | behaviour_k2/G1/pure |
| behaviour_k3 | pure | G2 | G2 | 20 | 60892 | 2498 | 0 | 0 | 8320 / 1.0000 / 1.0000 / 31817 | 50074 / 1.0000 / 1.0000 / 199985 | 0 / - / - / 0 | 244658 (12856 / 231802) | behaviour_k4/G3/pure |
| behaviour_k3 | pure | G3 | G3 | 7 | 2659 | 563 | 0 | 0 | 2096 / 1.0000 / 1.0000 / 11401 | 0 / - / - / 0 | 0 / - / - / 0 | 14824 (3423 / 11401) | behaviour_k4/G4/pure |
| behaviour_k3 | pure | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/pure; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/pure; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/pure; behaviour_k4/GLOBAL/shared_attack |
| behaviour_k3 | shared_attack | G1 | G1 | 26 | 93716 | 35833 | 2 | 1 | 7763 / 1.0000 / 1.0000 / 98046 | 50103 / 0.9998 / 0.9998 / 400590 | 17 / 0.4706 / 0.4706 / 95 | 618759 (120028 / 498731) | behaviour_k2/G1/shared_attack |
| behaviour_k3 | shared_attack | G2 | G2 | 20 | 60892 | 2498 | 0 | 0 | 8320 / 1.0000 / 1.0000 / 98046 | 50074 / 1.0000 / 1.0000 / 400590 | 0 / - / - / 95 | 511587 (12856 / 498731) | behaviour_k4/G3/shared_attack |
| behaviour_k3 | shared_attack | G3 | G3 | 7 | 2659 | 563 | 1 | 1 | 2096 / 1.0000 / 1.0000 / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 502154 (3423 / 498731) | behaviour_k4/G4/shared_attack |
| behaviour_k3 | shared_attack | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/pure; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/pure; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/pure; behaviour_k4/GLOBAL/pure; behaviour_k4/GLOBAL/shared_attack |
| behaviour_k4 | pure | G1 | G1 | 15 | 70495 | 12612 | 3 | 2 | 7763 / 1.0000 / 1.0000 / 31173 | 50103 / 0.9998 / 0.9998 / 130118 | 17 / 0.5294 / 0.5294 / 95 | 222888 (61502 / 161386) | - |
| behaviour_k4 | pure | G2 | G2 | 11 | 23221 | 23221 | 0 | 0 | 0 / - / - / 19299 | 0 / - / - / 70487 | 0 / - / - / 0 | 148312 (58526 / 89786) | - |
| behaviour_k4 | pure | G3 | G3 | 20 | 60892 | 2498 | 0 | 0 | 8320 / 1.0000 / 1.0000 / 31817 | 50074 / 1.0000 / 1.0000 / 199985 | 0 / - / - / 0 | 244658 (12856 / 231802) | behaviour_k3/G2/pure |
| behaviour_k4 | pure | G4 | G4 | 7 | 2659 | 563 | 0 | 0 | 2096 / 1.0000 / 1.0000 / 11401 | 0 / - / - / 0 | 0 / - / - / 0 | 14824 (3423 / 11401) | behaviour_k3/G3/pure |
| behaviour_k4 | pure | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/pure; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/pure; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/pure; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/shared_attack |
| behaviour_k4 | shared_attack | G1 | G1 | 15 | 70495 | 12612 | 0 | 0 | 7763 / 1.0000 / 1.0000 / 98046 | 50103 / 0.9999 / 0.9999 / 400590 | 17 / 0.4118 / 0.4118 / 95 | 560233 (61502 / 498731) | - |
| behaviour_k4 | shared_attack | G2 | G2 | 11 | 23221 | 23221 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 557257 (58526 / 498731) | - |
| behaviour_k4 | shared_attack | G3 | G3 | 20 | 60892 | 2498 | 0 | 0 | 8320 / 1.0000 / 1.0000 / 98046 | 50074 / 1.0000 / 1.0000 / 400590 | 0 / - / - / 95 | 511587 (12856 / 498731) | behaviour_k3/G2/shared_attack |
| behaviour_k4 | shared_attack | G4 | G4 | 7 | 2659 | 563 | 1 | 1 | 2096 / 1.0000 / 1.0000 / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 502154 (3423 / 498731) | behaviour_k3/G3/shared_attack |
| behaviour_k4 | shared_attack | GEN | GLOBAL | 3 | 291 | 291 | 0 | 0 | 0 / - / - / 98046 | 0 / - / - / 400590 | 0 / - / - / 95 | 636193 (137462 / 498731) | global/GLOBAL/both; category/GLOBAL/pure; category/GLOBAL/shared_attack; behaviour_k2/GLOBAL/pure; behaviour_k2/GLOBAL/shared_attack; behaviour_k3/GLOBAL/pure; behaviour_k3/GLOBAL/shared_attack; behaviour_k4/GLOBAL/pure |

## Detail: benign holdout ((i) held-out session benign, train + val; (ii) all val benign)

| strategy | mode | evaluation | session | models refit | train benign removed | thr | (i) n | (i) FP@0.5 | (i) FP/h@0.5 | (i) FP@thr | (i) FP/h@thr | (ii) n | (ii) FP@0.5 | (ii) FP/h@0.5 | (ii) FP@thr | (ii) FP/h@thr | (ii) FP@0.5 / @thr from held session |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| global | both | benign_holdout_A | DDoS-SYN_Flood5 | 1/1 | 6559 | 0.475780 | 7690 | 2 | 4.51 | 2 | 4.51 | 39185 | 2 | 1.02 | 3 | 1.52 | 1 / 1 |
| category | pure | benign_holdout_A | DDoS-SYN_Flood5 | 8/8 | 6559 | 0.200504 | 7690 | 11 | 24.78 | 12 | 27.03 | 39185 | 0 | 0.00 | 2 | 1.02 | 0 / 0 |
| category | shared_attack | benign_holdout_A | DDoS-SYN_Flood5 | 8/8 | 6559 | 0.195429 | 7690 | 17 | 38.30 | 19 | 42.80 | 39185 | 2 | 1.02 | 4 | 2.03 | 2 / 2 |
| behaviour_k2 | pure | benign_holdout_A | DDoS-SYN_Flood5 | 3/3 | 6559 | 0.487865 | 7690 | 1 | 2.25 | 1 | 2.25 | 39185 | 1 | 0.51 | 2 | 1.02 | 0 / 0 |
| behaviour_k2 | shared_attack | benign_holdout_A | DDoS-SYN_Flood5 | 3/3 | 6559 | 0.686390 | 7690 | 9 | 20.28 | 5 | 11.26 | 39185 | 2 | 1.02 | 2 | 1.02 | 0 / 0 |
| behaviour_k3 | pure | benign_holdout_A | DDoS-SYN_Flood5 | 4/4 | 6559 | 0.487865 | 7690 | 6 | 13.52 | 6 | 13.52 | 39185 | 1 | 0.51 | 2 | 1.02 | 0 / 0 |
| behaviour_k3 | shared_attack | benign_holdout_A | DDoS-SYN_Flood5 | 4/4 | 6559 | 0.686390 | 7690 | 19 | 42.80 | 18 | 40.55 | 39185 | 3 | 1.52 | 3 | 1.52 | 1 / 1 |
| behaviour_k4 | pure | benign_holdout_A | DDoS-SYN_Flood5 | 5/5 | 6559 | 0.315928 | 7690 | 7 | 15.77 | 8 | 18.02 | 39185 | 2 | 1.02 | 2 | 1.02 | 0 / 0 |
| behaviour_k4 | shared_attack | benign_holdout_A | DDoS-SYN_Flood5 | 5/5 | 6559 | 0.147827 | 7690 | 21 | 47.31 | 26 | 58.57 | 39185 | 1 | 0.51 | 3 | 1.52 | 1 / 1 |
| global | both | benign_holdout_B | DDoS-SYN_Flood | 1/1 | 16799 | 0.790897 | 19238 | 18 | 27.38 | 0 | 0.00 | 39185 | 20 | 10.16 | 2 | 1.02 | 7 / 0 |
| category | pure | benign_holdout_B | DDoS-SYN_Flood | 8/8 | 16799 | 0.723084 | 19238 | 16 | 24.34 | 4 | 6.08 | 39185 | 11 | 5.59 | 0 | 0.00 | 5 / 0 |
| category | shared_attack | benign_holdout_B | DDoS-SYN_Flood | 8/8 | 16799 | 0.905955 | 19238 | 24 | 36.51 | 5 | 7.61 | 39185 | 7 | 3.56 | 2 | 1.02 | 5 / 0 |
| behaviour_k2 | pure | benign_holdout_B | DDoS-SYN_Flood | 3/3 | 16799 | 0.571438 | 19238 | 9 | 13.69 | 6 | 9.13 | 39185 | 8 | 4.07 | 4 | 2.03 | 4 / 2 |
| behaviour_k2 | shared_attack | benign_holdout_B | DDoS-SYN_Flood | 3/3 | 16799 | 0.723128 | 19238 | 18 | 27.38 | 0 | 0.00 | 39185 | 21 | 10.67 | 2 | 1.02 | 7 / 0 |
| behaviour_k3 | pure | benign_holdout_B | DDoS-SYN_Flood | 4/4 | 16799 | 0.571438 | 19238 | 9 | 13.69 | 6 | 9.13 | 39185 | 6 | 3.05 | 4 | 2.03 | 4 / 2 |
| behaviour_k3 | shared_attack | benign_holdout_B | DDoS-SYN_Flood | 4/4 | 16799 | 0.737614 | 19238 | 18 | 27.38 | 0 | 0.00 | 39185 | 21 | 10.67 | 2 | 1.02 | 7 / 0 |
| behaviour_k4 | pure | benign_holdout_B | DDoS-SYN_Flood | 5/5 | 16799 | 0.877847 | 19238 | 21 | 31.94 | 0 | 0.00 | 39185 | 21 | 10.67 | 1 | 0.51 | 8 / 0 |
| behaviour_k4 | shared_attack | benign_holdout_B | DDoS-SYN_Flood | 5/5 | 16799 | 0.619005 | 19238 | 10 | 15.21 | 6 | 9.13 | 39185 | 6 | 3.05 | 4 | 2.03 | 4 / 2 |

## Detail: capture rotation (SYN = held-out session's syn_flood rows, train + val)

| strategy | mode | evaluation | session | models refit | thr | SYN n | SYN DR@0.5 | SYN DR@thr | SYN rows by a 0-train-SYN model | their DR@0.5 / @thr | 0-train-SYN groups (rows) | (i) FP@0.5 (FP/h) | (i) FP@thr (FP/h) | (ii) FP@0.5 / @thr | SYN by group (n, DR@0.5, DR@thr, n train SYN) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| global | both | rotation_A | DDoS-SYN_Flood5 | 1/1 | 0.232760 | 250059 | 1.0000 | 1.0000 | 0 | - / - | - | 2 (4.51) | 2 (4.51) | 2 / 3 | GLOBAL: 250059, 1.0000, 1.0000, 200605 |
| category | pure | rotation_A | DDoS-SYN_Flood5 | 8/8 | 0.200504 | 250059 | 0.0461 | 0.0461 | 250059 | 0.0461 / 0.0461 | Power Outlet (116443); Unidentified (Espressif) (133616) | 1 (2.25) | 2 (4.51) | 0 / 2 | Power Outlet: 116443, 0.0249, 0.0249, 0 | Unidentified (Espressif): 133616, 0.0645, 0.0645, 0 |
| category | shared_attack | rotation_A | DDoS-SYN_Flood5 | 8/8 | 0.259024 | 250059 | 1.0000 | 1.0000 | 0 | - / - | - | 17 (38.30) | 18 (40.55) | 2 / 4 | Power Outlet: 116443, 1.0000, 1.0000, 200605 | Unidentified (Espressif): 133616, 1.0000, 1.0000, 200605 |
| behaviour_k2 | pure | rotation_A | DDoS-SYN_Flood5 | 3/3 | 0.487865 | 250059 | 0.1744 | 0.1744 | 250059 | 0.1744 / 0.1744 | G2 (250059) | 3 (6.76) | 3 (6.76) | 1 / 2 | G2: 250059, 0.1744, 0.1744, 0 |
| behaviour_k2 | shared_attack | rotation_A | DDoS-SYN_Flood5 | 3/3 | 0.343950 | 250059 | 1.0000 | 1.0000 | 0 | - / - | - | 10 (22.53) | 11 (24.78) | 2 / 3 | G2: 250059, 1.0000, 1.0000, 200605 |
| behaviour_k3 | pure | rotation_A | DDoS-SYN_Flood5 | 4/4 | 0.487865 | 250059 | 0.1744 | 0.1744 | 250059 | 0.1744 / 0.1744 | G2 (250059) | 8 (18.02) | 8 (18.02) | 1 / 2 | G2: 250059, 0.1744, 0.1744, 0 |
| behaviour_k3 | shared_attack | rotation_A | DDoS-SYN_Flood5 | 4/4 | 0.343950 | 250059 | 1.0000 | 1.0000 | 0 | - / - | - | 18 (40.55) | 20 (45.06) | 3 / 3 | G2: 250059, 1.0000, 1.0000, 200605 |
| behaviour_k4 | pure | rotation_A | DDoS-SYN_Flood5 | 5/5 | 0.315928 | 250059 | 0.1744 | 0.1744 | 250059 | 0.1744 / 0.1744 | G3 (250059) | 9 (20.28) | 10 (22.53) | 2 / 2 | G3: 250059, 0.1744, 0.1744, 0 |
| behaviour_k4 | shared_attack | rotation_A | DDoS-SYN_Flood5 | 5/5 | 0.527977 | 250059 | 1.0000 | 1.0000 | 0 | - / - | - | 19 (42.80) | 19 (42.80) | 3 / 3 | G3: 250059, 1.0000, 1.0000, 200605 |
| global | both | rotation_B | DDoS-SYN_Flood | 1/1 | 0.885948 | 250708 | 0.9976 | 0.9971 | 0 | - / - | - | 19 (28.90) | 1 (1.52) | 20 / 2 | GLOBAL: 250708, 0.9976, 0.9971, 199985 |
| category | pure | rotation_B | DDoS-SYN_Flood | 8/8 | 0.936141 | 250708 | 0.8505 | 0.8358 | 250708 | 0.8505 / 0.8358 | Audio (200605); Camera (50103) | 28 (42.59) | 1 (1.52) | 23 / 3 | Audio: 200605, 0.9840, 0.9665, 0 | Camera: 50103, 0.3159, 0.3127, 0 |
| category | shared_attack | rotation_B | DDoS-SYN_Flood | 8/8 | 0.224147 | 250708 | 0.9902 | 0.9982 | 0 | - / - | - | 14 (21.30) | 33 (50.20) | 5 / 6 | Audio: 200605, 0.9881, 0.9981, 199985 | Camera: 50103, 0.9986, 0.9986, 199985 |
| behaviour_k2 | pure | rotation_B | DDoS-SYN_Flood | 3/3 | 0.968802 | 250708 | 0.9981 | 0.5743 | 250708 | 0.9981 / 0.5743 | G1 (250708) | 20 (30.42) | 0 (0.00) | 24 / 2 | G1: 250708, 0.9981, 0.5743, 0 |
| behaviour_k2 | shared_attack | rotation_B | DDoS-SYN_Flood | 3/3 | 0.945842 | 250708 | 0.9980 | 0.9966 | 0 | - / - | - | 16 (24.34) | 0 (0.00) | 22 / 2 | G1: 250708, 0.9980, 0.9966, 199985 |
| behaviour_k3 | pure | rotation_B | DDoS-SYN_Flood | 4/4 | 0.968802 | 250708 | 0.9981 | 0.5743 | 250708 | 0.9981 / 0.5743 | G1 (250708) | 20 (30.42) | 0 (0.00) | 22 / 2 | G1: 250708, 0.9981, 0.5743, 0 |
| behaviour_k3 | shared_attack | rotation_B | DDoS-SYN_Flood | 4/4 | 0.945842 | 250708 | 0.9980 | 0.9966 | 0 | - / - | - | 16 (24.34) | 0 (0.00) | 20 / 1 | G1: 250708, 0.9980, 0.9966, 199985 |
| behaviour_k4 | pure | rotation_B | DDoS-SYN_Flood | 5/5 | 0.976244 | 250708 | 0.7896 | 0.7277 | 250708 | 0.7896 / 0.7277 | G1 (180221); G2 (70487) | 19 (28.90) | 0 (0.00) | 23 / 1 | G1: 180221, 0.9988, 0.9913, 0 | G2: 70487, 0.2548, 0.0535, 0 |
| behaviour_k4 | shared_attack | rotation_B | DDoS-SYN_Flood | 5/5 | 0.617301 | 250708 | 0.9977 | 0.9975 | 0 | - / - | - | 13 (19.77) | 10 (15.21) | 9 / 6 | G1: 180221, 0.9981, 0.9980, 199985 | G2: 70487, 0.9965, 0.9964, 199985 |

## Detail: cost (laptop proxies)

- Size: sum of the strategy's models' joblib sizes (the Pi loads every model). Latency: 1 thread: dict lookup MAC -> model, then that model's predict_proba on one flow; CONFIG latency single_calls calls over val rows sampled once (seed 42), the same rows for every strategy; one full pass over every strategy is run and discarded first (warm-up), then the measured pass. Fit time: sum of the strategy's models' fit times (all cores); a shared fit counts in every strategy using it.

| strategy | mode | status | n models | models | total size | lat med us | lat p99 us | lookup med us | fit s total |
|---|---|---|---|---|---|---|---|---|---|
| global | both | OK | 1 | GLOBAL | 154.3 kB | 98.8 | 257.4 | 0.16 | 8.6 |
| category | pure | OK | 8 | Audio; Camera; Home Automation; Hub; Lighting; Power Outlet; Unidentified (Espressif); GLOBAL | 846.6 kB | 98.5 | 286.5 | 0.15 | 12.4 |
| category | shared_attack | OK | 8 | Audio; Camera; Home Automation; Hub; Lighting; Power Outlet; Unidentified (Espressif); GLOBAL | 881.1 kB | 97.4 | 264.0 | 0.16 | 25.8 |
| behaviour_k2 | pure | OK | 3 | G1; G2; GLOBAL | 404.7 kB | 99.2 | 293.9 | 0.17 | 13.1 |
| behaviour_k2 | shared_attack | OK | 3 | G1; G2; GLOBAL | 404.8 kB | 98.3 | 234.2 | 0.16 | 15.5 |
| behaviour_k3 | pure | OK | 4 | G1; G2; G3; GLOBAL | 488.8 kB | 99.9 | 235.0 | 0.16 | 12.6 |
| behaviour_k3 | shared_attack | OK | 4 | G1; G2; G3; GLOBAL | 490.8 kB | 101.6 | 279.6 | 0.16 | 17.1 |
| behaviour_k4 | pure | OK | 5 | G1; G2; G3; G4; GLOBAL | 584.1 kB | 98.6 | 253.4 | 0.15 | 11.6 |
| behaviour_k4 | shared_attack | OK | 5 | G1; G2; G3; G4; GLOBAL | 591.9 kB | 101.8 | 252.0 | 0.16 | 19.1 |

## FP/hour denominators

| rows | benign rows | hours used | FP/h per FP | source |
|---|---|---|---|---|
| house val benign (val) | - | 1.9676 | 0.51 | computed: 08 benign_hours rule on manifest session_cuts + group benign starts (manifest has no per-group value) |
| A: (i) DDoS-SYN_Flood5 benign (train + val) | 7690 | 0.4439 | 2.25 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| A: (ii) all val benign | 39185 | 1.9676 | 0.51 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| B: (i) DDoS-SYN_Flood benign (train + val) | 19238 | 0.6574 | 1.52 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |
| B: (ii) all val benign | 39185 | 1.9676 | 0.51 | 08 benign_hours on manifest session_cuts, summed over the rows' splits |

## Groupings

| strategy | file | sha256 | groups (devices) |
|---|---|---|---|
| global | config/groupings/global.json | 74485f1cc113ac61... | GLOBAL (56) |
| category | config/groupings/category.json | 15154fd9962b1221... | Audio (8), Camera (14), GEN (3), Home Automation (6), Hub (6), Lighting (5), Power Outlet (10), Unidentified (Espressif) (4) |
| behaviour_k2 | config/groupings/behaviour_k2.json | 9f80565f7ece7f65... | G1 (26), G2 (27), GEN (3) |
| behaviour_k3 | config/groupings/behaviour_k3.json | cd8b4a39ac71e46b... | G1 (26), G2 (20), G3 (7), GEN (3) |
| behaviour_k4 | config/groupings/behaviour_k4.json | 1b2f8b961d00a1c1... | G1 (15), G2 (11), G3 (20), G4 (7), GEN (3) |

