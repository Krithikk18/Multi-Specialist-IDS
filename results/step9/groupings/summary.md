# 06d -- alternative groupings: coverage (train / val only)

- run 2026-10-19T17:17:15+00:00; version alt-1; derived from behaviour_groups.json v1.0
- verify_lock(): OK at start and end; protected files unchanged
- inputs sha256 (combined) `9c8a3dc7da16e02f5f6aa4ee8443e06aad6484d42b576c7cf2a25903c9f4c4c8`; datasets `/home/krithikk/lgids_cache/datasets/v1` train + val (test.parquet never opened)
- strategies: global, category, behaviour_k2, behaviour_k3, behaviour_k4; groupings in `config/groupings/<strategy>.json`
- facts only; no recommendation

## Device set

Filter: device_table `include_in_grouping == "yes"` -> 55 devices. v1.0 groups (device_table behaviour_group set): 56 devices; 05 fingerprints: 55.

- **include_yes**: 55
- **v10_behaviour_group_set**: 56
- **fingerprints_05**: 55
- **v10_grouped_but_include_not_yes**: Unidentified Amazon device (1c:12:b0) (1c:12:b0:9b:0c:ec)
- **include_yes_but_no_v10_group**: none
- **fingerprinted_but_include_not_yes**: none
- **include_yes_but_not_fingerprinted**: none
- **role_iot_but_include_not_yes**: Unidentified Amazon device (1c:12:b0) (1c:12:b0:9b:0c:ec)
- **include_yes_but_role_not_iot**: none
- category column: `paper_category` (no `device_category` column in device_table; 08 copies paper_category into the parquet's device_category)
- 05 category vs table paper_category mismatches: none
- GEN (usable benign flows < 100): Smart Board (64); iRobot Roomba (32); Wemo Smart Plug 1 (13)

## k2 reproduction of v1.0: **PASS**

- PASS -- input fingerprints sha256 == behaviour_groups.json source_sha256
- PASS -- input kept_features sha256 == behaviour_groups.json source_sha256
- PASS -- input cluster_input sha256 == behaviour_groups.json source_sha256
- PASS -- input groups_k2 sha256 == behaviour_groups.json source_sha256
- PASS -- input groups_k4 sha256 == behaviour_groups.json source_sha256
- PASS -- input 06_form_groups.py sha256 == behaviour_groups.json source_sha256
- PASS -- input 05_profile_devices.py sha256 == behaviour_groups.json source_sha256
- PASS -- scaler == behaviour_groups.json scaler (1e-9, same scale types)
- PASS -- cluster input == results/step6/cluster_input.csv (1e-6, same NaN cells)
- PASS -- k2 Ward memberships == results/step6/groups_k2.csv (high confidence)
- PASS -- k2 memberships == device_table behaviour_group (all 55 + the 06c device)
- PASS -- k2 centroids == behaviour_groups.json centroids_scaled (1e-6)
- PASS -- k2 spread (median / max member distance, n) == behaviour_groups.json spread (1e-6)
- PASS -- k2 06c placement of the Amazon device == 06c report + device_table (decision, distances 1e-4)

## Other checks: **PASS**

- PASS -- GEN rule (usable flows < min_flows) == 05 confidence 'low'
- PASS -- min_flows == behaviour_groups.json min_flows
- PASS -- 06c report used this behaviour_groups.json (sha256)
- PASS -- k3 Ward memberships == results/step6/groups_k3.csv (high confidence)
- PASS -- k4 Ward memberships == results/step6/groups_k4.csv (high confidence)
- PASS -- k4 memberships == device_table group_k4 (include_in_grouping == yes)
- PASS -- train.parquet group column == behaviour_k2 mapping (every row)
- PASS -- val.parquet group column == behaviour_k2 mapping (every row)
- PASS -- attack families in train / val == attack_set.json
- PASS -- global: train rows over groups == train.parquet rows
- PASS -- global: val rows over groups == val.parquet rows
- PASS -- category: train rows over groups == train.parquet rows
- PASS -- category: val rows over groups == val.parquet rows
- PASS -- behaviour_k2: train rows over groups == train.parquet rows
- PASS -- behaviour_k2: val rows over groups == val.parquet rows
- PASS -- behaviour_k3: train rows over groups == train.parquet rows
- PASS -- behaviour_k3: val rows over groups == val.parquet rows
- PASS -- behaviour_k4: train rows over groups == train.parquet rows
- PASS -- behaviour_k4: val rows over groups == val.parquet rows
- PASS -- GLOBAL val active benign hours 1.9676 == manifest per_split.val 1.9676 (1e-3)

## 06c-placed Amazon device (1c:12:b0:9b:0c:ec), per strategy

Scaled fingerprint from `results/step7/new_device/bruteforce_background_1c12b09b0cec.json` (219 usable flows); rule = 06c.place. device_table paper_category: 'Unidentified (Amazon)' (as-is it would be a 1-device category).

| strategy | decision | nearest | d_nearest | max_spread_nearest | ratio_to_max | second | d_second | reason |
|---|---|---|---|---|---|---|---|---|
| global | GLOBAL |  |  |  |  |  |  | all devices GLOBAL |
| category | Audio | Audio | 4.2665 | 5.3071 | 0.804 | Hub | 4.5159 | nearest centroid Audio within its max spread (4.266 <= 5.307) |
| behaviour_k2 | G1 | G1 | 4.3544 | 5.9531 | 0.731 | G2 | 5.3257 | nearest centroid G1 within its max spread (4.354 <= 5.953) |
| behaviour_k3 | G1 | G1 | 4.3544 | 5.9531 | 0.731 | G2 | 5.424 | nearest centroid G1 within its max spread (4.354 <= 5.953) |
| behaviour_k4 | G2 | G2 | 4.1836 | 5.3424 | 0.783 | G1 | 4.7477 | nearest centroid G2 within its max spread (4.184 <= 5.342) |

## Coverage per strategy x group

Rows are the v1.0 dataset rows regrouped. 08's caps were drawn per v1.0 cap key (train benign per device: unaffected by regrouping; attack per (v1.0 group, family, split): the alternative groups inherit that sample). Val hours: 08's benign_hours rule on the manifest's active segments / cut points and the group's benign flow starts in train + val (09's denominator); `valonly` uses val starts only. Flags: NO_ATTACK_<family> = 0 train rows; LOW_N_<family> = 1..49 train rows; TINY_GROUP = < 2 devices or < 1,000 benign train rows. GEN is scored by the GLOBAL model.

### global (k = 1)

| group | n_devices | n_low_confidence | train_benign | train_port_scan | train_syn_flood | train_udp_flood | val_benign | val_port_scan | val_syn_flood | val_udp_flood | val_active_benign_hours | val_active_benign_hours_valonly_starts | flags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GLOBAL | 56 | 4 | 137,462 | 98,046 | 400,590 | 95 | 39,185 | 18,179 | 100,177 | 17 | 1.9676 | 1.9676 |  |

### category (k = 7)

| group | n_devices | n_low_confidence | train_benign | train_port_scan | train_syn_flood | train_udp_flood | val_benign | val_port_scan | val_syn_flood | val_udp_flood | val_active_benign_hours | val_active_benign_hours_valonly_starts | flags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Audio | 8 | 1 | 30,866 | 16,963 | 200,605 | 79 | 6,286 | 5,765 | 0 | 17 | 1.9676 | 1.9676 |  |
| Camera | 14 | 0 | 53,399 | 34,848 | 0 | 0 | 10,131 | 0 | 50,103 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |
| Home Automation | 6 | 0 | 4,944 | 6,221 | 0 | 0 | 1,599 | 6,096 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |
| Hub | 6 | 0 | 30,696 | 4,111 | 0 | 16 | 17,049 | 0 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;LOW_N_udp_flood |
| Lighting | 5 | 0 | 3,424 | 1,151 | 0 | 0 | 600 | 6,318 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |
| Power Outlet | 10 | 0 | 10,531 | 22,282 | 116,443 | 0 | 2,741 | 0 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_udp_flood |
| Unidentified (Espressif) | 4 | 0 | 2,447 | 8,114 | 83,542 | 0 | 488 | 0 | 50,074 | 0 | 1.9676 | 1.9676 | NO_ATTACK_udp_flood |
| GEN | 3 | 3 | 1,155 | 4,356 | 0 | 0 | 291 | 0 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |

### behaviour_k2 (k = 2)

| group | n_devices | n_low_confidence | train_benign | train_port_scan | train_syn_flood | train_udp_flood | val_benign | val_port_scan | val_syn_flood | val_udp_flood | val_active_benign_hours | val_active_benign_hours_valonly_starts | flags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| G1 | 26 | 1 | 120,028 | 50,472 | 200,605 | 95 | 35,833 | 7,763 | 50,103 | 17 | 1.9676 | 1.9676 |  |
| G2 | 27 | 0 | 16,279 | 43,218 | 199,985 | 0 | 3,061 | 10,416 | 50,074 | 0 | 1.9676 | 1.9676 | NO_ATTACK_udp_flood |
| GEN | 3 | 3 | 1,155 | 4,356 | 0 | 0 | 291 | 0 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |

High-confidence devices whose nearest centroid is not their own group (they keep their Ward group; 06b's boundary cases): Philips Hue Bridge; Yi Indoor 2 Camera

### behaviour_k3 (k = 3)

| group | n_devices | n_low_confidence | train_benign | train_port_scan | train_syn_flood | train_udp_flood | val_benign | val_port_scan | val_syn_flood | val_udp_flood | val_active_benign_hours | val_active_benign_hours_valonly_starts | flags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| G1 | 26 | 1 | 120,028 | 50,472 | 200,605 | 95 | 35,833 | 7,763 | 50,103 | 17 | 1.9676 | 1.9676 |  |
| G2 | 20 | 0 | 12,856 | 31,817 | 199,985 | 0 | 2,498 | 8,320 | 50,074 | 0 | 1.9676 | 1.9676 | NO_ATTACK_udp_flood |
| G3 | 7 | 0 | 3,423 | 11,401 | 0 | 0 | 563 | 2,096 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |
| GEN | 3 | 3 | 1,155 | 4,356 | 0 | 0 | 291 | 0 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |

High-confidence devices whose nearest centroid is not their own group (they keep their Ward group; 06b's boundary cases): Philips Hue Bridge; Yi Indoor 2 Camera

### behaviour_k4 (k = 4)

| group | n_devices | n_low_confidence | train_benign | train_port_scan | train_syn_flood | train_udp_flood | val_benign | val_port_scan | val_syn_flood | val_udp_flood | val_active_benign_hours | val_active_benign_hours_valonly_starts | flags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| G1 | 15 | 0 | 61,502 | 31,173 | 130,118 | 95 | 12,612 | 7,763 | 50,103 | 17 | 1.9676 | 1.9676 |  |
| G2 | 11 | 1 | 58,526 | 19,299 | 70,487 | 0 | 23,221 | 0 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_udp_flood |
| G3 | 20 | 0 | 12,856 | 31,817 | 199,985 | 0 | 2,498 | 8,320 | 50,074 | 0 | 1.9676 | 1.9676 | NO_ATTACK_udp_flood |
| G4 | 7 | 0 | 3,423 | 11,401 | 0 | 0 | 563 | 2,096 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |
| GEN | 3 | 3 | 1,155 | 4,356 | 0 | 0 | 291 | 0 | 0 | 0 | 1.9676 | 1.9676 | NO_ATTACK_syn_flood;NO_ATTACK_udp_flood |

High-confidence devices whose nearest centroid is not their own group (they keep their Ward group; 06b's boundary cases): Philips Hue Bridge; TP-Link Tapo Camera

Val active benign hours are 1.9676 h for every group: 08's active segments are capture-level, and every group has >= 1 benign flow start in each segment that overlaps a val window.

## Val coverage (facts; not flags)

Families with val attack rows but 0 train rows in the group:

| strategy | group | family | val_rows |
|---|---|---|---|
| category | Camera | syn_flood | 50,103 |

Groups with 0 val attack rows (any family):

| strategy | group | val_benign | train_attack |
|---|---|---|---|
| category | Hub | 17,049 | 4,127 |
| category | Power Outlet | 2,741 | 138,725 |
| category | GEN | 291 | 4,356 |
| behaviour_k2 | GEN | 291 | 4,356 |
| behaviour_k3 | GEN | 291 | 4,356 |
| behaviour_k4 | G2 | 23,221 | 89,786 |
| behaviour_k4 | GEN | 291 | 4,356 |

## Category: listed for your merge decision (nothing merged)

Categories (excluding GEN) with < 2 devices or no train attack rows:

_none_

`Unidentified (Amazon)` (the 06c device's table category) has no device in this strategy: the device is placed by the 06c rule (Audio).

## behaviour_k3 / behaviour_k4 vs v1.0 (device_table behaviour_group)

### behaviour_k3

Device counts (rows v1.0, columns new):

| v1.0 | G1 | G2 | G3 | GEN |
|---|---|---|---|---|
| G1 | 26 | 0 | 0 | 0 |
| G2 | 0 | 20 | 7 | 0 |
| GEN | 0 | 0 | 0 | 3 |

Members per cell († = low confidence):

| v1.0 | behaviour_k3 | device |
|---|---|---|
| G1 | G1 | AMCREST WiFi Camera; Aeotec Smart Home Hub; Amazon Alexa Echo Dot 1; Amazon Alexa Echo Dot 2; Amazon Alexa Echo Studio; Amazon Echo Show; Arlo Base Station; Arlo Q Indoor Camera; Eufy HomeBase 2; Fibaro Home Center Lite; Google Nest Mini Speaker; Harman Kardon speaker (Ampak); Home Eye Camera; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Rbcior Camera; SmartThings Hub; Sonos One Speaker; TP-Link Tapo Camera; Unidentified Amazon device (1c:12:b0) †; Wemo Smart Plug 2; Wyze Camera; Yi Indoor 2 Camera; Yi Indoor Camera; Yi Outdoor Camera |
| G2 | G2 | Atomi Coffee Maker; GoSund Power Strip (1); GoSund Power Strip (2); GoSund Smart Plug WP2 (1); GoSund Smart Plug WP2 (2); HeimVision Smart WiFi Camera; HeimVision SmartLife Radio/Lamp; LIFX Lightbulb; LampUX RGB; Lumiman Bulb; Netatmo Weather Station; Teckin Light Strip; Teckin Plug 1; Teckin Plug 2; Unidentified ESP plug (1); Unidentified ESP plug (2); Unidentified ESP plug (3); Unidentified ESP plug (4); Yutron Plug 1; Yutron Plug 2 |
| G2 | G3 | Amazon Smart Plug; Cocoon Smart HVAC Fan; D-Link DCS8000LHA1 Mini Camera; Govee Smart Humidifier; Levoit Air Purifier; Nest Indoor Camera; Ring Base Station |
| GEN | GEN | Smart Board †; Wemo Smart Plug 1 †; iRobot Roomba † |

### behaviour_k4

Device counts (rows v1.0, columns new):

| v1.0 | G1 | G2 | G3 | G4 | GEN |
|---|---|---|---|---|---|
| G1 | 15 | 11 | 0 | 0 | 0 |
| G2 | 0 | 0 | 20 | 7 | 0 |
| GEN | 0 | 0 | 0 | 0 | 3 |

Members per cell († = low confidence):

| v1.0 | behaviour_k4 | device |
|---|---|---|
| G1 | G1 | AMCREST WiFi Camera; Amazon Alexa Echo Dot 1; Amazon Alexa Echo Studio; Amazon Echo Show; Eufy HomeBase 2; Google Nest Mini Speaker; Harman Kardon speaker (Ampak); LG Smart TV; Philips Hue Bridge; Rbcior Camera; Sonos One Speaker; Wemo Smart Plug 2; Wyze Camera; Yi Indoor 2 Camera; Yi Outdoor Camera |
| G1 | G2 | Aeotec Smart Home Hub; Amazon Alexa Echo Dot 2; Arlo Base Station; Arlo Q Indoor Camera; Fibaro Home Center Lite; Home Eye Camera; Netatmo Camera; SmartThings Hub; TP-Link Tapo Camera; Unidentified Amazon device (1c:12:b0) †; Yi Indoor Camera |
| G2 | G3 | Atomi Coffee Maker; GoSund Power Strip (1); GoSund Power Strip (2); GoSund Smart Plug WP2 (1); GoSund Smart Plug WP2 (2); HeimVision Smart WiFi Camera; HeimVision SmartLife Radio/Lamp; LIFX Lightbulb; LampUX RGB; Lumiman Bulb; Netatmo Weather Station; Teckin Light Strip; Teckin Plug 1; Teckin Plug 2; Unidentified ESP plug (1); Unidentified ESP plug (2); Unidentified ESP plug (3); Unidentified ESP plug (4); Yutron Plug 1; Yutron Plug 2 |
| G2 | G4 | Amazon Smart Plug; Cocoon Smart HVAC Fan; D-Link DCS8000LHA1 Mini Camera; Govee Smart Humidifier; Levoit Air Purifier; Nest Indoor Camera; Ring Base Station |
| GEN | GEN | Smart Board †; Wemo Smart Plug 1 †; iRobot Roomba † |

