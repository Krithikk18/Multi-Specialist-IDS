# Step 6b -- behaviour group proposal (NOT locked)

- **run_timestamp_utc**: 2026-10-10T08:09:15+00:00
- **fingerprints**: /mnt/d/Projects/Company Project/Paper_Implemetation/results/step6/device_fingerprints.csv
- **kept_features**: ['log_flows_per_hour', 'log_median_bytes', 'log_p90_bytes', 'median_packets', 'pct_single_packet', 'log_median_duration_us', 'upload_ratio', 'pct_udp', 'pct_dns', 'pct_discovery', 'gap_cv', 'pct_internet', 'pct_device', 'log_distinct_peers']
- **flows**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/benign_flows_tagged.csv
- **05_profile_devices.py**: /mnt/d/Projects/Company Project/Paper_Implemetation/05_profile_devices.py
- **out_dir**: results/step6
- **k_min**: 2
- **k_max**: 12
- **min_group_flows**: 2000
- **n_boot**: 100
- **seed**: 42
- **clip**: 3.0
- **capture_hours**: 9.2578
- **python**: 3.11.17
- **numpy**: 2.4.6
- **pandas**: 3.0.6
- **scipy**: 1.17.1
- **scikit_learn**: 1.9.1
- **runtime_s**: 28.0

Input SHA256:

- `fingerprints`: 96c312af72cfdfc115bec9574737dc1c58b4c888590abc1ec84a4b7168c25c2c
- `kept_features`: 2c12fe7f62ba3c74a99ce27ec55c9491d4e42de9aaa820608dc841b36027b20e
- `flows`: f9c033abaf07289999f4c1300f09b00a48624aecd2a63ef0a5ec7632abf2c799
- `05_profile_devices.py`: be7fe4fc53be6f76a28b403b22cd6aa7c35d3517425f1fa310e4e09db8ea06fa

## Integrity: **PASS**

- **recomputed_fingerprints_max_abs_diff**: 0.0
- **recomputed_fingerprints_match_csv**: True
- **recomputed_usable_counts_match_csv**: True
- **high_confidence_devices**: 52
- **low_confidence_devices_assigned**: 3
- **every_candidate_has_k_groups**: True
- **bootstrap_nan_values_imputed_as_0**: 0
- **all_figures_written**: True
- **device_table_untouched**: True
- **fingerprints_sha256_unchanged**: True
- **kept_features_sha256_unchanged**: True
- **flows_sha256_unchanged**: True
- **05_profile_devices.py_sha256_unchanged**: True

## 1. Cluster-input scaling (fit on high-confidence devices)

| feature | scale_type | scale | median | iqr | p95_minus_p5 | max_abs_z_before_clip | n_clipped |
|---|---|---|---|---|---|---|---|
| log_flows_per_hour | iqr | 0.62332 | 1.832317 | 0.62332 | 1.504083 | 3.542 | 1 |
| log_median_bytes | iqr | 0.656017 | 2.608526 | 0.656017 | 1.507503 | 3.976 | 2 |
| log_p90_bytes | iqr | 0.846278 | 3.615845 | 0.846278 | 1.8189 | 1.973 | 0 |
| median_packets | iqr | 12.125 | 8.0 | 12.125 | 31.9 | 127.381 | 1 |
| pct_single_packet | iqr | 9.26425 | 1.5545 | 9.26425 | 27.8992 | 6.216 | 2 |
| log_median_duration_us | iqr | 2.715787 | 7.789321 | 2.715787 | 2.968511 | 2.868 | 0 |
| upload_ratio | iqr | 0.558879 | 0.850861 | 0.558879 | 0.777563 | 1.23 | 0 |
| pct_udp | iqr | 24.27475 | 49.6615 | 24.27475 | 91.67615 | 2.073 | 0 |
| pct_dns | iqr | 15.82125 | 3.792 | 15.82125 | 36.2905 | 4.549 | 2 |
| pct_discovery | p95-p5 | 40.2638 | 0.0 | 2.266 | 40.2638 | 1.194 | 0 |
| gap_cv | iqr | 0.936231 | 0.978538 | 0.936231 | 1.968097 | 3.466 | 1 |
| pct_internet | iqr | 30.8295 | 54.2215 | 30.8295 | 72.89575 | 1.759 | 0 |
| pct_device | p95-p5 | 13.305 | 0.0 | 0.02325 | 13.305 | 6.991 | 1 |
| log_distinct_peers | iqr | 0.497325 | 0.954243 | 0.497325 | 1.350303 | 2.621 | 0 |

## 2–3. Ward clustering and choice of k

Feasible = every group has ≥ 2000 usable flows. Rank = mean of the ranks of silhouette (↑), CH (↑), DB (↓) and merge gap (↑) over all k.

| k | silhouette | calinski_harabasz | davies_bouldin | merge_height | merge_gap | min_group_flows | min_group_devices | smallest_group_flows_devices | feasible | mean_rank |
|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 0.3073 | 21.81 | 1.3568 | 16.3597 | 7.4857 | 13616 | 25 | 27 | True | 5.0 |
| 3 | 0.2841 | 15.87 | 1.1809 | 8.8739 | 0.0301 | 2141 | 7 | 7 | True | 7.75 |
| 4 | 0.2872 | 14.88 | 1.5481 | 8.8439 | 0.8799 | 2141 | 7 | 7 | True | 7.875 |
| 5 | 0.2953 | 14.58 | 1.2817 | 7.9639 | 0.2208 | 372 | 1 | 1 | False | 9.0 |
| 6 | 0.3144 | 15.13 | 1.1675 | 7.7431 | 1.5456 | 372 | 1 | 1 | False | 4.75 |
| 7 | 0.3286 | 14.92 | 1.0664 | 6.1975 | 0.2994 | 372 | 1 | 1 | False | 5.5 |
| 8 | 0.3371 | 15.01 | 1.0464 | 5.8981 | 1.0583 | 372 | 1 | 1 | False | 4.0 |
| 9 | 0.3399 | 14.64 | 0.9911 | 4.8398 | 0.0336 | 372 | 1 | 1 | False | 5.5 |
| 10 | 0.344 | 14.59 | 1.0074 | 4.8062 | 0.0898 | 372 | 1 | 1 | False | 5.75 |
| 11 | 0.3221 | 14.79 | 0.9924 | 4.7164 | 0.4509 | 372 | 1 | 1 | False | 5.5 |
| 12 | 0.3378 | 14.88 | 0.9322 | 4.2655 | 0.0102 | 339 | 1 | 1 | False | 5.375 |

### Candidates

- **k = 2**: mean rank 5.00; silhouette 0.307 (rank 8/11), CH 21.8 (rank 1), DB 1.357 (rank 10), merge gap 7.486 (rank 1); smallest group 13,616 flows (27 devices); bootstrap mean ARI 0.888
- **k = 3**: mean rank 7.75; silhouette 0.284 (rank 11/11), CH 15.9 (rank 2), DB 1.181 (rank 8), merge gap 0.030 (rank 10); smallest group 2,141 flows (7 devices); bootstrap mean ARI 0.761
- **k = 4**: mean rank 7.88; silhouette 0.287 (rank 10/11), CH 14.9 (rank 6), DB 1.548 (rank 11), merge gap 0.880 (rank 4); smallest group 2,141 flows (7 devices); bootstrap mean ARI 0.697

### Recommended k = **2**

k = 2 has the best mean internal-validity rank among feasible k and no other candidate is ≥ 0.10 more stable under bootstrap (mean ARI 0.888; most stable candidate k = 2 at 0.888). Rule: best mean rank unless another candidate's bootstrap mean ARI is ≥ 0.10 higher.

## 4. Cross-checks (ARI vs Ward at the same k)

| k | kmeans | average_correlation | ward_without_median_packets |
|---|---|---|---|
| 2 | 0.849 | 0.923 | 0.923 |
| 3 | 0.468 | 0.768 | 0.474 |
| 4 | 0.631 | 0.666 | 0.516 |

## 5. Stability

### (a) Bootstrap over flows

Each high-confidence device's usable flows were resampled with replacement (same count), fingerprints recomputed with 05_profile_devices.build_fingerprints, rescaled with the scaler fitted above, and re-clustered with Ward. Caveat: duplicated flows add zero inter-flow gaps (inflating gap_cv) and cannot add new peers (deflating log_distinct_peers), so ARI is a conservative estimate.

| k | mean | median | p5 | min | max |
|---|---|---|---|---|---|
| 2 | 0.888 | 0.849 | 0.778 | 0.778 | 1.0 |
| 3 | 0.761 | 0.863 | 0.462 | 0.36 | 1.0 |
| 4 | 0.697 | 0.636 | 0.588 | 0.456 | 1.0 |

Per-device stay frequency (share of bootstrap runs in which the device stays in the cluster matched to its base group):

| device_name | category | k2_group | k3_group | k4_group | k2_stay | k3_stay | k4_stay |
|---|---|---|---|---|---|---|---|
| AMCREST WiFi Camera | Camera | G1 | G1 | G1 | 1.0 | 0.76 | 0.82 |
| Arlo Base Station | Camera | G1 | G1 | G2 | 1.0 | 0.8 | 0.96 |
| Arlo Q Indoor Camera | Camera | G1 | G1 | G2 | 1.0 | 0.92 | 0.8 |
| D-Link DCS8000LHA1 Mini Camera | Camera | G2 | G3 | G4 | 1.0 | 0.68 | 0.97 |
| HeimVision Smart WiFi Camera | Camera | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Home Eye Camera | Camera | G1 | G1 | G2 | 1.0 | 0.7 | 0.36 |
| Nest Indoor Camera | Camera | G2 | G3 | G4 | 1.0 | 0.69 | 0.98 |
| Netatmo Camera | Camera | G1 | G1 | G2 | 1.0 | 0.96 | 0.75 |
| Rbcior Camera | Camera | G1 | G1 | G1 | 1.0 | 0.98 | 0.43 |
| TP-Link Tapo Camera | Camera | G1 | G1 | G2 | 1.0 | 0.96 | 0.75 |
| Wyze Camera | Camera | G1 | G1 | G1 | 1.0 | 0.76 | 0.82 |
| Yi Indoor 2 Camera | Camera | G1 | G1 | G1 | 0.37 | 0.2 | 0.27 |
| Yi Indoor Camera | Camera | G1 | G1 | G2 | 1.0 | 0.8 | 0.96 |
| Yi Outdoor Camera | Camera | G1 | G1 | G1 | 0.37 | 0.2 | 0.27 |
| Amazon Alexa Echo Dot 1 | Audio | G1 | G1 | G1 | 1.0 | 0.99 | 0.4 |
| Amazon Alexa Echo Dot 2 | Audio | G1 | G1 | G2 | 1.0 | 0.93 | 0.82 |
| Amazon Alexa Echo Studio | Audio | G1 | G1 | G1 | 1.0 | 0.99 | 0.4 |
| Amazon Echo Show | Audio | G1 | G1 | G1 | 1.0 | 0.99 | 0.4 |
| Google Nest Mini Speaker | Audio | G1 | G1 | G1 | 1.0 | 0.99 | 0.39 |
| Harman Kardon speaker (Ampak) | Audio | G1 | G1 | G1 | 1.0 | 0.76 | 0.82 |
| Sonos One Speaker | Audio | G1 | G1 | G1 | 1.0 | 0.99 | 0.4 |
| Aeotec Smart Home Hub | Hub | G1 | G1 | G2 | 1.0 | 0.8 | 0.96 |
| Eufy HomeBase 2 | Hub | G1 | G1 | G1 | 1.0 | 0.76 | 0.82 |
| Fibaro Home Center Lite | Hub | G1 | G1 | G2 | 1.0 | 0.7 | 0.36 |
| Philips Hue Bridge | Hub | G1 | G1 | G1 | 1.0 | 0.99 | 0.4 |
| Ring Base Station | Hub | G2 | G3 | G4 | 0.98 | 0.69 | 0.97 |
| SmartThings Hub | Hub | G1 | G1 | G2 | 1.0 | 0.8 | 0.96 |
| Atomi Coffee Maker | Home Automation | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Cocoon Smart HVAC Fan | Home Automation | G2 | G3 | G4 | 1.0 | 0.69 | 0.98 |
| Govee Smart Humidifier | Home Automation | G2 | G3 | G4 | 1.0 | 0.68 | 0.97 |
| LG Smart TV | Home Automation | G1 | G1 | G1 | 1.0 | 0.99 | 0.4 |
| Levoit Air Purifier | Home Automation | G2 | G3 | G4 | 1.0 | 0.69 | 0.98 |
| Netatmo Weather Station | Home Automation | G2 | G2 | G3 | 1.0 | 0.97 | 0.95 |
| HeimVision SmartLife Radio/Lamp | Lighting | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| LIFX Lightbulb | Lighting | G2 | G2 | G3 | 0.89 | 0.89 | 0.89 |
| LampUX RGB | Lighting | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Lumiman Bulb | Lighting | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Teckin Light Strip | Lighting | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Amazon Smart Plug | Power Outlet | G2 | G3 | G4 | 1.0 | 0.68 | 0.97 |
| GoSund Power Strip (1) | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| GoSund Power Strip (2) | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| GoSund Smart Plug WP2 (1) | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| GoSund Smart Plug WP2 (2) | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Teckin Plug 1 | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Teckin Plug 2 | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Wemo Smart Plug 2 | Power Outlet | G1 | G1 | G1 | 0.91 | 0.91 | 0.34 |
| Yutron Plug 1 | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Yutron Plug 2 | Power Outlet | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Unidentified ESP plug (1) | Unidentified (Espressif) | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Unidentified ESP plug (2) | Unidentified (Espressif) | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Unidentified ESP plug (3) | Unidentified (Espressif) | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |
| Unidentified ESP plug (4) | Unidentified (Espressif) | G2 | G2 | G3 | 1.0 | 1.0 | 1.0 |

### (b) Leave-one-feature-out (ARI vs Ward with all features)

| dropped_feature | k2 | k3 | k4 |
|---|---|---|---|
| log_flows_per_hour | 1.0 | 0.579 | 0.72 |
| log_median_bytes | 0.849 | 0.863 | 0.876 |
| log_p90_bytes | 1.0 | 1.0 | 1.0 |
| median_packets | 0.923 | 0.474 | 0.516 |
| pct_single_packet | 1.0 | 0.53 | 0.702 |
| log_median_duration_us | 0.923 | 0.495 | 0.674 |
| upload_ratio | 1.0 | 0.537 | 1.0 |
| pct_udp | 0.646 | 0.266 | 0.427 |
| pct_dns | 1.0 | 0.547 | 0.955 |
| pct_discovery | 1.0 | 1.0 | 1.0 |
| gap_cv | 1.0 | 1.0 | 0.753 |
| pct_internet | 0.849 | 0.485 | 0.513 |
| pct_device | 1.0 | 1.0 | 1.0 |
| log_distinct_peers | 0.322 | 0.419 | 0.541 |

## 6. Low-confidence devices (nearest group centroid, flagged)

Distance in scaled space (NaN features skipped, distance rescaled by √(features/available)); spread = the group members' distances to their centroid.

| k | device_name | category | usable_flows | group | distance | group_median_spread | group_max_spread | ratio_to_median | features_used | flag |
|---|---|---|---|---|---|---|---|---|---|---|
| 2 | Smart Board | Home Automation | 64 | G1 | 3.879 | 2.649 | 5.953 | 1.46 | 14/14 | low_confidence |
| 2 | iRobot Roomba | Home Automation | 32 | G2 | 4.394 | 1.089 | 4.445 | 4.03 | 14/14 | low_confidence |
| 2 | Wemo Smart Plug 1 | Power Outlet | 13 | G1 | 6.607 | 2.649 | 5.953 | 2.49 | 13/14 | low_confidence |
| 3 | Smart Board | Home Automation | 64 | G1 | 3.879 | 2.649 | 5.953 | 1.46 | 14/14 | low_confidence |
| 3 | iRobot Roomba | Home Automation | 32 | G2 | 4.315 | 0.8 | 3.195 | 5.39 | 14/14 | low_confidence |
| 3 | Wemo Smart Plug 1 | Power Outlet | 13 | G1 | 6.607 | 2.649 | 5.953 | 2.49 | 13/14 | low_confidence |
| 4 | Smart Board | Home Automation | 64 | G2 | 3.431 | 2.499 | 5.342 | 1.37 | 14/14 | low_confidence |
| 4 | iRobot Roomba | Home Automation | 32 | G3 | 4.315 | 0.8 | 3.195 | 5.39 | 14/14 | low_confidence |
| 4 | Wemo Smart Plug 1 | Power Outlet | 13 | G2 | 6.442 | 2.499 | 5.342 | 2.58 | 13/14 | low_confidence |

## 7. Group profiles

### k = 2

- **G1** (25 devices, 191,119 usable flows) — *high flow rate, short flows, many single-packet flows, many peers*  
  top |median z|: log_flows_per_hour +0.94, log_median_duration_us -0.91, pct_single_packet +0.84, log_distinct_peers +0.78  
  devices: AMCREST WiFi Camera [Camera]; Arlo Base Station [Camera]; Arlo Q Indoor Camera [Camera]; Home Eye Camera [Camera]; Netatmo Camera [Camera]; Rbcior Camera [Camera]; TP-Link Tapo Camera [Camera]; Wyze Camera [Camera]; Yi Indoor 2 Camera [Camera]; Yi Indoor Camera [Camera]; Yi Outdoor Camera [Camera]; Amazon Alexa Echo Dot 1 [Audio]; Amazon Alexa Echo Dot 2 [Audio]; Amazon Alexa Echo Studio [Audio]; Amazon Echo Show [Audio]; Google Nest Mini Speaker [Audio]; Harman Kardon speaker (Ampak) [Audio]; Sonos One Speaker [Audio]; Aeotec Smart Home Hub [Hub]; Eufy HomeBase 2 [Hub]; Fibaro Home Center Lite [Hub]; Philips Hue Bridge [Hub]; SmartThings Hub [Hub]; LG Smart TV [Home Automation]; Wemo Smart Plug 2 [Power Outlet]
  low-confidence assigned: Smart Board; Wemo Smart Plug 1
- **G2** (27 devices, 13,616 usable flows) — *many packets/flow, large payloads*  
  top |median z|: median_packets +0.66, log_median_bytes +0.57, gap_cv -0.40, log_distinct_peers -0.22  
  devices: D-Link DCS8000LHA1 Mini Camera [Camera]; HeimVision Smart WiFi Camera [Camera]; Nest Indoor Camera [Camera]; Ring Base Station [Hub]; Atomi Coffee Maker [Home Automation]; Cocoon Smart HVAC Fan [Home Automation]; Govee Smart Humidifier [Home Automation]; Levoit Air Purifier [Home Automation]; Netatmo Weather Station [Home Automation]; HeimVision SmartLife Radio/Lamp [Lighting]; LIFX Lightbulb [Lighting]; LampUX RGB [Lighting]; Lumiman Bulb [Lighting]; Teckin Light Strip [Lighting]; Amazon Smart Plug [Power Outlet]; GoSund Power Strip (1) [Power Outlet]; GoSund Power Strip (2) [Power Outlet]; GoSund Smart Plug WP2 (1) [Power Outlet]; GoSund Smart Plug WP2 (2) [Power Outlet]; Teckin Plug 1 [Power Outlet]; Teckin Plug 2 [Power Outlet]; Yutron Plug 1 [Power Outlet]; Yutron Plug 2 [Power Outlet]; Unidentified ESP plug (1) [Unidentified (Espressif)]; Unidentified ESP plug (2) [Unidentified (Espressif)]; Unidentified ESP plug (3) [Unidentified (Espressif)]; Unidentified ESP plug (4) [Unidentified (Espressif)]
  low-confidence assigned: iRobot Roomba

### k = 3

- **G1** (25 devices, 191,119 usable flows) — *high flow rate, short flows, many single-packet flows, many peers*  
  top |median z|: log_flows_per_hour +0.94, log_median_duration_us -0.91, pct_single_packet +0.84, log_distinct_peers +0.78  
  devices: AMCREST WiFi Camera [Camera]; Arlo Base Station [Camera]; Arlo Q Indoor Camera [Camera]; Home Eye Camera [Camera]; Netatmo Camera [Camera]; Rbcior Camera [Camera]; TP-Link Tapo Camera [Camera]; Wyze Camera [Camera]; Yi Indoor 2 Camera [Camera]; Yi Indoor Camera [Camera]; Yi Outdoor Camera [Camera]; Amazon Alexa Echo Dot 1 [Audio]; Amazon Alexa Echo Dot 2 [Audio]; Amazon Alexa Echo Studio [Audio]; Amazon Echo Show [Audio]; Google Nest Mini Speaker [Audio]; Harman Kardon speaker (Ampak) [Audio]; Sonos One Speaker [Audio]; Aeotec Smart Home Hub [Hub]; Eufy HomeBase 2 [Hub]; Fibaro Home Center Lite [Hub]; Philips Hue Bridge [Hub]; SmartThings Hub [Hub]; LG Smart TV [Home Automation]; Wemo Smart Plug 2 [Power Outlet]
  low-confidence assigned: Smart Board; Wemo Smart Plug 1
- **G2** (20 devices, 11,475 usable flows) — *many packets/flow, large payloads*  
  top |median z|: median_packets +0.66, log_median_bytes +0.64, gap_cv -0.39, pct_dns -0.24  
  devices: HeimVision Smart WiFi Camera [Camera]; Atomi Coffee Maker [Home Automation]; Netatmo Weather Station [Home Automation]; HeimVision SmartLife Radio/Lamp [Lighting]; LIFX Lightbulb [Lighting]; LampUX RGB [Lighting]; Lumiman Bulb [Lighting]; Teckin Light Strip [Lighting]; GoSund Power Strip (1) [Power Outlet]; GoSund Power Strip (2) [Power Outlet]; GoSund Smart Plug WP2 (1) [Power Outlet]; GoSund Smart Plug WP2 (2) [Power Outlet]; Teckin Plug 1 [Power Outlet]; Teckin Plug 2 [Power Outlet]; Yutron Plug 1 [Power Outlet]; Yutron Plug 2 [Power Outlet]; Unidentified ESP plug (1) [Unidentified (Espressif)]; Unidentified ESP plug (2) [Unidentified (Espressif)]; Unidentified ESP plug (3) [Unidentified (Espressif)]; Unidentified ESP plug (4) [Unidentified (Espressif)]
  low-confidence assigned: iRobot Roomba
- **G3** (7 devices, 2,141 usable flows) — *many packets/flow, TCP-heavy, Internet-facing, regular timing*  
  top |median z|: median_packets +2.06, pct_udp -1.79, pct_internet +1.36, gap_cv -0.76  
  devices: D-Link DCS8000LHA1 Mini Camera [Camera]; Nest Indoor Camera [Camera]; Ring Base Station [Hub]; Cocoon Smart HVAC Fan [Home Automation]; Govee Smart Humidifier [Home Automation]; Levoit Air Purifier [Home Automation]; Amazon Smart Plug [Power Outlet]

### k = 4

- **G1** (15 devices, 51,534 usable flows) — *many peers, high flow rate, DNS-heavy, download-heavy*  
  top |median z|: log_distinct_peers +1.08, log_flows_per_hour +1.01, pct_dns +0.71, upload_ratio -0.56  
  devices: AMCREST WiFi Camera [Camera]; Rbcior Camera [Camera]; Wyze Camera [Camera]; Yi Indoor 2 Camera [Camera]; Yi Outdoor Camera [Camera]; Amazon Alexa Echo Dot 1 [Audio]; Amazon Alexa Echo Studio [Audio]; Amazon Echo Show [Audio]; Google Nest Mini Speaker [Audio]; Harman Kardon speaker (Ampak) [Audio]; Sonos One Speaker [Audio]; Eufy HomeBase 2 [Hub]; Philips Hue Bridge [Hub]; LG Smart TV [Home Automation]; Wemo Smart Plug 2 [Power Outlet]
- **G2** (10 devices, 139,585 usable flows) — *many single-packet flows, DNS-heavy, short flows, bursty timing*  
  top |median z|: pct_single_packet +2.44, pct_dns +1.67, log_median_duration_us -0.94, gap_cv +0.94  
  devices: Arlo Base Station [Camera]; Arlo Q Indoor Camera [Camera]; Home Eye Camera [Camera]; Netatmo Camera [Camera]; TP-Link Tapo Camera [Camera]; Yi Indoor Camera [Camera]; Amazon Alexa Echo Dot 2 [Audio]; Aeotec Smart Home Hub [Hub]; Fibaro Home Center Lite [Hub]; SmartThings Hub [Hub]
  low-confidence assigned: Smart Board; Wemo Smart Plug 1
- **G3** (20 devices, 11,475 usable flows) — *many packets/flow, large payloads*  
  top |median z|: median_packets +0.66, log_median_bytes +0.64, gap_cv -0.39, pct_dns -0.24  
  devices: HeimVision Smart WiFi Camera [Camera]; Atomi Coffee Maker [Home Automation]; Netatmo Weather Station [Home Automation]; HeimVision SmartLife Radio/Lamp [Lighting]; LIFX Lightbulb [Lighting]; LampUX RGB [Lighting]; Lumiman Bulb [Lighting]; Teckin Light Strip [Lighting]; GoSund Power Strip (1) [Power Outlet]; GoSund Power Strip (2) [Power Outlet]; GoSund Smart Plug WP2 (1) [Power Outlet]; GoSund Smart Plug WP2 (2) [Power Outlet]; Teckin Plug 1 [Power Outlet]; Teckin Plug 2 [Power Outlet]; Yutron Plug 1 [Power Outlet]; Yutron Plug 2 [Power Outlet]; Unidentified ESP plug (1) [Unidentified (Espressif)]; Unidentified ESP plug (2) [Unidentified (Espressif)]; Unidentified ESP plug (3) [Unidentified (Espressif)]; Unidentified ESP plug (4) [Unidentified (Espressif)]
  low-confidence assigned: iRobot Roomba
- **G4** (7 devices, 2,141 usable flows) — *many packets/flow, TCP-heavy, Internet-facing, regular timing*  
  top |median z|: median_packets +2.06, pct_udp -1.79, pct_internet +1.36, gap_cv -0.76  
  devices: D-Link DCS8000LHA1 Mini Camera [Camera]; Nest Indoor Camera [Camera]; Ring Base Station [Hub]; Cocoon Smart HVAC Fan [Home Automation]; Govee Smart Humidifier [Home Automation]; Levoit Air Purifier [Home Automation]; Amazon Smart Plug [Power Outlet]

### Known-pair check

Group of each member; 'together' = all members share one group; 'boot' = share of bootstrap runs with all members in one cluster.

| set | k | n_members | n_groups | together | boot_together | placement |
|---|---|---|---|---|---|---|
| GoSund (4) | 2 | 4 | 1 | True | 1.0 | GoSund Power Strip (1)→G2; GoSund Power Strip (2)→G2; GoSund Smart Plug WP2 (1)→G2; GoSund Smart Plug WP2 (2)→G2 |
| ESP plugs (4) | 2 | 4 | 1 | True | 1.0 | Unidentified ESP plug (1)→G2; Unidentified ESP plug (2)→G2; Unidentified ESP plug (3)→G2; Unidentified ESP plug (4)→G2 |
| Teckin/Yutron plugs (4) | 2 | 4 | 1 | True | 1.0 | Teckin Plug 1→G2; Teckin Plug 2→G2; Yutron Plug 1→G2; Yutron Plug 2→G2 |
| Lighting | 2 | 5 | 1 | True | 0.89 | HeimVision SmartLife Radio/Lamp→G2; LIFX Lightbulb→G2; LampUX RGB→G2; Lumiman Bulb→G2; Teckin Light Strip→G2 |
| Echo family | 2 | 4 | 1 | True | 1.0 | Amazon Alexa Echo Dot 1→G1; Amazon Alexa Echo Dot 2→G1; Amazon Alexa Echo Studio→G1; Amazon Echo Show→G1 |
| Cameras | 2 | 14 | 2 | False | 0.0 | AMCREST WiFi Camera→G1; Arlo Base Station→G1; Arlo Q Indoor Camera→G1; D-Link DCS8000LHA1 Mini Camera→G2; HeimVision Smart WiFi Camera→G2; Home Eye Camera→G1; Nest Indoor Camera→G2; Netatmo Camera→G1; Rbcior Camera→G1; TP-Link Tapo Camera→G1; Wyze Camera→G1; Yi Indoor 2 Camera→G1; Yi Indoor Camera→G1; Yi Outdoor Camera→G1 |
| GoSund (4) | 3 | 4 | 1 | True | 1.0 | GoSund Power Strip (1)→G2; GoSund Power Strip (2)→G2; GoSund Smart Plug WP2 (1)→G2; GoSund Smart Plug WP2 (2)→G2 |
| ESP plugs (4) | 3 | 4 | 1 | True | 1.0 | Unidentified ESP plug (1)→G2; Unidentified ESP plug (2)→G2; Unidentified ESP plug (3)→G2; Unidentified ESP plug (4)→G2 |
| Teckin/Yutron plugs (4) | 3 | 4 | 1 | True | 1.0 | Teckin Plug 1→G2; Teckin Plug 2→G2; Yutron Plug 1→G2; Yutron Plug 2→G2 |
| Lighting | 3 | 5 | 1 | True | 0.89 | HeimVision SmartLife Radio/Lamp→G2; LIFX Lightbulb→G2; LampUX RGB→G2; Lumiman Bulb→G2; Teckin Light Strip→G2 |
| Echo family | 3 | 4 | 1 | True | 0.94 | Amazon Alexa Echo Dot 1→G1; Amazon Alexa Echo Dot 2→G1; Amazon Alexa Echo Studio→G1; Amazon Echo Show→G1 |
| Cameras | 3 | 14 | 3 | False | 0.0 | AMCREST WiFi Camera→G1; Arlo Base Station→G1; Arlo Q Indoor Camera→G1; D-Link DCS8000LHA1 Mini Camera→G3; HeimVision Smart WiFi Camera→G2; Home Eye Camera→G1; Nest Indoor Camera→G3; Netatmo Camera→G1; Rbcior Camera→G1; TP-Link Tapo Camera→G1; Wyze Camera→G1; Yi Indoor 2 Camera→G1; Yi Indoor Camera→G1; Yi Outdoor Camera→G1 |
| GoSund (4) | 4 | 4 | 1 | True | 1.0 | GoSund Power Strip (1)→G3; GoSund Power Strip (2)→G3; GoSund Smart Plug WP2 (1)→G3; GoSund Smart Plug WP2 (2)→G3 |
| ESP plugs (4) | 4 | 4 | 1 | True | 1.0 | Unidentified ESP plug (1)→G3; Unidentified ESP plug (2)→G3; Unidentified ESP plug (3)→G3; Unidentified ESP plug (4)→G3 |
| Teckin/Yutron plugs (4) | 4 | 4 | 1 | True | 1.0 | Teckin Plug 1→G3; Teckin Plug 2→G3; Yutron Plug 1→G3; Yutron Plug 2→G3 |
| Lighting | 4 | 5 | 1 | True | 0.89 | HeimVision SmartLife Radio/Lamp→G3; LIFX Lightbulb→G3; LampUX RGB→G3; Lumiman Bulb→G3; Teckin Light Strip→G3 |
| Echo family | 4 | 4 | 2 | False | 0.76 | Amazon Alexa Echo Dot 1→G1; Amazon Alexa Echo Dot 2→G2; Amazon Alexa Echo Studio→G1; Amazon Echo Show→G1 |
| Cameras | 4 | 14 | 4 | False | 0.0 | AMCREST WiFi Camera→G1; Arlo Base Station→G2; Arlo Q Indoor Camera→G2; D-Link DCS8000LHA1 Mini Camera→G4; HeimVision Smart WiFi Camera→G3; Home Eye Camera→G2; Nest Indoor Camera→G4; Netatmo Camera→G2; Rbcior Camera→G1; TP-Link Tapo Camera→G2; Wyze Camera→G1; Yi Indoor 2 Camera→G1; Yi Indoor Camera→G2; Yi Outdoor Camera→G1 |

## 8. Figures

- **fig5_dendrogram** (fig5_dendrogram.pdf, fig5_dendrogram.png): Ward dendrogram of the 52 high-confidence devices over the 14 scaled fingerprint features; leaf labels are coloured by category, branches by group, and the dashed line marks the cut at the recommended k = 2.
- **fig6_k_selection** (fig6_k_selection.pdf, fig6_k_selection.png): Internal validity of Ward partitions for k = 2–12: silhouette, Calinski–Harabasz and Davies–Bouldin. Hollow grey points are infeasible (a group below 2,000 usable flows); circled points are the candidates and the dashed line marks the recommended k = 2.
- **fig7_fingerprints_by_group** (fig7_fingerprints_by_group.pdf, fig7_fingerprints_by_group.png): Scaled behaviour fingerprints ordered by proposed group (k = 2) and dendrogram order within each group; the left strip shows the group and the second strip the category (companion to Fig. 2). † hatched rows are low-confidence devices placed at their nearest group centroid.
- **fig8_pca_groups** (fig8_pca_groups.pdf, fig8_pca_groups.png): First two principal components of the cluster input (PC1 40.2%, PC2 17.5% of variance); colour = proposed group (k = 2), marker = category, hollow = low confidence (projected; an undefined feature is set to the median for display). A visual aid only: clustering used all 14 features.
- **fig9_stability** (fig9_stability.pdf, fig9_stability.png): Adjusted Rand index between the base Ward partition and 100 flow-level bootstrap re-clusterings for each candidate k (fingerprints recomputed, scaler held fixed).
