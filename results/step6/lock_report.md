# Step 6c -- behaviour groups LOCKED

- **version**: 1.0 (2026-10-10)
- **primary grouping**: Ward (Euclidean), k = 2, from `groups_k2.csv`; k = 4 kept as `group_k4` for comparison; `paper_category` is the category baseline
- **lock record**: `config/behaviour_groups.json`
- **device table**: `config/device_table.csv` (backup: `results/step6/device_table_before_lock.csv`)

## Verification: **PASS**

- PASS -- scaler_reproduces_cluster_input (max abs diff <= 1e-6)
- PASS -- member distances match groups_k2.distance_to_centroid (1e-4)
- PASS -- all 3 low-confidence devices -> GEN by rule (Smart Board: min_flows gate (64 < 100), Wemo Smart Plug 1: min_flows gate (13 < 100), iRobot Roomba: min_flows gate (32 < 100))
- PASS -- high-confidence reproduce groups_k2 50/52; mismatches exactly the Ward boundary cases ['Philips Hue Bridge', 'Yi Indoor 2 Camera']
- PASS -- device_table: only behaviour_group changed + 3 columns added
- PASS -- fingerprints unchanged
- PASS -- kept_features unchanged
- PASS -- cluster_input unchanged
- PASS -- groups_k2 unchanged
- PASS -- groups_k4 unchanged
- PASS -- 06_form_groups.py unchanged
- PASS -- 05_profile_devices.py unchanged

### Placement rule (NEW devices only) re-applied to every known device

Known devices keep their device_table group; this re-application only checks the rule. Rule: usable flows < 100 -> GEN; else nearest centroid; GEN if distance > that group's max member distance (G1 max 5.953, G2 max 4.445; medians G1 2.649, G2 1.089).

**Low-confidence devices (all GEN by rule):**

| device | confidence | usable_flows | groups_k2 | rule_result | rule_step | nearest | d_G1 | d_G2 | d_over_median_spread |
|---|---|---|---|---|---|---|---|---|---|
| Smart Board | low_confidence | 64 | G1 | GEN | min_flows gate (64 < 100) | G1 | 3.8794 | 4.2618 | 1.46 |
| Wemo Smart Plug 1 | low_confidence | 13 | G1 | GEN | min_flows gate (13 < 100) | G1 | 6.6065 | 7.0135 | 2.49 |
| iRobot Roomba | low_confidence | 32 | G2 | GEN | min_flows gate (32 < 100) | G2 | 4.8154 | 4.3938 | 4.03 |

**Ward boundary cases (2 of 52 high-confidence):** Ward joins clusters by minimum variance increase, not by nearest centroid, so these G1 members sit closer to the G2 centroid. They keep their Ward group (G1) in the device table; a NEW device with the same fingerprint would be placed in G2.

| device | confidence | usable_flows | groups_k2 | rule_result | rule_step | nearest | d_G1 | d_G2 | d_over_median_spread |
|---|---|---|---|---|---|---|---|---|---|
| Philips Hue Bridge | high | 2692 | G1 | G2 | nearest centroid | G2 | 2.9159 | 2.6131 | 2.4 |
| Yi Indoor 2 Camera | high | 911 | G1 | G2 | nearest centroid | G2 | 3.0755 | 3.0512 | 2.8 |

(Full per-device table in `config/behaviour_groups.json` -> verification.placement.)

## Group counts

| group | label | devices | high_conf | low_conf | usable_flows |
|---|---|---|---|---|---|
| G1 | high-activity multi-peer | 25 | 25 | 0 | 191119 |
| G2 | low-activity simple | 27 | 27 | 0 | 13616 |
| GEN | generalist fallback | 3 | 0 | 3 | 109 |

Total: 55 devices, 204,844 usable flows.

## Device table diff (vs backup)

- rows: 73 -> 73
- columns added: ['behaviour_group_label', 'group_confidence', 'group_k4']
- columns removed: []
- cells changed: {'behaviour_group': 73}
- behaviour_group transitions: `TBD (Step 6) -> G2` x27; `TBD (Step 6) -> G1` x25; `n/a -> ` x18; `TBD (Step 6) -> GEN` x3

## Figure change

- **fig2_device_fingerprints** regenerated (fig2_device_fingerprints.pdf, fig2_device_fingerprints.png): now drawn on the cluster-input scaling (robust median/IQR, p95-p5 fallback where IQR < 0.1 x (p95-p5), clipped ±3; identical to `cluster_input.csv` and Fig. 7). The previous fig2 used IQR-only scaling (unit fallback), so features with a near-zero IQR were not comparable with Fig. 7. Layout and row order (by category) are unchanged.

## Final group membership

| device | category | group | label | confidence | group_k4 | usable_flows |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Dot 1 | Audio | G1 | high-activity multi-peer | high | G1 | 1573 |
| Amazon Alexa Echo Dot 2 | Audio | G1 | high-activity multi-peer | high | G2 | 372 |
| Amazon Alexa Echo Studio | Audio | G1 | high-activity multi-peer | high | G1 | 3252 |
| Amazon Echo Show | Audio | G1 | high-activity multi-peer | high | G1 | 5247 |
| Google Nest Mini Speaker | Audio | G1 | high-activity multi-peer | high | G1 | 3891 |
| Harman Kardon speaker (Ampak) | Audio | G1 | high-activity multi-peer | high | G1 | 9619 |
| Sonos One Speaker | Audio | G1 | high-activity multi-peer | high | G1 | 1536 |
| AMCREST WiFi Camera | Camera | G1 | high-activity multi-peer | high | G1 | 2432 |
| Arlo Base Station | Camera | G1 | high-activity multi-peer | high | G2 | 1385 |
| Arlo Q Indoor Camera | Camera | G1 | high-activity multi-peer | high | G2 | 3752 |
| Home Eye Camera | Camera | G1 | high-activity multi-peer | high | G2 | 21760 |
| Netatmo Camera | Camera | G1 | high-activity multi-peer | high | G2 | 1488 |
| Rbcior Camera | Camera | G1 | high-activity multi-peer | high | G1 | 1767 |
| TP-Link Tapo Camera | Camera | G1 | high-activity multi-peer | high | G2 | 2244 |
| Wyze Camera | Camera | G1 | high-activity multi-peer | high | G1 | 9609 |
| Yi Indoor 2 Camera | Camera | G1 | high-activity multi-peer | high | G1 | 911 |
| Yi Indoor Camera | Camera | G1 | high-activity multi-peer | high | G2 | 2807 |
| Yi Outdoor Camera | Camera | G1 | high-activity multi-peer | high | G1 | 1169 |
| LG Smart TV | Home Automation | G1 | high-activity multi-peer | high | G1 | 4253 |
| Aeotec Smart Home Hub | Hub | G1 | high-activity multi-peer | high | G2 | 2111 |
| Eufy HomeBase 2 | Hub | G1 | high-activity multi-peer | high | G1 | 3112 |
| Fibaro Home Center Lite | Hub | G1 | high-activity multi-peer | high | G2 | 101507 |
| Philips Hue Bridge | Hub | G1 | high-activity multi-peer | high | G1 | 2692 |
| SmartThings Hub | Hub | G1 | high-activity multi-peer | high | G2 | 2159 |
| Wemo Smart Plug 2 | Power Outlet | G1 | high-activity multi-peer | high | G1 | 471 |
| D-Link DCS8000LHA1 Mini Camera | Camera | G2 | low-activity simple | high | G4 | 225 |
| HeimVision Smart WiFi Camera | Camera | G2 | low-activity simple | high | G3 | 910 |
| Nest Indoor Camera | Camera | G2 | low-activity simple | high | G4 | 294 |
| Atomi Coffee Maker | Home Automation | G2 | low-activity simple | high | G3 | 623 |
| Cocoon Smart HVAC Fan | Home Automation | G2 | low-activity simple | high | G4 | 290 |
| Govee Smart Humidifier | Home Automation | G2 | low-activity simple | high | G4 | 286 |
| Levoit Air Purifier | Home Automation | G2 | low-activity simple | high | G4 | 300 |
| Netatmo Weather Station | Home Automation | G2 | low-activity simple | high | G3 | 443 |
| Ring Base Station | Hub | G2 | low-activity simple | high | G4 | 438 |
| HeimVision SmartLife Radio/Lamp | Lighting | G2 | low-activity simple | high | G3 | 615 |
| LIFX Lightbulb | Lighting | G2 | low-activity simple | high | G3 | 339 |
| LampUX RGB | Lighting | G2 | low-activity simple | high | G3 | 541 |
| Lumiman Bulb | Lighting | G2 | low-activity simple | high | G3 | 617 |
| Teckin Light Strip | Lighting | G2 | low-activity simple | high | G3 | 626 |
| Amazon Smart Plug | Power Outlet | G2 | low-activity simple | high | G4 | 308 |
| GoSund Power Strip (1) | Power Outlet | G2 | low-activity simple | high | G3 | 546 |
| GoSund Power Strip (2) | Power Outlet | G2 | low-activity simple | high | G3 | 544 |
| GoSund Smart Plug WP2 (1) | Power Outlet | G2 | low-activity simple | high | G3 | 542 |
| GoSund Smart Plug WP2 (2) | Power Outlet | G2 | low-activity simple | high | G3 | 538 |
| Teckin Plug 1 | Power Outlet | G2 | low-activity simple | high | G3 | 607 |
| Teckin Plug 2 | Power Outlet | G2 | low-activity simple | high | G3 | 607 |
| Yutron Plug 1 | Power Outlet | G2 | low-activity simple | high | G3 | 609 |
| Yutron Plug 2 | Power Outlet | G2 | low-activity simple | high | G3 | 606 |
| Unidentified ESP plug (1) | Unidentified (Espressif) | G2 | low-activity simple | high | G3 | 538 |
| Unidentified ESP plug (2) | Unidentified (Espressif) | G2 | low-activity simple | high | G3 | 538 |
| Unidentified ESP plug (3) | Unidentified (Espressif) | G2 | low-activity simple | high | G3 | 543 |
| Unidentified ESP plug (4) | Unidentified (Espressif) | G2 | low-activity simple | high | G3 | 543 |
| Smart Board | Home Automation | GEN | generalist fallback | low | GEN | 64 |
| iRobot Roomba | Home Automation | GEN | generalist fallback | low | GEN | 32 |
| Wemo Smart Plug 1 | Power Outlet | GEN | generalist fallback | low | GEN | 13 |
