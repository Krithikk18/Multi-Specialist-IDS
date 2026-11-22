# Phase 3.1 part D -- train -> val drift diagnosis (read-only) -- PASS

## Rules (fixed before any number)

- **D1 capture-wide shift**: >= 70% of devices with >= 100 benign flows in both splits have KS > 0.2 on at
  least one timing feature.
- **D2 device-concentrated shift**: <= 2 devices account for >= 70% of the benign rows in features with KS > 0.2.
  Operational: for EVERY timing feature with pooled benign KS > 0.2, the 2 largest devices among those with their own
  KS > 0.2 on it hold >= 70% of all benign rows (train + val); no such feature -> DOES NOT HOLD.
- **D3 attack-tool shift**: attack classes show KS > 0.2 on timing features while benign stays < 0.1. Operational: some
  attack class (>= 100 rows in both splits) has KS > 0.2 on a timing feature AND the pooled benign KS < 0.1 on every
  timing feature.
- **D4 load / time-of-day**: per 5-minute window, median timing features correlate with the total packet rate or the
  time of day (Spearman |rho| >= 0.5). Operational: windows = (session, floor(start / 300)) with >= 30 benign flows,
  both splits; median over the window's benign flows; packet rate = sum of Total Fwd + Bwd packets of all flows starting in
  the window / 300 s; time of day = UTC hours.
- Each verdict is HOLDS / DOES NOT HOLD with its numbers; more than one may hold. Evaluated on BENIGN flows unless stated.

- v2_1_oriented train vs val (test never read); timing features (17): Flow Duration, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd Packets/s, Bwd Packets/s, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min

## Verdicts

| rule | verdict | numbers |
|---|---|---|
| D1 capture-wide | **DOES NOT HOLD** | 16 of 46 eligible devices (35%) have KS > 0.2 on >= 1 timing feature |
| D2 device-concentrated | **DOES NOT HOLD** | features with pooled KS > 0.2: 0; top-2 drifted-device row share per feature: none |
| D3 attack-tool | **DOES NOT HOLD** | pooled benign max KS 0.157; attack max KS syn_flood 0.592, port_scan 0.153 |
| D4 load / time of day | **DOES NOT HOLD** | 161 windows; max |rho| 0.39; features over 0.5: none |

## Pooled KS per timing feature (benign) and per class

| feature | benign | syn_flood | port_scan |
|---|---|---|---|
| Flow Duration | 0.114 | 0.592 | 0.153 |
| Flow Bytes/s | 0.067 | 0.000 | 0.000 |
| Flow Packets/s | 0.098 | 0.384 | 0.127 |
| Flow IAT Mean | 0.157 | 0.320 | 0.152 |
| Flow IAT Std | 0.084 | 0.555 | 0.002 |
| Flow IAT Max | 0.109 | 0.457 | 0.153 |
| Flow IAT Min | 0.143 | 0.131 | 0.152 |
| Fwd Packets/s | 0.105 | 0.388 | 0.127 |
| Bwd Packets/s | 0.084 | 0.034 | 0.126 |
| Active Mean | 0.057 | 0.008 | 0.000 |
| Active Std | 0.033 | 0.000 | 0.000 |
| Active Max | 0.057 | 0.008 | 0.000 |
| Active Min | 0.057 | 0.008 | 0.000 |
| Idle Mean | 0.065 | 0.319 | 0.000 |
| Idle Std | 0.040 | 0.557 | 0.000 |
| Idle Max | 0.065 | 0.457 | 0.000 |
| Idle Min | 0.065 | 0.125 | 0.000 |

## Devices (benign, >= 100 flows in both splits): max KS over timing features and adversarial AUC

| device | group | train | val | max KS | feature | adversarial AUC |
|---|---|---|---|---|---|---|
| HeimVision SmartLife Radio/Lamp | G2 | 657 | 102 | 0.402 | Flow IAT Max | 0.856 |
| Unidentified ESP plug (1) | G2 | 610 | 118 | 0.291 | Flow Duration | 0.850 |
| GoSund Smart Plug WP2 (1) | G2 | 611 | 123 | 0.263 | Flow Duration | 0.840 |
| Fibaro Home Center Lite | G1 | 20,047 | 15,014 | 0.263 | Flow IAT Mean | 0.841 |
| TP-Link Tapo Camera | G1 | 3,836 | 537 | 0.251 | Flow IAT Min | 0.789 |
| Wyze Camera | G1 | 11,780 | 1,730 | 0.225 | Flow Duration | 0.797 |
| Wemo Smart Plug 2 | G1 | 4,890 | 1,637 | 0.224 | Bwd Packets/s | 0.908 |
| LampUX RGB | G2 | 603 | 120 | 0.216 | Flow IAT Min | 0.805 |
| Yutron Plug 1 | G2 | 632 | 126 | 0.214 | Flow IAT Min | 0.819 |
| HeimVision Smart WiFi Camera | G2 | 973 | 177 | 0.212 | Idle Min | 0.701 |
| Teckin Plug 2 | G2 | 627 | 127 | 0.211 | Flow IAT Mean | 0.825 |
| Unidentified ESP plug (4) | G2 | 616 | 128 | 0.211 | Flow Duration | 0.792 |
| Unidentified Amazon device (1c:12:b0) | G1 | 1,829 | 381 | 0.210 | Flow IAT Min | 0.749 |
| Unidentified ESP plug (3) | G2 | 610 | 124 | 0.204 | Flow Duration | 0.775 |
| GoSund Power Strip (2) | G2 | 590 | 121 | 0.203 | Flow Duration | 0.776 |
| Rbcior Camera | G1 | 1,668 | 213 | 0.202 | Active Std | 0.700 |
| Lumiman Bulb | G2 | 917 | 144 | 0.197 | Flow Duration | 0.726 |
| Unidentified ESP plug (2) | G2 | 611 | 118 | 0.191 | Flow Duration | 0.760 |
| AMCREST WiFi Camera | G1 | 5,104 | 694 | 0.186 | Flow IAT Min | 0.780 |
| Netatmo Camera | G1 | 1,516 | 401 | 0.183 | Flow Duration | 0.673 |
| Amazon Smart Plug | G2 | 692 | 101 | 0.180 | Active Min | 0.828 |
| Amazon Alexa Echo Dot 2 | G1 | 1,254 | 260 | 0.178 | Bwd Packets/s | 0.669 |
| Google Nest Mini Speaker | G1 | 6,171 | 1,210 | 0.174 | Flow Duration | 0.824 |
| Teckin Plug 1 | G2 | 624 | 127 | 0.174 | Flow IAT Mean | 0.694 |
| GoSund Power Strip (1) | G2 | 613 | 122 | 0.170 | Flow Duration | 0.767 |
| Yutron Plug 2 | G2 | 630 | 134 | 0.168 | Flow IAT Min | 0.650 |
| GoSund Smart Plug WP2 (2) | G2 | 622 | 123 | 0.164 | Bwd Packets/s | 0.852 |
| Teckin Light Strip | G2 | 981 | 155 | 0.155 | Flow IAT Mean | 0.769 |
| Harman Kardon speaker (Ampak) | G1 | 8,360 | 1,784 | 0.143 | Bwd Packets/s | 0.735 |
| Arlo Q Indoor Camera | G1 | 2,449 | 893 | 0.134 | Bwd Packets/s | 0.701 |
| Yi Outdoor Camera | G1 | 1,145 | 217 | 0.133 | Flow IAT Min | 0.663 |
| Eufy HomeBase 2 | G1 | 3,344 | 599 | 0.129 | Flow Bytes/s | 0.777 |
| Yi Indoor Camera | G1 | 2,031 | 556 | 0.125 | Idle Std | 0.676 |
| Yi Indoor 2 Camera | G1 | 935 | 205 | 0.122 | Flow IAT Mean | 0.706 |
| Atomi Coffee Maker | G2 | 628 | 133 | 0.118 | Flow Duration | 0.577 |
| Sonos One Speaker | G1 | 1,745 | 326 | 0.114 | Flow IAT Std | 0.667 |
| SmartThings Hub | G1 | 2,240 | 407 | 0.092 | Flow IAT Min | 0.724 |
| Amazon Alexa Echo Dot 1 | G1 | 2,838 | 518 | 0.090 | Flow Bytes/s | 0.781 |
| Aeotec Smart Home Hub | G1 | 2,223 | 406 | 0.085 | Flow Packets/s | 0.668 |
| Smart Board | GEN | 868 | 249 | 0.081 | Flow IAT Min | 0.517 |
| Arlo Base Station | G1 | 1,399 | 282 | 0.081 | Flow Packets/s | 0.584 |
| Philips Hue Bridge | G1 | 2,444 | 551 | 0.080 | Bwd Packets/s | 0.608 |
| Home Eye Camera | G1 | 19,702 | 4,084 | 0.069 | Flow Bytes/s | 0.668 |
| LG Smart TV | G1 | 2,409 | 1,121 | 0.066 | Flow IAT Min | 0.591 |
| Amazon Alexa Echo Studio | G1 | 3,457 | 690 | 0.058 | Flow IAT Max | 0.715 |
| Amazon Echo Show | G1 | 5,212 | 1,117 | 0.048 | Flow IAT Min | 0.708 |

## Adversarial validation (benign train vs val, 5-fold out-of-fold)

- AUC overall **0.810**; per group G1 0.813 (train 120,028 / val 35,833), G2 0.767 (train 16,279 / val 3,061), GEN 0.599 (train 1,155 / val 291)
- top features (share of total gain): Flow IAT Mean 12.8 %, Fwd Packet Length Min 8.9 %, Flow IAT Min 6.3 %, Flow Duration 4.9 %, Bwd Packets/s 4.7 %, FWD Init Win Bytes 4.3 %, Flow IAT Std 4.2 %, Fwd Packets/s 3.9 %, Flow IAT Max 3.1 %, Bwd Init Win Bytes 3.0 %

## Does model error rise with drift? (promoted GLOBAL s0, val, per eligible device)

- Spearman(error rate, adversarial AUC) = +0.00; Spearman(benign false-alarm rate, AUC) = +0.16; Spearman(error rate, max KS) = -0.18

| device | group | val flows | error rate | benign FA rate | adversarial AUC |
|---|---|---|---|---|---|
| Wemo Smart Plug 2 | G1 | 1,637 | 0.0000 | 0.0000 | 0.908 |
| HeimVision SmartLife Radio/Lamp | G2 | 102 | 0.0000 | 0.0000 | 0.856 |
| GoSund Smart Plug WP2 (2) | G2 | 123 | 0.0000 | 0.0000 | 0.852 |
| Unidentified ESP plug (1) | G2 | 118 | 0.0000 | 0.0000 | 0.850 |
| Fibaro Home Center Lite | G1 | 15,014 | 0.0000 | 0.0000 | 0.841 |
| GoSund Smart Plug WP2 (1) | G2 | 123 | 0.0000 | 0.0000 | 0.840 |
| Amazon Smart Plug | G2 | 101 | 0.0000 | 0.0000 | 0.828 |
| Teckin Plug 2 | G2 | 127 | 0.0000 | 0.0000 | 0.825 |
| Google Nest Mini Speaker | G1 | 1,226 | 0.0057 | 0.0017 | 0.824 |
| Yutron Plug 1 | G2 | 126 | 0.0000 | 0.0000 | 0.819 |
| LampUX RGB | G2 | 120 | 0.0000 | 0.0000 | 0.805 |
| Wyze Camera | G1 | 1,730 | 0.0000 | 0.0000 | 0.797 |
| Unidentified ESP plug (4) | G2 | 128 | 0.0000 | 0.0000 | 0.792 |
| TP-Link Tapo Camera | G1 | 537 | 0.0000 | 0.0000 | 0.789 |
| Amazon Alexa Echo Dot 1 | G1 | 518 | 0.0000 | 0.0000 | 0.781 |
| AMCREST WiFi Camera | G1 | 50,797 | 0.0041 | 0.0000 | 0.780 |
| Eufy HomeBase 2 | G1 | 599 | 0.0000 | 0.0000 | 0.777 |
| GoSund Power Strip (2) | G2 | 121 | 0.0000 | 0.0000 | 0.776 |
| Unidentified ESP plug (3) | G2 | 27,787 | 0.0000 | 0.0000 | 0.775 |
| Teckin Light Strip | G2 | 2,330 | 0.0000 | 0.0000 | 0.769 |
| GoSund Power Strip (1) | G2 | 122 | 0.0000 | 0.0000 | 0.767 |
| Unidentified ESP plug (2) | G2 | 22,529 | 0.0000 | 0.0000 | 0.760 |
| Unidentified Amazon device (1c:12:b0) | G1 | 381 | 0.0000 | 0.0000 | 0.749 |
| Harman Kardon speaker (Ampak) | G1 | 5,549 | 0.0002 | 0.0000 | 0.735 |
| Lumiman Bulb | G2 | 2,282 | 0.0000 | 0.0000 | 0.726 |
| SmartThings Hub | G1 | 407 | 0.0000 | 0.0000 | 0.724 |
| Amazon Alexa Echo Studio | G1 | 690 | 0.0000 | 0.0000 | 0.715 |
| Amazon Echo Show | G1 | 3,118 | 0.0019 | 0.0000 | 0.708 |
| Yi Indoor 2 Camera | G1 | 205 | 0.0000 | 0.0000 | 0.706 |
| HeimVision Smart WiFi Camera | G2 | 177 | 0.0000 | 0.0000 | 0.701 |
| Arlo Q Indoor Camera | G1 | 893 | 0.0000 | 0.0000 | 0.701 |
| Rbcior Camera | G1 | 213 | 0.0000 | 0.0000 | 0.700 |
| Teckin Plug 1 | G2 | 127 | 0.0000 | 0.0000 | 0.694 |
| Yi Indoor Camera | G1 | 556 | 0.0000 | 0.0000 | 0.676 |
| Netatmo Camera | G1 | 401 | 0.0000 | 0.0000 | 0.673 |
| Amazon Alexa Echo Dot 2 | G1 | 260 | 0.0000 | 0.0000 | 0.669 |
| Home Eye Camera | G1 | 4,084 | 0.0000 | 0.0000 | 0.668 |
| Aeotec Smart Home Hub | G1 | 406 | 0.0000 | 0.0000 | 0.668 |
| Sonos One Speaker | G1 | 326 | 0.0000 | 0.0000 | 0.667 |
| Yi Outdoor Camera | G1 | 217 | 0.0000 | 0.0000 | 0.663 |
| Yutron Plug 2 | G2 | 134 | 0.0000 | 0.0000 | 0.650 |
| Philips Hue Bridge | G1 | 551 | 0.0000 | 0.0000 | 0.608 |
| LG Smart TV | G1 | 3,119 | 0.0029 | 0.0000 | 0.591 |
| Arlo Base Station | G1 | 282 | 0.0000 | 0.0000 | 0.584 |
| Atomi Coffee Maker | G2 | 133 | 0.0000 | 0.0000 | 0.577 |
| Smart Board | GEN | 249 | 0.0000 | 0.0000 | 0.517 |

## Figures

- `figures/ks_device_feature.png`
- `figures/ks_per_class.png`
- `figures/adversarial_auc.png`
- `figures/error_vs_drift.png`

## Checks

- PASS  config.py / class_map.json unchanged  {'config/config.py': 'c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf', 'config/class_map.json': '64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580'}
