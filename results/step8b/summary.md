# Step 8b -- dataset v1_1: v1 + daytime benign test sessions

- run 2026-10-19T19:35:39+00:00, runtime 6.9 s, peak RSS 1,215 MB
- args: `08b_extend_test.py`
- log: `/mnt/d/Projects/Company Project/Paper_Implemetation/logs/08b_extend_test_2026-10-19T193539Z.log`

## Assertions

**PASS**

| check | pass | detail |
|---|---|---|
| verify_lock | PASS | 10 checks |
| v1 files match manifest_v1 (rows, bytes) | PASS | ok |
| features = v1 (features_v1.json sha256, order, v1 parquet schema) | PASS | 70 features, sha256 cf73976fd384a466... (json cf73976fd384a466..., manifest_v1 cf73976fd384a466...); parquet columns = features + ['y', 'attack_family', 'group', 'device', 'device_category', 'session', 'split', 'start_ts']: True |
| device_table, behaviour_groups, split_plan.json unchanged since v1 | PASS | ok (sha256 = manifest_v1) |
| daytime inputs: extractor lock, 07 hard_pass, same pcap / jar / device_table, columns | PASS | ok (3 session(s)) |
| no daytime row labelled attack (07, all rows) | PASS | attack-labelled rows per session {'BenignTraffic1': 0, 'BenignTraffic2': 0, 'BenignTraffic3': 0} |
| daytime time ranges overlap no v1 session and no other daytime session | PASS | ok (1 shared boundary second(s)) |
| daytime rows written: y 0, attack_family blank, split test, group in G1/G2/GEN | PASS | 0 rows with a group outside ('G1', 'G2', 'GEN') (y / family / split are set as constants) |
| train / val parquet = byte copies of v1 (sha256) | PASS | {'train': True, 'val': True} |
| v1.1 test = v1 test rows unchanged, then the daytime rows | PASS | head 473,810 rows = v1 test 473,810 (column sha256 b2ace46c5389a0f8...); tail 220,359 = daytime 220,359; total 694,169 |
| v1 parquet, results/step8, split_plan.json unchanged after the run | PASS | ok (sha256 before = after) |

Boundary seconds shared (not an overlap; Timestamps are whole seconds, the pcaps are packet-disjoint):

- BenignTraffic1 [2022-10-08T02:30:28+00:00, 2022-10-08T09:45:20+00:00] / benign_night [2022-10-07T17:15:00+00:00, 2022-10-08T02:30:28+00:00]: share second 2022-10-08T02:30:28+00:00

## Test active benign hours (08 rule) and FP / hour

- v1 test: **3.018 h** (manifest_v1)
- added: **18.742 h** (BenignTraffic1 7.248, BenignTraffic2 8.033, BenignTraffic3 3.461); registered-owner rows only: 18.742 h
- v1.1 test: **21.760 h** (x7.21)

| test_FPs | FP_per_h_v1 | FP_per_h_v1_1 |
|---|---|---|
| 1 | 0.3314 | 0.046 |
| 2 | 0.6627 | 0.0919 |
| 5 | 1.6568 | 0.2298 |
| 10 | 3.3136 | 0.4596 |
| 20 | 6.6271 | 0.9191 |
| 50 | 16.5678 | 2.2978 |

## Test rows before / after

| dataset | benign | attack | total |
|---|---|---|---|
| v1 | 54,714 | 419,096 | 473,810 |
| v1_1 | 275,073 | 419,096 | 694,169 |

## Daytime sessions

rows = all flows in the file; added = rows written to test

| session | start_utc | end_utc | span_h | active_h | segments | rows | label_attack | not_owned | exclude_reason | label_excluded | ungrouped | unregistered_mac_kept | added | benign_h |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| BenignTraffic1 | 2022-10-08T02:30:28+00:00 | 2022-10-08T09:45:20+00:00 | 7.25 | 7.25 | 1 | 93,698 | 0 | 6,812 | 0 | 1,573 | 0 | 8 | 85,321 | 7.248 |
| BenignTraffic2 | 2022-10-08T09:45:21+00:00 | 2022-10-08T17:47:19+00:00 | 8.03 | 8.03 | 1 | 101,111 | 0 | 5,339 | 0 | 1,488 | 0 | 0 | 94,284 | 8.033 |
| BenignTraffic3 | 2022-10-08T17:47:21+00:00 | 2022-10-08T21:15:00+00:00 | 3.46 | 3.46 | 1 | 43,078 | 0 | 1,755 | 0 | 569 | 0 | 0 | 40,754 | 3.461 |

## 07 labels per daytime session (all rows)

| session | attack | benign | excluded | excluded_by_reason |
|---|---|---|---|---|
| BenignTraffic1 | 0 | 91,713 | 1,985 | attacker_offwindow 1,985 |
| BenignTraffic2 | 0 | 99,166 | 1,945 | attacker_offwindow 1,915, attacker_normal_traffic 18, attack_normal_service_ambiguous 12 |
| BenignTraffic3 | 0 | 42,317 | 761 | attacker_offwindow 761 |

## Rows added per group

| group | BenignTraffic1 | BenignTraffic2 | BenignTraffic3 | total |
|---|---|---|---|---|
| G1 | 74,713 | 82,625 | 35,680 | 193,018 |
| G2 | 10,460 | 11,618 | 5,055 | 27,133 |
| GEN | 148 | 41 | 19 | 208 |

## Rows added per device

| group | device | BenignTraffic1 | BenignTraffic2 | BenignTraffic3 | total |
|---|---|---|---|---|---|
| G1 | Home Eye Camera | 17,026 | 18,777 | 8,227 | 44,030 |
| G1 | Harman Kardon speaker (Ampak) | 7,360 | 8,274 | 3,490 | 19,124 |
| G1 | Wyze Camera | 7,372 | 8,035 | 3,595 | 19,002 |
| G1 | Arlo Q Indoor Camera | 4,461 | 4,764 | 2,354 | 11,579 |
| G1 | LG Smart TV | 4,088 | 3,949 | 1,499 | 9,536 |
| G1 | Fibaro Home Center Lite | 3,628 | 4,021 | 1,735 | 9,384 |
| G1 | Amazon Echo Show | 3,480 | 3,833 | 1,405 | 8,718 |
| G1 | Yi Indoor Camera | 2,889 | 3,186 | 1,384 | 7,459 |
| G1 | Google Nest Mini Speaker | 2,612 | 2,716 | 1,184 | 6,512 |
| G1 | Amazon Alexa Echo Studio | 2,532 | 2,871 | 1,105 | 6,508 |
| G1 | Eufy HomeBase 2 | 2,432 | 2,668 | 1,161 | 6,261 |
| G1 | TP-Link Tapo Camera | 1,943 | 2,589 | 1,140 | 5,672 |
| G1 | AMCREST WiFi Camera | 1,854 | 2,055 | 832 | 4,741 |
| G1 | Philips Hue Bridge | 1,636 | 1,902 | 830 | 4,368 |
| G1 | SmartThings Hub | 1,681 | 1,867 | 784 | 4,332 |
| G1 | Aeotec Smart Home Hub | 1,638 | 1,853 | 787 | 4,278 |
| G1 | Amazon Alexa Echo Dot 1 | 1,241 | 1,476 | 602 | 3,319 |
| G1 | Netatmo Camera | 1,219 | 1,418 | 543 | 3,180 |
| G1 | Sonos One Speaker | 1,132 | 1,364 | 592 | 3,088 |
| G1 | Arlo Base Station | 1,121 | 1,191 | 503 | 2,815 |
| G1 | Yi Outdoor Camera | 1,036 | 1,137 | 510 | 2,683 |
| G1 | Rbcior Camera | 1,046 | 1,155 | 471 | 2,672 |
| G1 | Yi Indoor 2 Camera | 679 | 785 | 323 | 1,787 |
| G1 | Amazon Alexa Echo Dot 2 | 313 | 393 | 486 | 1,192 |
| G1 | Wemo Smart Plug 2 | 294 | 346 | 138 | 778 |
| G2 | HeimVision Smart WiFi Camera | 649 | 707 | 306 | 1,662 |
| G2 | Lumiman Bulb | 491 | 536 | 229 | 1,256 |
| G2 | Atomi Coffee Maker | 482 | 537 | 227 | 1,246 |
| G2 | Teckin Light Strip | 480 | 534 | 228 | 1,242 |
| G2 | HeimVision SmartLife Radio/Lamp | 472 | 529 | 226 | 1,227 |
| G2 | Yutron Plug 2 | 467 | 525 | 226 | 1,218 |
| G2 | Teckin Plug 2 | 469 | 519 | 226 | 1,214 |
| G2 | Yutron Plug 1 | 470 | 513 | 225 | 1,208 |
| G2 | Teckin Plug 1 | 465 | 517 | 224 | 1,206 |
| G2 | GoSund Power Strip (1) | 422 | 477 | 203 | 1,102 |
| G2 | GoSund Power Strip (2) | 420 | 475 | 203 | 1,098 |
| G2 | LampUX RGB | 419 | 472 | 202 | 1,093 |
| G2 | Unidentified ESP plug (4) | 420 | 471 | 201 | 1,092 |
| G2 | Unidentified ESP plug (3) | 420 | 467 | 203 | 1,090 |
| G2 | Unidentified ESP plug (2) | 417 | 468 | 204 | 1,089 |
| G2 | GoSund Smart Plug WP2 (2) | 418 | 467 | 202 | 1,087 |
| G2 | Unidentified ESP plug (1) | 416 | 470 | 201 | 1,087 |
| G2 | GoSund Smart Plug WP2 (1) | 415 | 466 | 200 | 1,081 |
| G2 | Netatmo Weather Station | 348 | 393 | 163 | 904 |
| G2 | LIFX Lightbulb | 326 | 367 | 160 | 853 |
| G2 | Ring Base Station | 273 | 236 | 156 | 665 |
| G2 | Levoit Air Purifier | 241 | 261 | 117 | 619 |
| G2 | Amazon Smart Plug | 227 | 257 | 119 | 603 |
| G2 | Cocoon Smart HVAC Fan | 229 | 251 | 109 | 589 |
| G2 | Nest Indoor Camera | 218 | 261 | 104 | 583 |
| G2 | Govee Smart Humidifier | 221 | 250 | 107 | 578 |
| G2 | D-Link DCS8000LHA1 Mini Camera | 165 | 192 | 84 | 441 |
| GEN | Smart Board | 101 | 0 | 0 | 101 |
| GEN | iRobot Roomba | 25 | 27 | 12 | 64 |
| GEN | Wemo Smart Plug 1 | 14 | 14 | 7 | 35 |
| GEN | unregistered:f0:b4:d2:f9:60:95 | 8 | 0 | 0 | 8 |

## Unregistered MACs (in the pcap map, not in device_table)

endpoint_flows = flows with this MAC as an endpoint (role unlisted); kept_as_gen = written to test (group GEN, device_category unregistered_mac); dropped_excluded = unowned + exclude_reason or label excluded. Flows with a registered smart-home device on the other side stay that device's rows.

| session | mac | endpoint_flows | kept_as_gen | dropped_excluded |
|---|---|---|---|---|
| BenignTraffic1 | f0:b4:d2:f9:60:95 | 8 | 8 | 0 |

- flows with an unlisted endpoint owned by a registered device: 0

## NaN / Inf replaced by 0 (daytime rows written)

| column | nan | inf |
|---|---|---|
| Flow Bytes/s | 8,573 | 14,143 |
| Flow Packets/s | 0 | 22,716 |
| Flow IAT Mean | 22,620 | 0 |
| Flow IAT Std | 22,620 | 0 |
| Flow IAT Max | 22,620 | 0 |
| Flow IAT Min | 22,620 | 0 |

## Outputs

| file | rows | bytes | sha256 | path |
|---|---|---|---|---|
| train.parquet | 636,193 | 53,905,498 | e01c2ae2bae7ce49b64a8e003d5ebe258a1f15e1600751f1ae3e0090738dd2a4 | /home/krithikk/lgids_cache/datasets/v1_1/train.parquet |
| val.parquet | 157,558 | 14,086,088 | f992fc82ed8cd34f2c8a26eab4f780473ae71b53d7577d66fd7724a789bc1a03 | /home/krithikk/lgids_cache/datasets/v1_1/val.parquet |
| test.parquet | 694,169 | 70,144,527 | 0650b0fd0dcc01d84a4b12020fc3d625484b84c42e0844e3c0e1794cc3bf45b5 | /home/krithikk/lgids_cache/datasets/v1_1/test.parquet |
| split_plan_v1_1.json |  | 3,788 | 56813a35e1cbcf46a7f41ae9cdd1e5d1affb0b94f3ef358427ad778e13182827 | /mnt/d/Projects/Company Project/Paper_Implemetation/config/split_plan_v1_1.json |

## Inputs

| session | extractor_rows | sha256 | pcap_sha256 | path |
|---|---|---|---|---|
| BenignTraffic1 | 93,698 | ba56437c91177b85d4ac624bc20c18be899f31fd5577eb6956f680f88586a649 | 7af057c6681e076151cc28e123a44ea6ff0e3b174d39d456ba7ccf1ac22d24c0 | /home/krithikk/lgids_cache/flows/benign_day/BenignTraffic1/BenignTraffic1_labelled.csv.gz |
| BenignTraffic2 | 101,111 | c71e641589e525b01f89f0df93470069a473db7f27a5ce4d6a47a1bcba08f16a | ddafc1c1d3432bdde55340423196ceee79bba47b48b14179ae48d561cca341b8 | /home/krithikk/lgids_cache/flows/benign_day/BenignTraffic2/BenignTraffic2_labelled.csv.gz |
| BenignTraffic3 | 43,078 | bccaf5fa1c5bd3831866001100c600893156275bf92278d0d50b7a1b17ceb35d | af98016449742052bca87d7ac598cf6e4e4558c33480cdb665f93da7b60b6e11 | /home/krithikk/lgids_cache/flows/benign_day/BenignTraffic3/BenignTraffic3_labelled.csv.gz |

v1: train sha256 e01c2ae2bae7ce49... (636,193 rows), val sha256 f992fc82ed8cd34f... (157,558 rows), test sha256 7ddbe0fa45dd20af... (473,810 rows)
