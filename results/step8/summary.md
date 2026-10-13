# Step 8 -- dataset build v1

- run 2026-10-13T19:05:20+00:00, runtime 244.1 s, peak RSS 3,033 MB
- args: `08_build_datasets.py`
- split plan v1.0 (sha256 38de9358ea0b223e...), groups 1.0, attack set v1, seed 42, gap 120 s, time_basis active (a pause > 300 s ends an active segment)

## !!! WARNINGS

- **WARN** (GEN, port_scan): 4,356 attack rows in train but NONE in test
- **WARN** (GEN, syn_flood): only 3 attack rows in test (< min_test_attack_warn 20; train 0, val 0)
- **WARN** (GEN, udp_flood): no attack rows in any split

## Hard checks

**PASS**

| check | pass | detail |
|---|---|---|
| no row in two splits | PASS | overlaps {'train&val': 0, 'train&test': 0, 'val&test': 0}, duplicate ids within a split {'train': 0, 'val': 0, 'test': 0} |
| per session max(t) of each split < min(t) of the next | PASS | ok |
| no identity column in features | PASS | ok |
| y matches label (y == 1 iff attack, attack_family set iff y) | PASS | 0 mismatches |
| pass-2 pre-sample counts == pass-1 counts | PASS | 0 keys differ {} |
| train split not empty | PASS | 636,193 rows |

## Totals per split

rows written

| split | benign | attack | total |
|---|---|---|---|
| train | 137,462 | 498,731 | 636,193 |
| val | 39,185 | 118,373 | 157,558 |
| test | 54,714 | 419,096 | 473,810 |

## Sessions

rows = all flows in the file; train / val / test / gap_dropped = usable rows (owned, no exclude_reason, label != excluded, grouped) before caps

| session | alias | mode | start_utc | end_utc | span_h | active_h | segments | rows | not_owned | exclude_reason | label_excluded | ungrouped | train | val | test | gap_dropped | cuts_utc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign_night | benign_night | time_split | 2022-10-07T17:15:00+00:00 | 2022-10-08T02:30:28+00:00 | 9.26 | 9.26 | 1 | 223,108 | 13,162 | 5,102 | 0 | 0 | 162,803 | 24,686 | 16,104 | 1,251 | gap@train|val@10-07 23:43:50, val@10-07 23:45:50, gap@val|test@10-08 01:07:09, test@10-08 01:09:09 |
| DDoS-SYN_Flood | SYN first part | train | 2022-08-26T18:18:00+00:00 | 2022-08-29T12:31:44+00:00 | 66.23 | 0.68 | 4 | 6,800,503 | 2,040 | 0 | 15,529 | 0 | 5,887,481 | 791,696 | 0 | 103,757 | gap@train|val@08-26 19:07:38, val@08-26 19:09:38 |
| DDoS-SYN_Flood5 | SYN 5 | train | 2022-08-29T17:20:34+00:00 | 2022-08-29T17:57:10+00:00 | 0.61 | 0.48 | 2 | 5,297,297 | 1,223 | 0 | 3 | 0 | 4,205,647 | 713,445 | 0 | 376,979 | gap@train|val@08-29 17:44:54, val@08-29 17:46:54 |
| DDoS-SYN_Flood10 | SYN 10 | test | 2022-08-30T13:10:09+00:00 | 2022-08-30T13:45:21+00:00 | 0.59 | 0.59 | 1 | 6,099,055 | 1,765 | 0 | 13,401 | 0 | 0 | 0 | 6,083,889 | 0 |  |
| DDoS-SYN_Flood15 | SYN 15 | test | 2022-11-29T19:18:18+00:00 | 2022-12-01T14:43:00+00:00 | 43.41 | 0.36 | 2 | 3,104,718 | 1,417 | 86 | 660 | 0 | 0 | 0 | 3,102,555 | 0 |  |
| Recon-PortScan | Recon-PortScan | time_split | 2022-09-26T16:31:00+00:00 | 2022-09-27T17:16:00+00:00 | 24.75 | 3.3 | 10 | 207,429 | 9,915 | 0 | 106 | 0 | 135,693 | 28,528 | 30,135 | 3,052 | gap@train|val@09-27 14:28:38, val@09-27 14:30:38, gap@val|test@09-27 15:04:20, test@09-27 15:06:20 |
| Mirai-udpplain | Mirai first part | train | 2023-01-19T15:51:00+00:00 | 2023-01-19T16:23:25+00:00 | 0.54 | 0.44 | 2 | 8,806 | 1,460 | 0 | 29 | 0 | 6,720 | 597 | 0 | 0 | gap@train|val@01-19 16:19:27, val@01-19 16:21:27 |
| Mirai-udpplain24 | Mirai 24 | test | 2023-02-07T16:23:57+00:00 | 2023-02-14T17:38:00+00:00 | 169.23 | 0.25 | 2 | 6,251 | 832 | 0 | 83 | 0 | 0 | 0 | 5,336 | 0 |  |

## Active benign hours per session per split (FP/hour denominator)

active segments (a pause > active_idle_gap_seconds between flow starts ends one) holding >= 1 usable benign flow start, clipped to the split's wall-clock window, gap windows excluded; FP/hour denominator. Train benign is subsampled by the caps; val / test benign never is.

| session | train | val | test |
|---|---|---|---|
| benign_night | 6.481 | 1.355 | 1.355 |
| DDoS-SYN_Flood | 0.578 | 0.079 | 0.0 |
| DDoS-SYN_Flood5 | 0.406 | 0.038 | 0.0 |
| DDoS-SYN_Flood10 | 0.0 | 0.0 | 0.587 |
| DDoS-SYN_Flood15 | 0.0 | 0.0 | 0.362 |
| Recon-PortScan | 2.312 | 0.462 | 0.462 |
| Mirai-udpplain | 0.375 | 0.033 | 0.0 |
| Mirai-udpplain24 | 0.0 | 0.0 | 0.251 |
| TOTAL | 10.151 | 1.968 | 3.018 |

## Gap drops (flows starting within gap_seconds after a cut)

| session | split | label | family | n |
|---|---|---|---|---|
| DDoS-SYN_Flood | gap@train|val | attack | syn_flood | 102,920 |
| DDoS-SYN_Flood | gap@train|val | benign |  | 837 |
| DDoS-SYN_Flood5 | gap@train|val | attack | syn_flood | 375,770 |
| DDoS-SYN_Flood5 | gap@train|val | benign |  | 1,209 |
| Recon-PortScan | gap@train|val | attack | port_scan | 2,235 |
| Recon-PortScan | gap@train|val | benign |  | 817 |
| benign_night | gap@train|val | benign |  | 846 |
| benign_night | gap@val|test | benign |  | 405 |

## Rows per split x group x label x family

| split | group | label | family | before_caps | written |
|---|---|---|---|---|---|
| train | G1 | attack | port_scan | 50,472 | 50,472 |
| train | G1 | attack | syn_flood | 5,864,210 | 200,605 |
| train | G1 | attack | udp_flood | 95 | 95 |
| train | G1 | benign |  | 223,461 | 120,028 |
| train | G2 | attack | port_scan | 43,218 | 43,218 |
| train | G2 | attack | syn_flood | 4,195,098 | 199,985 |
| train | G2 | benign |  | 16,279 | 16,279 |
| train | GEN | attack | port_scan | 4,356 | 4,356 |
| train | GEN | benign |  | 1,155 | 1,155 |
| val | G1 | attack | port_scan | 7,763 | 7,763 |
| val | G1 | attack | syn_flood | 789,257 | 50,103 |
| val | G1 | attack | udp_flood | 17 | 17 |
| val | G1 | benign |  | 35,833 | 35,833 |
| val | G2 | attack | port_scan | 10,416 | 10,416 |
| val | G2 | attack | syn_flood | 712,314 | 50,074 |
| val | G2 | benign |  | 3,061 | 3,061 |
| val | GEN | benign |  | 291 | 291 |
| test | G1 | attack | port_scan | 11,791 | 11,791 |
| test | G1 | attack | syn_flood | 4,654,900 | 199,774 |
| test | G1 | attack | udp_flood | 35 | 35 |
| test | G1 | benign |  | 47,720 | 47,720 |
| test | G2 | attack | port_scan | 8,715 | 8,715 |
| test | G2 | attack | syn_flood | 4,507,838 | 198,755 |
| test | G2 | attack | udp_flood | 23 | 23 |
| test | G2 | benign |  | 6,451 | 6,451 |
| test | GEN | attack | syn_flood | 3 | 3 |
| test | GEN | benign |  | 543 | 543 |

## Cap keys

| cap_key | count | cap | p |
|---|---|---|---|
| attack|test|G1|syn_flood | 4,654,900 | 200,000 | 0.042965 |
| attack|test|G2|syn_flood | 4,507,838 | 200,000 | 0.044367 |
| attack|train|G1|syn_flood | 5,864,210 | 200,000 | 0.034105 |
| attack|train|G2|syn_flood | 4,195,098 | 200,000 | 0.047675 |
| attack|val|G1|syn_flood | 789,257 | 50,000 | 0.063351 |
| attack|val|G2|syn_flood | 712,314 | 50,000 | 0.070194 |
| benign|train|G1|Fibaro Home Center Lite | 123,480 | 20,000 | 0.161970 |

(56 more cap keys under their cap, p = 1)

## Train rows per device (before / after caps)

| group | device | benign_before | benign_after | attack_before | attack_after |
|---|---|---|---|---|---|
| G1 | Fibaro Home Center Lite | 123,480 | 20,047 | 0 | 0 |
| G1 | Home Eye Camera | 19,702 | 19,702 | 5,002 | 5,002 |
| G1 | Wyze Camera | 11,780 | 11,780 | 1,001 | 1,001 |
| G1 | Harman Kardon speaker (Ampak) | 8,360 | 8,360 | 0 | 0 |
| G1 | Google Nest Mini Speaker | 6,171 | 6,171 | 1,735,740 | 62,585 |
| G1 | Amazon Echo Show | 5,212 | 5,212 | 0 | 0 |
| G1 | AMCREST WiFi Camera | 5,104 | 5,104 | 3,306 | 3,306 |
| G1 | Wemo Smart Plug 2 | 4,890 | 4,890 | 2,001 | 2,001 |
| G1 | TP-Link Tapo Camera | 3,836 | 3,836 | 2,001 | 2,001 |
| G1 | Amazon Alexa Echo Studio | 3,457 | 3,457 | 7,027 | 7,027 |
| G1 | Eufy HomeBase 2 | 3,344 | 3,344 | 3,003 | 3,003 |
| G1 | Amazon Alexa Echo Dot 1 | 2,838 | 2,838 | 2,071,833 | 72,547 |
| G1 | Arlo Q Indoor Camera | 2,449 | 2,449 | 3,280 | 3,280 |
| G1 | Philips Hue Bridge | 2,444 | 2,444 | 1,124 | 1,124 |
| G1 | LG Smart TV | 2,409 | 2,409 | 0 | 0 |
| G1 | SmartThings Hub | 2,240 | 2,240 | 0 | 0 |
| G1 | Aeotec Smart Home Hub | 2,223 | 2,223 | 0 | 0 |
| G1 | Yi Indoor Camera | 2,031 | 2,031 | 0 | 0 |
| G1 | Unidentified Amazon device (1c:12:b0) | 1,829 | 1,829 | 2,063,651 | 72,487 |
| G1 | Sonos One Speaker | 1,745 | 1,745 | 3,001 | 3,001 |
| G1 | Rbcior Camera | 1,668 | 1,668 | 0 | 0 |
| G1 | Netatmo Camera | 1,516 | 1,516 | 4,015 | 4,015 |
| G1 | Arlo Base Station | 1,399 | 1,399 | 3,001 | 3,001 |
| G1 | Amazon Alexa Echo Dot 2 | 1,254 | 1,254 | 0 | 0 |
| G1 | Yi Outdoor Camera | 1,145 | 1,145 | 2,468 | 2,468 |
| G1 | Yi Indoor 2 Camera | 935 | 935 | 3,323 | 3,323 |
| G2 | Teckin Light Strip | 981 | 981 | 0 | 0 |
| G2 | HeimVision Smart WiFi Camera | 973 | 973 | 3,088 | 3,088 |
| G2 | Lumiman Bulb | 917 | 917 | 0 | 0 |
| G2 | Amazon Smart Plug | 692 | 692 | 4,282 | 4,282 |
| G2 | HeimVision SmartLife Radio/Lamp | 657 | 657 | 0 | 0 |
| G2 | Yutron Plug 1 | 632 | 632 | 2,030 | 2,030 |
| G2 | Yutron Plug 2 | 630 | 630 | 2,170 | 2,170 |
| G2 | Atomi Coffee Maker | 628 | 628 | 3,465 | 3,465 |
| G2 | Cocoon Smart HVAC Fan | 627 | 627 | 0 | 0 |
| G2 | Teckin Plug 2 | 627 | 627 | 2,118 | 2,118 |
| G2 | Teckin Plug 1 | 624 | 624 | 1,013 | 1,013 |
| G2 | GoSund Smart Plug WP2 (2) | 622 | 622 | 2,184 | 2,184 |
| G2 | Unidentified ESP plug (4) | 616 | 616 | 0 | 0 |
| G2 | GoSund Power Strip (1) | 613 | 613 | 2,129 | 2,129 |
| G2 | GoSund Smart Plug WP2 (1) | 611 | 611 | 2,451,594 | 118,620 |
| G2 | Unidentified ESP plug (2) | 611 | 611 | 1,749,496 | 87,357 |
| G2 | Unidentified ESP plug (1) | 610 | 610 | 2,171 | 2,171 |
| G2 | Unidentified ESP plug (3) | 610 | 610 | 2,128 | 2,128 |
| G2 | LampUX RGB | 603 | 603 | 1,151 | 1,151 |
| G2 | GoSund Power Strip (2) | 590 | 590 | 2,178 | 2,178 |
| G2 | Nest Indoor Camera | 462 | 462 | 4,363 | 4,363 |
| G2 | Govee Smart Humidifier | 435 | 435 | 0 | 0 |
| G2 | Netatmo Weather Station | 435 | 435 | 0 | 0 |
| G2 | Levoit Air Purifier | 410 | 410 | 2,756 | 2,756 |
| G2 | D-Link DCS8000LHA1 Mini Camera | 399 | 399 | 0 | 0 |
| G2 | Ring Base Station | 398 | 398 | 0 | 0 |
| G2 | LIFX Lightbulb | 266 | 266 | 0 | 0 |
| GEN | Smart Board | 868 | 868 | 1,004 | 1,004 |
| GEN | Wemo Smart Plug 1 | 210 | 210 | 2,002 | 2,002 |
| GEN | iRobot Roomba | 77 | 77 | 1,350 | 1,350 |

## Features

- 70 features, sha256 `cf73976fd384a46609789d952d803b695cf462557595b02838066d4b3285ce5c` -> `/mnt/d/Projects/Company Project/Paper_Implemetation/config/features_v1.json`
- dropped identity: Flow ID, Src IP, Src Port, Dst IP, Dst Port, Timestamp, Label
- dropped constant in train: Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, URG Flag Count, Fwd Bytes/Bulk Avg, Fwd Packet/Bulk Avg, Fwd Bulk Rate Avg

## NaN / Inf replaced by 0 (rows written)

| split | column | nan | inf |
|---|---|---|---|
| train | Flow Bytes/s | 39,288 | 8,707 |
| train | Flow Packets/s | 0 | 47,995 |
| train | Flow IAT Mean | 47,818 | 0 |
| train | Flow IAT Std | 47,818 | 0 |
| train | Flow IAT Max | 47,818 | 0 |
| train | Flow IAT Min | 47,818 | 0 |
| val | Flow Bytes/s | 24,003 | 1,685 |
| val | Flow Packets/s | 0 | 25,688 |
| val | Flow IAT Mean | 25,646 | 0 |
| val | Flow IAT Std | 25,646 | 0 |
| val | Flow IAT Max | 25,646 | 0 |
| val | Flow IAT Min | 25,646 | 0 |
| test | Flow Bytes/s | 30,366 | 3,513 |
| test | Flow Packets/s | 0 | 33,879 |
| test | Flow IAT Mean | 33,757 | 0 |
| test | Flow IAT Std | 33,757 | 0 |
| test | Flow IAT Max | 33,757 | 0 |
| test | Flow IAT Min | 33,757 | 0 |

## Outputs

| split | rows | bytes | path |
|---|---|---|---|
| train | 636,193 | 53,905,498 | /home/krithikk/lgids_cache/datasets/v1/train.parquet |
| val | 157,558 | 14,086,088 | /home/krithikk/lgids_cache/datasets/v1/val.parquet |
| test | 473,810 | 40,747,838 | /home/krithikk/lgids_cache/datasets/v1/test.parquet |

## Inputs

| session | rows | sha256 | path |
|---|---|---|---|
| benign_night | 223,108 | f9c033abaf07289999f4c1300f09b00a48624aecd2a63ef0a5ec7632abf2c799 | /mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/benign_flows_tagged.csv |
| DDoS-SYN_Flood | 6,800,503 | 7fa59d2e1a8a5d3ab4df1d7812a7e323ac41f41f605807c3fa57a236c586d6be | /home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood/DDoS-SYN_Flood_labelled.csv.gz |
| DDoS-SYN_Flood5 | 5,297,297 | 6861e9a9152a5de1e9ced3bfd27c86c24a09bb9bd20f5152b040952d929f906c | /home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood5/DDoS-SYN_Flood5_labelled.csv.gz |
| DDoS-SYN_Flood10 | 6,099,055 | 2586a753d5e10b7cfb23c668a78957b55a5189a5c7a245d3a1db0ebe293d6cde | /home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood10/DDoS-SYN_Flood10_labelled.csv.gz |
| DDoS-SYN_Flood15 | 3,104,718 | 72d028090c31d21e12bc6ae6cbc532af2843dd37f9975029f68467ff0d180f04 | /home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood15/DDoS-SYN_Flood15_labelled.csv.gz |
| Recon-PortScan | 207,429 | b1a085a10adf2c3dfeb74f8179441aab4a061d729252c690760cb9a7ea3e8741 | /home/krithikk/lgids_cache/flows/attack/Recon-PortScan/Recon-PortScan_labelled.csv.gz |
| Mirai-udpplain | 8,806 | 036b76645b3603b0fb89fc6217f50b822602acb9697b2b11bfd8f5fb81a009b4 | /home/krithikk/lgids_cache/flows/attack/Mirai-udpplain/Mirai-udpplain_labelled.csv.gz |
| Mirai-udpplain24 | 6,251 | b5fa27a8f1efd5e823bc0a5cd41398f9f7af7744f837326259f2d817ff4b71bc | /home/krithikk/lgids_cache/flows/attack/Mirai-udpplain24/Mirai-udpplain24_labelled.csv.gz |

## Filter drops

| session | rows | not_owned | exclude_reason | label_excluded | ungrouped | owner_device_name_mismatch |
|---|---|---|---|---|---|---|
| benign_night | 223,108 | 13,162 | 5,102 | 0 | 0 | 0 |
| DDoS-SYN_Flood | 6,800,503 | 2,040 | 0 | 15,529 | 0 | 0 |
| DDoS-SYN_Flood5 | 5,297,297 | 1,223 | 0 | 3 | 0 | 0 |
| DDoS-SYN_Flood10 | 6,099,055 | 1,765 | 0 | 13,401 | 0 | 0 |
| DDoS-SYN_Flood15 | 3,104,718 | 1,417 | 86 | 660 | 0 | 0 |
| Recon-PortScan | 207,429 | 9,915 | 0 | 106 | 0 | 0 |
| Mirai-udpplain | 8,806 | 1,460 | 0 | 29 | 0 | 0 |
| Mirai-udpplain24 | 6,251 | 832 | 0 | 83 | 0 | 0 |
