# Step 12c -- Protocol-0 traffic and the GRE flood (EXPLORATORY -- not part of the pre-registered evaluation)

**EXPLORATORY -- not part of the pre-registered evaluation.** No training, no threshold change; frozen Step 10 models loaded read-only; test.parquet never opened. Greeth: only the base-part pilot outputs of 12b.

- run 2026-10-20T16:30:07+00:00, git HEAD `e3718cde3f206bd7e0dce3a9ac958c9f56dd32ca`, 12c_proto0_analysis.py sha256 `70c9e3acef57379e...`, runtime 203 s
- input checks: PASS train.parquet sha256 == prereg; PASS val.parquet sha256 == prereg; PASS model G1 sha256 == prereg; PASS model G2 sha256 == prereg; PASS model GLOBAL sha256 == prereg; PASS features_v1.json file sha256 == prereg; PASS behaviour_k2.json sha256 == prereg; PASS xgboost version == prereg; PASS pilot pcap sidecar sha256 == config/sha256_greeth.txt (base part); PASS 12b packets.json keyed to the base part; PASS pilot flow CSV extracted from the base part with the locked jar

## Answers (proposal -- you decide)

- **Q1 frozen models vs the GRE flood:** FINAL @ T_house: flood 0/52 flows (0.0 %), GRE streams 0/50, packets in flagged flows 0.0 %; FINAL @ 0.5: flood 0/52 flows (0.0 %), GRE streams 0/50, packets in flagged flows 0.0 %; BASELINE @ T_house: flood 0/52 flows (0.0 %), GRE streams 0/50, packets in flagged flows 0.0 %; BASELINE @ 0.5: flood 0/52 flows (0.0 %), GRE streams 0/50, packets in flagged flows 0.0 %
- **Q2 benign Protocol 0 vs the flood:** benign Protocol-0 rows: train 1,979 (1.44 % of benign), val 489 (1.25 % of benign); Flow Packets/s: benign max 6,535.9, p99.9 3,413.1 vs flood min 0.9 / median 636.9 (GRE-stream min 168.9); Total Fwd Packet: benign max 141.0, p99.9 137.0 vs flood min 2.0 / median 57,265.5 (GRE-stream min 1,389.0)
- **Q3 one-feature rate rule:** Flow Packets/s > 6535.95: detects 0/52 flood flows (0.0 %), GRE streams 0 (0.0 %); AUC 0.9846; margin min / benign max: all flood 0.000, GRE streams 0.026; hits on the pilot's non-attacker Protocol-0 flows 0/130 (of which non-IPv4 artefacts 0/16); Total Fwd Packet > 141: detects 50/52 flood flows (96.2 %), GRE streams 50 (100.0 %); AUC 0.9774; margin min / benign max: all flood 0.014, GRE streams 9.851; hits on the pilot's non-attacker Protocol-0 flows 9/130 (of which non-IPv4 artefacts 9/16)

## 1. Benign Protocol-0 inventory (train / val)

| split | proto0_rows | benign_rows | pct_of_key_benign |
|---|---|---|---|
| train | 1,979 | 137,462 | 1.44 |
| val | 489 | 39,185 | 1.25 |

Protocol-0 ATTACK rows (train / val):

_none_

### by device_category

| split | key | proto0_rows | benign_rows | pct_of_key_benign | pct_of_split_proto0_benign |
|---|---|---|---|---|---|
| train | Audio | 786 | 29,037 | 2.71 | 39.72 |
| train | Camera | 637 | 53,399 | 1.19 | 32.19 |
| train | Hub | 303 | 30,696 | 0.99 | 15.31 |
| train | Home Automation | 120 | 5,889 | 2.04 | 6.06 |
| train | Power Outlet | 71 | 10,741 | 0.66 | 3.59 |
| train | Unidentified (Espressif) | 38 | 2,447 | 1.55 | 1.92 |
| train | Lighting | 17 | 3,424 | 0.50 | 0.86 |
| train | Unidentified (Amazon) | 7 | 1,829 | 0.38 | 0.35 |
| val | Audio | 168 | 5,905 | 2.85 | 34.36 |
| val | Camera | 152 | 10,131 | 1.50 | 31.08 |
| val | Hub | 79 | 17,049 | 0.46 | 16.16 |
| val | Home Automation | 58 | 1,883 | 3.08 | 11.86 |
| val | Power Outlet | 19 | 2,748 | 0.69 | 3.89 |
| val | Lighting | 7 | 600 | 1.17 | 1.43 |
| val | Unidentified (Espressif) | 6 | 488 | 1.23 | 1.23 |

### by group

| split | key | proto0_rows | benign_rows | pct_of_key_benign | pct_of_split_proto0_benign |
|---|---|---|---|---|---|
| train | G1 | 1,820 | 120,028 | 1.52 | 91.97 |
| train | G2 | 140 | 16,279 | 0.86 | 7.07 |
| train | GEN | 19 | 1,155 | 1.65 | 0.96 |
| val | G1 | 447 | 35,833 | 1.25 | 91.41 |
| val | G2 | 37 | 3,061 | 1.21 | 7.57 |
| val | GEN | 5 | 291 | 1.72 | 1.02 |

### by session

| split | key | proto0_rows | benign_rows | pct_of_key_benign | pct_of_split_proto0_benign |
|---|---|---|---|---|---|
| train | benign_night | 1,298 | 85,836 | 1.51 | 65.59 |
| train | Recon-PortScan | 284 | 21,643 | 1.31 | 14.35 |
| train | DDoS-SYN_Flood | 164 | 16,799 | 0.98 | 8.29 |
| train | Mirai-udpplain | 119 | 6,625 | 1.80 | 6.01 |
| train | DDoS-SYN_Flood5 | 114 | 6,559 | 1.74 | 5.76 |
| val | benign_night | 376 | 24,686 | 1.52 | 76.89 |
| val | Recon-PortScan | 81 | 10,349 | 0.78 | 16.56 |
| val | DDoS-SYN_Flood | 16 | 2,439 | 0.66 | 3.27 |
| val | DDoS-SYN_Flood5 | 8 | 1,131 | 0.71 | 1.64 |
| val | Mirai-udpplain | 8 | 580 | 1.38 | 1.64 |

### by device

| split | key | proto0_rows | benign_rows | pct_of_key_benign | pct_of_split_proto0_benign |
|---|---|---|---|---|---|
| train | Google Nest Mini Speaker | 457 | 6,171 | 7.41 | 23.09 |
| train | Wyze Camera | 298 | 11,780 | 2.53 | 15.06 |
| train | Philips Hue Bridge | 273 | 2,444 | 11.17 | 13.79 |
| train | Netatmo Camera | 255 | 1,516 | 16.82 | 12.89 |
| train | Amazon Alexa Echo Dot 1 | 115 | 2,838 | 4.05 | 5.81 |
| train | Amazon Alexa Echo Studio | 108 | 3,457 | 3.12 | 5.46 |
| train | Amazon Echo Show | 104 | 5,212 | 2.00 | 5.26 |
| train | LG Smart TV | 91 | 2,409 | 3.78 | 4.60 |
| train | Rbcior Camera | 31 | 1,668 | 1.86 | 1.57 |
| train | Arlo Q Indoor Camera | 29 | 2,449 | 1.18 | 1.47 |
| train | Fibaro Home Center Lite | 22 | 20,047 | 0.11 | 1.11 |
| train | Unidentified ESP plug (2) | 13 | 611 | 2.13 | 0.66 |
| train | TP-Link Tapo Camera | 12 | 3,836 | 0.31 | 0.61 |
| train | Unidentified ESP plug (1) | 12 | 610 | 1.97 | 0.61 |
| train | Smart Board | 11 | 868 | 1.27 | 0.56 |
| train | Nest Indoor Camera | 11 | 462 | 2.38 | 0.56 |
| train | GoSund Smart Plug WP2 (1) | 11 | 611 | 1.80 | 0.56 |
| train | Unidentified ESP plug (4) | 10 | 616 | 1.62 | 0.51 |
| train | LampUX RGB | 9 | 603 | 1.49 | 0.45 |
| train | Yutron Plug 1 | 8 | 632 | 1.27 | 0.40 |
| train | Wemo Smart Plug 1 | 8 | 210 | 3.81 | 0.40 |
| train | Aeotec Smart Home Hub | 7 | 2,223 | 0.31 | 0.35 |
| train | Unidentified Amazon device (1c:12:b0) | 7 | 1,829 | 0.38 | 0.35 |
| train | Levoit Air Purifier | 7 | 410 | 1.71 | 0.35 |
| train | Atomi Coffee Maker | 7 | 628 | 1.11 | 0.35 |
| train | Wemo Smart Plug 2 | 7 | 4,890 | 0.14 | 0.35 |
| train | Yutron Plug 2 | 7 | 630 | 1.11 | 0.35 |
| train | Teckin Plug 1 | 6 | 624 | 0.96 | 0.30 |
| train | Teckin Plug 2 | 6 | 627 | 0.96 | 0.30 |
| train | Lumiman Bulb | 5 | 917 | 0.55 | 0.25 |
| train | GoSund Smart Plug WP2 (2) | 5 | 622 | 0.80 | 0.25 |
| train | Amazon Smart Plug | 5 | 692 | 0.72 | 0.25 |
| train | GoSund Power Strip (1) | 4 | 613 | 0.65 | 0.20 |
| train | GoSund Power Strip (2) | 4 | 590 | 0.68 | 0.20 |
| train | Unidentified ESP plug (3) | 3 | 610 | 0.49 | 0.15 |
| train | Cocoon Smart HVAC Fan | 2 | 627 | 0.32 | 0.10 |
| train | Govee Smart Humidifier | 2 | 435 | 0.46 | 0.10 |
| train | Amazon Alexa Echo Dot 2 | 2 | 1,254 | 0.16 | 0.10 |
| train | Teckin Light Strip | 2 | 981 | 0.20 | 0.10 |
| train | Yi Outdoor Camera | 1 | 1,145 | 0.09 | 0.05 |

### Distributions

| population | feature | n | min | p50 | p90 | p99 | p99.9 | max |
|---|---|---|---|---|---|---|---|---|
| benign Protocol 0, train | Total Fwd Packet | 1,979 | 1.0 | 6.0 | 20.0 | 104.7 | 137.0 | 141.0 |
| benign Protocol 0, train | Flow Duration | 1,979 | 0.0 | 72,227,520.0 | 109,929,545.6 | 119,997,032.3 | 119,999,597.1 | 119,999,976.0 |
| benign Protocol 0, train | Flow Packets/s | 1,979 | 0.0 | 0.2 | 6.4 | 50.1 | 175.2 | 302.6 |
| benign Protocol 0, train | Fwd Packets/s | 1,979 | 0.0 | 0.2 | 4.7 | 50.0 | 151.8 | 224.5 |
| benign Protocol 0, val | Total Fwd Packet | 489 | 1.0 | 5.0 | 12.2 | 20.0 | 38.3 | 49.0 |
| benign Protocol 0, val | Flow Duration | 489 | 0.0 | 10,027,061.0 | 109,805,902.4 | 119,997,731.5 | 119,999,254.1 | 119,999,504.0 |
| benign Protocol 0, val | Flow Packets/s | 489 | 0.0 | 0.5 | 22.2 | 1,612.1 | 6,535.9 | 6,535.9 |
| benign Protocol 0, val | Fwd Packets/s | 489 | 0.0 | 0.5 | 14.3 | 846.7 | 3,268.0 | 3,268.0 |
| benign Protocol 0, train + val | Total Fwd Packet | 2,468 | 1.0 | 6.0 | 20.0 | 54.3 | 137.0 | 141.0 |
| benign Protocol 0, train + val | Flow Duration | 2,468 | 0.0 | 72,205,232.0 | 109,902,339.2 | 119,997,234.6 | 119,999,550.9 | 119,999,976.0 |
| benign Protocol 0, train + val | Flow Packets/s | 2,468 | 0.0 | 0.2 | 7.4 | 88.5 | 3,413.1 | 6,535.9 |
| benign Protocol 0, train + val | Fwd Packets/s | 2,468 | 0.0 | 0.2 | 5.9 | 73.1 | 1,706.6 | 3,268.0 |
| GRE flood flows (52, pilot) | Total Fwd Packet | 52 | 2.0 | 57,265.5 | 119,422.1 | 157,401.9 | 161,306.2 | 161,740.0 |
| GRE flood flows (52, pilot) | Flow Duration | 52 | 485,457.0 | 115,145,480.0 | 119,980,266.4 | 119,999,963.8 | 119,999,974.8 | 119,999,976.0 |
| GRE flood flows (52, pilot) | Flow Packets/s | 52 | 0.9 | 636.9 | 1,047.9 | 1,329.1 | 1,347.5 | 1,349.6 |
| GRE flood flows (52, pilot) | Fwd Packets/s | 52 | 0.9 | 636.7 | 1,047.9 | 1,329.0 | 1,347.5 | 1,349.6 |
| GRE flood, GRE streams only | Total Fwd Packet | 50 | 1,389.0 | 60,199.0 | 119,828.0 | 157,572.1 | 161,323.2 | 161,740.0 |
| GRE flood, GRE streams only | Flow Duration | 50 | 1,342,587.0 | 117,249,524.0 | 119,981,078.4 | 119,999,964.2 | 119,999,974.8 | 119,999,976.0 |
| GRE flood, GRE streams only | Flow Packets/s | 50 | 168.9 | 648.7 | 1,053.7 | 1,329.9 | 1,347.6 | 1,349.6 |
| GRE flood, GRE streams only | Fwd Packets/s | 50 | 168.9 | 648.7 | 1,053.7 | 1,329.8 | 1,347.6 | 1,349.6 |
| pilot non-attacker Protocol 0 | Total Fwd Packet | 130 | 1.0 | 4.0 | 102.1 | 1,231.2 | 1,845.0 | 1,935.0 |
| pilot non-attacker Protocol 0 | Flow Duration | 130 | 0.0 | 16,011,439.0 | 116,493,079.2 | 119,936,537.3 | 119,988,526.5 | 119,991,864.0 |
| pilot non-attacker Protocol 0 | Flow Packets/s | 130 | 0.0 | 1.0 | 44.9 | 362.8 | 761.5 | 816.0 |
| pilot non-attacker Protocol 0 | Fwd Packets/s | 130 | 0.0 | 0.9 | 22.5 | 181.4 | 380.8 | 408.0 |

Flow Duration in microseconds; rates per second; 1-packet flows have Flow Packets/s = 0 after 08's NaN / inf -> 0 cleaning (pilot rows cleaned the same way).

## 2. What benign Protocol 0 is (one benign train capture, packets)

`BenignTraffic.pcap` (session benign_night, sha256 `549a89337f529412...`), packets before the train / val cut 2022-10-07T23:43:50+00:00 only: 36,287 non-TCP/UDP IPv4 packets of 2,395,158 IPv4 (1.515 %); lean tshark, 137.7 s.

| ip_proto | name | packets | pct_of_non_tcp_udp |
|---|---|---|---|
| 1 | ICMP | 35,567 | 98.02 |
| 2 | IGMP | 720 | 1.98 |

Top senders (ip.proto, source MAC):

| ip_proto | name | device | class | src_mac | packets |
|---|---|---|---|---|---|
| 1 | ICMP | Yi Indoor 2 Camera | G1 | 84:7a:b6:62:3a:6c | 19,754 |
| 1 | ICMP | Google Nest Mini Speaker | G1 | cc:f4:11:9c:d0:00 | 3,960 |
| 1 | ICMP | Gateway / router | gateway | 3c:18:a0:41:c3:a0 | 3,156 |
| 1 | ICMP | attacker (testbed Pi) | attacker | dc:a6:32:dc:27:d5 | 1,921 |
| 1 | ICMP | Wyze Camera | G1 | 7c:78:b2:86:0d:81 | 1,073 |
| 1 | ICMP | Randomised MAC (phone/laptop) | excluded | 56:4f:8a:e1:f3:2d | 1,024 |
| 1 | ICMP | Amazon Echo Show | G1 | 2c:71:ff:05:f1:15 | 755 |
| 1 | ICMP | Amazon Alexa Echo Studio | G1 | 08:7c:39:ce:6e:2a | 750 |
| 1 | ICMP | Amazon Alexa Echo Dot 1 | G1 | 1c:fe:2b:98:16:dd | 750 |
| 1 | ICMP | LG Smart TV | G1 | ac:f1:08:4e:00:82 | 581 |
| 1 | ICMP | Unknown | unknown | 24:05:88:30:6f:89 | 519 |
| 1 | ICMP | Unknown | unknown | e8:1b:69:f8:d4:e3 | 492 |
| 2 | IGMP | Philips Hue Bridge | G1 | 00:17:88:60:d6:4f | 388 |
| 1 | ICMP | Yi Indoor Camera | G1 | 84:7a:b6:64:62:58 | 325 |
| 2 | IGMP | Randomised MAC (phone/laptop) | excluded | 56:4f:8a:e1:f3:2d | 313 |
| 1 | ICMP | AMCREST WiFi Camera | G1 | 9c:8e:cd:1d:ab:9f | 168 |
| 1 | ICMP | Arlo Base Station | G1 | 3c:37:86:6f:b9:51 | 153 |
| 1 | ICMP | Fibaro Home Center Lite | G1 | ac:17:02:05:34:27 | 78 |
| 1 | ICMP | Yi Outdoor Camera | G1 | 2c:d2:6b:66:d2:87 | 59 |
| 1 | ICMP | Rbcior Camera | G1 | 10:5a:17:97:a5:c6 | 33 |
| 2 | IGMP | Aeotec Smart Home Hub | G1 | 28:6d:97:9e:f4:d5 | 9 |
| 2 | IGMP | LG Smart TV | G1 | ac:f1:08:4e:00:82 | 6 |
| 1 | ICMP | Aeotec Smart Home Hub | G1 | 28:6d:97:9e:f4:d5 | 4 |
| 1 | ICMP | Cocoon Smart HVAC Fan | G2 | 08:3a:f2:1f:bc:68 | 3 |
| 2 | IGMP | Netatmo Camera | G1 | 70:ee:50:68:0e:32 | 2 |

## 3. GRE flood (12b pilot, base part) vs benign Protocol 0 (train + val)

Pilot flows: other 5,604, non_attacker_proto0 130, attacker_tcp_udp_side 100, flood 52. Flood = attacker flows (12b rule) that are not TCP / UDP; GRE streams = (attacker IP, victim IP) pairs that carried outer ip.proto 47 (50 of the flood flows).

### Single-feature ROC-AUC (09b method) and zero-benign-FP threshold, features that vary on the flood

| feature | auc | auc_train | auc_val | direction | flag | benign_max | benign_p99_9 | flood_min | flood_gre_min | flood_median | zero_fp_rule | zero_fp_detected | zero_fp_detected_gre | zero_fp_rule_hits_pilot_non_attacker_p0 | of_which_non_ipv4_artifact |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Fwd Packets/s | 0.9863 | 0.9896 | 0.9729 | flood higher |  | 3,267.9739 | 1,706.5711 | 0.8975 | 168.9236 | 636.6545 | Fwd Packets/s > 3267.97 | 0 | 0 | 0 | 0 |
| Flow Packets/s | 0.9846 | 0.9889 | 0.9672 | flood higher |  | 6,535.9478 | 3,413.1422 | 0.8975 | 168.9236 | 636.9178 | Flow Packets/s > 6535.95 | 0 | 0 | 0 | 0 |
| Total Fwd Packet | 0.9774 | 0.9768 | 0.9800 | flood higher |  | 141.0000 | 137.0000 | 2.0000 | 1,389.0000 | 57,265.5000 | Total Fwd Packet > 141 | 50 | 50 | 9 | 9 |
| Flow IAT Mean | 0.0255 | 0.0226 | 0.0373 | flood lower |  | 97,290,600.0000 | 67,574,935.3000 | 740.9659 | 740.9659 | 1,570.4139 | Flow IAT Mean < 0 | 0 | 0 | 0 | 0 |
| Flow IAT Min | 0.0377 | 0.0395 | 0.0302 | flood lower |  | 97,290,600.0000 | 54,629,299.2840 | 0.0000 | 0.0000 | 0.0000 | Flow IAT Min < 0 | 0 | 0 | 0 | 0 |
| Subflow Fwd Packets | 0.9558 | 0.9551 | 0.9590 | flood higher |  | 25.0000 | 14.0660 | 0.0000 | 0.0000 | 4,410.5000 | Subflow Fwd Packets > 25 | 49 | 49 | 5 | 5 |
| Fwd IAT Min | 0.0500 | 0.0417 | 0.0836 | flood lower |  | 97,290,600.0000 | 70,027,977.9560 | 0.0000 | 0.0000 | 0.0000 | Fwd IAT Min < 0 | 0 | 0 | 0 | 0 |
| Fwd IAT Mean | 0.0594 | 0.0399 | 0.1380 | flood lower |  | 97,290,600.0000 | 70,027,977.9560 | 740.9659 | 740.9659 | 1,571.0822 | Fwd IAT Mean < 0 | 0 | 0 | 0 | 0 |
| Fwd IAT Total | 0.7748 | 0.7716 | 0.7877 | flood higher |  | 119,999,976.0000 | 119,999,550.9040 | 485,457.0000 | 1,342,587.0000 | 115,145,480.0000 | Fwd IAT Total > 1.2e+08 | 0 | 0 | 0 | 0 |
| Flow Duration | 0.7736 | 0.7701 | 0.7876 | flood higher |  | 119,999,976.0000 | 119,999,550.9040 | 485,457.0000 | 1,342,587.0000 | 115,145,480.0000 | Flow Duration > 1.2e+08 | 0 | 0 | 0 | 0 |
| Active Mean | 0.7333 | 0.7302 | 0.7456 | flood higher |  | 23,642,010.0000 | 17,078,886.7460 | 0.0000 | 0.0000 | 27,727,342.0000 | Active Mean > 2.3642e+07 | 28 | 28 | 1 | 1 |
| Active Max | 0.7331 | 0.7300 | 0.7455 | flood higher |  | 25,402,870.0000 | 19,797,115.1360 | 0.0000 | 0.0000 | 31,332,554.0000 | Active Max > 2.54029e+07 | 28 | 28 | 5 | 2 |
| Active Min | 0.7270 | 0.7237 | 0.7404 | flood higher |  | 23,642,010.0000 | 17,078,886.7460 | 0.0000 | 0.0000 | 11,970,463.5000 | Active Min > 2.3642e+07 | 24 | 24 | 1 | 1 |
| Flow IAT Std | 0.3562 | 0.3426 | 0.4112 | flood lower |  | 63,868,968.0000 | 54,650,820.0000 | 0.0000 | 15,736.6973 | 41,033.2910 | Flow IAT Std < 0 | 0 | 0 | 0 | 0 |
| Fwd IAT Std | 0.3856 | 0.3676 | 0.4588 | flood lower |  | 78,248,696.0000 | 63,547,709.1960 | 0.0000 | 15,736.6973 | 44,806.0527 | Fwd IAT Std < 0 | 0 | 0 | 0 | 0 |
| Idle Max | 0.4152 | 0.4071 | 0.4482 | flood lower |  | 113,240,608.0000 | 110,949,903.2960 | 0.0000 | 0.0000 | 7,091,273.0000 | Idle Max < 0 | 0 | 0 | 0 | 0 |
| Idle Mean | 0.4300 | 0.4217 | 0.4636 | flood lower |  | 113,240,608.0000 | 110,949,903.2960 | 0.0000 | 0.0000 | 7,091,273.0000 | Idle Mean < 0 | 0 | 0 | 0 | 0 |
| Active Std | 0.5579 | 0.5566 | 0.5629 | flood higher |  | 8,956,260.0000 | 7,722,650.0225 | 0.0000 | 0.0000 | 0.0000 | Active Std > 8.95626e+06 | 4 | 4 | 6 | 3 |
| Idle Min | 0.4452 | 0.4374 | 0.4766 | flood lower |  | 113,240,608.0000 | 110,949,903.2960 | 0.0000 | 0.0000 | 6,304,709.0000 | Idle Min < 0 | 0 | 0 | 0 | 0 |
| Idle Std | 0.4646 | 0.4653 | 0.4616 | flood lower |  | 58,751,572.0000 | 49,686,085.3880 | 0.0000 | 0.0000 | 0.0000 | Idle Std < 0 | 0 | 0 | 0 | 0 |
| Subflow Bwd Packets | 0.5277 | 0.5230 | 0.5463 | flood higher |  | 14.0000 | 10.0000 | 0.0000 | 0.0000 | 0.0000 | Subflow Bwd Packets > 14 | 0 | 0 | 0 | 0 |
| Total Bwd packets | 0.5256 | 0.5288 | 0.5130 | flood higher |  | 141.0000 | 135.5330 | 0.0000 | 0.0000 | 0.0000 | Total Bwd packets > 141 | 0 | 0 | 0 | 0 |
| Bwd IAT Min | 0.4836 | 0.4792 | 0.5011 | flood lower |  | 60,009,728.0000 | 34,383,213.4000 | 0.0000 | 0.0000 | 0.0000 | Bwd IAT Min < 0 | 0 | 0 | 0 | 0 |
| Flow IAT Max | 0.4860 | 0.4747 | 0.5319 | flood lower |  | 113,240,608.0000 | 110,949,903.2960 | 485,457.0000 | 537,296.0000 | 7,091,273.0000 | Flow IAT Max < 0 | 0 | 0 | 0 | 0 |
| Bwd IAT Total | 0.5126 | 0.5074 | 0.5337 | flood higher |  | 119,980,000.0000 | 118,201,388.3680 | 0.0000 | 0.0000 | 0.0000 | Bwd IAT Total > 1.1998e+08 | 0 | 0 | 0 | 0 |
| Bwd IAT Std | 0.5115 | 0.5058 | 0.5345 | flood higher |  | 76,640,480.0000 | 76,593,516.4800 | 0.0000 | 0.0000 | 0.0000 | Bwd IAT Std > 7.66405e+07 | 0 | 0 | 0 | 0 |
| Fwd IAT Max | 0.4958 | 0.4862 | 0.5346 | flood lower |  | 113,240,608.0000 | 110,966,988.0240 | 485,457.0000 | 537,296.0000 | 7,503,371.5000 | Fwd IAT Max < 0 | 0 | 0 | 0 | 0 |
| Bwd Packets/s | 0.5022 | 0.5115 | 0.4645 | flood higher |  | 3,267.9739 | 1,706.5711 | 0.0000 | 0.0000 | 0.0000 | Bwd Packets/s > 3267.97 | 0 | 0 | 0 | 0 |
| Bwd IAT Mean | 0.4978 | 0.4922 | 0.5208 | flood lower |  | 60,009,728.0000 | 54,688,976.7440 | 0.0000 | 0.0000 | 0.0000 | Bwd IAT Mean < 0 | 0 | 0 | 0 | 0 |
| Bwd IAT Max | 0.5013 | 0.4960 | 0.5229 | flood higher |  | 108,847,064.0000 | 108,838,398.0480 | 0.0000 | 0.0000 | 0.0000 | Bwd IAT Max > 1.08847e+08 | 0 | 0 | 0 | 0 |

zero_fp_rule_hits_pilot_non_attacker_p0 = the rule's hits on the pilot capture's non-attacker Protocol-0 flows (same capture as the flood, not in train / val); of_which_non_ipv4_artifact = hits on pseudo-flows whose two addresses never appear as an IPv4 address in the capture: CICFlowMeter reads non-IPv4 frames as IPv4 (ARP gives '8.6.0.1 -> 8.0.6.4' = the ARP header bytes 08 06 00 01 / 08 00 06 04; a spot check of 15:34-15:36 UTC found ARP to be almost all non-IP frames there).


40 features are constant on the flood flows (listed in gre_vs_benign_auc.csv with varies_on_flood = False).

## 4. Frozen Step 10 models on the pilot flows

| population | system | operating_point | threshold | n | flagged | flagged_pct | packets_in_flagged | packets_total | score_median | routed_models |
|---|---|---|---|---|---|---|---|---|---|---|
| flood (attacker, not TCP / UDP) | FINAL | T_house | 0.5683 | 52 | 0 | 0.0000 | 0 | 3,254,938 | 0.1072 | G1 50; GLOBAL 2 |
| flood (attacker, not TCP / UDP) | FINAL | 0.5 | 0.5000 | 52 | 0 | 0.0000 | 0 | 3,254,938 | 0.1072 | G1 50; GLOBAL 2 |
| flood (attacker, not TCP / UDP) | BASELINE | T_house | 0.5928 | 52 | 0 | 0.0000 | 0 | 3,254,938 | 0.2579 | GLOBAL 52 |
| flood (attacker, not TCP / UDP) | BASELINE | 0.5 | 0.5000 | 52 | 0 | 0.0000 | 0 | 3,254,938 | 0.2579 | GLOBAL 52 |
| flood, GRE streams only | FINAL | T_house | 0.5683 | 50 | 0 | 0.0000 | 0 | 3,254,927 | 0.1072 | G1 50 |
| flood, GRE streams only | FINAL | 0.5 | 0.5000 | 50 | 0 | 0.0000 | 0 | 3,254,927 | 0.1072 | G1 50 |
| flood, GRE streams only | BASELINE | T_house | 0.5928 | 50 | 0 | 0.0000 | 0 | 3,254,927 | 0.2579 | GLOBAL 50 |
| flood, GRE streams only | BASELINE | 0.5 | 0.5000 | 50 | 0 | 0.0000 | 0 | 3,254,927 | 0.2579 | GLOBAL 50 |
| flood, not GRE streams | FINAL | T_house | 0.5683 | 2 | 0 | 0.0000 | 0 | 11 | 0.0000 | GLOBAL 2 |
| flood, not GRE streams | FINAL | 0.5 | 0.5000 | 2 | 0 | 0.0000 | 0 | 11 | 0.0000 | GLOBAL 2 |
| flood, not GRE streams | BASELINE | T_house | 0.5928 | 2 | 0 | 0.0000 | 0 | 11 | 0.0000 | GLOBAL 2 |
| flood, not GRE streams | BASELINE | 0.5 | 0.5000 | 2 | 0 | 0.0000 | 0 | 11 | 0.0000 | GLOBAL 2 |
| attacker TCP / UDP side flows | FINAL | T_house | 0.5683 | 100 | 6 | 6.0000 | 37 | 660 | 0.0000 | GLOBAL 55; G1 45 |
| attacker TCP / UDP side flows | FINAL | 0.5 | 0.5000 | 100 | 6 | 6.0000 | 37 | 660 | 0.0000 | GLOBAL 55; G1 45 |
| attacker TCP / UDP side flows | BASELINE | T_house | 0.5928 | 100 | 6 | 6.0000 | 46 | 660 | 0.0000 | GLOBAL 100 |
| attacker TCP / UDP side flows | BASELINE | 0.5 | 0.5000 | 100 | 7 | 7.0000 | 48 | 660 | 0.0000 | GLOBAL 100 |
| non-attacker Protocol-0 flows | FINAL | T_house | 0.5683 | 130 | 0 | 0.0000 | 0 | 11,119 | 0.0000 | G1 64; GLOBAL 39; G2 27 |
| non-attacker Protocol-0 flows | FINAL | 0.5 | 0.5000 | 130 | 0 | 0.0000 | 0 | 11,119 | 0.0000 | G1 64; GLOBAL 39; G2 27 |
| non-attacker Protocol-0 flows | BASELINE | T_house | 0.5928 | 130 | 0 | 0.0000 | 0 | 11,119 | 0.0000 | GLOBAL 130 |
| non-attacker Protocol-0 flows | BASELINE | 0.5 | 0.5000 | 130 | 0 | 0.0000 | 0 | 11,119 | 0.0000 | GLOBAL 130 |
|   of which non-IPv4 artefacts (ARP / LLC read as IPv4) | FINAL | T_house | 0.5683 | 16 | 0 | 0.0000 | 0 | 9,307 | 0.0000 | GLOBAL 16 |
|   of which non-IPv4 artefacts (ARP / LLC read as IPv4) | FINAL | 0.5 | 0.5000 | 16 | 0 | 0.0000 | 0 | 9,307 | 0.0000 | GLOBAL 16 |
|   of which non-IPv4 artefacts (ARP / LLC read as IPv4) | BASELINE | T_house | 0.5928 | 16 | 0 | 0.0000 | 0 | 9,307 | 0.0000 | GLOBAL 16 |
|   of which non-IPv4 artefacts (ARP / LLC read as IPv4) | BASELINE | 0.5 | 0.5000 | 16 | 0 | 0.0000 | 0 | 9,307 | 0.0000 | GLOBAL 16 |

Routing: k2 group of the flow's owner (attacker flows: the non-attacker endpoint; other flows: the source if a registered iot device, else the destination); no iot owner -> GEN -> GLOBAL. Owner IP -> MAC from a lean sender-evidence tshark pass on the pilot base part, then 12b's attacker-destination map.

### The flood flows, scored

| Src IP | Dst IP | gre_stream | owner_device | group | routed_model | Total Fwd Packet | Flow Packets/s | score_FINAL | score_BASELINE |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.150 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 161,740 | 1,349.5981 | 0.0535 | 0.2589 |
| 192.168.137.238 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 153,234 | 1,309.4375 | 0.0573 | 0.2035 |
| 192.168.137.207 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 130,969 | 1,093.0045 | 0.1072 | 0.2579 |
| 192.168.137.238 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 123,075 | 1,028.3895 | 0.1161 | 0.3078 |
| 192.168.137.128 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 121,493 | 1,012.6062 | 0.1072 | 0.2579 |
| 192.168.137.238 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 119,643 | 1,165.8512 | 0.1072 | 0.2579 |
| 192.168.137.238 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 117,434 | 1,111.5820 | 0.0734 | 0.2579 |
| 192.168.137.238 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 108,712 | 1,049.3595 | 0.1072 | 0.2579 |
| 192.168.137.128 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 100,291 | 836.8604 | 0.0680 | 0.2383 |
| 192.168.137.238 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 96,409 | 805.8684 | 0.1404 | 0.2722 |
| 192.168.137.150 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 95,388 | 794.9906 | 0.0535 | 0.2589 |
| 192.168.137.106 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 87,835 | 740.1696 | 0.0535 | 0.2589 |
| 192.168.137.207 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 87,546 | 745.8765 | 0.1144 | 0.2027 |
| 192.168.137.207 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 83,521 | 696.5279 | 0.1516 | 0.3685 |
| 192.168.137.106 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 83,319 | 736.2487 | 0.0573 | 0.2035 |
| 192.168.137.150 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 78,173 | 651.4419 | 0.1516 | 0.3685 |
| 192.168.137.128 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 76,753 | 645.9485 | 0.1270 | 0.3858 |
| 192.168.137.128 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 76,416 | 744.4126 | 0.1072 | 0.2579 |
| 192.168.137.162 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 70,825 | 590.7335 | 0.1144 | 0.2027 |
| 192.168.137.128 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 70,277 | 792.2331 | 0.1072 | 0.2579 |
| 192.168.137.150 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 64,620 | 539.9404 | 0.1404 | 0.2722 |
| 192.168.137.106 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 64,565 | 725.9293 | 0.0535 | 0.2589 |
| 192.168.137.150 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 64,232 | 535.8366 | 0.1613 | 0.3057 |
| 192.168.137.147 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 63,552 | 530.2289 | 0.1072 | 0.2579 |
| 192.168.137.147 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 62,009 | 525.8628 | 0.1516 | 0.3078 |
| 192.168.137.147 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 58,389 | 486.9175 | 0.0573 | 0.2035 |
| 192.168.137.128 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 56,142 | 468.0833 | 0.1404 | 0.2722 |
| 192.168.137.207 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 52,655 | 618.4782 | 0.1404 | 0.2722 |
| 192.168.137.147 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 50,141 | 420.5692 | 0.1516 | 0.3237 |
| 192.168.137.106 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 50,082 | 417.4667 | 0.1404 | 0.2579 |
| 192.168.137.150 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 48,153 | 508.0396 | 0.1404 | 0.2722 |
| 192.168.137.162 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 47,951 | 513.2968 | 0.1072 | 0.2579 |
| 192.168.137.238 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 45,289 | 994.3999 | 0.0671 | 0.2053 |
| 192.168.137.106 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 44,526 | 373.5588 | 0.2525 | 0.3753 |
| 192.168.137.207 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 44,345 | 369.6088 | 0.2525 | 0.3753 |
| 192.168.137.147 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 42,634 | 656.4192 | 0.0638 | 0.2611 |
| 192.168.137.162 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 42,409 | 454.3611 | 0.1404 | 0.2579 |
| 192.168.137.162 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 38,027 | 318.0523 | 0.2525 | 0.3753 |
| 192.168.137.162 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 34,574 | 288.1491 | 0.1404 | 0.3753 |
| 192.168.137.128 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 32,298 | 677.5160 | 0.0770 | 0.2053 |
| 192.168.137.106 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 31,525 | 730.2043 | 0.0525 | 0.2053 |
| 192.168.137.150 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 29,795 | 627.8869 | 0.0684 | 0.2053 |
| 192.168.137.207 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 29,324 | 436.4446 | 0.1646 | 0.2745 |
| 192.168.137.106 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 27,879 | 360.5199 | 0.1646 | 0.2722 |
| 192.168.137.207 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 24,963 | 564.7035 | 0.0809 | 0.2404 |
| 192.168.137.147 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 17,246 | 392.9057 | 0.0671 | 0.2053 |
| 192.168.137.162 | 192.168.137.242 | True | AMCREST WiFi Camera | G1 | G1 | 16,996 | 735.6869 | 0.0684 | 0.2053 |
| 192.168.137.162 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 13,899 | 168.9236 | 0.1404 | 0.0009 |
| 192.168.137.147 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 11,717 | 471.6242 | 0.0638 | 0.2611 |
| 192.168.137.150 | 192.168.137.254 | True | Amazon Alexa Echo Dot 1 | G1 | G1 | 1,389 | 1,034.5698 | 0.0002 | 0.0002 |
| 192.168.137.171 | 192.168.137.11 | False | Unknown | GEN | GLOBAL | 9 | 0.8975 | 0.0000 | 0.0000 |
| 192.168.137.11 | 224.0.0.22 | False | unknown | GEN | GLOBAL | 2 | 4.1198 | 0.0000 | 0.0000 |
