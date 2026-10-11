# Step 7 -- attack labels: Mirai-udpplain (udp_flood)

- pcap `/home/krithikk/lgids_cache/ciciot2023/attack/Mirai-udpplain/Mirai-udpplain.pcap`; run 2026-10-11T15:13:53+00:00; runtime 20.4 s; peak RSS python 2,133.2 MB, largest child 6,473.9 MB
- flows `/home/krithikk/lgids_cache/flows/attack/Mirai-udpplain/Mirai-udpplain.pcap_Flow__singlepkt.csv` (extracted); 03b **WARN**
- map `/home/krithikk/lgids_cache/maps/Mirai-udpplain_ip_mac_map.csv` (reused, 90 rows, 0 overlapping IP conflicts); conflict resolution {'conflicts': 0, 'ambiguous_on_conflict_ips': 0, 'prescan_seconds': 0.0, 'udp_flow_keys': 5118}
- 07a stats `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage/Mirai-udpplain_stats.json`; pad ±60 s; K 10
- labelled CSV `/home/krithikk/lgids_cache/flows/attack/Mirai-udpplain/Mirai-udpplain_labelled.csv.gz`; timeline `Mirai-udpplain_timeline.png`
- spoof: collision IPs none (07a: 0 device-IP collisions, 10 distinct attacker ip.src)

## Hard checks: **PASS**

| check | value | result |
|---|---|---|
| attack flows outside 07a burst windows (+pad) | 0 | PASS |
| attack flows whose victim is not a 07a victim | 0 | PASS |
| flows without exactly one outcome | 0 | PASS |
| rows written == flow CSV rows == meta row_count | 8,806 / 8,806 | PASS |
| label counts sum to rows | 8,806 | PASS |

## Attacker IP set (T1b): 14 IPs (14 LAN, 0 external / other; 14 unicast used for T1b) from 3,563,700 attacker-MAC packets

| ip | scope | used_for_T1b | attacker_macs | packets | resolves_to_attacker | non_attacker_host_overlaps | map_macs | first_utc | last_utc |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.150 | LAN | True | dc:a6:32:c9:e4:d5 | 753,040 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:51:19.282503+00:00 | 2023-01-19T16:23:26.541028+00:00 |
| 192.168.137.238 | LAN | True | dc:a6:32:c9:e4:90 | 658,375 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:51:17.098022+00:00 | 2023-01-19T16:23:26.574506+00:00 |
| 192.168.137.162 | LAN | True | dc:a6:32:c9:e5:a4 | 644,118 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:51:04.794441+00:00 | 2023-01-19T16:23:22.263052+00:00 |
| 192.168.137.147 | LAN | True | dc:a6:32:dc:27:d5 | 441,943 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2023-01-19T15:51:19.368647+00:00 | 2023-01-19T16:23:25.859447+00:00 |
| 192.168.137.207 | LAN | True | dc:a6:32:c9:e4:ab | 392,816 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:51:17.150112+00:00 | 2023-01-19T16:23:26.408403+00:00 |
| 192.168.137.106 | LAN | True | dc:a6:32:c9:e5:ef | 371,764 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:51:31.852521+00:00 | 2023-01-19T16:23:07.589819+00:00 |
| 192.168.137.128 | LAN | True | e4:5f:01:55:90:c4 | 296,399 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2023-01-19T15:51:35.717281+00:00 | 2023-01-19T16:23:25.620523+00:00 |
| fe80::7751:923:3c0f:1915 | LAN | True | dc:a6:32:c9:e4:c6 | 40 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:56:18.940761+00:00 | 2023-01-19T16:17:38.582572+00:00 |
| 192.168.137.13 | LAN | True | dc:a6:32:c9:e6:f4 | 24 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:53:18.859183+00:00 | 2023-01-19T15:55:20.936336+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e4ab | LAN | True | dc:a6:32:c9:e4:ab | 1 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:53:46.959048+00:00 | 2023-01-19T15:53:46.959048+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e490 | LAN | True | dc:a6:32:c9:e4:90 | 1 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2023-01-19T15:54:58.599034+00:00 | 2023-01-19T15:54:58.599034+00:00 |
| 192.168.137.11 | LAN | True | dc:a6:32:c9:e5:02 | 1 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2023-01-19T16:09:20.550628+00:00 | 2023-01-19T16:09:20.550628+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e502 | LAN | True | dc:a6:32:c9:e5:02 | 1 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2023-01-19T16:11:50.406074+00:00 | 2023-01-19T16:11:50.406074+00:00 |
| 192.168.137.236 | LAN | True | dc:a6:32:c9:e4:c6 | 1 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2023-01-19T16:18:35.010887+00:00 | 2023-01-19T16:18:35.010887+00:00 |

### Flows passing T1 only via T1b: 0

| outcome | without_T1b | with_T1b |
|---|---|---|
| attack | 112 | 112 |
| benign | 8,636 | 8,636 |
| excluded:attack_normal_service_ambiguous | 16 | 16 |
| excluded:attacker_normal_traffic | 17 | 17 |
| excluded:attacker_offwindow | 25 | 25 |
| excluded:spoof_collision | 0 | 0 |
| excluded:victim_ambiguous | 0 | 0 |

## Labels (8,806 flows)

| label | flows | pct |
|---|---|---|
| attack | 112 | 1.272 |
| benign | 8,636 | 98.069 |
| excluded | 58 | 0.659 |

### Excluded by reason

| reason | flows |
|---|---|
| attacker_offwindow | 25 |
| attacker_normal_traffic | 17 |
| victim_ambiguous | 0 |
| attack_normal_service_ambiguous | 16 |
| spoof_collision | 0 |

- attack by family: {'udp_flood': 112}
- pad_only: 6 attack flows (8 flows overall) pass T2 only thanks to the padding
- T4 flow mapping (attacker-MAC flows): {'icmp_error_pseudo_flows': 18, 'attacker_sent_no_packets': 18}
- **gateway-victim attack flows: 0** (unowned; non-iot victims total 0: {'iot': 112})

### By owner group (04 ownership)

| group | attack | benign | excluded |
|---|---|---|---|
| G1 | 112 | 5,590 | 29 |
| G2 | 0 | 1,549 | 0 |
| GEN | 0 | 66 | 0 |
| ungrouped | 0 | 0 | 0 |
| unowned | 0 | 1,431 | 29 |

### 04 exclude_reason x label

| exclude_reason | label | flows |
|---|---|---|
| (blank) | attack | 112 |
| (blank) | benign | 8,610 |
| (blank) | excluded | 58 |
| invalid_parse | benign | 26 |

### Attack flows per victim device

| device | group | role | mac | attack_flows | 07a_reason | 07a_attack_packets |
|---|---|---|---|---|---|---|
| Google Nest Mini Speaker | G1 | iot | cc:f4:11:9c:d0:00 | 42 | both | 344,367 |
| Amazon Alexa Echo Dot 1 | G1 | iot | 1c:fe:2b:98:16:dd | 32 | both | 1,952,092 |
| Amazon Alexa Echo Studio | G1 | iot | 08:7c:39:ce:6e:2a | 21 | both | 1,262,306 |
| Philips Hue Bridge | G1 | iot | 00:17:88:60:d6:4f | 16 | both | 132 |
| Amazon Echo Show | G1 | iot | 2c:71:ff:05:f1:15 | 1 | both | 8 |

### Attack flows per 07a burst window

| window | start | end | 07a_packets | attack_flows |
|---|---|---|---|---|
| 0 | 2023-01-19T15:51:00.000000+00:00 | 2023-01-19T16:02:00.000000+00:00 | 1,954,531 | 52 |
| 1 | 2023-01-19T16:08:00.000000+00:00 | 2023-01-19T16:19:00.000000+00:00 | 1,265,013 | 43 |
| 2 | 2023-01-19T16:22:00.000000+00:00 | 2023-01-19T16:24:00.000000+00:00 | 344,152 | 17 |

## Soft checks

### Victim groups vs 07a coverage

| group | victims_with_attack_flows | 07a_victims | 07a_verdict | verdict | match |
|---|---|---|---|---|---|
| G1 | 5 | 5 | PASS | PASS | ok |
| G2 | 0 | 0 | FAIL | FAIL | ok |
| GEN | 0 | 0 | FAIL | FAIL | ok |

- attack flows / 07a attacker packets: 3.1e-05 (112 / 3,563,700)
- benign flows inside a burst with a 07a victim on one side, by the other side's role: {'iot': 1872, 'external': 1235, 'gateway': 938, 'excluded': 253, 'unknown': 101, 'broadcast': 94, 'unlisted': 54} (external / lan_unmapped here would be spoofed attack traffic that T1 cannot see)

### Benign owned-flow share per device vs the benign capture (largest differences)

| device | group | benign_flows_here | share_here_pct | share_benign_capture_pct | diff_pp |
|---|---|---|---|---|---|
| Fibaro Home Center Lite | G1 | 0 | 0.0 | 48.35 | -48.35 |
| Google Nest Mini Speaker | G1 | 1,257 | 17.45 | 1.85 | 15.59 |
| TP-Link Tapo Camera | G1 | 565 | 7.84 | 1.07 | 6.77 |
| Amazon Alexa Echo Dot 1 | G1 | 452 | 6.27 | 0.75 | 5.52 |
| Harman Kardon speaker (Ampak) | G1 | 0 | 0.0 | 4.58 | -4.58 |
| AMCREST WiFi Camera | G1 | 377 | 5.23 | 1.16 | 4.07 |
| Wyze Camera | G1 | 591 | 8.2 | 4.58 | 3.63 |
| Home Eye Camera | G1 | 523 | 7.26 | 10.36 | -3.11 |
| Teckin Light Strip | G2 | 190 | 2.64 | 0.3 | 2.34 |
| Yi Indoor 2 Camera | G1 | 60 | 0.83 | 2.86 | -2.03 |
| LG Smart TV | G1 | 0 | 0.0 | 2.03 | -2.03 |
| Amazon Echo Show | G1 | 321 | 4.46 | 2.5 | 1.96 |
| Amazon Smart Plug | G2 | 151 | 2.1 | 0.15 | 1.95 |
| Aeotec Smart Home Hub | G1 | 178 | 2.47 | 1.01 | 1.47 |
| HeimVision SmartLife Radio/Lamp | G2 | 112 | 1.55 | 0.29 | 1.26 |

### Per-attacker-MAC burst windows used for T2 (07a, anchored)

- dc:a6:32:c9:e4:90: 15:51:00-15:56:00 (2023-01-19); 15:59:00-16:02:00 (2023-01-19); 16:08:00-16:14:00 (2023-01-19); 16:22:00-16:24:00 (2023-01-19)
- dc:a6:32:c9:e4:ab: 15:51:00-16:01:00 (2023-01-19); 16:08:00-16:14:00 (2023-01-19); 16:22:00-16:24:00 (2023-01-19)
- dc:a6:32:c9:e4:d5: 15:51:00-16:02:00 (2023-01-19); 16:08:00-16:14:00 (2023-01-19); 16:22:00-16:24:00 (2023-01-19)
- dc:a6:32:c9:e5:a4: 15:51:00-15:56:00 (2023-01-19); 15:59:00-16:02:00 (2023-01-19); 16:08:00-16:15:00 (2023-01-19); 16:22:00-16:24:00 (2023-01-19)
- dc:a6:32:c9:e5:ef: 15:51:00-15:56:00 (2023-01-19); 15:59:00-16:02:00 (2023-01-19); 16:08:00-16:14:00 (2023-01-19); 16:22:00-16:24:00 (2023-01-19)
- dc:a6:32:dc:27:d5: 15:51:00-16:02:00 (2023-01-19); 16:08:00-16:15:00 (2023-01-19); 16:22:00-16:24:00 (2023-01-19)
- e4:5f:01:55:90:c4: 15:51:00-15:57:00 (2023-01-19); 16:00:00-16:02:00 (2023-01-19); 16:08:00-16:14:00 (2023-01-19); 16:22:00-16:24:00 (2023-01-19)
