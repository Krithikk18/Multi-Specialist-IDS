# Step 7 -- attack labels: DDoS-SYN_Flood5 (syn_flood)

- pcap `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood5.pcap`; run 2026-10-11T14:51:27+00:00; runtime 1709.4 s; peak RSS python 2,133.2 MB, largest child 6,357.0 MB
- flows `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood5/DDoS-SYN_Flood5.pcap_Flow__singlepkt.csv` (extracted); 03b **WARN**
- map `/home/krithikk/lgids_cache/maps/DDoS-SYN_Flood5_ip_mac_map.csv` (built, 104 rows, 0 overlapping IP conflicts); conflict resolution {'conflicts': 0, 'ambiguous_on_conflict_ips': 0, 'prescan_seconds': 17.1, 'udp_flow_keys': 6602}
- 07a stats `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage/DDoS-SYN_Flood5_stats.json`; pad ±60 s; K 10
- labelled CSV `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood5/DDoS-SYN_Flood5_labelled.csv.gz`; timeline `DDoS-SYN_Flood5_timeline.png`
- spoof: collision IPs none (07a: 0 device-IP collisions, 10 distinct attacker ip.src)

## Hard checks: **PASS**

| check | value | result |
|---|---|---|
| attack flows outside 07a burst windows (+pad) | 0 | PASS |
| attack flows whose victim is not a 07a victim | 0 | PASS |
| flows without exactly one outcome | 0 | PASS |
| rows written == flow CSV rows == meta row_count | 5,297,297 / 5,297,297 | PASS |
| label counts sum to rows | 5,297,297 | PASS |

## Attacker IP set (T1b): 18 IPs (18 LAN, 0 external / other; 18 unicast used for T1b) from 26,604,267 attacker-MAC packets

| ip | scope | used_for_T1b | attacker_macs | packets | resolves_to_attacker | non_attacker_host_overlaps | map_macs | first_utc | last_utc |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.195 | LAN | True | dc:a6:32:c9:e4:90 | 4,322,582 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:20:34.263512+00:00 | 2022-08-29T17:57:10.777458+00:00 |
| 192.168.137.96 | LAN | True | dc:a6:32:c9:e5:a4 | 4,289,280 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:20:34.262862+00:00 | 2022-08-29T17:57:10.666950+00:00 |
| 192.168.137.17 | LAN | True | dc:a6:32:dc:27:d5 | 4,011,184 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-08-29T17:20:34.274603+00:00 | 2022-08-29T17:57:10.759815+00:00 |
| 192.168.137.224 | LAN | True | dc:a6:32:c9:e4:d5 | 3,973,326 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:20:34.273711+00:00 | 2022-08-29T17:57:10.785191+00:00 |
| 192.168.137.240 | LAN | True | dc:a6:32:c9:e4:ab | 3,784,680 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:20:34.292395+00:00 | 2022-08-29T17:57:10.776361+00:00 |
| 192.168.137.58 | LAN | True | dc:a6:32:c9:e5:ef | 3,649,637 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:20:34.283323+00:00 | 2022-08-29T17:57:10.698091+00:00 |
| 192.168.137.134 | LAN | True | e4:5f:01:55:90:c4 | 2,569,848 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2022-08-29T17:20:34.304533+00:00 | 2022-08-29T17:57:09.715198+00:00 |
| 192.168.137.242 | LAN | True | dc:a6:32:c9:e5:02 | 37 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:21:01.345653+00:00 | 2022-08-29T17:56:46.903671+00:00 |
| 192.168.137.90 | LAN | True | dc:a6:32:c9:e6:f4 | 28 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:36:24.289268+00:00 | 2022-08-29T17:47:20.835771+00:00 |
| 192.168.137.213 | LAN | True | dc:a6:32:c9:e4:c6 | 13 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:36:20.359796+00:00 | 2022-08-29T17:44:04.165940+00:00 |
| fe80::dea6:32ff:fec9:e4d5 | LAN | True | dc:a6:32:c9:e4:d5 | 2 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:22:19.647965+00:00 | 2022-08-29T17:26:12.740999+00:00 |
| fe80::7751:923:3c0f:1915 | LAN | True | dc:a6:32:c9:e4:c6 | 2 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:36:09.982599+00:00 | 2022-08-29T17:42:34.031454+00:00 |
| fe80::dea6:32ff:fec9:e4ab | LAN | True | dc:a6:32:c9:e4:ab | 1 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:21:20.903861+00:00 | 2022-08-29T17:21:20.903861+00:00 |
| fe80::dea6:32ff:fec9:e502 | LAN | True | dc:a6:32:c9:e5:02 | 1 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:29:24.851694+00:00 | 2022-08-29T17:29:24.851694+00:00 |
| fe80::dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 1 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-08-29T17:36:24.935738+00:00 | 2022-08-29T17:36:24.935738+00:00 |
| fe80::dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 1 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:39:22.113925+00:00 | 2022-08-29T17:39:22.113925+00:00 |
| fe80::dea6:32ff:fec9:e5a4 | LAN | True | dc:a6:32:c9:e5:a4 | 1 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:41:43.787454+00:00 | 2022-08-29T17:41:43.787454+00:00 |
| fe80::dea6:32ff:fec9:e5ef | LAN | True | dc:a6:32:c9:e5:ef | 1 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-08-29T17:57:08.904998+00:00 | 2022-08-29T17:57:08.904998+00:00 |

### Flows passing T1 only via T1b: 0

| outcome | without_T1b | with_T1b |
|---|---|---|
| attack | 5,283,182 | 5,283,182 |
| benign | 14,060 | 14,060 |
| excluded:attack_normal_service_ambiguous | 3 | 3 |
| excluded:attacker_normal_traffic | 1 | 1 |
| excluded:attacker_offwindow | 51 | 51 |
| excluded:spoof_collision | 0 | 0 |
| excluded:victim_ambiguous | 0 | 0 |

## Labels (5,297,297 flows)

| label | flows | pct |
|---|---|---|
| attack | 5,283,182 | 99.734 |
| benign | 14,060 | 0.265 |
| excluded | 55 | 0.001 |

### Excluded by reason

| reason | flows |
|---|---|
| attacker_offwindow | 51 |
| attacker_normal_traffic | 1 |
| victim_ambiguous | 0 |
| attack_normal_service_ambiguous | 3 |
| spoof_collision | 0 |

- attack by family: {'syn_flood': 5283182}
- pad_only: 36 attack flows (36 flows overall) pass T2 only thanks to the padding
- T4 flow mapping (attacker-MAC flows): {'icmp_error_pseudo_flows': 1, 'attacker_sent_no_packets': 3}
- **gateway-victim attack flows: 0** (unowned; non-iot victims total 0: {'iot': 5283182})

### By owner group (04 ownership)

| group | attack | benign | excluded |
|---|---|---|---|
| G1 | 0 | 11,180 | 0 |
| G2 | 5,283,182 | 1,625 | 3 |
| GEN | 0 | 84 | 0 |
| ungrouped | 0 | 0 | 0 |
| unowned | 0 | 1,171 | 52 |

### 04 exclude_reason x label

| exclude_reason | label | flows |
|---|---|---|
| (blank) | attack | 5,283,182 |
| (blank) | benign | 14,034 |
| (blank) | excluded | 55 |
| invalid_parse | benign | 26 |

### Attack flows per victim device

| device | group | role | mac | attack_flows | 07a_reason | 07a_attack_packets |
|---|---|---|---|---|---|---|
| GoSund Smart Plug WP2 (1) | G2 | iot | b8:f0:09:03:29:79 | 2,449,417 | both | 12,450,028 |
| Unidentified ESP plug (2) | G2 | iot | 50:02:91:10:09:8f | 2,440,286 | both | 13,274,570 |
| Unidentified ESP plug (3) | G2 | iot | c4:dd:57:0c:39:94 | 393,479 | both | 877,056 |

### Attack flows per 07a burst window

| window | start | end | 07a_packets | attack_flows |
|---|---|---|---|---|
| 0 | 2022-08-29T17:20:00.000000+00:00 | 2022-08-29T17:33:00.000000+00:00 | 12,451,249 | 2,449,417 |
| 1 | 2022-08-29T17:36:00.000000+00:00 | 2022-08-29T17:49:00.000000+00:00 | 13,275,901 | 2,440,286 |
| 2 | 2022-08-29T17:56:00.000000+00:00 | 2022-08-29T17:58:00.000000+00:00 | 877,117 | 393,479 |

## Soft checks

### Victim groups vs 07a coverage

| group | victims_with_attack_flows | 07a_victims | 07a_verdict | verdict | match |
|---|---|---|---|---|---|
| G1 | 0 | 0 | FAIL | FAIL | ok |
| G2 | 3 | 3 | PASS | PASS | ok |
| GEN | 0 | 0 | FAIL | FAIL | ok |

- attack flows / 07a attacker packets: 0.198584 (5,283,182 / 26,604,267)
- benign flows inside a burst with a 07a victim on one side, by the other side's role: {'iot': 5345, 'external': 64, 'broadcast': 52, 'unknown': 59, 'unlisted': 133, 'gateway': 3} (external / lan_unmapped here would be spoofed attack traffic that T1 cannot see)

### Benign owned-flow share per device vs the benign capture (largest differences)

| device | group | benign_flows_here | share_here_pct | share_benign_capture_pct | diff_pp |
|---|---|---|---|---|---|
| AMCREST WiFi Camera | G1 | 1,561 | 12.11 | 1.16 | 10.95 |
| Home Eye Camera | G1 | 257 | 1.99 | 10.36 | -8.37 |
| Unidentified Amazon device (1c:12:b0) | G1 | 610 | 4.73 | 0.0 | 4.73 |
| Harman Kardon speaker (Ampak) | G1 | 13 | 0.1 | 4.58 | -4.48 |
| Fibaro Home Center Lite | G1 | 5,815 | 45.12 | 48.35 | -3.23 |
| Yi Indoor 2 Camera | G1 | 49 | 0.38 | 2.86 | -2.48 |
| Amazon Alexa Echo Dot 2 | G1 | 262 | 2.03 | 0.18 | 1.86 |
| LG Smart TV | G1 | 33 | 0.26 | 2.03 | -1.77 |
| Wyze Camera | G1 | 414 | 3.21 | 4.58 | -1.36 |
| Arlo Q Indoor Camera | G1 | 74 | 0.57 | 1.79 | -1.21 |
| Cocoon Smart HVAC Fan | G2 | 161 | 1.25 | 0.14 | 1.11 |
| Google Nest Mini Speaker | G1 | 122 | 0.95 | 1.85 | -0.91 |
| Nest Indoor Camera | G2 | 134 | 1.04 | 0.14 | 0.9 |
| Amazon Smart Plug | G2 | 129 | 1.0 | 0.15 | 0.85 |
| Lumiman Bulb | G2 | 143 | 1.11 | 0.29 | 0.82 |

### Per-attacker-MAC burst windows used for T2 (07a, anchored)

- dc:a6:32:c9:e4:90: 17:20:00-17:33:00 (2022-08-29); 17:36:00-17:49:00 (2022-08-29); 17:56:00-17:58:00 (2022-08-29)
- dc:a6:32:c9:e4:ab: 17:20:00-17:32:00 (2022-08-29); 17:36:00-17:49:00 (2022-08-29); 17:56:00-17:58:00 (2022-08-29)
- dc:a6:32:c9:e4:d5: 17:20:00-17:32:00 (2022-08-29); 17:36:00-17:49:00 (2022-08-29); 17:56:00-17:58:00 (2022-08-29)
- dc:a6:32:c9:e5:a4: 17:20:00-17:32:00 (2022-08-29); 17:36:00-17:49:00 (2022-08-29); 17:56:00-17:58:00 (2022-08-29)
- dc:a6:32:c9:e5:ef: 17:20:00-17:32:00 (2022-08-29); 17:36:00-17:48:00 (2022-08-29); 17:56:00-17:58:00 (2022-08-29)
- dc:a6:32:dc:27:d5: 17:20:00-17:32:00 (2022-08-29); 17:36:00-17:48:00 (2022-08-29); 17:56:00-17:58:00 (2022-08-29)
- e4:5f:01:55:90:c4: 17:20:00-17:32:00 (2022-08-29); 17:36:00-17:48:00 (2022-08-29); 17:56:00-17:57:00 (2022-08-29)
