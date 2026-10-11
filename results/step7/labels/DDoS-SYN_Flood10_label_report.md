# Step 7 -- attack labels: DDoS-SYN_Flood10 (syn_flood)

- pcap `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood10.pcap`; run 2026-10-11T15:03:26+00:00; runtime 708.7 s; peak RSS python 2,133.2 MB, largest child 6,473.9 MB
- flows `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood10/DDoS-SYN_Flood10.pcap_Flow__singlepkt.csv` (extracted); 03b **WARN**
- map `/home/krithikk/lgids_cache/maps/DDoS-SYN_Flood10_ip_mac_map.csv` (reused, 104 rows, 0 overlapping IP conflicts); conflict resolution {'conflicts': 0, 'ambiguous_on_conflict_ips': 0, 'prescan_seconds': 20.4, 'udp_flow_keys': 8126}
- 07a stats `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage/DDoS-SYN_Flood10_stats.json`; pad ±60 s; K 10
- labelled CSV `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood10/DDoS-SYN_Flood10_labelled.csv.gz`; timeline `DDoS-SYN_Flood10_timeline.png`
- spoof: collision IPs none (07a: 0 device-IP collisions, 11 distinct attacker ip.src)

## Hard checks: **PASS**

| check | value | result |
|---|---|---|
| attack flows outside 07a burst windows (+pad) | 0 | PASS |
| attack flows whose victim is not a 07a victim | 0 | PASS |
| flows without exactly one outcome | 0 | PASS |
| rows written == flow CSV rows == meta row_count | 6,099,055 / 6,099,055 | PASS |
| label counts sum to rows | 6,099,055 | PASS |

## Attacker IP set (T1b): 18 IPs (16 LAN, 2 external / other; 16 unicast used for T1b) from 26,420,022 attacker-MAC packets

| ip | scope | used_for_T1b | attacker_macs | packets | resolves_to_attacker | non_attacker_host_overlaps | map_macs | first_utc | last_utc |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.224 | LAN | True | dc:a6:32:c9:e4:d5 | 5,029,239 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:10:09.108684+00:00 | 2022-08-30T13:45:21.248973+00:00 |
| 192.168.137.240 | LAN | True | dc:a6:32:c9:e4:ab | 4,093,091 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:10:09.116444+00:00 | 2022-08-30T13:45:21.231857+00:00 |
| 192.168.137.96 | LAN | True | dc:a6:32:c9:e5:a4 | 3,676,375 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:10:09.100902+00:00 | 2022-08-30T13:45:21.103937+00:00 |
| 192.168.137.17 | LAN | True | dc:a6:32:dc:27:d5 | 3,670,310 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-08-30T13:10:09.104307+00:00 | 2022-08-30T13:45:21.209120+00:00 |
| 192.168.137.134 | LAN | True | e4:5f:01:55:90:c4 | 3,577,019 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2022-08-30T13:10:11.200735+00:00 | 2022-08-30T13:45:21.188821+00:00 |
| 192.168.137.195 | LAN | True | dc:a6:32:c9:e4:90 | 3,517,146 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:10:09.259957+00:00 | 2022-08-30T13:45:21.099455+00:00 |
| 192.168.137.58 | LAN | True | dc:a6:32:c9:e5:ef | 2,850,472 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:10:09.152790+00:00 | 2022-08-30T13:45:19.858177+00:00 |
| 192.168.137.213 | LAN | True | dc:a6:32:c9:e4:c6 | 68 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:12:03.235713+00:00 | 2022-08-30T13:41:59.885279+00:00 |
| 192.168.137.242 | LAN | True | dc:a6:32:c9:e5:02 | 37 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:13:04.737774+00:00 | 2022-08-30T13:45:16.130750+00:00 |
| 192.168.137.90 | LAN | True | dc:a6:32:c9:e6:f4 | 33 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:38:06.508913+00:00 | 2022-08-30T13:44:30.700025+00:00 |
| fe80::7751:923:3c0f:1915 | LAN | True | dc:a6:32:c9:e4:c6 | 15 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:28:29.716108+00:00 | 2022-08-30T13:32:42.715750+00:00 |
| fe80::dea6:32ff:fec9:e5a4 | LAN | True | dc:a6:32:c9:e5:a4 | 2 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:12:30.927812+00:00 | 2022-08-30T13:41:43.721796+00:00 |
| fe80::e65f:1ff:fe55:90c4 | LAN | True | e4:5f:01:55:90:c4 | 2 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2022-08-30T13:25:01.828536+00:00 | 2022-08-30T13:28:25.958248+00:00 |
| :: | unspecified | False | dc:a6:32:c9:e4:c6 | 2 | no | - | - | 2022-08-30T13:28:28.718222+00:00 | 2022-08-30T13:28:29.509917+00:00 |
| fe80::dea6:32ff:fec9:e502 | LAN | True | dc:a6:32:c9:e5:02 | 1 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:12:25.088027+00:00 | 2022-08-30T13:12:25.088027+00:00 |
| fe80::dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 1 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-08-30T13:15:03.430873+00:00 | 2022-08-30T13:15:03.430873+00:00 |
| 0.0.0.0 | unspecified | False | dc:a6:32:c9:e4:c6 | 1 | no | - | - | 2022-08-30T13:28:29.453702+00:00 | 2022-08-30T13:28:29.453702+00:00 |
| fe80::dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 1 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-08-30T13:39:22.029534+00:00 | 2022-08-30T13:39:22.029534+00:00 |

### Flows passing T1 only via T1b: 0

| outcome | without_T1b | with_T1b |
|---|---|---|
| attack | 6,067,638 | 6,067,638 |
| benign | 17,953 | 17,953 |
| excluded:attack_normal_service_ambiguous | 13,401 | 13,401 |
| excluded:attacker_normal_traffic | 2 | 2 |
| excluded:attacker_offwindow | 61 | 61 |
| excluded:spoof_collision | 0 | 0 |
| excluded:victim_ambiguous | 0 | 0 |

## Labels (6,099,055 flows)

| label | flows | pct |
|---|---|---|
| attack | 6,067,638 | 99.485 |
| benign | 17,953 | 0.294 |
| excluded | 13,464 | 0.221 |

### Excluded by reason

| reason | flows |
|---|---|
| attacker_offwindow | 61 |
| attacker_normal_traffic | 2 |
| victim_ambiguous | 0 |
| attack_normal_service_ambiguous | 13,401 |
| spoof_collision | 0 |

- attack by family: {'syn_flood': 6067638}
- pad_only: 0 attack flows (0 flows overall) pass T2 only thanks to the padding
- T4 flow mapping (attacker-MAC flows): {'icmp_error_pseudo_flows': 0, 'attacker_sent_no_packets': 13403}
- **gateway-victim attack flows: 0** (unowned; non-iot victims total 0: {'iot': 6067638})

### By owner group (04 ownership)

| group | attack | benign | excluded |
|---|---|---|---|
| G1 | 1,559,800 | 14,147 | 4,725 |
| G2 | 4,507,838 | 2,012 | 8,676 |
| GEN | 0 | 92 | 0 |
| ungrouped | 0 | 0 | 0 |
| unowned | 0 | 1,702 | 63 |

### 04 exclude_reason x label

| exclude_reason | label | flows |
|---|---|---|
| (blank) | attack | 6,067,638 |
| (blank) | benign | 17,923 |
| (blank) | excluded | 13,464 |
| invalid_parse | benign | 30 |

### Attack flows per victim device

| device | group | role | mac | attack_flows | 07a_reason | 07a_attack_packets |
|---|---|---|---|---|---|---|
| Teckin Light Strip | G2 | iot | 18:69:d8:eb:d4:3e | 2,297,864 | both | 11,634,391 |
| Unidentified ESP plug (4) | G2 | iot | c4:dd:57:13:07:c6 | 2,209,974 | both | 8,418,895 |
| Amazon Echo Show | G1 | iot | 2c:71:ff:05:f1:15 | 1,559,800 | both | 6,361,949 |

### Attack flows per 07a burst window

| window | start | end | 07a_packets | attack_flows |
|---|---|---|---|---|
| 0 | 2022-08-30T13:10:00.000000+00:00 | 2022-08-30T13:46:00.000000+00:00 | 26,420,022 | 6,067,638 |

## Soft checks

### Victim groups vs 07a coverage

| group | victims_with_attack_flows | 07a_victims | 07a_verdict | verdict | match |
|---|---|---|---|---|---|
| G1 | 1 | 1 | FAIL | FAIL | ok |
| G2 | 2 | 2 | PASS | PASS | ok |
| GEN | 0 | 0 | FAIL | FAIL | ok |

- attack flows / 07a attacker packets: 0.229661 (6,067,638 / 26,420,022)
- benign flows inside a burst with a 07a victim on one side, by the other side's role: {'iot': 5751, 'external': 322, 'broadcast': 82, 'unknown': 73, 'unlisted': 313, 'gateway': 78} (external / lan_unmapped here would be spoofed attack traffic that T1 cannot see)

### Benign owned-flow share per device vs the benign capture (largest differences)

| device | group | benign_flows_here | share_here_pct | share_benign_capture_pct | diff_pp |
|---|---|---|---|---|---|
| Home Eye Camera | G1 | 314 | 1.93 | 10.36 | -8.43 |
| Fibaro Home Center Lite | G1 | 6,879 | 42.33 | 48.35 | -6.02 |
| AMCREST WiFi Camera | G1 | 1,083 | 6.66 | 1.16 | 5.51 |
| Unidentified Amazon device (1c:12:b0) | G1 | 809 | 4.98 | 0.0 | 4.98 |
| TP-Link Tapo Camera | G1 | 640 | 3.94 | 1.07 | 2.87 |
| Wyze Camera | G1 | 311 | 1.91 | 4.58 | -2.66 |
| Amazon Alexa Echo Dot 2 | G1 | 428 | 2.63 | 0.18 | 2.46 |
| Yi Indoor 2 Camera | G1 | 68 | 0.42 | 2.86 | -2.45 |
| Harman Kardon speaker (Ampak) | G1 | 372 | 2.29 | 4.58 | -2.29 |
| LG Smart TV | G1 | 0 | 0.0 | 2.03 | -2.03 |
| Amazon Alexa Echo Dot 1 | G1 | 373 | 2.3 | 0.75 | 1.55 |
| Google Nest Mini Speaker | G1 | 523 | 3.22 | 1.85 | 1.36 |
| Arlo Q Indoor Camera | G1 | 76 | 0.47 | 1.79 | -1.32 |
| Lumiman Bulb | G2 | 225 | 1.38 | 0.29 | 1.09 |
| Teckin Light Strip | G2 | 225 | 1.38 | 0.3 | 1.09 |

### Per-attacker-MAC burst windows used for T2 (07a, anchored)

- dc:a6:32:c9:e4:90: 13:10:00-13:35:00 (2022-08-30); 13:38:00-13:46:00 (2022-08-30)
- dc:a6:32:c9:e4:ab: 13:10:00-13:21:00 (2022-08-30); 13:24:00-13:46:00 (2022-08-30)
- dc:a6:32:c9:e4:d5: 13:10:00-13:34:00 (2022-08-30); 13:38:00-13:46:00 (2022-08-30)
- dc:a6:32:c9:e5:a4: 13:10:00-13:35:00 (2022-08-30); 13:38:00-13:46:00 (2022-08-30)
- dc:a6:32:c9:e5:ef: 13:10:00-13:46:00 (2022-08-30)
- dc:a6:32:dc:27:d5: 13:10:00-13:20:00 (2022-08-30); 13:23:00-13:32:00 (2022-08-30); 13:38:00-13:46:00 (2022-08-30)
- e4:5f:01:55:90:c4: 13:10:00-13:20:00 (2022-08-30); 13:23:00-13:35:00 (2022-08-30); 13:38:00-13:46:00 (2022-08-30)
