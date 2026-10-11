# Step 7 -- attack labels: Mirai-udpplain24 (udp_flood)

- pcap `/home/krithikk/lgids_cache/ciciot2023/attack/Mirai-udpplain/Mirai-udpplain24.pcap`; run 2026-10-11T15:14:03+00:00; runtime 10.0 s; peak RSS python 2,133.2 MB, largest child 6,473.9 MB
- flows `/home/krithikk/lgids_cache/flows/attack/Mirai-udpplain24/Mirai-udpplain24.pcap_Flow__singlepkt.csv` (extracted); 03b **WARN**
- map `/home/krithikk/lgids_cache/maps/Mirai-udpplain24_ip_mac_map.csv` (reused, 115 rows, 0 overlapping IP conflicts); conflict resolution {'conflicts': 0, 'ambiguous_on_conflict_ips': 0, 'prescan_seconds': 0.0, 'udp_flow_keys': 4129}
- 07a stats `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage/Mirai-udpplain24_stats.json`; pad ±60 s; K 10
- labelled CSV `/home/krithikk/lgids_cache/flows/attack/Mirai-udpplain24/Mirai-udpplain24_labelled.csv.gz`; timeline `Mirai-udpplain24_timeline.png`
- spoof: collision IPs none (07a: 0 device-IP collisions, 10 distinct attacker ip.src)

## Hard checks: **PASS**

| check | value | result |
|---|---|---|
| attack flows outside 07a burst windows (+pad) | 0 | PASS |
| attack flows whose victim is not a 07a victim | 0 | PASS |
| flows without exactly one outcome | 0 | PASS |
| rows written == flow CSV rows == meta row_count | 6,251 / 6,251 | PASS |
| label counts sum to rows | 6,251 | PASS |

## Attacker IP set (T1b): 31 IPs (31 LAN, 0 external / other; 31 unicast used for T1b) from 1,456,835 attacker-MAC packets

| ip | scope | used_for_T1b | attacker_macs | packets | resolves_to_attacker | non_attacker_host_overlaps | map_macs | first_utc | last_utc |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.238 | LAN | True | dc:a6:32:c9:e4:90 | 388,401 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:24:21.570919+00:00 | 2023-02-14T17:38:00.238625+00:00 |
| 192.168.137.162 | LAN | True | dc:a6:32:c9:e5:a4 | 220,703 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:23:57.789760+00:00 | 2023-02-14T17:37:22.161163+00:00 |
| 192.168.137.147 | LAN | True | dc:a6:32:dc:27:d5 | 209,111 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2023-02-07T16:23:57.808917+00:00 | 2023-02-14T17:34:28.083788+00:00 |
| 192.168.137.128 | LAN | True | dc:a6:32:c9:e4:d5 | 190,097 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:24:17.704489+00:00 | 2023-02-14T17:29:34.495253+00:00 |
| 192.168.137.207 | LAN | True | dc:a6:32:c9:e4:ab | 166,888 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:23:57.816036+00:00 | 2023-02-14T17:28:19.760344+00:00 |
| 192.168.137.247 | LAN | True | e4:5f:01:55:90:c4 | 144,142 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2023-02-07T16:24:03.232833+00:00 | 2023-02-14T17:28:04.915181+00:00 |
| 192.168.137.106 | LAN | True | dc:a6:32:c9:e5:ef | 131,985 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:24:06.555871+00:00 | 2023-02-07T16:27:59.990097+00:00 |
| 192.168.137.13 | LAN | True | dc:a6:32:c9:e6:f4 | 336 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:08.943597+00:00 | 2023-02-14T17:37:57.260156+00:00 |
| 192.168.137.11 | LAN | True | dc:a6:32:c9:e5:02 | 13 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:10.172658+00:00 | 2023-02-07T16:27:38.425958+00:00 |
| fe80::dea6:32ff:fec9:e490 | LAN | True | dc:a6:32:c9:e4:90 | 2 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:06.792872+00:00 | 2023-02-07T16:26:07.207991+00:00 |
| fe80::dea6:32ff:fec9:e4ab | LAN | True | dc:a6:32:c9:e4:ab | 2 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:07.403503+00:00 | 2023-02-07T16:26:07.746552+00:00 |
| 192.168.137.236 | LAN | True | dc:a6:32:c9:e4:c6 | 2 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:06.724106+00:00 | 2023-02-14T17:34:58.199749+00:00 |
| fe80::7751:923:3c0f:1915 | LAN | True | dc:a6:32:c9:e4:c6 | 2 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:06.500313+00:00 | 2023-02-07T16:26:06.724158+00:00 |
| fe80::dea6:32ff:fec9:e4d5 | LAN | True | dc:a6:32:c9:e4:d5 | 2 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:08.092935+00:00 | 2023-02-07T16:26:08.092948+00:00 |
| fe80::dea6:32ff:fec9:e502 | LAN | True | dc:a6:32:c9:e5:02 | 2 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:09.859745+00:00 | 2023-02-07T16:26:10.172711+00:00 |
| fe80::dea6:32ff:fec9:e5a4 | LAN | True | dc:a6:32:c9:e5:a4 | 2 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:06.702495+00:00 | 2023-02-07T16:26:07.115989+00:00 |
| fe80::dea6:32ff:fec9:e5ef | LAN | True | dc:a6:32:c9:e5:ef | 2 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:08.219260+00:00 | 2023-02-07T16:26:08.330772+00:00 |
| fe80::dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 2 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:07.642682+00:00 | 2023-02-07T16:26:08.241831+00:00 |
| fe80::dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 2 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2023-02-07T16:26:08.283772+00:00 | 2023-02-07T16:26:08.783903+00:00 |
| fe80::e65f:1ff:fe55:90c4 | LAN | True | e4:5f:01:55:90:c4 | 2 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2023-02-07T16:26:06.755497+00:00 | 2023-02-07T16:26:07.462753+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e490 | LAN | True | dc:a6:32:c9:e4:90 | 1 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:06.795766+00:00 | 2023-02-07T16:26:06.795766+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e4ab | LAN | True | dc:a6:32:c9:e4:ab | 1 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:07.494767+00:00 | 2023-02-07T16:26:07.494767+00:00 |
| fdcc:d8dd:e1af:26ab:b792:bd43:8ad5:20d4 | LAN | True | dc:a6:32:c9:e4:c6 | 1 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:06.724103+00:00 | 2023-02-07T16:26:06.724103+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e4d5 | LAN | True | dc:a6:32:c9:e4:d5 | 1 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:08.125144+00:00 | 2023-02-07T16:26:08.125144+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e502 | LAN | True | dc:a6:32:c9:e5:02 | 1 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:10.172655+00:00 | 2023-02-07T16:26:10.172655+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e5a4 | LAN | True | dc:a6:32:c9:e5:a4 | 1 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:06.815254+00:00 | 2023-02-07T16:26:06.815254+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e5ef | LAN | True | dc:a6:32:c9:e5:ef | 1 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:08.291231+00:00 | 2023-02-07T16:26:08.291231+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 1 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2023-02-07T16:26:08.943595+00:00 | 2023-02-07T16:26:08.943595+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 1 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2023-02-07T16:26:08.309043+00:00 | 2023-02-07T16:26:08.309043+00:00 |
| fdcc:d8dd:e1af:26ab:e65f:1ff:fe55:90c4 | LAN | True | e4:5f:01:55:90:c4 | 1 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2023-02-07T16:26:06.727499+00:00 | 2023-02-07T16:26:06.727499+00:00 |
| fd5a:7bd:2aea:e111:dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 1 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2023-02-14T17:37:35.863147+00:00 | 2023-02-14T17:37:35.863147+00:00 |

### Flows passing T1 only via T1b: 0

| outcome | without_T1b | with_T1b |
|---|---|---|
| attack | 58 | 58 |
| benign | 5,928 | 5,928 |
| excluded:attack_normal_service_ambiguous | 18 | 18 |
| excluded:attacker_normal_traffic | 16 | 16 |
| excluded:attacker_offwindow | 231 | 231 |
| excluded:spoof_collision | 0 | 0 |
| excluded:victim_ambiguous | 0 | 0 |

## Labels (6,251 flows)

| label | flows | pct |
|---|---|---|
| attack | 58 | 0.928 |
| benign | 5,928 | 94.833 |
| excluded | 265 | 4.239 |

### Excluded by reason

| reason | flows |
|---|---|
| attacker_offwindow | 231 |
| attacker_normal_traffic | 16 |
| victim_ambiguous | 0 |
| attack_normal_service_ambiguous | 18 |
| spoof_collision | 0 |

- attack by family: {'udp_flood': 58}
- pad_only: 14 attack flows (17 flows overall) pass T2 only thanks to the padding
- T4 flow mapping (attacker-MAC flows): {'icmp_error_pseudo_flows': 41, 'attacker_sent_no_packets': 33}
- **gateway-victim attack flows: 0** (unowned; non-iot victims total 0: {'iot': 58})

### By owner group (04 ownership)

| group | attack | benign | excluded |
|---|---|---|---|
| G1 | 35 | 4,572 | 65 |
| G2 | 23 | 649 | 18 |
| GEN | 0 | 57 | 0 |
| ungrouped | 0 | 0 | 0 |
| unowned | 0 | 650 | 182 |

### 04 exclude_reason x label

| exclude_reason | label | flows |
|---|---|---|
| (blank) | attack | 58 |
| (blank) | benign | 5,910 |
| (blank) | excluded | 265 |
| invalid_parse | benign | 18 |

### Attack flows per victim device

| device | group | role | mac | attack_flows | 07a_reason | 07a_attack_packets |
|---|---|---|---|---|---|---|
| Google Nest Mini Speaker | G1 | iot | cc:f4:11:9c:d0:00 | 25 | both | 219 |
| D-Link DCS8000LHA1 Mini Camera | G2 | iot | b0:c5:54:59:2e:99 | 15 | both | 1,162,421 |
| Philips Hue Bridge | G1 | iot | 00:17:88:60:d6:4f | 10 | new_service | 101 |
| Teckin Plug 1 | G2 | iot | d4:a6:51:76:06:64 | 8 | both | 289,000 |

### Attack flows per 07a burst window

| window | start | end | 07a_packets | attack_flows |
|---|---|---|---|---|
| 0 | 2023-02-07T16:23:00.000000+00:00 | 2023-02-07T16:28:00.000000+00:00 | 1,162,956 | 23 |
| 1 | 2023-02-14T17:27:00.000000+00:00 | 2023-02-14T17:38:00.000000+00:00 | 293,588 | 35 |

## Soft checks

### Victim groups vs 07a coverage

| group | victims_with_attack_flows | 07a_victims | 07a_verdict | verdict | match |
|---|---|---|---|---|---|
| G1 | 2 | 3 | PASS | PASS | ok |
| G2 | 2 | 2 | PASS | PASS | ok |
| GEN | 0 | 0 | FAIL | FAIL | ok |

- attack flows / 07a attacker packets: 4e-05 (58 / 1,456,835)
- benign flows inside a burst with a 07a victim on one side, by the other side's role: {'iot': 1894, 'external': 956, 'gateway': 415, 'broadcast': 57, 'unknown': 53, 'excluded': 45, 'unlisted': 43} (external / lan_unmapped here would be spoofed attack traffic that T1 cannot see)

### Benign owned-flow share per device vs the benign capture (largest differences)

| device | group | benign_flows_here | share_here_pct | share_benign_capture_pct | diff_pp |
|---|---|---|---|---|---|
| Fibaro Home Center Lite | G1 | 0 | 0.0 | 48.35 | -48.35 |
| Google Nest Mini Speaker | G1 | 1,266 | 23.99 | 1.85 | 22.13 |
| TP-Link Tapo Camera | G1 | 746 | 14.13 | 1.07 | 13.07 |
| Amazon Alexa Echo Dot 1 | G1 | 355 | 6.73 | 0.75 | 5.98 |
| Amazon Echo Show | G1 | 380 | 7.2 | 2.5 | 4.7 |
| Harman Kardon speaker (Ampak) | G1 | 1 | 0.02 | 4.58 | -4.56 |
| Home Eye Camera | G1 | 336 | 6.37 | 10.36 | -4.0 |
| AMCREST WiFi Camera | G1 | 267 | 5.06 | 1.16 | 3.9 |
| Yi Indoor 2 Camera | G1 | 34 | 0.64 | 2.86 | -2.22 |
| Lumiman Bulb | G2 | 126 | 2.39 | 0.29 | 2.09 |
| LG Smart TV | G1 | 0 | 0.0 | 2.03 | -2.03 |
| Nest Indoor Camera | G2 | 87 | 1.65 | 0.14 | 1.51 |
| Aeotec Smart Home Hub | G1 | 122 | 2.31 | 1.01 | 1.31 |
| Amazon Alexa Echo Studio | G1 | 141 | 2.67 | 1.55 | 1.12 |
| SmartThings Hub | G1 | 111 | 2.1 | 1.03 | 1.07 |

### Per-attacker-MAC burst windows used for T2 (07a, anchored)

- dc:a6:32:c9:e4:90: 16:24:00-16:28:00 (2023-02-07); 17:27:00-17:29:00 (2023-02-14); 17:37:00-17:38:00 (2023-02-14)
- dc:a6:32:c9:e4:ab: 16:23:00-16:28:00 (2023-02-07); 17:27:00-17:29:00 (2023-02-14)
- dc:a6:32:c9:e4:d5: 16:24:00-16:28:00 (2023-02-07); 17:28:00-17:30:00 (2023-02-14)
- dc:a6:32:c9:e5:a4: 16:23:00-16:28:00 (2023-02-07); 17:28:00-17:30:00 (2023-02-14)
- dc:a6:32:c9:e5:ef: 16:24:00-16:28:00 (2023-02-07)
- dc:a6:32:dc:27:d5: 16:23:00-16:28:00 (2023-02-07); 17:27:00-17:28:00 (2023-02-14); 17:33:00-17:35:00 (2023-02-14)
- e4:5f:01:55:90:c4: 16:24:00-16:28:00 (2023-02-07); 17:27:00-17:29:00 (2023-02-14)
