# Step 7 -- attack labels: DDoS-SYN_Flood (syn_flood)

- pcap `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood.pcap`; run 2026-10-11T14:22:29+00:00; runtime 1831.7 s; peak RSS python 2,133.2 MB, largest child 6,357.0 MB
- flows `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood/DDoS-SYN_Flood.pcap_Flow__singlepkt.csv` (extracted); 03b **WARN**
- map `/home/krithikk/lgids_cache/maps/DDoS-SYN_Flood_ip_mac_map.csv` (built, 106 rows, 0 overlapping IP conflicts); conflict resolution {'conflicts': 0, 'ambiguous_on_conflict_ips': 0, 'prescan_seconds': 18.6, 'udp_flow_keys': 15379}
- 07a stats `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage/DDoS-SYN_Flood_stats.json`; pad ±60 s; K 10
- labelled CSV `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood/DDoS-SYN_Flood_labelled.csv.gz`; timeline `DDoS-SYN_Flood_timeline.png`
- spoof: collision IPs none (07a: 0 device-IP collisions, 10 distinct attacker ip.src)

## Hard checks: **PASS**

| check | value | result |
|---|---|---|
| attack flows outside 07a burst windows (+pad) | 0 | PASS |
| attack flows whose victim is not a 07a victim | 0 | PASS |
| flows without exactly one outcome | 0 | PASS |
| rows written == flow CSV rows == meta row_count | 6,800,503 / 6,800,503 | PASS |
| label counts sum to rows | 6,800,503 | PASS |

## Attacker IP set (T1b): 17 IPs (17 LAN, 0 external / other; 17 unicast used for T1b) from 26,003,644 attacker-MAC packets

| ip | scope | used_for_T1b | attacker_macs | packets | resolves_to_attacker | non_attacker_host_overlaps | map_macs | first_utc | last_utc |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.240 | LAN | True | dc:a6:32:c9:e4:ab | 7,078,448 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:18:44.221935+00:00 | 2022-08-29T12:31:38.435092+00:00 |
| 192.168.137.17 | LAN | True | dc:a6:32:dc:27:d5 | 4,305,989 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-08-26T18:18:39.796419+00:00 | 2022-08-29T12:31:38.506393+00:00 |
| 192.168.137.195 | LAN | True | dc:a6:32:c9:e4:90 | 4,162,388 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:19:02.814854+00:00 | 2022-08-29T12:31:35.315555+00:00 |
| 192.168.137.134 | LAN | True | e4:5f:01:55:90:c4 | 3,826,465 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2022-08-26T18:18:39.916397+00:00 | 2022-08-29T12:31:44.272993+00:00 |
| 192.168.137.58 | LAN | True | dc:a6:32:c9:e5:ef | 3,658,374 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:18:48.779240+00:00 | 2022-08-29T12:31:44.275216+00:00 |
| 192.168.137.224 | LAN | True | dc:a6:32:c9:e4:d5 | 2,962,444 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:18:45.536743+00:00 | 2022-08-29T12:31:44.067941+00:00 |
| 192.168.137.96 | LAN | True | dc:a6:32:c9:e5:a4 | 1,840 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:23:58.203550+00:00 | 2022-08-29T12:31:18.564193+00:00 |
| 192.168.137.242 | LAN | True | dc:a6:32:c9:e5:02 | 5 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:45:07.652842+00:00 | 2022-08-26T18:46:13.949128+00:00 |
| 192.168.137.213 | LAN | True | dc:a6:32:c9:e4:c6 | 3 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:23:05.411902+00:00 | 2022-08-26T18:43:35.995276+00:00 |
| fe80::dea6:32ff:fec9:e502 | LAN | True | dc:a6:32:c9:e5:02 | 3 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:29:24.709896+00:00 | 2022-08-29T12:29:25.633747+00:00 |
| 192.168.137.90 | LAN | True | dc:a6:32:c9:e6:f4 | 3 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:43:41.293723+00:00 | 2022-08-26T19:01:37.284751+00:00 |
| fe80::dea6:32ff:fec9:e5ef | LAN | True | dc:a6:32:c9:e5:ef | 3 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:50:01.705922+00:00 | 2022-08-29T12:27:38.888272+00:00 |
| fe80::dea6:32ff:fec9:e5a4 | LAN | True | dc:a6:32:c9:e5:a4 | 2 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:22:49.323284+00:00 | 2022-08-26T18:39:27.950694+00:00 |
| fe80::dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 2 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:24:58.147369+00:00 | 2022-08-26T18:39:21.567337+00:00 |
| fe80::dea6:32ff:fec9:e4d5 | LAN | True | dc:a6:32:c9:e4:d5 | 2 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-08-26T18:59:54.124713+00:00 | 2022-08-26T19:01:28.390288+00:00 |
| fe80::dea6:32ff:fec9:e4ab | LAN | True | dc:a6:32:c9:e4:ab | 2 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-08-26T19:01:40.899624+00:00 | 2022-08-26T19:05:11.925187+00:00 |
| fe80::dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 1 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-08-26T18:44:18.606655+00:00 | 2022-08-26T18:44:18.606655+00:00 |

### Flows passing T1 only via T1b: 0

| outcome | without_T1b | with_T1b |
|---|---|---|
| attack | 6,756,387 | 6,756,387 |
| benign | 28,563 | 28,563 |
| excluded:attack_normal_service_ambiguous | 13,689 | 13,689 |
| excluded:attacker_normal_traffic | 12 | 12 |
| excluded:attacker_offwindow | 1,852 | 1,852 |
| excluded:spoof_collision | 0 | 0 |
| excluded:victim_ambiguous | 0 | 0 |

## Labels (6,800,503 flows)

| label | flows | pct |
|---|---|---|
| attack | 6,756,387 | 99.351 |
| benign | 28,563 | 0.42 |
| excluded | 15,553 | 0.229 |

### Excluded by reason

| reason | flows |
|---|---|
| attacker_offwindow | 1,852 |
| attacker_normal_traffic | 12 |
| victim_ambiguous | 0 |
| attack_normal_service_ambiguous | 13,689 |
| spoof_collision | 0 |

- attack by family: {'syn_flood': 6756387}
- pad_only: 168 attack flows (168 flows overall) pass T2 only thanks to the padding
- T4 flow mapping (attacker-MAC flows): {'icmp_error_pseudo_flows': 0, 'attacker_sent_no_packets': 13689}
- **gateway-victim attack flows: 0** (unowned; non-iot victims total 0: {'iot': 6756387})

### By owner group (04 ownership)

| group | attack | benign | excluded |
|---|---|---|---|
| G1 | 6,756,387 | 24,001 | 15,529 |
| G2 | 0 | 2,386 | 0 |
| GEN | 0 | 160 | 0 |
| ungrouped | 0 | 0 | 0 |
| unowned | 0 | 2,016 | 24 |

### 04 exclude_reason x label

| exclude_reason | label | flows |
|---|---|---|
| (blank) | attack | 6,756,387 |
| (blank) | benign | 28,522 |
| (blank) | excluded | 15,553 |
| invalid_parse | benign | 41 |

### Attack flows per victim device

| device | group | role | mac | attack_flows | 07a_reason | 07a_attack_packets |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Dot 1 | G1 | iot | 1c:fe:2b:98:16:dd | 2,069,844 | both | 7,650,195 |
| Unidentified Amazon device (1c:12:b0) | G1 | iot | 1c:12:b0:9b:0c:ec | 2,061,651 | both | 8,782,212 |
| Google Nest Mini Speaker | G1 | iot | cc:f4:11:9c:d0:00 | 1,835,635 | both | 6,698,192 |
| AMCREST WiFi Camera | G1 | iot | 9c:8e:cd:1d:ab:9f | 789,257 | both | 2,868,217 |

### Attack flows per 07a burst window

| window | start | end | 07a_packets | attack_flows |
|---|---|---|---|---|
| 0 | 2022-08-26T18:18:00.000000+00:00 | 2022-08-26T18:31:00.000000+00:00 | 7,651,647 | 2,069,844 |
| 1 | 2022-08-26T18:39:00.000000+00:00 | 2022-08-26T18:52:00.000000+00:00 | 8,783,908 | 2,061,651 |
| 2 | 2022-08-26T18:57:00.000000+00:00 | 2022-08-26T19:10:00.000000+00:00 | 6,699,483 | 1,835,635 |
| 3 | 2022-08-29T12:28:00.000000+00:00 | 2022-08-29T12:32:00.000000+00:00 | 2,868,605 | 789,257 |

## Soft checks

### Victim groups vs 07a coverage

| group | victims_with_attack_flows | 07a_victims | 07a_verdict | verdict | match |
|---|---|---|---|---|---|
| G1 | 4 | 5 | PASS | PASS | ok |
| G2 | 0 | 0 | FAIL | FAIL | ok |
| GEN | 0 | 0 | FAIL | FAIL | ok |

- attack flows / 07a attacker packets: 0.259825 (6,756,387 / 26,003,644)
- benign flows inside a burst with a 07a victim on one side, by the other side's role: {'external': 2877, 'gateway': 2822, 'iot': 362, 'broadcast': 59, 'unknown': 15} (external / lan_unmapped here would be spoofed attack traffic that T1 cannot see)

### Benign owned-flow share per device vs the benign capture (largest differences)

| device | group | benign_flows_here | share_here_pct | share_benign_capture_pct | diff_pp |
|---|---|---|---|---|---|
| Fibaro Home Center Lite | G1 | 9,193 | 34.63 | 48.35 | -13.72 |
| Home Eye Camera | G1 | 613 | 2.31 | 10.36 | -8.06 |
| Wyze Camera | G1 | 3,098 | 11.67 | 4.58 | 7.09 |
| Google Nest Mini Speaker | G1 | 2,089 | 7.87 | 1.85 | 6.02 |
| AMCREST WiFi Camera | G1 | 1,711 | 6.45 | 1.16 | 5.29 |
| TP-Link Tapo Camera | G1 | 1,550 | 5.84 | 1.07 | 4.77 |
| Harman Kardon speaker (Ampak) | G1 | 175 | 0.66 | 4.58 | -3.92 |
| Amazon Alexa Echo Dot 1 | G1 | 1,127 | 4.25 | 0.75 | 3.5 |
| Unidentified Amazon device (1c:12:b0) | G1 | 796 | 3.0 | 0.0 | 3.0 |
| Yi Indoor 2 Camera | G1 | 77 | 0.29 | 2.86 | -2.57 |
| Amazon Alexa Echo Dot 2 | G1 | 606 | 2.28 | 0.18 | 2.11 |
| LG Smart TV | G1 | 7 | 0.03 | 2.03 | -2.0 |
| Arlo Q Indoor Camera | G1 | 122 | 0.46 | 1.79 | -1.33 |
| Amazon Echo Show | G1 | 392 | 1.48 | 2.5 | -1.02 |
| Yi Indoor Camera | G1 | 126 | 0.47 | 1.34 | -0.86 |

### Per-attacker-MAC burst windows used for T2 (07a, anchored)

- dc:a6:32:c9:e4:90: 18:19:00-18:30:00 (2022-08-26); 18:39:00-18:52:00 (2022-08-26); 18:57:00-19:09:00 (2022-08-26); 12:28:00-12:32:00 (2022-08-29)
- dc:a6:32:c9:e4:ab: 18:18:00-18:31:00 (2022-08-26); 18:39:00-18:52:00 (2022-08-26); 18:57:00-19:10:00 (2022-08-26); 12:28:00-12:32:00 (2022-08-29)
- dc:a6:32:c9:e4:d5: 18:18:00-18:30:00 (2022-08-26); 18:39:00-18:52:00 (2022-08-26); 18:57:00-19:09:00 (2022-08-26); 12:28:00-12:32:00 (2022-08-29)
- dc:a6:32:c9:e5:ef: 18:18:00-18:30:00 (2022-08-26); 18:39:00-18:52:00 (2022-08-26); 18:57:00-19:10:00 (2022-08-26); 12:28:00-12:32:00 (2022-08-29)
- dc:a6:32:dc:27:d5: 18:18:00-18:31:00 (2022-08-26); 18:39:00-18:52:00 (2022-08-26); 18:57:00-19:10:00 (2022-08-26); 12:28:00-12:32:00 (2022-08-29)
- e4:5f:01:55:90:c4: 18:18:00-18:31:00 (2022-08-26); 18:39:00-18:52:00 (2022-08-26); 18:57:00-19:10:00 (2022-08-26); 12:28:00-12:32:00 (2022-08-29)
