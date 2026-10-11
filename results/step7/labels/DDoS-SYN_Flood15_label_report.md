# Step 7 -- attack labels: DDoS-SYN_Flood15 (syn_flood)

- pcap `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood15.pcap`; run 2026-10-11T15:13:32+00:00; runtime 603.3 s; peak RSS python 2,133.2 MB, largest child 6,473.9 MB
- flows `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood15/DDoS-SYN_Flood15.pcap_Flow__singlepkt.csv` (extracted); 03b **WARN**
- map `/home/krithikk/lgids_cache/maps/DDoS-SYN_Flood15_ip_mac_map.csv` (reused, 159 rows, 1 overlapping IP conflicts); conflict resolution {'conflicts': 1, 'ambiguous_on_conflict_ips': 389, 'prescan_seconds': 13.2, 'udp_flow_keys': 4270, 'packets_extracted': 1153, 'tshark_seconds': 235.8, 'resolved_flows': 389, 'both_macs_in_flow': 0, 'ip_clash_artifact': 86, 'resolved_to': {'34:75:63:73:f3:36': 238, '28:6d:97:9e:f4:d5': 151}}
- 07a stats `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage/DDoS-SYN_Flood15_stats.json`; pad ±60 s; K 10
- labelled CSV `/home/krithikk/lgids_cache/flows/attack/DDoS-SYN_Flood15/DDoS-SYN_Flood15_labelled.csv.gz`; timeline `DDoS-SYN_Flood15_timeline.png`
- spoof: collision IPs ['192.168.137.68', '192.168.137.76'] (07a: 2 device-IP collisions, 15 distinct attacker ip.src)

## Hard checks: **PASS**

| check | value | result |
|---|---|---|
| attack flows outside 07a burst windows (+pad) | 0 | PASS |
| attack flows whose victim is not a 07a victim | 0 | PASS |
| flows without exactly one outcome | 0 | PASS |
| rows written == flow CSV rows == meta row_count | 3,104,718 / 3,104,718 | PASS |
| label counts sum to rows | 3,104,718 | PASS |

## Attacker IP set (T1b): 24 IPs (24 LAN, 0 external / other; 24 unicast used for T1b) from 13,545,175 attacker-MAC packets

| ip | scope | used_for_T1b | attacker_macs | packets | resolves_to_attacker | non_attacker_host_overlaps | map_macs | first_utc | last_utc |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.201 | LAN | True | dc:a6:32:c9:e4:ab | 3,125,394 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:18:18.222708+00:00 | 2022-12-01T14:43:00.883049+00:00 |
| 192.168.137.99 | LAN | True | dc:a6:32:c9:e4:90 | 2,278,249 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:18:18.222383+00:00 | 2022-12-01T14:43:00.880162+00:00 |
| 192.168.137.36 | LAN | True | e4:5f:01:55:90:c4 | 1,989,428 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2022-11-29T19:18:53.923507+00:00 | 2022-12-01T14:43:00.882275+00:00 |
| 192.168.137.34 | LAN | True | dc:a6:32:c9:e5:ef | 1,855,796 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:18:23.247774+00:00 | 2022-12-01T14:42:56.469180+00:00 |
| 192.168.137.7 | LAN | True | dc:a6:32:dc:27:d5 | 1,603,903 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-11-29T19:18:19.573129+00:00 | 2022-12-01T14:43:00.793821+00:00 |
| 192.168.137.153 | LAN | True | dc:a6:32:c9:e4:d5 | 1,422,565 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:18:24.454503+00:00 | 2022-12-01T14:43:00.866070+00:00 |
| 192.168.137.87 | LAN | True | dc:a6:32:c9:e5:a4 | 1,266,344 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:18:24.249491+00:00 | 2022-12-01T14:43:00.846221+00:00 |
| 192.168.137.105 | LAN | True | dc:a6:32:dc:28:48 | 279 | whole span | - | dc:a6:32:dc:28:48 (unlisted) | 2022-12-01T14:32:07.367301+00:00 | 2022-12-01T14:43:00.473846+00:00 |
| 192.168.137.68 | LAN | True | dc:a6:32:dc:28:48 | 120 | whole span | - | dc:a6:32:dc:28:48 (unlisted);70:ee:50:68:0e:32 (Netatmo Camera) | 2022-11-29T19:18:31.145220+00:00 | 2022-11-29T19:28:41.669960+00:00 |
| fe80::7751:923:3c0f:1915 | LAN | True | dc:a6:32:c9:e4:c6 | 20 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:22:32.574197+00:00 | 2022-11-29T19:28:32.102332+00:00 |
| fe80::c202:f47b:52fb:af75 | LAN | True | dc:a6:32:dc:28:48 | 14 | whole span | - | dc:a6:32:dc:28:48 (unlisted) | 2022-11-29T19:22:32.553561+00:00 | 2022-12-01T14:42:59.412904+00:00 |
| 192.168.137.238 | LAN | True | dc:a6:32:c9:e4:c6 | 3 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:18:31.132548+00:00 | 2022-11-29T19:27:03.834647+00:00 |
| 192.168.137.166 | LAN | True | dc:a6:32:c9:e5:02 | 3 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:22:48.363366+00:00 | 2022-11-29T19:27:05.006106+00:00 |
| 192.168.137.243 | LAN | True | dc:a6:32:c9:e6:f4 | 2 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:23:17.456698+00:00 | 2022-11-29T19:26:01.846687+00:00 |
| 192.168.137.60 | LAN | True | dc:a6:32:c9:e4:c6 | 2 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-12-01T14:36:56.643096+00:00 | 2022-12-01T14:37:10.056792+00:00 |
| 192.168.137.200 | LAN | True | dc:a6:32:c9:e5:02 | 2 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-12-01T14:36:46.134952+00:00 | 2022-12-01T14:37:14.926412+00:00 |
| 192.168.137.76 | LAN | True | dc:a6:32:c9:e6:f4 | 2 | whole span | - | 68:57:2d:56:ac:47 (Atomi Coffee Maker);dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-12-01T14:36:55.241648+00:00 | 2022-12-01T14:37:19.267643+00:00 |
| fd5a:7bd:2aea:e111:a8a8:83b3:af26:994f | LAN | True | dc:a6:32:c9:e4:c6 | 1 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-11-29T19:23:02.110707+00:00 | 2022-11-29T19:23:02.110707+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e5ef | LAN | True | dc:a6:32:c9:e5:ef | 1 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-12-01T14:35:24.920203+00:00 | 2022-12-01T14:35:24.920203+00:00 |
| fdcc:d8dd:e1af:26ab:dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 1 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-12-01T14:36:49.088450+00:00 | 2022-12-01T14:36:49.088450+00:00 |
| fdcc:d8dd:e1af:26ab:b792:bd43:8ad5:20d4 | LAN | True | dc:a6:32:c9:e4:c6 | 1 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-12-01T14:37:04.254740+00:00 | 2022-12-01T14:37:04.254740+00:00 |
| fdcc:d8dd:e1af:26ab:e65f:1ff:fe55:90c4 | LAN | True | e4:5f:01:55:90:c4 | 1 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2022-12-01T14:39:29.523133+00:00 | 2022-12-01T14:39:29.523133+00:00 |
| fd5a:7bd:2aea:e111:dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 1 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-12-01T14:43:00.793627+00:00 | 2022-12-01T14:43:00.793627+00:00 |
| fe80::dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 1 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-12-01T14:43:00.612282+00:00 | 2022-12-01T14:43:00.612282+00:00 |

### Flows passing T1 only via T1b: 0

| outcome | without_T1b | with_T1b |
|---|---|---|
| attack | 3,095,108 | 3,095,108 |
| benign | 8,812 | 8,812 |
| excluded:attack_normal_service_ambiguous | 552 | 552 |
| excluded:attacker_normal_traffic | 60 | 60 |
| excluded:attacker_offwindow | 186 | 186 |
| excluded:spoof_collision | 0 | 0 |
| excluded:victim_ambiguous | 0 | 0 |

## Labels (3,104,718 flows)

| label | flows | pct |
|---|---|---|
| attack | 3,095,108 | 99.69 |
| benign | 8,812 | 0.284 |
| excluded | 798 | 0.026 |

### Excluded by reason

| reason | flows |
|---|---|
| attacker_offwindow | 186 |
| attacker_normal_traffic | 60 |
| victim_ambiguous | 0 |
| attack_normal_service_ambiguous | 552 |
| spoof_collision | 0 |

- attack by family: {'syn_flood': 3095108}
- pad_only: 3 attack flows (15 flows overall) pass T2 only thanks to the padding
- T4 flow mapping (attacker-MAC flows): {'icmp_error_pseudo_flows': 5, 'attacker_sent_no_packets': 564}
- **gateway-victim attack flows: 0** (unowned; non-iot victims total 5: {'iot': 3095103, 'unlisted': 5})

### By owner group (04 ownership)

| group | attack | benign | excluded |
|---|---|---|---|
| G1 | 3,095,100 | 6,085 | 639 |
| G2 | 0 | 1,365 | 0 |
| GEN | 3 | 88 | 21 |
| ungrouped | 0 | 0 | 0 |
| unowned | 5 | 1,274 | 138 |

### 04 exclude_reason x label

| exclude_reason | label | flows |
|---|---|---|
| (blank) | attack | 3,095,108 |
| (blank) | benign | 8,703 |
| (blank) | excluded | 798 |
| invalid_parse | benign | 23 |
| ip_clash_artifact | benign | 86 |

### Attack flows per victim device

| device | group | role | mac | attack_flows | 07a_reason | 07a_attack_packets |
|---|---|---|---|---|---|---|
| Sonos One Speaker | G1 | iot | 48:a6:b8:f9:1b:88 | 2,314,118 | both | 10,365,155 |
| Amazon Alexa Echo Dot 2 | G1 | iot | a0:d0:dc:c4:08:ff | 780,982 | both | 3,177,190 |
| unknown | unknown | unlisted | 00:02:75:f4:97:45 | 5 | both | 106 |
| Smart Board | GEN | iot | 00:02:75:f6:e3:cb | 3 | both | 126 |

### Attack flows per 07a burst window

| window | start | end | 07a_packets | attack_flows |
|---|---|---|---|---|
| 0 | 2022-11-29T19:18:00.000000+00:00 | 2022-11-29T19:22:00.000000+00:00 | 3,177,940 | 780,985 |
| 1 | 2022-12-01T14:32:00.000000+00:00 | 2022-12-01T14:44:00.000000+00:00 | 10,366,387 | 2,314,123 |

## Soft checks

### Victim groups vs 07a coverage

| group | victims_with_attack_flows | 07a_victims | 07a_verdict | verdict | match |
|---|---|---|---|---|---|
| G1 | 2 | 3 | PASS | PASS | ok |
| G2 | 0 | 0 | FAIL | FAIL | ok |
| GEN | 1 | 1 | FAIL | FAIL | ok |

- attack flows / 07a attacker packets: 0.228503 (3,095,108 / 13,545,175)
- benign flows inside a burst with a 07a victim on one side, by the other side's role: {'iot': 2269, 'external': 411, 'gateway': 56, 'excluded': 92, 'unknown': 53, 'broadcast': 35, 'unlisted': 66} (external / lan_unmapped here would be spoofed attack traffic that T1 cannot see)

### Benign owned-flow share per device vs the benign capture (largest differences)

| device | group | benign_flows_here | share_here_pct | share_benign_capture_pct | diff_pp |
|---|---|---|---|---|---|
| Fibaro Home Center Lite | G1 | 0 | 0.0 | 48.35 | -48.35 |
| Unidentified Amazon device (1c:12:b0) | G1 | 746 | 9.9 | 0.0 | 9.9 |
| Amazon Alexa Echo Dot 2 | G1 | 479 | 6.35 | 0.18 | 6.18 |
| Amazon Alexa Echo Dot 1 | G1 | 387 | 5.13 | 0.75 | 4.38 |
| Google Nest Mini Speaker | G1 | 454 | 6.02 | 1.85 | 4.17 |
| Home Eye Camera | G1 | 470 | 6.24 | 10.36 | -4.13 |
| Amazon Alexa Echo Studio | G1 | 413 | 5.48 | 1.55 | 3.93 |
| TP-Link Tapo Camera | G1 | 364 | 4.83 | 1.07 | 3.76 |
| Amazon Echo Show | G1 | 459 | 6.09 | 2.5 | 3.59 |
| AMCREST WiFi Camera | G1 | 293 | 3.89 | 1.16 | 2.73 |
| LG Smart TV | G1 | 0 | 0.0 | 2.03 | -2.03 |
| Harman Kardon speaker (Ampak) | G1 | 211 | 2.8 | 4.58 | -1.78 |
| Aeotec Smart Home Hub | G1 | 206 | 2.73 | 1.01 | 1.73 |
| Yi Indoor 2 Camera | G1 | 100 | 1.33 | 2.86 | -1.54 |
| Amazon Smart Plug | G2 | 106 | 1.41 | 0.15 | 1.26 |

### Per-attacker-MAC burst windows used for T2 (07a, anchored)

- dc:a6:32:c9:e4:90: 19:18:00-19:22:00 (2022-11-29); 14:32:00-14:44:00 (2022-12-01)
- dc:a6:32:c9:e4:ab: 19:18:00-19:22:00 (2022-11-29); 14:32:00-14:44:00 (2022-12-01)
- dc:a6:32:c9:e4:d5: 19:18:00-19:22:00 (2022-11-29); 14:32:00-14:44:00 (2022-12-01)
- dc:a6:32:c9:e5:a4: 19:18:00-19:22:00 (2022-11-29); 14:32:00-14:44:00 (2022-12-01)
- dc:a6:32:c9:e5:ef: 19:18:00-19:22:00 (2022-11-29); 14:32:00-14:43:00 (2022-12-01)
- dc:a6:32:dc:27:d5: 19:19:00-19:22:00 (2022-11-29); 14:32:00-14:44:00 (2022-12-01)
- e4:5f:01:55:90:c4: 19:18:00-19:22:00 (2022-11-29); 14:32:00-14:44:00 (2022-12-01)
