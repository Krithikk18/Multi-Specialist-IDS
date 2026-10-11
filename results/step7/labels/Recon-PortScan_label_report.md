# Step 7 -- attack labels: Recon-PortScan (port_scan)

- pcap `/home/krithikk/lgids_cache/ciciot2023/attack/Recon-PortScan/Recon-PortScan.pcap`; run 2026-10-11T13:51:34+00:00; runtime 40.1 s; peak RSS python 734.9 MB, largest child 1,680.8 MB
- flows `/home/krithikk/lgids_cache/flows/attack/Recon-PortScan/Recon-PortScan.pcap_Flow__singlepkt.csv` (extracted); 03b **WARN**
- map `/home/krithikk/lgids_cache/maps/Recon-PortScan_ip_mac_map.csv` (reused, 138 rows, 2 overlapping IP conflicts); conflict resolution {'conflicts': 2, 'ambiguous_on_conflict_ips': 1, 'prescan_seconds': 0.6, 'udp_flow_keys': 21663, 'packets_extracted': 1, 'tshark_seconds': 13.8, 'resolved_flows': 0, 'both_macs_in_flow': 0, 'ip_clash_artifact': 0, 'resolved_to': {}}
- 07a stats `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage/Recon-PortScan_stats.json`; pad ±60 s; K 10
- labelled CSV `/home/krithikk/lgids_cache/flows/attack/Recon-PortScan/Recon-PortScan_labelled.csv.gz`; timeline `Recon-PortScan_timeline.png`
- spoof: collision IPs none (07a: 0 device-IP collisions, 10 distinct attacker ip.src)

## Hard checks: **PASS**

| check | value | result |
|---|---|---|
| attack flows outside 07a burst windows (+pad) | 0 | PASS |
| attack flows whose victim is not a 07a victim | 0 | PASS |
| flows without exactly one outcome | 0 | PASS |
| rows written == flow CSV rows == meta row_count | 207,429 / 207,429 | PASS |
| label counts sum to rows | 207,429 | PASS |

## Attacker IP set (T1b): 21 IPs (20 LAN, 1 external / other; 20 unicast used for T1b) from 147,498 attacker-MAC packets

| ip | scope | used_for_T1b | attacker_macs | packets | resolves_to_attacker | non_attacker_host_overlaps | map_macs | first_utc | last_utc |
|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.178 | LAN | True | dc:a6:32:dc:27:d5 | 143,354 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-09-26T16:31:40.375520+00:00 | 2022-09-27T17:14:48.151614+00:00 |
| 192.168.137.98 | LAN | True | dc:a6:32:dc:28:48 | 3,519 | whole span | - | dc:a6:32:dc:28:48 (unlisted) | 2022-09-26T16:31:21.582408+00:00 | 2022-09-27T17:15:34.253787+00:00 |
| 192.168.137.217 | LAN | True | dc:a6:32:c9:e5:02 | 164 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-09-26T17:15:35.722941+00:00 | 2022-09-27T15:00:51.058719+00:00 |
| 192.168.137.86 | LAN | True | dc:a6:32:c9:e4:c6 | 9 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-09-26T16:31:03.143732+00:00 | 2022-09-27T14:59:31.487245+00:00 |
| fe80::dea6:32ff:fec9:e502 | LAN | True | dc:a6:32:c9:e5:02 | 7 | whole span | - | dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB)) | 2022-09-26T16:37:26.713617+00:00 | 2022-09-27T14:41:08.180753+00:00 |
| 192.168.137.4 | LAN | True | dc:a6:32:c9:e6:f4 | 5 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-09-26T17:23:45.833805+00:00 | 2022-09-27T15:25:04.388534+00:00 |
| fe80::dea6:32ff:fec9:e490 | LAN | True | dc:a6:32:c9:e4:90 | 4 | whole span | - | dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB)) | 2022-09-26T16:49:53.672048+00:00 | 2022-09-27T17:12:44.217479+00:00 |
| fe80::dea6:32ff:fec9:e4ab | LAN | True | dc:a6:32:c9:e4:ab | 4 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-09-26T17:27:43.487155+00:00 | 2022-09-27T15:27:43.619116+00:00 |
| fe80::dea6:32ff:fec9:e5a4 | LAN | True | dc:a6:32:c9:e5:a4 | 4 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-09-26T16:55:03.492560+00:00 | 2022-09-27T16:47:22.975178+00:00 |
| fe80::e65f:1ff:fe55:90c4 | LAN | True | e4:5f:01:55:90:c4 | 4 | whole span | - | e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB)) | 2022-09-26T16:55:09.711697+00:00 | 2022-09-27T15:25:33.280086+00:00 |
| 192.168.137.127 | LAN | True | dc:a6:32:c9:e5:a4 | 3 | whole span | - | dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB)) | 2022-09-26T16:50:27.404365+00:00 | 2022-09-27T14:50:27.615440+00:00 |
| fe80::dea6:32ff:fec9:e5ef | LAN | True | dc:a6:32:c9:e5:ef | 3 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-09-26T16:37:59.549707+00:00 | 2022-09-27T14:49:43.137414+00:00 |
| 192.168.137.27 | LAN | True | dc:a6:32:c9:e4:ab | 2 | whole span | - | dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB)) | 2022-09-27T13:51:51.462421+00:00 | 2022-09-27T14:51:51.497234+00:00 |
| fe80::7751:923:3c0f:1915 | LAN | True | dc:a6:32:c9:e4:c6 | 2 | whole span | - | dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB)) | 2022-09-26T17:23:41.773556+00:00 | 2022-09-27T14:23:41.890544+00:00 |
| fe80::dea6:32ff:fec9:e4d5 | LAN | True | dc:a6:32:c9:e4:d5 | 2 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-09-26T17:03:20.512946+00:00 | 2022-09-26T18:22:22.519784+00:00 |
| 0.0.0.0 | unspecified | False | dc:a6:32:c9:e5:02 | 2 | no | - | - | 2022-09-26T17:15:29.900559+00:00 | 2022-09-26T18:15:30.080324+00:00 |
| fe80::dea6:32ff:fec9:e6f4 | LAN | True | dc:a6:32:c9:e6:f4 | 2 | whole span | - | dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB)) | 2022-09-26T18:39:44.997834+00:00 | 2022-09-27T14:38:06.045848+00:00 |
| fe80::dea6:32ff:fedc:27d5 | LAN | True | dc:a6:32:dc:27:d5 | 2 | whole span | - | dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB)) | 2022-09-26T18:22:21.809128+00:00 | 2022-09-26T18:25:04.651959+00:00 |
| fe80::c202:f47b:52fb:af75 | LAN | True | dc:a6:32:dc:28:48 | 2 | whole span | - | dc:a6:32:dc:28:48 (unlisted) | 2022-09-26T17:02:55.552107+00:00 | 2022-09-27T14:50:16.292848+00:00 |
| 192.168.137.64 | LAN | True | dc:a6:32:c9:e4:d5 | 1 | whole span | - | dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB)) | 2022-09-27T13:54:46.045268+00:00 | 2022-09-27T13:54:46.045268+00:00 |
| 192.168.137.151 | LAN | True | dc:a6:32:c9:e5:ef | 1 | whole span | - | dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB)) | 2022-09-27T13:53:13.195066+00:00 | 2022-09-27T13:53:13.195066+00:00 |

### Flows passing T1 only via T1b: 0

| outcome | without_T1b | with_T1b |
|---|---|---|
| attack | 143,138 | 143,138 |
| benign | 63,341 | 63,341 |
| excluded:attack_normal_service_ambiguous | 86 | 86 |
| excluded:attacker_normal_traffic | 24 | 24 |
| excluded:attacker_offwindow | 840 | 840 |
| excluded:spoof_collision | 0 | 0 |
| excluded:victim_ambiguous | 0 | 0 |

## Labels (207,429 flows)

| label | flows | pct |
|---|---|---|
| attack | 143,138 | 69.006 |
| benign | 63,341 | 30.536 |
| excluded | 950 | 0.458 |

### Excluded by reason

| reason | flows |
|---|---|
| attacker_offwindow | 840 |
| attacker_normal_traffic | 24 |
| victim_ambiguous | 0 |
| attack_normal_service_ambiguous | 86 |
| spoof_collision | 0 |

- attack by family: {'port_scan': 143138}
- pad_only: 272 attack flows (274 flows overall) pass T2 only thanks to the padding
- T4 flow mapping (attacker-MAC flows): {'icmp_error_pseudo_flows': 0, 'attacker_sent_no_packets': 194}
- **gateway-victim attack flows: 0** (unowned; non-iot victims total 4,172: {'iot': 138966, 'unlisted': 4172})

### By owner group (04 ownership)

| group | attack | benign | excluded |
|---|---|---|---|
| G1 | 70,026 | 54,094 | 89 |
| G2 | 64,584 | 2,975 | 17 |
| GEN | 4,356 | 1,373 | 0 |
| ungrouped | 0 | 0 | 0 |
| unowned | 4,172 | 4,899 | 844 |

### 04 exclude_reason x label

| exclude_reason | label | flows |
|---|---|---|
| (blank) | attack | 143,138 |
| (blank) | benign | 63,212 |
| (blank) | excluded | 950 |
| invalid_parse | benign | 128 |
| ip_conflict_unresolved | benign | 1 |

### Attack flows per victim device

| device | group | role | mac | attack_flows | 07a_reason | 07a_attack_packets |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Studio | G1 | iot | 08:7c:39:ce:6e:2a | 7,006 | both | 7,012 |
| Home Eye Camera | G1 | iot | 34:75:63:73:f3:36 | 5,002 | both | 5,009 |
| Nest Indoor Camera | G2 | iot | 44:bb:3b:00:39:07 | 4,363 | both | 4,365 |
| Amazon Smart Plug | G2 | iot | b8:5f:98:d0:76:e6 | 4,282 | both | 4,282 |
| Netatmo Camera | G1 | iot | 70:ee:50:68:0e:32 | 4,015 | both | 4,039 |
| Unidentified ESP plug (2) | G2 | iot | 50:02:91:10:09:8f | 3,815 | both | 3,822 |
| Harman Kardon speaker (Ampak) | G1 | iot | b0:f1:ec:d3:e7:98 | 3,765 | both | 3,783 |
| Atomi Coffee Maker | G2 | iot | 68:57:2d:56:ac:47 | 3,465 | both | 3,469 |
| Yi Indoor 2 Camera | G1 | iot | 84:7a:b6:62:3a:6c | 3,323 | both | 3,326 |
| AMCREST WiFi Camera | G1 | iot | 9c:8e:cd:1d:ab:9f | 3,306 | both | 3,321 |
| Arlo Q Indoor Camera | G1 | iot | 40:5d:82:35:14:c8 | 3,280 | both | 3,282 |
| Rbcior Camera | G1 | iot | 10:5a:17:97:a5:c6 | 3,192 | both | 3,198 |
| HeimVision Smart WiFi Camera | G2 | iot | 44:01:bb:ec:10:4a | 3,088 | both | 3,101 |
| Eufy HomeBase 2 | G1 | iot | 8c:85:80:6c:b6:47 | 3,003 | both | 3,013 |
| Sonos One Speaker | G1 | iot | 48:a6:b8:f9:1b:88 | 3,001 | both | 3,009 |
| Arlo Base Station | G1 | iot | 3c:37:86:6f:b9:51 | 3,001 | both | 3,014 |
| Google Nest Mini Speaker | G1 | iot | cc:f4:11:9c:d0:00 | 2,999 | new_service | 3,018 |
| Levoit Air Purifier | G2 | iot | 1c:9d:c2:8c:9a:94 | 2,756 | both | 2,758 |
| Yi Outdoor Camera | G1 | iot | 2c:d2:6b:66:d2:87 | 2,468 | both | 2,471 |
| Aeotec Smart Home Hub | G1 | iot | 28:6d:97:9e:f4:d5 | 2,458 | both | 2,465 |
| Cocoon Smart HVAC Fan | G2 | iot | 08:3a:f2:1f:bc:68 | 2,382 | both | 2,383 |
| HeimVision SmartLife Radio/Lamp | G2 | iot | d4:a6:51:30:64:b7 | 2,279 | both | 2,281 |
| Unidentified ESP plug (4) | G2 | iot | c4:dd:57:13:07:c6 | 2,235 | both | 2,237 |
| GoSund Smart Plug WP2 (2) | G2 | iot | 50:02:91:10:ac:d8 | 2,184 | both | 2,186 |
| GoSund Power Strip (2) | G2 | iot | b8:f0:09:03:9a:af | 2,178 | both | 2,180 |
| GoSund Smart Plug WP2 (1) | G2 | iot | b8:f0:09:03:29:79 | 2,177 | both | 2,180 |
| Teckin Light Strip | G2 | iot | 18:69:d8:eb:d4:3e | 2,175 | both | 2,177 |
| Unidentified ESP plug (1) | G2 | iot | 24:a1:60:14:7f:f9 | 2,171 | both | 2,173 |
| Yutron Plug 2 | G2 | iot | d4:a6:51:21:6c:29 | 2,170 | both | 2,172 |
| unknown | unknown | unlisted | 50:02:91:b1:68:0c | 2,169 | both | 2,171 |
| Lumiman Bulb | G2 | iot | 84:e3:42:42:ed:0b | 2,138 | both | 2,140 |
| SmartThings Hub | G1 | iot | 28:6d:97:7a:2b:2d | 2,132 | both | 2,135 |
| GoSund Power Strip (1) | G2 | iot | 50:02:91:1a:ce:e1 | 2,129 | both | 2,131 |
| Unidentified ESP plug (3) | G2 | iot | c4:dd:57:0c:39:94 | 2,128 | both | 2,130 |
| Teckin Plug 2 | G2 | iot | d4:a6:51:78:97:4e | 2,118 | both | 2,120 |
| Govee Smart Humidifier | G2 | iot | d4:ad:fc:29:c8:a2 | 2,096 | both | 2,096 |
| D-Link DCS8000LHA1 Mini Camera | G2 | iot | b0:c5:54:59:2e:99 | 2,054 | both | 2,064 |
| Yutron Plug 1 | G2 | iot | d4:a6:51:20:91:d1 | 2,030 | both | 2,032 |
| Fibaro Home Center Lite | G1 | iot | ac:17:02:05:34:27 | 2,008 | both | 2,018 |
| LIFX Lightbulb | G2 | iot | d0:73:d5:35:fb:c8 | 2,005 | both | 2,007 |
| unknown | unknown | unlisted | c0:e7:bf:0a:79:d1 | 2,003 | both | 2,006 |
| Wemo Smart Plug 1 | GEN | iot | 30:23:03:f3:84:2b | 2,002 | both | 2,003 |
| Netatmo Weather Station | G2 | iot | 70:ee:50:6b:a8:1a | 2,002 | both | 2,009 |
| TP-Link Tapo Camera | G1 | iot | 6c:5a:b0:44:1d:90 | 2,001 | both | 2,010 |
| Wemo Smart Plug 2 | G1 | iot | 30:23:03:f3:57:cb | 2,001 | both | 2,008 |
| Yi Indoor Camera | G1 | iot | 84:7a:b6:64:62:58 | 2,001 | both | 2,003 |
| Unidentified Amazon device (1c:12:b0) | G1 | iot | 1c:12:b0:9b:0c:ec | 2,000 | both | 2,002 |
| Amazon Echo Show | G1 | iot | 2c:71:ff:05:f1:15 | 2,000 | new_service | 2,019 |
| Ring Base Station | G2 | iot | b0:09:da:3e:82:6c | 2,000 | both | 2,002 |
| LG Smart TV | G1 | iot | ac:f1:08:4e:00:82 | 1,998 | new_service | 2,012 |
| Amazon Alexa Echo Dot 1 | G1 | iot | 1c:fe:2b:98:16:dd | 1,957 | both | 1,961 |
| iRobot Roomba | GEN | iot | 50:14:79:37:80:18 | 1,350 | both | 1,352 |
| LampUX RGB | G2 | iot | f4:cf:a2:34:48:6b | 1,151 | both | 1,152 |
| Philips Hue Bridge | G1 | iot | 00:17:88:60:d6:4f | 1,108 | new_service | 1,114 |
| Teckin Plug 1 | G2 | iot | d4:a6:51:76:06:64 | 1,013 | both | 1,032 |
| Smart Board | GEN | iot | 00:02:75:f6:e3:cb | 1,004 | both | 1,005 |
| Wyze Camera | G1 | iot | 7c:78:b2:86:0d:81 | 1,001 | both | 1,002 |

### Attack flows per 07a burst window

| window | start | end | 07a_packets | attack_flows |
|---|---|---|---|---|
| 0 | 2022-09-26T16:31:00.000000+00:00 | 2022-09-26T16:32:00.000000+00:00 | 1,986 | 1,957 |
| 1 | 2022-09-26T16:42:00.000000+00:00 | 2022-09-26T16:43:00.000000+00:00 | 2,030 | 2,000 |
| 2 | 2022-09-26T16:49:00.000000+00:00 | 2022-09-26T16:51:00.000000+00:00 | 7,003 | 7,006 |
| 3 | 2022-09-26T16:54:00.000000+00:00 | 2022-09-26T16:55:00.000000+00:00 | 3,049 | 2,999 |
| 4 | 2022-09-26T17:02:00.000000+00:00 | 2022-09-26T17:30:00.000000+00:00 | 36,090 | 35,341 |
| 5 | 2022-09-26T18:12:00.000000+00:00 | 2022-09-26T18:40:00.000000+00:00 | 23,675 | 23,005 |
| 6 | 2022-09-26T18:44:00.000000+00:00 | 2022-09-26T18:45:00.000000+00:00 | 2,229 | 2,414 |
| 7 | 2022-09-26T18:58:00.000000+00:00 | 2022-09-26T18:59:00.000000+00:00 | 1,150 | 1,108 |
| 8 | 2022-09-26T19:04:00.000000+00:00 | 2022-09-26T19:08:00.000000+00:00 | 2,477 | 2,354 |
| 9 | 2022-09-27T13:44:00.000000+00:00 | 2022-09-27T13:55:00.000000+00:00 | 7,664 | 7,331 |
| 10 | 2022-09-27T13:59:00.000000+00:00 | 2022-09-27T14:09:00.000000+00:00 | 8,453 | 8,226 |
| 11 | 2022-09-27T14:14:00.000000+00:00 | 2022-09-27T14:24:00.000000+00:00 | 8,643 | 8,477 |
| 12 | 2022-09-27T14:29:00.000000+00:00 | 2022-09-27T14:46:00.000000+00:00 | 13,124 | 12,555 |
| 13 | 2022-09-27T14:49:00.000000+00:00 | 2022-09-27T14:51:00.000000+00:00 | 3,863 | 3,765 |
| 14 | 2022-09-27T14:58:00.000000+00:00 | 2022-09-27T14:59:00.000000+00:00 | 2,053 | 1,998 |
| 15 | 2022-09-27T15:02:00.000000+00:00 | 2022-09-27T15:03:00.000000+00:00 | 2,135 | 2,096 |
| 16 | 2022-09-27T15:08:00.000000+00:00 | 2022-09-27T15:10:00.000000+00:00 | 2,425 | 2,382 |
| 17 | 2022-09-27T15:24:00.000000+00:00 | 2022-09-27T15:28:00.000000+00:00 | 5,291 | 5,193 |
| 18 | 2022-09-27T16:47:00.000000+00:00 | 2022-09-27T16:48:00.000000+00:00 | 2,304 | 2,279 |
| 19 | 2022-09-27T17:00:00.000000+00:00 | 2022-09-27T17:01:00.000000+00:00 | 2,101 | 2,054 |
| 20 | 2022-09-27T17:04:00.000000+00:00 | 2022-09-27T17:05:00.000000+00:00 | 2,067 | 2,008 |
| 21 | 2022-09-27T17:08:00.000000+00:00 | 2022-09-27T17:15:00.000000+00:00 | 6,710 | 6,590 |

## Soft checks

### Victim groups vs 07a coverage

| group | victims_with_attack_flows | 07a_victims | 07a_verdict | verdict | match |
|---|---|---|---|---|---|
| G1 | 25 | 25 | PASS | PASS | ok |
| G2 | 27 | 27 | PASS | PASS | ok |
| GEN | 3 | 3 | PASS | PASS | ok |

- attack flows / 07a attacker packets: 0.97044 (143,138 / 147,498)
- benign flows inside a burst with a 07a victim on one side, by the other side's role: {'external': 33281, 'gateway': 10782, 'unlisted': 7443, 'iot': 5255, 'broadcast': 2493, 'unknown': 417, 'excluded': 272} (external / lan_unmapped here would be spoofed attack traffic that T1 cannot see)

### Benign owned-flow share per device vs the benign capture (largest differences)

| device | group | benign_flows_here | share_here_pct | share_benign_capture_pct | diff_pp |
|---|---|---|---|---|---|
| Wemo Smart Plug 2 | G1 | 7,205 | 12.33 | 0.22 | 12.1 |
| Yi Indoor 2 Camera | G1 | 218 | 0.37 | 2.86 | -2.49 |
| Smart Board | GEN | 1,298 | 2.22 | 0.03 | 2.19 |
| Home Eye Camera | G1 | 4,823 | 8.25 | 10.36 | -2.11 |
| Wyze Camera | G1 | 1,549 | 2.65 | 4.58 | -1.93 |
| Unidentified Amazon device (1c:12:b0) | G1 | 1,088 | 1.86 | 0.0 | 1.86 |
| LG Smart TV | G1 | 333 | 0.57 | 2.03 | -1.46 |
| Yi Indoor Camera | G1 | 39 | 0.07 | 1.34 | -1.27 |
| Arlo Q Indoor Camera | G1 | 354 | 0.61 | 1.79 | -1.18 |
| Fibaro Home Center Lite | G1 | 28,842 | 49.35 | 48.35 | 1.0 |
| Harman Kardon speaker (Ampak) | G1 | 2,147 | 3.67 | 4.58 | -0.91 |
| Amazon Echo Show | G1 | 947 | 1.62 | 2.5 | -0.88 |
| Rbcior Camera | G1 | 49 | 0.08 | 0.84 | -0.76 |
| Amazon Alexa Echo Dot 2 | G1 | 431 | 0.74 | 0.18 | 0.56 |
| Eufy HomeBase 2 | G1 | 573 | 0.98 | 1.48 | -0.5 |

### Per-attacker-MAC burst windows used for T2 (07a, anchored)

- dc:a6:32:dc:27:d5: 16:31:00-16:32:00 (2022-09-26); 16:42:00-16:43:00 (2022-09-26); 16:49:00-16:51:00 (2022-09-26); 16:54:00-16:55:00 (2022-09-26); 17:02:00-17:30:00 (2022-09-26); 18:12:00-18:40:00 (2022-09-26); 18:44:00-18:45:00 (2022-09-26); 18:58:00-18:59:00 (2022-09-26); 19:04:00-19:08:00 (2022-09-26); 13:44:00-13:55:00 (2022-09-27); 13:59:00-14:09:00 (2022-09-27); 14:14:00-14:24:00 (2022-09-27); 14:29:00-14:46:00 (2022-09-27); 14:49:00-14:51:00 (2022-09-27); 14:58:00-14:59:00 (2022-09-27); 15:02:00-15:03:00 (2022-09-27); 15:08:00-15:10:00 (2022-09-27); 15:24:00-15:28:00 (2022-09-27); 16:47:00-16:48:00 (2022-09-27); 17:00:00-17:01:00 (2022-09-27); 17:04:00-17:05:00 (2022-09-27); 17:08:00-17:15:00 (2022-09-27)
