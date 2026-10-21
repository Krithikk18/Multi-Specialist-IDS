# Step 13 -- rate_guard calibration on benign train / val packets (PROPOSAL ONLY -- thresholds are proposed here, not decided)

- run 2026-10-21T15:21:25+00:00, git HEAD `d5cd50aa0e30f0f14842db7f80cf8de267c4951b`, 13_rate_guard_calibrate.py sha256 `3425334cb5aa1e42...`, rate_guard.py sha256 `ba7ebfa44ba1f431...`, runtime 990 s, peak RSS python 135 MB / tshark 144 MB
- input checks: 24/24 PASS; guard consistency checks: 30/30 PASS
- sessions read (train / val only, cuts from results/step8/manifest_v1.json, 08's rule on packet time): benign_night (time_split, filter `frame.time_epoch < 1665191229.650000`), DDoS-SYN_Flood (train, filter `none`), DDoS-SYN_Flood5 (train, filter `none`), Recon-PortScan (time_split, filter `frame.time_epoch < 1664291060.800000`), Mirai-udpplain (train, filter `none`)
- never opened: DDoS-SYN_Flood10 / 15, Mirai-udpplain24 (test), BenignTraffic1-3 (test_only), any greeth part, test.parquet; packets at or after the val -> test gap start are dropped inside tshark
- packets: tshark outer-header fields (-E occurrence=f), IPv4 only, no protocol filter; RateGuard per capture x split x window, TCP / UDP = clock ticks, flush() per capture; percentiles over NON-EMPTY windows (nearest rank)
- exclusion: EVERY capture (benign_night included) drops packets with an attacker / testbed-Pi MAC on either side (ATTACKER_MACS or device_table role testbed_pi); phone / laptop packets stay in and are reported as shares

- cross-check vs 12c's benign_night train census (before the Pi exclusion; 12c did not exclude): IPv4 2,395,158 here vs 2,395,158; non-TCP/UDP 36,287 vs 36,287 -> MATCH

## 1. Per session

### train

| session | mode | ipv4_packets | excluded_packets | excluded_in_scope | kept_packets | in_scope_packets | in_scope_by_proto | phone_in_scope | windows_10s | late_10s | first_packet_utc | last_packet_utc | runtime_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign_night | time_split | 2,395,158 | 23,469 | 1,925 | 2,371,689 | 34,362 | ICMP: 33,644; IGMP: 718 | 1,338 | 2,305 | 0 | 2022-10-07T17:15:00.350Z | 2022-10-07T23:43:50.297Z | 50.30 |
| DDoS-SYN_Flood | train | 22,805,264 | 22,659,532 | 0 | 145,732 | 5,304 | ICMP: 5,206; IGMP: 98 | 0 | 204 | 0 | 2022-08-26T18:18:00.516Z | 2022-08-26T19:07:38.649Z | 427.90 |
| DDoS-SYN_Flood5 | train | 22,257,594 | 22,180,901 | 3 | 76,693 | 3,942 | ICMP: 3,891; IGMP: 51 | 0 | 122 | 0 | 2022-08-29T17:20:34.268Z | 2022-08-29T17:44:54.268Z | 434.50 |
| Recon-PortScan | time_split | 490,626 | 192,030 | 10 | 298,596 | 4,916 | ICMP: 4,746; IGMP: 170 | 93 | 491 | 0 | 2022-09-26T16:31:00.218Z | 2022-09-27T14:25:00.757Z | 13.30 |
| Mirai-udpplain | train | 3,275,152 | 3,214,995 | 81 | 60,157 | 3,699 | ICMP: 3,627; IGMP: 72 | 96 | 131 | 0 | 2023-01-19T15:51:00.595Z | 2023-01-19T16:19:01.077Z | 62.00 |

### val

| session | mode | ipv4_packets | excluded_packets | excluded_in_scope | kept_packets | in_scope_packets | in_scope_by_proto | phone_in_scope | windows_10s | late_10s | first_packet_utc | last_packet_utc | runtime_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign_night | time_split | 597,492 | 5,438 | 475 | 592,054 | 3,651 | ICMP: 3,417; IGMP: 234 | 420 | 468 | 0 | 2022-10-07T23:45:50.303Z | 2022-10-08T01:07:09.599Z | 50.30 |
| DDoS-SYN_Flood | train | 2,895,782 | 2,878,513 | 0 | 17,269 | 260 | ICMP: 252; IGMP: 8 | 0 | 27 | 0 | 2022-08-29T12:27:00.356Z | 2022-08-29T12:31:44.251Z | 427.90 |
| DDoS-SYN_Flood5 | train | 2,273,559 | 2,265,396 | 0 | 8,163 | 266 | ICMP: 264; IGMP: 2 | 0 | 15 | 0 | 2022-08-29T17:46:54.363Z | 2022-08-29T17:57:10.749Z | 434.50 |
| Recon-PortScan | time_split | 137,970 | 34,989 | 0 | 102,981 | 1,320 | ICMP: 1,275; IGMP: 45 | 28 | 125 | 0 | 2022-09-27T14:30:38.609Z | 2022-09-27T15:04:00.701Z | 13.30 |
| Mirai-udpplain | train | 347,514 | 344,256 | 288 | 3,258 | 122 | ICMP: 118; IGMP: 4 | 0 | 9 | 0 | 2023-01-19T16:22:00.567Z | 2023-01-19T16:23:26.511Z | 62.00 |

Excluded packets (attacker / testbed-Pi MAC, every capture) by reason, protocol mix and MAC:

| session | split | excluded_packets | excluded_by_reason | excluded_by_proto | excluded_by_mac |
|---|---|---|---|---|---|
| benign_night | train | 23,469 | eth.dst ATTACKER_MACS: 11,199; eth.src ATTACKER_MACS: 12,270 | TCP: 14,266; UDP: 7,278; ICMP: 1,923; IGMP: 2 | Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 23,286; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 65; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:c6): 31; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 29; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 14; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 13; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 13; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 11; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 5; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 2 |
| benign_night | val | 5,438 | eth.dst ATTACKER_MACS: 2,658; eth.src ATTACKER_MACS: 2,780 | TCP: 3,079; UDP: 1,884; ICMP: 465; IGMP: 10 | Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 5,207; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:c6): 104; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 69; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 47; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 2; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 1 |
| DDoS-SYN_Flood | train | 22,659,532 | eth.dst ATTACKER_MACS: 384,013; eth.src ATTACKER_MACS: 22,275,519 | TCP: 22,659,498; UDP: 34 | Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 5,717,833; Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 3,905,080; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 3,782,016; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 3,377,047; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 3,176,763; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 2,699,041; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 1,732; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 10; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:c6): 5; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 5 |
| DDoS-SYN_Flood | val | 2,878,513 | eth.dst ATTACKER_MACS: 10,766; eth.src ATTACKER_MACS: 2,867,747 | TCP: 2,878,513 | Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 1,152,010; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 436,117; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 361,257; Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 330,095; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 307,925; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 290,786; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 323 |
| DDoS-SYN_Flood5 | train | 22,180,901 | eth.dst ATTACKER_MACS: 202; eth.src ATTACKER_MACS: 22,180,699 | TCP: 22,180,781; UDP: 117; ICMP: 3 | Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 3,636,205; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 3,346,020; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 3,292,700; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 3,179,548; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 3,102,629; Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 3,055,502; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 2,568,178; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 56; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 40; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:c6): 23 |
| DDoS-SYN_Flood5 | val | 2,265,396 | eth.dst ATTACKER_MACS: 23; eth.src ATTACKER_MACS: 2,265,373 | TCP: 2,265,388; UDP: 8 | Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 410,241; Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 408,372; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 380,561; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 374,844; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 364,110; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 326,160; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 1,100; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 6; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 2 |
| Recon-PortScan | train | 192,030 | eth.dst ATTACKER_MACS: 87,239; eth.src ATTACKER_MACS: 104,791 | TCP: 191,394; UDP: 626; ICMP: 6; IGMP: 4 | Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 186,852; attacker dc:a6:32:dc:28:48 (dc:a6:32:dc:28:48): 5,089; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 65; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:c6): 12; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 4; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 3; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 1 |
| Recon-PortScan | val | 34,989 | eth.dst ATTACKER_MACS: 16,126; eth.src ATTACKER_MACS: 18,863 | TCP: 34,825; UDP: 164 | Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 33,600; attacker dc:a6:32:dc:28:48 (dc:a6:32:dc:28:48): 1,375; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:c6): 4; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 1; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 1; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 1; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 1 |
| Mirai-udpplain | train | 3,214,995 | eth.dst ATTACKER_MACS: 465; eth.src ATTACKER_MACS: 3,214,530 | UDP: 3,214,428; TCP: 486; ICMP: 81 | Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 692,071; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 599,244; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 582,883; Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 395,895; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 352,870; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 337,193; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 254,790; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e6:f4): 45; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:02): 2; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:c6): 2 |
| Mirai-udpplain | val | 344,256 | eth.dst ATTACKER_MACS: 305; eth.src ATTACKER_MACS: 343,951 | UDP: 343,903; ICMP: 288; TCP: 65 | Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:90): 75,516; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:d5): 61,023; Raspberry Pi 4 (8 GB) [testbed_pi] (dc:a6:32:dc:27:d5): 46,081; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:a4): 45,395; Raspberry Pi 4 (4 GB) [testbed_pi] (e4:5f:01:55:90:c4): 41,653; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e4:ab): 39,964; Raspberry Pi 4 (2 GB) [testbed_pi] (dc:a6:32:c9:e5:ef): 34,624 |

Per capture: benign_night gap dropped 15,092, non-IPv4 110,347, tshark+loop 48 s; DDoS-SYN_Flood gap dropped 857,360, non-IPv4 38,605, tshark+loop 425 s; DDoS-SYN_Flood5 gap dropped 2,162,316, non-IPv4 26,667, tshark+loop 430 s; Recon-PortScan gap dropped 10,236, non-IPv4 24,717, tshark+loop 13 s; Mirai-udpplain gap dropped 0, non-IPv4 19,603, tshark+loop 58 s

## 2. Per level x proto (10 s windows)

dst_scope: all = pooled; unicast; mcast_bcast = multicast 224.0.0.0/4 + broadcast (flagged separately). windows_at_max = windows that reach the max; up to 3 distinct keys are listed (' | '-separated, same order in every max_* column). Devices from the MACs seen on the key's packets (07 device_table mapping).

### train -- stream

| proto_class | proto | dst_scope | nonempty_windows | max_packets | p99 | p99_9 | max_rate_pps | windows_at_max | max_keys | max_senders | max_receivers | max_session | max_window_start_utc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ICMP | all | all | 14,848 | 53 | 13.00 | 19.00 | 5.30 | 1 | 192.168.137.109 -> 192.168.137.1 ICMP | Teckin Light Strip | Gateway / router [gateway] | Mirai-udpplain | 2023-01-19T15:56:50.000Z |
| ICMP | all | unicast | 14,848 | 53 | 13.00 | 19.00 | 5.30 | 1 | 192.168.137.109 -> 192.168.137.1 ICMP | Teckin Light Strip | Gateway / router [gateway] | Mirai-udpplain | 2023-01-19T15:56:50.000Z |
| IGMP | all | all | 616 | 4 | 3.00 | 4.00 | 0.40 | 6 | 192.168.137.12 -> 224.0.0.22 IGMP | 192.168.137.99 -> 224.0.0.22 IGMP | 192.168.137.253 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | Unidentified Amazon device (1c:12:b0) | LG Smart TV | multicast 01:00:5e:00:00:16 | multicast 01:00:5e:00:00:16 | multicast 01:00:5e:00:00:16 | DDoS-SYN_Flood | DDoS-SYN_Flood | benign_night | 2022-08-26T18:58:40.000Z | 2022-08-26T19:06:40.000Z | 2022-10-07T20:30:20.000Z |
| IGMP | all | mcast_bcast | 616 | 4 | 3.00 | 4.00 | 0.40 | 6 | 192.168.137.12 -> 224.0.0.22 IGMP | 192.168.137.99 -> 224.0.0.22 IGMP | 192.168.137.253 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | Unidentified Amazon device (1c:12:b0) | LG Smart TV | multicast 01:00:5e:00:00:16 | multicast 01:00:5e:00:00:16 | multicast 01:00:5e:00:00:16 | DDoS-SYN_Flood | DDoS-SYN_Flood | benign_night | 2022-08-26T18:58:40.000Z | 2022-08-26T19:06:40.000Z | 2022-10-07T20:30:20.000Z |
| DEFAULT | all | all | 0 | 0 | N/A | N/A | 0.00 | 0 |  |  |  |  |  |

### train -- victim

| proto_class | proto | dst_scope | nonempty_windows | max_packets | p99 | p99_9 | max_rate_pps | windows_at_max | max_keys | max_senders | max_receivers | max_session | max_window_start_utc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ICMP | all | all | 11,772 | 107 | 19.00 | 28.00 | 10.70 | 1 | * -> 192.168.137.1 ICMP | Arlo Base Station; Google Nest Mini Speaker; Unknown [unknown]; Wyze Camera; Yi Indoor Camera; unlisted c0:e7:bf:0a:79:d1 (+more) | Gateway / router [gateway] | Mirai-udpplain | 2023-01-19T15:56:50.000Z |
| ICMP | all | unicast | 11,772 | 107 | 19.00 | 28.00 | 10.70 | 1 | * -> 192.168.137.1 ICMP | Arlo Base Station; Google Nest Mini Speaker; Unknown [unknown]; Wyze Camera; Yi Indoor Camera; unlisted c0:e7:bf:0a:79:d1 (+more) | Gateway / router [gateway] | Mirai-udpplain | 2023-01-19T15:56:50.000Z |
| IGMP | all | all | 579 | 11 | 4.00 | 11.00 | 1.10 | 1 | * -> 224.0.0.22 IGMP | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Netatmo Camera; Philips Hue Bridge | multicast 01:00:5e:00:00:16 | Mirai-udpplain | 2023-01-19T15:58:20.000Z |
| IGMP | all | mcast_bcast | 579 | 11 | 4.00 | 11.00 | 1.10 | 1 | * -> 224.0.0.22 IGMP | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Netatmo Camera; Philips Hue Bridge | multicast 01:00:5e:00:00:16 | Mirai-udpplain | 2023-01-19T15:58:20.000Z |
| DEFAULT | all | all | 0 | 0 | N/A | N/A | 0.00 | 0 |  |  |  |  |  |

### val -- stream

| proto_class | proto | dst_scope | nonempty_windows | max_packets | p99 | p99_9 | max_rate_pps | windows_at_max | max_keys | max_senders | max_receivers | max_session | max_window_start_utc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ICMP | all | all | 2,409 | 19 | 10.00 | 17.00 | 1.90 | 1 | 192.168.137.190 -> 192.168.137.50 ICMP | Unknown [unknown] | Unidentified ESP plug (2) | DDoS-SYN_Flood5 | 2022-08-29T17:47:00.000Z |
| ICMP | all | unicast | 2,409 | 19 | 10.00 | 17.00 | 1.90 | 1 | 192.168.137.190 -> 192.168.137.50 ICMP | Unknown [unknown] | Unidentified ESP plug (2) | DDoS-SYN_Flood5 | 2022-08-29T17:47:00.000Z |
| IGMP | all | all | 165 | 5 | 4.00 | 5.00 | 0.50 | 1 | 192.168.137.61 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | multicast 01:00:5e:00:00:16 | benign_night | 2022-10-08T00:05:50.000Z |
| IGMP | all | mcast_bcast | 165 | 5 | 4.00 | 5.00 | 0.50 | 1 | 192.168.137.61 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | multicast 01:00:5e:00:00:16 | benign_night | 2022-10-08T00:05:50.000Z |
| DEFAULT | all | all | 0 | 0 | N/A | N/A | 0.00 | 0 |  |  |  |  |  |

### val -- victim

| proto_class | proto | dst_scope | nonempty_windows | max_packets | p99 | p99_9 | max_rate_pps | windows_at_max | max_keys | max_senders | max_receivers | max_session | max_window_start_utc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ICMP | all | all | 1,941 | 56 | 16.00 | 23.00 | 5.60 | 1 | * -> 192.168.137.35 ICMP | Gateway / router [gateway]; Unknown [unknown] | Netatmo Camera | benign_night | 2022-10-08T00:06:10.000Z |
| ICMP | all | unicast | 1,941 | 56 | 16.00 | 23.00 | 5.60 | 1 | * -> 192.168.137.35 ICMP | Gateway / router [gateway]; Unknown [unknown] | Netatmo Camera | benign_night | 2022-10-08T00:06:10.000Z |
| IGMP | all | all | 146 | 14 | 6.00 | 14.00 | 1.40 | 1 | * -> 224.0.0.22 IGMP | Aeotec Smart Home Hub; Amazon Alexa Echo Studio; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) | multicast 01:00:5e:00:00:16 | benign_night | 2022-10-08T00:05:50.000Z |
| IGMP | all | mcast_bcast | 146 | 14 | 6.00 | 14.00 | 1.40 | 1 | * -> 224.0.0.22 IGMP | Aeotec Smart Home Hub; Amazon Alexa Echo Studio; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) | multicast 01:00:5e:00:00:16 | benign_night | 2022-10-08T00:05:50.000Z |
| DEFAULT | all | all | 0 | 0 | N/A | N/A | 0.00 | 0 |  |  |  |  |  |

## 3. Phones / laptops (randomised MAC, role excluded) -- share of each max

Phones stay IN the calibration. max_phone_packets = their packets in the max window(s); max_without_phone = the max over all windows after removing their packets.

| split | level | proto_class | max_packets | max_phone_packets | max_without_phone |
|---|---|---|---|---|---|
| train | stream | ICMP | 53 | 0 | 53 |
| train | stream | IGMP | 4 | 0 | 4 |
| train | stream | DEFAULT | 0 | 0 | 0 |
| train | victim | ICMP | 107 | 30 | 77 |
| train | victim | IGMP | 11 | 0 | 11 |
| train | victim | DEFAULT | 0 | 0 | 0 |
| val | stream | ICMP | 19 | 0 | 19 |
| val | stream | IGMP | 5 | 0 | 5 |
| val | stream | DEFAULT | 0 | 0 | 0 |
| val | victim | ICMP | 56 | 0 | 56 |
| val | victim | IGMP | 14 | 0 | 14 |
| val | victim | DEFAULT | 0 | 0 | 0 |

## Sensitivity: 1 s / 10 s / 60 s windows (all destinations)

max_rate_vs_10s = max rate at this window / max rate at 10 s (short windows catch bursts; long ones average).

### train

| level | proto_class | window_s | nonempty_windows | max_packets | p99 | p99_9 | max_rate_pps | max_rate_vs_10s | max_keys | max_senders |
|---|---|---|---|---|---|---|---|---|---|---|
| stream | ICMP | 1 | 38,185 | 30 | 4.00 | 7.00 | 30.00 | 5.66 | 192.168.137.129 -> 192.168.137.1 ICMP | Randomised MAC (phone/laptop) [excluded] |
| stream | ICMP | 10 | 14,848 | 53 | 13.00 | 19.00 | 5.30 | 1.00 | 192.168.137.109 -> 192.168.137.1 ICMP | Teckin Light Strip |
| stream | ICMP | 60 | 7,159 | 77 | 50.00 | 71.00 | 1.28 | 0.24 | 192.168.137.174 -> 8.8.8.8 ICMP | 8.8.8.8 -> 192.168.137.174 ICMP | Arlo Q Indoor Camera | Gateway / router [gateway] |
| stream | IGMP | 1 | 949 | 3 | 2.00 | 3.00 | 3.00 | 7.50 | 192.168.137.109 -> 224.0.0.22 IGMP | 192.168.137.109 -> 224.0.0.22 IGMP | Smart Board | Smart Board |
| stream | IGMP | 10 | 616 | 4 | 3.00 | 4.00 | 0.40 | 1.00 | 192.168.137.12 -> 224.0.0.22 IGMP | 192.168.137.99 -> 224.0.0.22 IGMP | 192.168.137.253 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | Unidentified Amazon device (1c:12:b0) | LG Smart TV |
| stream | IGMP | 60 | 547 | 6 | 4.00 | 6.00 | 0.10 | 0.25 | 192.168.137.253 -> 224.0.0.22 IGMP | 192.168.137.38 -> 224.0.0.22 IGMP | 192.168.137.58 -> 224.0.0.22 IGMP | LG Smart TV | Philips Hue Bridge | Netatmo Camera |
| stream | DEFAULT | 1 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| stream | DEFAULT | 10 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| stream | DEFAULT | 60 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| victim | ICMP | 1 | 34,814 | 32 | 5.00 | 9.00 | 32.00 | 2.99 | * -> 192.168.137.1 ICMP | Arlo Base Station; Google Nest Mini Speaker; Unknown [unknown]; Wyze Camera; Yi Indoor Camera; unlisted c0:e7:bf:0a:79:d1 (+more) |
| victim | ICMP | 10 | 11,772 | 107 | 19.00 | 28.00 | 10.70 | 1.00 | * -> 192.168.137.1 ICMP | Arlo Base Station; Google Nest Mini Speaker; Unknown [unknown]; Wyze Camera; Yi Indoor Camera; unlisted c0:e7:bf:0a:79:d1 (+more) |
| victim | ICMP | 60 | 4,336 | 208 | 68.00 | 93.00 | 3.47 | 0.32 | * -> 192.168.137.1 ICMP | Arlo Base Station; Google Nest Mini Speaker; Unknown [unknown]; Wyze Camera; Yi Indoor Camera; unlisted c0:e7:bf:0a:79:d1 (+more) |
| victim | IGMP | 1 | 929 | 4 | 3.00 | 4.00 | 4.00 | 3.64 | * -> 224.0.0.22 IGMP | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Netatmo Camera; Philips Hue Bridge |
| victim | IGMP | 10 | 579 | 11 | 4.00 | 11.00 | 1.10 | 1.00 | * -> 224.0.0.22 IGMP | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Netatmo Camera; Philips Hue Bridge |
| victim | IGMP | 60 | 407 | 16 | 10.00 | 16.00 | 0.27 | 0.24 | * -> 224.0.0.22 IGMP | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Netatmo Camera; Philips Hue Bridge |
| victim | DEFAULT | 1 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| victim | DEFAULT | 10 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| victim | DEFAULT | 60 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |

### val

| level | proto_class | window_s | nonempty_windows | max_packets | p99 | p99_9 | max_rate_pps | max_rate_vs_10s | max_keys | max_senders |
|---|---|---|---|---|---|---|---|---|---|---|
| stream | ICMP | 1 | 4,551 | 8 | 4.00 | 5.00 | 8.00 | 4.21 | 192.168.137.174 -> 8.8.8.8 ICMP | 8.8.8.8 -> 192.168.137.174 ICMP | Arlo Q Indoor Camera | Gateway / router [gateway] |
| stream | ICMP | 10 | 2,409 | 19 | 10.00 | 17.00 | 1.90 | 1.00 | 192.168.137.190 -> 192.168.137.50 ICMP | Unknown [unknown] |
| stream | ICMP | 60 | 1,509 | 57 | 18.00 | 57.00 | 0.95 | 0.50 | 192.168.137.174 -> 8.8.8.8 ICMP | 8.8.8.8 -> 192.168.137.174 ICMP | Arlo Q Indoor Camera | Gateway / router [gateway] |
| stream | IGMP | 1 | 253 | 3 | 3.00 | 3.00 | 3.00 | 6.00 | 192.168.137.61 -> 224.0.0.22 IGMP | 192.168.137.66 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | Wemo Smart Plug 2 |
| stream | IGMP | 10 | 165 | 5 | 4.00 | 5.00 | 0.50 | 1.00 | 192.168.137.61 -> 224.0.0.22 IGMP | Google Nest Mini Speaker |
| stream | IGMP | 60 | 143 | 6 | 5.00 | 6.00 | 0.10 | 0.20 | 192.168.137.66 -> 224.0.0.22 IGMP | Wemo Smart Plug 2 |
| stream | DEFAULT | 1 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| stream | DEFAULT | 10 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| stream | DEFAULT | 60 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| victim | ICMP | 1 | 4,117 | 31 | 4.00 | 7.00 | 31.00 | 5.54 | * -> 192.168.137.35 ICMP | Gateway / router [gateway]; Unknown [unknown] |
| victim | ICMP | 10 | 1,941 | 56 | 16.00 | 23.00 | 5.60 | 1.00 | * -> 192.168.137.35 ICMP | Gateway / router [gateway]; Unknown [unknown] |
| victim | ICMP | 60 | 938 | 58 | 51.00 | 58.00 | 0.97 | 0.17 | * -> 192.168.137.1 ICMP | * -> 192.168.137.35 ICMP | Google Nest Mini Speaker; Randomised MAC (phone/laptop) [excluded]; Smart Board; Unknown [unknown]; Wyze Camera; unlisted c0:e7:bf:0a:79:d1 (+more) | Gateway / router [gateway]; Unknown [unknown] |
| victim | IGMP | 1 | 244 | 4 | 3.00 | 4.00 | 4.00 | 2.86 | * -> 224.0.0.22 IGMP | Aeotec Smart Home Hub; Amazon Alexa Echo Studio; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) |
| victim | IGMP | 10 | 146 | 14 | 6.00 | 14.00 | 1.40 | 1.00 | * -> 224.0.0.22 IGMP | Aeotec Smart Home Hub; Amazon Alexa Echo Studio; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) |
| victim | IGMP | 60 | 96 | 20 | 20.00 | 20.00 | 0.33 | 0.24 | * -> 224.0.0.22 IGMP | Aeotec Smart Home Hub; Amazon Alexa Echo Studio; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) |
| victim | DEFAULT | 1 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| victim | DEFAULT | 10 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |
| victim | DEFAULT | 60 | 0 | 0 | N/A | N/A | 0.00 | N/A |  |  |

## 4. Proposed thresholds (packets per 10 s window; alert iff packets > threshold)

threshold = int(margin x TRAIN max), all destination kinds pooled. DEFAULT = every non-TCP/UDP proto other than ICMP / IGMP (incl. GRE), floored: T = max(raw, ICMP threshold of the same level and margin); raw_ = before the floor (equal to T for ICMP / IGMP). Val exceedances are counted at T.

**Note: floor = ICMP threshold; legitimate VPN tunnels (GRE/ESP) are not represented in this benign data -- known limitation.**

| level | class | train_max | train_p99_9 | val_max | val_over_train_max | raw_2x | T_2x | val_exc_2x | raw_3x | T_3x | val_exc_3x | raw_5x | T_5x | val_exc_5x |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stream | ICMP | 53 | 19.00 | 19 | 0.36 | 106 | 106 | 0 windows / 0 keys | 159 | 159 | 0 windows / 0 keys | 265 | 265 | 0 windows / 0 keys |
| stream | IGMP | 4 | 4.00 | 5 | 1.25 | 8 | 8 | 0 windows / 0 keys | 12 | 12 | 0 windows / 0 keys | 20 | 20 | 0 windows / 0 keys |
| stream | DEFAULT | 0 | N/A | 0 | N/A | 0 | 106 | 0 windows / 0 keys | 0 | 159 | 0 windows / 0 keys | 0 | 265 | 0 windows / 0 keys |
| victim | ICMP | 107 | 28.00 | 56 | 0.52 | 214 | 214 | 0 windows / 0 keys | 321 | 321 | 0 windows / 0 keys | 535 | 535 | 0 windows / 0 keys |
| victim | IGMP | 11 | 11.00 | 14 | 1.27 | 22 | 22 | 0 windows / 0 keys | 33 | 33 | 0 windows / 0 keys | 55 | 55 | 0 windows / 0 keys |
| victim | DEFAULT | 0 | N/A | 0 | N/A | 0 | 214 | 0 windows / 0 keys | 0 | 321 | 0 windows / 0 keys | 0 | 535 | 0 windows / 0 keys |

DEFAULT train max per proto: stream: no packets; victim: no packets

### Val exceedances (the honesty check), by key / device

No val window exceeds any proposed threshold at any margin.

### GRE flood level vs the DEFAULT thresholds -- design data, not used to choose

12b pilot (base part, sha256 `87f8de16e575f23f...`): per GRE stream (src, dst, 47): packets / (last - first) x 10 s; per GRE victim (dst, 47): the streams' packets / (latest last - earliest first) x 10 s. Averages over the span, not per-window maxima. GRE streams 14: min 2,866 / median 6,319 packets per 10 s; GRE victims 2: min 39,521 / median 44,031.

| margin | raw_stream_DEFAULT | T_stream_DEFAULT | GRE_stream_min / T | GRE_stream_median / T | raw_victim_DEFAULT | T_victim_DEFAULT | GRE_victim_min / T | GRE_victim_median / T |
|---|---|---|---|---|---|---|---|---|
| 2x | 0 | 106 | 27.0 | 59.6 | 0 | 214 | 184.7 | 205.8 |
| 3x | 0 | 159 | 18.0 | 39.7 | 0 | 321 | 123.1 | 137.2 |
| 5x | 0 | 265 | 10.8 | 23.8 | 0 | 535 | 73.9 | 82.3 |

Factors use the floored T. N/A = T is 0 (only if the ICMP floor is 0 too): any packet alerts.

## 5. Recommendation (proposal only -- you decide)

Proposal: 2x the train max (10 s windows; DEFAULT floored at the ICMP threshold) -- the smallest tested margin with zero val exceedances at both levels and all three classes; the 12b GRE flood (design data, not used to choose) sits 27.0x (slowest stream) / 184.7x (smaller victim) above the DEFAULT thresholds. Note: floor = ICMP threshold; legitimate VPN tunnels (GRE/ESP) are not represented in this benign data -- known limitation.

Rule: smallest margin in (2, 3, 5) with zero val exceedances over both levels and all classes. All three margins are in rate_guard_thresholds_proposed.json as RateGuard keyword arguments.

## Top keys (10 s, top 5 per split x level x class; full list in calib_top_keys.csv)

| split | level | proto_class | rank | session | key | max_packets_10s | max_window_start_utc | nonempty_windows | packets_total | phone_packets_in_max | senders | receivers |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| train | stream | ICMP | 1 | Mirai-udpplain | 192.168.137.109 -> 192.168.137.1 ICMP | 53 | 2023-01-19T15:56:50.000Z | 22 | 127 | 0 | Teckin Light Strip | Gateway / router [gateway] |
| train | stream | ICMP | 2 | Mirai-udpplain | 192.168.137.129 -> 192.168.137.1 ICMP | 30 | 2023-01-19T15:56:50.000Z | 13 | 87 | 30 | Randomised MAC (phone/laptop) [excluded] | Gateway / router [gateway] |
| train | stream | ICMP | 3 | DDoS-SYN_Flood5 | 192.168.137.190 -> 192.168.137.10 ICMP | 29 | 2022-08-29T17:41:10.000Z | 8 | 60 | 0 | Unknown [unknown] | Yutron Plug 1 |
| train | stream | ICMP | 4 | DDoS-SYN_Flood | 192.168.137.190 -> 192.168.137.164 ICMP | 25 | 2022-08-26T18:48:50.000Z | 20 | 155 | 0 | Unknown [unknown] | Nest Indoor Camera |
| train | stream | ICMP | 5 | Mirai-udpplain | 192.168.137.248 -> 192.168.137.1 ICMP | 24 | 2023-01-19T16:14:30.000Z | 41 | 226 | 0 | Google Nest Mini Speaker | Gateway / router [gateway] |
| train | stream | IGMP | 1 | DDoS-SYN_Flood | 192.168.137.12 -> 224.0.0.22 IGMP | 4 | 2022-08-26T18:58:40.000Z | 6 | 16 | 0 | Google Nest Mini Speaker | multicast 01:00:5e:00:00:16 |
| train | stream | IGMP | 2 | DDoS-SYN_Flood | 192.168.137.99 -> 224.0.0.22 IGMP | 4 | 2022-08-26T19:06:40.000Z | 2 | 6 | 0 | Unidentified Amazon device (1c:12:b0) | multicast 01:00:5e:00:00:16 |
| train | stream | IGMP | 3 | Mirai-udpplain | 192.168.137.38 -> 224.0.0.22 IGMP | 4 | 2023-01-19T15:58:20.000Z | 19 | 38 | 0 | Philips Hue Bridge | multicast 01:00:5e:00:00:16 |
| train | stream | IGMP | 4 | Mirai-udpplain | 192.168.137.58 -> 224.0.0.22 IGMP | 4 | 2023-01-19T15:58:20.000Z | 10 | 18 | 0 | Netatmo Camera | multicast 01:00:5e:00:00:16 |
| train | stream | IGMP | 5 | benign_night | 192.168.137.253 -> 224.0.0.22 IGMP | 4 | 2022-10-07T20:30:20.000Z | 2 | 6 | 0 | LG Smart TV | multicast 01:00:5e:00:00:16 |
| train | victim | ICMP | 1 | Mirai-udpplain | * -> 192.168.137.1 ICMP | 107 | 2023-01-19T15:56:50.000Z | 119 | 1,055 | 30 | Arlo Base Station; Google Nest Mini Speaker; Unknown [unknown]; Wyze Camera; Yi Indoor Camera; unlisted c0:e7:bf:0a:79:d1 (+more) | Gateway / router [gateway] |
| train | victim | ICMP | 2 | Mirai-udpplain | * -> 192.168.137.171 ICMP | 57 | 2023-01-19T16:14:20.000Z | 29 | 309 | 0 | GoSund Power Strip (2); GoSund Smart Plug WP2 (1); Teckin Plug 1; Unidentified ESP plug (1); Unidentified ESP plug (2); Unidentified ESP plug (3) (+more) | Unknown [unknown] |
| train | victim | ICMP | 3 | DDoS-SYN_Flood | * -> 192.168.137.1 ICMP | 35 | 2022-08-26T18:28:40.000Z | 164 | 933 | 0 | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Home Eye Camera; Unknown [unknown]; unlisted c0:e7:bf:0a:79:d1 (+more) | Gateway / router [gateway] |
| train | victim | ICMP | 4 | DDoS-SYN_Flood5 | * -> 192.168.137.1 ICMP | 29 | 2022-08-29T17:24:40.000Z | 105 | 526 | 0 | Amazon Alexa Echo Dot 1; Amazon Alexa Echo Dot 2; Google Nest Mini Speaker; TP-Link Tapo Camera; Unidentified Amazon device (1c:12:b0); Unknown [unknown] (+more) | Gateway / router [gateway] |
| train | victim | ICMP | 5 | DDoS-SYN_Flood5 | * -> 192.168.137.10 ICMP | 29 | 2022-08-29T17:41:10.000Z | 8 | 60 | 0 | Unknown [unknown] | Yutron Plug 1 |
| train | victim | IGMP | 1 | Mirai-udpplain | * -> 224.0.0.22 IGMP | 11 | 2023-01-19T15:58:20.000Z | 24 | 68 | 0 | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Netatmo Camera; Philips Hue Bridge | multicast 01:00:5e:00:00:16 |
| train | victim | IGMP | 2 | DDoS-SYN_Flood | * -> 224.0.0.22 IGMP | 10 | 2022-08-26T19:06:40.000Z | 41 | 94 | 0 | Amazon Alexa Echo Dot 1; Netatmo Camera; Philips Hue Bridge; Smart Board; Unidentified Amazon device (1c:12:b0); unlisted ee:06:3b:b8:d1:df (+more) | multicast 01:00:5e:00:00:16 |
| train | victim | IGMP | 3 | DDoS-SYN_Flood5 | * -> 224.0.0.22 IGMP | 4 | 2022-08-29T17:37:20.000Z | 19 | 40 | 0 | Amazon Alexa Echo Studio; Philips Hue Bridge; Smart Board; Unidentified Amazon device (1c:12:b0) | multicast 01:00:5e:00:00:16 |
| train | victim | IGMP | 4 | benign_night | * -> 224.0.0.22 IGMP | 4 | 2022-10-07T18:43:50.000Z | 384 | 718 | 2 | Aeotec Smart Home Hub; Amazon Alexa Echo Studio; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) | multicast 01:00:5e:00:00:16 |
| train | victim | IGMP | 5 | DDoS-SYN_Flood5 | * -> 224.0.0.1 IGMP | 3 | 2022-08-29T17:28:40.000Z | 8 | 11 | 0 | GoSund Smart Plug WP2 (1); LampUX RGB; Unidentified ESP plug (1); Unidentified ESP plug (2); Unidentified ESP plug (4); unlisted 50:02:91:b1:68:0c (+more) | multicast 01:00:5e:00:00:01 |
| val | stream | ICMP | 1 | DDoS-SYN_Flood5 | 192.168.137.190 -> 192.168.137.50 ICMP | 19 | 2022-08-29T17:47:00.000Z | 2 | 27 | 0 | Unknown [unknown] | Unidentified ESP plug (2) |
| val | stream | ICMP | 2 | DDoS-SYN_Flood | 192.168.137.174 -> 8.8.8.8 ICMP | 17 | 2022-08-29T12:29:30.000Z | 5 | 49 | 0 | Arlo Q Indoor Camera | Gateway / router [gateway] |
| val | stream | ICMP | 3 | DDoS-SYN_Flood | 8.8.8.8 -> 192.168.137.174 ICMP | 17 | 2022-08-29T12:29:30.000Z | 5 | 49 | 0 | Gateway / router [gateway] | Arlo Q Indoor Camera |
| val | stream | ICMP | 4 | DDoS-SYN_Flood5 | 192.168.137.174 -> 8.8.8.8 ICMP | 13 | 2022-08-29T17:47:30.000Z | 8 | 67 | 0 | Arlo Q Indoor Camera | Gateway / router [gateway] |
| val | stream | ICMP | 5 | DDoS-SYN_Flood5 | 8.8.8.8 -> 192.168.137.174 ICMP | 13 | 2022-08-29T17:47:30.000Z | 8 | 66 | 0 | Gateway / router [gateway] | Arlo Q Indoor Camera |
| val | stream | IGMP | 1 | benign_night | 192.168.137.61 -> 224.0.0.22 IGMP | 5 | 2022-10-08T00:05:50.000Z | 1 | 5 | 0 | Google Nest Mini Speaker | multicast 01:00:5e:00:00:16 |
| val | stream | IGMP | 2 | benign_night | 192.168.137.172 -> 224.0.0.22 IGMP | 4 | 2022-10-08T00:11:10.000Z | 1 | 4 | 0 | Amazon Echo Show | multicast 01:00:5e:00:00:16 |
| val | stream | IGMP | 3 | benign_night | 192.168.137.186 -> 224.0.0.22 IGMP | 3 | 2022-10-08T00:05:50.000Z | 1 | 3 | 0 | SmartThings Hub | multicast 01:00:5e:00:00:16 |
| val | stream | IGMP | 4 | benign_night | 192.168.137.35 -> 224.0.0.22 IGMP | 3 | 2022-10-08T00:05:50.000Z | 3 | 5 | 0 | Netatmo Camera | multicast 01:00:5e:00:00:16 |
| val | stream | IGMP | 5 | benign_night | 192.168.137.66 -> 224.0.0.22 IGMP | 3 | 2022-10-08T00:06:40.000Z | 5 | 14 | 0 | Wemo Smart Plug 2 | multicast 01:00:5e:00:00:16 |
| val | victim | ICMP | 1 | benign_night | * -> 192.168.137.35 ICMP | 56 | 2022-10-08T00:06:10.000Z | 308 | 363 | 0 | Gateway / router [gateway]; Unknown [unknown] | Netatmo Camera |
| val | victim | ICMP | 2 | Recon-PortScan | * -> 192.168.137.1 ICMP | 23 | 2022-09-27T14:59:40.000Z | 120 | 904 | 0 | Google Nest Mini Speaker; Randomised MAC (phone/laptop) [excluded]; Smart Board; Unknown [unknown]; Wyze Camera; unlisted c0:e7:bf:0a:79:d1 (+more) | Gateway / router [gateway] |
| val | victim | ICMP | 3 | benign_night | * -> 192.168.137.103 ICMP | 21 | 2022-10-08T00:05:40.000Z | 59 | 138 | 0 | Aeotec Smart Home Hub; Cocoon Smart HVAC Fan; Randomised MAC (phone/laptop) [excluded]; Rbcior Camera; Wyze Camera; Yutron Plug 1 (+more) | Unknown [unknown] |
| val | victim | ICMP | 4 | benign_night | * -> 192.168.137.1 ICMP | 20 | 2022-10-08T00:01:50.000Z | 366 | 1,811 | 3 | Amazon Echo Show; Google Nest Mini Speaker; Randomised MAC (phone/laptop) [excluded]; Unknown [unknown]; Wyze Camera; Yi Indoor 2 Camera (+more) | Gateway / router [gateway] |
| val | victim | ICMP | 5 | DDoS-SYN_Flood | * -> 8.8.8.8 ICMP | 19 | 2022-08-29T12:29:30.000Z | 13 | 62 | 0 | Amazon Alexa Echo Dot 1; Amazon Smart Plug; Arlo Q Indoor Camera; Google Nest Mini Speaker; Wemo Smart Plug 2; Wyze Camera (+more) | Gateway / router [gateway] |
| val | victim | IGMP | 1 | benign_night | * -> 224.0.0.22 IGMP | 14 | 2022-10-08T00:05:50.000Z | 112 | 229 | 0 | Aeotec Smart Home Hub; Amazon Alexa Echo Studio; LG Smart TV; Netatmo Camera; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) | multicast 01:00:5e:00:00:16 |
| val | victim | IGMP | 2 | benign_night | * -> 224.0.0.1 IGMP | 3 | 2022-10-08T00:05:40.000Z | 1 | 3 | 0 | GoSund Smart Plug WP2 (1); LampUX RGB; Unidentified ESP plug (1) | multicast 01:00:5e:00:00:01 |
| val | victim | IGMP | 3 | DDoS-SYN_Flood | * -> 224.0.0.22 IGMP | 2 | 2022-08-29T12:28:20.000Z | 4 | 8 | 0 | Amazon Alexa Echo Dot 1; Netatmo Camera; Philips Hue Bridge; Smart Board; Unidentified Amazon device (1c:12:b0); unlisted ee:06:3b:b8:d1:df (+more) | multicast 01:00:5e:00:00:16 |
| val | victim | IGMP | 4 | DDoS-SYN_Flood5 | * -> 224.0.0.22 IGMP | 2 | 2022-08-29T17:47:30.000Z | 1 | 2 | 0 | Amazon Alexa Echo Studio; Philips Hue Bridge; Smart Board; Unidentified Amazon device (1c:12:b0) | multicast 01:00:5e:00:00:16 |
| val | victim | IGMP | 5 | Mirai-udpplain | * -> 224.0.0.22 IGMP | 2 | 2023-01-19T16:22:00.000Z | 2 | 4 | 0 | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Netatmo Camera; Philips Hue Bridge | multicast 01:00:5e:00:00:16 |

## Outputs

summary.md, calib_per_session.csv, calib_max_by_level_proto.csv, calib_top_keys.csv, calib_sensitivity_windows.csv, rate_guard_thresholds_proposed.json, run_meta.json
