# Step 5 -- flow tagging report

- **run_timestamp_utc**: 2026-10-08T18:27:20+00:00
- **flows**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/BenignTraffic.pcap_Flow__singlepkt.csv
- **flows_sha256**: b8a757e7339c1a97c4941efa8f6bea2f07981651d86e699e606315a2ee8b2606
- **map**: /mnt/d/Projects/Company Project/Paper_Implemetation/config/ip_mac_map.csv
- **map_sha256**: d819eea5f3d874974e58d0e6009db764b7844b03f63f8a642f64540548a4fa14
- **devices**: /mnt/d/Projects/Company Project/Paper_Implemetation/config/device_table.csv
- **devices_sha256**: 50dcde5b0dd547d580cdb9124e7d12ffdcb40f4a2d2b3c9804ec7af9df67945c
- **out**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/benign_flows_tagged.csv
- **out_sha256**: f9c033abaf07289999f4c1300f09b00a48624aecd2a63ef0a5ec7632abf2c799
- **subnet_broadcasts**: ['10.22.22.255', '169.254.255.255', '192.168.137.255']
- **window_tolerance_s**: 1.0
- **timestamp_format**: %d/%m/%Y %I:%M:%S %p (UTC)
- **resolve_conflicts**: True
- **conflict_rule**: sender_mac
- **runtime_s**: 162.2
- **python**: 3.11.17
- **pandas**: 3.0.6

## Integrity: **PASS**

- **input_rows**: 223108
- **output_columns**: 98
- **original_columns_in_order**: True
- **tag_columns_appended**: True
- **output_rows**: 223108
- **row_count_equal**: True
- **text_mismatch_cells**: 0
- **text_mismatch_by_column**: {}
- **value_mismatch_cells_nan_aware**: 0
- **value_mismatch_by_column**: {}
- **nan_cells_input**: 190221
- **input_sha256_before**: b8a757e7339c1a97c4941efa8f6bea2f07981651d86e699e606315a2ee8b2606
- **input_sha256_after**: b8a757e7339c1a97c4941efa8f6bea2f07981651d86e699e606315a2ee8b2606
- **input_sha256_unchanged**: True

## Expectations (IP/time lookup, before pcap resolution)

- **lan_unmapped_is_zero**: True
- **ambiguous_ips**: ['192.168.137.249']
- **ambiguous_ips_all_map_conflicts**: True
- **ambiguous_within_overlap_window**: True

## Rules

Endpoint: broadcast (multicast/255.255.255.255/subnet .255) > unspecified > external (not LAN-scope, as in 02) > LAN map lookup with window [first_seen-1s, last_seen+1s] (1 MAC -> device role, >1 -> ambiguous, 0 -> lan_unmapped). Ambiguous TCP/UDP flows are then resolved from pcap packets, time window start-1s .. start+duration+1s, exactly one MAC -> resolved. Rule sender_mac: only packets sent by the conflict IP (MAC = eth.src); key (conflict IP, peer IP, conflict-side port, peer port, protocol); ICMP errors matched via their inner UDP/TCP header. Owner: ambiguous side -> ip_conflict; both smart-home -> Src (device_device_initiator); one smart-home -> that side (device_side); both external + Protocol 0 -> invalid_parse; else unowned (no_device:<src_role>-<dst_role>). Smart-home = device-table role 'iot'. exclude_reason: ip_conflict_unresolved (still ambiguous), invalid_parse, ip_clash_artifact (pcap-resolved flow whose matched conflict-IP-sent packets are all ICMP destination-unreachable; owner kept); blank = usable.

## By owner_status

| value | flows | pct |
|---|---|---|
| owned | 209,946 | 94.101 |
| unowned | 12,739 | 5.71 |
| invalid_parse | 318 | 0.143 |
| ambiguous | 105 | 0.047 |

## By owner_rule

| value | flows | pct |
|---|---|---|
| device_side | 206,749 | 92.668 |
| no_device:unknown-external | 4,703 | 2.108 |
| device_device_initiator | 3,197 | 1.433 |
| no_device:unknown-gateway | 2,673 | 1.198 |
| no_device:excluded-gateway | 2,380 | 1.067 |
| no_device:excluded-external | 943 | 0.423 |
| no_device:gateway-broadcast | 560 | 0.251 |
| no_device:testbed_pi-broadcast | 400 | 0.179 |
| no_device:excluded-broadcast | 341 | 0.153 |
| invalid_parse:external-external-proto0 | 318 | 0.143 |
| no_device:unspecified-broadcast | 256 | 0.115 |
| no_device:external-excluded | 177 | 0.079 |
| ip_conflict | 105 | 0.047 |
| no_device:external-unknown | 101 | 0.045 |
| no_device:testbed_pi-external | 83 | 0.037 |
| no_device:gateway-testbed_pi | 53 | 0.024 |
| no_device:unknown-unknown | 36 | 0.016 |
| no_device:gateway-excluded | 12 | 0.005 |
| no_device:testbed_pi-gateway | 8 | 0.004 |
| no_device:testbed_pi-unknown | 5 | 0.002 |
| no_device:gateway-unknown | 3 | 0.001 |
| no_device:excluded-unknown | 2 | 0.001 |
| no_device:external-testbed_pi | 2 | 0.001 |
| no_device:unknown-testbed_pi | 1 | 0.0 |

## By owner_resolution

| value | flows | pct |
|---|---|---|
| ip_time | 212,435 | 95.216 |
| pcap_packet_mac | 10,568 | 4.737 |
| unresolved | 105 | 0.047 |

## By exclude_reason

| value | flows | pct |
|---|---|---|
| (blank = usable) | 217,583 | 97.524 |
| ip_clash_artifact | 5,102 | 2.287 |
| invalid_parse | 318 | 0.143 |
| ip_conflict_unresolved | 105 | 0.047 |

## Conflict resolution (rule: sender_mac)

- **ambiguous flows before -> after**: 10,673 -> 105 (10,568 resolved)
- **ip_clash_artifact flows**: 5,102 (Yi Indoor 2 Camera 5,102)
- **packets extracted**: 63,540
- **rule**: sender_mac
- **packets_sent_by_conflict_ip**: 41792
- **packets_sent_mac_counts**: {'84:7a:b6:62:3a:6c': 21692, '24:05:88:30:6f:89': 20100}
- **packets_non_candidate_mac**: 0
- **packets_icmp_with_inner_header**: 19745
- **packets_icmp_dest_unreachable**: 19745
- **packets_icmp_dest_unreachable_by_mac**: {'84:7a:b6:62:3a:6c': 19745}
- **packets_usable**: 41482
- **join_rows_before_time_filter**: 87319
- **packet_flow_matches**: 41569
- **packets_matched_to_any_flow**: 41482
- **flows_with_matched_packets**: 10568
- **flows_mixed_unreach_and_other**: 0
- **tshark runtime**: 112.7 s
- **pcap verified**: True (549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8)
- **display filter**: `(ip.addr == 192.168.137.249 && frame.time_epoch >= 1665162898.889190 && frame.time_epoch <= 1665176786.758781)`

### Conflicts found in map

| ip | macs | devices | overlap | tshark_window |
|---|---|---|---|---|
| 192.168.137.249 | 24:05:88:30:6f:89, 84:7a:b6:62:3a:6c | Unknown, Yi Indoor 2 Camera | 2022-10-07T17:15:00.889190+00:00 .. 2022-10-07T21:06:24.758781+00:00 | 2022-10-07T17:14:58.889190+00:00 .. 2022-10-07T21:06:26.758781+00:00 |

### Resolved to

| mac | device | role | flows |
|---|---|---|---|
| 84:7a:b6:62:3a:6c | Yi Indoor 2 Camera | iot | 5,476 |
| 24:05:88:30:6f:89 | Unknown | unknown | 5,092 |

### Resolved flows -- resulting ownership

| owner_status | owner_rule | flows |
|---|---|---|
| owned | device_side | 5,476 |
| unowned | no_device:unknown-external | 3,177 |
| unowned | no_device:unknown-gateway | 1,915 |

### Still ambiguous by reason

| ambiguous_reason | protocol | flows |
|---|---|---|
| no_packet_match | 0 | 104 |
| no_packet_match | 17 | 1 |

### Owned flows per candidate device: before resolution -> after (total / usable = exclude_reason blank)

| mac | device | before | after | after_usable |
|---|---|---|---|---|
| 24:05:88:30:6f:89 | Unknown | 0 | 0 | 0 |
| 84:7a:b6:62:3a:6c | Yi Indoor 2 Camera | 537 | 6,013 | 911 |

## Invalid parse: 318 flows

Rule `invalid_parse:external-external-proto0`: both endpoints external and Protocol 0 (non-IP frames misread as IP). Most frequent addresses: 8.6.0.1 (278), 8.0.6.4 (278), 0.6.0.1 (40), 175.129.1.2 (40)

| Flow ID | Src IP | Dst IP | Protocol | Timestamp | Flow Duration | Total Fwd Packet | Total Bwd packets | Total Length of Fwd Packet |
|---|---|---|---|---|---|---|---|---|
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:15:00 PM | 119580202 | 232 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:17:02 PM | 119411456 | 224 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:19:02 PM | 118398290 | 242 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:21:02 PM | 119105291 | 231 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:23:02 PM | 119813326 | 236 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:25:02 PM | 118003617 | 229 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:27:02 PM | 119508572 | 237 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:29:02 PM | 119374858 | 238 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:31:02 PM | 119445197 | 228 | 0 | 0.0 |
| 8.6.0.1-8.0.6.4-0-0-0 | 8.6.0.1 | 8.0.6.4 | 0 | 07/10/2022 05:33:02 PM | 119992849 | 261 | 0 | 0.0 |

## lan_unmapped endpoints: 0

_none_

## Ambiguous flows remaining: 105

| ip | flows | candidate_macs | first_flow_utc | last_flow_utc |
|---|---|---|---|---|
| 192.168.137.249 | 105 | 24:05:88:30:6f:89, 84:7a:b6:62:3a:6c | 2022-10-07T17:15:06+00:00 | 2022-10-07T21:06:21+00:00 |

## Flows per smart-home owner device (55/55 own >= 1 flow; LOW = < 100)

| owner_device | owner_mac | owner_category | flows | usable | device_side | device_device_initiator | low_flag |
|---|---|---|---|---|---|---|---|
| Fibaro Home Center Lite | ac:17:02:05:34:27 | Hub | 101,507 | 101,507 | 101,507 | 0 |  |
| Home Eye Camera | 34:75:63:73:f3:36 | Camera | 21,760 | 21,760 | 21,760 | 0 |  |
| Harman Kardon speaker (Ampak) | b0:f1:ec:d3:e7:98 | Audio | 9,619 | 9,619 | 9,217 | 402 |  |
| Wyze Camera | 7c:78:b2:86:0d:81 | Camera | 9,609 | 9,609 | 9,609 | 0 |  |
| Yi Indoor 2 Camera | 84:7a:b6:62:3a:6c | Camera | 6,013 | 911 | 6,013 | 0 |  |
| Amazon Echo Show | 2c:71:ff:05:f1:15 | Audio | 5,247 | 5,247 | 4,142 | 1,105 |  |
| LG Smart TV | ac:f1:08:4e:00:82 | Home Automation | 4,253 | 4,253 | 3,957 | 296 |  |
| Google Nest Mini Speaker | cc:f4:11:9c:d0:00 | Audio | 3,891 | 3,891 | 3,891 | 0 |  |
| Arlo Q Indoor Camera | 40:5d:82:35:14:c8 | Camera | 3,752 | 3,752 | 3,752 | 0 |  |
| Amazon Alexa Echo Studio | 08:7c:39:ce:6e:2a | Audio | 3,252 | 3,252 | 2,410 | 842 |  |
| Eufy HomeBase 2 | 8c:85:80:6c:b6:47 | Hub | 3,112 | 3,112 | 3,112 | 0 |  |
| Yi Indoor Camera | 84:7a:b6:64:62:58 | Camera | 2,807 | 2,807 | 2,807 | 0 |  |
| Philips Hue Bridge | 00:17:88:60:d6:4f | Hub | 2,692 | 2,692 | 2,638 | 54 |  |
| AMCREST WiFi Camera | 9c:8e:cd:1d:ab:9f | Camera | 2,432 | 2,432 | 2,418 | 14 |  |
| TP-Link Tapo Camera | 6c:5a:b0:44:1d:90 | Camera | 2,244 | 2,244 | 2,244 | 0 |  |
| SmartThings Hub | 28:6d:97:7a:2b:2d | Hub | 2,159 | 2,159 | 2,157 | 2 |  |
| Aeotec Smart Home Hub | 28:6d:97:9e:f4:d5 | Hub | 2,111 | 2,111 | 2,104 | 7 |  |
| Rbcior Camera | 10:5a:17:97:a5:c6 | Camera | 1,767 | 1,767 | 1,767 | 0 |  |
| Amazon Alexa Echo Dot 1 | 1c:fe:2b:98:16:dd | Audio | 1,573 | 1,573 | 1,499 | 74 |  |
| Sonos One Speaker | 48:a6:b8:f9:1b:88 | Audio | 1,536 | 1,536 | 1,511 | 25 |  |
| Netatmo Camera | 70:ee:50:68:0e:32 | Camera | 1,488 | 1,488 | 1,488 | 0 |  |
| Arlo Base Station | 3c:37:86:6f:b9:51 | Camera | 1,385 | 1,385 | 1,385 | 0 |  |
| Yi Outdoor Camera | 2c:d2:6b:66:d2:87 | Camera | 1,169 | 1,169 | 1,169 | 0 |  |
| HeimVision Smart WiFi Camera | 44:01:bb:ec:10:4a | Camera | 910 | 910 | 910 | 0 |  |
| Teckin Light Strip | 18:69:d8:eb:d4:3e | Lighting | 626 | 626 | 626 | 0 |  |
| Atomi Coffee Maker | 68:57:2d:56:ac:47 | Home Automation | 623 | 623 | 623 | 0 |  |
| Lumiman Bulb | 84:e3:42:42:ed:0b | Lighting | 617 | 617 | 617 | 0 |  |
| HeimVision SmartLife Radio/Lamp | d4:a6:51:30:64:b7 | Lighting | 615 | 615 | 615 | 0 |  |
| Yutron Plug 1 | d4:a6:51:20:91:d1 | Power Outlet | 609 | 609 | 609 | 0 |  |
| Teckin Plug 1 | d4:a6:51:76:06:64 | Power Outlet | 607 | 607 | 607 | 0 |  |
| Teckin Plug 2 | d4:a6:51:78:97:4e | Power Outlet | 607 | 607 | 607 | 0 |  |
| Yutron Plug 2 | d4:a6:51:21:6c:29 | Power Outlet | 606 | 606 | 606 | 0 |  |
| GoSund Power Strip (1) | 50:02:91:1a:ce:e1 | Power Outlet | 546 | 546 | 546 | 0 |  |
| GoSund Power Strip (2) | b8:f0:09:03:9a:af | Power Outlet | 544 | 544 | 544 | 0 |  |
| Unidentified ESP plug (3) | c4:dd:57:0c:39:94 | Unidentified (Espressif) | 543 | 543 | 543 | 0 |  |
| Unidentified ESP plug (4) | c4:dd:57:13:07:c6 | Unidentified (Espressif) | 543 | 543 | 543 | 0 |  |
| GoSund Smart Plug WP2 (1) | b8:f0:09:03:29:79 | Power Outlet | 542 | 542 | 542 | 0 |  |
| LampUX RGB | f4:cf:a2:34:48:6b | Lighting | 541 | 541 | 541 | 0 |  |
| GoSund Smart Plug WP2 (2) | 50:02:91:10:ac:d8 | Power Outlet | 538 | 538 | 538 | 0 |  |
| Unidentified ESP plug (1) | 24:a1:60:14:7f:f9 | Unidentified (Espressif) | 538 | 538 | 538 | 0 |  |
| Unidentified ESP plug (2) | 50:02:91:10:09:8f | Unidentified (Espressif) | 538 | 538 | 538 | 0 |  |
| Wemo Smart Plug 2 | 30:23:03:f3:57:cb | Power Outlet | 471 | 471 | 457 | 14 |  |
| Netatmo Weather Station | 70:ee:50:6b:a8:1a | Home Automation | 443 | 443 | 443 | 0 |  |
| Ring Base Station | b0:09:da:3e:82:6c | Hub | 438 | 438 | 438 | 0 |  |
| Amazon Alexa Echo Dot 2 | a0:d0:dc:c4:08:ff | Audio | 372 | 372 | 26 | 346 |  |
| LIFX Lightbulb | d0:73:d5:35:fb:c8 | Lighting | 339 | 339 | 323 | 16 |  |
| Amazon Smart Plug | b8:5f:98:d0:76:e6 | Power Outlet | 308 | 308 | 308 | 0 |  |
| Levoit Air Purifier | 1c:9d:c2:8c:9a:94 | Home Automation | 300 | 300 | 300 | 0 |  |
| Nest Indoor Camera | 44:bb:3b:00:39:07 | Camera | 294 | 294 | 294 | 0 |  |
| Cocoon Smart HVAC Fan | 08:3a:f2:1f:bc:68 | Home Automation | 290 | 290 | 290 | 0 |  |
| Govee Smart Humidifier | d4:ad:fc:29:c8:a2 | Home Automation | 286 | 286 | 286 | 0 |  |
| D-Link DCS8000LHA1 Mini Camera | b0:c5:54:59:2e:99 | Camera | 225 | 225 | 225 | 0 |  |
| Smart Board | 00:02:75:f6:e3:cb | Home Automation | 64 | 64 | 64 | 0 | LOW |
| iRobot Roomba | 50:14:79:37:80:18 | Home Automation | 32 | 32 | 32 | 0 | LOW |
| Wemo Smart Plug 1 | 30:23:03:f3:84:2b | Power Outlet | 13 | 13 | 13 | 0 | LOW |

## Device-device flows: 3,197 (18 distinct pairs) -- top 10

| src_device | dst_device | flows |
|---|---|---|
| Amazon Echo Show | Amazon Alexa Echo Dot 2 | 1,105 |
| Amazon Alexa Echo Studio | Amazon Alexa Echo Dot 2 | 842 |
| Harman Kardon speaker (Ampak) | Amazon Alexa Echo Dot 2 | 402 |
| LG Smart TV | Amazon Alexa Echo Dot 2 | 296 |
| Amazon Alexa Echo Dot 2 | Harman Kardon speaker (Ampak) | 196 |
| Amazon Alexa Echo Dot 1 | Amazon Alexa Echo Dot 2 | 74 |
| Amazon Alexa Echo Dot 2 | Amazon Alexa Echo Dot 1 | 57 |
| Philips Hue Bridge | Amazon Alexa Echo Dot 2 | 54 |
| Amazon Alexa Echo Dot 2 | Amazon Alexa Echo Studio | 51 |
| Amazon Alexa Echo Dot 2 | Amazon Echo Show | 37 |

## Protocol-0 flows: 2,768

### By owner device

| owner_device | flows |
|---|---|
| Google Nest Mini Speaker | 472 |
| (invalid_parse) | 318 |
| Wyze Camera | 306 |
| (unowned) | 301 |
| Netatmo Camera | 282 |
| Philips Hue Bridge | 277 |
| LG Smart TV | 170 |
| Fibaro Home Center Lite | 111 |
| Amazon Echo Show | 109 |
| Amazon Alexa Echo Studio | 109 |
| Amazon Alexa Echo Dot 1 | 109 |
| (ambiguous) | 104 |
| Rbcior Camera | 27 |
| Aeotec Smart Home Hub | 8 |
| Wemo Smart Plug 2 | 8 |
| Smart Board | 5 |
| Cocoon Smart HVAC Fan | 3 |
| Arlo Q Indoor Camera | 3 |
| Teckin Plug 1 | 2 |
| Lumiman Bulb | 2 |
| Yi Outdoor Camera | 2 |
| Yutron Plug 1 | 2 |
| Yutron Plug 2 | 2 |
| Unidentified ESP plug (2) | 2 |
| GoSund Smart Plug WP2 (1) | 2 |
| D-Link DCS8000LHA1 Mini Camera | 2 |
| LampUX RGB | 2 |
| LIFX Lightbulb | 2 |
| Unidentified ESP plug (1) | 2 |
| AMCREST WiFi Camera | 2 |
| SmartThings Hub | 2 |
| Netatmo Weather Station | 2 |
| Unidentified ESP plug (3) | 1 |
| Teckin Light Strip | 1 |
| Ring Base Station | 1 |
| Levoit Air Purifier | 1 |
| Atomi Coffee Maker | 1 |
| Govee Smart Humidifier | 1 |
| HeimVision SmartLife Radio/Lamp | 1 |
| Teckin Plug 2 | 1 |
| Nest Indoor Camera | 1 |
| GoSund Smart Plug WP2 (2) | 1 |
| Amazon Smart Plug | 1 |
| Unidentified ESP plug (4) | 1 |
| GoSund Power Strip (2) | 1 |
| GoSund Power Strip (1) | 1 |
| TP-Link Tapo Camera | 1 |
| Yi Indoor Camera | 1 |
| Harman Kardon speaker (Ampak) | 1 |
| Yi Indoor 2 Camera | 1 |

### By (src_role, dst_role)

| src_role | dst_role | flows |
|---|---|---|
| iot | gateway | 711 |
| iot | external | 363 |
| external | external | 318 |
| iot | broadcast | 301 |
| external | iot | 265 |
| unknown | iot | 216 |
| iot | iot | 166 |
| unknown | gateway | 144 |
| excluded | broadcast | 142 |
| ambiguous | gateway | 103 |
| iot | unknown | 23 |
| testbed_pi | broadcast | 6 |
| testbed_pi | unknown | 5 |
| excluded | unknown | 2 |
| ambiguous | unknown | 1 |
| unknown | testbed_pi | 1 |
| unknown | unknown | 1 |

## Unowned flows: 12,739 -- by rule

| value | flows | pct |
|---|---|---|
| no_device:unknown-external | 4,703 | 2.108 |
| no_device:unknown-gateway | 2,673 | 1.198 |
| no_device:excluded-gateway | 2,380 | 1.067 |
| no_device:excluded-external | 943 | 0.423 |
| no_device:gateway-broadcast | 560 | 0.251 |
| no_device:testbed_pi-broadcast | 400 | 0.179 |
| no_device:excluded-broadcast | 341 | 0.153 |
| no_device:unspecified-broadcast | 256 | 0.115 |
| no_device:external-excluded | 177 | 0.079 |
| no_device:external-unknown | 101 | 0.045 |
| no_device:testbed_pi-external | 83 | 0.037 |
| no_device:gateway-testbed_pi | 53 | 0.024 |
| no_device:unknown-unknown | 36 | 0.016 |
| no_device:gateway-excluded | 12 | 0.005 |
| no_device:testbed_pi-gateway | 8 | 0.004 |
| no_device:testbed_pi-unknown | 5 | 0.002 |
| no_device:gateway-unknown | 3 | 0.001 |
| no_device:excluded-unknown | 2 | 0.001 |
| no_device:external-testbed_pi | 2 | 0.001 |
| no_device:unknown-testbed_pi | 1 | 0.0 |

## Endpoint roles

### Src

| value | flows | pct |
|---|---|---|
| iot | 166,174 | 74.481 |
| external | 43,270 | 19.394 |
| unknown | 7,629 | 3.419 |
| excluded | 3,666 | 1.643 |
| gateway | 1,150 | 0.515 |
| testbed_pi | 859 | 0.385 |
| unspecified | 256 | 0.115 |
| ambiguous | 104 | 0.047 |

### Dst

| value | flows | pct |
|---|---|---|
| external | 98,509 | 44.153 |
| gateway | 63,976 | 28.675 |
| iot | 46,969 | 21.052 |
| broadcast | 11,894 | 5.331 |
| testbed_pi | 1,399 | 0.627 |
| excluded | 189 | 0.085 |
| unknown | 171 | 0.077 |
| ambiguous | 1 | 0.0 |
