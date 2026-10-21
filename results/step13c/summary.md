# Step 13c -- frozen rate guard v1: benign false-alarm test on the Step 10 TEST period (one shot)

- run 2026-10-21T18:36:28+00:00, git HEAD `bb84e3923892853e02a0d03dde2fed470700a97d`, 13c_rate_guard_benign_fp.py sha256 `d52b60047f6d0c3e...`, runtime 781 s, peak RSS python 177 MB / tshark 177 MB
- frozen guard: `config/rate_guard_v1.json` (sha256 `894f75f1b40ad371...`, git blob `7c3762e10e95` == HEAD), rate_guard.py sha256 `ba7ebfa44ba1f431...` == results/step13/run_meta.json; window 10 s; alert iff packets > threshold: stream 159 / victim 321 (DEFAULT, incl. GRE), ICMP 159 / 321, IGMP 12 / 33
- test period already opened by Step 10: results/step10/TEST_OPENED.json (2026-10-19T20:32:08+00:00)
- input checks 24/24 PASS; consistency checks 32/32 PASS; every pcap sha256 == its record
- read: the TEST ranges only (08 / 08b cuts: time_split sessions from the start of test via the tshark filter, test / test_only sessions whole); never opened: train / val ranges, greeth parts, test.parquet
- packets: 13's reader unchanged (outer header, IPv4, no protocol filter); 13's exclusion unchanged in EVERY capture (attacker / testbed-Pi MAC as eth.src or eth.dst -> dropped before the guard); one RateGuard per capture range (TCP / UDP = clock ticks), flush() at the end
- benign-key alert = any alert in a benign capture, or in an attack-session capture an alert whose key carried no kept packet to / from that capture's attacker IP set in its window (07's cached set, IPv4 unicast); attack-related = the rest (not in C4)

## Pre-declared criterion (fixed before this run)

- **C4** benign-key guard alerts (both levels, all protos; key has no attacker / testbed-Pi MAC packets) over daytime + night test benign combined: exact Garwood 95 % UPPER bound of alerts per hour <= 0.5 / h

**C4: PASS** -- 0 benign-key alerts over 21.730 h; exact Garwood 95 % upper bound 3.689 alerts = **0.1698 / h** (limit 0.5 / h)

## Benign-key alerts per hour (exact Garwood 95 % CI)

| scope | benign_key_alerts | hours | alerts_per_h | ci95_lower_per_h | ci95_upper_per_h | ci95_count |
|---|---|---|---|---|---|---|
| daytime + night (C4) | 0 | 21.7304 | 0.0000 | 0.0000 | 0.1698 | [0.000, 3.689] |
| daytime | 0 | 18.7424 | 0.0000 | 0.0000 | 0.1968 | [0.000, 3.689] |
| night | 0 | 2.9880 | 0.0000 | 0.0000 | 1.2346 | [0.000, 3.689] |

## Hours (how computed)

Exposure = packet active time. Per capture range the KEPT IPv4 packets (after the exclusion) are split into segments at pauses > 300 s (split_plan_v1_1 active_idle_gap_seconds) between consecutive packets (running max of the timestamp); hours = sum over segments of (last - first), summed over captures. For comparison: raw span = last - first kept packet; 08 / 08b = the flow-based active benign hours of manifest_v1 / manifest_v1_1 (Step 10's FP / hour denominator).

| capture | period | range | first_kept_utc | last_kept_utc | active_segments | active_hours | raw_span_hours | flow_active_hours_08 |
|---|---|---|---|---|---|---|---|---|
| benign_night | night | [2022-10-08T01:09:09+00:00, end] | 2022-10-08T01:09:09.664Z | 2022-10-08T02:30:28.319Z | 1 | 1.355 | 1.355 | 1.355 |
| Recon-PortScan | night | [2022-09-27T15:06:20+00:00, end] | 2022-09-27T15:08:00.455Z | 2022-09-27T17:16:00.794Z | 4 | 0.434 | 2.133 | 0.462 |
| DDoS-SYN_Flood10 | night | whole capture | 2022-08-30T13:10:09.132Z | 2022-08-30T13:45:21.130Z | 1 | 0.587 | 0.587 | 0.587 |
| DDoS-SYN_Flood15 | night | whole capture | 2022-11-29T19:18:18.242Z | 2022-12-01T14:43:00.681Z | 2 | 0.362 | 43.412 | 0.362 |
| Mirai-udpplain24 | night | whole capture | 2023-02-07T16:23:57.830Z | 2023-02-14T17:38:00.593Z | 2 | 0.251 | 169.234 | 0.251 |
| BenignTraffic1 | daytime | whole capture | 2022-10-08T02:30:28.319Z | 2022-10-08T09:45:21.025Z | 1 | 7.248 | 7.248 | 7.248 |
| BenignTraffic2 | daytime | whole capture | 2022-10-08T09:45:21.039Z | 2022-10-08T17:47:21.040Z | 1 | 8.033 | 8.033 | 8.033 |
| BenignTraffic3 | daytime | whole capture | 2022-10-08T17:47:21.040Z | 2022-10-08T21:15:01.072Z | 1 | 3.461 | 3.461 | 3.461 |

Totals: packet active 21.730 h (C4 denominator); raw span 235.464 h; 08 / 08b flow-based 21.760 h.

## Every benign-key alert

_none_

## Attack-related alerts (attack-session captures; NOT in C4)

_none_

## Headroom: max benign packets per 10 s window vs threshold

Benign windows = non-empty windows of benign keys (attack-related key-windows left out). max_over_threshold = max / threshold (alert iff > 1); headroom_factor = threshold / max. Ties: the first window is listed, windows_at_max counts all.

| period | level | proto_name | threshold | nonempty_benign_windows | max_packets | max_over_threshold | headroom_factor | windows_over_threshold | max_capture | max_key | max_senders | max_receivers | max_window_start_utc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| all | stream | ICMP | 159 | 26,093 | 29 | 0.182 | 5.483 | 0 | Mirai-udpplain24 | 192.168.137.179 -> 192.168.137.171 ICMP | Wyze Camera | Unknown [unknown] | 2023-02-14T17:32:50.000Z |
| all | stream | IGMP | 12 | 1,439 | 6 | 0.500 | 2.000 | 0 | BenignTraffic1 | 192.168.137.61 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | multicast 01:00:5e:00:00:16 | 2022-10-08T07:12:00.000Z |
| all | victim | ICMP | 321 | 22,120 | 56 | 0.174 | 5.732 | 0 | Mirai-udpplain24 | * -> 192.168.137.1 ICMP | Cocoon Smart HVAC Fan; D-Link DCS8000LHA1 Mini Camera; SmartThings Hub; TP-Link Tapo Camera; Unknown [unknown]; Wemo Smart Plug 1 (+more) | Gateway / router [gateway] | 2023-02-14T17:31:50.000Z |
| all | victim | IGMP | 33 | 1,328 | 14 | 0.424 | 2.357 | 0 | DDoS-SYN_Flood10 | * -> 224.0.0.22 IGMP | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Philips Hue Bridge; Smart Board; Unidentified Amazon device (1c:12:b0) (+more) | multicast 01:00:5e:00:00:16 | 2022-08-30T13:33:30.000Z |
| daytime | stream | ICMP | 159 | 21,101 | 14 | 0.088 | 11.357 | 0 | BenignTraffic1 | 192.168.137.16 -> 192.168.137.1 ICMP | AMCREST WiFi Camera | Gateway / router [gateway] | 2022-10-08T08:29:50.000Z |
| daytime | stream | IGMP | 12 | 1,169 | 6 | 0.500 | 2.000 | 0 | BenignTraffic1 | 192.168.137.61 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | multicast 01:00:5e:00:00:16 | 2022-10-08T07:12:00.000Z |
| daytime | victim | ICMP | 321 | 18,429 | 56 | 0.174 | 5.732 | 0 | BenignTraffic2 | * -> 192.168.137.35 ICMP | Gateway / router [gateway]; Unknown [unknown] | Netatmo Camera | 2022-10-08T11:06:20.000Z |
| daytime | victim | IGMP | 33 | 1,113 | 10 | 0.303 | 3.300 | 0 | BenignTraffic2 | * -> 224.0.0.22 IGMP | AMCREST WiFi Camera; Aeotec Smart Home Hub; Amazon Alexa Echo Dot 1; Amazon Alexa Echo Studio; Philips Hue Bridge; Randomised MAC (phone/laptop) [excluded] (+more) | multicast 01:00:5e:00:00:16 | 2022-10-08T11:06:10.000Z |
| night | stream | ICMP | 159 | 4,992 | 29 | 0.182 | 5.483 | 0 | Mirai-udpplain24 | 192.168.137.179 -> 192.168.137.171 ICMP | Wyze Camera | Unknown [unknown] | 2023-02-14T17:32:50.000Z |
| night | stream | IGMP | 12 | 270 | 5 | 0.417 | 2.400 | 0 | DDoS-SYN_Flood10 | 192.168.137.12 -> 224.0.0.22 IGMP | Google Nest Mini Speaker | multicast 01:00:5e:00:00:16 | 2022-08-30T13:12:30.000Z |
| night | victim | ICMP | 321 | 3,691 | 56 | 0.174 | 5.732 | 0 | Mirai-udpplain24 | * -> 192.168.137.1 ICMP | Cocoon Smart HVAC Fan; D-Link DCS8000LHA1 Mini Camera; SmartThings Hub; TP-Link Tapo Camera; Unknown [unknown]; Wemo Smart Plug 1 (+more) | Gateway / router [gateway] | 2023-02-14T17:31:50.000Z |
| night | victim | IGMP | 33 | 215 | 14 | 0.424 | 2.357 | 0 | DDoS-SYN_Flood10 | * -> 224.0.0.22 IGMP | Amazon Alexa Echo Dot 1; Amazon Echo Show; Google Nest Mini Speaker; Philips Hue Bridge; Smart Board; Unidentified Amazon device (1c:12:b0) (+more) | multicast 01:00:5e:00:00:16 | 2022-08-30T13:33:30.000Z |

## Per capture

| capture | period | capture_kind | ipv4_test_packets | excluded_packets | kept_packets | in_scope_packets | in_scope_by_proto | gap_packets_dropped | late_packets | alerts | benign_key_alerts | attack_related_alerts | attacker_ip_collision_packets | runtime_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign_night | night | benign | 514,862 | 5,227 | 509,635 | 3,359 | ICMP: 3,162; IGMP: 197 | 0 | 0 | 0 | 0 | 0 | 0 | 49.6 |
| Recon-PortScan | night | attack | 163,468 | 40,579 | 122,889 | 1,361 | ICMP: 1,330; IGMP: 31 | 0 | 0 | 0 | 0 | 0 | 0 | 9.0 |
| DDoS-SYN_Flood10 | night | attack | 26,729,334 | 26,617,124 | 112,210 | 5,584 | ICMP: 5,459; IGMP: 125 | 0 | 0 | 0 | 0 | 0 | 0 | 368.3 |
| DDoS-SYN_Flood15 | night | attack | 13,702,048 | 13,623,109 | 78,939 | 4,175 | ICMP: 4,107; IGMP: 68 | 0 | 0 | 0 | 0 | 0 | 215 | 189.0 |
| Mirai-udpplain24 | night | attack | 1,491,008 | 1,453,176 | 37,832 | 4,020 | ICMP: 3,965; IGMP: 55 | 0 | 0 | 0 | 0 | 0 | 0 | 22.0 |
| BenignTraffic1 | daytime | benign | 2,885,502 | 28,002 | 2,857,500 | 18,107 | ICMP: 17,055; IGMP: 1,052 | 0 | 0 | 0 | 0 | 0 | 0 | 48.2 |
| BenignTraffic2 | daytime | benign | 3,027,237 | 49,219 | 2,978,018 | 18,789 | ICMP: 17,964; IGMP: 825 | 0 | 0 | 0 | 0 | 0 | 0 | 47.4 |
| BenignTraffic3 | daytime | benign | 1,265,458 | 12,621 | 1,252,837 | 7,510 | ICMP: 7,304; IGMP: 206 | 0 | 0 | 0 | 0 | 0 | 0 | 20.3 |

Excluded packets (attacker / testbed-Pi MAC) per capture:

- benign_night: eth.dst ATTACKER_MACS: 2,597; eth.src ATTACKER_MACS: 2,630 | by proto: TCP 2,991, UDP 1,804, ICMP 429, IGMP 3
- Recon-PortScan: eth.dst ATTACKER_MACS: 19,587; eth.src ATTACKER_MACS: 20,992 | by proto: TCP 40,472, UDP 107
- DDoS-SYN_Flood10: eth.dst ATTACKER_MACS: 203,333; eth.src ATTACKER_MACS: 26,413,791 | by proto: TCP 26,616,859, UDP 254, ICMP 9, IGMP 2
- DDoS-SYN_Flood15: eth.dst ATTACKER_MACS: 81,017; eth.src ATTACKER_MACS: 13,542,092 | by proto: TCP 13,622,712, UDP 378, ICMP 19
- Mirai-udpplain24: eth.dst ATTACKER_MACS: 1,498; eth.src ATTACKER_MACS: 1,451,678 | by proto: UDP 1,451,596, ICMP 1,185, TCP 395
- BenignTraffic1: eth.dst ATTACKER_MACS: 13,912; eth.src ATTACKER_MACS: 14,090 | by proto: TCP 15,860, UDP 9,635, ICMP 2,499, IGMP 8
- BenignTraffic2: eth.dst ATTACKER_MACS: 27,451; eth.src ATTACKER_MACS: 21,768 | by proto: TCP 36,772, UDP 9,473, ICMP 2,967, IGMP 7
- BenignTraffic3: eth.dst ATTACKER_MACS: 5,947; eth.src ATTACKER_MACS: 6,674 | by proto: TCP 7,631, UDP 3,870, ICMP 1,117, IGMP 3

Attacker IP sets (07's cache, attack-session captures) and IP collisions (kept packets sending from a set IP):

- Recon-PortScan: 192.168.137.127, 192.168.137.151, 192.168.137.178, 192.168.137.217, 192.168.137.27, 192.168.137.4, 192.168.137.64, 192.168.137.86, 192.168.137.98; collisions: none
- DDoS-SYN_Flood10: 192.168.137.134, 192.168.137.17, 192.168.137.195, 192.168.137.213, 192.168.137.224, 192.168.137.240, 192.168.137.242, 192.168.137.58, 192.168.137.90, 192.168.137.96; collisions: none
- DDoS-SYN_Flood15: 192.168.137.105, 192.168.137.153, 192.168.137.166, 192.168.137.200, 192.168.137.201, 192.168.137.238, 192.168.137.243, 192.168.137.34, 192.168.137.36, 192.168.137.60, 192.168.137.68, 192.168.137.7, 192.168.137.76, 192.168.137.87, 192.168.137.99; collisions: 192.168.137.68 from Netatmo Camera (70:ee:50:68:0e:32) 166, 192.168.137.76 from Atomi Coffee Maker (68:57:2d:56:ac:47) 49
- Mirai-udpplain24: 192.168.137.106, 192.168.137.11, 192.168.137.128, 192.168.137.13, 192.168.137.147, 192.168.137.162, 192.168.137.207, 192.168.137.236, 192.168.137.238, 192.168.137.247; collisions: none

## Outputs

summary.md, benign_alerts.csv, attack_related_alerts.csv, headroom.csv, per_capture.csv, run_meta.json
