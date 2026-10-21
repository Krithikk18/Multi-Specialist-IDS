# Step 13b -- frozen rate guard v1 on Mirai greeth_flood (GRE flood)

- run 2026-10-21T16:39:24+00:00, git HEAD `95df416d19503181d3fa7cc24d25d5663a4935cb`, 13b_rate_guard_eval.py sha256 `6ccbb65ce1af050a...`, runtime 205 s, peak RSS python 136 MB / tshark 144 MB
- frozen guard: `config/rate_guard_v1.json` (sha256 `894f75f1b40ad371...`, git blob `7c3762e10e95` == HEAD), rate_guard.py sha256 `ba7ebfa44ba1f431...` == results/step13/run_meta.json; window 10 s; alert iff packets > threshold: stream 159 / victim 321 (DEFAULT, incl. GRE), ICMP 159 / 321, IGMP 12 / 33
- captures: Mirai-greeth_flood.pcap (DESIGN DATA, sha256 `87f8de16e575f23f...` == config/sha256_greeth.txt, 12b cached copy reused); Mirai-greeth_flood9.pcap (VALIDATION, sha256 `ccaa6f7dc7ef5a73...` == config/sha256_greeth.txt, copied to the cache); Mirai-greeth_flood18.pcap (VALIDATION, sha256 `4de6b847ae0b9c4a...` == config/sha256_greeth.txt, copied to the cache)
- never opened: Mirai-greeth_flood27 / 28 (reserved fresh test), test.parquet
- packets: 13's tshark reader unchanged (outer header, IPv4, no protocol filter); one RateGuard per capture over every IPv4 packet in file order (TCP / UDP = clock ticks, nothing excluded), flush() at the end
- attacker = outer eth.src in config ATTACKER_MACS; attack key = stream with attacker-sent packets / victim key (dst, 47) receiving attacker GRE; benign key = no attacker-MAC packet (eth.src or eth.dst) on the key; other = the rest
- alert time = capture ts of the clock tick that closed the window (flush: window end); latency = alert time - the victim's first attacker GRE packet

## Pre-declared criteria (fixed before this run)

- **C1** every attacked victim key (dst_ip, 47) raises a victim-level alert, and every GRE attacker stream with >= 1,000 packets raises a stream-level alert
- **C2** first alert for each attacked victim key <= 20 s after that victim's first attacker GRE packet
- **C3** 0 alerts on keys with NO attacker-MAC packets (benign keys)

## Verdict per capture

| capture | role | C1 | C2 | C3 | victims alerted | streams >= 1k alerted | max latency s | benign alerts | victim windows alerted |
|---|---|---|---|---|---|---|---|---|---|
| Mirai-greeth_flood.pcap | DESIGN DATA | PASS | PASS | PASS | 2/2 | 14/14 | 5.9 | 0 | 81/81 |
| Mirai-greeth_flood9.pcap | VALIDATION | PASS | PASS | PASS | 4/4 | 28/28 | 9.5 | 0 | 202/202 |
| Mirai-greeth_flood18.pcap | VALIDATION | PASS | PASS | PASS | 2/2 | 14/14 | 5.1 | 0 | 93/93 |

## DESIGN DATA -- already used in 12b / 12c to see the attack; reported for completeness, not evidence

### 1. Mirai-greeth_flood.pcap (DESIGN DATA)

- 3,340,156 IPv4 packets 2023-01-12T15:19:00.107Z .. 2023-01-12T15:37:06.823Z (18.1 min); attacker-sent 3,254,749 (GRE 3,254,376, UDP 164, TCP 141, ICMP 66, IGMP 2)
- non-TCP/UDP: GRE 3,254,376, ICMP 2,619, IGMP 86; keys 180 stream / 76 victim; guard: 86 windows closed, 557 alerts, late packets 0, max active keys 116
- consistency checks 4/4 PASS; tshark + loop 46 s

**C1 detection: PASS** -- attacked victim keys alerted 2/2; GRE attacker streams >= 1,000 packets alerted 14/14; GRE streams in total 14 (0 of those under 1,000 packets alerted)

**C2 latency: PASS** -- max 5.85 s (limit 20 s)

**C3 false alerts: PASS** -- 0 alerts on 0 benign keys

Latency per attacked victim key (victim level):

| dst_ip | victim_device | victim_group | attacker_gre_packets | attacker_streams | first_attacker_gre_utc | first_alert_window_start_utc | first_alert_packets | first_alert_emitted_utc | latency_s | latency_to_window_end_s |
|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.254 | Amazon Alexa Echo Dot 1 | G1 | 2,438,431 | 7 | 2023-01-12T15:19:44.145Z | 2023-01-12T15:19:40.000Z | 31,237 | 2023-01-12T15:19:50.000Z | 5.85 | 5.85 |
| 192.168.137.242 | AMCREST WiFi Camera | G1 | 815,945 | 7 | 2023-01-12T15:34:18.731Z | 2023-01-12T15:34:10.000Z | 5,644 | 2023-01-12T15:34:20.000Z | 1.27 | 1.27 |

Attack 10 s windows alerted (reported, no criterion; edge = the key's first / last attack window, usually partial):

| dst_ip | victim_attack_windows | victim_alerted_windows | victim_share_alerted | victim_unalerted_edge_windows | victim_unalerted_interior_windows | victim_unalerted_max_attacker_packets | any_level_alerted_windows | any_level_share_alerted |
|---|---|---|---|---|---|---|---|---|
| 192.168.137.254 | 63 | 63 | 1.000 | 0 | 0 | 0 | 63 | 1.000 |
| 192.168.137.242 | 18 | 18 | 1.000 | 0 | 0 | 0 | 18 | 1.000 |

- victim level: 81/81 = 1.000; victim or any of its attacker streams: 81/81 = 1.000; stream level (streams >= 1,000): 476/478 = 0.996
- benign-key alerts per hour: 0.00 (0 over 0.302 h)
- alerts on attacker keys that are not GRE: 0
- alerts by class x level: attack stream 476, attack victim 81

GRE attacker streams (ground truth; full table in ground_truth_streams.csv):

| src_ip | dst_ip | attacker_packets | first_utc | last_utc | victim_device | c1_in_scope | stream_alerted | attack_windows | alerted_windows | unalerted_interior_windows | first_stream_alert_latency_s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.238 | 192.168.137.254 | 565,273 | 2023-01-12T15:19:44.156Z | 2023-01-12T15:29:59.945Z | Amazon Alexa Echo Dot 1 | True | True | 55 | 54 | 1 | 5.84 |
| 192.168.137.150 | 192.168.137.254 | 449,463 | 2023-01-12T15:19:52.807Z | 2023-01-12T15:30:01.136Z | Amazon Alexa Echo Dot 1 | True | True | 57 | 57 | 0 | 7.20 |
| 192.168.137.128 | 192.168.137.254 | 401,081 | 2023-01-12T15:19:44.164Z | 2023-01-12T15:30:01.044Z | Amazon Alexa Echo Dot 1 | True | True | 54 | 54 | 0 | 5.84 |
| 192.168.137.207 | 192.168.137.254 | 340,814 | 2023-01-12T15:19:44.948Z | 2023-01-12T15:30:00.749Z | Amazon Alexa Echo Dot 1 | True | True | 49 | 48 | 1 | 5.05 |
| 192.168.137.106 | 192.168.137.254 | 274,887 | 2023-01-12T15:19:44.190Z | 2023-01-12T15:29:48.779Z | Amazon Alexa Echo Dot 1 | True | True | 52 | 52 | 0 | 5.81 |
| 192.168.137.147 | 192.168.137.254 | 230,053 | 2023-01-12T15:19:44.288Z | 2023-01-12T15:29:46.103Z | Amazon Alexa Echo Dot 1 | True | True | 43 | 43 | 0 | 5.71 |
| 192.168.137.238 | 192.168.137.242 | 198,522 | 2023-01-12T15:34:19.102Z | 2023-01-12T15:37:06.538Z | AMCREST WiFi Camera | True | True | 18 | 18 | 0 | 0.90 |
| 192.168.137.162 | 192.168.137.254 | 176,860 | 2023-01-12T15:19:44.145Z | 2023-01-12T15:30:01.134Z | Amazon Alexa Echo Dot 1 | True | True | 47 | 47 | 0 | 5.85 |
| 192.168.137.128 | 192.168.137.242 | 132,589 | 2023-01-12T15:34:18.868Z | 2023-01-12T15:37:06.786Z | AMCREST WiFi Camera | True | True | 18 | 18 | 0 | 1.13 |
| 192.168.137.106 | 192.168.137.242 | 114,843 | 2023-01-12T15:34:19.040Z | 2023-01-12T15:37:06.818Z | AMCREST WiFi Camera | True | True | 18 | 18 | 0 | 0.96 |
| 192.168.137.207 | 192.168.137.242 | 112,509 | 2023-01-12T15:34:18.731Z | 2023-01-12T15:37:06.760Z | AMCREST WiFi Camera | True | True | 18 | 18 | 0 | 1.27 |
| 192.168.137.150 | 192.168.137.242 | 94,026 | 2023-01-12T15:34:19.059Z | 2023-01-12T15:37:06.823Z | AMCREST WiFi Camera | True | True | 17 | 17 | 0 | 0.94 |
| 192.168.137.162 | 192.168.137.242 | 87,821 | 2023-01-12T15:34:42.891Z | 2023-01-12T15:37:06.006Z | AMCREST WiFi Camera | True | True | 15 | 15 | 0 | 7.11 |
| 192.168.137.147 | 192.168.137.242 | 75,635 | 2023-01-12T15:34:22.806Z | 2023-01-12T15:37:06.809Z | AMCREST WiFi Camera | True | True | 17 | 17 | 0 | 7.19 |

Every benign-key alert:

_none_

Alerts on attacker keys that are not GRE:

_none_

## VALIDATION -- first touch of parts 9 and 18

### 2. Mirai-greeth_flood9.pcap (VALIDATION)

- 3,429,034 IPv4 packets 2023-01-12T18:57:08.520Z .. 2023-01-12T19:42:21.599Z (45.2 min); attacker-sent 3,320,459 (GRE 3,319,942, UDP 196, TCP 180, ICMP 141)
- non-TCP/UDP: GRE 3,319,942, ICMP 29,585, IGMP 162; keys 229 stream / 79 victim; guard: 210 windows closed, 1,319 alerts, late packets 0, max active keys 68
- consistency checks 4/4 PASS; tshark + loop 51 s

**C1 detection: PASS** -- attacked victim keys alerted 4/4; GRE attacker streams >= 1,000 packets alerted 28/28; GRE streams in total 28 (0 of those under 1,000 packets alerted)

**C2 latency: PASS** -- max 9.48 s (limit 20 s)

**C3 false alerts: PASS** -- 0 alerts on 0 benign keys

Latency per attacked victim key (victim level):

| dst_ip | victim_device | victim_group | attacker_gre_packets | attacker_streams | first_attacker_gre_utc | first_alert_window_start_utc | first_alert_packets | first_alert_emitted_utc | latency_s | latency_to_window_end_s |
|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.61 | unknown | unknown | 1,177,349 | 7 | 2023-01-12T18:57:08.520Z | 2023-01-12T18:57:00.000Z | 6,907 | 2023-01-12T18:57:10.006Z | 1.49 | 1.48 |
| 192.168.137.64 | GoSund Power Strip (2) | G2 | 1,011,964 | 7 | 2023-01-12T19:08:30.558Z | 2023-01-12T19:08:30.000Z | 14,683 | 2023-01-12T19:08:40.037Z | 9.48 | 9.44 |
| 192.168.137.172 | Unidentified ESP plug (2) | G2 | 722,235 | 7 | 2023-01-12T19:38:18.980Z | 2023-01-12T19:38:10.000Z | 951 | 2023-01-12T19:38:20.019Z | 1.04 | 1.02 |
| 192.168.137.44 | GoSund Smart Plug WP2 (1) | G2 | 408,394 | 7 | 2023-01-12T19:23:45.916Z | 2023-01-12T19:23:40.000Z | 6,104 | 2023-01-12T19:23:50.000Z | 4.08 | 4.08 |

Attack 10 s windows alerted (reported, no criterion; edge = the key's first / last attack window, usually partial):

| dst_ip | victim_attack_windows | victim_alerted_windows | victim_share_alerted | victim_unalerted_edge_windows | victim_unalerted_interior_windows | victim_unalerted_max_attacker_packets | any_level_alerted_windows | any_level_share_alerted |
|---|---|---|---|---|---|---|---|---|
| 192.168.137.61 | 49 | 49 | 1.000 | 0 | 0 | 0 | 49 | 1.000 |
| 192.168.137.64 | 64 | 64 | 1.000 | 0 | 0 | 0 | 64 | 1.000 |
| 192.168.137.172 | 26 | 26 | 1.000 | 0 | 0 | 0 | 26 | 1.000 |
| 192.168.137.44 | 63 | 63 | 1.000 | 0 | 0 | 0 | 63 | 1.000 |

- victim level: 202/202 = 1.000; victim or any of its attacker streams: 202/202 = 1.000; stream level (streams >= 1,000): 1116/1188 = 0.939
- benign-key alerts per hour: 0.00 (0 over 0.754 h)
- alerts on attacker keys that are not GRE: 1
- alerts by class x level: attack stream 1,116, attack victim 202, other stream 1

GRE attacker streams (ground truth; full table in ground_truth_streams.csv):

| src_ip | dst_ip | attacker_packets | first_utc | last_utc | victim_device | c1_in_scope | stream_alerted | attack_windows | alerted_windows | unalerted_interior_windows | first_stream_alert_latency_s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.238 | 192.168.137.61 | 338,605 | 2023-01-12T18:57:08.531Z | 2023-01-12T19:05:01.409Z | unknown | True | True | 39 | 39 | 0 | 1.48 |
| 192.168.137.106 | 192.168.137.61 | 293,579 | 2023-01-12T18:57:50.287Z | 2023-01-12T19:05:01.388Z | unknown | True | True | 31 | 31 | 0 | 9.71 |
| 192.168.137.207 | 192.168.137.64 | 234,519 | 2023-01-12T19:08:45.813Z | 2023-01-12T19:18:53.529Z | GoSund Power Strip (2) | True | True | 60 | 60 | 0 | 4.19 |
| 192.168.137.238 | 192.168.137.64 | 167,101 | 2023-01-12T19:08:39.927Z | 2023-01-12T19:19:00.889Z | GoSund Power Strip (2) | True | True | 55 | 52 | 2 | 10.08 |
| 192.168.137.128 | 192.168.137.64 | 149,055 | 2023-01-12T19:08:30.641Z | 2023-01-12T19:19:01.276Z | GoSund Power Strip (2) | True | True | 52 | 49 | 3 | 9.40 |
| 192.168.137.147 | 192.168.137.64 | 141,497 | 2023-01-12T19:08:30.600Z | 2023-01-12T19:19:01.351Z | GoSund Power Strip (2) | True | True | 56 | 54 | 2 | 9.44 |
| 192.168.137.238 | 192.168.137.172 | 137,147 | 2023-01-12T19:38:38.787Z | 2023-01-12T19:42:16.422Z | Unidentified ESP plug (2) | True | True | 21 | 20 | 1 | 1.21 |
| 192.168.137.162 | 192.168.137.172 | 136,817 | 2023-01-12T19:38:20.304Z | 2023-01-12T19:42:21.059Z | Unidentified ESP plug (2) | True | True | 23 | 23 | 0 | 9.70 |
| 192.168.137.162 | 192.168.137.64 | 136,648 | 2023-01-12T19:08:30.558Z | 2023-01-12T19:18:55.446Z | GoSund Power Strip (2) | True | True | 50 | 46 | 4 | 9.48 |
| 192.168.137.128 | 192.168.137.61 | 134,511 | 2023-01-12T18:57:08.520Z | 2023-01-12T19:05:01.371Z | unknown | True | True | 32 | 32 | 0 | 1.49 |
| 192.168.137.106 | 192.168.137.64 | 134,192 | 2023-01-12T19:08:42.167Z | 2023-01-12T19:19:01.327Z | GoSund Power Strip (2) | True | True | 51 | 50 | 1 | 7.83 |
| 192.168.137.106 | 192.168.137.172 | 131,917 | 2023-01-12T19:38:19.096Z | 2023-01-12T19:42:21.586Z | Unidentified ESP plug (2) | True | True | 26 | 25 | 1 | 0.92 |
| 192.168.137.238 | 192.168.137.44 | 115,790 | 2023-01-12T19:23:45.959Z | 2023-01-12T19:34:00.435Z | GoSund Smart Plug WP2 (1) | True | True | 59 | 52 | 6 | 4.04 |
| 192.168.137.207 | 192.168.137.61 | 109,618 | 2023-01-12T18:57:14.864Z | 2023-01-12T19:04:59.697Z | unknown | True | True | 30 | 30 | 0 | 5.14 |
| 192.168.137.207 | 192.168.137.172 | 102,172 | 2023-01-12T19:38:32.053Z | 2023-01-12T19:42:21.599Z | Unidentified ESP plug (2) | True | True | 22 | 22 | 0 | 7.95 |
| 192.168.137.150 | 192.168.137.61 | 101,990 | 2023-01-12T18:57:09.779Z | 2023-01-12T19:04:56.548Z | unknown | True | True | 33 | 31 | 1 | 10.22 |
| 192.168.137.162 | 192.168.137.61 | 100,736 | 2023-01-12T18:57:08.691Z | 2023-01-12T19:04:51.254Z | unknown | True | True | 32 | 31 | 1 | 1.32 |
| 192.168.137.147 | 192.168.137.61 | 98,310 | 2023-01-12T18:57:11.232Z | 2023-01-12T19:04:06.073Z | unknown | True | True | 32 | 32 | 0 | 8.77 |
| 192.168.137.128 | 192.168.137.172 | 90,744 | 2023-01-12T19:38:18.980Z | 2023-01-12T19:42:21.388Z | Unidentified ESP plug (2) | True | True | 23 | 22 | 1 | 1.04 |
| 192.168.137.207 | 192.168.137.44 | 90,356 | 2023-01-12T19:23:45.999Z | 2023-01-12T19:34:00.288Z | GoSund Smart Plug WP2 (1) | True | True | 61 | 60 | 0 | 4.00 |
| 192.168.137.147 | 192.168.137.172 | 77,429 | 2023-01-12T19:38:19.002Z | 2023-01-12T19:42:16.879Z | Unidentified ESP plug (2) | True | True | 23 | 23 | 0 | 1.02 |
| 192.168.137.162 | 192.168.137.44 | 56,949 | 2023-01-12T19:23:45.916Z | 2023-01-12T19:33:59.716Z | GoSund Smart Plug WP2 (1) | True | True | 59 | 58 | 1 | 4.08 |
| 192.168.137.128 | 192.168.137.44 | 54,505 | 2023-01-12T19:23:45.918Z | 2023-01-12T19:33:59.192Z | GoSund Smart Plug WP2 (1) | True | True | 59 | 54 | 5 | 4.08 |
| 192.168.137.150 | 192.168.137.64 | 48,952 | 2023-01-12T19:08:31.111Z | 2023-01-12T19:18:56.675Z | GoSund Power Strip (2) | True | True | 55 | 48 | 7 | 8.93 |
| 192.168.137.150 | 192.168.137.172 | 46,009 | 2023-01-12T19:38:31.839Z | 2023-01-12T19:42:21.151Z | Unidentified ESP plug (2) | True | True | 21 | 21 | 0 | 8.16 |
| 192.168.137.147 | 192.168.137.44 | 39,212 | 2023-01-12T19:23:46.426Z | 2023-01-12T19:34:00.568Z | GoSund Smart Plug WP2 (1) | True | True | 63 | 60 | 2 | 3.57 |
| 192.168.137.106 | 192.168.137.44 | 37,751 | 2023-01-12T19:23:46.063Z | 2023-01-12T19:34:00.550Z | GoSund Smart Plug WP2 (1) | True | True | 62 | 54 | 8 | 3.94 |
| 192.168.137.150 | 192.168.137.44 | 13,831 | 2023-01-12T19:23:45.965Z | 2023-01-12T19:34:00.485Z | GoSund Smart Plug WP2 (1) | True | True | 58 | 37 | 19 | 14.04 |

Every benign-key alert:

_none_

Alerts on attacker keys that are not GRE:

| level | key_class | src_ip | dst_ip | proto_name | packets | threshold | window_start_utc | key_attacker_src_packets | key_attacker_dst_packets | senders | receivers |
|---|---|---|---|---|---|---|---|---|---|---|---|
| stream | other | 192.168.137.44 | 192.168.137.238 | ICMP | 248 | 159 | 2023-01-12T19:25:40.000Z | 0 | 2,960 | GoSund Smart Plug WP2 (1) (G2) | Raspberry Pi 4 (2 GB) (attacker) |

### 3. Mirai-greeth_flood18.pcap (VALIDATION)

- 3,387,871 IPv4 packets 2023-01-16T14:03:24.907Z .. 2023-01-16T14:22:37.230Z (19.2 min); attacker-sent 3,351,543 (GRE 3,351,233, TCP 169, ICMP 91, UDP 50)
- non-TCP/UDP: GRE 3,351,233, ICMP 5,534, IGMP 39; keys 150 stream / 63 victim; guard: 99 windows closed, 632 alerts, late packets 0, max active keys 73
- consistency checks 4/4 PASS; tshark + loop 51 s

**C1 detection: PASS** -- attacked victim keys alerted 2/2; GRE attacker streams >= 1,000 packets alerted 14/14; GRE streams in total 14 (0 of those under 1,000 packets alerted)

**C2 latency: PASS** -- max 5.09 s (limit 20 s)

**C3 false alerts: PASS** -- 0 alerts on 0 benign keys

Latency per attacked victim key (victim level):

| dst_ip | victim_device | victim_group | attacker_gre_packets | attacker_streams | first_attacker_gre_utc | first_alert_window_start_utc | first_alert_packets | first_alert_emitted_utc | latency_s | latency_to_window_end_s |
|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.29 | TP-Link Tapo Camera | G1 | 1,717,968 | 7 | 2023-01-16T14:03:24.907Z | 2023-01-16T14:03:20.000Z | 21,064 | 2023-01-16T14:03:30.000Z | 5.09 | 5.09 |
| 192.168.137.140 | Rbcior Camera | G1 | 1,633,265 | 7 | 2023-01-16T14:13:55.235Z | 2023-01-16T14:13:50.000Z | 18,722 | 2023-01-16T14:14:00.000Z | 4.76 | 4.76 |

Attack 10 s windows alerted (reported, no criterion; edge = the key's first / last attack window, usually partial):

| dst_ip | victim_attack_windows | victim_alerted_windows | victim_share_alerted | victim_unalerted_edge_windows | victim_unalerted_interior_windows | victim_unalerted_max_attacker_packets | any_level_alerted_windows | any_level_share_alerted |
|---|---|---|---|---|---|---|---|---|
| 192.168.137.29 | 41 | 41 | 1.000 | 0 | 0 | 0 | 41 | 1.000 |
| 192.168.137.140 | 52 | 52 | 1.000 | 0 | 0 | 0 | 52 | 1.000 |

- victim level: 93/93 = 1.000; victim or any of its attacker streams: 93/93 = 1.000; stream level (streams >= 1,000): 539/555 = 0.971
- benign-key alerts per hour: 0.00 (0 over 0.320 h)
- alerts on attacker keys that are not GRE: 0
- alerts by class x level: attack stream 539, attack victim 93

GRE attacker streams (ground truth; full table in ground_truth_streams.csv):

| src_ip | dst_ip | attacker_packets | first_utc | last_utc | victim_device | c1_in_scope | stream_alerted | attack_windows | alerted_windows | unalerted_interior_windows | first_stream_alert_latency_s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.137.238 | 192.168.137.29 | 852,220 | 2023-01-16T14:03:24.907Z | 2023-01-16T14:10:00.418Z | TP-Link Tapo Camera | True | True | 41 | 41 | 0 | 5.09 |
| 192.168.137.238 | 192.168.137.140 | 851,638 | 2023-01-16T14:13:55.318Z | 2023-01-16T14:22:37.230Z | Rbcior Camera | True | True | 46 | 46 | 0 | 4.68 |
| 192.168.137.207 | 192.168.137.29 | 169,923 | 2023-01-16T14:03:25.640Z | 2023-01-16T14:09:51.574Z | TP-Link Tapo Camera | True | True | 39 | 37 | 2 | 4.36 |
| 192.168.137.106 | 192.168.137.29 | 168,240 | 2023-01-16T14:03:24.986Z | 2023-01-16T14:10:00.236Z | TP-Link Tapo Camera | True | True | 39 | 39 | 0 | 5.01 |
| 192.168.137.128 | 192.168.137.140 | 166,344 | 2023-01-16T14:13:55.346Z | 2023-01-16T14:22:25.072Z | Rbcior Camera | True | True | 41 | 40 | 1 | 4.65 |
| 192.168.137.128 | 192.168.137.29 | 156,243 | 2023-01-16T14:03:24.938Z | 2023-01-16T14:09:58.570Z | TP-Link Tapo Camera | True | True | 38 | 38 | 0 | 5.06 |
| 192.168.137.150 | 192.168.137.29 | 154,805 | 2023-01-16T14:03:24.931Z | 2023-01-16T14:10:00.442Z | TP-Link Tapo Camera | True | True | 41 | 40 | 1 | 5.07 |
| 192.168.137.147 | 192.168.137.140 | 140,099 | 2023-01-16T14:13:55.235Z | 2023-01-16T14:22:25.610Z | Rbcior Camera | True | True | 37 | 34 | 2 | 4.76 |
| 192.168.137.207 | 192.168.137.140 | 129,280 | 2023-01-16T14:13:55.252Z | 2023-01-16T14:22:37.171Z | Rbcior Camera | True | True | 39 | 39 | 0 | 4.75 |
| 192.168.137.162 | 192.168.137.140 | 120,203 | 2023-01-16T14:14:05.598Z | 2023-01-16T14:22:30.090Z | Rbcior Camera | True | True | 41 | 39 | 1 | 4.40 |
| 192.168.137.106 | 192.168.137.140 | 117,343 | 2023-01-16T14:13:55.427Z | 2023-01-16T14:22:37.177Z | Rbcior Camera | True | True | 35 | 32 | 3 | 4.57 |
| 192.168.137.162 | 192.168.137.29 | 109,587 | 2023-01-16T14:03:27.441Z | 2023-01-16T14:10:00.028Z | TP-Link Tapo Camera | True | True | 39 | 37 | 1 | 2.56 |
| 192.168.137.150 | 192.168.137.140 | 108,358 | 2023-01-16T14:14:00.955Z | 2023-01-16T14:22:37.127Z | Rbcior Camera | True | True | 39 | 39 | 0 | 9.04 |
| 192.168.137.147 | 192.168.137.29 | 106,950 | 2023-01-16T14:03:25.057Z | 2023-01-16T14:10:00.436Z | TP-Link Tapo Camera | True | True | 40 | 38 | 1 | 4.94 |

Every benign-key alert:

_none_

Alerts on attacker keys that are not GRE:

_none_

## Cross-check vs 12b (base part)

GRE attacker streams here 14 vs 12b 14, packets and first / last identical: True; attacker GRE packets here 3,254,376 vs 12b 3,254,376 -> MATCH

## Outputs

summary.md, alerts.csv (every alert, classified), ground_truth_streams.csv (GRE attacker streams), latency.csv (per attacked victim key), run_meta.json
