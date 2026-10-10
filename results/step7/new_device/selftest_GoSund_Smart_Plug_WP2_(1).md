# 06c -- new-device placement: GoSund Smart Plug WP2 (1) (b8:f0:09:03:29:79)

- mode: **self-test**; run 2026-10-10T18:16:49+00:00; groups `/mnt/d/Projects/Company Project/Paper_Implemetation/config/behaviour_groups.json` v1.0 (locked, not modified)
- pcap: `/home/krithikk/lgids_cache/BenignTraffic.pcap` sha256 `549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8`
- flows: extracted `/mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/BenignTraffic.pcap_Flow__singlepkt.csv`; 03b overall **WARN** {'1 Structure': 'PASS', '2 Packet total': 'WARN', '3 Single-packet flows': 'PASS', '4 Time span': 'PASS', '5 Flow duration': 'PASS', '6 NaN / Infinity': 'WARN', '7 Protocol mix': 'PASS', '8 Duplicates': 'PASS', '9 IPs': 'PASS'}
- map: `/mnt/d/Projects/Company Project/Paper_Implemetation/config/ip_mac_map.csv` (109 rows, 1 overlapping IP conflicts); tagging: {'conflicts': 1, 'ambiguous_before': 10673, 'resolved_flows': 10568, 'flows': 223108, 'ambiguous_after': 105, 'tagged_csv': '/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/new_device/selftest/BenignTraffic_tagged.csv', 'identical_to_existing_benign_tagged_csv': True}
- device IP(s) in this pcap's map: ['192.168.137.79']

## Normalisation (05)

05 time-normalises only `log_flows_per_hour` = usable flows / capture hours, where capture hours = first..last Timestamp over ALL flows in the input CSV (every device shares one window); all other features are per-flow distributions or shares, and gap_cv is scale-free. 06c applies exactly this to the pcap's flow CSV.

## Flow counts per filter step

| step | flows |
|---|---|
| all_flows_in_capture | 223,108 |
| device_on_either_side | 542 |
| owned_by_device | 542 |
| owned_and_exclude_reason_blank | 542 |
| dropped_other_endpoint_attacker | 0 |
| usable_for_fingerprint | 542 |

## Features (capture hours 9.2578, usable flows 542)

| feature | raw | scaled | locked_raw | locked_scaled |
|---|---|---|---|---|
| log_flows_per_hour | 1.77485 | -0.0921975 | 1.77485 | -0.092197 |
| log_median_bytes | 3.16301 | 0.845231 | 3.16301 | 0.845231 |
| log_p90_bytes | 3.67219 | 0.0665798 | 3.67219 | 0.06658 |
| median_packets | 16.5 | 0.701031 | 16.5 | 0.701031 |
| pct_single_packet | 0.369 | -0.127965 | 0.369 | -0.127965 |
| log_median_duration_us | 8.07875 | 0.106573 | 8.07875 | 0.106573 |
| upload_ratio | 0.973331 | 0.219135 | 0.973331 | 0.219135 |
| pct_udp | 50.554 | 0.0367666 | 50.554 | 0.036767 |
| pct_dns | 0 | -0.239678 | 0 | -0.239678 |
| pct_discovery | 0 | 0 | 0 | 0 |
| gap_cv | 0.623783 | -0.378919 | 0.623783 | -0.378919 |
| pct_internet | 49.077 | -0.166869 | 49.077 | -0.166869 |
| pct_device | 0 | 0 | 0 | 0 |
| log_distinct_peers | 0.845098 | -0.219464 | 0.845098 | -0.219464 |

## Placement (locked rule)

- distance to G1 centroid **3.3835** (ratio to G1 max spread 0.568, to median 1.277)
- distance to G2 centroid **0.709** (ratio to G2 max spread 0.159, to median 0.651)
- max spreads: G1 5.953133, G2 4.445154
- **decision: G2** -- nearest centroid G2 within its max spread (0.709 <= 4.445)

## Self-test

| device | usable_flows | max_abs_diff_raw_15 | max_abs_diff_scaled_14 | decision | locked_group | PASS |
|---|---|---|---|---|---|---|
| GoSund Smart Plug WP2 (1) | 542 vs locked 542 | 0.00e+00 | 4.99e-07 | G2 | G2 | True |

## Context: locked fingerprints of existing speakers (benign capture)

| device | locked_group | usable_flows | d_G1 | d_G2 | d_G1/max | d_G2/max |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Dot 1 | G1 | 1,573 | 2.5711 | 3.2212 | 0.432 | 0.725 |
| Amazon Alexa Echo Dot 2 | G1 | 372 | 5.9531 | 7.1078 | 1.0 | 1.599 |
| Amazon Alexa Echo Studio | G1 | 3,252 | 3.056 | 3.9344 | 0.513 | 0.885 |
| Amazon Echo Show | G1 | 5,247 | 2.6493 | 4.2375 | 0.445 | 0.953 |
| Google Nest Mini Speaker | G1 | 3,891 | 1.9615 | 2.8124 | 0.329 | 0.633 |
