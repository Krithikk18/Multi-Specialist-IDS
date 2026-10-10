# 06c -- new-device placement: Amazon Alexa Echo Dot 1 (1c:fe:2b:98:16:dd)

- mode: **self-test**; run 2026-10-10T18:16:49+00:00; groups `/mnt/d/Projects/Company Project/Paper_Implemetation/config/behaviour_groups.json` v1.0 (locked, not modified)
- pcap: `/home/krithikk/lgids_cache/BenignTraffic.pcap` sha256 `549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8`
- flows: extracted `/mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/BenignTraffic.pcap_Flow__singlepkt.csv`; 03b overall **WARN** {'1 Structure': 'PASS', '2 Packet total': 'WARN', '3 Single-packet flows': 'PASS', '4 Time span': 'PASS', '5 Flow duration': 'PASS', '6 NaN / Infinity': 'WARN', '7 Protocol mix': 'PASS', '8 Duplicates': 'PASS', '9 IPs': 'PASS'}
- map: `/mnt/d/Projects/Company Project/Paper_Implemetation/config/ip_mac_map.csv` (109 rows, 1 overlapping IP conflicts); tagging: {'conflicts': 1, 'ambiguous_before': 10673, 'resolved_flows': 10568, 'flows': 223108, 'ambiguous_after': 105, 'tagged_csv': '/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/new_device/selftest/BenignTraffic_tagged.csv', 'identical_to_existing_benign_tagged_csv': True}
- device IP(s) in this pcap's map: ['192.168.137.250']

## Normalisation (05)

05 time-normalises only `log_flows_per_hour` = usable flows / capture hours, where capture hours = first..last Timestamp over ALL flows in the input CSV (every device shares one window); all other features are per-flow distributions or shares, and gap_cv is scale-free. 06c applies exactly this to the pcap's flow CSV.

## Flow counts per filter step

| step | flows |
|---|---|
| all_flows_in_capture | 223,108 |
| device_on_either_side | 1,630 |
| owned_by_device | 1,573 |
| owned_and_exclude_reason_blank | 1,573 |
| dropped_other_endpoint_attacker | 0 |
| usable_for_fingerprint | 1,573 |

## Features (capture hours 9.2578, usable flows 1573)

| feature | raw | scaled | locked_raw | locked_scaled |
|---|---|---|---|---|
| log_flows_per_hour | 2.23277 | 0.642453 | 2.23277 | 0.642453 |
| log_median_bytes | 2.44091 | -0.255507 | 2.44091 | -0.255507 |
| log_p90_bytes | 3.8791 | 0.311069 | 3.8791 | 0.311069 |
| median_packets | 14 | 0.494845 | 14 | 0.494845 |
| pct_single_packet | 4.768 | 0.346871 | 4.768 | 0.346871 |
| log_median_duration_us | 7.56971 | -0.0808633 | 7.56971 | -0.080863 |
| upload_ratio | 0.388223 | -0.827797 | 0.388223 | -0.827797 |
| pct_udp | 17.864 | -1.3099 | 17.864 | -1.3099 |
| pct_dns | 15.385 | 0.732749 | 15.385 | 0.732749 |
| pct_discovery | 1.017 | 0.0252584 | 1.017 | 0.025258 |
| gap_cv | 1.19914 | 0.235622 | 1.19914 | 0.235622 |
| pct_internet | 71.011 | 0.544592 | 71.011 | 0.544592 |
| pct_device | 4.704 | 0.353551 | 4.704 | 0.353551 |
| log_distinct_peers | 2.03743 | 2.17802 | 2.03743 | 2.17802 |

## Placement (locked rule)

- distance to G1 centroid **2.5711** (ratio to G1 max spread 0.432, to median 0.971)
- distance to G2 centroid **3.2212** (ratio to G2 max spread 0.725, to median 2.957)
- max spreads: G1 5.953133, G2 4.445154
- **decision: G1** -- nearest centroid G1 within its max spread (2.571 <= 5.953)

## Self-test

| device | usable_flows | max_abs_diff_raw_15 | max_abs_diff_scaled_14 | decision | locked_group | PASS |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Dot 1 | 1573 vs locked 1573 | 0.00e+00 | 4.21e-07 | G1 | G1 | True |

## Context: locked fingerprints of existing speakers (benign capture)

| device | locked_group | usable_flows | d_G1 | d_G2 | d_G1/max | d_G2/max |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Dot 1 | G1 | 1,573 | 2.5711 | 3.2212 | 0.432 | 0.725 |
| Amazon Alexa Echo Dot 2 | G1 | 372 | 5.9531 | 7.1078 | 1.0 | 1.599 |
| Amazon Alexa Echo Studio | G1 | 3,252 | 3.056 | 3.9344 | 0.513 | 0.885 |
| Amazon Echo Show | G1 | 5,247 | 2.6493 | 4.2375 | 0.445 | 0.953 |
| Google Nest Mini Speaker | G1 | 3,891 | 1.9615 | 2.8124 | 0.329 | 0.633 |
