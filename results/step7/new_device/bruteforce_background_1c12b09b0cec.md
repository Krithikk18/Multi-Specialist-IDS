# 06c -- new-device placement: Unidentified Amazon device (1c:12:b0) (1c:12:b0:9b:0c:ec)

- mode: **apply**; run 2026-10-10T18:31:17+00:00; groups `/mnt/d/Projects/Company Project/Paper_Implemetation/config/behaviour_groups.json` v1.0 (locked, not modified)
- pcap: `/home/krithikk/lgids_cache/ciciot2023/attack/DictionaryBruteForce/DictionaryBruteForce.pcap` sha256 `09ad3cfabd139b950da3078fec0f0fd196fe36cd82237d898035437f4c69161b`
- flows: reused `/mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/attack/DictionaryBruteForce/DictionaryBruteForce.pcap_Flow__singlepkt.csv`; 03b overall **WARN** {'1 Structure': 'PASS', '2 Packet total': 'WARN', '3 Single-packet flows': 'PASS', '4 Time span': 'PASS', '5 Flow duration': 'PASS', '6 NaN / Infinity': 'WARN', '7 Protocol mix': 'PASS', '8 Duplicates': 'PASS', '9 IPs': 'PASS'}
- map: `/mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/maps/DictionaryBruteForce_ip_mac_map.csv` (142 rows, 1 overlapping IP conflicts); tagging: {'conflicts': 1, 'ambiguous_before': 1169, 'resolved_flows': 264, 'flows': 9795, 'ambiguous_after': 905, 'tagged_csv': '/mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/attack/DictionaryBruteForce/DictionaryBruteForce.pcap_Flow__singlepkt_tagged_newdev.csv'}
- device IP(s) in this pcap's map: ['192.168.137.206', '192.168.137.50']

## Normalisation (05)

05 time-normalises only `log_flows_per_hour` = usable flows / capture hours, where capture hours = first..last Timestamp over ALL flows in the input CSV (every device shares one window); all other features are per-flow distributions or shares, and gap_cv is scale-free. 06c applies exactly this to the pcap's flow CSV.

## Flow counts per filter step

| step | flows |
|---|---|
| all_flows_in_capture | 9,795 |
| device_on_either_side | 243 |
| owned_by_device | 219 |
| owned_and_exclude_reason_blank | 219 |
| dropped_other_endpoint_attacker | 0 |
| usable_for_fingerprint | 219 |

## Features (capture hours 70.7333, usable flows 219)

| feature | raw | scaled | raw_segment | scaled_segment |
|---|---|---|---|---|
| log_flows_per_hour | 0.612374 | -1.95717 | 2.60314 | 1.23665 |
| log_median_bytes | 1.50515 | -1.68193 | 1.50515 | -1.68193 |
| log_p90_bytes | 3.14302 | -0.558717 | 3.14302 | -0.558717 |
| median_packets | 2 | -0.494845 | 2 | -0.494845 |
| pct_single_packet | 14.155 | 1.36012 | 14 | 1.34339 |
| log_median_duration_us | 5.50756 | -0.840183 | 5.9829 | -0.665154 |
| upload_ratio | 0.682378 | -0.301466 | 0.629463 | -0.396147 |
| pct_udp | 17.352 | -1.33099 | 18 | -1.3043 |
| pct_dns | 14.612 | 0.68389 | 15 | 0.708414 |
| pct_discovery | 0 | 0 | 0 | 0 |
| gap_cv | 14.3306 | 3 | 2.08004 | 1.17653 |
| pct_internet | 56.164 | 0.0630078 | 54 | -0.00718468 |
| pct_device | 3.196 | 0.24021 | 2.5 | 0.187899 |
| log_distinct_peers | 1.61278 | 1.32417 | 1.51851 | 1.13461 |

## Placement (locked rule)

- distance to G1 centroid **4.3544** (ratio to G1 max spread 0.731, to median 1.644)
- distance to G2 centroid **5.3257** (ratio to G2 max spread 1.198, to median 4.888)
- max spreads: G1 5.953133, G2 4.445154
- **decision: G1** -- nearest centroid G1 within its max spread (4.354 <= 5.953)

## Sensitivity: largest contiguous capture segment (report only)

- capture segments (flow gaps > 600 s split): 2022-10-14 16:18:00+00:00 -> 2022-10-14 16:19:00+00:00 (247 flows); 2022-10-14 16:32:00+00:00 -> 2022-10-14 16:33:00+00:00 (417 flows); 2022-10-17 13:21:00+00:00 -> 2022-10-17 13:51:00+00:00 (7,908 flows); 2022-10-17 14:56:00+00:00 -> 2022-10-17 15:02:00+00:00 (1,223 flows)
- segment 2022-10-17 13:21:00+00:00 -> 2022-10-17 13:51:00+00:00: capture hours 0.5, usable flows 200
- distances G1 2.2317 / G2 4.1556; ratio to max spread G1 0.375 / G2 0.935 -> **G1** (nearest centroid G1 within its max spread (2.232 <= 5.953))

## Context: locked fingerprints of existing speakers (benign capture)

| device | locked_group | usable_flows | d_G1 | d_G2 | d_G1/max | d_G2/max |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Dot 1 | G1 | 1,573 | 2.5711 | 3.2212 | 0.432 | 0.725 |
| Amazon Alexa Echo Dot 2 | G1 | 372 | 5.9531 | 7.1078 | 1.0 | 1.599 |
| Amazon Alexa Echo Studio | G1 | 3,252 | 3.056 | 3.9344 | 0.513 | 0.885 |
| Amazon Echo Show | G1 | 5,247 | 2.6493 | 4.2375 | 0.445 | 0.953 |
| Google Nest Mini Speaker | G1 | 3,891 | 1.9615 | 2.8124 | 0.329 | 0.633 |

## Applied

- added 1c:12:b0:9b:0c:ec as G1 to /mnt/d/Projects/Company Project/Paper_Implemetation/config/device_table.csv; backup /mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/new_device/device_table_backup_20261010T183117Z.csv
