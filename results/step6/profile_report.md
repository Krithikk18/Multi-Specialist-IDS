# Step 6 -- device behaviour fingerprints

- **run_timestamp_utc**: 2026-10-10T07:51:32+00:00
- **flows**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/benign_flows_tagged.csv
- **flows_sha256**: f9c033abaf07289999f4c1300f09b00a48624aecd2a63ef0a5ec7632abf2c799
- **devices**: /mnt/d/Projects/Company Project/Paper_Implemetation/config/device_table.csv
- **devices_sha256**: 50dcde5b0dd547d580cdb9124e7d12ffdcb40f4a2d2b3c9804ec7af9df67945c
- **out_dir**: /mnt/d/Projects/Company Project/Paper_Implemetation/results/step6
- **min_flows**: 100
- **corr_threshold**: 0.9
- **timestamp_format**: %d/%m/%Y %I:%M:%S %p (UTC)
- **columns_matched**: {'src_ip': 'Src IP', 'dst_ip': 'Dst IP', 'src_port': 'Src Port', 'dst_port': 'Dst Port', 'protocol': 'Protocol', 'timestamp': 'Timestamp', 'duration': 'Flow Duration', 'fwd_pkts': 'Total Fwd Packet', 'bwd_pkts': 'Total Bwd packets', 'fwd_bytes': 'Total Length of Fwd Packet', 'bwd_bytes': 'Total Length of Bwd Packet', 'src_mac': 'src_mac', 'dst_mac': 'dst_mac', 'src_role': 'src_role', 'dst_role': 'dst_role', 'owner_mac': 'owner_mac', 'owner_device': 'owner_device', 'owner_status': 'owner_status', 'exclude_reason': 'exclude_reason'}
- **capture_start_utc**: 2022-10-07T17:15:00+00:00
- **capture_end_utc**: 2022-10-08T02:30:28+00:00
- **capture_hours**: 9.2578
- **python**: 3.11.17
- **pandas**: 3.0.6
- **numpy**: 2.4.6
- **scipy**: 1.17.1
- **matplotlib**: 3.11.2
- **runtime_s**: 11.4

## Integrity: **PASS**

- **input_rows**: 223108
- **sum_usable_flows_over_devices**: 204844
- **usable_flows**: 204844
- **sum_equals_usable**: True
- **smart_home_devices_in_table**: 55
- **devices_in_fingerprints**: 55
- **every_smart_home_device_present**: True
- **usable_owners_not_smart_home**: []
- **owner_on_src_or_dst_side_for_all_usable**: True
- **kept_features_nonempty**: True
- **all_figures_written**: True
- **flows_sha256_unchanged**: True
- **devices_sha256_unchanged**: True

## Usable-flow filter

- **input_rows**: 223108
- **owned**: 209946
- **owned_but_excluded**: 5102
- **owned_excluded_by_reason**: {'ip_clash_artifact': 5102}
- **usable**: 204844
- **usable_pct_of_input**: 91.814
- **usable_owner_devices**: 55
- **owner_is_src**: 161072
- **owner_is_dst**: 43772

## Confidence

- **min_flows**: 100
- **high**: 52 devices, **low**: 3 devices (of which 0 with 0 usable flows)
- **zero_flow_devices**: none

Sensitivity (devices below threshold):

| min_flows | n_low | n_high | low_devices |
|---|---|---|---|
| 50 | 2 | 53 | iRobot Roomba; Wemo Smart Plug 1 |
| 100 | 3 | 52 | Smart Board; iRobot Roomba; Wemo Smart Plug 1 |
| 200 | 3 | 52 | Smart Board; iRobot Roomba; Wemo Smart Plug 1 |

Low-confidence devices:

| device_name | category | usable_flows |
|---|---|---|
| Wemo Smart Plug 1 | Power Outlet | 13 |
| iRobot Roomba | Home Automation | 32 |
| Smart Board | Home Automation | 64 |

## Correlation pruning

- **method**: Spearman over 52 high-confidence devices; |rho| > 0.9, strongest pair first, drop lower priority
- **kept (14)**: log_flows_per_hour, log_median_bytes, log_p90_bytes, median_packets, pct_single_packet, log_median_duration_us, upload_ratio, pct_udp, pct_dns, pct_discovery, gap_cv, pct_internet, pct_device, log_distinct_peers
- **dropped (1)**: pct_tcp

| order | dropped | partner_kept | rho |
|---|---|---|---|
| 1 | pct_tcp | pct_udp | -0.9657 |

All pairs with |rho| > threshold (before pruning):

| a | b | rho |
|---|---|---|
| pct_tcp | pct_udp | -0.9657 |

Robust-scaling parameters (fit on high-confidence devices):

| feature | median | iqr | scale_used | iqr_zero_fallback |
|---|---|---|---|---|
| log_flows_per_hour | 1.832317 | 0.62332 | 0.6233197500000001 | False |
| log_median_bytes | 2.608526 | 0.656017 | 0.6560174999999999 | False |
| log_p90_bytes | 3.615845 | 0.846278 | 0.8462782500000001 | False |
| median_packets | 8.0 | 12.125 | 12.125 | False |
| pct_single_packet | 1.5545 | 9.26425 | 9.26425 | False |
| log_median_duration_us | 7.789321 | 2.715787 | 2.7157867499999986 | False |
| upload_ratio | 0.850861 | 0.558879 | 0.5588785000000001 | False |
| pct_udp | 49.6615 | 24.27475 | 24.274749999999997 | False |
| pct_dns | 3.792 | 15.82125 | 15.821250000000001 | False |
| pct_discovery | 0.0 | 2.266 | 2.266 | False |
| gap_cv | 0.978538 | 0.936231 | 0.9362312500000001 | False |
| pct_internet | 54.2215 | 30.8295 | 30.829499999999996 | False |
| pct_device | 0.0 | 0.02325 | 0.02325 | False |
| log_distinct_peers | 0.954243 | 0.497325 | 0.4973249999999999 | False |

## Per-feature summary (raw values)

| feature | family | scope | n | nan | min | q25 | median | q75 | max |
|---|---|---|---|---|---|---|---|---|---|
| log_flows_per_hour | Volume | all | 55 | 0 | 0.381 | 1.7433 | 1.8289 | 2.378 | 4.04 |
| log_flows_per_hour | Volume | high | 52 | 0 | 1.4032 | 1.7717 | 1.8323 | 2.395 | 4.04 |
| log_median_bytes | Volume | all | 55 | 0 | 0.0 | 2.4063 | 2.6085 | 3.046 | 5.1771 |
| log_median_bytes | Volume | high | 52 | 0 | 0.0 | 2.4365 | 2.6085 | 3.0925 | 5.1771 |
| log_p90_bytes | Volume | all | 55 | 0 | 1.9494 | 2.8115 | 3.6158 | 3.6722 | 5.2854 |
| log_p90_bytes | Volume | high | 52 | 0 | 1.9494 | 2.8263 | 3.6158 | 3.6726 | 5.2854 |
| median_packets | Shape | all | 55 | 0 | 1.0 | 3.0 | 8.0 | 16.0 | 1552.5 |
| median_packets | Shape | high | 52 | 0 | 1.0 | 4.0 | 8.0 | 16.125 | 1552.5 |
| pct_single_packet | Shape | all | 55 | 0 | 0.0 | 0.1845 | 1.623 | 10.507 | 61.538 |
| pct_single_packet | Shape | high | 52 | 0 | 0.0 | 0.1847 | 1.5545 | 9.449 | 59.14 |
| log_median_duration_us | Shape | all | 55 | 0 | 0.0 | 5.3086 | 7.7886 | 8.0434 | 8.0789 |
| log_median_duration_us | Shape | high | 52 | 0 | 0.0 | 5.332 | 7.7893 | 8.0478 | 8.0789 |
| upload_ratio | Shape | all | 55 | 0 | 0.1553 | 0.3936 | 0.8391 | 0.956 | 1.0 |
| upload_ratio | Shape | high | 52 | 0 | 0.1637 | 0.3963 | 0.8509 | 0.9552 | 0.9971 |
| pct_tcp | Protocol | all | 55 | 0 | 0.0 | 38.379 | 49.355 | 67.422 | 96.599 |
| pct_tcp | Protocol | high | 52 | 0 | 0.0 | 40.4947 | 49.355 | 67.1445 | 96.599 |
| pct_udp | Protocol | all | 55 | 0 | 2.759 | 32.3335 | 50.366 | 61.318 | 100.0 |
| pct_udp | Protocol | high | 52 | 0 | 2.759 | 32.6783 | 49.6615 | 56.953 | 99.982 |
| pct_dns | Services | all | 55 | 0 | 0.0 | 0.0 | 3.789 | 15.2725 | 75.762 |
| pct_dns | Services | high | 52 | 0 | 0.0 | 0.1695 | 3.792 | 15.9908 | 75.762 |
| pct_discovery | Services | all | 55 | 0 | 0.0 | 0.0 | 0.0 | 2.765 | 92.308 |
| pct_discovery | Services | high | 52 | 0 | 0.0 | 0.0 | 0.0 | 2.266 | 48.083 |
| gap_cv | Rhythm | all | 54 | 1 | 0.2062 | 0.6036 | 0.9785 | 1.5405 | 4.223 |
| gap_cv | Rhythm | high | 52 | 0 | 0.2062 | 0.601 | 0.9785 | 1.5373 | 4.223 |
| pct_internet | Peers | all | 55 | 0 | 0.0 | 49.071 | 54.472 | 81.336 | 100.0 |
| pct_internet | Peers | high | 52 | 0 | 0.0 | 49.071 | 54.2215 | 79.9005 | 99.543 |
| pct_device | Peers | all | 55 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 93.011 |
| pct_device | Peers | high | 52 | 0 | 0.0 | 0.0 | 0.0 | 0.0232 | 93.011 |
| log_distinct_peers | Peers | all | 55 | 0 | 0.4771 | 0.8116 | 0.9542 | 1.3323 | 2.2577 |
| log_distinct_peers | Peers | high | 52 | 0 | 0.6021 | 0.8451 | 0.9542 | 1.3424 | 2.2577 |

## Category → colour (Okabe-Ito, used in every figure)

| category | colour |
|---|---|
| Camera | #E69F00 |
| Audio | #56B4E9 |
| Hub | #009E73 |
| Home Automation | #F0E442 |
| Lighting | #0072B2 |
| Power Outlet | #D55E00 |
| Unidentified (Espressif) | #CC79A7 |

## Figures

- **fig1_feature_correlation** (fig1_feature_correlation.pdf, fig1_feature_correlation.png): Spearman rank correlation between the 15 candidate fingerprint features across 52 high-confidence devices; features marked * were removed (|ρ| > 0.9).
- **fig2_device_fingerprints** (fig2_device_fingerprints.pdf, fig2_device_fingerprints.png): Robust-scaled behaviour fingerprints (retained features) of each smart-home device, grouped by category; † hatched rows have fewer than 100 usable flows.
- **fig3_volume_vs_size** (fig3_volume_vs_size.pdf, fig3_volume_vs_size.png): Flow rate versus median flow size per device; colour shows category and marker area scales with log usable flows.
- **fig4_usable_flows** (fig4_usable_flows.pdf, fig4_usable_flows.png): Usable benign flows per smart-home device (log scale); the dashed line marks the 100-flow confidence threshold.
