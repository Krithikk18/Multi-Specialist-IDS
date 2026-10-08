# Flow CSV check report

- **input_csv**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/BenignTraffic.pcap_Flow__singlepkt.csv
- **input_pcap**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/raw/ciciot2023/benign/BenignTraffic.pcap
- **file_size_bytes**: 112,138,812
- **file_size_mb**: 106.94
- **sha256**: b8a757e7339c1a97c4941efa8f6bea2f07981651d86e699e606315a2ee8b2606
- **rows_pandas**: 223,108
- **columns_pandas**: 84
- **columns_header**: 84
- **run_timestamp**: 2026-10-07T18:14:32+00:00
- **python_version**: 3.11.17
- **pandas_version**: 3.0.6
- **conda_env_prefix**: /home/krithikk/miniconda3/envs/lgids

## Summary

| Check | Status | Key number | Reason |
|---|---|---|---|
| 1 Structure | **PASS** | 0 bad rows | all 223,108 data rows have 84 fields |
| 2 Packet total | **WARN** | 3,605,764 / 3,664,164 | 58,400 packets (1.5938%) not in flows -- expected for non-IP (ARP, etc.) and possibly IPv6/unsupported packets |
| 3 Single-packet flows | **PASS** | 39,478 (17.6946%) | single-packet flows present -> patched CICFlowMeter build was used |
| 4 Time span | **PASS** | offset -0.000 h | CSV start matches pcap first packet within 0 s; both sides in UTC |
| 5 Flow duration | **PASS** | max 120,000,000 us | no flow exceeds the 120 s flow timeout |
| 6 NaN / Infinity | **WARN** | 236,938 bad cells | 236,938 NaN/inf cells in 6 columns; rate columns: 0 bad values NOT explained by duration==0 (expected artefact) |
| 7 Protocol mix | **PASS** | UDP 52.4%, TCP 46.4%, other/unknown 1.2% | only protocols 0/6/17 present |
| 8 Duplicates | **PASS** | 7 full / 7 w/o FlowID | duplicates 0.0031% of rows (<= 0.1% threshold) |
| 9 IPs | **PASS** | 497 src / 1,144 dst distinct | no blank src/dst IPs |

## Column mapping

- flow_id -> `Flow ID`
- src_ip -> `Src IP`
- dst_ip -> `Dst IP`
- src_port -> `Src Port`
- dst_port -> `Dst Port`
- protocol -> `Protocol`
- timestamp -> `Timestamp`
- flow_duration -> `Flow Duration`
- tot_fwd_pkts -> `Total Fwd Packet`
- tot_bwd_pkts -> `Total Bwd packets`
- flow_bytes_s -> `Flow Bytes/s`
- flow_pkts_s -> `Flow Packets/s`

## 1 Structure -- PASS

_all 223,108 data rows have 84 fields_

- **data_rows_csv_module**: 223,108
- **header_fields**: 84
- **bad_rows**: 0
- **first_bad_lines**: []

## 2 Packet total -- WARN

_58,400 packets (1.5938%) not in flows -- expected for non-IP (ARP, etc.) and possibly IPv6/unsupported packets_

- **flow_packet_sum**: 3,605,764
- **pcap_packets**: 3,664,164
- **gap_abs**: 58,400
- **gap_pct**: 1.5938

## 3 Single-packet flows -- PASS

_single-packet flows present -> patched CICFlowMeter build was used_

- **single_packet_flows**: 39,478
- **single_packet_pct**: 17.6946
- **flows_with_le0_packets**: 0
- **packets_per_flow**:
  - **1**:
    - **flows**: 39,478
    - **pct**: 17.6946
  - **2**:
    - **flows**: 80,371
    - **pct**: 36.0234
  - **3-10**:
    - **flows**: 75,437
    - **pct**: 33.8119
  - **11-100**:
    - **flows**: 26,073
    - **pct**: 11.6863
  - **101-1000**:
    - **flows**: 1,153
    - **pct**: 0.5168
  - **>1000**:
    - **flows**: 596
    - **pct**: 0.2671

## 4 Time span -- PASS

_CSV start matches pcap first packet within 0 s; both sides in UTC_

- **raw_first_row**: 07/10/2022 05:15:01 PM
- **raw_last_row**: 08/10/2022 01:29:08 AM
- **raw_at_min**: 07/10/2022 05:15:00 PM
- **raw_at_max**: 08/10/2022 02:30:28 AM
- **format_detected**: %d/%m/%Y %I:%M:%S %p
- **format_trials**:
  - format=%d/%m/%Y %I:%M:%S %p, unparsed_unique=0, span_s=33,328
  - format=%m/%d/%Y %I:%M:%S %p, unparsed_unique=0, span_s=2,625,328
  - format=%d/%m/%Y %H:%M:%S, unparsed_unique=32,317, span_s=None
  - format=%m/%d/%Y %H:%M:%S, unparsed_unique=32,317, span_s=None
  - format=%Y-%m-%d %H:%M:%S, unparsed_unique=32,317, span_s=None
- **unparsed_rows**: 0
- **csv_min**: 2022-10-07T17:15:00
- **csv_max**: 2022-10-08T02:30:28
- **csv_max_flow_end**: 2022-10-08T02:30:28.208824
- **csv_span_s**: 33,328
- **local_tz_of_this_run**: UTC
- **capinfos_exe**: /usr/bin/capinfos
- **capinfos_output**:

```
File name:           /mnt/d/Projects/Company Project/Paper_Implemetation/data/raw/ciciot2023/benign/BenignTraffic.pcap
First packet time:   1665162900.350417
Last packet time:    1665196228.319030
```

- **pcap_first_epoch**: 1,665,162,900.3504
- **pcap_last_epoch**: 1,665,196,228.319
- **pcap_first_utc**: 2022-10-07T17:15:00.350416899
- **pcap_last_utc**: 2022-10-08T02:30:28.319030046
- **pcap_span_s**: 33,327.9686
- **offset_csv_min_minus_pcap_first_h**: -0.0001
- **offset_csv_end_minus_pcap_last_h**: -0
- **csv_apparent_tz**: UTC-00:00
- **pcap_tz**: UTC (capinfos -S gives epoch seconds; converted here as UTC)

## 5 Flow duration -- PASS

_no flow exceeds the 120 s flow timeout_

- **max_duration_us**: 120,000,000
- **max_duration_s**: 120
- **min_duration_us**: 0
- **flows_over_120s**: 0
- **negative_durations**: 0
- **zero_duration_flows**: 39,513

## 6 NaN / Infinity -- WARN

_236,938 NaN/inf cells in 6 columns; rate columns: 0 bad values NOT explained by duration==0 (expected artefact)_

- **numeric_columns_checked**: 79
- **columns_with_bad_values**:
  - **Flow Bytes/s**:
    - **nan**: 32,309
    - **+inf**: 7,204
    - **-inf**: 0
    - **dtype_read**: float64
  - **Flow Packets/s**:
    - **nan**: 0
    - **+inf**: 39,513
    - **-inf**: 0
    - **dtype_read**: float64
  - **Flow IAT Mean**:
    - **nan**: 39,478
    - **+inf**: 0
    - **-inf**: 0
    - **dtype_read**: float64
  - **Flow IAT Std**:
    - **nan**: 39,478
    - **+inf**: 0
    - **-inf**: 0
    - **dtype_read**: float64
  - **Flow IAT Max**:
    - **nan**: 39,478
    - **+inf**: 0
    - **-inf**: 0
    - **dtype_read**: float64
  - **Flow IAT Min**:
    - **nan**: 39,478
    - **+inf**: 0
    - **-inf**: 0
    - **dtype_read**: float64
- **rate_columns_vs_zero_duration**:
  - **Flow Bytes/s**:
    - **bad_total**: 39,513
    - **bad_with_duration_0**: 39,513
    - **bad_with_duration_gt0**: 0
  - **Flow Packets/s**:
    - **bad_total**: 39,513
    - **bad_with_duration_0**: 39,513
    - **bad_with_duration_gt0**: 0
- **zero_duration_flows**: 39,513

## 7 Protocol mix -- PASS

_only protocols 0/6/17 present_

- **protocols**:
  - **17**:
    - **name**: UDP
    - **flows**: 116,887
    - **pct**: 52.3903
  - **6**:
    - **name**: TCP
    - **flows**: 103,453
    - **pct**: 46.369
  - **0**:
    - **name**: other/unknown
    - **flows**: 2,768
    - **pct**: 1.2407

## 8 Duplicates -- PASS

_duplicates 0.0031% of rows (<= 0.1% threshold)_

- **full_row_duplicates**: 7
- **full_row_dup_pct**: 0.0031
- **dups_ignoring_flow_id**: 7
- **dups_ignoring_flow_id_pct**: 0.0031

## 9 IPs -- PASS

_no blank src/dst IPs_

- **blank_src**: 0
- **blank_dst**: 0
- **distinct_src**: 497
- **distinct_dst**: 1,144
- **distinct_any**: 1,153
- **top10_ips**:
  - **192.168.137.41**: 101,507
  - **192.168.137.1**: 65,125
  - **157.249.81.141**: 64,645
  - **192.168.137.133**: 21,760
  - **192.168.137.249**: 11,210
  - **192.168.137.47**: 9,815
  - **192.168.137.227**: 9,609
  - **8.8.8.8**: 8,506
  - **8.8.4.4**: 7,345
  - **255.255.255.255**: 6,492

## All CSV columns

1. `Flow ID`
2. `Src IP`
3. `Src Port`
4. `Dst IP`
5. `Dst Port`
6. `Protocol`
7. `Timestamp`
8. `Flow Duration`
9. `Total Fwd Packet`
10. `Total Bwd packets`
11. `Total Length of Fwd Packet`
12. `Total Length of Bwd Packet`
13. `Fwd Packet Length Max`
14. `Fwd Packet Length Min`
15. `Fwd Packet Length Mean`
16. `Fwd Packet Length Std`
17. `Bwd Packet Length Max`
18. `Bwd Packet Length Min`
19. `Bwd Packet Length Mean`
20. `Bwd Packet Length Std`
21. `Flow Bytes/s`
22. `Flow Packets/s`
23. `Flow IAT Mean`
24. `Flow IAT Std`
25. `Flow IAT Max`
26. `Flow IAT Min`
27. `Fwd IAT Total`
28. `Fwd IAT Mean`
29. `Fwd IAT Std`
30. `Fwd IAT Max`
31. `Fwd IAT Min`
32. `Bwd IAT Total`
33. `Bwd IAT Mean`
34. `Bwd IAT Std`
35. `Bwd IAT Max`
36. `Bwd IAT Min`
37. `Fwd PSH Flags`
38. `Bwd PSH Flags`
39. `Fwd URG Flags`
40. `Bwd URG Flags`
41. `Fwd Header Length`
42. `Bwd Header Length`
43. `Fwd Packets/s`
44. `Bwd Packets/s`
45. `Packet Length Min`
46. `Packet Length Max`
47. `Packet Length Mean`
48. `Packet Length Std`
49. `Packet Length Variance`
50. `FIN Flag Count`
51. `SYN Flag Count`
52. `RST Flag Count`
53. `PSH Flag Count`
54. `ACK Flag Count`
55. `URG Flag Count`
56. `CWR Flag Count`
57. `ECE Flag Count`
58. `Down/Up Ratio`
59. `Average Packet Size`
60. `Fwd Segment Size Avg`
61. `Bwd Segment Size Avg`
62. `Fwd Bytes/Bulk Avg`
63. `Fwd Packet/Bulk Avg`
64. `Fwd Bulk Rate Avg`
65. `Bwd Bytes/Bulk Avg`
66. `Bwd Packet/Bulk Avg`
67. `Bwd Bulk Rate Avg`
68. `Subflow Fwd Packets`
69. `Subflow Fwd Bytes`
70. `Subflow Bwd Packets`
71. `Subflow Bwd Bytes`
72. `FWD Init Win Bytes`
73. `Bwd Init Win Bytes`
74. `Fwd Act Data Pkts`
75. `Fwd Seg Size Min`
76. `Active Mean`
77. `Active Std`
78. `Active Max`
79. `Active Min`
80. `Idle Mean`
81. `Idle Std`
82. `Idle Max`
83. `Idle Min`
84. `Label`
