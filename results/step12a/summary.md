# Step 12a -- Mirai data inventory (read-only)

- run 2026-10-20T05:50:02+00:00, git HEAD `6e7043b981cd553ecd448af720606821dc22d0e1`, 12a_mirai_inventory.py sha256 `4acca548e0f3faa9...`; parts list: none (path A: local parts only)
- no extraction, no training, no labelling; test.parquet never opened. Per-flow numbers from the existing 07 labelled CSVs, re-read with 08's filter and the manifest cut points; checks: PASS Mirai-udpplain: 07 attack flows == sum over victims == usable attack rows; PASS Mirai-udpplain24: 07 attack flows == sum over victims == usable attack rows; PASS Mirai dataset rows per (split, group) == manifest_v1 by_split_group_label_family

## 1-2. Mirai pcaps found locally, and their use

Searched (recursive, name contains 'mirai'): ~/lgids_cache/ciciot2023, data/raw.

| file | variant | part | alias | size_gb | packets | attacker_packets | first_utc | last_utc | used | session_mode | splits | used_in |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Mirai-udpplain.pcap | udpplain | (none) | Mirai first part | 2.05 | 3,642,269 | 3,563,700 | 2023-01-19T15:51:00.595065+00:00 | 2023-01-19T16:23:26.574506+00:00 | used | train | train+val | v1, v1_1 |
| Mirai-udpplain24.pcap | udpplain | 24 | Mirai 24 | 0.84 | 1,506,334 | 1,456,835 | 2023-02-07T16:23:57.789760+00:00 | 2023-02-14T17:38:00.630347+00:00 | used | test | test | v1, v1_1 |

- 2 local Mirai pcap(s), variant(s) ['udpplain']; 2 used, 0 unused. No greeth_flood / greip_flood or other udpplain part is present locally.

## 3. Yield of the used parts, per victim

| part | victim_device | group | attack_packets_07a | attack_flows_07 | attack_rows_train | attack_rows_val | attack_rows_test | packets_per_attack_flow_07a | pkts_median | pkts_max | dur_median_s | flows_near_120s_timeout | attack_5tuples | flows_if_only_120s_timeout |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Mirai-udpplain | Amazon Alexa Echo Dot 1 | G1 | 1,952,092 | 32 | 32 | 0 | 0 | 61,002.88 | 52,378.50 | 172,718.00 | 101.82 | 15 | 7 | 38 |
| Mirai-udpplain | Amazon Alexa Echo Studio | G1 | 1,262,306 | 21 | 21 | 0 | 0 | 60,109.81 | 56,320.00 | 112,248.00 | 119.19 | 14 | 7 | 21 |
| Mirai-udpplain | Google Nest Mini Speaker | G1 | 344,367 | 42 | 26 | 16 | 0 | 8,199.21 | 4.00 | 75,492.00 | 7.74 | 1 | 29 | 35 |
| Mirai-udpplain | Philips Hue Bridge | G1 | 132 | 16 | 16 | 0 | 0 | 8.25 | 8.00 | 15.00 | 1.42 | 0 | 16 | 16 |
| Mirai-udpplain | Gateway / router | gateway / not grouped | 30 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 0 | 0 | 0 |
| Mirai-udpplain | Amazon Echo Show | G1 | 8 | 1 | 0 | 1 | 0 | 8.00 | 1.00 | 1.00 | 0.00 | 0 | 1 | 1 |
| Mirai-udpplain | TOTAL G1 | G1 | 3,558,905 | 112 | 95 | 17 | 0 | N/A | 17,953.50 | 172,718.00 | 36.75 | 30 | 60 | 111 |
| Mirai-udpplain | TOTAL G2 | G2 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 0 | 0 | 0 |
| Mirai-udpplain | TOTAL ALL | ALL | 3,558,935 | 112 | 95 | 17 | 0 | N/A | 17,953.50 | 172,718.00 | 36.75 | 30 | 60 | 111 |
| Mirai-udpplain24 | D-Link DCS8000LHA1 Mini Camera | G2 | 1,162,421 | 15 | 0 | 0 | 15 | 77,494.73 | 71,040.00 | 202,690.00 | 113.43 | 7 | 7 | 17 |
| Mirai-udpplain24 | Teckin Plug 1 | G2 | 289,000 | 8 | 0 | 0 | 8 | 36,125.00 | 39,495.00 | 56,327.00 | 36.03 | 0 | 6 | 14 |
| Mirai-udpplain24 | Gateway / router | gateway / not grouped | 383 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 0 | 0 | 0 |
| Mirai-udpplain24 | Google Nest Mini Speaker | G1 | 219 | 25 | 0 | 0 | 25 | 8.76 | 2.00 | 30.00 | 0.23 | 0 | 12 | 12 |
| Mirai-udpplain24 | Philips Hue Bridge | G1 | 101 | 10 | 0 | 0 | 10 | 10.10 | 5.00 | 10.00 | 0.19 | 0 | 8 | 8 |
| Mirai-udpplain24 | Amazon Echo Show | G1 | 60 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 0 | 0 | 0 |
| Mirai-udpplain24 | TOTAL G1 | G1 | 380 | 35 | 0 | 0 | 35 | N/A | 2.00 | 30.00 | 0.23 | 0 | 20 | 20 |
| Mirai-udpplain24 | TOTAL G2 | G2 | 1,451,421 | 23 | 0 | 0 | 23 | N/A | 60,371.00 | 202,690.00 | 87.38 | 7 | 13 | 31 |
| Mirai-udpplain24 | TOTAL ALL | ALL | 1,452,184 | 58 | 0 | 0 | 58 | N/A | 7.50 | 202,690.00 | 7.00 | 7 | 33 | 51 |

attack_rows_<split> = dataset rows (08's filter + cuts; equal to manifest_v1 for every (split, group)); packets_per_attack_flow_07a = 07a attack packets / 07 attack flows; pkts_* = Total Fwd + Total Bwd packets of the victim's attack flows; flows_near_120s_timeout = flows lasting >= 115 s; flows_if_only_120s_timeout = per 5-tuple ceil(span / 120 s).

**Why so few flows.** A udpplain flood sends from a fixed source port to a fixed victim port, so each (attacker, victim) stream is ONE 5-tuple. CICFlowMeter starts a new flow only when the 120 s flow timeout expires or the stream idles > 5 s, so a flood of millions of packets becomes about (stream duration / 120 s) flows per 5-tuple:

- Mirai-udpplain: 3,558,935 attack packets -> 112 attack flows (31,776 packets per flow); the flows use 60 distinct 5-tuples, and the 120 s flow timeout alone would cut them into 111 flows; 30 flows last >= 115 s; median 17,954 packets, max 172,718
- Mirai-udpplain24: 1,452,184 attack packets -> 58 attack flows (25,038 packets per flow); the flows use 33 distinct 5-tuples, and the 120 s flow timeout alone would cut them into 51 flows; 7 flows last >= 115 s; median 8 packets, max 202,690

### Test Mirai flows (Mirai-udpplain24): packets per flow, G1 vs G2

| part | group | n_flows | pkts_min | pkts_p25 | pkts_median | pkts_p75 | pkts_p90 | pkts_max | dur_median_s | pkts_1 | pkts_2-10 | pkts_11-100 | pkts_101-1k | pkts_1k-10k | pkts_10k-100k | pkts_>100k | by_victim |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Mirai-udpplain24 | G1 | 35 | 1.00 | 2.00 | 2.00 | 5.00 | 10.00 | 30.00 | 0.23 | 4 | 28 | 3 | 0 | 0 | 0 | 0 | Google Nest Mini Speaker 25; Philips Hue Bridge 10 |
| Mirai-udpplain24 | G2 | 23 | 1,638.00 | 41,631.50 | 60,371.00 | 77,389.00 | 92,141.00 | 202,690.00 | 87.38 | 0 | 0 | 0 | 0 | 2 | 19 | 2 | D-Link DCS8000LHA1 Mini Camera 15; Teckin Plug 1 8 |

## 4. Yield rates (attack flows), per part and pooled

| scope | group | attack_flows | attack_packets | victims_with_flows | pcap_gb | flows_per_gb | flows_per_M_attack_packets | flows_per_victim | dataset_rows |
|---|---|---|---|---|---|---|---|---|---|
| Mirai-udpplain | G1 | 112 | 3,558,905 | 5 | 2.05 | 54.69 | 31.47 | 22.40 | 112 |
| Mirai-udpplain | G2 | 0 | 0 | 0 | 2.05 | 0.00 | N/A | N/A | 0 |
| Mirai-udpplain | ALL | 112 | 3,558,935 | 5 | 2.05 | 54.69 | 31.47 | 22.40 | 112 |
| Mirai-udpplain24 | G1 | 35 | 380 | 2 | 0.84 | 41.67 | 92,105.26 | 17.50 | 35 |
| Mirai-udpplain24 | G2 | 23 | 1,451,421 | 2 | 0.84 | 27.39 | 15.85 | 11.50 | 23 |
| Mirai-udpplain24 | ALL | 58 | 1,452,184 | 4 | 0.84 | 69.06 | 39.94 | 14.50 | 58 |
| POOLED | G1 | 147 | 3,559,285 | 7 | 2.89 | 50.90 | 41.30 | 21.00 | 147 |
| POOLED | G2 | 23 | 1,451,421 | 2 | 2.89 | 7.96 | 15.85 | 11.50 | 23 |
| POOLED | ALL | 170 | 5,011,119 | 9 | 2.89 | 58.87 | 33.92 | 18.89 | 170 |

Multiply flows_per_gb by a part's size for a first projection. The two parts disagree on group: the victims of each capture decide which group the flows land in, so per-group projections are only as good as the guess of who the victims are.

No parts list given (--parts-list): no per-part projection; use the rates above.

## 5. Time and disk per GB of pcap

| source | pcap_gb | extract_s | 07a_tshark_s | 07_label_s | map_s | 03b_s | total_s | s_per_gb | derived_disk_per_gb_mb | peak_rss_07_tshark_mb |
|---|---|---|---|---|---|---|---|---|---|---|
| Mirai-udpplain | 2.05 | 14.74 | 83.40 | 20.40 |  |  | 118.54 | 57.88 | 2.76 | 6,473.90 |
| Mirai-udpplain24 | 0.84 | 6.88 | 35.90 | 10.00 |  |  | 52.78 | 62.84 | 4.50 | 6,473.90 |
| MIRAIcut1M (1M-packet cut; singlepkt jar a96e7255..., before the idle sweeper) | 0.58 | 6.26 | N/A | N/A | 27.51 | 0.70 | 34.47 | 59.12 | 1.23 | N/A |

Pooled over the used parts (locked sweeper jar): 59.3 s per GB of pcap for extract + 07a + 07, and 3.3 MB of derived files (flow CSV, labelled CSV, maps) per GB, on top of the pcap itself. 07's tshark peaked at 6,474 MB RSS. The MIRAIcut1M row is a 1M-packet cut timed with the earlier singlepkt jar (before the idle sweeper); it is a cross-check, not the locked extractor.

## 6. Parts that could be reserved as an untouched future test set (proposal only)

**No local part can be reserved.** Both local Mirai pcaps are already in v1 / v1_1: Mirai-udpplain feeds train + val and Mirai-udpplain24 is the Step 10 test session. A new, untouched Mirai test set has to come from parts not downloaded yet. Re-run with --parts-list to rank listed parts.
