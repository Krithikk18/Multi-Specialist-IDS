# Step 39 -- context dataset v2_2_context -- PASS

- dataset dir `/home/krithikk/lgids_cache/v2/datasets/v2_2_context`, manifest sha256 `cfa2800eb7cfa86b...`

| split | rows | MB | evictions (host / pair) | warm-up flows (share) |
|---|---|---|---|---|
| train | 636,193 | 130.5 | 0 / 0 | 4,055 (0.0064) |
| val | 157,558 | 36.6 | 0 / 0 | 16,777 (0.1065) |

| split | class x group | rows |
|---|---|---|
| train | benign|G1 | 120,028 |
| train | benign|G2 | 16,279 |
| train | benign|GEN | 1,155 |
| train | syn_flood|G1 | 200,605 |
| train | syn_flood|G2 | 199,985 |
| train | udp_flood|G1 | 95 |
| train | port_scan|G1 | 50,472 |
| train | port_scan|G2 | 43,218 |
| train | port_scan|GEN | 4,356 |
| val | benign|G1 | 35,833 |
| val | benign|G2 | 3,061 |
| val | benign|GEN | 291 |
| val | syn_flood|G1 | 50,103 |
| val | syn_flood|G2 | 50,074 |
| val | udp_flood|G1 | 17 |
| val | port_scan|G1 | 7,763 |
| val | port_scan|G2 | 10,416 |

- real-data reference check (val slice): {'segment': ['benign_night', 'val'], 'start': 9355, 'rows': 10000, 'segment_rows': 24686, 'equal': True, 'mismatches': 0, 'evictions': {'host': 0, 'pair': 0}, 'first_mismatches': []}

- val compute cost: {'us_per_flow': 19.05478102032262, 'peak_hosts': 492, 'peak_pairs': 723, 'peak_events': 187633, 'state_note': 'peak tracked keys and window events within one segment (2 windows per key)'}

| split | segment | flows | us/flow | evictions | peak hosts / pairs / events | warm-up |
|---|---|---|---|---|---|---|
| train | DDoS-SYN_Flood / train | 217,404 | 22.9 | {'host': 0, 'pair': 0} | 466 / 725 / 80,370 | 1,185 |
| train | DDoS-SYN_Flood5 / train | 206,544 | 20.0 | {'host': 0, 'pair': 0} | 294 / 460 / 135,032 | 286 |
| train | Mirai-udpplain / train | 6,720 | 21.4 | {'host': 0, 'pair': 0} | 378 / 559 / 5,268 | 170 |
| train | Recon-PortScan / train | 119,689 | 17.9 | {'host': 0, 'pair': 0} | 458 / 639 / 133,302 | 2,252 |
| train | benign_night / train | 85,836 | 21.1 | {'host': 0, 'pair': 0} | 808 / 1050 / 7,270 | 162 |
| val | DDoS-SYN_Flood / val | 52,542 | 18.7 | {'host': 0, 'pair': 0} | 166 / 220 / 114,794 | 339 |
| val | DDoS-SYN_Flood5 / val | 51,205 | 18.4 | {'host': 0, 'pair': 0} | 173 / 220 / 187,633 | 15,636 |
| val | Mirai-udpplain / val | 597 | 17.3 | {'host': 0, 'pair': 0} | 135 / 160 / 2,277 | 258 |
| val | Recon-PortScan / val | 28,528 | 18.2 | {'host': 0, 'pair': 0} | 312 / 406 / 33,759 | 177 |
| val | benign_night / val | 24,686 | 22.1 | {'host': 0, 'pair': 0} | 492 / 723 / 5,175 | 367 |

- most separating context features (max |AUC - 0.5| vs train benign): ['ctx_hostmin_share_syn_no_ack_60s', 'ctx_hostmin_share_syn_no_ack_10s', 'ctx_pair_share_syn_no_ack_10s', 'ctx_pair_n_port_pairs_60s', 'ctx_pair_n_flows_60s', 'ctx_hostmax_n_port_pairs_10s'] (full table: feature_summary.json)

## Checks

- PASS  free space on the cache filesystem >= 20 GB  937.9 GB
- PASS  pinned feature list == names generated from the config  114 = 70 flow + 44 context
- PASS  phase2 config dataset == source_dataset  v2_1_oriented
- PASS  train: every v2_1 column and the row order unchanged  92 columns
- PASS  real-data reference check: streaming == naive on the val slice (exact, all 44)  10,000 flows of segment ['benign_night', 'val'], mismatches 0
- PASS  val: every v2_1 column and the row order unchanged  92 columns
