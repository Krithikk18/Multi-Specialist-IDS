# Step 20 -- ingest (v1_cicflowmeter) -- PASS

- run_id `20261120T133357Z`, 2026-11-20T13:33:57+00:00, git `99d650878a6b` (v2), 20_ingest_csv.py sha256 `7e54e072d6e7f9c9...`, runtime 323.2 s, peak RSS 5012 MB
- args: `20_ingest_csv.py --source v1_cicflowmeter --assume-label benign_night=benign`
- class_map v1 sha256 `64063149b74d09f6...`, features_v1 file sha256 `623d0d2483670f34...`
- Timestamp: `%d/%m/%Y %I:%M:%S %p`, tz=UTC attached explicitly -- extractor TZ=UTC lock (config/config.py EXTRACTOR.tz): CICFlowMeter writes naive local-time strings and the JVM is always started with TZ=UTC
- LAN subnets for the MAC rule: ['192.168.137.0/24', '10.22.22.0/24'] (config/config.py NETWORK.subnets (V1 / CICIoT2023 testbed))
- NaN / inf: NaN and +-inf -> 0 before the model (features_v1.json 'clean', V1 08); counted, not a failure
- test-session rows: test-session rows are read, schema-validated and counted (incl. NaN / inf counts); no feature-value statistics (means, distributions, correlations, histograms)

## Checks

**PASS** (49 checks, 0 failed)

| check | pass | detail |
|---|---|---|
| lock: config/config.py sha256 == step10_prereg pin (V1 config untouched) | PASS | c19bf4ffe4ee25a9... |
| lock: config/step10_prereg.json sha256 | PASS | 17f627f841263e94... |
| lock: step10_prereg records the same config.py / features pins | PASS | inputs_sha256 / features |
| lock: features_v1.json (file sha256, list sha256, 70) | PASS | ok |
| lock: class_map.json (sha256, LF, structure) | PASS | ok |
| lock: v1: extractor jar sha256 | PASS | /home/krithikk/tools/CICFlowMeter-sweep/build/install/CICFlowMeter/lib/CICFlowMeter-4.0.jar (01acf9411e7ab6a0...) |
| lock: v1: extractor patch exists | PASS | /mnt/d/Projects/Company Project/Paper_Implemetation/extractor/guard_gt0.patch |
| lock: v1: extractor sweeper patch exists | PASS | /mnt/d/Projects/Company Project/Paper_Implemetation/extractor/idle_sweeper.patch |
| lock: v1: config file device_table.csv | PASS | /mnt/d/Projects/Company Project/Paper_Implemetation/config/device_table.csv |
| lock: v1: config file ip_mac_map.csv | PASS | /mnt/d/Projects/Company Project/Paper_Implemetation/config/ip_mac_map.csv |
| lock: v1: config file behaviour_groups.json | PASS | /mnt/d/Projects/Company Project/Paper_Implemetation/config/behaviour_groups.json |
| lock: v1: groups version | PASS | behaviour_groups.json version '1.0' vs GROUPS.version 'v1.0' |
| lock: v1: groups labels | PASS | ['G1', 'G2', 'GEN'] vs ['G1', 'G2', 'GEN'] |
| lock: v1: groups lock verified | PASS | behaviour_groups.json verification.pass |
| lock: v1: extractor TZ | PASS | subprocess env TZ=UTC (this shell: TZ=None; not used by the JVM unless passed) |
| V1 frozen: 09_train_specialists.py sha256 == step10_prereg | PASS | d792112ee52ad3ce... vs d792112ee52ad3ce... |
| V1 frozen: config/config.py sha256 == step10_prereg | PASS | c19bf4ffe4ee25a9... vs c19bf4ffe4ee25a9... |
| V1 frozen: config/groupings/behaviour_k2.json sha256 == step10_prereg | PASS | 9f80565f7ece7f65... vs 9f80565f7ece7f65... |
| V1 frozen: config/split_plan_v1_1.json sha256 == step10_prereg | PASS | 56813a35e1cbcf46... vs 56813a35e1cbcf46... |
| V1 frozen: results/step8b/manifest_v1_1.json sha256 == step10_prereg | PASS | a1e5f38dbc287a43... vs a1e5f38dbc287a43... |
| V1 frozen: results/step8/manifest_v1.json sha256 == step10_prereg | PASS | c2e48e620ad38a1e... vs c2e48e620ad38a1e... |
| V1 frozen: config/attack_set.json sha256 == step10_prereg | PASS | b975bd3cc6d5b0fd... vs b975bd3cc6d5b0fd... |
| V1 frozen: config/behaviour_groups.json sha256 == step10_prereg | PASS | 5b26490de8a996ca... vs 5b26490de8a996ca... |
| V1 frozen: device_table.csv sha256 == manifest_v1 | PASS | 506d16bbaa3c0052... |
| 08b: daytime inputs: extractor lock, 07 hard_pass, same pcap / jar / device_table, columns | PASS | ok (3 session(s)) |
| features_v1 == 08 candidate features minus dropped_constant_in_train | PASS | 77 candidates, 70 features |
| input sha256 == V1 record: benign_night | PASS | f9c033abaf072899... |
| input sha256 == V1 record: DDoS-SYN_Flood | PASS | 7fa59d2e1a8a5d3a... |
| input sha256 == V1 record: DDoS-SYN_Flood5 | PASS | 6861e9a9152a5de1... |
| input sha256 == V1 record: DDoS-SYN_Flood10 | PASS | 2586a753d5e10b7c... |
| input sha256 == V1 record: DDoS-SYN_Flood15 | PASS | 72d028090c31d21e... |
| input sha256 == V1 record: Recon-PortScan | PASS | b1a085a10adf2c3d... |
| input sha256 == V1 record: Mirai-udpplain | PASS | 036b76645b3603b0... |
| input sha256 == V1 record: Mirai-udpplain24 | PASS | b5fa27a8f1efd5e8... |
| input sha256 == V1 record: BenignTraffic1 | PASS | ba56437c91177b85... |
| input sha256 == V1 record: BenignTraffic2 | PASS | c71e641589e525b0... |
| input sha256 == V1 record: BenignTraffic3 | PASS | bccaf5fa1c5bd383... |
| validation + filter: benign_night | PASS | in 223,108 kept 204,844 |
| validation + filter: DDoS-SYN_Flood | PASS | in 6,800,503 kept 6,782,934 |
| validation + filter: DDoS-SYN_Flood5 | PASS | in 5,297,297 kept 5,296,071 |
| validation + filter: DDoS-SYN_Flood10 | PASS | in 6,099,055 kept 6,083,889 |
| validation + filter: DDoS-SYN_Flood15 | PASS | in 3,104,718 kept 3,102,555 |
| validation + filter: Recon-PortScan | PASS | in 207,429 kept 197,408 |
| validation + filter: Mirai-udpplain | PASS | in 8,806 kept 7,317 |
| validation + filter: Mirai-udpplain24 | PASS | in 6,251 kept 5,336 |
| validation + filter: BenignTraffic1 | PASS | in 93,698 kept 85,321 |
| validation + filter: BenignTraffic2 | PASS | in 101,111 kept 94,284 |
| validation + filter: BenignTraffic3 | PASS | in 43,078 kept 40,754 |
| regression vs V1 | PASS | PASS |

## Per-input label declarations

| session | assume_label | declared_by | reason |
|---|---|---|---|
| benign_night | benign | --assume-label benign_night=benign | file has no label / attack_family columns (04 tagged capture, no 07 labelling); V1's 08 treats every row of it as benign (src kind 'benign') |

## Sessions: rows in / out, rejected by reason (V1 filter)

| session | filter | rows_in | kept | not_owned | exclude_reason | label_excluded | ungrouped | kept_unreg_GEN | status |
|---|---|---|---|---|---|---|---|---|---|
| benign_night | usable | 223,108 | 204,844 | 13,162 | 5,102 | 0 | 0 | 0 | ok |
| DDoS-SYN_Flood | usable | 6,800,503 | 6,782,934 | 2,040 | 0 | 15,529 | 0 | 0 | ok |
| DDoS-SYN_Flood5 | usable | 5,297,297 | 5,296,071 | 1,223 | 0 | 3 | 0 | 0 | ok |
| DDoS-SYN_Flood10 | usable | 6,099,055 | 6,083,889 | 1,765 | 0 | 13,401 | 0 | 0 | ok |
| DDoS-SYN_Flood15 | usable | 3,104,718 | 3,102,555 | 1,417 | 86 | 660 | 0 | 0 | ok |
| Recon-PortScan | usable | 207,429 | 197,408 | 9,915 | 0 | 106 | 0 | 0 | ok |
| Mirai-udpplain | usable | 8,806 | 7,317 | 1,460 | 0 | 29 | 0 | 0 | ok |
| Mirai-udpplain24 | usable | 6,251 | 5,336 | 832 | 0 | 83 | 0 | 0 | ok |
| BenignTraffic1 | usable_day | 93,698 | 85,321 | 6,804 | 0 | 1,573 | 0 | 8 | ok |
| BenignTraffic2 | usable_day | 101,111 | 94,284 | 5,339 | 0 | 1,488 | 0 | 0 | ok |
| BenignTraffic3 | usable_day | 43,078 | 40,754 | 1,755 | 0 | 569 | 0 | 0 | ok |

## Blank src_mac / dst_mac per reason (kept rows)

Allowed: public, broadcast, multicast, off_lan_private (04 resolves MACs from the LAN map only). lan_unicast / invalid_ip fail.

| session | column | public | broadcast | multicast | off_lan_private | lan_unicast | invalid_ip |
|---|---|---|---|---|---|---|---|
| benign_night | src_mac | 42,672 | 0 | 0 | 0 | 0 | 0 |
| benign_night | dst_mac | 89,275 | 6,226 | 4,111 | 0 | 0 | 0 |
| DDoS-SYN_Flood | src_mac | 5,880 | 0 | 0 | 0 | 0 | 0 |
| DDoS-SYN_Flood | dst_mac | 10,207 | 352 | 242 | 0 | 0 | 0 |
| DDoS-SYN_Flood5 | src_mac | 1,616 | 0 | 0 | 0 | 0 | 0 |
| DDoS-SYN_Flood5 | dst_mac | 5,089 | 207 | 124 | 0 | 0 | 0 |
| DDoS-SYN_Flood10 | src_mac | 1,018 | 0 | 0 | 0 | 0 | 0 |
| DDoS-SYN_Flood10 | dst_mac | 8,181 | 270 | 210 | 0 | 0 | 0 |
| DDoS-SYN_Flood15 | src_mac | 1,649 | 0 | 0 | 0 | 0 | 0 |
| DDoS-SYN_Flood15 | dst_mac | 2,620 | 238 | 144 | 0 | 0 | 0 |
| Recon-PortScan | src_mac | 8,462 | 0 | 0 | 0 | 0 | 0 |
| Recon-PortScan | dst_mac | 24,220 | 1,332 | 1,034 | 0 | 0 | 0 |
| Mirai-udpplain | src_mac | 334 | 0 | 0 | 0 | 0 | 0 |
| Mirai-udpplain | dst_mac | 3,585 | 234 | 140 | 0 | 0 | 0 |
| Mirai-udpplain24 | src_mac | 169 | 0 | 0 | 0 | 0 | 0 |
| Mirai-udpplain24 | dst_mac | 2,546 | 111 | 87 | 0 | 0 | 0 |
| BenignTraffic1 | src_mac | 6,079 | 0 | 0 | 0 | 0 | 0 |
| BenignTraffic1 | dst_mac | 48,482 | 5,003 | 3,057 | 1 | 0 | 0 |
| BenignTraffic2 | src_mac | 6,070 | 0 | 0 | 0 | 0 | 0 |
| BenignTraffic2 | dst_mac | 54,232 | 5,548 | 3,556 | 1 | 0 | 0 |
| BenignTraffic3 | src_mac | 3,923 | 0 | 0 | 0 | 0 | 0 |
| BenignTraffic3 | dst_mac | 22,413 | 2,414 | 1,473 | 0 | 0 | 0 |

## Labels per session (kept rows)

| session | benign | syn_flood | udp_flood | port_scan |
|---|---|---|---|---|
| benign_night | 204,844 | 0 | 0 | 0 |
| DDoS-SYN_Flood | 26,547 | 6,756,387 | 0 | 0 |
| DDoS-SYN_Flood5 | 12,889 | 5,283,182 | 0 | 0 |
| DDoS-SYN_Flood10 | 16,251 | 6,067,638 | 0 | 0 |
| DDoS-SYN_Flood15 | 7,452 | 3,095,103 | 0 | 0 |
| Recon-PortScan | 58,442 | 0 | 0 | 138,966 |
| Mirai-udpplain | 7,205 | 0 | 112 | 0 |
| Mirai-udpplain24 | 5,278 | 0 | 58 | 0 |
| BenignTraffic1 | 85,321 | 0 | 0 | 0 |
| BenignTraffic2 | 94,284 | 0 | 0 | 0 |
| BenignTraffic3 | 40,754 | 0 | 0 | 0 |

## Totals (all sessions, pre-split)

- rows in 21,985,054, kept 21,900,713, rejected not_owned 45,712, exclude_reason 5,188, label_excluded 33,441, ungrouped 0

| group | benign | syn_flood | udp_flood | port_scan |
|---|---|---|---|---|
| G1 | 503,720 | 11,411,287 | 147 | 70,026 |
| G2 | 53,310 | 9,791,020 | 23 | 64,584 |
| GEN | 2,237 | 3 | 0 | 4,356 |

## NaN / inf per feature (kept rows; replaced by 0)

| feature | nan | inf |
|---|---|---|
| Flow Bytes/s | 1,289,016 | 28,340 |
| Flow Packets/s | 0 | 1,317,356 |
| Flow IAT Mean | 1,316,880 | 0 |
| Flow IAT Std | 1,316,880 | 0 |
| Flow IAT Max | 1,316,880 | 0 |
| Flow IAT Min | 1,316,880 | 0 |

## Regression vs V1 -- PASS

All per-session comparisons PASS:

| session | field | ours | v1 | v1_record | pass |
|---|---|---|---|---|---|
| benign_night | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| benign_night | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| benign_night | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| DDoS-SYN_Flood | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| DDoS-SYN_Flood | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| DDoS-SYN_Flood | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| DDoS-SYN_Flood5 | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| DDoS-SYN_Flood5 | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| DDoS-SYN_Flood5 | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| DDoS-SYN_Flood10 | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| DDoS-SYN_Flood10 | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| DDoS-SYN_Flood10 | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| DDoS-SYN_Flood15 | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| DDoS-SYN_Flood15 | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| DDoS-SYN_Flood15 | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| Recon-PortScan | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| Recon-PortScan | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| Recon-PortScan | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| Mirai-udpplain | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| Mirai-udpplain | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| Mirai-udpplain | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| Mirai-udpplain24 | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| Mirai-udpplain24 | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| Mirai-udpplain24 | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| BenignTraffic1 | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| BenignTraffic1 | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| BenignTraffic1 | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| BenignTraffic2 | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| BenignTraffic2 | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| BenignTraffic2 | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| BenignTraffic3 | rows: y != V1 binary label | 0 | 0 | 08 label == attack / 08b y = 0 | PASS |
| BenignTraffic3 | rows: Timestamp != 08.flow_start | 0 | 0 | 08.flow_start | PASS |
| BenignTraffic3 | accounting: rows_in == kept + rejected | True | True | this run | PASS |
| benign_night | rows | 223,108 | 223,108 | results/step8/manifest_v1.json filter_drops | PASS |
| benign_night | not_owned | 13,162 | 13,162 | results/step8/manifest_v1.json filter_drops | PASS |
| benign_night | exclude_reason | 5,102 | 5,102 | results/step8/manifest_v1.json filter_drops | PASS |
| benign_night | label_excluded | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| benign_night | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| benign_night | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| benign_night | kept (pre-cap usable) | 204,844 | 204,844 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| DDoS-SYN_Flood | rows | 6,800,503 | 6,800,503 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood | not_owned | 2,040 | 2,040 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood | exclude_reason | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood | label_excluded | 15,529 | 15,529 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood | kept (pre-cap usable) | 6,782,934 | 6,782,934 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| DDoS-SYN_Flood5 | rows | 5,297,297 | 5,297,297 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood5 | not_owned | 1,223 | 1,223 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood5 | exclude_reason | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood5 | label_excluded | 3 | 3 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood5 | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood5 | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood5 | kept (pre-cap usable) | 5,296,071 | 5,296,071 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| DDoS-SYN_Flood10 | rows | 6,099,055 | 6,099,055 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood10 | not_owned | 1,765 | 1,765 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood10 | exclude_reason | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood10 | label_excluded | 13,401 | 13,401 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood10 | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood10 | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood10 | kept (pre-cap usable) | 6,083,889 | 6,083,889 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| DDoS-SYN_Flood15 | rows | 3,104,718 | 3,104,718 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood15 | not_owned | 1,417 | 1,417 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood15 | exclude_reason | 86 | 86 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood15 | label_excluded | 660 | 660 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood15 | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood15 | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| DDoS-SYN_Flood15 | kept (pre-cap usable) | 3,102,555 | 3,102,555 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| Recon-PortScan | rows | 207,429 | 207,429 | results/step8/manifest_v1.json filter_drops | PASS |
| Recon-PortScan | not_owned | 9,915 | 9,915 | results/step8/manifest_v1.json filter_drops | PASS |
| Recon-PortScan | exclude_reason | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Recon-PortScan | label_excluded | 106 | 106 | results/step8/manifest_v1.json filter_drops | PASS |
| Recon-PortScan | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Recon-PortScan | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Recon-PortScan | kept (pre-cap usable) | 197,408 | 197,408 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| Mirai-udpplain | rows | 8,806 | 8,806 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain | not_owned | 1,460 | 1,460 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain | exclude_reason | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain | label_excluded | 29 | 29 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain | kept (pre-cap usable) | 7,317 | 7,317 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| Mirai-udpplain24 | rows | 6,251 | 6,251 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain24 | not_owned | 832 | 832 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain24 | exclude_reason | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain24 | label_excluded | 83 | 83 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain24 | ungrouped | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain24 | owner_device_name_mismatch | 0 | 0 | results/step8/manifest_v1.json filter_drops | PASS |
| Mirai-udpplain24 | kept (pre-cap usable) | 5,336 | 5,336 | results/step8/manifest_v1.json sessions train+val+test+gap_dropped | PASS |
| BenignTraffic1 | rows | 93,698 | 93,698 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | label_attack | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | not_owned | 6,812 | 6,812 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | exclude_reason | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | label_excluded | 1,573 | 1,573 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | ungrouped | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | unregistered_mac_kept | 8 | 8 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | owner_device_name_mismatch | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic1 | kept | 85,321 | 85,321 | results/step8b/manifest_v1_1.json sessions added | PASS |
| BenignTraffic1 | kept group G1 | 74,713 | 74,713 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic1 | kept group G2 | 10,460 | 10,460 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic1 | kept group GEN | 148 | 148 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic2 | rows | 101,111 | 101,111 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | label_attack | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | not_owned | 5,339 | 5,339 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | exclude_reason | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | label_excluded | 1,488 | 1,488 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | ungrouped | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | unregistered_mac_kept | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | owner_device_name_mismatch | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic2 | kept | 94,284 | 94,284 | results/step8b/manifest_v1_1.json sessions added | PASS |
| BenignTraffic2 | kept group G1 | 82,625 | 82,625 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic2 | kept group G2 | 11,618 | 11,618 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic2 | kept group GEN | 41 | 41 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic3 | rows | 43,078 | 43,078 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | label_attack | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | not_owned | 1,755 | 1,755 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | exclude_reason | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | label_excluded | 569 | 569 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | ungrouped | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | unregistered_mac_kept | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | owner_device_name_mismatch | 0 | 0 | results/step8b/manifest_v1_1.json sessions | PASS |
| BenignTraffic3 | kept | 40,754 | 40,754 | results/step8b/manifest_v1_1.json sessions added | PASS |
| BenignTraffic3 | kept group G1 | 35,680 | 35,680 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic3 | kept group G2 | 5,055 | 5,055 | results/step8b/manifest_v1_1.json by_group | PASS |
| BenignTraffic3 | kept group GEN | 19 | 19 | results/step8b/manifest_v1_1.json by_group | PASS |

Aggregates over all V1 sessions (before caps; gap drops have no group, so per-group rows only for (label, family) without gap drops):

| key | ours | v1_before_caps | v1_gap_drops | pass |
|---|---|---|---|---|
| attack/port_scan | 138,966 | 136,731 | 2,235 | PASS |
| attack/syn_flood | 21,202,310 | 20,723,620 | 478,690 | PASS |
| attack/udp_flood | 170 | 170 | 0 | PASS |
| benign | 338,908 | 334,794 | 4,114 | PASS |
| G1/attack/udp_flood | 147 | 147 | 0 | PASS |
| G2/attack/udp_flood | 23 | 23 | 0 | PASS |

## Outputs

- dir `/home/krithikk/lgids_cache/v2/ingest/20261120T133357Z`

| session | rows | bytes | sha256 |
|---|---|---|---|
| benign_night | 204,844 | 25,615,237 | fb050a077aa7a0b2ce022f537957ae943fc0d6eb0f622161dd220a77ef9d37e0 |
| DDoS-SYN_Flood | 6,782,934 | 432,244,847 | 7578ab87d614219df903b5402a8c74e85ece5eb3b0f18e230ead02c5aab3c555 |
| DDoS-SYN_Flood5 | 5,296,071 | 326,902,212 | 3adb9805dc687b1da9325c48d4a45010819b1aa4e487c5431a31b356a7f7cfa6 |
| DDoS-SYN_Flood10 | 6,083,889 | 366,586,308 | 26030a29499a67035408ca5698c58e3bd2bc7bd193ab2067a4e5f397737071c6 |
| DDoS-SYN_Flood15 | 3,102,555 | 204,236,068 | ba69465696cd8592f964139d22bc186a7b9f71a10f0c75c98711b010fc5c1805 |
| Recon-PortScan | 197,408 | 13,024,483 | 8137430171751813ff43628dc0303c167e15ebde32e2ebdbb2c8d001c271177e |
| Mirai-udpplain | 7,317 | 1,116,413 | 7207a1326bcbbf577dafb7f426f0beb9f9d73c9842084cb006d2666255cbce5c |
| Mirai-udpplain24 | 5,336 | 759,670 | 3eed151b003881a4c7439ef2281a63c6a98670163487b530483aff7da23eed5a |
| BenignTraffic1 | 85,321 | 13,337,464 | 829bba5be4ef1091a47eb1270392803cbcbdd32397790074ae3abee6877a6469 |
| BenignTraffic2 | 94,284 | 14,643,685 | a9db72f9d266058c3348155063439b9ba7a60eef8b7421932be4071462671d00 |
| BenignTraffic3 | 40,754 | 6,405,609 | b3aab01e19779b425291d375995315cb0ed8771beb6ba1df097e296a59eaa59d |

- figures: class_counts.png, group_class_heatmap.png, validation_issues.png
