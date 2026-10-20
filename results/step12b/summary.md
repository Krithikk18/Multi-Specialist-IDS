# Step 12b -- Mirai greeth_flood pilot: does the locked extractor turn GRE into usable flows?

- run 2026-10-20T16:09:11+00:00, git HEAD `7c511132aaf3c998b275cc6260db4cb216508772`, 12b_greeth_pilot.py sha256 `552e429dffa82a5a...`
- scope: Mirai-greeth_flood.pcap only; parts 9 / 18 / 27 / 28 not touched; test.parquet never opened
- pcap `Mirai-greeth_flood.pcap`: cached copy reused; sha256 `87f8de16e575f23fca6c159a94360c6dd2970c4d9a1711d46c9468f1cf724c0e` == config/sha256_greeth.txt; 2.05 GB
- extractor: verify_lock() PASS; jar sha256 `01acf9411e7ab6a0...` (ahlashkari/CICFlowMeter@98a5eba + extractor/guard_gt0.patch + extractor/idle_sweeper.patch), 120 s / 5 s, TZ=UTC, -Xmx6g; run through extraction/run_cicflowmeter.py

## Verdict (proposal -- you decide): **FAIL**

- protocol 0: 100.0% of the attacker-sent packets in flows are in Protocol-0 flows
- degenerate: core shape feature(s) constant over the 52 flood flows (Total Length of Fwd Packet = 0, Fwd Packet Length Mean = 0)
- note: NaN / inf over ALL attacker flows in Flow Bytes/s, Flow IAT Max, Flow IAT Mean, Flow IAT Min, Flow IAT Std, Flow Packets/s, all in the TCP / UDP side flows (1-packet flows: duration 0, no IAT; 03b check 6 attributes them to duration == 0; 08 sets them to 0), none in the flood flows
- note: 40 of the 70 features are constant 0 over the flood flows: Protocol, Total Length of Fwd Packet, Total Length of Bwd Packet, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Fwd PSH Flags, Fwd Header Length, Bwd Header Length, Packet Length Min, Packet Length Max, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, CWR Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Fwd Segment Size Avg, Bwd Segment Size Avg, Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg, Subflow Fwd Bytes, Subflow Bwd Bytes, FWD Init Win Bytes, Bwd Init Win Bytes, Fwd Act Data Pkts, Fwd Seg Size Min

| item | value |
|---|---|
| attacker packets (outer eth.src = attacker MAC) | 3,257,230 |
|   of which GRE (outer ip.proto 47) | 3,254,376 |
| attacker flows (Src or Dst IP in the attacker IP set) | 152 |
| Total Fwd + Bwd packets of attacker flows | 3,255,598 |
| coverage (requested definition) | 99.95% |
| sent-side coverage (attacker-IP direction only) | 99.92% |
| dominant Protocol of attacker flows (by attacker-sent packets) | 0 (0 (no IP protocol / unknown)), 100.0% |
| Protocol-47 flows in the whole CSV | 0 |
| flood flows (attacker flows, Protocol not TCP / UDP) | 52 |
| features with NaN / inf (flood flows) | none |
| features with NaN / inf (all attacker flows) | Flow Bytes/s, Flow IAT Max, Flow IAT Mean, Flow IAT Min, Flow IAT Std, Flow Packets/s |
| features constant over the flood flows | 40 |
|   of those, constant 0 | 40 |
|   of those, varying over Mirai-udpplain attack flows | Protocol, Total Length of Fwd Packet, Total Length of Bwd Packet, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Fwd PSH Flags, Fwd Header Length, Bwd Header Length, Packet Length Min, Packet Length Max, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, Down/Up Ratio, Average Packet Size, Fwd Segment Size Avg, Bwd Segment Size Avg, Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg, Subflow Fwd Bytes, Subflow Bwd Bytes, FWD Init Win Bytes, Bwd Init Win Bytes, Fwd Act Data Pkts, Fwd Seg Size Min |
| core shape features constant (flood flows) | Total Length of Fwd Packet, Fwd Packet Length Mean |

Criteria: PASS if the attacker GRE traffic appears as flows with a usable (non-0) Protocol, coverage >= 90%, and the 70 features are not degenerate over the flood flows (no NaN / inf, and none of Flow Duration, Total Fwd Packet, Total Length of Fwd Packet, Fwd Packet Length Mean, Flow IAT Mean, Flow Packets/s constant).

## 1. Packet-level truth (tshark / capinfos, base part only)

| item | value |
|---|---|
| packets (capinfos) | 3,352,569 |
| packets (tshark) | 3,352,569 |
| capture start (UTC) | 2023-01-12T15:19:00+00:00 |
| capture end (UTC) | 2023-01-12T15:37:06+00:00 |
| duration | 1,086.7 s (18.1 min) |
| GRE packets (outer ip.proto 47) | 3,254,376 (97.07 %) |
|   sent by attacker MACs / by others | 3,254,376 / 0 |
| attacker packets | 3,257,230 (97.16 %) |
| attacker first / last packet (UTC) | 2023-01-12T15:19:03+00:00 .. 2023-01-12T15:37:06+00:00 (18.1 min) |
| GRE payload type (gre.proto, attacker) | 0x6558 3,254,272 (100.0 %); 0x6558,0xb7ac 2 (0.0 %); 0x6558,0x0d7b 1 (0.0 %); 0x6558,0x975e 1 (0.0 %); 0x6558,0x8d20 1 (0.0 %); 0x6558,0x645a 1 (0.0 %) |
| inner ip.proto inside GRE (attacker) | 17 3,254,363 (100.0 %); 231 2 (0.0 %); 248 1 (0.0 %); 235 1 (0.0 %); 183 1 (0.0 %); 58 1 (0.0 %) |
| inner ip.dst == outer ip.dst (attacker GRE) | 0 |
| distinct inner values (attacker GRE) | eth_src 100000+, eth_dst 100000+, ip_src 19, ip_dst 100000+, udp_sport 65536, udp_dport 65536, tcp_sport 0, tcp_dport 0 |
| attacker GRE frame length min / mean / max | 592 / 592.0 / 592 B |
| tshark pass | 192.9 s, peak RSS 398 MB |

### Protocol hierarchy (frame.protocols; all packets, attacker packets)

| key | all | all_pct | attacker | attacker_pct |
|---|---|---|---|---|
| eth:ethertype:ip:gre:eth:ethertype:ip:udp:data | 3,218,899 | 96.01 | 3,218,899 | 98.82 |
| eth:ethertype:ip:tcp | 40,837 | 1.22 | 92 | 0.00 |
| eth:ethertype:ip:tcp:tls | 25,076 | 0.75 | 0 | 0.00 |
| eth:ethertype:ip:gre:eth:ethertype:ip:udp:rtcp | 15,691 | 0.47 | 15,691 | 0.48 |
| eth:ethertype:arp | 9,905 | 0.30 | 2,398 | 0.07 |
| eth:ethertype:ip:udp:dns | 8,592 | 0.26 | 44 | 0.00 |
| eth:ethertype:ip:udp:data | 4,740 | 0.14 | 0 | 0.00 |
| eth:ethertype:ip:icmp:data | 1,708 | 0.05 | 0 | 0.00 |
| eth:ethertype:ip:gre:eth:ethertype:ip:udp:quake3:data | 849 | 0.03 | 849 | 0.03 |
| eth:ethertype:ip:udp:quic | 783 | 0.02 | 0 | 0.00 |
| eth:ethertype:ip:udp:mdns | 714 | 0.02 | 80 | 0.00 |
| eth:ethertype:ip:gre:eth:ethertype:ip:udp:goose:cotp | 681 | 0.02 | 681 | 0.02 |
| eth:llc | 651 | 0.02 | 3 | 0.00 |
| eth:ethertype:ipv6:udp:mdns | 598 | 0.02 | 56 | 0.00 |
| eth:ethertype:ip:tcp:data | 573 | 0.02 | 0 | 0.00 |

### Inner protocol stacks after `gre` (attacker GRE packets)

| inner stack | packets | pct |
|---|---|---|
| eth:ethertype:ip:udp:data | 3,218,899 | 98.91 |
| eth:ethertype:ip:udp:rtcp | 15,691 | 0.48 |
| eth:ethertype:ip:udp:quake3:data | 849 | 0.03 |
| eth:ethertype:ip:udp:goose:cotp | 681 | 0.02 |
| eth:ethertype:ip:udp:llc:data | 499 | 0.02 |
| eth:ethertype:ip:udp | 456 | 0.01 |
| eth:ethertype:ip:udp:bfd | 406 | 0.01 |
| eth:ethertype:ip:udp:dtls | 382 | 0.01 |
| eth:ethertype:ip:udp:wtls | 270 | 0.01 |
| eth:ethertype:ip:udp:dhcpv6 | 224 | 0.01 |

### Victims (outer eth.dst of attacker packets; 07a's device mapping, behaviour_k2 group)

| device | dst_mac | class_07a | group_k2 | attacker_packets | pct_of_attacker | attacker_macs |
|---|---|---|---|---|---|---|
| Amazon Alexa Echo Dot 1 | 1c:fe:2b:98:16:dd | G1 | G1 | 2,438,661 | 74.87 | dc:a6:32:c9:e4:90 dc:a6:32:c9:e4:ab dc:a6:32:c9:e4:d5 dc:a6:32:c9:e5:a4 dc:a6:32:c9:e5:ef dc:a6:32:dc:27:d5 e4:5f:01:55:90:c4 |
| AMCREST WiFi Camera | 9c:8e:cd:1d:ab:9f | G1 | G1 | 816,357 | 25.06 | dc:a6:32:c9:e4:90 dc:a6:32:c9:e4:ab dc:a6:32:c9:e4:d5 dc:a6:32:c9:e5:a4 dc:a6:32:c9:e5:ef dc:a6:32:dc:27:d5 e4:5f:01:55:90:c4 |
| broadcast / multicast | ff:ff:ff:ff:ff:ff | bcast | not grouped | 1,703 | 0.05 | dc:a6:32:c9:e4:90 dc:a6:32:c9:e4:ab dc:a6:32:c9:e4:c6 dc:a6:32:c9:e4:d5 dc:a6:32:c9:e5:02 dc:a6:32:c9:e5:a4 dc:a6:32:c9:e5:ef dc:a6:32:c9:e6:f4 dc:a6:32:dc:27:d5 e4:5f:01:55:90:c4 |
| Google Nest Mini Speaker | cc:f4:11:9c:d0:00 | G1 | G1 | 126 | 0.00 | dc:a6:32:c9:e5:a4 |
| Philips Hue Bridge | 00:17:88:60:d6:4f | G1 | G1 | 111 | 0.00 | dc:a6:32:c9:e5:a4 |
| broadcast / multicast | 01:00:5e:00:00:fb | bcast | not grouped | 80 | 0.00 | dc:a6:32:c9:e4:90 dc:a6:32:c9:e4:ab dc:a6:32:c9:e4:c6 dc:a6:32:c9:e4:d5 dc:a6:32:c9:e5:02 dc:a6:32:c9:e5:a4 dc:a6:32:c9:e5:ef dc:a6:32:c9:e6:f4 dc:a6:32:dc:27:d5 e4:5f:01:55:90:c4 |
| Gateway / router | 3c:18:a0:41:c3:a0 | gateway | gateway (not grouped) | 76 | 0.00 | dc:a6:32:c9:e4:c6 dc:a6:32:c9:e5:02 dc:a6:32:c9:e6:f4 |
| broadcast / multicast | 33:33:00:00:00:fb | bcast | not grouped | 56 | 0.00 | dc:a6:32:c9:e4:90 dc:a6:32:c9:e4:ab dc:a6:32:c9:e4:c6 dc:a6:32:c9:e4:d5 dc:a6:32:c9:e5:a4 dc:a6:32:c9:e5:ef dc:a6:32:dc:27:d5 e4:5f:01:55:90:c4 |
| broadcast / multicast | 01:00:5e:7f:ff:fa | bcast | not grouped | 28 | 0.00 | dc:a6:32:c9:e5:a4 |
| broadcast / multicast | 33:33:00:00:00:01 | bcast | not grouped | 9 | 0.00 | dc:a6:32:c9:e4:c6 |
| broadcast / multicast | 33:33:00:00:00:16 | bcast | not grouped | 8 | 0.00 | dc:a6:32:c9:e4:c6 dc:a6:32:c9:e5:02 |
| SmartThings Hub | 28:6d:97:7a:2b:2d | G1 | G1 | 3 | 0.00 | dc:a6:32:c9:e5:a4 |
| Aeotec Smart Home Hub | 28:6d:97:9e:f4:d5 | G1 | G1 | 3 | 0.00 | dc:a6:32:c9:e5:a4 |
| broadcast / multicast | 01:00:5e:00:00:16 | bcast | not grouped | 2 | 0.00 | dc:a6:32:c9:e5:02 |
| broadcast / multicast | 33:33:ff:c9:e4:d5 | bcast | not grouped | 1 | 0.00 | dc:a6:32:c9:e4:d5 |

### Attacker IP set (outer ip.src of attacker packets; 07's T1b rule)

| ip | packets | used | why |
|---|---|---|---|
| 192.168.137.238 | 763,803 | True | lan |
| 192.168.137.150 | 543,497 | True | lan |
| 192.168.137.128 | 533,678 | True | lan |
| 192.168.137.207 | 453,330 | True | lan |
| 192.168.137.106 | 389,738 | True | lan |
| 192.168.137.147 | 305,697 | True | lan |
| 192.168.137.162 | 264,923 | True | lan |
| (no IPv4) | 2,481 | False | non-IPv4 |
| 192.168.137.11 | 72 | True | lan |
| 192.168.137.13 | 5 | True | lan |
| 192.168.137.236 | 5 | True | lan |
| 0.0.0.0 | 1 | False | unspecified |

### Attacker streams (outer ip.src, ip.dst, ip.proto) and what the 120 s timeout alone would give

| src | dst | proto | packets | span_s | flows_if_only_120s_timeout |
|---|---|---|---|---|---|
| 192.168.137.238 | 192.168.137.254 | 47 (GRE) | 565,273 | 615.79 | 6 |
| 192.168.137.150 | 192.168.137.254 | 47 (GRE) | 449,463 | 608.33 | 6 |
| 192.168.137.128 | 192.168.137.254 | 47 (GRE) | 401,081 | 616.88 | 6 |
| 192.168.137.207 | 192.168.137.254 | 47 (GRE) | 340,814 | 615.80 | 6 |
| 192.168.137.106 | 192.168.137.254 | 47 (GRE) | 274,887 | 604.59 | 6 |
| 192.168.137.147 | 192.168.137.254 | 47 (GRE) | 230,053 | 601.81 | 6 |
| 192.168.137.238 | 192.168.137.242 | 47 (GRE) | 198,522 | 167.44 | 2 |
| 192.168.137.162 | 192.168.137.254 | 47 (GRE) | 176,860 | 616.99 | 6 |
| 192.168.137.128 | 192.168.137.242 | 47 (GRE) | 132,589 | 167.92 | 2 |
| 192.168.137.106 | 192.168.137.242 | 47 (GRE) | 114,843 | 167.78 | 2 |
| 192.168.137.207 | 192.168.137.242 | 47 (GRE) | 112,509 | 168.03 | 2 |
| 192.168.137.150 | 192.168.137.242 | 47 (GRE) | 94,026 | 167.76 | 2 |
| 192.168.137.162 | 192.168.137.242 | 47 (GRE) | 87,821 | 143.11 | 2 |
| 192.168.137.147 | 192.168.137.242 | 47 (GRE) | 75,635 | 164.00 | 2 |
|  |  | (non-IPv4) | 2,481 | 1,042.63 | 9 |

## 2. Extraction

| item | value |
|---|---|
| CSV | ~/lgids_cache/pilot_greeth/flows/Mirai-greeth_flood.pcap_Flow__singlepkt.csv |
| rows | 5,886 |
| cfm packets | {'total': 3352569, 'valid': 3349463, 'discarded': 3106} |
| idle sweeper | {'sweeps': 85, 'swept_flows': 3823, 'tombstones_left': 3688, 'successors_from_tombstone': 135, 'late_packets_beyond_slack': 0, 'slack_s': 60} |
| elapsed | 16.783 s |
| peak RSS (wrapper + JVM) | 824 MB |
| reused | False |

## 3. Flow-level check

### Flows by Protocol

| key | name | all | all_pct | all_packets | attacker | attacker_pct | attacker_packets | attacker_sent_packets |
|---|---|---|---|---|---|---|---|---|
| 0 | 0 (no IP protocol / unknown) | 182 | 3.09 | 3,266,057 | 52 | 34.21 | 3,254,938 | 3,254,381 |
| 6 | TCP | 1,481 | 25.16 | 66,550 | 31 | 20.39 | 208 | 138 |
| 17 | UDP | 4,223 | 71.75 | 16,561 | 69 | 45.39 | 452 | 229 |

attacker = Src IP or Dst IP in the attacker IP set; attacker_sent_packets = Total Fwd packets when the attacker IP is the Src IP, Total Bwd when it is the Dst IP.

### Attacker flows: packets per flow, duration, ports (per protocol; per stream in attacker_flows_profile.csv)

| scope | protocol_name | flows | packets_sum | sent_by_attacker_sum | pkts_min | pkts_median | pkts_max | dur_s_median | dur_s_max | flows_dur_ge_115s | src_ports_distinct | dst_ports_distinct | src_port_top | dst_port_top |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| TOTAL protocol | 0 (no IP protocol / unknown) | 52 | 3,254,938 | 3,254,381 | 2.00 | 57,286.00 | 161,740.00 | 115.15 | 120.00 | 26 | 1 | 1 | 0 (52) | 0 (52) |
| TOTAL protocol | TCP | 31 | 208 | 138 | 1.00 | 3.00 | 35.00 | 3.74 | 59.34 | 0 | 14 | 10 | 8009 (11); 80 (5); 43306 (3); 43330 (2); 43308 (1); ... 9 more | 8009 (14); 43306 (6); 43308 (4); 54168 (1); 54166 (1); ... 5 more |
| TOTAL protocol | UDP | 69 | 452 | 229 | 1.00 | 4.00 | 24.00 | 2.44 | 78.58 | 0 | 37 | 18 | 1900 (14); 5353 (14); 53 (7); 44708 (1); 56444 (1); ... 32 more | 53 (16); 5353 (14); 123 (10); 1900 (7); 44708 (2); ... 13 more |
| TOTAL ALL | ALL | 152 | 3,255,598 | 3,254,748 | 1.00 | 8.00 | 161,740.00 | 5.72 | 120.00 | 26 | 52 | 29 | 0 (52); 1900 (14); 5353 (14); 8009 (11); 53 (7); ... 47 more | 0 (52); 53 (16); 8009 (14); 5353 (14); 123 (10); ... 24 more |

### Top attacker streams (flows per attacker IP / other IP / protocol)

| protocol_name | attacker_ip | other_ip | flows | packets_sum | pkts_median | dur_s_median | src_port_top | dst_port_top |
|---|---|---|---|---|---|---|---|---|
| 0 (no IP protocol / unknown) | 192.168.137.238 | 192.168.137.254 | 5 | 565,273 | 117,434.00 | 105.65 | 0 (5) | 0 (5) |
| 0 (no IP protocol / unknown) | 192.168.137.150 | 192.168.137.254 | 6 | 449,463 | 71,396.50 | 119.76 | 0 (6) | 0 (6) |
| 0 (no IP protocol / unknown) | 192.168.137.128 | 192.168.137.254 | 5 | 401,081 | 76,416.00 | 118.82 | 0 (5) | 0 (5) |
| 0 (no IP protocol / unknown) | 192.168.137.207 | 192.168.137.254 | 5 | 340,814 | 52,655.00 | 119.82 | 0 (5) | 0 (5) |
| 0 (no IP protocol / unknown) | 192.168.137.106 | 192.168.137.254 | 5 | 274,887 | 50,082.00 | 118.67 | 0 (5) | 0 (5) |
| 0 (no IP protocol / unknown) | 192.168.137.147 | 192.168.137.254 | 5 | 230,053 | 50,141.00 | 117.92 | 0 (5) | 0 (5) |
| 0 (no IP protocol / unknown) | 192.168.137.238 | 192.168.137.242 | 2 | 198,594 | 99,297.00 | 81.32 | 0 (2) | 0 (2) |
| 0 (no IP protocol / unknown) | 192.168.137.162 | 192.168.137.254 | 5 | 176,860 | 38,027.00 | 93.42 | 0 (5) | 0 (5) |
| 0 (no IP protocol / unknown) | 192.168.137.128 | 192.168.137.242 | 2 | 132,674 | 66,337.00 | 83.81 | 0 (2) | 0 (2) |
| 0 (no IP protocol / unknown) | 192.168.137.106 | 192.168.137.242 | 2 | 114,935 | 57,467.50 | 78.23 | 0 (2) | 0 (2) |
| 0 (no IP protocol / unknown) | 192.168.137.207 | 192.168.137.242 | 2 | 112,578 | 56,289.00 | 80.84 | 0 (2) | 0 (2) |
| 0 (no IP protocol / unknown) | 192.168.137.150 | 192.168.137.242 | 2 | 94,103 | 47,051.50 | 83.73 | 0 (2) | 0 (2) |
| 0 (no IP protocol / unknown) | 192.168.137.162 | 192.168.137.242 | 2 | 87,893 | 43,946.50 | 71.56 | 0 (2) | 0 (2) |
| 0 (no IP protocol / unknown) | 192.168.137.147 | 192.168.137.242 | 2 | 75,719 | 37,859.50 | 82.00 | 0 (2) | 0 (2) |
| 0 (no IP protocol / unknown) | 192.168.137.11 | 192.168.137.171 | 1 | 9 | 9.00 | 10.03 | 0 (1) | 0 (1) |

### The 70 features: 52 flood flows (52 distinct rows) and all 152 attacker flows (144 distinct rows)

| feature | flood_nan_inf | flood_min | flood_max | flood_constant | all_nan | all_inf | all_min | all_max | udpplain_constant |
|---|---|---|---|---|---|---|---|---|---|
| Protocol | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 17.00 |  |
| Flow Duration | 0 | 485,457.00 | 119,999,976.00 |  | 0 | 0 | 0.00 | 119,999,976.00 |  |
| Total Fwd Packet | 0 | 2.00 | 161,740.00 |  | 0 | 0 | 1.00 | 161,740.00 |  |
| Total Bwd packets | 0 | 0.00 | 63.00 |  | 0 | 0 | 0.00 | 63.00 |  |
| Total Length of Fwd Packet | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 7,128.00 |  |
| Total Length of Bwd Packet | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 1,931.00 |  |
| Fwd Packet Length Max | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 1,671.00 |  |
| Fwd Packet Length Min | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 306.00 |  |
| Fwd Packet Length Mean | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 690.00 |  |
| Fwd Packet Length Std | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 737.33 |  |
| Bwd Packet Length Max | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 517.00 |  |
| Bwd Packet Length Min | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 110.00 |  |
| Bwd Packet Length Mean | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 127.00 |  |
| Bwd Packet Length Std | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 143.77 |  |
| Flow Bytes/s | 0 | 0.00 | 0.00 | yes | 2 | 14 | 0.00 | 98,470.36 |  |
| Flow Packets/s | 0 | 0.90 | 1,349.60 |  | 0 | 16 | 0.17 | 2,000,000.00 |  |
| Flow IAT Mean | 0 | 740.97 | 1,253,452.62 |  | 16 | 0 | 1.00 | 11,507,043.00 |  |
| Flow IAT Std | 0 | 0.00 | 468,793.68 |  | 16 | 0 | 0.00 | 13,536,429.98 |  |
| Flow IAT Max | 0 | 485,457.00 | 56,823,197.00 |  | 16 | 0 | 1.00 | 56,823,197.00 |  |
| Flow IAT Min | 0 | 0.00 | 1,000,086.00 |  | 16 | 0 | 0.00 | 11,507,043.00 |  |
| Fwd IAT Total | 0 | 485,457.00 | 119,999,976.00 |  | 0 | 0 | 0.00 | 119,999,976.00 |  |
| Fwd IAT Mean | 0 | 740.97 | 1,253,452.62 |  | 0 | 0 | 0.00 | 18,007,318.00 |  |
| Fwd IAT Std | 0 | 0.00 | 468,793.68 |  | 0 | 0 | 0.00 | 21,706,836.70 |  |
| Fwd IAT Max | 0 | 485,457.00 | 56,823,197.00 |  | 0 | 0 | 0.00 | 56,823,197.00 |  |
| Fwd IAT Min | 0 | 0.00 | 1,000,086.00 |  | 0 | 0 | 0.00 | 18,007,318.00 |  |
| Bwd IAT Total | 0 | 0.00 | 105,866,765.00 |  | 0 | 0 | 0.00 | 105,866,765.00 |  |
| Bwd IAT Mean | 0 | 0.00 | 2,473,462.76 |  | 0 | 0 | 0.00 | 17,983,930.00 |  |
| Bwd IAT Std | 0 | 0.00 | 7,227,071.96 |  | 0 | 0 | 0.00 | 7,227,071.96 |  |
| Bwd IAT Max | 0 | 0.00 | 53,451,231.00 |  | 0 | 0 | 0.00 | 53,451,231.00 |  |
| Bwd IAT Min | 0 | 0.00 | 13,069.00 |  | 0 | 0 | 0.00 | 17,983,930.00 |  |
| Fwd PSH Flags | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 1.00 |  |
| Fwd Header Length | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 512.00 |  |
| Bwd Header Length | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 832.00 |  |
| Fwd Packets/s | 0 | 0.90 | 1,349.60 |  | 0 | 0 | 0.00 | 2,000,000.00 |  |
| Bwd Packets/s | 0 | 0.00 | 0.98 |  | 0 | 0 | 0.00 | 220.90 |  |
| Packet Length Min | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 306.00 |  |
| Packet Length Max | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 1,671.00 |  |
| Packet Length Mean | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 306.00 |  |
| Packet Length Std | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 497.03 |  |
| Packet Length Variance | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 247,038.64 |  |
| FIN Flag Count | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 2.00 |  |
| SYN Flag Count | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 6.00 |  |
| RST Flag Count | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 2.00 |  |
| PSH Flag Count | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 25.00 |  |
| ACK Flag Count | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 35.00 |  |
| CWR Flag Count | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 0.00 | yes |
| ECE Flag Count | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 0.00 | yes |
| Down/Up Ratio | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 3.00 |  |
| Average Packet Size | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 612.00 |  |
| Fwd Segment Size Avg | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 690.00 |  |
| Bwd Segment Size Avg | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 127.00 |  |
| Bwd Bytes/Bulk Avg | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 7,481.00 |  |
| Bwd Packet/Bulk Avg | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 24.00 |  |
| Bwd Bulk Rate Avg | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 22,089.00 |  |
| Subflow Fwd Packets | 0 | 0.00 | 21,890.00 |  | 0 | 0 | 0.00 | 21,890.00 |  |
| Subflow Fwd Bytes | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 7,128.00 |  |
| Subflow Bwd Packets | 0 | 0.00 | 9.00 |  | 0 | 0 | 0.00 | 9.00 |  |
| Subflow Bwd Bytes | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 480.00 |  |
| FWD Init Win Bytes | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 64,240.00 |  |
| Bwd Init Win Bytes | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 28,960.00 |  |
| Fwd Act Data Pkts | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 23.00 |  |
| Fwd Seg Size Min | 0 | 0.00 | 0.00 | yes | 0 | 0 | 0.00 | 40.00 |  |
| Active Mean | 0 | 0.00 | 112,002,913.00 |  | 0 | 0 | 0.00 | 112,002,913.00 |  |
| Active Std | 0 | 0.00 | 35,540,078.48 |  | 0 | 0 | 0.00 | 35,540,078.48 |  |
| Active Max | 0 | 0.00 | 112,002,913.00 |  | 0 | 0 | 0.00 | 112,002,913.00 |  |
| Active Min | 0 | 0.00 | 112,002,913.00 |  | 0 | 0 | 0.00 | 112,002,913.00 |  |
| Idle Mean | 0 | 0.00 | 56,823,197.00 |  | 0 | 0 | 0.00 | 56,823,197.00 |  |
| Idle Std | 0 | 0.00 | 9,654,657.09 |  | 0 | 0 | 0.00 | 24,357,485.26 |  |
| Idle Max | 0 | 0.00 | 56,823,197.00 |  | 0 | 0 | 0.00 | 56,823,197.00 |  |
| Idle Min | 0 | 0.00 | 56,823,197.00 |  | 0 | 0 | 0.00 | 56,823,197.00 |  |

udpplain_constant = constant over the 112 Mirai-udpplain attack flows (~/lgids_cache/flows/attack/Mirai-udpplain/Mirai-udpplain_labelled.csv.gz, train + val source; read-only reference for what a UDP flood leaves constant).

### 03b checks on the CSV

| check | status | key_number | reason |
|---|---|---|---|
| 1 Structure | PASS | 0 bad rows | all 5,886 data rows have 84 fields |
| 2 Packet total | WARN | 3,349,168 / 3,352,569 | 3,401 packets (0.1014%) not in flows -- expected for non-IP (ARP, etc.) and possibly IPv6/unsupported packets |
| 3 Single-packet flows | PASS | 714 (12.1305%) | single-packet flows present -> patched CICFlowMeter build was used |
| 4 Time span | PASS | offset -0.000 h | CSV start matches pcap first packet within 0 s; both sides in UTC |
| 5 Flow duration | PASS | max 119,999,976 us | no flow exceeds the 120 s flow timeout |
| 6 NaN / Infinity | WARN | 4,288 bad cells | 4,288 NaN/inf cells in 6 columns; rate columns: 0 bad values NOT explained by duration==0 (expected artefact) |
| 7 Protocol mix | PASS | UDP 71.7%, TCP 25.2%, other/unknown 3.1% | only protocols 0/6/17 present |
| 8 Duplicates | WARN | 22 full / 22 w/o FlowID | duplicates 0.3738% of rows (> 0.1% threshold) |
| 9 IPs | PASS | 194 src / 360 dst distinct | no blank src/dst IPs |

03b overall WARN (exit 0); full report ~/lgids_cache/pilot_greeth/03b/flow_check_report.md (cache, not in git).

## Run cost

| step | wall_s | elapsed_s | peak_rss_mb | capinfos_peak_rss_mb | tshark_elapsed_s | tshark_peak_rss_mb | peak_rss_self_mb |
|---|---|---|---|---|---|---|---|
| 0_copy_and_hash | 1.30 |  |  |  |  |  |  |
| 1_packets | 193.50 |  |  | 7.30 | 191.60 | 398.30 |  |
| 2_extract | 18.70 | 18.70 | 823.50 |  |  |  |  |
| 3a_flows | 0.20 |  |  |  |  |  | 730.50 |
| 3b_03b_check | 1.80 | 1.70 | 165.60 |  |  |  |  |

Total 216 s. Steps ran one at a time.
