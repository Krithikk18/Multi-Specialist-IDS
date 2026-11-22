# Step 42 -- H-C2 fingerprint independence, H-C3 zero-day with context -- PASS

## H-C2

| class | Δ_flow (NOFP - GLOBAL) | Δ_ctx (CTX_NOFP - CTX) | Δ_ctx - Δ_flow [95 % CI] | verdict |
|---|---|---|---|---|
| syn_flood | -0.0001 | -0.0221 | -0.0220 [-0.0229, -0.0212] | DOES_NOT_HOLD |
| udp_flood (rare) | -0.0588 | +0.0000 | +0.0588 [+0.0235, +0.0941] | HOLDS |
| port_scan **(pre-registered)** | -0.0111 | -0.0000 | +0.0111 [+0.0098, +0.0138] | HOLDS |

## H-C3

| arm | role | verdict | mean miss-recall [95 % CI] (eligible pairs) | FA/h [95 % CI] | reason |
|---|---|---|---|---|---|
| CTX_TAIL_GLOBAL | **primary** | DOES_NOT_HOLD | 0.8536 [0.8046, 0.9000] (10) | 163.97 [155.47, 171.45] | FA/h CI upper bound 171.448 > reference 18.743 |
| CTX_IF_GLOBAL | report-only | DOES_NOT_HOLD | 0.8664 [0.8023, 0.9188] (10) | 19.46 [12.39, 25.60] | FA/h CI upper bound 25.605 > reference 18.743 |
| CTX_TAIL_PER_GROUP | report-only | DOES_NOT_HOLD | 0.8994 [0.8304, 0.9651] (10) | 173.80 [172.27, 175.34] | FA/h CI upper bound 175.340 > reference 18.743 |
| FLOWCTX_TAIL_GLOBAL | report-only | DOES_NOT_HOLD | 0.8376 [0.7822, 0.8906] (10) | 132.73 [126.08, 139.60] | FA/h CI upper bound 139.596 > reference 18.743 |

- FA reference (Phase 5A GLOBAL_NORMAL mean FA/h): 18.743; val benign hours 1.953
- out-of-range diagnostic: {'benign': 0.005001913997703202, 'syn_flood': 0.9455962945586313, 'udp_flood': 0.0, 'port_scan': 0.8562077121953903, 'misses': {'syn_flood|0': 0.7194570135746606, 'syn_flood|1': 0.7203389830508474, 'syn_flood|2': 0.9720107017904919, 'syn_flood|3': 0.7476635514018691, 'syn_flood|4': 0.7117903930131004, 'port_scan|0': 0.8923536439665471, 'port_scan|1': 0.8923150472092746, 'port_scan|2': 0.8923279158699808, 'port_scan|3': 0.8923279158699808, 'port_scan|4': 0.8923536439665471, 'udp_flood|0': 0.0, 'udp_flood|1': 0.0, 'udp_flood|2': 0.0, 'udp_flood|3': 0.0, 'udp_flood|4': 0.0}}

| arm | seed | FA (FA/h) | FA contaminated / clean | miss-recall (flagged / misses) | detector alone | combined recall |
|---|---|---|---|---|---|---|
| CTX_TAIL_GLOBAL | 0 | 341 (174.62) | 111 / 230 | syn_flood 0.7873 (174/221), port_scan 0.8953 (7494/8370), udp_flood 0.1176 (2/17) | syn_flood 0.9892, port_scan 0.9024, udp_flood 0.1176 | syn_flood 0.9995, port_scan 0.9518, udp_flood 0.1176 |
| CTX_TAIL_GLOBAL | 1 | 324 (165.92) | 106 / 218 | syn_flood 0.7458 (176/236), port_scan 0.8939 (7479/8367), udp_flood 0.1176 (2/17) | syn_flood 0.9814, port_scan 0.9011, udp_flood 0.1176 | syn_flood 0.9994, port_scan 0.9512, udp_flood 0.1176 |
| CTX_TAIL_GLOBAL | 2 | 288 (147.48) | 68 / 220 | syn_flood 0.9936 (9656/9718), port_scan 0.8942 (7483/8368), udp_flood 0.1176 (2/17) | syn_flood 0.9501, port_scan 0.8580, udp_flood 0.1176 | syn_flood 0.9994, port_scan 0.9513, udp_flood 0.1176 |
| CTX_TAIL_GLOBAL | 3 | 334 (171.04) | 111 / 223 | syn_flood 0.7991 (171/214), port_scan 0.8948 (7488/8368), udp_flood 0.1176 (2/17) | syn_flood 0.9877, port_scan 0.9019, udp_flood 0.1176 | syn_flood 0.9996, port_scan 0.9516, udp_flood 0.1176 |
| CTX_TAIL_GLOBAL | 4 | 314 (160.80) | 100 / 214 | syn_flood 0.7380 (169/229), port_scan 0.8943 (7485/8370), udp_flood 0.1176 (2/17) | syn_flood 0.9814, port_scan 0.9015, udp_flood 0.1176 | syn_flood 0.9994, port_scan 0.9513, udp_flood 0.1176 |
| CTX_IF_GLOBAL | 0 | 59 (30.21) | 57 / 2 | syn_flood 0.9321 (206/221), port_scan 0.8583 (7184/8370), udp_flood 0.0000 (0/17) | syn_flood 0.9951, port_scan 0.8290, udp_flood 0.0000 | syn_flood 0.9999, port_scan 0.9348, udp_flood 0.0000 |
| CTX_IF_GLOBAL | 1 | 45 (23.04) | 45 / 0 | syn_flood 0.8983 (212/236), port_scan 0.6419 (5371/8367), udp_flood 0.0000 (0/17) | syn_flood 0.9880, port_scan 0.5410, udp_flood 0.0000 | syn_flood 0.9998, port_scan 0.8352, udp_flood 0.0000 |
| CTX_IF_GLOBAL | 2 | 42 (21.51) | 42 / 0 | syn_flood 0.9978 (9697/9718), port_scan 0.9024 (7551/8368), udp_flood 0.0000 (0/17) | syn_flood 0.9894, port_scan 0.8687, udp_flood 0.0000 | syn_flood 0.9998, port_scan 0.9551, udp_flood 0.0000 |
| CTX_IF_GLOBAL | 3 | 16 (8.19) | 16 / 0 | syn_flood 0.9112 (195/214), port_scan 0.7486 (6264/8368), udp_flood 0.0000 (0/17) | syn_flood 0.9893, port_scan 0.6853, udp_flood 0.0000 | syn_flood 0.9998, port_scan 0.8843, udp_flood 0.0000 |
| CTX_IF_GLOBAL | 4 | 28 (14.34) | 28 / 0 | syn_flood 0.9039 (207/229), port_scan 0.8695 (7278/8370), udp_flood 0.0000 (0/17) | syn_flood 0.9918, port_scan 0.8224, udp_flood 0.0000 | syn_flood 0.9998, port_scan 0.9399, udp_flood 0.0000 |
| CTX_TAIL_PER_GROUP | 0 | 342 (175.14) | 112 / 230 | syn_flood 0.7692 (170/221), port_scan 0.9853 (8247/8370), udp_flood 0.1176 (2/17) | syn_flood 0.9776, port_scan 0.9422, udp_flood 0.1176 | syn_flood 0.9995, port_scan 0.9932, udp_flood 0.1176 |
| CTX_TAIL_PER_GROUP | 1 | 340 (174.11) | 112 / 228 | syn_flood 0.7669 (181/236), port_scan 0.9853 (8244/8367), udp_flood 0.1176 (2/17) | syn_flood 0.9775, port_scan 0.9421, udp_flood 0.1176 | syn_flood 0.9995, port_scan 0.9932, udp_flood 0.1176 |
| CTX_TAIL_PER_GROUP | 2 | 335 (171.55) | 111 / 224 | syn_flood 0.9936 (9656/9718), port_scan 0.9853 (8245/8368), udp_flood 0.0000 (0/17) | syn_flood 0.9694, port_scan 0.9416, udp_flood 0.0000 | syn_flood 0.9994, port_scan 0.9932, udp_flood 0.0000 |
| CTX_TAIL_PER_GROUP | 3 | 344 (176.16) | 112 / 232 | syn_flood 0.7991 (171/214), port_scan 0.9853 (8245/8368), udp_flood 0.1176 (2/17) | syn_flood 0.9809, port_scan 0.9422, udp_flood 0.1176 | syn_flood 0.9996, port_scan 0.9932, udp_flood 0.1176 |
| CTX_TAIL_PER_GROUP | 4 | 336 (172.06) | 112 / 224 | syn_flood 0.7380 (169/229), port_scan 0.9857 (8250/8370), udp_flood 0.1176 (2/17) | syn_flood 0.9760, port_scan 0.9419, udp_flood 0.1176 | syn_flood 0.9994, port_scan 0.9934, udp_flood 0.1176 |
| FLOWCTX_TAIL_GLOBAL | 0 | 260 (133.14) | 9 / 251 | syn_flood 0.7330 (162/221), port_scan 0.8933 (7477/8370), udp_flood 0.4118 (7/17) | syn_flood 0.9480, port_scan 0.8571, udp_flood 0.4118 | syn_flood 0.9994, port_scan 0.9509, udp_flood 0.4118 |
| FLOWCTX_TAIL_GLOBAL | 1 | 283 (144.92) | 28 / 255 | syn_flood 0.7373 (174/236), port_scan 0.8929 (7471/8367), udp_flood 0.4118 (7/17) | syn_flood 0.9488, port_scan 0.8567, udp_flood 0.4118 | syn_flood 0.9994, port_scan 0.9507, udp_flood 0.4118 |
| FLOWCTX_TAIL_GLOBAL | 2 | 239 (122.39) | 4 / 235 | syn_flood 0.9720 (9446/9718), port_scan 0.8923 (7467/8368), udp_flood 0.4118 (7/17) | syn_flood 0.9456, port_scan 0.8562, udp_flood 0.4118 | syn_flood 0.9973, port_scan 0.9504, udp_flood 0.4118 |
| FLOWCTX_TAIL_GLOBAL | 3 | 266 (136.22) | 9 / 257 | syn_flood 0.7570 (162/214), port_scan 0.8929 (7472/8368), udp_flood 0.4118 (7/17) | syn_flood 0.9483, port_scan 0.8567, udp_flood 0.4118 | syn_flood 0.9995, port_scan 0.9507, udp_flood 0.4118 |
| FLOWCTX_TAIL_GLOBAL | 4 | 248 (127.00) | 5 / 243 | syn_flood 0.7118 (163/229), port_scan 0.8930 (7474/8370), udp_flood 0.4118 (7/17) | syn_flood 0.9458, port_scan 0.8567, udp_flood 0.4118 | syn_flood 0.9993, port_scan 0.9507, udp_flood 0.4118 |

### CTX_TAIL_GLOBAL rules (q, held-out flag rate) and top firing features

- s0: q 0.999883, held-out rate 0.00098 (met True); per-group {'__global__': {'q': 0.9998834085598804, 'hold_rate': 0.0009821038847664775, 'met': True, 'n_fit': 109970}, 'G1': {'q': 0.9999174595814719, 'hold_rate': 0.0008747813046738316, 'met': True, 'n_fit': 96022}, 'G2': {'q': 0.9999235577725736, 'hold_rate': 0.0003071253071253071, 'met': True, 'n_fit': 13023}, 'fallback': [{'group': 'GEN', 'n': 1155}]}
- s1: q 0.999937, held-out rate 0.00080 (met True); per-group {'__global__': {'q': 0.9999369042655509, 'hold_rate': 0.0008002327949949076, 'met': True, 'n_fit': 109970}, 'G1': {'q': 0.9999073881271857, 'hold_rate': 0.000999750062484379, 'met': True, 'n_fit': 96022}, 'G2': {'q': 0.9999235577725736, 'hold_rate': 0.0006142506142506142, 'met': True, 'n_fit': 13023}, 'fallback': [{'group': 'GEN', 'n': 1155}]}
- s2: q 0.999937, held-out rate 0.00095 (met True); per-group {'__global__': {'q': 0.9999369042655509, 'hold_rate': 0.0009457296668121635, 'met': True, 'n_fit': 109970}, 'G1': {'q': 0.9999586317959754, 'hold_rate': 0.0008747813046738316, 'met': True, 'n_fit': 96022}, 'G2': {'q': 0.9999235577725736, 'hold_rate': 0.0006142506142506142, 'met': True, 'n_fit': 13023}, 'fallback': [{'group': 'GEN', 'n': 1155}]}
- s3: q 0.999911, held-out rate 0.00098 (met True); per-group {'__global__': {'q': 0.9999108749061854, 'hold_rate': 0.0009821038847664775, 'met': True, 'n_fit': 109970}, 'G1': {'q': 0.999896087769615, 'hold_rate': 0.0009164375572773473, 'met': True, 'n_fit': 96022}, 'G2': {'q': 0.9999235577725736, 'hold_rate': 0.0009213759213759214, 'met': True, 'n_fit': 13023}, 'fallback': [{'group': 'GEN', 'n': 1155}]}
- s4: q 0.999946, held-out rate 0.00098 (met True); per-group {'__global__': {'q': 0.9999458830473444, 'hold_rate': 0.0009821038847664775, 'met': True, 'n_fit': 109970}, 'G1': {'q': 0.99993927978043, 'hold_rate': 0.0009164375572773473, 'met': True, 'n_fit': 96022}, 'G2': {'q': 0.9999235577725736, 'hold_rate': 0.0006142506142506142, 'met': True, 'n_fit': 13023}, 'fallback': [{'group': 'GEN', 'n': 1155}]}
- s0 top firing features per class: {'benign': {'ctx_hostmax_n_peers_60s': 169, 'ctx_hostmax_n_flows_60s': 96, 'ctx_hostmax_n_port_pairs_60s': 96, 'ctx_hostmax_n_flows_10s': 36, 'ctx_hostmax_n_port_pairs_10s': 36}, 'syn_flood': {'ctx_hostmin_share_syn_no_ack_60s': 99090, 'ctx_hostmin_n_flows_10s': 91540, 'ctx_pair_n_flows_10s': 91540, 'ctx_hostmin_n_port_pairs_10s': 91536, 'ctx_pair_n_port_pairs_10s': 91536}, 'udp_flood': {'ctx_hostmax_sum_pkts_10s': 2, 'ctx_hostmax_sum_bytes_10s': 2}, 'port_scan': {'ctx_hostmin_n_flows_10s': 13469, 'ctx_hostmin_n_port_pairs_10s': 13469, 'ctx_pair_n_flows_10s': 13469, 'ctx_pair_n_port_pairs_10s': 13469, 'ctx_hostmin_n_flows_60s': 11227}}
- s1 top firing features per class: {'benign': {'ctx_hostmax_n_peers_60s': 169, 'ctx_hostmax_n_port_pairs_60s': 83, 'ctx_hostmax_n_flows_60s': 78, 'ctx_hostmax_n_flows_10s': 36, 'ctx_hostmax_n_port_pairs_10s': 36}, 'syn_flood': {'ctx_hostmin_share_syn_no_ack_60s': 95778, 'ctx_hostmin_n_flows_10s': 91469, 'ctx_pair_n_flows_10s': 91469, 'ctx_hostmin_n_port_pairs_10s': 91463, 'ctx_pair_n_port_pairs_10s': 91463}, 'udp_flood': {'ctx_hostmax_sum_pkts_10s': 2, 'ctx_hostmax_sum_bytes_10s': 2}, 'port_scan': {'ctx_hostmin_n_flows_10s': 13426, 'ctx_hostmin_n_port_pairs_10s': 13426, 'ctx_pair_n_flows_10s': 13426, 'ctx_pair_n_port_pairs_10s': 13426, 'ctx_hostmin_n_flows_60s': 11165}}
- s2 top firing features per class: {'benign': {'ctx_hostmax_n_peers_60s': 169, 'ctx_hostmax_n_flows_60s': 50, 'ctx_hostmax_n_port_pairs_60s': 50, 'ctx_hostmax_n_peers_10s': 31, 'ctx_hostmax_n_flows_10s': 29}, 'syn_flood': {'ctx_hostmin_n_flows_10s': 91492, 'ctx_pair_n_flows_10s': 91492, 'ctx_hostmin_n_port_pairs_10s': 91487, 'ctx_pair_n_port_pairs_10s': 91487, 'ctx_hostmin_n_flows_60s': 84255}, 'udp_flood': {'ctx_hostmax_sum_pkts_10s': 2, 'ctx_hostmax_sum_bytes_10s': 2}, 'port_scan': {'ctx_hostmin_n_flows_10s': 13442, 'ctx_hostmin_n_port_pairs_10s': 13442, 'ctx_pair_n_flows_10s': 13442, 'ctx_pair_n_port_pairs_10s': 13442, 'ctx_hostmin_n_flows_60s': 11165}}
- s3 top firing features per class: {'benign': {'ctx_hostmax_n_peers_60s': 169, 'ctx_hostmax_n_flows_60s': 92, 'ctx_hostmax_n_port_pairs_60s': 92, 'ctx_hostmax_n_flows_10s': 36, 'ctx_hostmax_n_port_pairs_10s': 36}, 'syn_flood': {'ctx_hostmin_share_syn_no_ack_60s': 98948, 'ctx_hostmin_n_flows_10s': 91517, 'ctx_pair_n_flows_10s': 91517, 'ctx_hostmin_n_port_pairs_10s': 91511, 'ctx_pair_n_port_pairs_10s': 91511}, 'udp_flood': {'ctx_hostmax_sum_pkts_10s': 2, 'ctx_hostmax_sum_bytes_10s': 2}, 'port_scan': {'ctx_hostmin_n_flows_10s': 13454, 'ctx_hostmin_n_port_pairs_10s': 13454, 'ctx_pair_n_flows_10s': 13454, 'ctx_pair_n_port_pairs_10s': 13454, 'ctx_hostmin_n_flows_60s': 11173}}
- s4 top firing features per class: {'benign': {'ctx_hostmax_n_peers_60s': 169, 'ctx_hostmax_n_port_pairs_60s': 83, 'ctx_hostmax_n_flows_60s': 78, 'ctx_hostmax_n_flows_10s': 29, 'ctx_hostmax_n_port_pairs_10s': 28}, 'syn_flood': {'ctx_hostmin_share_syn_no_ack_60s': 95778, 'ctx_hostmin_n_flows_10s': 91492, 'ctx_pair_n_flows_10s': 91492, 'ctx_hostmin_n_port_pairs_10s': 91487, 'ctx_pair_n_port_pairs_10s': 91487}, 'udp_flood': {'ctx_hostmax_sum_pkts_10s': 2, 'ctx_hostmax_sum_bytes_10s': 2}, 'port_scan': {'ctx_hostmin_n_flows_10s': 13442, 'ctx_hostmin_n_port_pairs_10s': 13442, 'ctx_pair_n_flows_10s': 13442, 'ctx_pair_n_port_pairs_10s': 13442, 'ctx_hostmin_n_flows_60s': 11143}}

- CTX_TAIL_PER_GROUP is report-only and not a routing claim (D163)
- val benign contamination share 0.0130

## Checks

- PASS  v2_1 val uid order == the Phase 5A LOAO run's  157,558
- PASS  every val row maps to a Phase 5A val row  0 unmapped
