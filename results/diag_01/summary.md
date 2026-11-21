# diag_01 -- why port_scan is labelled syn_flood (G1) -- PASS

- run `20261120T190728Z`; READ-ONLY: models of step 22 run `20261120T144232Z` (seed-0 primary boosters, sha256 checked) scored on val; train / val via common/phase2_data.load_split (test never read); nothing trained.
- feature matrix = the models' input: the 70 features of features_v1.json as float32 (step 22's preprocessing).

## Verdict rule (fixed before the numbers)

- **SUPPORTED** if conflict duplicates (exact or 6 significant figures) account for >= 50 % of the G1 specialist's port_scan -> syn_flood errors on G1 val, **or** the per-flow ceiling for G1 port_scan recall (train-majority lookup) is <= 0.90. **NOT SUPPORTED** otherwise.
- Context: a feature 'separates' when one threshold, picked on train, puts >= 90 % of the val conflict-duplicate port_scan flows on the port_scan side **and** >= 90 % of val syn_flood flows on the syn_flood side.

## Verdict

- **NOT SUPPORTED**: conflict duplicates are 0.0 % of the specialist's port_scan -> syn_flood errors (< 50 %); G1 port_scan per-flow ceiling = 1.0000 exact / 1.0000 at 6 sig. fig. (> 0.90).
- Context separation >= 90 / 90 on val: **NO** (0 feature x window combinations); best: n/a

## Q1 -- conflicting duplicates

### exact (float32 bit-identical); unique vectors train 559,550, val 122,558

| split | group | port_scan rows | also carry syn_flood | % |
|---|---|---|---|---|
| train | G1 | 50,472 | 0 | 0.0 |
| val | G1 | 7,763 | 0 | 0.0 |
| val vs train | G1 | 7,763 | 0 | 0.0 |
| train | G2 | 43,218 | 0 | 0.0 |
| val | G2 | 10,416 | 0 | 0.0 |
| val vs train | G2 | 10,416 | 0 | 0.0 |
| train | GEN | 4,356 | 0 | 0.0 |

Conflict matrix, % of row class a whose vector also carries label b:

- train_within: benign->syn_flood 0.4; benign->udp_flood 0.1; syn_flood->benign 0.0; syn_flood->udp_flood 0.0; udp_flood->benign 1.1; udp_flood->syn_flood 1.1
- val_within: benign->udp_flood 0.1; udp_flood->benign 5.9
- val_vs_train: benign->syn_flood 0.3; benign->udp_flood 0.1; udp_flood->benign 5.9

### sig6 (rounded to 6 significant figures); unique vectors train 544,073, val 113,040

| split | group | port_scan rows | also carry syn_flood | % |
|---|---|---|---|---|
| train | G1 | 50,472 | 0 | 0.0 |
| val | G1 | 7,763 | 0 | 0.0 |
| val vs train | G1 | 7,763 | 0 | 0.0 |
| train | G2 | 43,218 | 0 | 0.0 |
| val | G2 | 10,416 | 0 | 0.0 |
| val vs train | G2 | 10,416 | 0 | 0.0 |
| train | GEN | 4,356 | 0 | 0.0 |

Conflict matrix, % of row class a whose vector also carries label b:

- train_within: benign->syn_flood 0.4; benign->udp_flood 0.1; syn_flood->benign 0.0; syn_flood->udp_flood 0.0; udp_flood->benign 1.1; udp_flood->syn_flood 1.1
- val_within: benign->udp_flood 0.1; udp_flood->benign 5.9
- val_vs_train: benign->syn_flood 0.3; benign->udp_flood 0.1; udp_flood->benign 5.9

## Q2 -- per-flow ceiling (one label per feature vector)

| vectors | val subset | class | val flows | ceiling: train-majority lookup | ceiling: val oracle | achieved (ROUTED s0) |
|---|---|---|---|---|---|---|
| exact | all | syn_flood | 100,177 | 1.0000 | 1.0000 | 0.9976 |
| exact | all | port_scan | 18,179 | 1.0000 | 1.0000 | 0.8148 |
| exact | G1 | syn_flood | 50,103 | 1.0000 | 1.0000 | 0.9951 |
| exact | G1 | port_scan | 7,763 | 1.0000 | 1.0000 | 0.5663 |
| exact | G2 | syn_flood | 50,074 | 1.0000 | 1.0000 | 1.0000 |
| exact | G2 | port_scan | 10,416 | 1.0000 | 1.0000 | 1.0000 |
| sig6 | all | syn_flood | 100,177 | 1.0000 | 1.0000 | 0.9976 |
| sig6 | all | port_scan | 18,179 | 1.0000 | 1.0000 | 0.8148 |
| sig6 | G1 | syn_flood | 50,103 | 1.0000 | 1.0000 | 0.9951 |
| sig6 | G1 | port_scan | 7,763 | 1.0000 | 1.0000 | 0.5663 |
| sig6 | G2 | syn_flood | 50,074 | 1.0000 | 1.0000 | 1.0000 |
| sig6 | G2 | port_scan | 10,416 | 1.0000 | 1.0000 | 1.0000 |

Train-majority lookup: vectors never seen in train count as correct (optimistic). Val oracle: each val vector gets its majority val label (the best any deterministic per-flow function can do on these rows).

## Q3 -- anatomy of the port_scan -> syn_flood errors on G1 val (seed 0)

| model | port_scan flows | errors -> syn_flood | conflict dup (exact) | conflict dup (exact or 6sf) | single-packet | correct but conflict dup |
|---|---|---|---|---|---|---|
| SPEC_G1__sqrt | 7,763 | 3,367 (43.4 %) | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) | 0 |
| GLOBAL__sqrt | 7,763 | 3,155 (40.6 %) | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) | 0 |

Crosstab (rows = prediction, columns = conflict x packets), specialist:

| prediction | no conflict, multi-packet | no conflict, single-packet |
|---|---|---|
| port_scan (correct) | 3,651 | 745 |
| syn_flood | 3,367 | 0 |

## Q4 -- profiles (port_scan vs syn_flood)

| split | group | class | n | single-packet % | Flow Duration q50 [q5, q95] | Fwd pkts q50 [q95] | Bwd pkts q50 [q95] | SYN q50 | RST q50 | distinct Dst Port | distinct init-win | top init-win | distinct src IP | top src MAC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| train | G1 | port_scan | 50,472 | 25.7 | 30310 [0, 689688] | 1 [1] | 1 [1] | 1 | 1 | 1,021 | 4 | 1024.0:47883, 0.0:2579, 29200.0:7 | 8 | dc:a6:32:dc:27:d5 |
| train | G1 | syn_flood | 200,605 | 4.6 | 9.59189e+07 [1.59786e+06, 1.17696e+08] | 4 [7] | 0 [1] | 4 | 0 | 6,271 | 4 | 512.0:197097, 65535.0:1786, 29200.0:1548 | 9 | dc:a6:32:c9:e4:ab |
| train | G2 | port_scan | 43,218 | 7.6 | 52855.5 [0, 920043] | 1 [1] | 1 [1] | 1 | 1 | 1,066 | 4 | 1024.0:31417, 4380.0:11075, 2920.0:671 | 14 | dc:a6:32:dc:27:d5 |
| train | G2 | syn_flood | 199,985 | 1.5 | 1.06674e+08 [5.52323e+07, 1.18358e+08] | 5 [8] | 0 [0] | 5 | 0 | 5 | 2 | 512.0:199982, 4380.0:3 | 9 | dc:a6:32:c9:e4:90 |
| train | GEN | port_scan | 4,356 | 31.0 | 4582 [0, 265960] | 1 [1] | 1 [1] | 1 | 1 | 1,005 | 2 | 1024.0:4020, 0.0:336 | 3 | dc:a6:32:dc:27:d5 |
| val | G1 | port_scan | 7,763 | 9.6 | 15597 [0, 510650] | 1 [1] | 1 [1] | 1 | 1 | 1,012 | 5 | 0.0:4348, 1024.0:3396, 29200.0:9 | 4 | dc:a6:32:dc:27:d5 |
| val | G1 | syn_flood | 50,103 | 15.3 | 7.43164e+07 [0, 1.15311e+08] | 3 [12] | 0 [0] | 3 | 0 | 346 | 3 | 512.0:49681, 14600.0:352, 0.0:70 | 7 | dc:a6:32:c9:e5:ef |
| val | G2 | port_scan | 10,416 | 19.7 | 72829 [0, 2.32204e+06] | 1 [1] | 1 [1] | 1 | 1 | 1,012 | 5 | 1024.0:8883, 4380.0:1286, 2920.0:240 | 6 | dc:a6:32:dc:27:d5 |
| val | G2 | syn_flood | 50,074 | 17.0 | 2.12824e+07 [0, 4.45747e+07] | 2 [3] | 0 [0] | 2 | 0 | 2 | 2 | 512.0:50073, 4380.0:1 | 8 | dc:a6:32:c9:e4:ab |

Source overlap:

- train: {"src_ip_A": 23, "src_ip_B": 12, "src_ip_shared": 0, "B_rows_with_src_ip_seen_in_A": 0.0, "src_mac_A": ["00:02:75:f6:e3:cb", "00:17:88:60:d6:4f", "1c:9d:c2:8c:9a:94", "24:a1:60:14:7f:f9", "2c:d2:6b:66:d2:87"], "src_mac_B": ["1c:12:b0:9b:0c:ec", "1c:fe:2b:98:16:dd", "50:02:91:10:09:8f", "b8:f0:09:03:29:79", "cc:f4:11:9c:d0:00"], "src_mac_shared": ["50:02:91:10:09:8f", "b8:f0:09:03:29:79", "dc:a6:32:dc:27:d5"]}
- val: {"src_ip_A": 9, "src_ip_B": 9, "src_ip_shared": 0, "B_rows_with_src_ip_seen_in_A": 0.0, "src_mac_A": ["18:69:d8:eb:d4:3e", "2c:71:ff:05:f1:15", "70:ee:50:6b:a8:1a", "84:e3:42:42:ed:0b", "ac:f1:08:4e:00:82"], "src_mac_B": ["50:02:91:10:09:8f", "9c:8e:cd:1d:ab:9f", "dc:a6:32:c9:e4:90", "dc:a6:32:c9:e4:ab", "dc:a6:32:c9:e4:d5"], "src_mac_shared": ["dc:a6:32:dc:27:d5"]}

## Q5 -- causal cross-flow context (same Src IP, flows started strictly earlier in [t - W, t))

- **caveat**: the dataset carries V1's caps -- syn_flood rows are a sample (p per key attack|train|G1|syn_flood 0.034, attack|val|G1|syn_flood 0.063, attack|train|G2|syn_flood 0.048, attack|val|G2|syn_flood 0.070), so counts involving syn_flood traffic are undercounts here; port_scan is never capped.
- compute cost (single Python process, dict counters; dev machine): train_W2 327,218 rows/s, train_W10 331,824 rows/s, train_W60 335,962 rows/s, val_W2 335,331 rows/s, val_W10 307,143 rows/s, val_W60 349,885 rows/s

Thresholds picked on train (conflict-duplicate port_scan vs all syn_flood), read on val:

| W (s) | feature | subset | rule | conflict port_scan on port_scan side | syn_flood on syn_flood side |
|---|---|---|---|---|---|

Val quantiles at W = 10 s (q5 / q50 / q95):

| group | class | feature | q5 | q50 | q95 | n |
|---|---|---|---|---|---|---|
| G1 | port_scan | ctx_distinct_dports | 0 | 4 | 294 | 7,763 |
| G1 | port_scan | ctx_same_dst_dport | 0 | 0 | 298 | 7,763 |
| G1 | port_scan | ctx_distinct_dips | 0 | 1 | 4 | 7,763 |
| G1 | syn_flood | ctx_distinct_dports | 1 | 1 | 1 | 50,103 |
| G1 | syn_flood | ctx_same_dst_dport | 2 | 895 | 2011 | 50,103 |
| G1 | syn_flood | ctx_distinct_dips | 1 | 1 | 1 | 50,103 |
| G2 | port_scan | ctx_distinct_dports | 0 | 110 | 481 | 10,416 |
| G2 | port_scan | ctx_same_dst_dport | 0 | 0 | 1 | 10,416 |
| G2 | port_scan | ctx_distinct_dips | 0 | 1 | 1 | 10,416 |
| G2 | syn_flood | ctx_distinct_dports | 1 | 1 | 1 | 50,074 |
| G2 | syn_flood | ctx_same_dst_dport | 8 | 1440 | 2688 | 50,074 |
| G2 | syn_flood | ctx_distinct_dips | 1 | 1 | 1 | 50,074 |

## Figures

- `figures/conflict_matrix_exact.png` -- % of each class whose exact feature vector also carries another label (train, val, val vs train).
- `figures/error_anatomy_focus.png` -- G1 val port_scan flows by the specialist's prediction, split by conflict duplicate and single packet.
- `figures/ceiling_vs_achieved.png` -- per-flow ceilings (train-majority lookup, val oracle) vs ROUTED seed-0 recall per class, all / per group.
- `figures/context_W10.png` -- ECDFs of the three causal context features (W = 10 s) for port_scan vs syn_flood per group (val; syn_flood capped).
