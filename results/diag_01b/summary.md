# diag_01b -- alternatives: what the G1 port_scan -> syn_flood errors have in common -- PASS

- READ-ONLY follow-up to `results/diag_01` (duplicate hypothesis NOT SUPPORTED). Train / val only; the seed-0 specialist loaded read-only; nothing trained.

- SPEC_G1__sqrt__s0 on G1 val port_scan: 3,367 of 7,763 labelled syn_flood (43.4 %)

## E1 -- FWD Init Win Bytes of G1 port_scan flows, train vs val, and the error rate per value

| init win | train n | train % | val n | val % | val errors | val error rate | % of all errors |
|---|---|---|---|---|---|---|---|
| 0 | 2,579 | 5.1 | 4,348 | 56.0 | 3,353 | 77.1 % | 99.6 |
| 1024 | 47,883 | 94.9 | 3,396 | 43.7 | 0 | 0.0 % | 0.0 |
| 29200 | 7 | 0.0 | 9 | 0.1 | 9 | 100.0 % | 0.3 |
| 14600 | 3 | 0.0 | 5 | 0.1 | 0 | 0.0 % | 0.0 |
| 65535 | 0 | 0.0 | 5 | 0.1 | 5 | 100.0 % | 0.1 |

- train syn_flood FWD Init Win Bytes (all groups, top values): {'512.0': 397079, '65535.0': 1786, '29200.0': 1548, '0.0': 174, '4380.0': 3}
- train port_scan FWD Init Win Bytes (all groups, top values): {'1024.0': 83320, '4380.0': 11075, '0.0': 2915, '2920.0': 671, '28694.0': 55, '29200.0': 7, '14600.0': 3}

## E2 -- errors vs correct port_scan flows (G1 val) and train port_scan (q50 [q5, q95])

| feature | errors | correct | train port_scan |
|---|---|---|---|
| Flow Duration | 15880 [10578.3, 23339] | 13851.5 [0, 531094] | 30310 [0, 689688] |
| Total Fwd Packet | 1 [1, 1] | 1 [1, 1] | 1 [1, 1] |
| Total Bwd packets | 1 [1, 1] | 1 [0, 1] | 1 [0, 1] |
| SYN Flag Count | 1 [1, 1] | 1 [1, 1] | 1 [1, 1] |
| RST Flag Count | 1 [1, 1] | 1 [0, 1] | 1 [0, 1] |
| ACK Flag Count | 1 [1, 1] | 1 [0, 1] | 1 [0, 1] |
| FIN Flag Count | 0 [0, 0] | 0 [0, 0] | 0 [0, 0] |
| FWD Init Win Bytes | 0 [0, 0] | 1024 [0, 1024] | 1024 [0, 1024] |
| Bwd Init Win Bytes | 1024 [1024, 1024] | 0 [0, 1024] | 0 [0, 1024] |
| Fwd Header Length | 20 [20, 20] | 24 [20, 24] | 24 [20, 24] |
| Flow IAT Min | 15862 [10576, 23128.1] | 13849.5 [0, 531094] | 30310 [0, 688916] |

## E3 -- where and when

Top device by errors:

| device | n | errors | error rate |
|---|---|---|---|
| LG Smart TV | 1,998 | 1,529 | 76.5 % |
| Amazon Echo Show | 2,000 | 1,095 | 54.8 % |
| Harman Kardon speaker (Ampak) | 3,765 | 743 | 19.7 % |

Top Dst IP by errors:

| Dst IP | n | errors | error rate |
|---|---|---|---|
| 192.168.137.178 | 4,367 | 3,367 | 77.1 % |
| 192.168.137.177 | 2,647 | 0 | 0.0 % |
| 192.168.137.191 | 149 | 0 | 0.0 % |
| 192.168.137.212 | 600 | 0 | 0.0 % |

Top session by errors:

| session | n | errors | error rate |
|---|---|---|---|
| Recon-PortScan | 7,763 | 3,367 | 43.4 % |

- val window 2022-09-27T14:38:13+00:00 .. 2022-09-27T14:58:38+00:00 (4 minutes with port_scan flows; 0 minutes where every flow is an error, 0 with none); train window 2022-09-26T16:31:40+00:00 .. 2022-09-27T14:23:32+00:00

## E4 -- causal context (same Src IP, [t - W, t)): threshold picked on train (all port_scan vs all syn_flood), read on val

- syn_flood rows are V1's capped sample, so syn_flood-side counts are undercounts (see diag_01).

| W (s) | feature | port_scan set (val) | rule | port_scan on port_scan side | syn_flood on syn_flood side |
|---|---|---|---|---|---|
| 2 | ctx_distinct_dports | all val A (n=18,179) | >= 2 | 66.5 % | 99.7 % |
| 2 | ctx_distinct_dports | G1 val A (n=7,763) | >= 2 | 42.4 % | 99.7 % |
| 2 | ctx_distinct_dports | G1 val A misclassified as B (n=3,367) | >= 2 | 10.2 % | 99.7 % |
| 2 | ctx_same_dst_dport | all val A (n=18,179) | < 3 | 88.8 % | 92.7 % |
| 2 | ctx_same_dst_dport | G1 val A (n=7,763) | < 3 | 80.1 % | 92.7 % |
| 2 | ctx_same_dst_dport | G1 val A misclassified as B (n=3,367) | < 3 | 69.9 % | 92.7 % |
| 2 | ctx_distinct_dips | all val A (n=18,179) | < 1 | 20.4 % | 94.1 % |
| 2 | ctx_distinct_dips | G1 val A (n=7,763) | < 1 | 27.7 % | 94.1 % |
| 2 | ctx_distinct_dips | G1 val A misclassified as B (n=3,367) | < 1 | 40.5 % | 94.1 % |
| 10 | ctx_distinct_dports | all val A (n=18,179) | >= 2 | 81.7 % | 99.6 % |
| 10 | ctx_distinct_dports | G1 val A (n=7,763) | >= 2 | 78.1 % | 99.6 % |
| 10 | ctx_distinct_dports | G1 val A misclassified as B (n=3,367) | >= 2 | 71.4 % | 99.6 % |
| 10 | ctx_same_dst_dport | all val A (n=18,179) | < 3 | 88.7 % | 95.9 % |
| 10 | ctx_same_dst_dport | G1 val A (n=7,763) | < 3 | 80.0 % | 95.9 % |
| 10 | ctx_same_dst_dport | G1 val A misclassified as B (n=3,367) | < 3 | 69.6 % | 95.9 % |
| 10 | ctx_distinct_dips | all val A (n=18,179) | < 1 | 17.7 % | 96.6 % |
| 10 | ctx_distinct_dips | G1 val A (n=7,763) | < 1 | 21.9 % | 96.6 % |
| 10 | ctx_distinct_dips | G1 val A misclassified as B (n=3,367) | < 1 | 28.6 % | 96.6 % |
| 60 | ctx_distinct_dports | all val A (n=18,179) | >= 2 | 90.3 % | 99.6 % |
| 60 | ctx_distinct_dports | G1 val A (n=7,763) | >= 2 | 85.0 % | 99.6 % |
| 60 | ctx_distinct_dports | G1 val A misclassified as B (n=3,367) | >= 2 | 77.2 % | 99.6 % |
| 60 | ctx_same_dst_dport | all val A (n=18,179) | < 27 | 88.8 % | 96.1 % |
| 60 | ctx_same_dst_dport | G1 val A (n=7,763) | < 27 | 79.9 % | 96.1 % |
| 60 | ctx_same_dst_dport | G1 val A misclassified as B (n=3,367) | < 27 | 69.5 % | 96.1 % |
| 60 | ctx_distinct_dips | all val A (n=18,179) | >= 2 | 25.6 % | 99.6 % |
| 60 | ctx_distinct_dips | G1 val A (n=7,763) | >= 2 | 44.0 % | 99.6 % |
| 60 | ctx_distinct_dips | G1 val A misclassified as B (n=3,367) | >= 2 | 77.2 % | 99.6 % |

## Figures

- `figures/init_window_shift.png` -- share of G1 port_scan flows per FWD Init Win Bytes value in train vs val (left) and the specialist's val error rate per value (right).
