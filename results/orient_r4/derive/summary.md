# Orientation R4 -- STEP A derivation (train) -- run PASS

- run `20261122T063716Z`; READ-ONLY; v2_1_oriented train (+ val for the R3 audit) via load_split; test never read.
- ground truth (evaluation only): {'attack_source': {'rule': "13_rate_guard_calibrate.MacBook.get(mac)[0] != '' (ATTACKER_MACS.matches(mac) or device_table role == testbed_pi)", 'ATTACKER_MACS.exact': ['e4:5f:01:55:90:c4'], 'ATTACKER_MACS.prefixes': ['dc:a6:32'], 'device_table_testbed_pi': ['dc:a6:32:c9:e4:90', 'dc:a6:32:c9:e4:ab', 'dc:a6:32:c9:e4:c6', 'dc:a6:32:c9:e4:d5', 'dc:a6:32:c9:e5:02', 'dc:a6:32:c9:e5:a4', 'dc:a6:32:c9:e5:ef', 'dc:a6:32:c9:e6:f4', 'dc:a6:32:dc:27:d5', 'e4:5f:01:55:90:c4']}, 'inventory_roles': ['iot'], 'inventory_macs': 56}

## Selection rule (fixed before the numbers)

- candidates: Protocol == TCP AND <= 4 of 42 structural predicates, on rows R3 did not flip;
- admissible iff on TRAIN: benign flagged <= 0.05 % in every group, TRUTH_FORWARD flagged <= 0.1 % per attack class, non-TCP flagged = 0 (TCP clause);
- best = highest TRUTH_REVERSED recall; ties -> fewer predicates -> no port predicate -> fewer benign flags -> fewer TRUTH_FORWARD flags -> fewer other attack rows -> predicate order;
- STOP if the best admissible recall < 90 %.

## A1 -- ground-truth counts (TCP attack rows)

| split | group | class | rows | TCP | REVERSED | REVERSED (R3 did not flip) | FORWARD | R3 flipped | other TCP |
|---|---|---|---|---|---|---|---|---|---|
| train | G1 | port_scan | 50,472 | 50,472 | 10 | 10 | 50,462 | 2,579 | 0 |
| train | G1 | syn_flood | 200,605 | 200,605 | 6,884 | 6,883 | 193,721 | 1 | 0 |
| train | G1 | udp_flood | 95 | 33 | 14 | 14 | 19 | 0 | 0 |
| train | G2 | port_scan | 43,218 | 43,218 | 11,801 | 11,801 | 31,417 | 0 | 0 |
| train | G2 | syn_flood | 199,985 | 199,985 | 4 | 4 | 199,981 | 0 | 0 |
| train | GEN | port_scan | 4,356 | 4,356 | 0 | 0 | 4,356 | 336 | 0 |
| val | G1 | port_scan | 7,763 | 7,763 | 19 | 19 | 7,744 | 4,348 | 0 |
| val | G1 | syn_flood | 50,103 | 50,103 | 366 | 363 | 49,737 | 3 | 0 |
| val | G1 | udp_flood | 17 | 10 | 0 | 0 | 10 | 0 | 0 |
| val | G2 | port_scan | 10,416 | 10,416 | 1,533 | 1,533 | 8,883 | 0 | 0 |
| val | G2 | syn_flood | 50,074 | 50,074 | 1 | 1 | 50,073 | 0 | 0 |

Predicate profile (train, % of rows where it holds):

| predicate | REVERSED | FORWARD | benign TCP |
|---|---|---|---|
| Total Fwd Packet == 1 | 97.0 | 20.5 | 22.79 |
| Total Fwd Packet <= 2 | 99.9 | 26.5 | 33.83 |
| Total Bwd packets == 0 | 0.0 | 83.9 | 28.40 |
| Total Bwd packets == 1 | 70.3 | 16.1 | 10.90 |
| Total Bwd packets >= 1 | 100.0 | 16.1 | 71.60 |
| SYN Flag Count == 0 | 0.0 | 0.0 | 60.90 |
| SYN Flag Count == 1 | 65.6 | 20.7 | 0.56 |
| SYN Flag Count >= 1 | 100.0 | 100.0 | 39.10 |
| SYN Flag Count == 2 | 5.0 | 5.9 | 29.09 |
| ACK Flag Count == 0 | 18.8 | 83.8 | 7.17 |
| ACK Flag Count == 1 | 79.7 | 16.2 | 17.79 |
| ACK Flag Count >= 1 | 81.2 | 16.2 | 92.83 |
| ACK Flag Count == 2 | 1.3 | 0.0 | 6.40 |
| RST Flag Count == 0 | 31.2 | 83.5 | 88.73 |
| RST Flag Count == 1 | 68.8 | 16.5 | 9.38 |
| RST Flag Count >= 1 | 68.8 | 16.5 | 11.27 |
| RST Flag Count == 2 | 0.0 | 0.0 | 1.89 |
| FIN Flag Count == 0 | 100.0 | 100.0 | 58.56 |
| FIN Flag Count == 1 | 0.0 | 0.0 | 19.59 |
| FIN Flag Count >= 1 | 0.0 | 0.0 | 41.44 |
| FIN Flag Count == 2 | 0.0 | 0.0 | 21.73 |
| PSH Flag Count == 0 | 100.0 | 100.0 | 37.04 |
| PSH Flag Count == 1 | 0.0 | 0.0 | 6.75 |
| PSH Flag Count >= 1 | 0.0 | 0.0 | 62.96 |
| PSH Flag Count == 2 | 0.0 | 0.0 | 20.64 |
| CWR Flag Count == 0 | 100.0 | 100.0 | 99.21 |
| CWR Flag Count == 1 | 0.0 | 0.0 | 0.79 |
| CWR Flag Count >= 1 | 0.0 | 0.0 | 0.79 |
| CWR Flag Count == 2 | 0.0 | 0.0 | 0.00 |
| ECE Flag Count == 0 | 100.0 | 100.0 | 99.21 |
| ECE Flag Count == 1 | 0.0 | 0.0 | 0.19 |
| ECE Flag Count >= 1 | 0.0 | 0.0 | 0.79 |
| ECE Flag Count == 2 | 0.0 | 0.0 | 0.60 |
| FWD Init Win Bytes == 0 | 0.0 | 0.0 | 3.24 |
| FWD Init Win Bytes > 0 | 100.0 | 100.0 | 96.76 |
| Bwd Init Win Bytes == 0 | 5.8 | 93.8 | 30.27 |
| Bwd Init Win Bytes > 0 | 94.2 | 6.2 | 69.73 |
| FWD Init Win Bytes > Bwd Init Win Bytes | 81.3 | 93.8 | 76.61 |
| Fwd Header Length / Total Fwd Packet > Bwd Header Length / Total Bwd packets | 18.1 | 14.3 | 14.05 |
| Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets | 63.0 | 1.9 | 23.54 |
| Fwd Header Length / Total Fwd Packet == Bwd Header Length / Total Bwd packets | 18.9 | 0.0 | 34.01 |
| Src Port < Dst Port | 79.1 | 19.1 | 34.03 |

Numeric profile (train; p05 / median / p95, share == 0):

| field | REVERSED | FORWARD |
|---|---|---|
| FWD Init Win Bytes | 512 / 4380 / 65535, zero 0 % | 512 / 512 / 1024, zero 0 % |
| Bwd Init Win Bytes | 0 / 1024 / 1024, zero 6 % | 0 / 0 / 2920, zero 94 % |
| Fwd Header Length / Total Fwd Packet | 20 / 20 / 24, zero 0 % | 20 / 20 / 24, zero 0 % |
| Bwd Header Length / Total Bwd packets | 20 / 24 / 24, zero 0 % | 20 / 20 / 24, zero 0 % |
| Total Fwd Packet | 1 / 1 / 1, zero 0 % | 1 / 4 / 7, zero 0 % |
| Total Bwd packets | 1 / 1 / 5, zero 0 % | 0 / 0 / 1, zero 84 % |
| SYN Flag Count | 1 / 1 / 6, zero 0 % | 1 / 4 / 7, zero 0 % |
| ACK Flag Count | 0 / 1 / 1, zero 19 % | 0 / 0 / 1, zero 84 % |
| RST Flag Count | 0 / 1 / 1, zero 31 % | 0 / 0 / 1, zero 84 % |
| FIN Flag Count | 0 / 0 / 0, zero 100 % | 0 / 0 / 0, zero 100 % |
| PSH Flag Count | 0 / 0 / 0, zero 100 % | 0 / 0 / 0, zero 100 % |
| CWR Flag Count | 0 / 0 / 0, zero 100 % | 0 / 0 / 0, zero 100 % |
| ECE Flag Count | 0 / 0 / 0, zero 100 % | 0 / 0 / 0, zero 100 % |
| Src Port | 513 / 4070 / 55442, zero 0 % | 3992.75 / 37242 / 62441, zero 0 % |
| Dst Port | 6237.4 / 43679 / 57509, zero 0 % | 1199 / 6668 / 55442, zero 0 % |
| Src Port < Dst Port (share) | 0.791 | 0.191 |

## A2 / A3 -- search (124,313 candidates, 89,287 admissible; 1,074 distinct predicate patterns over 548,859 unflipped TCP train rows)

- **STOP: no rule** (best admissible recall 0.7525 < 0.9)

Top admissible candidates:

| rule | recall | predicates | max benign % | max FORWARD % | other attack |
|---|---|---|---|---|---|
| `Total Fwd Packet == 1 AND ACK Flag Count == 1 AND Bwd Init Win Bytes > 0 AND FWD Init Win Bytes > Bwd Init Win Bytes` | 75.25 | 4 | 0.0123 | 0.0000 | 0 |
| `Total Fwd Packet <= 2 AND ACK Flag Count == 1 AND Bwd Init Win Bytes > 0 AND FWD Init Win Bytes > Bwd Init Win Bytes` | 75.25 | 4 | 0.0307 | 0.0000 | 0 |
| `ACK Flag Count == 1 AND Bwd Init Win Bytes > 0 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Src Port < Dst Port` | 65.75 | 4 | 0.0042 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 3 | 0.0350 | 0.0000 | 0 |
| `SYN Flag Count == 1 AND Bwd Init Win Bytes > 0 AND FWD Init Win Bytes > Bwd Init Win Bytes` | 63.00 | 3 | 0.0300 | 0.0000 | 0 |
| `SYN Flag Count == 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 3 | 0.0017 | 0.0000 | 0 |
| `ACK Flag Count == 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 3 | 0.0025 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND Total Fwd Packet <= 2 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 4 | 0.0350 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND Total Bwd packets == 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 4 | 0.0108 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND Total Bwd packets >= 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 4 | 0.0350 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND SYN Flag Count == 1 AND Bwd Init Win Bytes > 0 AND FWD Init Win Bytes > Bwd Init Win Bytes` | 63.00 | 4 | 0.0242 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND SYN Flag Count == 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 4 | 0.0008 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND SYN Flag Count >= 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 4 | 0.0008 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND ACK Flag Count == 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 4 | 0.0000 | 0.0000 | 0 |
| `Total Fwd Packet == 1 AND ACK Flag Count >= 1 AND FWD Init Win Bytes > Bwd Init Win Bytes AND Fwd Header Length / Total Fwd Packet < Bwd Header Length / Total Bwd packets` | 63.00 | 4 | 0.0350 | 0.0000 | 0 |

Highest-recall candidates regardless of admissibility:

| rule | recall | max benign % | max FORWARD % | admissible |
|---|---|---|---|---|
| `Total Bwd packets >= 1 AND FWD Init Win Bytes > 0` | 100.00 | 48.0803 | 76.1315 | False |
| `Total Bwd packets >= 1 AND CWR Flag Count == 0 AND FWD Init Win Bytes > 0` | 100.00 | 48.0803 | 76.1315 | False |
| `Total Bwd packets >= 1 AND ECE Flag Count == 0 AND FWD Init Win Bytes > 0` | 100.00 | 48.0803 | 76.1315 | False |
| `Total Bwd packets >= 1 AND CWR Flag Count == 0 AND ECE Flag Count == 0 AND FWD Init Win Bytes > 0` | 100.00 | 48.0803 | 76.1315 | False |
| `Total Bwd packets >= 1` | 100.00 | 48.2155 | 76.1315 | False |
| `Total Bwd packets >= 1 AND CWR Flag Count == 0` | 100.00 | 48.2155 | 76.1315 | False |
| `Total Bwd packets >= 1 AND ECE Flag Count == 0` | 100.00 | 48.2155 | 76.1315 | False |
| `Total Bwd packets >= 1 AND CWR Flag Count == 0 AND ECE Flag Count == 0` | 100.00 | 48.2155 | 76.1315 | False |
| `FWD Init Win Bytes > 0` | 100.00 | 52.5217 | 99.9561 | False |
| `CWR Flag Count == 0 AND FWD Init Win Bytes > 0` | 100.00 | 52.5217 | 99.9561 | False |

## A4 -- R3 over-flip audit (report-only)

| split | class | R3 flipped | FORWARD before the flip (over-flip) | REVERSED before the flip (correct) |
|---|---|---|---|---|
| train | benign | 8 | 0 | 0 |
| train | port_scan | 2,915 | 0 | 2,915 |
| train | syn_flood | 1 | 1 | 0 |
| train | udp_flood | 0 | 0 | 0 |
| val | benign | 0 | 0 | 0 |
| val | port_scan | 4,348 | 0 | 4,348 |
| val | syn_flood | 3 | 3 | 0 |
| val | udp_flood | 0 | 0 | 0 |

diag_03 flows traced (R3-flipped flows that ended in H4):

- `DDoS-SYN_Flood:6540458` (val, syn_flood): R3 flipped True; before the flip src dc:a6:32:c9:e4:90 -> dst 9c:8e:cd:1d:ab:9f; FORWARD before the flip: True; fwd / bwd packets 1 / 1, FWD / Bwd Init Win 14600 / 0 (as extracted)
- `DDoS-SYN_Flood:6593394` (val, syn_flood): R3 flipped True; before the flip src dc:a6:32:c9:e4:90 -> dst 9c:8e:cd:1d:ab:9f; FORWARD before the flip: True; fwd / bwd packets 1 / 1, FWD / Bwd Init Win 14600 / 0 (as extracted)

Exclusion search (R3 AND one predicate; must keep every correct R3 flip and every R3 gate (a) row [{'class_a': 'port_scan', 'focus_group': 'G1'}] in train and val):

- no single structural predicate removes an over-flip without losing a correct R3 flip: no proposal.
  - Total Fwd Packet == 1: keeps all correct flips True, removes 0 train / 0 val, lost {'train': 0, 'val': 0}
  - Total Fwd Packet <= 2: keeps all correct flips True, removes 0 train / 0 val, lost {'train': 0, 'val': 0}
  - Total Bwd packets == 1: keeps all correct flips True, removes 0 train / 1 val, lost {'train': 0, 'val': 0}
  - Total Bwd packets >= 1: keeps all correct flips True, removes 0 train / 0 val, lost {'train': 0, 'val': 0}
  - SYN Flag Count == 1: keeps all correct flips True, removes 0 train / 1 val, lost {'train': 0, 'val': 0}
  - SYN Flag Count >= 1: keeps all correct flips True, removes 0 train / 0 val, lost {'train': 0, 'val': 0}

## Figures

- `figures/profile_predicates.png` -- share of REVERSED / FORWARD / benign rows per predicate
- `figures/profile_numeric.png` -- Init Win, header length per packet, packet counts, flags: REVERSED vs FORWARD
- `figures/frontier.png` -- recall vs max benign flag % of every candidate, chosen rule marked

## Checks

- PASS  R3 recomputed from the pinned map on v2_0 == v2_1 orientation_flipped (train, val)  
- PASS  config.py / class_map.json unchanged  {'config/config.py': 'c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf', 'config/class_map.json': '64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580'}
