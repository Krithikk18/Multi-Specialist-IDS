# Orientation normaliser -- R3 gate -- run PASS

- run `20261121T074211Z`; READ-ONLY; train / val via common/phase2_data.load_split (test never read).
- R1 = `FWD Init Win Bytes == 0 AND Bwd Init Win Bytes > 0`; **R3 = `Protocol == 6 AND R1 AND SYN Flag Count >= 1 AND Total Fwd Packet == 1`**.

## Gate (fixed before the numbers; all must hold, else STOP)

- (a) R3 flags 100 % of G1 val port_scan flows with FWD Init Win Bytes = 0, and exactly the port_scan rows R1 flags in train and val;
- (b) benign flagged by R3 <= 0.05 % in every split x group;
- (c) syn_flood rows flagged by R3 <= 10 per split;
- (d) 0 non-TCP rows flagged by R3.

## Result

- **GATE PASS**
- (a) PASS: R3 flags 4,348 of 4,348 G1 val port_scan flows with FWD Init Win Bytes = 0 (R1 4,348); per split port_scan rows R1 / R3 / R1-not-R3 / R3-not-R1: train 2,915 / 2,915 / 0 / 0; val 4,348 / 4,348 / 0 / 0
- (b) PASS: worst split x group train G1: 8 of 120,028 benign = 0.0013 %
- (c) PASS: syn_flood rows flagged by R3 per split {'train': 1, 'val': 3}
- (d) PASS: non-TCP flagged {'train': {'R3': 0, 'R3_without_protocol_clause': 0}, 'val': {'R3': 0, 'R3_without_protocol_clause': 0}}

## Flags per split x group x class

| split | group | class | n | R1 | R1 % | R3 | R3 % |
|---|---|---|---|---|---|---|---|
| train | G1 | benign | 120,028 | 451 | 0.0709 | 8 | 0.0013 |
| train | G1 | syn_flood | 200,605 | 146 | 0.0229 | 1 | 0.0002 |
| train | G1 | udp_flood | 95 | 2 | 0.0003 | 0 | 0.0000 |
| train | G1 | port_scan | 50,472 | 2,579 | 0.4054 | 2,579 | 0.4054 |
| train | G2 | benign | 16,279 | 21 | 0.0033 | 0 | 0.0000 |
| train | G2 | syn_flood | 199,985 | 0 | 0.0000 | 0 | 0.0000 |
| train | G2 | port_scan | 43,218 | 0 | 0.0000 | 0 | 0.0000 |
| train | GEN | benign | 1,155 | 0 | 0.0000 | 0 | 0.0000 |
| train | GEN | port_scan | 4,356 | 336 | 0.0528 | 336 | 0.0528 |
| val | G1 | benign | 35,833 | 181 | 0.1149 | 0 | 0.0000 |
| val | G1 | syn_flood | 50,103 | 64 | 0.0406 | 3 | 0.0019 |
| val | G1 | udp_flood | 17 | 0 | 0.0000 | 0 | 0.0000 |
| val | G1 | port_scan | 7,763 | 4,348 | 2.7596 | 4,348 | 2.7596 |
| val | G2 | benign | 3,061 | 2 | 0.0013 | 0 | 0.0000 |
| val | G2 | syn_flood | 50,074 | 0 | 0.0000 | 0 | 0.0000 |
| val | G2 | port_scan | 10,416 | 0 | 0.0000 | 0 | 0.0000 |
| val | GEN | benign | 291 | 0 | 0.0000 | 0 | 0.0000 |

## port_scan rows R1 flags and R3 does not

- train: 0 rows
- val: 0 rows

## Benign rows R3 still flags

- train: 8 rows: LG Smart TV 8009->52022 (fwd 1.0, bwd 1.0, SYN 1.0, RST 1.0, FIN 0.0); LG Smart TV 8009->52024 (fwd 1.0, bwd 1.0, SYN 1.0, RST 1.0, FIN 0.0); LG Smart TV 8009->52026 (fwd 1.0, bwd 1.0, SYN 1.0, RST 1.0, FIN 0.0); LG Smart TV 8009->52028 (fwd 1.0, bwd 1.0, SYN 1.0, RST 1.0, FIN 0.0); Amazon Alexa Echo Dot 2 41194->55443 (fwd 1.0, bwd 6.0, SYN 6.0, RST 1.0, FIN 0.0); Amazon Alexa Echo Dot 2 58778->55443 (fwd 1.0, bwd 4.0, SYN 4.0, RST 1.0, FIN 0.0); Amazon Alexa Echo Dot 2 58804->55443 (fwd 1.0, bwd 2.0, SYN 2.0, RST 1.0, FIN 0.0); Amazon Alexa Echo Dot 2 42176->55443 (fwd 1.0, bwd 1.0, SYN 1.0, RST 1.0, FIN 0.0)
- val: 0 rows

## Figures

- `figures/flag_rate_r1_vs_r3.png` -- % of each class flagged by R1 (left) and R3 (right) per split x group, with flagged / n.
