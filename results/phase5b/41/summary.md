# Step 41 -- orientation robustness (H-C1), real reversals, contamination -- PASS

- flip: {'rows': 157558, 'swapped_by_guard': 137593, 'not_swapped_non_tcp': 19965, 'rows_with_changed_flow_features': 137570}

- **H-C1 (TCP flows only (the normaliser's TCP guard); non-TCP agreement is 1 by construction, not evidence): HOLDS** -- agreement GLOBAL_CTX - GLOBAL, TCP flows +0.041703 [+0.029295, +0.048830] (lo > 0: True); TCP benign +0.028408 [+0.025849, +0.030915] (lo > 0: True)

| arm | seed | TCP | TCP benign | TCP per class | non-TCP (by construction) | all | flows changed |
|---|---|---|---|---|---|---|---|
| GLOBAL | 0 | 0.920970 | 0.969106 | benign 0.969106, syn_flood 0.997724, udp_flood 0.600000, port_scan 0.447274 | 1.000000 | 0.930984 | 10,874 |
| GLOBAL_CTX | 0 | 0.971241 | 0.999480 | benign 0.999480, syn_flood 0.999361, udp_flood 0.900000, port_scan 0.786457 | 1.000000 | 0.974885 | 3,957 |
| CTX_ONLY | 0 | 1.000000 | 1.000000 | benign 1.000000, syn_flood 1.000000, udp_flood 1.000000, port_scan 1.000000 | 1.000000 | 1.000000 | 0 |
| GLOBAL_NOFP | 0 | 0.916820 | 0.970042 | benign 0.970042, syn_flood 0.998103, udp_flood 0.700000, port_scan 0.412729 | 1.000000 | 0.927360 | 11,445 |
| GLOBAL_CTX_NOFP | 0 | 0.999622 | 0.999376 | benign 0.999376, syn_flood 0.999611, udp_flood 0.900000, port_scan 1.000000 | 1.000000 | 0.999670 | 52 |
| GLOBAL | 1 | 0.921769 | 0.974203 | benign 0.974203, syn_flood 0.998014, udp_flood 0.600000, port_scan 0.446339 | 1.000000 | 0.931682 | 10,764 |
| GLOBAL_CTX | 1 | 0.939016 | 0.998596 | benign 0.998596, syn_flood 0.996426, udp_flood 0.900000, port_scan 0.559657 | 1.000000 | 0.946743 | 8,391 |
| CTX_ONLY | 1 | 1.000000 | 1.000000 | benign 1.000000, syn_flood 1.000000, udp_flood 1.000000, port_scan 1.000000 | 1.000000 | 1.000000 | 0 |
| GLOBAL_NOFP | 1 | 0.916609 | 0.970094 | benign 0.970094, syn_flood 0.997834, udp_flood 0.700000, port_scan 0.412564 | 1.000000 | 0.927176 | 11,474 |
| GLOBAL_CTX_NOFP | 1 | 0.999644 | 0.999272 | benign 0.999272, syn_flood 0.999661, udp_flood 0.900000, port_scan 1.000000 | 1.000000 | 0.999689 | 49 |
| GLOBAL | 2 | 0.922423 | 0.968586 | benign 0.968586, syn_flood 0.997464, udp_flood 0.600000, port_scan 0.460256 | 1.000000 | 0.932254 | 10,674 |
| GLOBAL_CTX | 2 | 0.970892 | 0.999792 | benign 0.999792, syn_flood 0.999361, udp_flood 0.900000, port_scan 0.783486 | 1.000000 | 0.974581 | 4,005 |
| CTX_ONLY | 2 | 1.000000 | 1.000000 | benign 1.000000, syn_flood 1.000000, udp_flood 1.000000, port_scan 1.000000 | 1.000000 | 1.000000 | 0 |
| GLOBAL_NOFP | 2 | 0.916442 | 0.968898 | benign 0.968898, syn_flood 0.997824, udp_flood 0.700000, port_scan 0.412619 | 1.000000 | 0.927030 | 11,497 |
| GLOBAL_CTX_NOFP | 2 | 0.999760 | 0.999220 | benign 0.999220, syn_flood 0.999830, udp_flood 0.900000, port_scan 1.000000 | 1.000000 | 0.999791 | 33 |
| GLOBAL | 3 | 0.922998 | 0.974203 | benign 0.974203, syn_flood 0.997654, udp_flood 0.600000, port_scan 0.457616 | 1.000000 | 0.932755 | 10,595 |
| GLOBAL_CTX | 3 | 0.969257 | 0.999376 | benign 0.999376, syn_flood 0.999571, udp_flood 0.900000, port_scan 0.770394 | 1.000000 | 0.973153 | 4,230 |
| CTX_ONLY | 3 | 1.000000 | 1.000000 | benign 1.000000, syn_flood 1.000000, udp_flood 1.000000, port_scan 1.000000 | 1.000000 | 1.000000 | 0 |
| GLOBAL_NOFP | 3 | 0.918077 | 0.970094 | benign 0.970094, syn_flood 0.998163, udp_flood 0.600000, port_scan 0.421915 | 1.000000 | 0.928458 | 11,272 |
| GLOBAL_CTX_NOFP | 3 | 0.999673 | 0.999324 | benign 0.999324, syn_flood 0.999701, udp_flood 0.900000, port_scan 0.999945 | 1.000000 | 0.999714 | 45 |
| GLOBAL | 4 | 0.922467 | 0.968742 | benign 0.968742, syn_flood 0.997504, udp_flood 0.600000, port_scan 0.460201 | 1.000000 | 0.932292 | 10,668 |
| GLOBAL_CTX | 4 | 0.968734 | 0.999636 | benign 0.999636, syn_flood 0.996307, udp_flood 0.900000, port_scan 0.784147 | 1.000000 | 0.972696 | 4,302 |
| CTX_ONLY | 4 | 1.000000 | 1.000000 | benign 1.000000, syn_flood 1.000000, udp_flood 1.000000, port_scan 1.000000 | 1.000000 | 1.000000 | 0 |
| GLOBAL_NOFP | 4 | 0.917670 | 0.970094 | benign 0.970094, syn_flood 0.998053, udp_flood 0.600000, port_scan 0.419440 | 1.000000 | 0.928103 | 11,328 |
| GLOBAL_CTX_NOFP | 4 | 0.999760 | 0.999220 | benign 0.999220, syn_flood 0.999830, udp_flood 0.900000, port_scan 1.000000 | 1.000000 | 0.999791 | 33 |

- real reversals (diag_03 B, H1): available True, 233 flows

| arm | seed | error rate on H1 flows | errors | diag_03 incidents still false |
|---|---|---|---|---|
| GLOBAL | 0 | 0.8326 | 194 | 3 / 3 |
| GLOBAL | 1 | 0.4678 | 109 | 4 / 4 |
| GLOBAL | 2 | 0.9485 | 221 | 3 / 3 |
| GLOBAL | 3 | 0.8670 | 202 | 4 / 4 |
| GLOBAL | 4 | 0.8927 | 208 | 3 / 3 |
| GLOBAL_CTX | 0 | 0.0944 | 22 | 1 / 3 |
| GLOBAL_CTX | 1 | 0.1373 | 32 | 1 / 4 |
| GLOBAL_CTX | 2 | 0.1373 | 32 | 1 / 3 |
| GLOBAL_CTX | 3 | 0.1416 | 33 | 1 / 4 |
| GLOBAL_CTX | 4 | 0.1416 | 33 | 1 / 3 |
| CTX_ONLY | 0 | 0.1073 | 25 | 1 / 3 |
| CTX_ONLY | 1 | 0.1416 | 33 | 1 / 4 |
| CTX_ONLY | 2 | 0.1416 | 33 | 1 / 3 |
| CTX_ONLY | 3 | 0.1416 | 33 | 1 / 4 |
| CTX_ONLY | 4 | 0.1116 | 26 | 1 / 3 |
| GLOBAL_NOFP | 0 | 0.8197 | 191 | 1 / 3 |
| GLOBAL_NOFP | 1 | 0.8627 | 201 | 1 / 4 |
| GLOBAL_NOFP | 2 | 0.8455 | 197 | 1 / 3 |
| GLOBAL_NOFP | 3 | 0.8197 | 191 | 1 / 4 |
| GLOBAL_NOFP | 4 | 0.8155 | 190 | 1 / 3 |
| GLOBAL_CTX_NOFP | 0 | 0.1202 | 28 | 1 / 3 |
| GLOBAL_CTX_NOFP | 1 | 0.1288 | 30 | 1 / 4 |
| GLOBAL_CTX_NOFP | 2 | 0.1288 | 30 | 1 / 3 |
| GLOBAL_CTX_NOFP | 3 | 0.1373 | 32 | 1 / 4 |
| GLOBAL_CTX_NOFP | 4 | 0.1373 | 32 | 1 / 3 |

- contamination (60 s): 509 of 39,185 val benign flows (0.0130)

| arm | seed | FA contaminated (n) | FA clean (n) | FA/h clean |
|---|---|---|---|---|
| GLOBAL | 0 | 1 (509) | 1 (38,676) | 0.512 |
| GLOBAL | 1 | 1 (509) | 1 (38,676) | 0.512 |
| GLOBAL | 2 | 1 (509) | 1 (38,676) | 0.512 |
| GLOBAL | 3 | 0 (509) | 1 (38,676) | 0.512 |
| GLOBAL | 4 | 1 (509) | 2 (38,676) | 1.024 |
| GLOBAL_CTX | 0 | 0 (509) | 1 (38,676) | 0.512 |
| GLOBAL_CTX | 1 | 0 (509) | 0 (38,676) | 0.0 |
| GLOBAL_CTX | 2 | 0 (509) | 1 (38,676) | 0.512 |
| GLOBAL_CTX | 3 | 0 (509) | 0 (38,676) | 0.0 |
| GLOBAL_CTX | 4 | 0 (509) | 0 (38,676) | 0.0 |
| CTX_ONLY | 0 | 2 (509) | 2 (38,676) | 1.024 |
| CTX_ONLY | 1 | 2 (509) | 5 (38,676) | 2.56 |
| CTX_ONLY | 2 | 2 (509) | 2 (38,676) | 1.024 |
| CTX_ONLY | 3 | 3 (509) | 3 (38,676) | 1.536 |
| CTX_ONLY | 4 | 1 (509) | 2 (38,676) | 1.024 |
| GLOBAL_NOFP | 0 | 0 (509) | 3 (38,676) | 1.536 |
| GLOBAL_NOFP | 1 | 0 (509) | 1 (38,676) | 0.512 |
| GLOBAL_NOFP | 2 | 0 (509) | 3 (38,676) | 1.536 |
| GLOBAL_NOFP | 3 | 0 (509) | 2 (38,676) | 1.024 |
| GLOBAL_NOFP | 4 | 0 (509) | 2 (38,676) | 1.024 |
| GLOBAL_CTX_NOFP | 0 | 0 (509) | 0 (38,676) | 0.0 |
| GLOBAL_CTX_NOFP | 1 | 0 (509) | 0 (38,676) | 0.0 |
| GLOBAL_CTX_NOFP | 2 | 0 (509) | 0 (38,676) | 0.0 |
| GLOBAL_CTX_NOFP | 3 | 0 (509) | 0 (38,676) | 0.0 |
| GLOBAL_CTX_NOFP | 4 | 0 (509) | 0 (38,676) | 0.0 |

## Checks

- PASS  val rows == step 40's (uid sha256)  157,558
- PASS  context recomputed on the original val stream == stored (exact)  
- PASS  context recomputed on the FLIPPED val stream == stored (exact)  
- PASS  CTX_ONLY flip agreement == 1.0 exactly (every seed)  [1.0, 1.0, 1.0, 1.0, 1.0]
