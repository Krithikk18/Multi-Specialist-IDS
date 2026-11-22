# Step 43 -- Part B: TreeSHAP perturbation check -- PASS

- k = 5, random draws 5; median replacement can create out-of-distribution rows; results describe the model, not the attack

| model | predicted class | n | drop top-k | drop random-k | drop bottom-k | top - random [95 % CI] | verdict | flip top / random / bottom | context SHAP share | fingerprint in top-k |
|---|---|---|---|---|---|---|---|---|---|---|
| GLOBAL | benign | 1,000 | 0.0001 | 0.0000 | 0.0000 | 0.0001 [-0.0004, 0.0007] | NOT_FAITHFUL | 0.000 / 0.000 / 0.000 | 0.000 | 0.679 |
| GLOBAL | syn_flood | 1,000 | 0.9993 | 0.0006 | 0.0000 | 0.9987 [0.9985, 0.9989] | FAITHFUL | 1.000 / 0.000 / 0.000 | 0.000 | 1.000 |
| GLOBAL | udp_flood | 13 | 0.8459 | 0.0487 | 0.0268 | 0.7972 [0.7326, 0.8560] | FAITHFUL | 1.000 / 0.046 / 0.077 | 0.000 | 1.000 |
| GLOBAL | port_scan | 1,000 | 0.8814 | 0.0649 | 0.0007 | 0.8165 [0.8089, 0.8238] | FAITHFUL | 1.000 / 0.073 / 0.001 | 0.000 | 1.000 |
| GLOBAL_CTX | benign | 1,000 | 0.0003 | 0.0000 | -0.0000 | 0.0003 [-0.0009, 0.0018] | NOT_FAITHFUL | 0.001 / 0.000 / 0.000 | 0.564 | 0.637 |
| GLOBAL_CTX | syn_flood | 1,000 | 0.0359 | 0.0020 | 0.0005 | 0.0340 [0.0282, 0.0402] | FAITHFUL | 0.013 / 0.002 / 0.001 | 0.743 | 0.998 |
| GLOBAL_CTX | udp_flood | 8 | 0.9353 | 0.0281 | 0.0140 | 0.9072 [0.7747, 0.9868] | FAITHFUL | 1.000 / 0.050 / 0.000 | 0.680 | 0.250 |
| GLOBAL_CTX | port_scan | 1,000 | 0.8952 | 0.0003 | 0.0000 | 0.8949 [0.8904, 0.8994] | FAITHFUL | 1.000 / 0.000 / 0.000 | 0.774 | 1.000 |

| model | temperature | source | sample | TreeSHAP additivity max error |
|---|---|---|---|---|
| GLOBAL | 1.4231 | deployed registry calibrator (val fit) | 3,013 | 4.8e-06 |
| GLOBAL_CTX | 1.0447 | inner split (63,620 rows) | 3,008 | 6.7e-06 |

## Checks

- PASS  GLOBAL seed-0 model == the deployed registry entry (sha256)  a0b0afc91a469ef3...
- PASS  GLOBAL: TreeSHAP additivity (sum of contributions == margin)  max error 4.77e-06
- PASS  GLOBAL_CTX: TreeSHAP additivity (sum of contributions == margin)  max error 6.68e-06
