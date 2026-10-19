# Step 9 bake-off (round 1)

- run: 2026-10-19T13:53:42+00:00 | seed 42 | features sha256 cf73976fd384a466... | verify_lock PASS
- Round 1 = library defaults + class-weight handling only. Ranked by val PR-AUC; **no winner is declared**.
- Deviation from defaults: LR max_iter=2000 (default 100): convergence fix, not tuning (lbfgs stopped at 100 iterations with a ConvergenceWarning on GLOBAL).
- DR@FP/h<=1: lowest val threshold with val FP/hour <= 1; thresholds are chosen on val and DR is read on the same val, so it is optimistic.
- Latency / throughput / size are laptop proxies (WSL, 1 thread), not Pi numbers. Fit time uses all cores.
- GLOBAL = all train / val rows (G1 + G2 + GEN devices), same splits.

## FP/hour denominators (active benign val hours)

| group | hours | source |
|---|---|---|
| G1 | 1.9676 | computed: 08 benign_hours rule on manifest session_cuts + group benign starts (manifest has no per-group value) |
| G2 | 1.9676 | computed: 08 benign_hours rule on manifest session_cuts + group benign starts (manifest has no per-group value) |
| GLOBAL | 1.9676 | computed: 08 benign_hours rule on manifest session_cuts + group benign starts (manifest has no per-group value) |

## G1

| rank | model | status | PR-AUC | ROC-AUC | DR@FP/h<=1 | thr@FP/h<=1 | FP/h@FP/h<=1 | DR port_scan | DR syn_flood | DR udp_flood | DR@0.5 | FP/h@0.5 | lat med us | lat p99 us | flows/s | size | fit s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | XGB | OK | 1.0000 | 1.0000 | 0.9997 | 0.742858 | 0.51 | 1.0000 | 0.9998 | 0.4706 LOW_N | 0.9997 | 1.02 | 138.6 | 579.4 | 893108 | 156.4 kB | 16.3 |
| 2 | LGBM | OK | 1.0000 | 1.0000 | 0.9997 | 0.504345 | 0.51 | 1.0000 | 0.9998 | 0.5882 LOW_N | 0.9997 | 0.51 | 421.7 | 1424.9 | 617381 | 353.4 kB | 45.5 |
| 3 | CAT | OK | 1.0000 | 1.0000 | 0.9997 | 0.531358 | 0.51 | 1.0000 | 0.9999 | 0.4118 LOW_N | 0.9997 | 0.51 | 143.3 | 679.6 | 488863 | 1.12 MB | 53.3 |
| 4 | MLP | OK | 1.0000 | 1.0000 | 0.9997 | 0.342715 | 0.51 | 1.0000 | 0.9998 | 0.4118 LOW_N | 0.9996 | 0.51 | 249.1 | 443.0 | 306195 | 128.2 kB | 22.2 |
| 5 | ET | OK | 1.0000 | 1.0000 | 0.9993 | 0.690000 | 0.51 | 1.0000 | 0.9994 | 0.5294 LOW_N | 0.9997 | 1.52 | 5036.0 | 9322.2 | 161007 | 11.06 MB | 19.6 |
| 6 | RF | OK | 0.9999 | 0.9999 | 0.9998 | 0.330000 | 0.51 | 1.0000 | 0.9999 | 0.5294 LOW_N | 0.9997 | 0.51 | 4446.2 | 9063.7 | 288056 | 5.17 MB | 13.9 |
| 7 | KNN | OK | 0.9997 | 0.9997 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | 0.0000 LOW_N | 0.9991 | 7.62 | 28327.4 | 72690.9 | 608 | 108.39 MB | 0.7 |
| 8 | DT | OK | 0.9996 | 0.9996 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | 0.0000 LOW_N | 0.9997 | 9.15 | 68.6 | 195.1 | 15783750 | 20.0 kB | 8.4 |
| 9 | LR | OK | 0.9991 | 0.9990 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | 0.0000 LOW_N | 0.9988 | 132.14 | 246.0 | 617.8 | 3910243 | 3.6 kB | 3.3 |

## G2

| rank | model | status | PR-AUC | ROC-AUC | DR@FP/h<=1 | thr@FP/h<=1 | FP/h@FP/h<=1 | DR port_scan | DR syn_flood | DR udp_flood | DR@0.5 | FP/h@0.5 | lat med us | lat p99 us | flows/s | size | fit s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | XGB | OK | 1.0000 | 1.0000 | 1.0000 | 0.469866 | 0.51 | 1.0000 | 1.0000 | N/A | 1.0000 | 0.00 | 125.8 | 420.9 | 1962952 | 93.9 kB | 7.2 |
| 2 | CAT | OK | 1.0000 | 1.0000 | 1.0000 | 0.200335 | 0.51 | 1.0000 | 1.0000 | N/A | 1.0000 | 0.00 | 113.0 | 372.4 | 699398 | 345.6 kB | 26.8 |
| 3 | LGBM | OK | 1.0000 | 1.0000 | 1.0000 | 0.029992 | 0.51 | 1.0000 | 1.0000 | N/A | 1.0000 | 0.00 | 371.9 | 1673.6 | 430508 | 349.9 kB | 10.9 |
| 4 | RF | OK | 1.0000 | 1.0000 | 1.0000 | 0.290000 | 0.51 | 1.0000 | 1.0000 | N/A | 1.0000 | 0.00 | 4624.3 | 10072.4 | 269470 | 2.55 MB | 6.3 |
| 5 | ET | OK | 1.0000 | 1.0000 | 1.0000 | 0.220000 | 0.51 | 1.0000 | 1.0000 | N/A | 1.0000 | 0.00 | 4141.2 | 7872.5 | 171527 | 3.79 MB | 11.3 |
| 6 | MLP | OK | 1.0000 | 1.0000 | 0.9955 | 0.741679 | 0.51 | 1.0000 | 0.9945 | N/A | 0.9992 | 1.02 | 243.8 | 632.1 | 1672462 | 128.6 kB | 36.6 |
| 7 | DT | OK | 1.0000 | 0.9997 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | N/A | 1.0000 | 1.02 | 71.2 | 253.8 | 17861895 | 3.7 kB | 2.9 |
| 8 | KNN | OK | 0.9999 | 0.9992 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | N/A | 1.0000 | 7.62 | 18998.6 | 22760.2 | 888 | 75.77 MB | 0.5 |
| 9 | LR | OK | 0.9993 | 0.9963 | 0.0003 | 0.999979 | 0.51 | 0.0017 | 0.0000 | N/A | 0.9901 | 15.76 | 244.7 | 674.3 | 3642238 | 3.6 kB | 2.4 |

## GLOBAL

| rank | model | status | PR-AUC | ROC-AUC | DR@FP/h<=1 | thr@FP/h<=1 | FP/h@FP/h<=1 | DR port_scan | DR syn_flood | DR udp_flood | DR@0.5 | FP/h@0.5 | lat med us | lat p99 us | flows/s | size | fit s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | XGB | OK | 1.0000 | 1.0000 | 0.9998 | 0.805388 | 0.51 | 1.0000 | 0.9999 | 0.4118 LOW_N | 0.9998 | 1.52 | 149.0 | 1123.6 | 1014868 | 154.3 kB | 19.1 |
| 2 | LGBM | OK | 1.0000 | 1.0000 | 0.9998 | 0.767291 | 0.51 | 1.0000 | 0.9999 | 0.5294 LOW_N | 0.9998 | 1.02 | 411.3 | 1029.6 | 608095 | 352.7 kB | 6.5 |
| 3 | CAT | OK | 1.0000 | 1.0000 | 0.9998 | 0.631374 | 0.51 | 1.0000 | 0.9999 | 0.4118 LOW_N | 0.9998 | 1.02 | 118.9 | 316.7 | 792290 | 1.12 MB | 55.0 |
| 4 | MLP | OK | 1.0000 | 1.0000 | 0.9996 | 0.803089 | 0.51 | 1.0000 | 0.9997 | 0.4118 LOW_N | 0.9997 | 1.52 | 238.1 | 631.9 | 260721 | 128.1 kB | 33.4 |
| 5 | ET | OK | 1.0000 | 1.0000 | 0.9998 | 0.540000 | 0.51 | 1.0000 | 0.9999 | 0.5882 LOW_N | 0.9998 | 1.52 | 4731.0 | 10189.9 | 121311 | 15.00 MB | 47.4 |
| 6 | RF | OK | 1.0000 | 1.0000 | 0.9998 | 0.510000 | 0.51 | 1.0000 | 0.9999 | 0.5294 LOW_N | 0.9998 | 1.02 | 4368.4 | 7988.2 | 170382 | 7.70 MB | 36.2 |
| 7 | KNN | OK | 0.9998 | 0.9997 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | 0.0000 LOW_N | 0.9991 | 19.82 | 45539.2 | 66633.7 | 322 | 185.77 MB | 1.1 |
| 8 | DT | OK | 0.9998 | 0.9997 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | 0.0000 LOW_N | 0.9997 | 6.10 | 70.7 | 226.4 | 13896320 | 19.4 kB | 13.7 |
| 9 | LR | OK | 0.9988 | 0.9975 | 0.0000 | inf | 0.00 | 0.0000 | 0.0000 | 0.0000 LOW_N | 0.9917 | 151.96 | 325.5 | 1506.5 | 2662291 | 3.6 kB | 8.4 |

## Small-sample / missing-family flags (val, per group)

| group | attack_family | n_val | flag |
|---|---|---|---|
| G1 | udp_flood | 17 | LOW_N |
| G2 | udp_flood | 0 | N/A |
| GLOBAL | udp_flood | 17 | LOW_N |

## Caveats

- G1 udp_flood: LOW_N (n=17 val attack rows); its DR rests on < 50 rows.
- G2 udp_flood: N/A (n=0 val attack rows); its DR is not defined.
- GLOBAL udp_flood: LOW_N (n=17 val attack rows); its DR rests on < 50 rows.
- G1 LR: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- G1 DT: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- G1 KNN: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- G2 DT: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- G2 KNN: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- GLOBAL LR: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- GLOBAL DT: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- GLOBAL KNN: at FP/h<=1 the budget met only by flagging nothing (threshold inf, DR 0)
- GEN val holds benign rows only (no attacks), so GEN contributes FPs but no detections to GLOBAL.
- kNN scores take only k+1 = 6 distinct values (k = 5), so its operating points are coarse.
