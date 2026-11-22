# Step 34 -- val-B evaluation, regression gate, Amendment 2 section 4, poisoning, feedback bias -- PASS

- retrain run `20261122T132243Z`, labels run `20261122T132232Z`, queue run `20261122T132156Z`; val-B 76,131 flows, non-rare ['benign', 'syn_flood', 'port_scan']

## Per arm on val-B (5-seed mean [95 % t-CI]; paired diff vs R0)

| system | macro-F1 non-rare | diff vs R0 | FA / h | recall benign | recall syn_flood | recall udp_flood | recall port_scan | fit s | gate PASS |
|---|---|---|---|---|---|---|---|---|---|
| R0 | 0.99666 [0.99571, 0.99760] | +0.00000 [+0.00000, +0.00000] | 0.000 [0.000, 0.000] | 1.0000 [1.0000, 1.0000] | 0.9975 [0.9967, 0.9982] | 0.6000 [0.3224, 0.8776] | 0.9988 [0.9987, 0.9989] | 0.00 [0.00, 0.00] | (deployed) |
| ROUTED_v21 | 0.99600 [0.99590, 0.99610] | -0.00065 [-0.00167, +0.00037] | 1.078 [1.078, 1.078] | 0.9999 [0.9999, 0.9999] | 0.9970 [0.9969, 0.9970] | 0.4000 [0.1224, 0.6776] | 0.9989 [0.9989, 0.9989] | - | 0/5 |
| R1 | 0.99968 [0.99966, 0.99971] | +0.00303 [+0.00206, +0.00399] | 1.941 [1.342, 2.540] | 0.9999 [0.9998, 0.9999] | 0.9998 [0.9998, 0.9998] | 0.2000 [-0.1400, 0.5400] | 0.9995 [0.9993, 0.9996] | 16.07 [7.15, 24.99] | 0/5 |
| R2 | 0.99975 [0.99964, 0.99987] | +0.00310 [+0.00222, +0.00398] | 0.431 [-0.302, 1.165] | 1.0000 [0.9999, 1.0000] | 0.9998 [0.9997, 0.9998] | 0.5000 [0.5000, 0.5000] | 0.9996 [0.9994, 0.9999] | 2.52 [1.38, 3.66] | 3/5 |
| R3 | 0.99965 [0.99950, 0.99980] | +0.00299 [+0.00210, +0.00388] | 1.510 [-0.017, 3.037] | 0.9999 [0.9998, 1.0000] | 0.9998 [0.9997, 1.0000] | 0.1000 [-0.1776, 0.3776] | 0.9993 [0.9987, 0.9999] | 0.96 [0.60, 1.32] | 1/5 |
| S2_GLOBAL | 0.99972 [0.99970, 0.99975] | +0.00307 [+0.00210, +0.00404] | 0.431 [-0.302, 1.165] | 1.0000 [0.9999, 1.0000] | 0.9998 [0.9998, 0.9998] | 0.2000 [-0.1400, 0.5400] | 0.9995 [0.9995, 0.9995] | 13.85 [10.24, 17.45] | 3/5 |
| S2_SPEC | 0.99967 [0.99965, 0.99969] | +0.00301 [+0.00206, +0.00396] | 1.294 [0.695, 1.893] | 0.9999 [0.9999, 1.0000] | 0.9998 [0.9998, 0.9998] | 0.2000 [-0.1400, 0.5400] | 0.9994 [0.9994, 0.9994] | 14.50 [11.20, 17.80] | 0/5 |
| R2__P1 | 0.82797 [0.72870, 0.92724] | -0.16868 [-0.26763, -0.06974] | 5762.588 [4461.366, 7063.810] | 0.6431 [0.5626, 0.7237] | 0.9835 [0.9466, 1.0203] | 0.0000 [0.0000, 0.0000] | 0.7774 [0.4348, 1.1201] | 1.09 [0.91, 1.27] | 0/5 |
| R2__P2 | 0.55626 [0.50812, 0.60440] | -0.44040 [-0.48909, -0.39170] | 636.525 [-1130.751, 2403.801] | 0.9606 [0.8511, 1.0700] | 0.9316 [0.8219, 1.0413] | 0.4000 [0.1224, 0.6776] | 0.0002 [-0.0002, 0.0005] | 0.95 [0.81, 1.08] | 0/5 |
| R2__budget_1000 | 0.99686 [0.99572, 0.99800] | +0.00020 [-0.00016, +0.00057] | 0.216 [-0.383, 0.815] | 1.0000 [0.9999, 1.0000] | 0.9976 [0.9967, 0.9985] | 0.6000 [0.3224, 0.8776] | 0.9988 [0.9987, 0.9989] | 0.96 [0.63, 1.29] | 4/5 |
| R2__budget_10000 | 0.99921 [0.99917, 0.99925] | +0.00255 [+0.00163, +0.00347] | 0.000 [0.000, 0.000] | 1.0000 [1.0000, 1.0000] | 0.9994 [0.9994, 0.9995] | 0.7000 [0.3600, 1.0400] | 0.9987 [0.9987, 0.9987] | 1.79 [0.14, 3.45] | 5/5 |
| R2__no_random | 0.99975 [0.99960, 0.99989] | +0.00309 [+0.00217, +0.00401] | 0.216 [-0.383, 0.815] | 1.0000 [0.9999, 1.0000] | 0.9998 [0.9997, 0.9998] | 0.4000 [0.1224, 0.6776] | 0.9996 [0.9990, 1.0003] | 2.46 [1.54, 3.39] | 4/5 |
| R2__noise_0.02 | 0.84182 [0.73554, 0.94810] | -0.15483 [-0.26136, -0.04830] | 6250.713 [1111.581, 11389.845] | 0.6129 [0.2947, 0.9312] | 0.9637 [0.8728, 1.0546] | 0.1000 [-0.1776, 0.3776] | 0.9294 [0.8603, 0.9985] | 1.30 [0.87, 1.73] | 0/5 |

## Amendment 2 section 4 verdict

**DOES_NOT_WIN** -- WINS iff [forgetting lower (CI excludes 0) OR (equal within 0.002 AND >= 2x lower retrain time)] AND affected-group macro-F1 not worse by more than 0.005

- forgetting on the groups without labels ['G2', 'GEN'] (non-rare macro-F1 drop): S2_SPEC +0.00000 [+0.00000, +0.00000], S2_GLOBAL +0.00006 [-0.00005, +0.00016]; difference (per-group - global) -0.00006 [-0.00016, +0.00005]; lower: False, equal within 0.002: True
- retrain time: S2_SPEC 14.50 s, S2_GLOBAL 13.85 s (ratio 0.96; >= 2.0 needed): False
- affected group G1 non-rare macro-F1: S2_SPEC 0.99959 [0.99956, 0.99961], S2_GLOBAL 0.99963 [0.99962, 0.99965]; diff -0.00005 [-0.00008, -0.00002] (>= -0.005): True
- note: In the per-group arm, the other groups' specialists are unchanged, so their forgetting is zero by construction. The real question of Amendment 2 §4 is whether retraining GLOBAL causes forgetting on the other groups. If it doesn't, per-group can win only on cost. (proof: S2_SPEC predictions on the other groups' rows == v2_1 ROUTED: True)
- kill rule: Phase 4 test does NOT favour per-group (Amendment 2 section 5: no Stage 3 routing claim)

## Poisoning

| batch | poison | validator | gate if used (PASS / seeds) | verdict |
|---|---|---|---|---|
| P1 | {'target_class': 'syn_flood', 'flipped_to': 'benign', 'flip_frac': 0.1, 'n_flipped': 4686, 'n_target': 46863} | QUARANTINED ['c_confident_disagreement'] | 0/5 | **CAUGHT_BY_VALIDATOR** |
| P2 | {'target_class': 'port_scan', 'flipped_to': 'benign', 'flip_frac': 1.0, 'n_flipped': 10320, 'n_target': 10320} | QUARANTINED ['c_confident_disagreement'] | 0/5 | **CAUGHT_BY_VALIDATOR** |

## Feedback bias

- val-A missed attack flows: 24 {'syn_flood': 18, 'udp_flood': 6}; labelled with the random sample 1, without 0
- syn_flood: val-B recall R0 0.9975 [0.9967, 0.9982], R2 with random 0.9998 [0.9997, 0.9998], without 0.9998 [0.9997, 0.9998]; on R0's val-B misses ([17, 14, 11, 13, 20]): with 0.3038 [0.1064, 0.5013], without 0.2859 [0.0532, 0.5187]
- udp_flood: val-B recall R0 0.6000 [0.3224, 0.8776], R2 with random 0.5000 [0.5000, 0.5000], without 0.4000 [0.1224, 0.6776]; on R0's val-B misses ([0, 1, 1, 1, 1]): with 0.0000 [0.0000, 0.0000], without 0.0000 [0.0000, 0.0000]

## Registry

- CANDIDATE `GLOBAL__none__P4_R2__s0__20261122T132243Z` (R2, global, serves ['GEN'])
- CANDIDATE `GLOBAL__none__P4_R3__s0__20261122T132243Z` (R3, global, serves ['GEN'])
- REJECTED R1 s0: (iii) FA/h rise 2.157 > 0.5
- REJECTED R1 s1: (iii) FA/h rise 2.157 > 0.5
- REJECTED R1 s2: (iii) FA/h rise 2.157 > 0.5
- REJECTED R1 s3: (iii) FA/h rise 1.078 > 0.5
- REJECTED R1 s4: (iii) FA/h rise 2.157 > 0.5
- REJECTED R2 s2: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2 s4: (iii) FA/h rise 1.078 > 0.5
- REJECTED R3 s1: (iii) FA/h rise 1.078 > 0.5
- REJECTED R3 s2: (iii) FA/h rise 3.235 > 0.5
- REJECTED R3 s3: (iii) FA/h rise 1.078 > 0.5
- REJECTED R3 s4: (iii) FA/h rise 2.157 > 0.5
- REJECTED S2_GLOBAL s0: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_GLOBAL s1: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC s0: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC s1: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC s2: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC s3: (iii) FA/h rise 2.157 > 0.5
- REJECTED S2_SPEC s4: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2__P1 s0: (i) recall drop > 0.01 on class(es) {0: 0.44694, 3: 0.10637}; (ii) non-rare macro-F1 drop 0.15553 > 0.002; (iii) FA/h rise 7217.256 > 0.5
- REJECTED R2__P1 s1: (i) recall drop > 0.01 on class(es) {0: 0.29513, 1: 0.06807, 3: 0.09492}; (ii) non-rare macro-F1 drop 0.13995 > 0.002; (iii) FA/h rise 4765.848 > 0.5
- REJECTED R2__P1 s2: (i) recall drop > 0.01 on class(es) {0: 0.3137, 3: 0.71498}; (ii) non-rare macro-F1 drop 0.30826 > 0.002; (iii) FA/h rise 5065.668 > 0.5
- REJECTED R2__P1 s3: (i) recall drop > 0.01 on class(es) {0: 0.40266, 3: 0.09543}; (ii) non-rare macro-F1 drop 0.12846 > 0.002; (iii) FA/h rise 6502.217 > 0.5
- REJECTED R2__P1 s4: (i) recall drop > 0.01 on class(es) {0: 0.32585, 3: 0.09505}; (ii) non-rare macro-F1 drop 0.11122 > 0.002; (iii) FA/h rise 5261.953 > 0.5
- REJECTED R2__P2 s0: (i) recall drop > 0.01 on class(es) {0: 0.19709, 3: 0.99873}; (ii) non-rare macro-F1 drop 0.44116 > 0.002; (iii) FA/h rise 3182.624 > 0.5
- REJECTED R2__P2 s1: (i) recall drop > 0.01 on class(es) {1: 0.16369, 3: 0.99809}; (ii) non-rare macro-F1 drop 0.48002 > 0.002
- REJECTED R2__P2 s2: (i) recall drop > 0.01 on class(es) {3: 0.99885}; (ii) non-rare macro-F1 drop 0.40088 > 0.002
- REJECTED R2__P2 s3: (i) recall drop > 0.01 on class(es) {3: 0.99873}; (ii) non-rare macro-F1 drop 0.40112 > 0.002
- REJECTED R2__P2 s4: (i) recall drop > 0.01 on class(es) {1: 0.16243, 3: 0.99873}; (ii) non-rare macro-F1 drop 0.47882 > 0.002
- REJECTED R2__budget_1000 s3: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2__no_random s2: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2__noise_0.02 s0: (i) recall drop > 0.01 on class(es) {0: 0.3682, 3: 0.09518}; (ii) non-rare macro-F1 drop 0.11303 > 0.002; (iii) FA/h rise 5945.716 > 0.5
- REJECTED R2__noise_0.02 s1: (i) recall drop > 0.01 on class(es) {0: 0.2769, 1: 0.16575, 3: 0.02036}; (ii) non-rare macro-F1 drop 0.21950 > 0.002; (iii) FA/h rise 4471.420 > 0.5
- REJECTED R2__noise_0.02 s2: (i) recall drop > 0.01 on class(es) {0: 0.76571}; (ii) non-rare macro-F1 drop 0.25653 > 0.002; (iii) FA/h rise 12364.889 > 0.5
- REJECTED R2__noise_0.02 s3: (i) recall drop > 0.01 on class(es) {0: 0.06766, 3: 0.10663}; (ii) non-rare macro-F1 drop 0.04053 > 0.002; (iii) FA/h rise 1092.510 > 0.5
- REJECTED R2__noise_0.02 s4: (i) recall drop > 0.01 on class(es) {0: 0.45696, 3: 0.12483}; (ii) non-rare macro-F1 drop 0.14457 > 0.002; (iii) FA/h rise 7379.029 > 0.5

## Checks

- PASS  split parquet sha256 == step 31 manifest  
- PASS  every val row has a split part  157,558 / 157,558
- PASS  step 22 run dir is the run 33 used  20261121T075821Z
- PASS  S2_SPEC predictions on the other groups' val-B rows == v2_1 ROUTED (zero forgetting by construction)  31,381 rows x 5 seeds
- PASS  GLOBAL__none__P4_R2__s0__20261122T132243Z: registered CANDIDATE; deployment load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/GLOBAL__none__P4_R2__s0__20261122T132243Z
- PASS  GLOBAL__none__P4_R3__s0__20261122T132243Z: registered CANDIDATE; deployment load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/GLOBAL__none__P4_R3__s0__20261122T132243Z
- PASS  promoted entry unchanged (files + state log sha256, state promoted)  GLOBAL__none__s0__20261121T075821Z: state promoted
