# LG-IDS V2 Phase 4 -- continual learning loop (val only) -- summary

Runs: step 31 `20261122T132156Z`, 32 `20261122T132232Z`, 33 `20261122T132243Z`, 34 (see results/phase4/34/). Pre-registration `docs/V2_PREREG_PHASE4.md` sha256 `63fe91834e4a7e45c5b237fec5af9e5283a537f82dd942e72c155204154810ac`, config `config/v2_phase4.json` sha256 `1c2ab2cb232a906d6d532a2d2e2076c1be4bbd22bd1199a5f3117f44a59e3555`. The test split was never read. Nothing was approved or promoted.

## Split

- val-A 81,427 flows (labelled live period), val-B 76,131 flows (judging set); val-B support {'benign': 14973, 'syn_flood': 53297, 'udp_flood': 2, 'port_scan': 7859}; rare for the gate (< 50): ['udp_flood']

## Loop

- runtime on val-A: parity exact (81,427 / 81,427 classes, max |dp| 0.0e+00, features identical 81,427)
- queue `20261122T132156Z`: 58,405 items (alerts 57,193, random 1,212)
- queue `20261122T132156Z__no_random`: 57,193 items (alerts 57,193, random 0)
- batch `20261122T132232Z__primary`: 58,405 labels, accuracy vs truth 1.0000, validator **VALID** 
- batch `20261122T132232Z__noise_0.02`: 58,405 labels, accuracy vs truth 0.9807, validator **VALID** 
- batch `20261122T132232Z__budget_1000`: 1,000 labels, accuracy vs truth 1.0000, validator **VALID** 
- batch `20261122T132232Z__budget_10000`: 10,000 labels, accuracy vs truth 1.0000, validator **VALID** 
- batch `20261122T132232Z__no_random`: 57,193 labels, accuracy vs truth 1.0000, validator **VALID** 
- batch `20261122T132232Z__P1`: 58,405 labels, accuracy vs truth 0.9198, validator **QUARANTINED** ['c_confident_disagreement']
- batch `20261122T132232Z__P2`: 58,405 labels, accuracy vs truth 0.8233, validator **QUARANTINED** ['c_confident_disagreement']

## Headline per arm (val-B, 5-seed mean [95 % t-CI])

| system | non-rare macro-F1 | diff vs R0 | FA / h | recall benign | recall syn_flood | recall port_scan | retrain s | peak RSS MB | gate PASS / seeds |
|---|---|---|---|---|---|---|---|---|---|
| R0 no retrain (deployed) | 0.99666 [0.99571, 0.99760] | - | 0.000 [0.000, 0.000] | 1.0000 [1.0000, 1.0000] | 0.9975 [0.9967, 0.9982] | 0.9988 [0.9987, 0.9989] | 0.00 [0.00, 0.00] | - | deployed |
| v2_1 ROUTED (reference) | 0.99600 [0.99590, 0.99610] | -0.00065 [-0.00167, +0.00037] | 1.078 [1.078, 1.078] | 0.9999 [0.9999, 0.9999] | 0.9970 [0.9969, 0.9970] | 0.9989 [0.9989, 0.9989] | - | - | 0/5 |
| R1 full retrain | 0.99968 [0.99966, 0.99971] | +0.00303 [+0.00206, +0.00399] | 1.941 [1.342, 2.540] | 0.9999 [0.9998, 0.9999] | 0.9998 [0.9998, 0.9998] | 0.9995 [0.9993, 0.9996] | 16.07 [7.15, 24.99] | 1788 [1767, 1810] | 0/5 |
| R2 warm start + replay | 0.99975 [0.99964, 0.99987] | +0.00310 [+0.00222, +0.00398] | 0.431 [-0.302, 1.165] | 1.0000 [0.9999, 1.0000] | 0.9998 [0.9997, 0.9998] | 0.9996 [0.9994, 0.9999] | 2.52 [1.38, 3.66] | 1289 [1271, 1307] | 3/5 |
| R3 warm start, labels only | 0.99965 [0.99950, 0.99980] | +0.00299 [+0.00210, +0.00388] | 1.510 [-0.017, 3.037] | 0.9999 [0.9998, 1.0000] | 0.9998 [0.9997, 1.0000] | 0.9993 [0.9987, 0.9999] | 0.96 [0.60, 1.32] | 1104 [1087, 1121] | 1/5 |
| S2-GLOBAL (G1 labels) | 0.99972 [0.99970, 0.99975] | +0.00307 [+0.00210, +0.00404] | 0.431 [-0.302, 1.165] | 1.0000 [0.9999, 1.0000] | 0.9998 [0.9998, 0.9998] | 0.9995 [0.9995, 0.9995] | 13.85 [10.24, 17.45] | 1760 [1743, 1777] | 3/5 |
| S2-G1 (ROUTED) | 0.99967 [0.99965, 0.99969] | +0.00301 [+0.00206, +0.00396] | 1.294 [0.695, 1.893] | 0.9999 [0.9999, 1.0000] | 0.9998 [0.9998, 0.9998] | 0.9994 [0.9994, 0.9994] | 14.50 [11.20, 17.80] | 1736 [1719, 1752] | 0/5 |
| R2 on P1 | 0.82797 [0.72870, 0.92724] | -0.16868 [-0.26763, -0.06974] | 5762.588 [4461.366, 7063.810] | 0.6431 [0.5626, 0.7237] | 0.9835 [0.9466, 1.0203] | 0.7774 [0.4348, 1.1201] | 1.09 [0.91, 1.27] | 1327 [1312, 1341] | 0/5 |
| R2 on P2 | 0.55626 [0.50812, 0.60440] | -0.44040 [-0.48909, -0.39170] | 636.525 [-1130.751, 2403.801] | 0.9606 [0.8511, 1.0700] | 0.9316 [0.8219, 1.0413] | 0.0002 [-0.0002, 0.0005] | 0.95 [0.81, 1.08] | 1327 [1312, 1341] | 0/5 |
| R2 on budget_1000 | 0.99686 [0.99572, 0.99800] | +0.00020 [-0.00016, +0.00057] | 0.216 [-0.383, 0.815] | 1.0000 [0.9999, 1.0000] | 0.9976 [0.9967, 0.9985] | 0.9988 [0.9987, 0.9989] | 0.96 [0.63, 1.29] | 1264 [1251, 1276] | 4/5 |
| R2 on budget_10000 | 0.99921 [0.99917, 0.99925] | +0.00255 [+0.00163, +0.00347] | 0.000 [0.000, 0.000] | 1.0000 [1.0000, 1.0000] | 0.9994 [0.9994, 0.9995] | 0.9987 [0.9987, 0.9987] | 1.79 [0.14, 3.45] | 1274 [1264, 1285] | 5/5 |
| R2 on no_random | 0.99975 [0.99960, 0.99989] | +0.00309 [+0.00217, +0.00401] | 0.216 [-0.383, 0.815] | 1.0000 [0.9999, 1.0000] | 0.9998 [0.9997, 0.9998] | 0.9996 [0.9990, 1.0003] | 2.46 [1.54, 3.39] | 1322 [1311, 1332] | 4/5 |
| R2 on noise_0.02 | 0.84182 [0.73554, 0.94810] | -0.15483 [-0.26136, -0.04830] | 6250.713 [1111.581, 11389.845] | 0.6129 [0.2947, 0.9312] | 0.9637 [0.8728, 1.0546] | 0.9294 [0.8603, 0.9985] | 1.30 [0.87, 1.73] | 1294 [1278, 1310] | 0/5 |

## Amendment 2 section 4 verdict

**DOES_NOT_WIN** (WINS iff [forgetting lower (CI excludes 0) OR (equal within 0.002 AND >= 2x lower retrain time)] AND affected-group macro-F1 not worse by more than 0.005).

- forgetting (non-rare macro-F1 drop on the unlabelled groups ['G2', 'GEN']): S2-GLOBAL +0.00006 [-0.00005, +0.00016], S2-G1 +0.00000 [+0.00000, +0.00000]; difference -0.00006 [-0.00016, +0.00005]
- retrain time S2-G1 14.50 s vs S2-GLOBAL 13.85 s (global / per-group = 0.96, needs >= 2.0)
- affected group G1: S2-G1 0.99959 [0.99956, 0.99961], S2-GLOBAL 0.99963 [0.99962, 0.99965]
- **In the per-group arm, the other groups' specialists are unchanged, so their forgetting is zero by construction. The real question of Amendment 2 §4 is whether retraining GLOBAL causes forgetting on the other groups. If it doesn't, per-group can win only on cost.**
- kill rule (Amendment 2 section 5): Phase 4 test does NOT favour per-group (Amendment 2 section 5: no Stage 3 routing claim)

## Poisoning

- P1 (syn_flood -> benign, 4,686 of 46,863 labels): validator QUARANTINED ['c_confident_disagreement']; R2 on it passes the gate in 0/5 seeds -> **CAUGHT_BY_VALIDATOR**
- P2 (port_scan -> benign, 10,320 of 10,320 labels): validator QUARANTINED ['c_confident_disagreement']; R2 on it passes the gate in 0/5 seeds -> **CAUGHT_BY_VALIDATOR**

## Feedback bias

- val-A attack flows the deployed model did not alert on: 24 {'syn_flood': 18, 'udp_flood': 6}; labelled with the random 5 %: 1; without: 0
- syn_flood: R2 val-B recall with random 0.9998 [0.9997, 0.9998], alerts only 0.9998 [0.9997, 0.9998]; on R0's val-B misses: with 0.3038 [0.1064, 0.5013], without 0.2859 [0.0532, 0.5187]
- udp_flood: R2 val-B recall with random 0.5000 [0.5000, 0.5000], alerts only 0.4000 [0.1224, 0.6776]; on R0's val-B misses: with 0.0000 [0.0000, 0.0000], without 0.0000 [0.0000, 0.0000]

## Registry

- CANDIDATE `GLOBAL__none__P4_R2__s0__20261122T132243Z` (R2)
- CANDIDATE `GLOBAL__none__P4_R3__s0__20261122T132243Z` (R3)
- REJECTED R1 seed 0: (iii) FA/h rise 2.157 > 0.5
- REJECTED R1 seed 1: (iii) FA/h rise 2.157 > 0.5
- REJECTED R1 seed 2: (iii) FA/h rise 2.157 > 0.5
- REJECTED R1 seed 3: (iii) FA/h rise 1.078 > 0.5
- REJECTED R1 seed 4: (iii) FA/h rise 2.157 > 0.5
- REJECTED R2 seed 2: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2 seed 4: (iii) FA/h rise 1.078 > 0.5
- REJECTED R3 seed 1: (iii) FA/h rise 1.078 > 0.5
- REJECTED R3 seed 2: (iii) FA/h rise 3.235 > 0.5
- REJECTED R3 seed 3: (iii) FA/h rise 1.078 > 0.5
- REJECTED R3 seed 4: (iii) FA/h rise 2.157 > 0.5
- REJECTED S2_GLOBAL seed 0: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_GLOBAL seed 1: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC seed 0: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC seed 1: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC seed 2: (iii) FA/h rise 1.078 > 0.5
- REJECTED S2_SPEC seed 3: (iii) FA/h rise 2.157 > 0.5
- REJECTED S2_SPEC seed 4: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2__P1 seed 0: (i) recall drop > 0.01 on class(es) {0: 0.44694, 3: 0.10637}; (ii) non-rare macro-F1 drop 0.15553 > 0.002; (iii) FA/h rise 7217.256 > 0.5
- REJECTED R2__P1 seed 1: (i) recall drop > 0.01 on class(es) {0: 0.29513, 1: 0.06807, 3: 0.09492}; (ii) non-rare macro-F1 drop 0.13995 > 0.002; (iii) FA/h rise 4765.848 > 0.5
- REJECTED R2__P1 seed 2: (i) recall drop > 0.01 on class(es) {0: 0.3137, 3: 0.71498}; (ii) non-rare macro-F1 drop 0.30826 > 0.002; (iii) FA/h rise 5065.668 > 0.5
- REJECTED R2__P1 seed 3: (i) recall drop > 0.01 on class(es) {0: 0.40266, 3: 0.09543}; (ii) non-rare macro-F1 drop 0.12846 > 0.002; (iii) FA/h rise 6502.217 > 0.5
- REJECTED R2__P1 seed 4: (i) recall drop > 0.01 on class(es) {0: 0.32585, 3: 0.09505}; (ii) non-rare macro-F1 drop 0.11122 > 0.002; (iii) FA/h rise 5261.953 > 0.5
- REJECTED R2__P2 seed 0: (i) recall drop > 0.01 on class(es) {0: 0.19709, 3: 0.99873}; (ii) non-rare macro-F1 drop 0.44116 > 0.002; (iii) FA/h rise 3182.624 > 0.5
- REJECTED R2__P2 seed 1: (i) recall drop > 0.01 on class(es) {1: 0.16369, 3: 0.99809}; (ii) non-rare macro-F1 drop 0.48002 > 0.002
- REJECTED R2__P2 seed 2: (i) recall drop > 0.01 on class(es) {3: 0.99885}; (ii) non-rare macro-F1 drop 0.40088 > 0.002
- REJECTED R2__P2 seed 3: (i) recall drop > 0.01 on class(es) {3: 0.99873}; (ii) non-rare macro-F1 drop 0.40112 > 0.002
- REJECTED R2__P2 seed 4: (i) recall drop > 0.01 on class(es) {1: 0.16243, 3: 0.99873}; (ii) non-rare macro-F1 drop 0.47882 > 0.002
- REJECTED R2__budget_1000 seed 3: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2__no_random seed 2: (iii) FA/h rise 1.078 > 0.5
- REJECTED R2__noise_0.02 seed 0: (i) recall drop > 0.01 on class(es) {0: 0.3682, 3: 0.09518}; (ii) non-rare macro-F1 drop 0.11303 > 0.002; (iii) FA/h rise 5945.716 > 0.5
- REJECTED R2__noise_0.02 seed 1: (i) recall drop > 0.01 on class(es) {0: 0.2769, 1: 0.16575, 3: 0.02036}; (ii) non-rare macro-F1 drop 0.21950 > 0.002; (iii) FA/h rise 4471.420 > 0.5
- REJECTED R2__noise_0.02 seed 2: (i) recall drop > 0.01 on class(es) {0: 0.76571}; (ii) non-rare macro-F1 drop 0.25653 > 0.002; (iii) FA/h rise 12364.889 > 0.5
- REJECTED R2__noise_0.02 seed 3: (i) recall drop > 0.01 on class(es) {0: 0.06766, 3: 0.10663}; (ii) non-rare macro-F1 drop 0.04053 > 0.002; (iii) FA/h rise 1092.510 > 0.5
- REJECTED R2__noise_0.02 seed 4: (i) recall drop > 0.01 on class(es) {0: 0.45696, 3: 0.12483}; (ii) non-rare macro-F1 drop 0.14457 > 0.002; (iii) FA/h rise 7379.029 > 0.5

## What Phase 4 shows, and what needs real operators

- Shown (val, simulated operator): the loop runs end to end with the Pi runtime unchanged (exact parity); labels are signed, append-only and refused when tampered; the validator and the gate behave as pre-registered on clean, noisy, budget-limited and poisoned batches; retrained models enter the registry only as signed candidates; the cost and forgetting of each retraining strategy on this data.
- Not shown: real operator accuracy, latency, fatigue or bias (labels here are ground truth, uniform noise or a designed flip); label budgets in a real SOC; drift beyond the val window (val-B is the second half of the same captures, and val was used for Phase 2 selection and the deployed temperature); a poisoning attacker who knows the validator's 0.99 / 5 % rule and stays under it; any test-split number.

## Figures

- `figures/split_composition.png`
- `figures/recall_per_arm.png`
- `figures/forgetting.png`
- `figures/time_vs_macro_f1.png`
- `figures/gate_outcomes.png`
- `figures/poisoning.png`
- `figures/feedback_bias.png`
- `figures/loop_diagram.png`
