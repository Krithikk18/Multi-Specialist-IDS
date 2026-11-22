# LG-IDS V2 Phase 5B -- orientation-free host / host-pair context features + TreeSHAP perturbation check

Runs: step 39 `20261122T185056Z`, step 40 `20261122T185128Z`, step 41 `20261122T185605Z`, step 42 `20261122T185630Z`, step 43 `20261122T185706Z`, step 44 `20261122T185712Z`. Offline, train + val only; nothing registered, runtime untouched. Pre-registration `docs/V2_PREREG_PHASE5B.md`. D163 holds: no routing-novelty claim; the per-group model of normal below is report-only.

## Verdicts

- **Non-inferiority (GLOBAL_CTX vs GLOBAL): PASS** -- non-rare macro-F1 difference +0.00187 [+0.00146, +0.00212] (needs lower bound > -0.002); FA-count differences per seed [-1.0, -2.0, -1.0, -1.0, -3.0] (median -1.0, needs <= 2). Warm-up flows excluded: PASS.
- **H-C1 (orientation robustness, TCP flows): HOLDS** -- flip agreement GLOBAL_CTX - GLOBAL: TCP flows +0.041703 [+0.029295, +0.048830], TCP benign +0.028408 [+0.025849, +0.030915] (non-TCP flows are not swapped: agreement 1 by construction, not evidence).
- **H-C2 (fingerprint independence, port_scan): HOLDS** -- Δ_flow -0.0111, Δ_ctx -0.0000, Δ_ctx - Δ_flow +0.0111 [+0.0098, +0.0138].
- **H-C3 (zero-day with context; primary CTX_TAIL_GLOBAL, D165): DOES_NOT_HOLD** -- FA/h CI upper bound 171.448 > reference 18.743; miss-recall +0.8536 [+0.8046, +0.9000] over 10 eligible pairs; FA/h 163.972 [155.471, 171.448] vs Phase 5A GLOBAL_NORMAL 18.743. Same rule applied to the report-only arms (never the verdict): CTX_IF_GLOBAL DOES_NOT_HOLD (miss-recall +0.8664 [+0.8023, +0.9188], FA/h 19.46 [12.39, 25.60]); CTX_TAIL_PER_GROUP DOES_NOT_HOLD (miss-recall +0.8994 [+0.8304, +0.9651], FA/h 173.80 [172.27, 175.34]); FLOWCTX_TAIL_GLOBAL DOES_NOT_HOLD (miss-recall +0.8376 [+0.7822, +0.8906], FA/h 132.73 [126.08, 139.60]).
- **Part B (TreeSHAP perturbation)**: GLOBAL: benign NOT_FAITHFUL, syn_flood FAITHFUL, udp_flood FAITHFUL, port_scan FAITHFUL; GLOBAL_CTX: benign NOT_FAITHFUL, syn_flood FAITHFUL, udp_flood FAITHFUL, port_scan FAITHFUL.

## Dataset v2_2_context

- train: 636,193 rows; evictions host 0, pair 0; warm-up 4,055 (0.0064)
- val: 157,558 rows; evictions host 0, pair 0; warm-up 16,777 (0.1065)
- real-data reference check: 10,000-flow val slice of segment ['benign_night', 'val']: streaming == naive **True** (0 mismatches)
- val compute cost (dev machine, pure Python): 19.1 us/flow; peak state per segment 492 hosts, 723 pairs, 187,633 window events

## Stage 1 arms (val, 5 seeds)

| arm | recall benign | recall syn_flood | recall udp_flood | recall port_scan | macro-F1 non-rare | FA per seed | FA/h |
|---|---|---|---|---|---|---|---|
| GLOBAL | 0.9999 | 0.9980 | 0.6000 | 0.9992 | 0.99779 | [2, 2, 2, 1, 3] | 1.02 |
| GLOBAL_CTX | 1.0000 | 0.9995 | 0.4118 | 1.0000 | 0.99966 | [1, 0, 1, 0, 0] | 0.20 |
| CTX_ONLY | 0.9999 | 0.9725 | 0.1647 | 0.9970 | 0.97227 | [4, 7, 4, 6, 3] | 2.46 |
| GLOBAL_NOFP | 0.9999 | 0.9979 | 0.5412 | 0.9881 | 0.99539 | [3, 1, 3, 2, 2] | 1.13 |
| GLOBAL_CTX_NOFP | 1.0000 | 0.9774 | 0.4118 | 1.0000 | 0.97685 | [0, 0, 0, 0, 0] | 0.00 |

Differences vs GLOBAL (mean [95 % bootstrap CI over seeds]): GLOBAL_CTX: macro-F1 +0.00187 [+0.00146, +0.00212], FA count -1.6 [-2.4, -1.0]; CTX_ONLY: macro-F1 -0.02552 [-0.02935, -0.02314], FA count +2.8 [+1.2, +4.4]; GLOBAL_NOFP: macro-F1 -0.00240 [-0.00292, -0.00190], FA count +0.2 [-0.6, +1.0]; GLOBAL_CTX_NOFP: macro-F1 -0.02094 [-0.02166, -0.02038], FA count -2.0 [-2.6, -1.4]

## Orientation, real reversals, contamination

- flip: 137,593 of 157,558 val flows swapped (the normaliser's TCP guard; 19,965 non-TCP unchanged); context identical after the flip (checked).
- flip agreement (5-seed mean, TCP / TCP benign): GLOBAL 0.922125 / 0.970968; GLOBAL_CTX 0.963828 / 0.999376; CTX_ONLY 1.000000 / 1.000000; GLOBAL_NOFP 0.917124 / 0.969844; GLOBAL_CTX_NOFP 0.999692 / 0.999282
- real reversals (233 diag_03 H1 flows): error rate (5-seed mean) and diag_03 incidents still false: GLOBAL 0.802, 3.4 / 3; GLOBAL_CTX 0.130, 1.0 / 3; CTX_ONLY 0.129, 1.0 / 3; GLOBAL_NOFP 0.833, 1.0 / 3; GLOBAL_CTX_NOFP 0.130, 1.0 / 3
- contamination: 509 of 39,185 val benign flows (0.0130) had an attack flow on one of their hosts in the previous 60 s. FA on contaminated / clean benign (5-seed mean): GLOBAL 0.8 / 1.2; GLOBAL_CTX 0.0 / 0.4; CTX_ONLY 2.0 / 2.8; GLOBAL_NOFP 0.0 / 2.2; GLOBAL_CTX_NOFP 0.0 / 0.0

## Fingerprint ablation (H-C2, every class)

- syn_flood: Δ_flow -0.0001, Δ_ctx -0.0221, Δ_ctx - Δ_flow -0.0220 [-0.0229, -0.0212] -> DOES_NOT_HOLD
- udp_flood (rare): Δ_flow -0.0588, Δ_ctx +0.0000, Δ_ctx - Δ_flow +0.0588 [+0.0235, +0.0941] -> HOLDS
- port_scan: Δ_flow -0.0111, Δ_ctx -0.0000, Δ_ctx - Δ_flow +0.0111 [+0.0098, +0.0138] -> HOLDS

## Zero-day with context (H-C3 and report-only arms)

- CTX_TAIL_GLOBAL (primary): miss-recall syn_flood 0.8128, port_scan 0.8945, udp_flood 0.1176; FA per seed [341, 324, 288, 334, 314] (163.97/h); detector alone syn_flood 0.9779, port_scan 0.8930, udp_flood 0.1176
- CTX_IF_GLOBAL (report-only): miss-recall syn_flood 0.9287, port_scan 0.8041, udp_flood 0.0000; FA per seed [59, 45, 42, 16, 28] (19.46/h); detector alone syn_flood 0.9907, port_scan 0.7493, udp_flood 0.0000
- CTX_TAIL_PER_GROUP (report-only; not a routing claim, D163): miss-recall syn_flood 0.8134, port_scan 0.9854, udp_flood 0.0941; FA per seed [342, 340, 335, 344, 336] (173.80/h); detector alone syn_flood 0.9763, port_scan 0.9420, udp_flood 0.0941
- FLOWCTX_TAIL_GLOBAL (report-only): miss-recall syn_flood 0.7822, port_scan 0.8929, udp_flood 0.4118; FA per seed [260, 283, 239, 266, 248] (132.73/h); detector alone syn_flood 0.9473, port_scan 0.8567, udp_flood 0.4118

- out-of-range diagnostic (share with >= 1 context feature above the train-benign maximum): benign 0.0050, syn_flood 0.9456, udp_flood 0.0000, port_scan 0.8562; Stage 1 misses (class|seed): syn_flood|0 0.719, syn_flood|1 0.720, syn_flood|2 0.972, syn_flood|3 0.748, syn_flood|4 0.712, port_scan|0 0.892, port_scan|1 0.892, port_scan|2 0.892, port_scan|3 0.892, port_scan|4 0.892, udp_flood|0 0.000, udp_flood|1 0.000, udp_flood|2 0.000, udp_flood|3 0.000, udp_flood|4 0.000
- CTX_TAIL_GLOBAL calibration per seed (q, held-out flag rate): s0 0.999883 / 0.00098; s1 0.999937 / 0.00080; s2 0.999937 / 0.00095; s3 0.999911 / 0.00098; s4 0.999946 / 0.00098
- top firing context features of CTX_TAIL_GLOBAL (seed 0, per true class): {'benign': {'ctx_hostmax_n_peers_60s': 169, 'ctx_hostmax_n_flows_60s': 96, 'ctx_hostmax_n_port_pairs_60s': 96, 'ctx_hostmax_n_flows_10s': 36, 'ctx_hostmax_n_port_pairs_10s': 36}, 'syn_flood': {'ctx_hostmin_share_syn_no_ack_60s': 99090, 'ctx_hostmin_n_flows_10s': 91540, 'ctx_pair_n_flows_10s': 91540, 'ctx_hostmin_n_port_pairs_10s': 91536, 'ctx_pair_n_port_pairs_10s': 91536}, 'udp_flood': {'ctx_hostmax_sum_pkts_10s': 2, 'ctx_hostmax_sum_bytes_10s': 2}, 'port_scan': {'ctx_hostmin_n_flows_10s': 13469, 'ctx_hostmin_n_port_pairs_10s': 13469, 'ctx_pair_n_flows_10s': 13469, 'ctx_pair_n_port_pairs_10s': 13469, 'ctx_hostmin_n_flows_60s': 11227}}

## TreeSHAP perturbation (Part B)

| model | predicted class | n | drop top-k | random-k | bottom-k | top - random [CI] | verdict | context SHAP share | fingerprint in top-k |
|---|---|---|---|---|---|---|---|---|---|
| GLOBAL | benign | 1,000 | 0.0001 | 0.0000 | 0.0000 | +0.0001 [-0.0004, +0.0007] | NOT_FAITHFUL | 0.000 | 0.679 |
| GLOBAL | syn_flood | 1,000 | 0.9993 | 0.0006 | 0.0000 | +0.9987 [+0.9985, +0.9989] | FAITHFUL | 0.000 | 1.000 |
| GLOBAL | udp_flood | 13 | 0.8459 | 0.0487 | 0.0268 | +0.7972 [+0.7326, +0.8560] | FAITHFUL | 0.000 | 1.000 |
| GLOBAL | port_scan | 1,000 | 0.8814 | 0.0649 | 0.0007 | +0.8165 [+0.8089, +0.8238] | FAITHFUL | 0.000 | 1.000 |
| GLOBAL_CTX | benign | 1,000 | 0.0003 | 0.0000 | -0.0000 | +0.0003 [-0.0009, +0.0018] | NOT_FAITHFUL | 0.564 | 0.637 |
| GLOBAL_CTX | syn_flood | 1,000 | 0.0359 | 0.0020 | 0.0005 | +0.0340 [+0.0282, +0.0402] | FAITHFUL | 0.743 | 0.998 |
| GLOBAL_CTX | udp_flood | 8 | 0.9353 | 0.0281 | 0.0140 | +0.9072 [+0.7747, +0.9868] | FAITHFUL | 0.680 | 0.250 |
| GLOBAL_CTX | port_scan | 1,000 | 0.8952 | 0.0003 | 0.0000 | +0.8949 [+0.8904, +0.8994] | FAITHFUL | 0.774 | 1.000 |

Disclosure: median replacement can create out-of-distribution rows; results describe the model, not the attack.

## Cost on the dev machine

- context features: 19.1 us/flow (pure Python streaming), peak state 492 hosts / 723 pairs / 187,633 window events per segment
- CTX_TAIL model of normal: 44 thresholds (one float per context feature) and an any-feature comparison per flow; no model file

## Limitations (stated in the prereg before any result)

1. Same CICIoT2023 testbed: few hosts, attackers are testbed Pis.
2. val is not fully held out.
3. Context features may partly re-encode what the packet-level rate guard sees (not compared here).
4. Held-out classes are still only floods and scans.
5. Benign flows of a host under attack inherit attack-looking context (measured above, not fixed).
6. 1-second start resolution: sub-second order comes from durations.
7. CTX_TAIL only sees attacks that push some context feature above the benign tail; low-and-slow attacks inside the benign range are invisible to it; contaminated benign flows raise false alarms (measured).
8. H-C1 is a TCP result (the normaliser swaps TCP flows only).

## What this means

**H1 limitation (SYN/ACK-first reversals).** H-C1 HOLDS. On the real reversed flows behind diag_03's misclassified incidents the error rate is 0.802 for GLOBAL, 0.130 for GLOBAL_CTX and 0.129 for CTX_ONLY. Adding context reduces these errors.

**Scanner-shortcut finding (Phase 3.1 C).** H-C2 HOLDS: with context features the model loses less port_scan recall when the fingerprint features are removed.

**Phase 5A floor effect.** H-C3 DOES_NOT_HOLD: the benign-only upper-tail rule on the context features does not meet the pre-registered bar (FA/h CI upper bound 171.448 > reference 18.743); see the per-class miss-recall and false alarms above for how far it moved from the 5A floor. The 5A IsolationForest recipe on the same context features (CTX_IF_GLOBAL, report-only) gives DOES_NOT_HOLD with miss-recall 0.8664, which shows how much of the outcome is the detector rather than the features.

**Non-inferiority** of GLOBAL_CTX: PASS.

## What a runtime stage would need (not built here)

- the same `common/context_features.ContextState` fed flow by flow at flow end (it already is streaming and bounded); per-capture / per-interface segmentation and a policy for state across restarts;
- a cost budget: the Python implementation measured above would need to be vectorised or ported for the Pi;
- eviction monitoring (spoofed floods can exhaust the key caps) and a decision on warm-up behaviour after start;
- re-validation of parity (offline == streaming) exactly as Phase 3 did for the flow path.

## Figures

- `figures/1_context_construction.png`
- `figures/2_context_distributions.png`
- `figures/3_stage1_recall_fa.png`
- `figures/4_flip_agreement.png`
- `figures/5_fingerprint_ablation.png`
- `figures/6_zeroday_context.png`
- `figures/7_shap_perturbation.png`
