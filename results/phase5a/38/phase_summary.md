# LG-IDS V2 Phase 5A -- zero-day test (leave-one-attack-out + model of normal, per-group vs global)

Runs: step 36 `20261122T174129Z`, step 37 `20261122T174358Z`, step 38 `20261122T174504Z`. Offline, train + val only (full val); nothing registered, runtime untouched. Pre-registration `docs/V2_PREREG_PHASE5.md`.

## Headline

- **Amendment 2 §3 verdict: CONFLICT** -- prereg reading: DOES_NOT_WIN ((a) fails: recall-difference CI lower bound +0.0000 <= 0); Amendment 2 literal reading: PER_GROUP_WINS ((a) and (b) hold); readings agree: False.
- (a) miss-recall difference PER_GROUP - GLOBAL, mean [95 % bootstrap CI] over 10 eligible pairs: +0.0000 [+0.0000, +0.0000] (n=10); t-interval (report-only) +0.0000 [+0.0000, +0.0000] (n=10).
- (b) FA/h difference PER_GROUP - GLOBAL over 5 seeds: -6.145 [-9.218, -3.687] (n=5) (margin 0.5 / h).
- Phase 4 §4 (pinned): DOES_NOT_WIN.

**Kill rule §5: not evaluated (the §3 verdict is CONFLICT; a human decision is needed).**

## Held-out classes and Stage 1 misses

- verdict classes (>= 50 val flows): syn_flood, port_scan; rare, report-only: udp_flood. Val benign hours 1.953.

| held out | seed | val k flows | Stage 1 misses | caught as another attack | eligible | miss-recall GLOBAL | PER_GROUP | RANDOM_GROUP | d |
|---|---|---|---|---|---|---|---|---|---|
| syn_flood | 0 | 100,177 | 221 | 99,956 {'port_scan': 99956} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| syn_flood | 1 | 100,177 | 236 | 99,941 {'port_scan': 99941} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| syn_flood | 2 | 100,177 | 9,718 | 90,459 {'port_scan': 90459} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| syn_flood | 3 | 100,177 | 214 | 99,963 {'port_scan': 99963} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| syn_flood | 4 | 100,177 | 229 | 99,948 {'port_scan': 99948} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| port_scan | 0 | 18,179 | 8,370 | 9,809 {'syn_flood': 9809} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| port_scan | 1 | 18,179 | 8,367 | 9,812 {'syn_flood': 9812} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| port_scan | 2 | 18,179 | 8,368 | 9,811 {'syn_flood': 9811} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| port_scan | 3 | 18,179 | 8,368 | 9,811 {'syn_flood': 9811} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| port_scan | 4 | 18,179 | 8,370 | 9,809 {'syn_flood': 9809} | yes | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| udp_flood (rare) | 0 | 17 | 17 | 0 {} | no | 0.0000 | 0.1765 | 0.0000 | 0.1765 |
| udp_flood (rare) | 1 | 17 | 17 | 0 {} | no | 0.0000 | 0.0588 | 0.0000 | 0.0588 |
| udp_flood (rare) | 2 | 17 | 17 | 0 {} | no | 0.0000 | 0.1765 | 0.0000 | 0.1765 |
| udp_flood (rare) | 3 | 17 | 17 | 0 {} | no | 0.0000 | 0.1765 | 0.0000 | 0.1765 |
| udp_flood (rare) | 4 | 17 | 17 | 0 {} | no | 0.0000 | 0.0588 | 0.0000 | 0.0588 |

Eligible pairs per class: syn_flood 5/5, port_scan 5/5, udp_flood 0/5

LOAO Stage 1 benign sanity (val): syn_flood s0: benign recall 0.99992, FA 3 (1.536/h); syn_flood s1: benign recall 0.99987, FA 5 (2.560/h); syn_flood s2: benign recall 0.99992, FA 3 (1.536/h); syn_flood s3: benign recall 0.99982, FA 7 (3.585/h); syn_flood s4: benign recall 0.99987, FA 5 (2.560/h); port_scan s0: benign recall 0.99992, FA 3 (1.536/h); port_scan s1: benign recall 0.99992, FA 3 (1.536/h); port_scan s2: benign recall 0.99992, FA 3 (1.536/h); port_scan s3: benign recall 0.99997, FA 1 (0.512/h); port_scan s4: benign recall 0.99992, FA 3 (1.536/h); udp_flood s0: benign recall 1.00000, FA 0 (0.000/h); udp_flood s1: benign recall 1.00000, FA 0 (0.000/h); udp_flood s2: benign recall 1.00000, FA 0 (0.000/h); udp_flood s3: benign recall 0.99997, FA 1 (0.512/h); udp_flood s4: benign recall 1.00000, FA 0 (0.000/h)

Control (report-only): full refit with this code vs the step 22 deployed model: {'seed': 0, 'refit_sha256': 'a0b0afc91a469ef322d043a599d9c585245c9251d1b775611e0742864106faff', 'step22_sha256': 'a0b0afc91a469ef322d043a599d9c585245c9251d1b775611e0742864106faff', 'bytes_identical': True, 'val_argmax_agreement': 1.0, 'val_disagreements': 0, 'best_iteration': 68, 'step22_rounds': 69, 'fit_seconds': 18.095}

## False alarms on val benign (detector alone)

| arm | seed | flagged flows | val benign flows | benign hours | FA/h | flag rate |
|---|---|---|---|---|---|---|
| GLOBAL_NORMAL | 0 | 35 | 39,185 | 1.953 | 17.923 | 0.00089 |
| GLOBAL_NORMAL | 1 | 32 | 39,185 | 1.953 | 16.387 | 0.00082 |
| GLOBAL_NORMAL | 2 | 44 | 39,185 | 1.953 | 22.532 | 0.00112 |
| GLOBAL_NORMAL | 3 | 27 | 39,185 | 1.953 | 13.826 | 0.00069 |
| GLOBAL_NORMAL | 4 | 45 | 39,185 | 1.953 | 23.044 | 0.00115 |
| PER_GROUP_NORMAL | 0 | 25 | 39,185 | 1.953 | 12.802 | 0.00064 |
| PER_GROUP_NORMAL | 1 | 24 | 39,185 | 1.953 | 12.290 | 0.00061 |
| PER_GROUP_NORMAL | 2 | 20 | 39,185 | 1.953 | 10.242 | 0.00051 |
| PER_GROUP_NORMAL | 3 | 22 | 39,185 | 1.953 | 11.266 | 0.00056 |
| PER_GROUP_NORMAL | 4 | 32 | 39,185 | 1.953 | 16.387 | 0.00082 |
| RANDOM_GROUP_NORMAL | 0 | 54 | 39,185 | 1.953 | 27.653 | 0.00138 |
| RANDOM_GROUP_NORMAL | 1 | 52 | 39,185 | 1.953 | 26.629 | 0.00133 |
| RANDOM_GROUP_NORMAL | 2 | 20 | 39,185 | 1.953 | 10.242 | 0.00051 |
| RANDOM_GROUP_NORMAL | 3 | 41 | 39,185 | 1.953 | 20.996 | 0.00105 |
| RANDOM_GROUP_NORMAL | 4 | 49 | 39,185 | 1.953 | 25.092 | 0.00125 |

## Models of normal

| arm | seed | models: n train benign / threshold | fallback | 90/10 held-out flag rate |
|---|---|---|---|---|
| GLOBAL_NORMAL | 0 | __global__: 137,462 / 0.65920 | - | 0.00102 |
| PER_GROUP_NORMAL | 0 | G1: 120,028 / 0.65012; G2: 16,279 / 0.67672; GEN: 1,155 / 0.68457 | - | 0.00116 |
| RANDOM_GROUP_NORMAL | 0 | G1: 120,028 / 0.64648; G2: 16,279 / 0.65380; GEN: 1,155 / 0.65670 | - | 0.00138 |
| GLOBAL_NORMAL | 1 | __global__: 137,462 / 0.65140 | - | 0.00065 |
| PER_GROUP_NORMAL | 1 | G1: 120,028 / 0.65928; G2: 16,279 / 0.68097; GEN: 1,155 / 0.67844 | - | 0.00109 |
| RANDOM_GROUP_NORMAL | 1 | G1: 120,028 / 0.66747; G2: 16,279 / 0.64564; GEN: 1,155 / 0.67266 | - | 0.00095 |
| GLOBAL_NORMAL | 2 | __global__: 137,462 / 0.66072 | - | 0.00065 |
| PER_GROUP_NORMAL | 2 | G1: 120,028 / 0.65098; G2: 16,279 / 0.67718; GEN: 1,155 / 0.68126 | - | 0.00087 |
| RANDOM_GROUP_NORMAL | 2 | G1: 120,028 / 0.65215; G2: 16,279 / 0.66021; GEN: 1,155 / 0.64867 | - | 0.00131 |
| GLOBAL_NORMAL | 3 | __global__: 137,462 / 0.65277 | - | 0.00124 |
| PER_GROUP_NORMAL | 3 | G1: 120,028 / 0.65405; G2: 16,279 / 0.67705; GEN: 1,155 / 0.68679 | - | 0.00073 |
| RANDOM_GROUP_NORMAL | 3 | G1: 120,028 / 0.66378; G2: 16,279 / 0.65100; GEN: 1,155 / 0.67685 | - | 0.00080 |
| GLOBAL_NORMAL | 4 | __global__: 137,462 / 0.64898 | - | 0.00073 |
| PER_GROUP_NORMAL | 4 | G1: 120,028 / 0.65032; G2: 16,279 / 0.67602; GEN: 1,155 / 0.68152 | - | 0.00124 |
| RANDOM_GROUP_NORMAL | 4 | G1: 120,028 / 0.66234; G2: 16,279 / 0.64314; GEN: 1,155 / 0.65489 | - | 0.00080 |

Determinism (seed-0 refit, identical scores): {'GLOBAL_NORMAL': True, 'PER_GROUP_NORMAL': True, 'RANDOM_GROUP_NORMAL': True}

## Report-only

- **RANDOM_GROUP vs GLOBAL** (same paired analysis): recall d +0.0000 [+0.0000, +0.0000] (n=10); FA/h d +3.380 [-4.916, +9.422] (n=5); (a) False, (b) False -> would 'win': False.
- detector alone on ALL val flows of k (5-seed mean): syn_flood: GLOBAL 0.0000, PER_GROUP 0.0000, RANDOM_GROUP 0.0000; port_scan: GLOBAL 0.0000, PER_GROUP 0.0000, RANDOM_GROUP 0.0000; udp_flood: GLOBAL 0.0000, PER_GROUP 0.1294, RANDOM_GROUP 0.0000
- combined system (Stage 1 alert OR flag) recall on k (5-seed mean): syn_flood: GLOBAL 0.9788, PER_GROUP 0.9788, RANDOM_GROUP 0.9788; port_scan: GLOBAL 0.5397, PER_GROUP 0.5397, RANDOM_GROUP 0.5397; udp_flood: GLOBAL 0.0000, PER_GROUP 0.1294, RANDOM_GROUP 0.0000
- combined FA/h on val benign (5-seed mean; LOAO Stage 1 FA + detector FA): syn_flood: Stage 1 alone 2.36, GLOBAL 21.10 (41.2 flows), PER_GROUP 14.95 (29.2 flows), RANDOM_GROUP 24.48 (47.8 flows); port_scan: Stage 1 alone 1.33, GLOBAL 20.07 (39.2 flows), PER_GROUP 13.93 (27.2 flows), RANDOM_GROUP 23.45 (45.8 flows)
- drift: val-benign flag rate per arm x group, 5-seed mean, nominal 0.0010: GLOBAL G1 0.00065, G2 0.00431, GEN 0.00000; PER_GROUP G1 0.00060, G2 0.00105, GEN 0.00000; RANDOM_GROUP G1 0.00061, G2 0.00693, GEN 0.00000
- per-group miss-recall (seed-mean over pairs with misses in the group): syn_flood G1: GLOBAL 0.0000, PER_GROUP 0.0000, RANDOM_GROUP 0.0000; syn_flood G2: GLOBAL 0.0000, PER_GROUP 0.0000, RANDOM_GROUP 0.0000; port_scan G1: GLOBAL 0.0000, PER_GROUP 0.0000, RANDOM_GROUP 0.0000; port_scan G2: GLOBAL 0.0000, PER_GROUP 0.0000, RANDOM_GROUP 0.0000
- scoring cost (n_jobs 4): GLOBAL batch 6.9 us/flow, single flow 7440 us (median of 200); PER_GROUP batch 6.8 us/flow, single flow 7552 us (median of 200); RANDOM_GROUP batch 6.8 us/flow, single flow 7531 us (median of 200)
- model sizes on disk (seed 0): GLOBAL 2609 KB; PER_GROUP 7030 KB; RANDOM_GROUP 7803 KB

## Limitations (stated in the prereg before any result)

1. Only 2 held-out classes enter the verdict, all floods / scans; the CI covers seed noise, not attack variety.
2. Isolation Forest is strong on globally extreme points and weak on local anomalies inside dense benign regions; the test says nothing about stealthy attacks.
3. Flow level only; in the deployed hybrid the rate guard would likely catch these floods anyway.
4. val is not fully held out (Phase 2 selection, Amendment 2, the deployed temperature; Phase 4 disclosure).
5. The model of normal is benign-only: the same fitted models score every held-out class; only the miss set changes.
6. The bootstrap treats (class, seed) pairs as independent although they share seeds and classes.

## What this means for the paper

The two readings of Amendment 2 §3 disagree (CONFLICT), so no verdict is declared and Phase 5A stops for a human decision (see the headline).

## Figures

- `figures/1_pipeline.png`
- `figures/2_where_heldout_flows_go.png`
- `figures/3_miss_recall_pairs.png`
- `figures/4_verdict_cis.png`
- `figures/5_false_alarms.png`
- `figures/6_score_distributions.png`
- `figures/7_threshold_check.png`
