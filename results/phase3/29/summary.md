# Step 29 -- incident-level evaluation of the streaming runtime (val) -- PASS

- step 28 run `20261122T050150Z` (parity gate PASS); benign val hours 1.953 (G1 1.953, G2 1.953, GEN 1.953)
- 13 ground-truth episodes (gap 60 s, detection window end + 120 s); CIs: 5 seeds (t) for the flow path, bootstrap over episodes for the rate guard and time-to-detect, Garwood for seed-0 counts

## GLOBAL

| class | path | detection rate | median TTD s [boot CI] | p95 TTD s [boot CI] | detected (seed 0) |
|---|---|---|---|---|---|
| syn_flood | flow | 1.000 [1.000, 1.000] (n=3) | 4.2 [2.2, 12.0] | 11.2 [2.2, 12.0] | 3 |
| syn_flood | rate_guard | 1.000 [1.000, 1.000] (n=3) | 3.0 [0.0, 4.0] | 3.9 [0.0, 4.0] | 3 |
| syn_flood | either | 1.000 [1.000, 1.000] (n=3) | 2.2 [0.0, 4.0] | 3.8 [0.0, 4.0] | 3 |
| syn_flood | flow_own | 1.000 [1.000, 1.000] (n=3) | 4.2 [2.2, 12.0] | 11.2 [2.2, 12.0] | 3 |
| udp_flood | flow | 0.500 [0.500, 0.500] (n=2) | 19.5 [19.5, 19.5] | 19.5 [19.5, 19.5] | 1 |
| udp_flood | rate_guard | 0.500 [0.000, 1.000] (n=2) | 8.0 [8.0, 8.0] | 8.0 [8.0, 8.0] | 1 |
| udp_flood | either | 0.500 [0.500, 0.500] (n=2) | 8.0 [8.0, 8.0] | 8.0 [8.0, 8.0] | 1 |
| udp_flood | flow_own | 0.500 [0.500, 0.500] (n=2) | 19.5 [19.5, 19.5] | 19.5 [19.5, 19.5] | 1 |
| port_scan | flow | 1.000 [1.000, 1.000] (n=8) | 0.0 [0.0, 0.2] | 0.2 [0.1, 0.2] | 8 |
| port_scan | rate_guard | 0.000 [0.000, 0.000] (n=8) | - [-, -] | - [-, -] | 0 |
| port_scan | either | 1.000 [1.000, 1.000] (n=8) | 0.0 [0.0, 0.2] | 0.2 [0.1, 0.2] | 8 |
| port_scan | flow_own | 1.000 [1.000, 1.000] (n=8) | 0.0 [0.0, 0.2] | 0.2 [0.1, 0.2] | 8 |

| measure (per benign val hour) | all | G1 | G2 | GEN |
|---|---|---|---|---|
| flow-level false alarms / h (5 seeds) | 1.024 [0.575, 1.474] | 1.024 [0.575, 1.474] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| alert-level false alarms / h (5 seeds) | 1.024 [0.575, 1.474] | 1.024 [0.575, 1.474] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |
| false incidents / h, flow path (5 seeds) | 0.512 [0.512, 0.512] | 0.512 [0.512, 0.512] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] |

- seed 0: flow-level FA 1.024 [0.124, 3.700] (2 / 1.953 h); false incidents 0.512 [0.013, 2.853] (1 / 1.953 h); misclassified incidents 1.536 [0.317, 4.490] (3 / 1.953 h); false incidents incl. rate guard 0.512 [0.013, 2.853] (1 / 1.953 h); flow incidents {'n': 16, 'correct': 12, 'misclassified': 3, 'false': 1}; attack-argmax flows below the 0.5 threshold: 18
- misclassified incidents / h (5 seeds): 1.741 [1.393, 2.089]; incidents per run: 16.4 [15.7, 17.1]

## ROUTED

| class | path | detection rate | median TTD s [boot CI] | p95 TTD s [boot CI] | detected (seed 0) |
|---|---|---|---|---|---|
| syn_flood | flow | 1.000 [1.000, 1.000] (n=3) | 4.2 [2.2, 12.0] | 11.2 [2.2, 12.0] | 3 |
| syn_flood | rate_guard | 1.000 [1.000, 1.000] (n=3) | 3.0 [0.0, 4.0] | 3.9 [0.0, 4.0] | 3 |
| syn_flood | either | 1.000 [1.000, 1.000] (n=3) | 2.2 [0.0, 4.0] | 3.8 [0.0, 4.0] | 3 |
| syn_flood | flow_own | 1.000 [1.000, 1.000] (n=3) | 4.2 [2.2, 12.0] | 11.2 [2.2, 12.0] | 3 |
| udp_flood | flow | 0.500 [0.500, 0.500] (n=2) | 19.5 [19.5, 19.5] | 19.5 [19.5, 19.5] | 1 |
| udp_flood | rate_guard | 0.500 [0.000, 1.000] (n=2) | 8.0 [8.0, 8.0] | 8.0 [8.0, 8.0] | 1 |
| udp_flood | either | 0.500 [0.500, 0.500] (n=2) | 8.0 [8.0, 8.0] | 8.0 [8.0, 8.0] | 1 |
| udp_flood | flow_own | 0.500 [0.500, 0.500] (n=2) | 19.5 [19.5, 19.5] | 19.5 [19.5, 19.5] | 1 |
| port_scan | flow | 1.000 [1.000, 1.000] (n=8) | 0.0 [0.0, 0.2] | 0.2 [0.1, 0.2] | 8 |
| port_scan | rate_guard | 0.000 [0.000, 0.000] (n=8) | - [-, -] | - [-, -] | 0 |
| port_scan | either | 1.000 [1.000, 1.000] (n=8) | 0.0 [0.0, 0.2] | 0.2 [0.1, 0.2] | 8 |
| port_scan | flow_own | 1.000 [1.000, 1.000] (n=8) | 0.0 [0.0, 0.2] | 0.2 [0.1, 0.2] | 8 |

| measure (per benign val hour) | all | G1 | G2 | GEN |
|---|---|---|---|---|
| flow-level false alarms / h (5 seeds) | 1.741 [1.393, 2.089] | 1.229 [0.881, 1.577] | 0.512 [0.512, 0.512] | 0.000 [0.000, 0.000] |
| alert-level false alarms / h (5 seeds) | 1.741 [1.393, 2.089] | 1.229 [0.881, 1.577] | 0.512 [0.512, 0.512] | 0.000 [0.000, 0.000] |
| false incidents / h, flow path (5 seeds) | 1.024 [1.024, 1.024] | 0.512 [0.512, 0.512] | 0.512 [0.512, 0.512] | 0.000 [0.000, 0.000] |

- seed 0: flow-level FA 2.048 [0.558, 5.245] (4 / 1.953 h); false incidents 1.024 [0.124, 3.700] (2 / 1.953 h); misclassified incidents 1.536 [0.317, 4.490] (3 / 1.953 h); false incidents incl. rate guard 1.024 [0.124, 3.700] (2 / 1.953 h); flow incidents {'n': 17, 'correct': 12, 'misclassified': 3, 'false': 2}; attack-argmax flows below the 0.5 threshold: 12
- misclassified incidents / h (5 seeds): 1.639 [1.354, 1.923]; incidents per run: 17.2 [16.6, 17.8]

## Rate guard (packet path, model-independent)

- alerts 397 (v2 397, V1 rule 0); on no episode of their device: 6 ({'v2': 6, 'v1': 0}) -> benign alerts / h 3.073 [1.128, 6.688] (6 / 1.953 h)
- incidents 4, false 0 -> 0.000 [0.000, 1.889] (0 / 1.953 h); by group {'G1': 0, 'G2': 0, 'GEN': 0}

## Report-only sweeps (GLOBAL s0, flow path)

| threshold | window s | incidents | false incidents / h | detection rate | median TTD s | alert-level FA |
|---|---|---|---|---|---|---|
| 0.5 | 30 | 16 | 0.512 | 0.923 | 0.2 | 2 |
| 0.5 | 60 | 16 | 0.512 | 0.923 | 0.2 | 2 |
| 0.5 | 120 | 16 | 0.512 | 0.923 | 0.2 | 2 |
| 0.7 | 30 | 16 | 0.512 | 0.923 | 0.2 | 1 |
| 0.7 | 60 | 16 | 0.512 | 0.923 | 0.2 | 1 |
| 0.7 | 120 | 16 | 0.512 | 0.923 | 0.2 | 1 |
| 0.9 | 30 | 15 | 0.000 | 0.923 | 0.2 | 0 |
| 0.9 | 60 | 15 | 0.000 | 0.923 | 0.2 | 0 |
| 0.9 | 120 | 15 | 0.000 | 0.923 | 0.2 | 0 |

## Figures

- `figures/replay_timeline.png`
- `figures/ttd_ecdf.png`
- `figures/false_alarms_per_group.png`
- `figures/detection_rate.png`
- `figures/sweeps.png`

## Checks

- PASS  step 28 parity gate passed  {'run_id': '20261122T050150Z', 'manifest_sha256': '1d711f9e907d419ab82d92fc0f1c9f616041ec2869768c463d5e460f08d28fa8', 'parity_gate': 'PASS'}
- PASS  every run's alerts / health / outbox chain verifies (runtime key, expected count + head)  10 runs x 3 logs
- PASS  rate-guard alerts identical across modes (model-independent packet path)  [397, 397] alerts
- PASS  sweep default cell reproduces the runtime's flow incidents (pure policy == runtime policy)  16 vs 16
