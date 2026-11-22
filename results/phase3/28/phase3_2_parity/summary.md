# Step 28 -- streaming runtime on val + parity gate -- PASS

- run `20261122T140750Z`; CSV replay of `v2_0_v1equiv` val rows (extractor orientation) at max speed; offline reference `v2_1_oriented` val (n = 157,558); runtime alert key fingerprint `a67c1cc451c9500f`
- **PARITY GATE: PASS** (GLOBAL s0, the promoted model; criteria in docs/V2_PREREG_PHASE3.md section 1)

## Parity per run

| run | flows | features identical | class agree | max abs dp | group agree | device agree |
|---|---|---|---|---|---|---|
| GLOBAL_s0 | 157,558 | 157,558 | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| ROUTED_s0 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |

## Runtime runs

| run | eval-only | flows | wall s | flows / s | flow alerts | rate-guard alerts v2 / v1 | incidents | packets | quarantined | dropped | backlog peak | peak RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GLOBAL_s0 | False | 157,558 | 249.7 | 631 | 118,321 | 397 / 0 | 20 | 6,252,317 | 0 | 0 | 20,000 | 1394 |
| ROUTED_s0 | True | 157,558 | 216.4 | 728 | 118,338 | 397 / 0 | 21 | 6,252,317 | 0 | 0 | 20,000 | 1459 |

Run folders hold predictions.parquet, alerts.jsonl, health.jsonl, alerts_outbox.jsonl (all three chained + signed), incidents.json, latency.npz, rss.json, manifest.json.

## Figures

- `figures/parity_confusion.png`
- `figures/parity_abs_dp_hist.png`

## Checks

- PASS  offline reference reproduces step 23 (FLAT_GLOBAL_A1_none seed 0: FA count, recall)  FA 2 vs 2; recall [0.999949, 0.997914, 0.647059, 0.999175] vs [0.999949, 0.997914, 0.647059, 0.999175]
- PASS  parity GLOBAL_s0: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity GLOBAL_s0: runtime-normalised features == v2_1_oriented (exact float32, all 70)  157,558 / 157,558 rows identical
- PASS  parity GLOBAL_s0: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s0: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity GLOBAL_s0: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s0: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s0: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity ROUTED_s0: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s0: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity ROUTED_s0: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s0: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  compare GLOBAL_s0: predictions identical to phase3_1_parity row for row (every column)  157,558 rows (parts) vs 157,558 (parts)
- PASS  compare GLOBAL_s0: rate-guard alerts and incidents identical to phase3_1_parity  rate-guard alerts 397 vs 397; incidents 20 vs 20
- PASS  compare ROUTED_s0: predictions identical to phase3_1_parity row for row (every column)  157,558 rows (parts) vs 157,558 (parts)
- PASS  compare ROUTED_s0: rate-guard alerts and incidents identical to phase3_1_parity  rate-guard alerts 397 vs 397; incidents 21 vs 21
