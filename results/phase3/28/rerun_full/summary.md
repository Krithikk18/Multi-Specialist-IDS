# Step 28 -- streaming runtime on val + parity gate -- PASS

- run `20261122T050150Z`; CSV replay of `v2_0_v1equiv` val rows (extractor orientation) at max speed; offline reference `v2_1_oriented` val (n = 157,558); runtime alert key fingerprint `a67c1cc451c9500f`
- **PARITY GATE: PASS** (GLOBAL s0, the promoted model; criteria in docs/V2_PREREG_PHASE3.md section 1)

## Parity per run

| run | flows | features identical | class agree | max abs dp | group agree | device agree |
|---|---|---|---|---|---|---|
| GLOBAL_s0 | 157,558 | 157,558 | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| ROUTED_s0 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| GLOBAL_s1 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| GLOBAL_s2 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| GLOBAL_s3 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| GLOBAL_s4 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| ROUTED_s1 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| ROUTED_s2 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| ROUTED_s3 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |
| ROUTED_s4 | 157,558 | - | 157,558 | 0.00e+00 | 157,558 | 157,558 |

## Runtime runs

| run | eval-only | flows | wall s | flows / s | flow alerts | rate-guard alerts v2 / v1 | incidents | packets | quarantined | dropped | backlog peak | peak RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| GLOBAL_s0 | False | 157,558 | 142.9 | 1,103 | 118,321 | 397 / 0 | 20 | 6,252,317 | 0 | 0 | 20,000 | 8230 |
| ROUTED_s0 | True | 157,558 | 94.9 | 1,661 | 118,338 | 397 / 0 | 21 | 6,252,317 | 0 | 0 | 20,000 | 8230 |
| GLOBAL_s1 | True | 157,558 | 53.0 | 2,975 | 118,239 | 0 / 0 | 17 | 0 | 0 | 0 | 20,000 | 8230 |
| GLOBAL_s2 | True | 157,558 | 47.4 | 3,327 | 118,312 | 0 / 0 | 16 | 0 | 0 | 0 | 20,000 | 8230 |
| GLOBAL_s3 | True | 157,558 | 64.0 | 2,462 | 118,314 | 0 / 0 | 17 | 0 | 0 | 0 | 20,000 | 8230 |
| GLOBAL_s4 | True | 157,558 | 46.3 | 3,405 | 118,336 | 0 / 0 | 16 | 0 | 0 | 0 | 20,000 | 8230 |
| ROUTED_s1 | True | 157,558 | 47.4 | 3,324 | 118,324 | 0 / 0 | 17 | 0 | 0 | 0 | 20,000 | 8230 |
| ROUTED_s2 | True | 157,558 | 61.9 | 2,543 | 118,340 | 0 / 0 | 17 | 0 | 0 | 0 | 20,000 | 8230 |
| ROUTED_s3 | True | 157,558 | 53.8 | 2,927 | 118,347 | 0 / 0 | 18 | 0 | 0 | 0 | 20,000 | 8230 |
| ROUTED_s4 | True | 157,558 | 42.7 | 3,686 | 118,336 | 0 / 0 | 17 | 0 | 0 | 0 | 20,000 | 8230 |

Run folders hold predictions.parquet, alerts.jsonl, health.jsonl, alerts_outbox.jsonl (all three chained + signed), incidents.json, latency.npz, rss.json, manifest.json.

## pcap path (report-only)

- slice `Recon-PortScan` val window: 143,215 frames (sha256 `fb58a8958299d320...`, source sha256 checked); locked CICFlowMeter: 29,677 flows in 5.3 s wall (27,091 frames/s incl. JVM start); CSV schema required checks pass: True
- matched to dataset rows (Flow ID + start second, in order): **28,135 of 28,528** dataset rows in the window (98.6%); features identical within tolerance on **28,131 (99.99%)** of matched flows (target >= 99 %)
- emission-time lag (reconstructed emission - (start + duration)), all rows: p50 1018.00 s, p95 1804.98 s, p99 1836.99 s, max 1922.0 s
- runtime on this source: 29,677 flows; routing through the IP -> MAC map; group == dataset group on matched flows: 0.87%
- mismatching features (count of matched flows): {'Flow Duration': 4, 'Total Fwd Packet': 3, 'Total Bwd packets': 2, 'Total Length of Fwd Packet': 2, 'Total Length of Bwd Packet': 1, 'Fwd Packet Length Max': 2, 'Fwd Packet Length Min': 1, 'Fwd Packet Length Mean': 2, 'Fwd Packet Length Std': 1, 'Bwd Packet Length Max': 1, 'Bwd Packet Length Mean': 1, 'Bwd Packet Length Std': 1, 'Flow Bytes/s': 3, 'Flow Packets/s': 4, 'Flow IAT Mean': 4, 'Flow IAT Std': 2, 'Flow IAT Max': 4, 'Flow IAT Min': 4, 'Fwd IAT Total': 3, 'Fwd IAT Mean': 3, 'Fwd IAT Std': 1, 'Fwd IAT Max': 3, 'Fwd IAT Min': 3, 'Bwd IAT Total': 1, 'Bwd IAT Mean': 1, 'Bwd IAT Max': 1, 'Bwd IAT Min': 1, 'Fwd PSH Flags': 2, 'Fwd Header Length': 4, 'Bwd Header Length': 2, 'Fwd Packets/s': 4, 'Bwd Packets/s': 2, 'Packet Length Max': 3, 'Packet Length Mean': 3, 'Packet Length Std': 3, 'Packet Length Variance': 3, 'FIN Flag Count': 2, 'RST Flag Count': 3, 'PSH Flag Count': 3, 'ACK Flag Count': 2, 'Down/Up Ratio': 2, 'Average Packet Size': 3, 'Fwd Segment Size Avg': 2, 'Bwd Segment Size Avg': 1, 'FWD Init Win Bytes': 3, 'Bwd Init Win Bytes': 1, 'Fwd Seg Size Min': 1}

## Figures

- `figures/parity_confusion.png`
- `figures/parity_abs_dp_hist.png`
- `figures/pcap_feature_mismatch.png`

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
- PASS  parity GLOBAL_s1: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity GLOBAL_s1: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s1: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity GLOBAL_s1: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s1: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s2: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity GLOBAL_s2: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s2: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity GLOBAL_s2: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s2: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s3: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity GLOBAL_s3: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s3: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity GLOBAL_s3: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s3: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s4: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity GLOBAL_s4: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s4: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity GLOBAL_s4: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity GLOBAL_s4: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s1: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity ROUTED_s1: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s1: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity ROUTED_s1: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s1: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s2: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity ROUTED_s2: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s2: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity ROUTED_s2: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s2: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s3: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity ROUTED_s3: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s3: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity ROUTED_s3: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s3: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s4: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 157,558 / offline 157,558; quarantined 0, dropped 0
- PASS  parity ROUTED_s4: predicted class == offline step 23 path (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s4: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity ROUTED_s4: routing group == dataset group (100 %)  157,558 / 157,558
- PASS  parity ROUTED_s4: protected device == dataset device_mac (100 %)  157,558 / 157,558
- PASS  pcap path: feature equality on matched flows >= 99 % (report-only target)  28,131 / 28,135 matched rows identical; matched 28,135 of 28,528 dataset rows (98.6%); CSV rows 29,677
