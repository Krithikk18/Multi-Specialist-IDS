# Step 31 -- val-A / val-B split + runtime on val-A + review queue -- PASS

## Split (docs/V2_PREREG_PHASE4.md section 1)

- val_A 81,427 flows, val_B 76,131 flows; split definition sha256 `6a48765357f2cbf3...`
- val_B support {'benign': 14973, 'syn_flood': 53297, 'udp_flood': 2, 'port_scan': 7859}; rare for the gate (< 50): ['udp_flood']; absent in val_B: []

| session | extent lo | extent hi | midpoint | val flows |
|---|---|---|---|---|
| DDoS-SYN_Flood | 1661776020 | 1661776304 | 1661776162.0 | 52,542 |
| DDoS-SYN_Flood5 | 1661795215 | 1661795830 | 1661795522.5 | 51,205 |
| Mirai-udpplain | 1674145320 | 1674145405 | 1674145362.5 | 597 |
| Recon-PortScan | 1664289039 | 1664291040 | 1664290039.5 | 28,528 |
| benign_night | 1665186351 | 1665191229 | 1665188790.0 | 24,686 |

Per class x group counts: `split.json`.

## Runtime on val-A + parity

- runtime `/home/krithikk/lgids_cache/v2/cl/runtime/20261122T132156Z_GLOBAL_s0_valA`: 81,427 flows, 3,148 flows/s, alerts 57,193, incidents 11
- parity: features identical 81,427 / 81,427; class agree 81,427; max |dp| 0.00e+00; group 81,427; device 81,427; vs Phase 3 full run {'pred_equal': True, 'max_abs_dp': 0.0, 'rows': 81427}

## Review queues

| queue | items | alerts | random | non-alerted | rate |
|---|---|---|---|---|---|
| 20261122T132156Z | 58,405 | 57,193 | 1,212 | 24,234 | 0.05 |
| 20261122T132156Z__no_random | 57,193 | 57,193 | 0 | 24,234 | 0.0 |

## Checks

- PASS  Phase 3 config pinned (the latest pinned runtime config)  config/v2_phase3_1.json sha256 14e45250569f3dee...
- PASS  replay / reference datasets as the Phase 3 config says  replay v2_0_v1equiv, reference v2_1_oriented
- PASS  replay rows == reference rows (same uids, order, labels, groups)  157,558 vs 157,558
- PASS  runtime model = the promoted deployed entry (deployment load, promoted only)  ['GLOBAL__none__s0__20261121T075821Z']
- PASS  parity val-A GLOBAL s0: every val flow processed and matched 1:1 (0 quarantined, 0 dropped)  runtime 81,427 / offline 81,427; quarantined 0, dropped 0
- PASS  parity val-A GLOBAL s0: runtime-normalised features == v2_1_oriented (exact float32, all 70)  81,427 / 81,427 rows identical
- PASS  parity val-A GLOBAL s0: predicted class == offline step 23 path (100 %)  81,427 / 81,427
- PASS  parity val-A GLOBAL s0: calibrated probabilities within 1e-06 of softmax(margin / T)  max |dp| 0.000e+00
- PASS  parity val-A GLOBAL s0: routing group == dataset group (100 %)  81,427 / 81,427
- PASS  parity val-A GLOBAL s0: protected device == dataset device_mac (100 %)  81,427 / 81,427
- PASS  val-A predictions == Phase 3 full-val runtime run for the same flows (report-only)  pred equal True, max |dp| 0.00e+00
