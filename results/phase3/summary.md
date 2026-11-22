# LG-IDS V2 Phase 3 -- streaming runtime (val only): summary

Pre-registration `docs/V2_PREREG_PHASE3.md` (sha256 `14ff67c4...`, pinned with `config/v2_phase3.json` `398ee6b7...`)
was written before any runtime evaluation. Stage 1 = the promoted FLAT_GLOBAL model (Amendment 2, sha256 `075f738e...`;
registry entry `GLOBAL__none__s0__20261121T075821Z`). Every number below is on VAL; nothing from the test split was read.
Decisions: `docs/V2_DECISIONS.md` D57-D91. Architecture: `figures/runtime_architecture.png`.

## 1. Parity gate: PASS (step 28 run `20261122T050150Z`, `28/rerun_full/`)

CSV replay of the 157,558 val flows (extractor orientation) through the runtime vs offline step 23 / 24 on `v2_1_oriented`:

| check (GLOBAL s0, promoted) | result |
|---|---|
| flows processed / matched 1:1, quarantined, dropped | 157,558 / 157,558, 0, 0 |
| runtime-normalised features == v2_1 (exact float32, 70) | 157,558 / 157,558 |
| predicted class == offline step 23 path | 157,558 / 157,558 (100 %) |
| calibrated probabilities, max abs difference | 0.0 (gate 1e-6) |
| routing group / protected device == dataset | 100 % / 100 % |
| offline reference reproduces step 23 seed 0 (FA count, per-class recall) | 2 == 2, recall identical |

The same checks pass for ROUTED s0 and for GLOBAL / ROUTED seeds 1-4 (all 100 %, max abs dp 0). The first full run
(`20261121T192135Z`) was killed at ROUTED s3; its 8 completed runs had also passed and are kept (D85).

**pcap path (report-only)**: the locked CICFlowMeter on the Recon-PortScan val window (143,215 frames -> 29,677 flows,
rows emitted as flows end) matched 28,135 of 28,528 dataset rows (98.6 %); **99.99 %** of matched flows have identical
features; their predictions equal the CSV-replay predictions on 100 %. Two caveats (`pcap_diag/`, D89): the prereg's
emission-time rule overstates the lag (p50 1,018 s; sweeper-aware p50 221 s, running-max p50 70 s), and routing needs
a per-capture / live IP -> MAC source (static map: 0.87 % group agreement; the capture's own map: 100 %).

## 2. Headline incident metrics (step 29, `29/rerun_fig_fix/`; 13 episodes, 1.953 benign val hours)

Detection rate and time-to-detect, GLOBAL (flow path: mean [95 % t-CI] over 5 seeds; rate guard: bootstrap over
episodes; TTD seed 0 with bootstrap CI). ROUTED is identical on every detection cell.

| class (episodes) | path | detection rate | median TTD s | p95 TTD s |
|---|---|---|---|---|
| syn_flood (3) | flow model | 1.00 | 4.2 [2.2, 12.0] | 11.2 |
| | rate guard | 1.00 | 3.0 [0.0, 4.0] | 3.9 |
| | either | 1.00 | 2.2 [0.0, 4.0] | 3.8 |
| udp_flood (2) | flow model | 0.50 | 19.5 | 19.5 |
| | rate guard | 0.50 | 8.0 | 8.0 |
| | either | 0.50 | 8.0 | 8.0 |
| port_scan (8) | flow model | 1.00 | 0.0 [0.0, 0.2] | 0.2 |
| | rate guard | 0.00 | - | - |
| | either | 1.00 | 0.0 [0.0, 0.2] | 0.2 |

The undetected udp_flood episode is one zero-duration flow on a second device (no packet surge, no alert).
`29/rerun_fig_fix/figures/ttd_ecdf.png` shows why the hybrid needs both paths: the rate guard is first on floods, only
the flow model sees scans.

| per benign val hour | GLOBAL | ROUTED |
|---|---|---|
| flow-level false alarms (5 seeds) | 1.024 [0.575, 1.474] | 1.741 [1.393, 2.089] |
| false incidents, flow path (5 seeds) | 0.512 [0.512, 0.512] | 1.024 [1.024, 1.024] |
| seed 0 false incidents [Garwood] | 0.512 [0.013, 2.853] (1) | 1.024 [0.124, 3.700] (2) |
| misclassified incidents (5 seeds) | 1.741 [1.393, 2.089] | 1.639 [1.354, 1.923] |

Per group (GLOBAL): every flow-level false alarm and the single false incident are in G1; G2 and GEN are 0. ROUTED adds
a G2 false alarm and false incident. Counting incidents instead of flows halves the false-alarm rate.

Rate guard (packet path, 6.25 M val packets): 397 alerts, 4 incidents, **0 false incidents** (0.000 / h, Garwood upper
1.889). By the prereg's literal rule, 6 alerts lie outside any episode window (3.07 / h); all 6 hit the DDoS-SYN_Flood5
victim in the 9 s before the episode's first labelled flow, which received 146,288 attacker-MAC packets in that time.
On a sender basis the benign count is 0 (D87). V1's non-TCP/UDP rule raised 0 alerts on val.

Report-only sweeps: threshold 0.9 removes the one false incident (0.512 -> 0.000 / h) at the same 12 / 13 flow-path
detections; the aggregation window (30 / 60 / 120 s) changes nothing on val.

## 3. Benchmark (step 30, dev machine: i5-12450HX, 12 threads, 9.6 GB, WSL2; Python 3.11.17, XGBoost 3.4.2)

| run | flows / s | e2e p50 / p95 ms | dropped | peak RSS MB |
|---|---|---|---|---|
| max, batch 1 / 16 / 64 / 256 (full val) | 956 / 2,728 / **3,258** / 2,210 | backlog-bound | 0 | 1,502 |
| 1x, batch 64 (busiest slice: a SYN flood, 186 flows / s offered) | 186 (kept up) | 82 / 292 | 0 | 1,502 |
| 10x, batch 64 (same slice) | 1,533 (backlog peak 16,496 / 20,000) | 1,831 / 5,364 | 0 | 1,502 |

Per-flow latency at batch 64 (p50 / p95 us): route 1.2 / 2.9, normalise 5.8 / 13.7, features 8.3 / 12.1, predict
81 / 215, calibrate 9.6 / 28, policy 0.1 / 1.0, log 5.7 / 110; SHAP 185 / 514 us **per alert** (`bench_shap_diag/`,
D90). Packet path: reader 157 k packets / s, reader + rate guard v2 + V1 rule 129 k packets / s. CICFlowMeter: 27 k
frames / s including JVM start.

## 4. What is proven, and what waits for the Pi

Proven on val (dev machine): the runtime reproduces the offline pipeline bit for bit (features, classes, probabilities,
routing). Only signed, pinned, promoted models load, and the policy config is integrity-checked at start. Every alert,
health and outbox record is hash-chained and signed, and all 30 logs verify. The hybrid detects every syn_flood and
port_scan episode, the rate guard alone raises 0 false incidents, and incident aggregation halves the false-alarm rate.

Waits for the Pi: latency / throughput budgets (dev numbers are report-only); live capture (online CICFlowMeter +
packet capture instead of file replay and whole-file mmaps); a live IP -> MAC source for routing; chunked prediction
flushing (memory grows ~200 MB per 157 k flows); alert-heavy floods, where SHAP + signing per alert halves throughput
(SHAP could be rate-limited per incident); the Networking contract (`docs/V2_ALERT_CONTRACT.md`, PROPOSED).
