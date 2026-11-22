# Step 30 -- runtime benchmark (dev machine, report-only) -- PASS

- machine: 12th Gen Intel(R) Core(TM) i5-12450HX, 12 logical CPUs, 9.6 GB RAM, Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.39; Python 3.11.17, XGBoost 3.4.2, numpy 2.4.6 (dev machine (WSL2 on Windows); not the Pi)
- GLOBAL (promoted model), boosters single-threaded, flow path only (packet path benchmarked separately); batch-stage latencies are per batch and amortised per flow

## Throughput

| run | batch | speed | flows | wall s | flows / s | dropped | backlog peak | e2e p50 / p95 / p99 ms | queue wait p95 ms | peak RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|
| max_b1 | 1 | max | 157,558 / 157,558 | 164.7 | 956 | 0 | 20,000 | 23558.24 / 29508.45 / 29930.63 | 29507.18 | 1502 |
| max_b16 | 16 | max | 157,558 / 157,558 | 57.8 | 2,728 | 0 | 20,000 | 8240.89 / 9053.42 / 9168.23 | 9046.42 | 1502 |
| max_b64 | 64 | max | 157,558 / 157,558 | 48.4 | 3,258 | 0 | 20,000 | 6945.00 / 7339.32 / 7516.17 | 7318.70 | 1502 |
| max_b256 | 256 | max | 157,558 / 157,558 | 71.3 | 2,210 | 0 | 20,000 | 10219.69 / 13046.87 / 13938.58 | 13007.85 | 1502 |
| 1x_b64 | 64 | 1x | 52,542 / 52,542 | 283.1 | 186 | 0 | 601 | 81.62 / 292.08 / 511.60 | 141.09 | 1502 |
| 10x_b64 | 64 | 10x | 52,542 / 52,542 | 34.3 | 1,533 | 0 | 16,496 | 1830.77 / 5364.13 / 5853.59 | 5340.91 | 1502 |

## Per-stage latency (microseconds per flow; p50 / p95 / p99)

| run | route | normalise | features | predict | calibrate | shap | policy | log |
|---|---|---|---|---|---|---|---|---|
| max_b1 | 3.4 / 5.6 / 7.8 | 10.7 / 17.8 / 36.4 | 12.0 / 17.8 / 28.7 | 203.6 / 364.6 / 517.3 | 28.4 / 49.3 / 65.6 | 436.5 / 1679.6 / 4913.1 | 3.8 / 7.5 / 11.1 | 150.3 / 235.2 / 298.6 |
| max_b16 | 1.3 / 4.6 / 6.4 | 6.6 / 17.5 / 22.6 | 8.5 / 15.1 / 23.4 | 53.6 / 193.9 / 318.8 | 5.8 / 26.0 / 39.1 | 3.5 / 299.6 / 531.5 | 0.2 / 1.5 / 2.4 | 7.1 / 122.0 / 180.9 |
| max_b64 | 1.2 / 2.9 / 7.3 | 5.8 / 13.7 / 24.9 | 8.3 / 12.1 / 22.6 | 81.3 / 214.5 / 388.6 | 9.6 / 28.0 / 47.9 | 2.5 / 189.6 / 315.5 | 0.1 / 1.0 / 2.3 | 5.7 / 110.3 / 144.7 |
| max_b256 | 2.0 / 3.5 / 8.4 | 7.9 / 14.8 / 29.2 | 11.0 / 15.2 / 34.9 | 88.3 / 276.7 / 544.2 | 10.4 / 34.1 / 61.9 | 2.3 / 296.0 / 550.3 | 0.1 / 1.5 / 4.6 | 5.5 / 172.4 / 242.7 |
| 1x_b64 | 2.2 / 10.2 / 19.5 | 9.0 / 26.8 / 49.5 | 12.0 / 37.5 / 67.7 | 16.9 / 839.6 / 1142.9 | 1.7 / 117.8 / 190.8 | 296.8 / 2317.6 / 7063.9 | 1.2 / 6.3 / 16.4 | 162.4 / 371.5 / 700.5 |
| 10x_b64 | 1.0 / 3.3 / 10.4 | 6.5 / 12.9 / 27.4 | 8.1 / 15.9 / 33.8 | 14.6 / 560.9 / 1046.6 | 1.4 / 70.9 / 149.8 | 175.6 / 411.6 / 1063.0 | 0.9 / 3.7 / 11.8 | 103.3 / 200.9 / 289.2 |

Per batch (microseconds; p50 / p95 / p99): max_b1: predict 204/365/517, SHAP (batches with alerts) 437/1680; max_b16: predict 292/712/978, SHAP (batches with alerts) 7/4593; max_b64: predict 213/1298/1471, SHAP (batches with alerts) 5/11677; max_b256: predict 203/1577/3702, SHAP (batches with alerts) 5/16945; 1x_b64: predict 903/1694/2131, SHAP (batches with alerts) 13805/25105; 10x_b64: predict 660/1475/2375, SHAP (batches with alerts) 10441/18780

- paced runs replay the busiest 10-minute val slice (event window 1661776021 .. 1661776621); at 1x the offered rate is the capture's own flow rate (val is a capped sample, so this is a lower bound of the real rate)

## Packet path

- 6,252,317 val packets: reader 157,438 packets/s; reader + rate guard v2 + V1 rule 129,072 packets/s (includes the captures' sha256 check (first pass only) and skipping the train part of each capture on record headers)
- CICFlowMeter (locked jar, offline mode): 143,215 frames -> 29,677 flows in 5.3 s wall = 27,091 frames/s incl. JVM start (step 28 run 20261122T050150Z pcap path)

## Figures

- `figures/stage_latency_box.png`
- `figures/throughput.png`
- `figures/rss_over_time.png`

Dev-machine numbers only; Pi budgets are set when the hardware arrives (docs/V2_PREREG_PHASE3.md section 7).
