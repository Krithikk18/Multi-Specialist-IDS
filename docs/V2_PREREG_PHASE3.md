# LG-IDS V2 -- Phase 3 pre-registration: streaming runtime (val only)

Status: written and pinned (`PREREG_PHASE3_SHA256` in `common/schemas.py`, with `config/v2_phase3.json` as
`V2_PHASE3_CONFIG_SHA256`; both checked by `verify_v2_lock()`) **before** any runtime evaluation. The runtime refuses
to start if the policy config's bytes differ from the pin (DFD P5). Implementation choices it does not fix are logged
in `docs/V2_DECISIONS.md` (D61+). Everything here is VAL only; no test flow and no packet in a test time window is
read (every data source refuses split `test`).

Model under test: the promoted Stage 1 model (Amendment 2) `GLOBAL__none__s0__20261121T075821Z` in **GLOBAL**
mode; **ROUTED** (`SPEC_G1__none` / `SPEC_G2__none` / `GLOBAL__none`, seed 0, candidate entries, loaded in an
explicit evaluation-only mode) is run once alongside for comparison. Seeds 1-4 of both (step 22 run
`20261121T075821Z`, step 24 calibrators `20261121T080937Z`) are run the same way, evaluation-only, for 5-seed CIs.

## 1. Parity gate (pass / fail)

- **Input**: CSV replay of the val flows. The replayed rows are the `v2_0_v1equiv` val rows, i.e. the same flows as
  `v2_1_oriented` val in the extractor's own orientation, so the runtime's normaliser (`common/orientation.py`
  dict API) is exercised; the offline reference is `v2_1_oriented` val.
- **Pass iff, for the promoted model (GLOBAL, seed 0), on the full val split**:
  1. 100 % of val flows are processed (none quarantined, none dropped) and matched 1:1 to the offline rows;
  2. the runtime-normalised features equal the `v2_1_oriented` features for 100 % of flows (all 70, exact float32);
  3. runtime predicted class == offline step 23 predicted class for **100 %** of flows;
  4. runtime calibrated probabilities within **1e-6** (max absolute difference, every class) of the offline ones
     (offline = step 23's prediction path + step 24's `P = softmax(margin / T)` with the entry's T);
  5. runtime routing (MAC -> device -> group) == the dataset `group` column for **100 %** of val flows, and the
     runtime's protected device == the dataset `device_mac` for 100 %.
  The offline reference must itself reproduce step 23's recorded seed-0 GLOBAL numbers (false-alarm count, macro-F1).
  On failure: diagnose, fix, re-run (at most two attempts), then stop.
- **pcap path (report-only)**: the locked CICFlowMeter on a val-window pcap slice; flows matched to the dataset rows
  by (Flow ID, start time); report the share of matched flows whose 70 features are identical within float
  tolerance (|a - b| <= 1e-9 + 1e-6 |b|; target >= 99 %), profile mismatches by feature, and report the
  emission-time vs start + duration lag.

## 2. Event time

- A flow becomes visible to the runtime when CICFlowMeter emits it.
- CSV replay: **emission time = flow start + Flow Duration** (start = the dataset `start_ts`, CICFlowMeter's
  Timestamp truncated to the second). This is a lower bound of the real emission time (flows held until a timeout,
  a FIN or end of file surface later) and carries up to 1 s of start-time truncation. Replay order = emission time,
  ties in dataset row order.
- pcap path: the real emission ORDER (CSV row order); emission time reconstructed as the running maximum of
  start + duration over the rows emitted so far (a lower bound that respects the real order), raised to the start
  of the same Flow ID's successor flow when that successor starts >= the flow timeout after the flow (timeout-
  triggered emission).
- Decision time of a flow = the event time at which its micro-batch is scored (<= emission + 200 ms).
  Time-to-detect uses decision time.
- Packets (rate guard) are on the same event clock (capture timestamps). A rate-guard decision is made when its
  window closes (window end).
- Note: val attack flows are a capped sample (<= 50,000 per family per group, split_definition); the replay sees
  fewer flows per second than the capture had. Packets are not sampled.

## 3. Ground-truth episodes

Attack flows (dataset label != benign) are grouped per (class, protected device), protected device = the endpoint the
routing rule assigns (the dataset `device_mac`). Sorted by start: a flow starts a new episode iff its start is more
than **60 s** after the latest end (start + duration) of the current episode. Episode start = first start, episode end
= latest end.

## 4. Policy defaults (fixed now, not tuned on val)

- **Alert**: a flow whose argmax class is an attack class AND whose calibrated max-probability >= **0.5**.
- **Incident**: alerts aggregated by key (predicted class, protected device). An incident stays open while alerts for
  its key keep arriving within **60 s** of the previous one (event time); it closes 60 s after its last alert. The
  same key cannot open a new incident within a **300 s cooldown** after the close; alerts in the cooldown are logged
  as suppressed and do not extend anything.
- **Rate-guard alerts** go through the same policy with the key (rate_guard, protected device).
- **Severity**: from config per class, values High / Medium / Low only; a class not in the map -> Medium.

## 5. Incident metrics

- **Episode detected** by a path iff that path raised an alert for the episode's device (any class) during
  [episode start, episode end + **120 s**]. Paths: flow model, rate guard, either. Also reported: detected by an
  alert of the episode's own class (flow path).
- **Time-to-detect** = first such alert's decision time - episode start; median and p95 per class x path.
- **Incident outcome**: correct = its [first, last alert] interval overlaps the detection window of an episode of its
  class on its device (rate-guard incidents: of any class); misclassified = overlaps only episodes of other classes;
  **false** = overlaps no episode on its device.
- Reported overall and per group: false incidents / h, misclassified incidents / h, flow-level false alarms / h
  (benign flows with argmax != benign, exactly as Phase 2), alert-level false alarms / h (benign flows that became
  alerts); hours = Phase 2's benign val hours (session active segments, pause > 300 s) of the flows in scope.
- CIs: GLOBAL and ROUTED over the 5 seeds (mean and 95 % t-CI, 4 df); seed 0 also with an exact Poisson (Garwood)
  CI on counts; the rate guard (one deterministic run) with a bootstrap over episodes (detection, time-to-detect;
  10,000 resamples, seed 0) and Garwood on its benign alert count.
- Rate-guard benign alerts / h: rate-guard incidents (and alerts) overlapping no episode on their device, over the
  same benign hours.

## 6. Rate guard v2 rule

- Counts packets per **1 s** window INTO each protected device, per protocol family **TCP (6) / UDP (17) / other**.
  Protected device = destination MAC that the inventory lists with an owner role (the routing rule); a unicast
  destination MAC the inventory does not list -> the fallback group (08b's unregistered-MAC rule); every other
  destination (non-owner roles, broadcast, multicast) is not counted.
- **Threshold** per (group, family) = **2 x the maximum** packets in a 1 s window into any one device of that group
  seen in **train benign** (train-window packets of train / time_split captures with no attacker / testbed-Pi MAC on
  either side: V1 step 13's exclusion). Zero train-benign alerts by construction (alert iff count > threshold).
- An alert fires on the **3rd consecutive** 1 s window above threshold for the same (device, family), and on every
  further consecutive window above it; an empty window counts as 0 packets.
- A (group, family) with fewer than **60** non-empty train-benign windows uses the fallback group's threshold for
  that family; if the fallback group also has fewer, the threshold pooled over all groups (logged which).
- **V1's non-TCP/UDP rule is kept exactly as it is**: V1 `rate_guard.RateGuard` with `config/rate_guard_v1.json`
  (10 s windows, stream + victim levels), imported read-only, on the same packets.
- Thresholds are fitted once (`27_fit_rate_guard.py`) into a file whose sha256 is in a manifest; the runtime refuses
  a thresholds file whose sha256 differs.

## 7. Benchmark protocol (report-only on the dev machine)

Per-stage latency p50 / p95 / p99 (normalise, route, features, predict, calibrate, SHAP-on-alert, policy, log),
flows / s, peak RSS, at batch sizes {1, 16, 64, 256} and replay speeds {1x on a 10-min val slice, 10x on the same
slice, max on full val}, with backlog and drops. Machine info recorded. Pi budgets are set when the hardware arrives.

## 8. Report-only sweeps (never change the defaults)

Confidence threshold {0.5, 0.7, 0.9}; aggregation window {30, 60, 120 s}; computed by re-running the pure policy on
the recorded predictions.
