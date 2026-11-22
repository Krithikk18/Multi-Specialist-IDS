# diag_03 -- choices log (READ-ONLY diagnostic; nothing here is a decision of the project)

Every choice the prompt did not fix, with the default taken. None of these is in `docs/V2_DECISIONS.md`, because
nothing is decided here. Rules A0 / B0 are the prompt's and are copied verbatim into A_summary.md / B_summary.md
before anything is computed (the scripts write them first, then compute, then append).

## Inputs and identity

- C01 **Runs**: step 28 `rerun_full` run `20261122T050150Z` (10 runs: GLOBAL / ROUTED x s0-s4; the PCAP run is not
  an input). Manifest sha256 re-checked (`common/phase3_run.resolve`), and every alerts / health / outbox hash chain
  re-verified with the runtime public key before use. Step 29 `rerun_fig_fix` metrics read the same way; its
  episodes are recomputed with step 29's own `episodes()` and must equal its metrics.json (hard check).
- C02 **Step 29 code reused, not re-implemented**: `29_eval_stream.py` is imported read-only (importlib) for
  `ground_truth`, `episodes`, `load_run`, `detect`, `incident_outcomes`, `run_metrics`, `rg_metrics`, `ci_seeds`,
  `garwood_rate`. The A2 what-if only replaces each episode's `start`. The prereg numbers are reproduced first and
  must match step 29 exactly (hard checks).
- C03 **Attacker host identity (evaluation-only ground truth)**: V1 step 13 / Phase 3 D74, used as-is:
  `13_rate_guard_calibrate.MacBook(07a.Devices(config/device_table.csv)).get(mac)[0] != ""`, i.e.
  `config.ATTACKER_MACS.matches(mac)` (exact `e4:5f:01:55:90:c4`, prefix `dc:a6:32`) or device_table role
  `testbed_pi` (11 MACs: `dc:a6:32:dc:27:d5`, `dc:a6:32:c9:e4:c6`, `dc:a6:32:c9:e5:02`, `dc:a6:32:c9:e6:f4`,
  `dc:a6:32:c9:e5:ef`, `dc:a6:32:c9:e5:a4`, `dc:a6:32:c9:e4:d5`, `dc:a6:32:c9:e4:90`, `e4:5f:01:55:90:c4`,
  `dc:a6:32:c9:e4:ab`, ...; full list in A_run.json / B_run.json `hosts`). This identity is "the attacker host" in
  the source check, in A2, and in H1 / H3.
- C04 **Source-share breakdown (report-only)**: attacker = `ATTACKER_MACS.exact`; testbed = the rest of the D74
  identity; other device = any other device_table MAC (any role, incl. the gateway); unknown = unlisted MAC.
  The source check uses attacker + testbed (= the D74 identity, C03). The exact-only share is also reported.

## Part A

- C05 **Triggering windows** of an alert with decision time t (= window end) and streak s: the s windows
  [t - s, t - s + 1), ..., [t - 1, t). Every alert's streak is reported; the source share pools all of them.
- C06 **Packets counted in the source check**: packets whose destination MAC is the protected device and whose
  protocol family is the alert's family, i.e. the packets the guard counted for that alert's key. The share over
  all families is reported next to it. The recounted last window must equal the runtime's `count` (warn check).
- C07 **Timing check episode**: among same-device episodes with -10 s <= t - start < 0, the one with the nearest
  start. If none, the protocol check uses the nearest same-device episode (distance to [start, end + 120 s]), so the
  protocol check is still evaluated and reported.
- C08 **Episode majority protocol family**: from v2_1 val `Protocol` of the episode's labelled flows (same class,
  same device, start in [episode start, episode end]; count must equal step 29's n_flows), mapped to a family by
  the config's `rate_guard.families` (TCP 6, UDP 17, else `other`), i.e. the rate guard's own family rule. No
  class -> protocol map.
- C09 **Nearest episode** (same device / any device): smallest distance from t to [start, end + 120 s], ties by
  |t - start|; gap reported as t - labelled start.
- C10 **Headline hours**: step 29's benign val hours (1.952778 h), as in the prereg figure.
- C11 **Runs compared for the 6 alerts**: GLOBAL_s0 vs ROUTED_s0 must be identical (hard check). Seeds 1-4 ran
  without the packet path (D77; their step 28 counts show packets 0), so they carry 0 rate-guard alerts by design;
  reported per run, not treated as a difference.
- C12 **A2 attacker-first-packet start**: the earliest VAL packet (any IPv4 protocol, file order, min timestamp)
  from the D74 identity with destination MAC = the episode's device, timestamp in [labelled start - 60 s, labelled
  start). If there is none, the episode start is unchanged (shift 0). Flags: first packet within 1 s of the window's
  lower edge (shift capped by the 60 s lookback); lookback reaching before the val window's first instant (the
  reader never returns pre-val packets). Labelled start is the dataset `start_ts` (whole second), as in step 29 (D81).
- C13 **A2 packets**: only the VAL packets of the captures holding an episode, read with
  `common/packet_source.session_packets(cfg, session, "val")` (capture sha256 checked; test sessions refused;
  reading stops at the first packet of a later split). No train packet is used, though train is allowed: the
  runtime only saw val.
- C14 **A2 recomputation**: the same 10 runs and the same rate-guard alerts (s0's for every seed, D77), with
  episodes whose start is moved; episode end, grouping, detection slack, incident rules, hours unchanged. Reported:
  rate-guard alerts on no episode / h and false incidents / h, flow-path false and misclassified incidents / h
  (5-seed mean, t-CI), seed-0 counts, and time-to-detect median / p95 + detected counts per class x path for seed 0
  of both modes (the prereg reports seed 0 for TTD). Point estimates only (no bootstrap) for the what-if.
- C15 **A3**: the draft is generated with the A2 numbers filled in; it is not referenced by any code and not pinned.

## Part B

- C16 **Misclassified incidents**: flow-path incidents (class != rate_guard) labelled "misclassified" by step 29's
  `incident_outcomes` (rate-guard incidents are always "correct" if they overlap any episode, so they are never
  misclassified). Count must equal step 29's per-run count (hard check).
- C17 **Contributing alert flows**: rows of predictions.parquet with `incident_id` = the incident and
  `policy_decision` in {opened, extended}. Suppressed-in-cooldown alerts do not belong to the incident. The count
  is compared with the incident's `n_alerts` (warn check).
- C18 **"Its episode"** (H2, and the flow's "start relative to the episode"): among the episodes the incident
  overlaps, the one whose [start, end + 120 s] holds the flow's start; else the nearest.
- C19 **Flow start** = dataset `start_ts` (whole second), the same clock as the episode bounds.
- C20 **H1 endpoints**: v2_1 (post-normalisation) `src_mac` / `dst_mac` (the normaliser swaps them with the
  features); "protected device" = the incident's device (= dataset `device_mac`); TCP = Protocol 6;
  `orientation_flipped` from the runtime predictions (checked equal to the dataset column, warn).
- C21 **H3**: "attacker<->device traffic" = one MAC is the protected device and the other is in the D74 identity.
  "Inside an attack episode on that device" = flow start in [start, end] of ANY episode on that device (the
  labelled interval, without the 120 s detection slack). The count that would move H4 -> H3 with the slack is
  reported (report-only).
- C22 **Pooling**: every contributing alert flow of every misclassified incident of the 10 runs counts once per
  run (the same flow in two runs counts twice), as "pooled over all 10 runs" reads. The per-incident majority
  split is reported as a side view.
- C23 **Incident identity across seeds / modes**: signature = predicted class @ device @ overlapped episode ids.
  Stable = present in all 5 seeds of a mode.
- C24 **Confusion**: one count per (overlapped episode true class, incident predicted class) per incident.
- C25 **H1 profile figure** (only if H1 flows exist): H1 flows deduplicated by flow uid over the runs, against
  correctly classified flows (label == pred) of the classes involved in GLOBAL_s0 (seeded sample <= 3,000 each).
- C26 **SHAP**: the runtime's own top-3 TreeSHAP per alert (`top3` in alerts.jsonl: feature, value, SHAP), not
  recomputed.

## Run

- C27 Development runs wrote to the session scratchpad only; the final run wrote to `results/diag_03/`. Every
  output is a new file (the scripts refuse existing targets).

## Added during the run (report-only additions; no verdict rule changed)

- C28 **H1 base rate** (`B_h1_base_rate.csv`): the H1 predicate evaluated on ALL labelled flows of the overlapped
  episodes, with the s0 models' predictions for matching vs non-matching flows. Added after the first development
  run showed H1 at ~99 %, to check that the predicate is not simply the shape of every flow in those episodes.
  Not part of the B0 verdict.
- C29 **Mechanism columns for A2** (`A_episode_start_shift.csv`): per episode, the capture's val window start, the
  capture's first val flow start, and the device's first val flow start. Added after the first development run
  showed that the only shifted episode's lookback is clipped by the val window start. diag_03 reads no gap / train
  flows, so the "flows that started in gap@train|val" explanation in the A3 draft is labelled as inferred.
- C30 **Figures**: alert panels mark the val window start (no val packet exists before it, which is why the
  panels are empty to its left). Points at the same shift share one label in the shift plot. The H1 profile
  separates the two H1 patterns (port_scan episodes -> syn_flood; syn_flood episodes -> port_scan) and uses the
  fixed class colours for the correctly classified reference flows.
- C31 **Development runs**: the first run of each part stopped or ran degraded on a parser bug (alerts.jsonl is
  compact JSON; the substring match expected `": "`). Part A stopped on its hard check (0 vs 6 off-episode alerts),
  and part B ran with SHAP missing. Fixed in `diag_03_common.parse_alerts`. Part B now hard-checks that every
  contributing flow has its runtime top-3 SHAP (1984 / 1984). Only the scratchpad was written by those runs.
