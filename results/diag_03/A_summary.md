# diag_03 part A -- rate-guard alerts on no episode (READ-ONLY, val)

### A0. Rule, fixed before any numbers. Write it verbatim at the top of results/diag_03/A_summary.md before computing anything.
For each rate-guard alert that overlaps no episode under the prereg rule:
- **Source check:** at least 90% of the packets INTO the protected device during the alert's triggering windows (the 3+ consecutive
  1 s windows above threshold) come from the attacker host.
- **Timing check:** there is an episode on the SAME protected device whose labelled start is at most 10 s after the alert's decision
  time (−10 s ≤ alert time − episode start < 0).
- **Protocol check:** the alert's protocol family equals the majority protocol family of that episode's labelled flows. This is
  computed from the data, with no hard-coded class→protocol map.
Verdict per alert: **PRECURSOR** iff all three checks hold; otherwise **FALSE_ALARM**, recording which checks failed.
Headline: rate-guard benign alerts/h = (FALSE_ALARM count) / 1.953 h. The prereg figure (3.07/h) stays the primary number, and both
numbers are always reported side by side.

---

## Results (computed after the rule above was written)

Inputs: step 28 run `20261122T050150Z` (rerun_full), step 29 `rerun_fig_fix`; benign val hours 1.9528. Attacker host = V1 step 13 / D74 identity (13_rate_guard_calibrate.MacBook.get(mac)[0] != '' (ATTACKER_MACS.matches(mac) or device_table role == testbed_pi)). Rate guard alerts on no episode (prereg rule): **6**.

### A1. Per-alert verdicts (`A_alerts.csv`)

| alert | decision time | device | family | triggering windows (pkts vs threshold) | attacker-identity share | timing episode (alert - start) | episode majority family | failed | verdict |
|---|---|---|---|---|---|---|---|---|---|
| rgA1 | 1661795217 | Unidentified ESP plug (2) `50:02:91:10:09:8f` (G2) | TCP | [1661795214,1661795215) 12240 pkts > 644; [1661795215,1661795216) 16509 pkts > 644; [1661795216,1661795217) 17468 pkts > 644 | 1.0000 | ep000 (-6.0 s) | TCP | - | **PRECURSOR** |
| rgA2 | 1661795218 | Unidentified ESP plug (2) `50:02:91:10:09:8f` (G2) | TCP | [1661795214,1661795215) 12240 pkts > 644; [1661795215,1661795216) 16509 pkts > 644; [1661795216,1661795217) 17468 pkts > 644; [1661795217,1661795218) 17573 pkts > 644 | 1.0000 | ep000 (-5.0 s) | TCP | - | **PRECURSOR** |
| rgA3 | 1661795219 | Unidentified ESP plug (2) `50:02:91:10:09:8f` (G2) | TCP | [1661795214,1661795215) 12240 pkts > 644; [1661795215,1661795216) 16509 pkts > 644; [1661795216,1661795217) 17468 pkts > 644; [1661795217,1661795218) 17573 pkts > 644; [1661795218,1661795219) 17370 pkts > 644 | 1.0000 | ep000 (-4.0 s) | TCP | - | **PRECURSOR** |
| rgA4 | 1661795220 | Unidentified ESP plug (2) `50:02:91:10:09:8f` (G2) | TCP | [1661795214,1661795215) 12240 pkts > 644; [1661795215,1661795216) 16509 pkts > 644; [1661795216,1661795217) 17468 pkts > 644; [1661795217,1661795218) 17573 pkts > 644; [1661795218,1661795219) 17370 pkts > 644; [1661795219,1661795220) 18430 pkts > 644 | 1.0000 | ep000 (-3.0 s) | TCP | - | **PRECURSOR** |
| rgA5 | 1661795221 | Unidentified ESP plug (2) `50:02:91:10:09:8f` (G2) | TCP | [1661795214,1661795215) 12240 pkts > 644; [1661795215,1661795216) 16509 pkts > 644; [1661795216,1661795217) 17468 pkts > 644; [1661795217,1661795218) 17573 pkts > 644; [1661795218,1661795219) 17370 pkts > 644; [1661795219,1661795220) 18430 pkts > 644; [1661795220,1661795221) 14918 pkts > 644 | 1.0000 | ep000 (-2.0 s) | TCP | - | **PRECURSOR** |
| rgA6 | 1661795222 | Unidentified ESP plug (2) `50:02:91:10:09:8f` (G2) | TCP | [1661795214,1661795215) 12240 pkts > 644; [1661795215,1661795216) 16509 pkts > 644; [1661795216,1661795217) 17468 pkts > 644; [1661795217,1661795218) 17573 pkts > 644; [1661795218,1661795219) 17370 pkts > 644; [1661795219,1661795220) 18430 pkts > 644; [1661795220,1661795221) 14918 pkts > 644; [1661795221,1661795222) 15308 pkts > 644 | 1.0000 | ep000 (-1.0 s) | TCP | - | **PRECURSOR** |

- PRECURSOR **6**, FALSE_ALARM **0**.
- **Rate-guard benign alerts / h: prereg (primary) 3.073 (6 / 1.953 h)  |  FALSE_ALARM only 0.000 [0.000, 1.889] (0 / 1.953 h, Garwood 95 %)**.
- Packet share by source host in the triggering windows (alert family): rgA1: attacker 0.000, testbed 1.000, other device 0.000, unknown 0.000; rgA2: attacker 0.000, testbed 1.000, other device 0.000, unknown 0.000; rgA3: attacker 0.000, testbed 1.000, other device 0.000, unknown 0.000; rgA4: attacker 0.000, testbed 1.000, other device 0.000, unknown 0.000; rgA5: attacker 0.000, testbed 1.000, other device 0.000, unknown 0.000; rgA6: attacker 0.000, testbed 1.000, other device 0.000, unknown 0.000

Across runs (D77: seeds 1-4 ran without the packet path, so they carry no rate-guard alerts by design):

| run | packet path ran | rate-guard alerts | on no episode | same 6 as GLOBAL_s0 |
|---|---|---|---|---|
| GLOBAL_s0 | True | 397 | 6 | True |
| GLOBAL_s1 | False | 0 | 0 | False |
| GLOBAL_s2 | False | 0 | 0 | False |
| GLOBAL_s3 | False | 0 | 0 | False |
| GLOBAL_s4 | False | 0 | 0 | False |
| ROUTED_s0 | True | 397 | 6 | True |
| ROUTED_s1 | False | 0 | 0 | False |
| ROUTED_s2 | False | 0 | 0 | False |
| ROUTED_s3 | False | 0 | 0 | False |
| ROUTED_s4 | False | 0 | 0 | False |

### A2. Episode-start what-if (REPORT-ONLY; replaces nothing)

Attacker-first-packet start = the first packet from the attacker identity into the episode's device in [labelled start - 60 s, labelled start); shift = labelled start - that time (`A_episode_start_shift.csv`).

| episode | class | device | labelled start | attacker-first-packet | shift s | attacker pkts in lookback | notes |
|---|---|---|---|---|---|---|---|
| ep000 | syn_flood | 50:02:91:10:09:8f | 1661795223 | 1661795214.301 | 8.699 | 146,288 | lookback clipped by the val window start |
| ep001 | syn_flood | 9c:8e:cd:1d:ab:9f | 1661776096 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep002 | syn_flood | c4:dd:57:0c:39:94 | 1661795779 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep003 | udp_flood | 2c:71:ff:05:f1:15 | 1674145349 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep004 | udp_flood | cc:f4:11:9c:d0:00 | 1674145324 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged); lookback clipped by the val window start |
| ep005 | port_scan | 18:69:d8:eb:d4:3e | 1664289305 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep006 | port_scan | 2c:71:ff:05:f1:15 | 1664289493 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep007 | port_scan | 70:ee:50:6b:a8:1a | 1664289667 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep008 | port_scan | 84:e3:42:42:ed:0b | 1664289129 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep009 | port_scan | ac:f1:08:4e:00:82 | 1664290695 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep010 | port_scan | b0:f1:ec:d3:e7:98 | 1664290158 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep011 | port_scan | d0:73:d5:35:fb:c8 | 1664289912 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |
| ep012 | port_scan | d4:ad:fc:29:c8:a2 | 1664290937 | - | 0.000 | 0 | no attacker packet in the 60 s lookback (start unchanged) |

#### what-if, not pre-registered

| measure (val, per benign hour = 1.953 h) | prereg (as reported) | what-if, not pre-registered |
|---|---|---|
| rate guard: alerts on no episode / h | 3.073 (6) | 0.000 (0) |
| rate guard: false incidents / h | 0.000 (0) | 0.000 (0) |
| GLOBAL flow path: false incidents / h (5 seeds) | 0.512 [0.512, 0.512] | 0.512 [0.512, 0.512] |
| GLOBAL flow path: misclassified incidents / h (5 seeds) | 1.741 [1.393, 2.089] | 1.741 [1.393, 2.089] |
| GLOBAL seed 0: false / misclassified incidents (counts) | 1 / 3 | 1 / 3 |
| ROUTED flow path: false incidents / h (5 seeds) | 1.024 [1.024, 1.024] | 1.024 [1.024, 1.024] |
| ROUTED flow path: misclassified incidents / h (5 seeds) | 1.639 [1.354, 1.923] | 1.639 [1.354, 1.923] |
| ROUTED seed 0: false / misclassified incidents (counts) | 2 / 3 | 2 / 3 |

Time to detect (seed 0; s) and detection rate, per class x path. Cell = median / p95 (detected / episodes); prereg -> what-if.

| mode | class | path | prereg median / p95 (det.) | what-if median / p95 (det.) |
|---|---|---|---|---|
| GLOBAL | syn_flood | flow | 4.2 / 11.2 (3/3) | 12.0 / 12.8 (3/3) |
| GLOBAL | syn_flood | rate_guard | 3.0 / 3.9 (3/3) | 3.0 / 3.9 (3/3) |
| GLOBAL | syn_flood | either | 2.2 / 3.8 (3/3) | 2.7 / 3.9 (3/3) |
| GLOBAL | syn_flood | flow_own | 4.2 / 11.2 (3/3) | 12.0 / 12.8 (3/3) |
| GLOBAL | udp_flood | flow | 19.5 / 19.5 (1/2) | 19.5 / 19.5 (1/2) |
| GLOBAL | udp_flood | rate_guard | 8.0 / 8.0 (1/2) | 8.0 / 8.0 (1/2) |
| GLOBAL | udp_flood | either | 8.0 / 8.0 (1/2) | 8.0 / 8.0 (1/2) |
| GLOBAL | udp_flood | flow_own | 19.5 / 19.5 (1/2) | 19.5 / 19.5 (1/2) |
| GLOBAL | port_scan | flow | 0.0 / 0.2 (8/8) | 0.0 / 0.2 (8/8) |
| GLOBAL | port_scan | rate_guard | - / - (0/8) | - / - (0/8) |
| GLOBAL | port_scan | either | 0.0 / 0.2 (8/8) | 0.0 / 0.2 (8/8) |
| GLOBAL | port_scan | flow_own | 0.0 / 0.2 (8/8) | 0.0 / 0.2 (8/8) |
| ROUTED | syn_flood | flow | 4.2 / 11.2 (3/3) | 12.0 / 12.8 (3/3) |
| ROUTED | syn_flood | rate_guard | 3.0 / 3.9 (3/3) | 3.0 / 3.9 (3/3) |
| ROUTED | syn_flood | either | 2.2 / 3.8 (3/3) | 2.7 / 3.9 (3/3) |
| ROUTED | syn_flood | flow_own | 4.2 / 11.2 (3/3) | 12.0 / 12.8 (3/3) |
| ROUTED | udp_flood | flow | 19.5 / 19.5 (1/2) | 19.5 / 19.5 (1/2) |
| ROUTED | udp_flood | rate_guard | 8.0 / 8.0 (1/2) | 8.0 / 8.0 (1/2) |
| ROUTED | udp_flood | either | 8.0 / 8.0 (1/2) | 8.0 / 8.0 (1/2) |
| ROUTED | udp_flood | flow_own | 19.5 / 19.5 (1/2) | 19.5 / 19.5 (1/2) |
| ROUTED | port_scan | flow | 0.0 / 0.2 (8/8) | 0.0 / 0.2 (8/8) |
| ROUTED | port_scan | rate_guard | - / - (0/8) | - / - (0/8) |
| ROUTED | port_scan | either | 0.0 / 0.2 (8/8) | 0.0 / 0.2 (8/8) |
| ROUTED | port_scan | flow_own | 0.0 / 0.2 (8/8) | 0.0 / 0.2 (8/8) |

### A3. `amendment_3_proposal_DRAFT.md` written.

### Figures

- `figures/A_alert_panels.png` -- one panel per alert, packet rate into the device (1 s bins, stacked by source host), threshold, triggering windows, labelled episode start
- `figures/A_episode_start_shift.png` -- per-episode start shift by class

### Checks

- PASS  GLOBAL_s0: rate-guard alerts identical to GLOBAL_s0  397 alerts
- PASS  ROUTED_s0: rate-guard alerts identical to GLOBAL_s0  397 alerts
- PASS  off-episode alerts (prereg rule, step 29's window [start, end + 120 s]) == step 29's count  6 vs 6
- PASS  no packet of a test window read (every scanned session's reader stopped at / before its cut or ended)  {'DDoS-SYN_Flood': 'train', 'DDoS-SYN_Flood5': 'train', 'Mirai-udpplain': 'train', 'Recon-PortScan': 'time_split'}
- PASS  rgA1: recounted packets of its last window == the runtime's count  17468 vs 17468
- PASS  rgA2: recounted packets of its last window == the runtime's count  17573 vs 17573
- PASS  rgA3: recounted packets of its last window == the runtime's count  17370 vs 17370
- PASS  rgA4: recounted packets of its last window == the runtime's count  18430 vs 18430
- PASS  rgA5: recounted packets of its last window == the runtime's count  14918 vs 14918
- PASS  rgA6: recounted packets of its last window == the runtime's count  15308 vs 15308
- PASS  prereg reproduction GLOBAL_s0: flow incidents == step 29  {'n': 16, 'correct': 12, 'misclassified': 3, 'false': 1}
- PASS  prereg reproduction ROUTED_s0: flow incidents == step 29  {'n': 17, 'correct': 12, 'misclassified': 3, 'false': 2}
- PASS  prereg reproduction GLOBAL_s1: flow incidents == step 29  {'n': 17, 'correct': 12, 'misclassified': 4, 'false': 1}
- PASS  prereg reproduction GLOBAL_s2: flow incidents == step 29  {'n': 16, 'correct': 12, 'misclassified': 3, 'false': 1}
- PASS  prereg reproduction GLOBAL_s3: flow incidents == step 29  {'n': 17, 'correct': 12, 'misclassified': 4, 'false': 1}
- PASS  prereg reproduction GLOBAL_s4: flow incidents == step 29  {'n': 16, 'correct': 12, 'misclassified': 3, 'false': 1}
- PASS  prereg reproduction ROUTED_s1: flow incidents == step 29  {'n': 17, 'correct': 12, 'misclassified': 3, 'false': 2}
- PASS  prereg reproduction ROUTED_s2: flow incidents == step 29  {'n': 17, 'correct': 12, 'misclassified': 3, 'false': 2}
- PASS  prereg reproduction ROUTED_s3: flow incidents == step 29  {'n': 18, 'correct': 12, 'misclassified': 4, 'false': 2}
- PASS  prereg reproduction ROUTED_s4: flow incidents == step 29  {'n': 17, 'correct': 12, 'misclassified': 3, 'false': 2}
- PASS  prereg reproduction: rate-guard off-episode alerts and false incidents == step 29  {'alerts_on_no_episode': 6, 'alerts_on_no_episode_per_h': 3.072546230440967, 'incidents': 4, 'false_incidents': 0, 'false_incidents_per_h': 0.0}
- PASS  prereg reproduction: GLOBAL s0 median TTD syn_flood / flow == step 29  4.200000047683716 vs 4.200000047683716
- PASS  prereg reproduction: GLOBAL s0 median TTD syn_flood / rate_guard == step 29  3.0 vs 3.0
- PASS  prereg reproduction: GLOBAL s0 median TTD syn_flood / either == step 29  2.200000047683716 vs 2.200000047683716
- PASS  prereg reproduction: GLOBAL s0 median TTD udp_flood / flow == step 29  19.48074507713318 vs 19.48074507713318
- PASS  prereg reproduction: GLOBAL s0 median TTD udp_flood / rate_guard == step 29  8.0 vs 8.0
- PASS  prereg reproduction: GLOBAL s0 median TTD udp_flood / either == step 29  8.0 vs 8.0
- PASS  prereg reproduction: GLOBAL s0 median TTD port_scan / flow == step 29  0.04241299629211426 vs 0.04241299629211426
- PASS  prereg reproduction: GLOBAL s0 median TTD port_scan / rate_guard == step 29  None vs nan
- PASS  prereg reproduction: GLOBAL s0 median TTD port_scan / either == step 29  0.04241299629211426 vs 0.04241299629211426
- PASS  config.py / class_map.json sha256 unchanged start -> end  {'config/config.py': 'c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf', 'config/class_map.json': '64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580'}

verify_v2_lock OK at start and end; config/config.py c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf, config/class_map.json 64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580 (unchanged: True).
