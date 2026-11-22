# DRAFT -- proposed Phase 3 Amendment 3: episode start = attacker-first-packet start

**Status: DRAFT ONLY. Not pinned, not referenced by any code, not adopted.** Proposed by diag_03 **after the Phase 3 results were seen** (the 6 rate-guard alerts on no episode, `docs/V2_DECISIONS.md` D87). Any adoption would have to be pinned before it is applied to a split it has not yet been evaluated on (test); on val it can only ever be a post-hoc re-description.

## Proposed change (applies to BOTH paths: flow model and rate guard)

Prereg section 3 (ground-truth episodes): episodes are still grouped as now (attack flows per (class, protected device), new episode after a > 60 s gap; episode end = latest end). The **episode start** becomes the earlier of (a) the first labelled flow's start and (b) the first packet from the attacker / testbed identity (V1 step 13's rule, evaluation-only ground truth) into the episode's device within the 60 s before (a). Every other rule (detection window end + 120 s, incident outcome, time-to-detect = first alert - episode start, hours) is unchanged.

## Why (diag_03 part A)

- 6 of 6 rate-guard alerts on no episode pass all three pre-fixed checks (source >= 90 % attacker identity, alert within 10 s before a same-device episode's labelled start, family == the episode's majority family); 0 fail at least one.
- Val episodes with any attacker packet into their device in the 60 s before the labelled start: 1 of 13; the change moves only: ep000 (syn_flood, shift 8.7 s, lookback clipped by the val window start).
- Mechanism seen in the data (report-only): ep000: the capture's val window opens at 1661795214.3, the capture's first val flow starts at 1661795215, the device's first val flow at 1661795220, its first attacker packet in val at 1661795214.3. Packets are split by packet time and flows by flow start time (08's rule), so packets of flows that started in gap@train|val still reach the device inside the val window, while those flows are not val flows. The labelled episode then starts at the first flow that STARTED in val. This explanation is inferred: diag_03 did not read gap-window flows.

## Alternatives (not evaluated here)

- Leave the episode start as pre-registered and report the boundary alerts as 'attack packets of flows outside the val split' (sender-based, as D87 / V1 13c do).
- Make the packet path and the flow path use the same cut: e.g. drop val packets of 5-tuples whose flow started before the val cut. This changes the data the runtime sees, so it would need its own pre-registration.

## Effect on every Phase 3 headline number (val; from diag_03 A2)

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

Per-episode start shift:

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

## Risks / reasons against

- It is chosen after seeing the result it removes, so on val it cannot count as a pre-registered result; the prereg numbers stay primary and both are reported.
- An earlier start lengthens every time-to-detect that is measured from it (see the table), so it is not a free improvement.
- The attacker identity is evaluation-only ground truth; the runtime never knows it, so the change affects only how episodes are scored, never what the runtime does.
