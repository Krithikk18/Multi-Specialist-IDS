# diag_03 part B -- misclassified incidents (READ-ONLY, val)

### B0. Rules, fixed before any numbers. Write them verbatim at the top of results/diag_03/B_summary.md first.
A misclassified incident = an incident overlapping an episode of a different attack class on the same device (prereg Phase 3 definition).
Each flow that contributed an alert to such an incident is assigned to the FIRST hypothesis it matches, in this order:
- **H1 unfixed reversal:** a TCP flow whose source endpoint (after normalisation) is the protected device and whose destination is
  the attacker host, with orientation_flipped = False. A reversal R3 didn't catch, e.g. SYN/ACK-first.
- **H2 label boundary:** the flow's start lies within 10 s of its episode's labelled start or end.
- **H3 collateral traffic:** the flow's true label is benign, or it is not attacker↔device traffic, but it lies inside an attack episode on
  that device (the device's own traffic disturbed by the attack).
- **H4 genuine confusion:** everything else.
Verdict: a hypothesis "explains" the misclassified incidents iff it covers ≥ 80% of their alert flows, pooled over all 10 runs (GLOBAL + ROUTED × 5 seeds).
If none reaches 80%, say so and give the split.

---

## Results (computed after the rules above were written)

Inputs: step 28 run `20261122T050150Z` (rerun_full); incidents classified with step 29's own `incident_outcomes`; contributing flow = an alert with policy decision opened / extended for that incident. Attacker host = V1 step 13 / D74 identity. 'Its episode' = the overlapped episode whose [start, end + 120 s] holds the flow's start (else the nearest); see choices.md.

### Counts per run

| run | misclassified incidents | alert flows | H1 | H2 | H3 | H4 |
|---|---|---|---|---|---|---|
| GLOBAL_s0 | 3 | 189 | 187 | 0 | 0 | 2 |
| GLOBAL_s1 | 4 | 71 | 69 | 0 | 0 | 2 |
| GLOBAL_s2 | 3 | 220 | 218 | 0 | 0 | 2 |
| GLOBAL_s3 | 4 | 199 | 196 | 0 | 0 | 3 |
| GLOBAL_s4 | 3 | 202 | 200 | 0 | 0 | 2 |
| ROUTED_s0 | 3 | 217 | 215 | 0 | 0 | 2 |
| ROUTED_s1 | 3 | 223 | 221 | 0 | 0 | 2 |
| ROUTED_s2 | 3 | 218 | 216 | 0 | 0 | 2 |
| ROUTED_s3 | 4 | 223 | 220 | 0 | 0 | 3 |
| ROUTED_s4 | 3 | 222 | 220 | 0 | 0 | 2 |
| **pooled** | **33** | **1984** | **1962** (98.9%) | **0** (0.0%) | **0** (0.0%) | **22** (1.1%) |

### Verdict

- **H1 unfixed reversal** covers >= 80 % of the pooled alert flows and explains the misclassified incidents.
- Per incident (report-only, the hypothesis holding most of its flows): H1 30, H2 0, H3 0, H4 3 of 33 incidents.
- Sensitivity (report-only): 0 H4 flows would be H3 if 'inside an episode' included the 120 s detection slack.

### Incidents (`B_incidents.csv`)

| run | incident | predicted | device (group) | episode(s), true class | first - ep start s | last - ep end s | alert flows | H1/H2/H3/H4 |
|---|---|---|---|---|---|---|---|---|
| GLOBAL_s0 | inc000003 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 175 | 173/0/0/2 |
| GLOBAL_s0 | inc000011 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| GLOBAL_s0 | inc000016 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| GLOBAL_s1 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 56 | 55/0/0/1 |
| GLOBAL_s1 | inc000003 | udp_flood | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +188.3 | -19.9 | 1 | 0/0/0/1 |
| GLOBAL_s1 | inc000009 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| GLOBAL_s1 | inc000014 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| GLOBAL_s2 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 206 | 204/0/0/2 |
| GLOBAL_s2 | inc000008 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| GLOBAL_s2 | inc000013 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| GLOBAL_s3 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 184 | 182/0/0/2 |
| GLOBAL_s3 | inc000003 | udp_flood | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +41.6 | -166.6 | 1 | 0/0/0/1 |
| GLOBAL_s3 | inc000009 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| GLOBAL_s3 | inc000014 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| GLOBAL_s4 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 188 | 186/0/0/2 |
| GLOBAL_s4 | inc000008 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| GLOBAL_s4 | inc000013 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| ROUTED_s0 | inc000003 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 203 | 201/0/0/2 |
| ROUTED_s0 | inc000012 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| ROUTED_s0 | inc000017 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| ROUTED_s1 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 209 | 207/0/0/2 |
| ROUTED_s1 | inc000009 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| ROUTED_s1 | inc000014 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| ROUTED_s2 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 204 | 202/0/0/2 |
| ROUTED_s2 | inc000009 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| ROUTED_s2 | inc000014 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| ROUTED_s3 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 208 | 206/0/0/2 |
| ROUTED_s3 | inc000003 | udp_flood | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +88.7 | -119.5 | 1 | 0/0/0/1 |
| ROUTED_s3 | inc000010 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| ROUTED_s3 | inc000015 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |
| ROUTED_s4 | inc000002 | port_scan | AMCREST WiFi Camera `9c:8e:cd:1d:ab:9f` (G1) | ep001, syn_flood | +12.2 | -1.0 | 208 | 206/0/0/2 |
| ROUTED_s4 | inc000009 | syn_flood | Amazon Echo Show `2c:71:ff:05:f1:15` (G1) | ep006, port_scan | +0.2 | -0.0 | 5 | 5/0/0/0 |
| ROUTED_s4 | inc000014 | syn_flood | LG Smart TV `ac:f1:08:4e:00:82` (G1) | ep009, port_scan | +0.2 | -1.0 | 9 | 9/0/0/0 |

### Stability across seeds

**GLOBAL**

| incident signature (predicted@device@episodes) | seeds | stable (all 5) |
|---|---|---|
| port_scan@9c:8e:cd:1d:ab:9f@ep001 | [0, 1, 2, 3, 4] | True |
| syn_flood@2c:71:ff:05:f1:15@ep006 | [0, 1, 2, 3, 4] | True |
| syn_flood@ac:f1:08:4e:00:82@ep009 | [0, 1, 2, 3, 4] | True |
| udp_flood@9c:8e:cd:1d:ab:9f@ep001 | [1, 3] | False |

**ROUTED**

| incident signature (predicted@device@episodes) | seeds | stable (all 5) |
|---|---|---|
| port_scan@9c:8e:cd:1d:ab:9f@ep001 | [0, 1, 2, 3, 4] | True |
| syn_flood@2c:71:ff:05:f1:15@ep006 | [0, 1, 2, 3, 4] | True |
| syn_flood@ac:f1:08:4e:00:82@ep009 | [0, 1, 2, 3, 4] | True |
| udp_flood@9c:8e:cd:1d:ab:9f@ep001 | [3] | False |

### Context for H1 (report-only, not part of the verdict): the H1 predicate on ALL labelled flows of the overlapped episodes (`B_h1_base_rate.csv`)

| episode | class | labelled flows | match H1 predicate | GLOBAL s0: own class among matching / non-matching | ROUTED s0: own class among matching / non-matching |
|---|---|---|---|---|---|
| ep001 | syn_flood | 50,103 | 363 (0.7%) | 46.3% / 100.0% | 43.0% / 100.0% |
| ep006 | port_scan | 2,000 | 5 (0.2%) | 0.0% / 100.0% | 0.0% / 100.0% |
| ep009 | port_scan | 1,998 | 9 (0.5%) | 0.0% / 100.0% | 0.0% / 100.0% |

Predicted classes of the matching flows: ep001 GLOBAL s0 {'port_scan': 178, 'syn_flood': 168, 'benign': 17}; ep006 GLOBAL s0 {'syn_flood': 5}; ep009 GLOBAL s0 {'syn_flood': 9}

### GLOBAL vs ROUTED

- in both: ['port_scan@9c:8e:cd:1d:ab:9f@ep001', 'syn_flood@2c:71:ff:05:f1:15@ep006', 'syn_flood@ac:f1:08:4e:00:82@ep009', 'udp_flood@9c:8e:cd:1d:ab:9f@ep001']
- GLOBAL only: none
- ROUTED only: none

### Confusion (episode true class -> incident predicted class), incidents pooled over 10 runs

| true \ predicted | syn_flood | udp_flood | port_scan |
|---|---|---|---|
| syn_flood | 0 | 3 | 10 |
| udp_flood | 0 | 0 | 0 |
| port_scan | 20 | 0 | 0 |

### Figures

- `figures/B_hypothesis_share.png`
- `figures/B_confusion.png`
- `figures/B_h1_profile.png`

### Checks

- PASS  GLOBAL_s0 inc000003: contributing flows == incident n_alerts  175 vs 175
- PASS  GLOBAL_s0 inc000011: contributing flows == incident n_alerts  5 vs 5
- PASS  GLOBAL_s0 inc000016: contributing flows == incident n_alerts  9 vs 9
- PASS  GLOBAL_s1 inc000002: contributing flows == incident n_alerts  56 vs 56
- PASS  GLOBAL_s1 inc000003: contributing flows == incident n_alerts  1 vs 1
- PASS  GLOBAL_s1 inc000009: contributing flows == incident n_alerts  5 vs 5
- PASS  GLOBAL_s1 inc000014: contributing flows == incident n_alerts  9 vs 9
- PASS  GLOBAL_s2 inc000002: contributing flows == incident n_alerts  206 vs 206
- PASS  GLOBAL_s2 inc000008: contributing flows == incident n_alerts  5 vs 5
- PASS  GLOBAL_s2 inc000013: contributing flows == incident n_alerts  9 vs 9
- PASS  GLOBAL_s3 inc000002: contributing flows == incident n_alerts  184 vs 184
- PASS  GLOBAL_s3 inc000003: contributing flows == incident n_alerts  1 vs 1
- PASS  GLOBAL_s3 inc000009: contributing flows == incident n_alerts  5 vs 5
- PASS  GLOBAL_s3 inc000014: contributing flows == incident n_alerts  9 vs 9
- PASS  GLOBAL_s4 inc000002: contributing flows == incident n_alerts  188 vs 188
- PASS  GLOBAL_s4 inc000008: contributing flows == incident n_alerts  5 vs 5
- PASS  GLOBAL_s4 inc000013: contributing flows == incident n_alerts  9 vs 9
- PASS  ROUTED_s0 inc000003: contributing flows == incident n_alerts  203 vs 203
- PASS  ROUTED_s0 inc000012: contributing flows == incident n_alerts  5 vs 5
- PASS  ROUTED_s0 inc000017: contributing flows == incident n_alerts  9 vs 9
- PASS  ROUTED_s1 inc000002: contributing flows == incident n_alerts  209 vs 209
- PASS  ROUTED_s1 inc000009: contributing flows == incident n_alerts  5 vs 5
- PASS  ROUTED_s1 inc000014: contributing flows == incident n_alerts  9 vs 9
- PASS  ROUTED_s2 inc000002: contributing flows == incident n_alerts  204 vs 204
- PASS  ROUTED_s2 inc000009: contributing flows == incident n_alerts  5 vs 5
- PASS  ROUTED_s2 inc000014: contributing flows == incident n_alerts  9 vs 9
- PASS  ROUTED_s3 inc000002: contributing flows == incident n_alerts  208 vs 208
- PASS  ROUTED_s3 inc000003: contributing flows == incident n_alerts  1 vs 1
- PASS  ROUTED_s3 inc000010: contributing flows == incident n_alerts  5 vs 5
- PASS  ROUTED_s3 inc000015: contributing flows == incident n_alerts  9 vs 9
- PASS  ROUTED_s4 inc000002: contributing flows == incident n_alerts  208 vs 208
- PASS  ROUTED_s4 inc000009: contributing flows == incident n_alerts  5 vs 5
- PASS  ROUTED_s4 inc000014: contributing flows == incident n_alerts  9 vs 9
- PASS  every contributing alert flow has the runtime's top-3 SHAP in alerts.jsonl  1984 / 1984
- PASS  misclassified incidents pooled == sum of step 29 per-run counts  33
- PASS  config.py / class_map.json sha256 unchanged start -> end  {'config/config.py': 'c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf', 'config/class_map.json': '64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580'}
- PASS  10 per-run hard checks (incident outcomes == step 29), listed in B_run.json

verify_v2_lock OK at start and end; config/config.py c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf, config/class_map.json 64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580 (unchanged: True).
