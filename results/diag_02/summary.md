# diag_02 -- orientation-normaliser rule check -- PASS

- run `20261121T072536Z`; READ-ONLY: train / val via common/phase2_data.load_split (test never read); seed-0 primary models of step 22 run `20261120T144232Z` loaded read-only (sha256 checked) and used to PREDICT val; top-10 SHAP features from step 25 run `20261120T183817Z`; every flip is in memory; nothing trained, no dataset version, no existing file changed.
- rule **R1 (proposed)**: `FWD Init Win Bytes == 0 AND Bwd Init Win Bytes > 0`. Variant **R2**: R1 AND `SYN Flag Count >= 1` (reported, not part of the verdict).
- swap map from CICFlowMeter's `BasicFlow.java` (reviewed source, sha256 `408feaefe77ef323c4279e68fbec30763cd9fc630aa75310ed1cf63e0cac0752`): `orientation_map_proposed.json` (for review; NOT in config/).

## Verdict rule (fixed before the numbers)

**PASS** only if all four hold:
- (a) R1 flags >= 95 % of G1 val port_scan flows that have FWD Init Win Bytes = 0;
- (b) flagged benign <= 1 % of benign in every split x group (or the excess is shown in T4 to be genuine reversals);
- (c) R1 never flags a non-TCP flow;
- (d) the swap map has no UNRESOLVED feature, or each unresolved one has a stated safe default.
Reported separately (not part of PASS): the G1 specialist's port_scan recall on flipped G1 val, and whether ROUTED now >= FLAT_GLOBAL.

## Verdict

- **PASS**
- (a) PASS: R1 flags 4,348 of 4,348 G1 val port_scan flows with FWD Init Win Bytes = 0 = **100.00 %** (>= 95 %).
- (b) PASS: worst split x group = val G1: 181 of 35,833 benign = **0.505 %** (<= 1 %).
- (c) PASS: non-TCP flows flagged = {'train': 0, 'val': 0}.
- (d) PASS: UNRESOLVED entries = none; the 3 unpaired fields and the asymmetric init-window pair carry a stated default and exactness condition (T1).

Reported separately (lower bound: models trained on UNFLIPPED train, not retrained):

- G1 specialist port_scan recall on G1 val: original **0.5663** -> flipped (R1) **0.9982**.
- ROUTED >= FLAT_GLOBAL on flipped val: macro-F1 all **NO**, non-rare **NO** (numbers in T6).

## T1 -- swap map (70 features + identity)

- 32 features in 16 exact forward/backward pairs; 2 in 1 asymmetric pair; 32 direction-free; 1 derived (recomputed); 3 unpaired with a stated default; **UNRESOLVED: 0**.
- identity: swap Src IP <-> Dst IP, Src Port <-> Dst Port, src_mac <-> dst_mac; rebuild Flow ID (format 'src-dst-sport-dport-proto' matches train 100.0 %, val 100.0 % of rows); keep device / device_mac / owner_mac / group / timestamps (dataset attribution, orientation-free).

| feature | class | partner / handling | exact when |
|---|---|---|---|
| Total Fwd Packet | pair | <-> Total Bwd packets | always |
| Total Length of Fwd Packet | pair | <-> Total Length of Bwd Packet | always |
| Fwd Packet Length Max | pair | <-> Bwd Packet Length Max | always |
| Fwd Packet Length Min | pair | <-> Bwd Packet Length Min | always |
| Fwd Packet Length Mean | pair | <-> Bwd Packet Length Mean | always |
| Fwd Packet Length Std | pair | <-> Bwd Packet Length Std | always |
| Fwd IAT Total | pair | <-> Bwd IAT Total | always |
| Fwd IAT Mean | pair | <-> Bwd IAT Mean | always |
| Fwd IAT Std | pair | <-> Bwd IAT Std | always |
| Fwd IAT Max | pair | <-> Bwd IAT Max | always |
| Fwd IAT Min | pair | <-> Bwd IAT Min | always |
| Fwd PSH Flags | **unpaired** | rest = PSH Flag Count - Fwd PSH Flags (PSH among the other packets). rest == 0 -> 0 (exact); old Total Fwd Packet == 1 and rest >= old Total Bwd packets -> 1 (every backward packet has PSH; exact); otherwise 0 | rest == 0, or (old Total Fwd Packet == 1 and rest >= old Total Bwd packets) |
| Fwd Header Length | pair | <-> Bwd Header Length | always |
| Fwd Packets/s | pair | <-> Bwd Packets/s | always |
| Down/Up Ratio | **derived** | recompute floor(new_bwd / new_fwd) = floor(old Total Fwd Packet / old Total Bwd packets) (Java integer division `backward.size()/forward.size()`; 0 if no forward packet) | always |
| Fwd Segment Size Avg | pair | <-> Bwd Segment Size Avg | always |
| Subflow Fwd Packets | pair | <-> Subflow Bwd Packets | always |
| Subflow Fwd Bytes | pair | <-> Subflow Bwd Bytes | always |
| FWD Init Win Bytes | **asymmetric pair** | <-> Bwd Init Win Bytes -- first fwd packet's window | old Total Bwd packets == 1 |
| Bwd Init Win Bytes | **asymmetric pair** | <-> FWD Init Win Bytes -- LAST bwd packet's window | old Total Fwd Packet == 1 |
| Fwd Act Data Pkts | **unpaired** | old Total Bwd packets <= 1 -> 0; old Bwd Packet Length Max == 0 -> 0; old Bwd Packet Length Min >= 1 -> old Total Bwd packets - 1 (all exact); otherwise the lower bound max(0, ceil(old Total Length of Bwd Packet / old Bwd Packet Length Max) - 1) | old Total Bwd packets <= 1, or backward payloads all 0, or all >= 1 |
| Fwd Seg Size Min | **unpaired** | old Total Bwd packets == 1: old Bwd Header Length (exact); > 1: floor(old Bwd Header Length / old Total Bwd packets) (mean header >= true minimum: approximate); 0 backward packets: 0 | old Total Bwd packets == 1 |

Direction-free (32): Protocol, Flow Duration, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Packet Length Min, Packet Length Max, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, CWR Flag Count, ECE Flag Count, Average Packet Size, Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min.

Ambiguous fields resolved from the source:
- **Subflow Fwd/Bwd Packets / Bytes**: direction count / sfCount, and sfCount (gaps > 1 s) is direction-free -> exact pairs.
- **Fwd PSH Flags**: incremented only in firstPacket() -> 'the first forward packet has PSH'; Bwd PSH Flags is structurally 0 (dropped); no partner -> unpaired.
- **Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg**: reference-equality bug sends every packet to the 'backward' bulk counters -> they describe all packets, direction-free (the Fwd bulk features are structurally 0).
- **Fwd Seg Size Min**: minimum header bytes of forward packets, no backward counterpart -> unpaired.
- **FWD / Bwd Init Win Bytes**: first forward packet vs LAST backward packet -> asymmetric.
- **Active / Idle**, **Flow IAT**: computed on every packet's timestamp -> direction-free; **Fwd / Bwd IAT**: exact pairs.
- **Down/Up Ratio**: Java integer division of the packet counts -> recomputed.

Exactness on the 4,595 val rows R1 flags: FWD Init Win Bytes 4,414 (96.1 %); Bwd Init Win Bytes 4,528 (98.5 %); Fwd Seg Size Min 4,414 (96.1 %); Fwd Act Data Pkts 4,443 (96.7 %); Fwd PSH Flags 4,441 (96.6 %); ALL_FIELDS 4,368 (95.1 %). G1 val port_scan flagged rows exact in every field: 4,348 of 4,348.

## T2 -- what the rule flips

| split | group | class | n | R1 flagged | R1 % | R2 flagged | R2 % |
|---|---|---|---|---|---|---|---|
| train | G1 | benign | 120,028 | 451 | 0.376 | 20 | 0.017 |
| train | G1 | syn_flood | 200,605 | 146 | 0.073 | 146 | 0.073 |
| train | G1 | udp_flood | 95 | 2 | 2.105 | 2 | 2.105 |
| train | G1 | port_scan | 50,472 | 2,579 | 5.110 | 2,579 | 5.110 |
| train | G2 | benign | 16,279 | 21 | 0.129 | 0 | 0.000 |
| train | G2 | syn_flood | 199,985 | 0 | 0.000 | 0 | 0.000 |
| train | G2 | port_scan | 43,218 | 0 | 0.000 | 0 | 0.000 |
| train | GEN | benign | 1,155 | 0 | 0.000 | 0 | 0.000 |
| train | GEN | port_scan | 4,356 | 336 | 7.713 | 336 | 7.713 |
| val | G1 | benign | 35,833 | 181 | 0.505 | 0 | 0.000 |
| val | G1 | syn_flood | 50,103 | 64 | 0.128 | 64 | 0.128 |
| val | G1 | udp_flood | 17 | 0 | 0.000 | 0 | 0.000 |
| val | G1 | port_scan | 7,763 | 4,348 | 56.009 | 4,348 | 56.009 |
| val | G2 | benign | 3,061 | 2 | 0.065 | 0 | 0.000 |
| val | G2 | syn_flood | 50,074 | 0 | 0.000 | 0 | 0.000 |
| val | G2 | port_scan | 10,416 | 0 | 0.000 | 0 | 0.000 |
| val | GEN | benign | 291 | 0 | 0.000 | 0 | 0.000 |

Benign per device (devices with >= 1 R1-flagged flow; top 12 per split):

| split | group | device | benign n | R1 flagged | R1 % | R2 flagged |
|---|---|---|---|---|---|---|
| train | G1 | Fibaro Home Center Lite | 20,047 | 72 | 0.36 | 0 |
| train | G1 | Amazon Alexa Echo Dot 2 | 1,254 | 71 | 5.66 | 7 |
| train | G1 | Rbcior Camera | 1,668 | 56 | 3.36 | 0 |
| train | G1 | Aeotec Smart Home Hub | 2,223 | 39 | 1.75 | 0 |
| train | G1 | SmartThings Hub | 2,240 | 38 | 1.70 | 0 |
| train | G1 | LG Smart TV | 2,409 | 29 | 1.20 | 12 |
| train | G1 | TP-Link Tapo Camera | 3,836 | 23 | 0.60 | 0 |
| train | G1 | Wyze Camera | 11,780 | 21 | 0.18 | 0 |
| train | G1 | Amazon Echo Show | 5,212 | 19 | 0.36 | 0 |
| train | G1 | Amazon Alexa Echo Studio | 3,457 | 19 | 0.55 | 0 |
| train | G1 | Unidentified Amazon device (1c:12:b0) | 1,829 | 16 | 0.87 | 0 |
| train | G1 | Google Nest Mini Speaker | 6,171 | 13 | 0.21 | 0 |
| val | G1 | Fibaro Home Center Lite | 15,014 | 101 | 0.67 | 0 |
| val | G1 | LG Smart TV | 1,121 | 11 | 0.98 | 0 |
| val | G1 | Rbcior Camera | 213 | 11 | 5.16 | 0 |
| val | G1 | Google Nest Mini Speaker | 1,210 | 9 | 0.74 | 0 |
| val | G1 | SmartThings Hub | 407 | 9 | 2.21 | 0 |
| val | G1 | TP-Link Tapo Camera | 537 | 7 | 1.30 | 0 |
| val | G1 | Aeotec Smart Home Hub | 406 | 7 | 1.72 | 0 |
| val | G1 | Amazon Echo Show | 1,117 | 6 | 0.54 | 0 |
| val | G1 | Amazon Alexa Echo Dot 1 | 518 | 5 | 0.97 | 0 |
| val | G1 | Arlo Q Indoor Camera | 893 | 4 | 0.45 | 0 |
| val | G1 | Amazon Alexa Echo Dot 2 | 260 | 3 | 1.15 | 0 |
| val | G1 | Wyze Camera | 1,730 | 2 | 0.12 | 0 |

Edge cases:

- train: protocol column `Protocol` values {'0': 1979, '6': 551783, '17': 82431}; both windows 0 by protocol {'0': 1979, '6': 1287, '17': 82431} (TCP by class {'benign': 1258, 'syn_flood': 28, 'udp_flood': 1, 'port_scan': 0}); Bwd window missing 0 / negative 0; FWD window missing 0 / negative 0; **non-TCP flagged R1 0**, R2 0; non-TCP rows with any non-zero window 0; a `Protocol == 6` guard changes 0 R1 flags.
- val: protocol column `Protocol` values {'0': 489, '6': 137593, '17': 19476}; both windows 0 by protocol {'0': 489, '6': 306, '17': 19476} (TCP by class {'benign': 300, 'syn_flood': 6, 'udp_flood': 0, 'port_scan': 0}); Bwd window missing 0 / negative 0; FWD window missing 0 / negative 0; **non-TCP flagged R1 0**, R2 0; non-TCP rows with any non-zero window 0; a `Protocol == 6` guard changes 0 R1 flags.

Independent orientation signal for attack rows (source MAC == the attacked device's MAC = 'victim first'):

| split | class | rule | n | victim-first | flagged | flagged & victim-first | flagged, not victim-first | victim-first, not flagged |
|---|---|---|---|---|---|---|---|---|
| train | syn_flood | R1 | 400,590 | 6,887 | 146 | 0 | 146 | 6,887 |
| train | syn_flood | R2 | 400,590 | 6,887 | 146 | 0 | 146 | 6,887 |
| train | udp_flood | R1 | 95 | 14 | 2 | 0 | 2 | 14 |
| train | udp_flood | R2 | 95 | 14 | 2 | 0 | 2 | 14 |
| train | port_scan | R1 | 98,046 | 14,726 | 2,915 | 2,915 | 0 | 11,811 |
| train | port_scan | R2 | 98,046 | 14,726 | 2,915 | 2,915 | 0 | 11,811 |
| val | syn_flood | R1 | 100,177 | 364 | 64 | 0 | 64 | 364 |
| val | syn_flood | R2 | 100,177 | 364 | 64 | 0 | 64 | 364 |
| val | udp_flood | R1 | 17 | 0 | 0 | 0 | 0 | 0 |
| val | udp_flood | R2 | 17 | 0 | 0 | 0 | 0 | 0 |
| val | port_scan | R1 | 18,179 | 5,900 | 4,348 | 4,348 | 0 | 1,552 |
| val | port_scan | R2 | 18,179 | 5,900 | 4,348 | 4,348 | 0 | 1,552 |

- FWD Init Win Bytes of victim-first attack flows R1 does NOT flag (top values): train: {"syn_flood": {"512": 3822, "65535": 1695, "29200": 1367, "4380": 3}, "udp_flood": {"29200": 5, "503": 4, "28960": 4, "470": 1}, "port_scan": {"4380": 11075, "2920": 671, "28694": 55, "29200": 7, "14600": 3}}; val: {"syn_flood": {"14600": 346, "512": 17, "4380": 1}, "port_scan": {"4380": 1286, "2920": 240, "29200": 9, "65535": 5, "5744": 5, "14600": 5}}

## T3 -- coverage of the known errors

- G1 val port_scan: 7,763 flows, 4,348 with FWD Init Win Bytes = 0.

| rule | flagged of the FWD-win-0 flows | % | specialist errors on G1 val (all) flagged | % | port_scan -> syn_flood errors flagged | % |
|---|---|---|---|---|---|---|
| R1 | 4,348 / 4,348 | 100.00 | 3,363 / 3,623 | 92.82 | 3,353 / 3,367 | 99.58 |
| R2 | 4,348 / 4,348 | 100.00 | 3,363 / 3,623 | 92.82 | 3,353 / 3,367 | 99.58 |

## T4 -- safety on benign: profile of flagged benign flows

| split, rule | flagged | devices | TCP | SYN = 0 | RST >= 1 | FIN >= 1 | 1 fwd pkt | fwd payload 0 | Dst Port < 1024 | Src Port < 1024 | device is source | duration q50 [q5, q95] us | bwd pkts q50 [q95] |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| train, R1 | 472 | 24 | 472 | 95.8 % | 100.0 % | 82.8 % | 91.5 % | 100.0 % | 57.2 % | 12.1 % | 84.1 % | 64840.5 [3590.15, 5.14804e+06] | 2 [5] |
| train, R2 | 20 | 3 | 20 | 0.0 % | 100.0 % | 0.0 % | 40.0 % | 100.0 % | 5.0 % | 0.0 % | 100.0 % | 503804 [48338.8, 2.40863e+06] | 1 [4.1] |
| val, R1 | 183 | 16 | 183 | 100.0 % | 100.0 % | 85.8 % | 96.7 % | 100.0 % | 83.1 % | 7.1 % | 91.3 % | 42782 [10039.2, 182788] | 2 [6] |
| val, R2 | 0 | | | | | | | | | | | | |
- reference, all train benign TCP (53,114): SYN = 0 60.9 %, RST >= 1 11.3 %, FWD Init Win Bytes = 0 3.3 %.
- reference, all val benign TCP (19,227): SYN = 0 57.6 %, RST >= 1 7.2 %, FWD Init Win Bytes = 0 2.5 %.
- train|R1: top devices {'Fibaro Home Center Lite': 72, 'Amazon Alexa Echo Dot 2': 71, 'Rbcior Camera': 56, 'Aeotec Smart Home Hub': 39, 'SmartThings Hub': 38, 'LG Smart TV': 29, 'TP-Link Tapo Camera': 23, 'Wyze Camera': 21}; top Dst Port {'443': 267, '55443': 45, '8443': 15, '5000': 11, '52646': 9}; top Src Port {'443': 56, '55443': 34, '8009': 12, '50920': 11, '34186': 4}.
- val|R1: top devices {'Fibaro Home Center Lite': 101, 'Rbcior Camera': 11, 'LG Smart TV': 11, 'SmartThings Hub': 9, 'Google Nest Mini Speaker': 9, 'TP-Link Tapo Camera': 7, 'Aeotec Smart Home Hub': 7, 'Amazon Echo Show': 6}; top Dst Port {'443': 151, '4431': 9, '8009': 3, '54095': 1, '55443': 1}; top Src Port {'443': 13, '55443': 5, '40414': 2, '39748': 2, '40114': 2}.

Judgement: see the final report / section 'T4 judgement' below.

### T4 judgement

- train: 472 of 137,462 benign flagged (0.343 %); TCP 472; 95.8 % carry no SYN, 100.0 % a RST, 82.8 % a FIN, 91.5 % a single forward packet. -> mostly connection TAILS (a window-0 RST written first, the peer's FIN/ACKs after), not openers: genuine 'first packet is not the initiator's' cases. But 57.2 % have a service port (< 1024) as Dst Port and 84.1 % the device as source: the current source is usually the CLIENT, so the swap makes the SERVER the source -- a mis-flip in client/server terms. R2 (needs a SYN) flags 20 of them.
- val: 183 of 39,185 benign flagged (0.467 %); TCP 183; 100.0 % carry no SYN, 100.0 % a RST, 85.8 % a FIN, 96.7 % a single forward packet. -> mostly connection TAILS (a window-0 RST written first, the peer's FIN/ACKs after), not openers: genuine 'first packet is not the initiator's' cases. But 83.1 % have a service port (< 1024) as Dst Port and 91.3 % the device as source: the current source is usually the CLIENT, so the swap makes the SERVER the source -- a mis-flip in client/server terms. R2 (needs a SYN) flags 0 of them.

## T5 -- does flipping make val look like train? (in memory)

FWD Init Win Bytes shares (G1 val port_scan (n=7,763) vs train port_scan (all groups, n=98,046)):

| value | train before | val before | train after | val after | train G1 before | train G1 after |
|---|---|---|---|---|---|---|
| 0 | 3.0 % | 56.0 % | 0.0 % | 0.0 % | 5.1 % | 0.0 % |
| 1024 | 85.0 % | 43.7 % | 88.0 % | 99.8 % | 94.9 % | 100.0 % |
| 2920 | 0.7 % | 0.0 % | 0.7 % | 0.0 % | 0.0 % | 0.0 % |
| 4380 | 11.3 % | 0.0 % | 11.3 % | 0.0 % | 0.0 % | 0.0 % |
| 29200 | 0.0 % | 0.1 % | 0.0 % | 0.1 % | 0.0 % | 0.0 % |
| other | 0.1 % | 0.1 % | 0.1 % | 0.1 % | 0.0 % | 0.0 % |

KS statistic, G1 val port_scan vs train port_scan, for the top-10 SHAP features of the G1 specialist (after = normaliser applied to train and val; last column = flipped val vs the raw train the models saw):

| feature | reference | before | after (both flipped) | flipped val vs raw train |
|---|---|---|---|---|
| FWD Init Win Bytes | train all groups | 0.5304 | 0.1180 | 0.1180 |
| FWD Init Win Bytes | train G1 | 0.5090 | 0.0022 | 0.0511 |
| SYN Flag Count | train all groups | 0.0032 | 0.0032 | 0.0032 |
| SYN Flag Count | train G1 | 0.0032 | 0.0032 | 0.0032 |
| Flow IAT Min | train all groups | 0.2875 | 0.2875 | 0.2875 |
| Flow IAT Min | train G1 | 0.2832 | 0.2832 | 0.2832 |
| Packet Length Max | train all groups | 0.0000 | 0.0000 | 0.0000 |
| Packet Length Max | train G1 | 0.0000 | 0.0000 | 0.0000 |
| Fwd Header Length | train all groups | 0.4101 | 0.1202 | 0.1500 |
| Fwd Header Length | train G1 | 0.5090 | 0.0006 | 0.0511 |
| Bwd Packets/s | train all groups | 0.3711 | 0.3711 | 0.3711 |
| Bwd Packets/s | train G1 | 0.4446 | 0.4446 | 0.4446 |
| Fwd Seg Size Min | train all groups | 0.4101 | 0.1203 | 0.1500 |
| Fwd Seg Size Min | train G1 | 0.5084 | 0.0006 | 0.0517 |
| Flow Packets/s | train all groups | 0.3702 | 0.3702 | 0.3702 |
| Flow Packets/s | train G1 | 0.4433 | 0.4433 | 0.4433 |
| Flow Duration | train all groups | 0.2858 | 0.2858 | 0.2858 |
| Flow Duration | train G1 | 0.2816 | 0.2816 | 0.2816 |
| Fwd IAT Min | train all groups | 0.0008 | 0.0008 | 0.0008 |
| Fwd IAT Min | train G1 | 0.0009 | 0.0009 | 0.0009 |

## T6 -- effect on the EXISTING models (predict only; seed 0)

**Lower bound**: every model was trained on UNFLIPPED train; retraining on normalised data is the real test.

- original-val metrics reproduce step 23 seed 0: max |diff| = 0.

Per model, step 23's evaluation rows (specialist: own-group benign + every attack row; GLOBAL: all val):

| model | subset | condition | recall benign | recall syn_flood | recall udp_flood | recall port_scan | false alarms (benign -> attack) |
|---|---|---|---|---|---|---|---|
| GLOBAL__sqrt | all | original | 0.9998 | 0.9976 | 0.5294 | 0.8264 | 7 / 39,185 |
| GLOBAL__sqrt | all | flipped R1 | 0.9998 | 0.9973 | 0.5294 | 0.9992 | 7 / 39,185 |
| GLOBAL__sqrt | all | flipped R2 | 0.9998 | 0.9973 | 0.5294 | 0.9992 | 7 / 39,185 |
| GLOBAL__sqrt | G1 | original | 0.9998 | 0.9952 | 0.5294 | 0.5936 | 7 / 35,833 |
| GLOBAL__sqrt | G1 | flipped R1 | 0.9998 | 0.9946 | 0.5294 | 0.9982 | 7 / 35,833 |
| GLOBAL__sqrt | G1 | flipped R2 | 0.9998 | 0.9946 | 0.5294 | 0.9982 | 7 / 35,833 |
| GLOBAL__sqrt | G2 | original | 1.0000 | 1.0000 | n/a | 1.0000 | 0 / 3,061 |
| GLOBAL__sqrt | G2 | flipped R1 | 1.0000 | 1.0000 | n/a | 1.0000 | 0 / 3,061 |
| GLOBAL__sqrt | G2 | flipped R2 | 1.0000 | 1.0000 | n/a | 1.0000 | 0 / 3,061 |
| GLOBAL__sqrt | GEN | original | 1.0000 | n/a | n/a | n/a | 0 / 291 |
| GLOBAL__sqrt | GEN | flipped R1 | 1.0000 | n/a | n/a | n/a | 0 / 291 |
| GLOBAL__sqrt | GEN | flipped R2 | 1.0000 | n/a | n/a | n/a | 0 / 291 |
| SPEC_G1__sqrt | all | original | 0.9998 | 0.9976 | 0.6471 | 0.8148 | 6 / 35,833 |
| SPEC_G1__sqrt | all | flipped R1 | 0.9998 | 0.9972 | 0.6471 | 0.9992 | 6 / 35,833 |
| SPEC_G1__sqrt | all | flipped R2 | 0.9998 | 0.9972 | 0.6471 | 0.9992 | 6 / 35,833 |
| SPEC_G1__sqrt | G1 | original | 0.9998 | 0.9951 | 0.6471 | 0.5663 | 6 / 35,833 |
| SPEC_G1__sqrt | G1 | flipped R1 | 0.9998 | 0.9945 | 0.6471 | 0.9982 | 6 / 35,833 |
| SPEC_G1__sqrt | G1 | flipped R2 | 0.9998 | 0.9945 | 0.6471 | 0.9982 | 6 / 35,833 |
| SPEC_G1__sqrt | G2 | original | n/a | 1.0000 | n/a | 1.0000 | 0 / 0 |
| SPEC_G1__sqrt | G2 | flipped R1 | n/a | 1.0000 | n/a | 1.0000 | 0 / 0 |
| SPEC_G1__sqrt | G2 | flipped R2 | n/a | 1.0000 | n/a | 1.0000 | 0 / 0 |
| SPEC_G2__sqrt | all | original | 0.9987 | 0.9977 | 0.6471 | 0.9999 | 4 / 3,061 |
| SPEC_G2__sqrt | all | flipped R1 | 0.9987 | 0.9977 | 0.6471 | 0.9999 | 4 / 3,061 |
| SPEC_G2__sqrt | all | flipped R2 | 0.9987 | 0.9977 | 0.6471 | 0.9999 | 4 / 3,061 |
| SPEC_G2__sqrt | G1 | original | n/a | 0.9955 | 0.6471 | 0.9997 | 0 / 0 |
| SPEC_G2__sqrt | G1 | flipped R1 | n/a | 0.9954 | 0.6471 | 0.9997 | 0 / 0 |
| SPEC_G2__sqrt | G1 | flipped R2 | n/a | 0.9954 | 0.6471 | 0.9997 | 0 / 0 |
| SPEC_G2__sqrt | G2 | original | 0.9987 | 1.0000 | n/a | 1.0000 | 4 / 3,061 |
| SPEC_G2__sqrt | G2 | flipped R1 | 0.9987 | 1.0000 | n/a | 1.0000 | 4 / 3,061 |
| SPEC_G2__sqrt | G2 | flipped R2 | 0.9987 | 1.0000 | n/a | 1.0000 | 4 / 3,061 |

Systems (every val row; ROUTED = each flow -> its group's specialist, else GLOBAL):

| system | subset | condition | macro-F1 all | macro-F1 non-rare | recall benign | recall syn_flood | recall udp_flood | recall port_scan | false alarms |
|---|---|---|---|---|---|---|---|---|---|
| ROUTED | all | original | 0.8671 | 0.9579 | 0.9997 | 0.9976 | 0.6471 | 0.8148 | 10 |
| ROUTED | all | flipped R1 | 0.8727 | 0.9969 | 0.9997 | 0.9972 | 0.6471 | 0.9992 | 10 |
| ROUTED | all | flipped R2 | 0.8727 | 0.9969 | 0.9997 | 0.9972 | 0.6471 | 0.9992 | 10 |
| ROUTED | G1 | original | 0.8304 | 0.8915 | 0.9998 | 0.9951 | 0.6471 | 0.5663 | 6 |
| ROUTED | G1 | flipped R1 | 0.8790 | 0.9932 | 0.9998 | 0.9945 | 0.6471 | 0.9982 | 6 |
| ROUTED | G1 | flipped R2 | 0.8790 | 0.9932 | 0.9998 | 0.9945 | 0.6471 | 0.9982 | 6 |
| ROUTED | G2 | original | 0.9997 | 0.9997 | 0.9987 | 1.0000 | n/a | 1.0000 | 4 |
| ROUTED | G2 | flipped R1 | 0.9997 | 0.9997 | 0.9987 | 1.0000 | n/a | 1.0000 | 4 |
| ROUTED | G2 | flipped R2 | 0.9997 | 0.9997 | 0.9987 | 1.0000 | n/a | 1.0000 | 4 |
| ROUTED | GEN | original | 1.0000 | 1.0000 | 1.0000 | n/a | n/a | n/a | 0 |
| ROUTED | GEN | flipped R1 | 1.0000 | 1.0000 | 1.0000 | n/a | n/a | n/a | 0 |
| ROUTED | GEN | flipped R2 | 1.0000 | 1.0000 | 1.0000 | n/a | n/a | n/a | 0 |
| FLAT_GLOBAL | all | original | 0.8569 | 0.9607 | 0.9998 | 0.9976 | 0.5294 | 0.8264 | 7 |
| FLAT_GLOBAL | all | flipped R1 | 0.8841 | 0.9970 | 0.9998 | 0.9973 | 0.5294 | 0.9992 | 7 |
| FLAT_GLOBAL | all | flipped R2 | 0.8841 | 0.9970 | 0.9998 | 0.9973 | 0.5294 | 0.9992 | 7 |
| FLAT_GLOBAL | G1 | original | 0.8111 | 0.8997 | 0.9998 | 0.9952 | 0.5294 | 0.5936 | 7 |
| FLAT_GLOBAL | G1 | flipped R1 | 0.8815 | 0.9935 | 0.9998 | 0.9946 | 0.5294 | 0.9982 | 7 |
| FLAT_GLOBAL | G1 | flipped R2 | 0.8815 | 0.9935 | 0.9998 | 0.9946 | 0.5294 | 0.9982 | 7 |
| FLAT_GLOBAL | G2 | original | 0.9999 | 0.9999 | 1.0000 | 1.0000 | n/a | 1.0000 | 0 |
| FLAT_GLOBAL | G2 | flipped R1 | 0.9999 | 0.9999 | 1.0000 | 1.0000 | n/a | 1.0000 | 0 |
| FLAT_GLOBAL | G2 | flipped R2 | 0.9999 | 0.9999 | 1.0000 | 1.0000 | n/a | 1.0000 | 0 |
| FLAT_GLOBAL | GEN | original | 1.0000 | 1.0000 | 1.0000 | n/a | n/a | n/a | 0 |
| FLAT_GLOBAL | GEN | flipped R1 | 1.0000 | 1.0000 | 1.0000 | n/a | n/a | n/a | 0 |
| FLAT_GLOBAL | GEN | flipped R2 | 1.0000 | 1.0000 | 1.0000 | n/a | n/a | n/a | 0 |

## Figures

- `figures/flip_rate_heatmap.png` -- % of each class flagged REVERSED by R1, per split x group (n per cell).
- `figures/fwd_init_win_before_after.png` -- FWD Init Win Bytes value shares, G1 val port_scan vs train port_scan, before and after flipping (normaliser applied to both splits).
- `figures/recall_before_after.png` -- per-class recall of the seed-0 primary models on their step-23 val rows, original (hollow) vs flipped val (filled); models not retrained.
- `figures/routed_vs_flat_macro_f1.png` -- ROUTED vs FLAT_GLOBAL macro-F1 (all / non-rare classes), original vs flipped (R1, R2) val, seed 0; lower bound.

