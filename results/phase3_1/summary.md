# LG-IDS V2 Phase 3.1 -- close-out of Phase 3 (val only) -- summary

Everything here is on TRAIN / VAL; nothing from the test split was read. Parts C, D, E are report-only: no deployed
model, dataset, registry entry or pre-registration changed. Decisions D102-D114 (`docs/V2_DECISIONS.md`). Config:
`config/v2_phase3_1.json` (sha256 `14e45250...`, pinned as `V2_PHASE3_1_CONFIG_SHA256`). Figures to use: Part C
`initwin_ablation/figures/recall_with_without_initwin_fixed.png` and Part D `drift/figures/error_vs_drift_fixed.png`
(label-overlap fixes, D114; the originals are kept).

## A. Chunked prediction writing

- **Parity re-run** (`results/phase3/28/phase3_1_parity/`, run 20261122T072459Z, `--config config/v2_phase3_1.json
  --s0-only --compare-to rerun_full`): **parity gate PASS** (GLOBAL s0 + ROUTED s0: every val flow, features exact,
  classes 100 %, max |dp| 0, routing 100 %). **Predictions identical to rerun_full row for row, every column: yes**
  (GLOBAL s0 and ROUTED s0, 157,558 rows each, 120 parts vs the single file); rate-guard alerts (397) and incidents
  (20 / 21) identical too.
- **Flow-path memory** (`results/phase3_1/memory/`; one process, 3 consecutive full-val GLOBAL s0 runs, no packet path):

  | | process peak | RSS after run 1 / 2 / 3 | per-run growth |
  |---|---|---|---|
  | before (Phase 3 code path, `v2_phase3.json`) | 1,407 MB | 644 / 701 / 694 MB | +57 / -7 MB |
  | after (chunked, `v2_phase3_1.json`) | 1,293 MB | 538 / 566 / 603 MB | +28 / +37 MB |
  | after + `malloc_trim(0)` after each run | 1,271 MB | 442 / 448 / 476 MB | +6 / +28 MB |

  Chunking removes the end-of-run buffer (peak -114 MB, RSS after a run ~100 MB lower). The "no per-run growth"
  target is **not fully met**: most of the remaining growth is memory the allocator keeps after free (malloc_trim
  returns ~100 MB), but a residual of +6 / +28 MB per 157,558-flow run remains. The in-run peak is dominated by the
  CSV-replay source (the whole val split in memory) and the models, which a live source on the Pi does not have.
- **Packet-path peak**: captures opened one at a time in event-time order (pages released as read) give the same
  packet sequence (0 cross-session inversions; rate-guard alerts identical to rerun_full): GLOBAL s0 process peak
  **1,383 MB** (flow + packet path) vs **8,230 MB** in Phase 3.

## B. Passive IP -> MAC learning (pcap path, Recon-PortScan val slice, 28,135 matched flows)

| routing | group == dataset | device == dataset |
|---|---|---|
| static map (Phase 3) | 0.87 % | 0.00 % |
| **learned** (packets incl. ARP, causal) | **100.00 %** | **100.00 %** |

Learner: 73 bindings (62 from ARP), 3,696 ARP records, 1 gateway MAC (the inventory's gateway / router; 38,142 frames
from it not bound), **0 ip_mac_change, 0 ip_mac_flap**; flows whose endpoint had no binding: source 1,980, destination
4,974, both 56; 520 flows took the unknown-device rule (GEN). CSV-replay parity unaffected (it carries MACs).

## C. Init Win shortcut ablation (`results/phase3_1/initwin_ablation/`)

Rule: without FWD / Bwd Init Win Bytes the model is shortcut-DEPENDENT iff port_scan recall drops by > 0.02 (5-seed
mean) with the paired 95 % CI entirely below 0; otherwise shortcut-CONVENIENT. **VERDICT: shortcut-CONVENIENT.**
port_scan recall 0.9992 -> 0.9877 (paired diff -0.0115 [-0.0150, -0.0079]: a real but small loss); macro-F1
non-rare 0.9978 -> 0.9954 (-0.0024 [-0.0032, -0.0016]); flow-level false alarms 1.02 -> 1.23 / h (+0.20 [-0.36,
0.77]); udp_flood (rare, 17 rows) 0.60 -> 0.51. port_scan SHAP after removal: Fwd Header Length 31.4 %, SYN Flag Count
13.9 %, RST Flag Count 11.7 %, Flow Duration 9.9 %, ACK Flag Count 8.2 % (FWD Init Win Bytes carried 61.8 % before).

## D. Train -> val drift (`results/phase3_1/drift/`)

| rule | verdict | numbers |
|---|---|---|
| D1 capture-wide | DOES NOT HOLD | 16 of 46 devices (35 %) have KS > 0.2 on a timing feature |
| D2 device-concentrated | DOES NOT HOLD | no timing feature has pooled benign KS > 0.2 (max 0.157, Flow IAT Mean) |
| D3 attack-tool | DOES NOT HOLD | syn_flood KS up to 0.59 (Flow Duration), 0.56 (Idle Std / Flow IAT Std); but benign max 0.157 is not < 0.1 |
| D4 load / time of day | DOES NOT HOLD | 161 windows, max |rho| 0.39 |

Adversarial validation (benign train vs val): AUC 0.810 overall, G1 0.813, G2 0.767, GEN 0.599; top features Flow
IAT Mean, Fwd Packet Length Min, Flow IAT Min, Flow Duration, Bwd Packets/s. Model error does not rise with drift:
Spearman(error rate, device AUC) = +0.00 over 46 devices.

**What this means for Phase 4.** The large train -> val shift is in the syn_flood flows' timing (Flow Duration,
Flow IAT, Idle: KS 0.3-0.6), i.e. in how the flood captures differ, not in the home devices; benign traffic drifts
moderately and diffusely (no timing feature above KS 0.2 pooled, 16 of 46 devices above 0.2 on some feature, no
load or time-of-day link), yet a classifier tells benign train from val with AUC 0.81, mostly through inter-arrival
times and minimum packet sizes. None of this is costing accuracy today (error is flat against per-device drift). Phase
4 should monitor Flow IAT / Flow Duration / Idle and Fwd Packet Length Min per group, and judge drift by its effect
on errors rather than by KS alone. Retraining on newer data for one group is realistic for G1 (most benign rows:
120k train / 36k val, highest drift AUC); for G2 (16k / 3k benign) and GEN (1.2k / 0.3k) a group-only retrain would
rest on too few benign rows, so those groups would need pooled or longer collection.

## E. Packet reordering (`results/phase3_1/reordering/`, for the Networking team)

- File order is time-sorted: **130 inversions in 57.7 M frames** (<= 8 microseconds, only in the two SYN-flood captures);
  classic pcap, microsecond timestamps, no interface ids; duplicates within 1 ms 0.001-0.05 %.
- **Replies stamped before the SYN they answer**: port_scan RST/ACK 20.6 % (20,584 of 99,677), benign SYN/ACK 14.0 %,
  syn_flood SYN/ACK 2.8 %; per device 0-100 % and stable (e.g. one hub 100 %).
- Link to the orientation work: on the devices R3 applies to, R3 flips match the RST/ACK-first handshakes within a
  few flows (e.g. 1,840 vs 1,842; 1,395 vs 1,395); devices with RST/ACK-first replies but 0 R3 flips are the G2
  devices whose reply carries a non-zero window (the shape R4 step A could not separate); SYN/ACK-first share vs the
  diag_03 H1 shape: Spearman +0.63 over 53 capture x device cells.
- Multi-interface evidence: none in the file format; the reply-before-request pattern on sorted files points to the
  capture point (e.g. a mirror merging two paths), see `docs/V2_NOTES_FOR_NETWORKING.md`.

## F. Notes for the Networking team

`docs/V2_NOTES_FOR_NETWORKING.md` (1 page): flow schema, passive IP -> MAC learning and what it needs from the
capture point, the reordering findings and questions, and the pointer to `docs/V2_ALERT_CONTRACT.md` (PROPOSED).
