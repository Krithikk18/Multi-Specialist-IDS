# Step 21 -- dataset version `v2_0_v1equiv` -- PASS

- 2026-11-20T13:51:21+00:00, git `99d650878a6b` (v2, dirty=True), 21_version_dataset.py sha256 `93151520863737dc...`, runtime 37.4 s, peak RSS 4402 MB
- ingest run `20261120T133357Z`, ingest_manifest sha256 `16c96c346949c514fc841840c674ffda2de5e942daee44437745447e4444eff6`
- split definition sha256 `67f329c0c34fddb51eb91936b9d49799633b5ce8078b95f470391c18c60ea627` (V1's recorded cuts, reused; V1's seeded caps, reproduced)
- test rows: selected, written, counted and hashed (identity checks) only; V1's test.parquet is read for the key columns session, start_ts, y, group only; no feature-value statistics on any split

## !!! udp_flood coverage (decide in Phase 2)

- G1: train 95, val 17, test 35 udp_flood flows.
- **G2 has 0 udp_flood flows in train and val**; its 23 udp_flood flows are all in test.
- **GEN has 0 udp_flood flows in every split** (train 0, val 0, test 0).

| split | G1 | G2 | GEN | total |
|---|---|---|---|---|
| train | 95 | 0 | 0 | 95 |
| val | 17 | 0 | 0 | 17 |
| test | 35 | 23 | 0 | 58 |

A G2 or GEN udp_flood flow can therefore only be learned from G1 examples (or not at all); Phase 1 does not fix this.

## Coverage warnings (class present for a group, but 0 flows in train and / or val)

| class | group | missing_in | train | val | test |
|---|---|---|---|---|---|
| syn_flood | GEN | train+val | 0 | 0 | 3 |
| udp_flood | G2 | train+val | 0 | 0 | 23 |
| port_scan | GEN | val | 4,356 | 0 | 0 |

## Checks

**PASS** (41 hard checks, 0 failed; 1 warnings)

| check | result | detail |
|---|---|---|
| lock: config/config.py sha256 == step10_prereg pin (V1 config untouched) | PASS | c19bf4ffe4ee25a9... |
| lock: config/step10_prereg.json sha256 | PASS | 17f627f841263e94... |
| lock: step10_prereg records the same config.py / features pins | PASS | inputs_sha256 / features |
| lock: features_v1.json (file sha256, list sha256, 70) | PASS | ok |
| lock: class_map.json (sha256, LF, structure) | PASS | ok |
| V1 frozen: results/step8/manifest_v1.json == step10_prereg | PASS | c2e48e620ad38a1e... |
| V1 frozen: results/step8b/manifest_v1_1.json == step10_prereg | PASS | a1e5f38dbc287a43... |
| V1 frozen: config/split_plan_v1_1.json == step10_prereg | PASS | 56813a35e1cbcf46... |
| ingest run PASS, full (not dry, no --limit-rows), source v1_cicflowmeter | PASS | status PASS, dry False, limit None |
| ingest_manifest sha256 == results/20 copy == results/20/run_meta.json | PASS | 16c96c346949c514... (run_meta run_id 20261120T133357Z) |
| ingest class_map / features pins == current | PASS | class_map 64063149b74d09f6..., features 623d0d2483670f34... |
| recorded cut labels agree with the session modes (split_plan_v1_1) | PASS | benign_night:time_split, DDoS-SYN_Flood:train, DDoS-SYN_Flood5:train, DDoS-SYN_Flood10:test, DDoS-SYN_Flood15:test, Recon-PortScan:time_split, Mirai-udpplain:train, Mirai-udpplain24:test, BenignTraffic1:test_only, BenignTraffic2:test_only, BenignTraffic3:test_only |
| 3-decimal boundary rounding cannot move a whole-second flow start (all boundaries > 0.0005 s from an integer) | PASS | min distance 0.050 s over 14 boundaries |
| cap keys: count, cap, p == manifest_v1 cap_keys (exact) | PASS | 63 keys |
| per (split, group, label, family): before caps and written == V1 (manifest_v1 + v1_1 daytime) | PASS | 27 keys |
| rows per split == manifest_v1_1 outputs | PASS | train 636,193/636,193, val 157,558/157,558, test 694,169/694,169 |
| coverage: each class >= 1 flow in train and val for every group it appears in | WARN | syn_flood/GEN missing in train+val (train 0, val 0, test 3); udp_flood/G2 missing in train+val (train 0, val 0, test 23); port_scan/GEN missing in val (train 4356, val 0, test 0) |
| row identity train: every row == V1 v1_1/train.parquet (70 features + 8 meta, positional) | PASS | rows 636,193 vs 636,193, mismatching rows 0, V1 file sha256 == prereg |
| row identity val: every row == V1 v1_1/val.parquet (70 features + 8 meta, positional) | PASS | rows 157,558 vs 157,558, mismatching rows 0, V1 file sha256 == prereg |
| test keys (session, start_ts, y, group) == V1 v1_1/test.parquet, positional (no V1 feature column read) | PASS | rows 694,169 vs 694,169, mismatching rows 0; V1 file rows/bytes == manifest_v1_1 |
| test rows in V1 schema: 08b column sha256 == manifest_v1_1 (V1 part, daytime part) | PASS | v1 part b2ace46c5389a0f8... == b2ace46c5389a0f8... (473,810 rows); daytime a89864e568183958... == a89864e568183958... (220,359 rows) |

## Flows per split x group x class

| split | group | benign | syn_flood | udp_flood | port_scan | total |
|---|---|---|---|---|---|---|
| train | G1 | 120,028 | 200,605 | 95 | 50,472 | 371,200 |
| train | G2 | 16,279 | 199,985 | 0 | 43,218 | 259,482 |
| train | GEN | 1,155 | 0 | 0 | 4,356 | 5,511 |
| val | G1 | 35,833 | 50,103 | 17 | 7,763 | 93,716 |
| val | G2 | 3,061 | 50,074 | 0 | 10,416 | 63,551 |
| val | GEN | 291 | 0 | 0 | 0 | 291 |
| test | G1 | 240,738 | 199,774 | 35 | 11,791 | 452,338 |
| test | G2 | 33,584 | 198,755 | 23 | 8,715 | 241,077 |
| test | GEN | 751 | 3 | 0 | 0 | 754 |

| split | benign | syn_flood | udp_flood | port_scan | total |
|---|---|---|---|---|---|
| train | 137,462 | 400,590 | 95 | 98,046 | 636,193 |
| val | 39,185 | 100,177 | 17 | 18,179 | 157,558 |
| test | 275,073 | 398,532 | 58 | 20,506 | 694,169 |

## Row-level identity vs V1

| split | rows_ours | rows_v1 | mismatching_rows | compared |
|---|---|---|---|---|
| train | 636,193 | 636,193 | 0 | 70 features + y, attack_family, group, device, device_category, session, split, start_ts |
| val | 157,558 | 157,558 | 0 | 70 features + y, attack_family, group, device, device_category, session, split, start_ts |
| test | 694,169 | 694,169 | 0 | session, start_ts, y, group (keys only) |

- test, full content in V1's schema (08b ColumnHasher, nothing read from V1's test file): V1 part `b2ace46c5389a0f8...` vs record `b2ace46c5389a0f8...` (473,810 rows); daytime `a89864e568183958...` vs record `a89864e568183958...` (220,359 rows)

## Counts vs V1 (before caps, written)

| split | group | label | family | pre_ours | pre_v1 | written_ours | written_v1 | pass |
|---|---|---|---|---|---|---|---|---|
| test | G1 | attack | port_scan | 11,791 | 11,791 | 11,791 | 11,791 | PASS |
| test | G1 | attack | syn_flood | 4,654,900 | 4,654,900 | 199,774 | 199,774 | PASS |
| test | G1 | attack | udp_flood | 35 | 35 | 35 | 35 | PASS |
| test | G1 | benign |  | 240,738 | 240,738 | 240,738 | 240,738 | PASS |
| test | G2 | attack | port_scan | 8,715 | 8,715 | 8,715 | 8,715 | PASS |
| test | G2 | attack | syn_flood | 4,507,838 | 4,507,838 | 198,755 | 198,755 | PASS |
| test | G2 | attack | udp_flood | 23 | 23 | 23 | 23 | PASS |
| test | G2 | benign |  | 33,584 | 33,584 | 33,584 | 33,584 | PASS |
| test | GEN | attack | syn_flood | 3 | 3 | 3 | 3 | PASS |
| test | GEN | benign |  | 751 | 751 | 751 | 751 | PASS |
| train | G1 | attack | port_scan | 50,472 | 50,472 | 50,472 | 50,472 | PASS |
| train | G1 | attack | syn_flood | 5,864,210 | 5,864,210 | 200,605 | 200,605 | PASS |
| train | G1 | attack | udp_flood | 95 | 95 | 95 | 95 | PASS |
| train | G1 | benign |  | 223,461 | 223,461 | 120,028 | 120,028 | PASS |
| train | G2 | attack | port_scan | 43,218 | 43,218 | 43,218 | 43,218 | PASS |
| train | G2 | attack | syn_flood | 4,195,098 | 4,195,098 | 199,985 | 199,985 | PASS |
| train | G2 | benign |  | 16,279 | 16,279 | 16,279 | 16,279 | PASS |
| train | GEN | attack | port_scan | 4,356 | 4,356 | 4,356 | 4,356 | PASS |
| train | GEN | benign |  | 1,155 | 1,155 | 1,155 | 1,155 | PASS |
| val | G1 | attack | port_scan | 7,763 | 7,763 | 7,763 | 7,763 | PASS |
| val | G1 | attack | syn_flood | 789,257 | 789,257 | 50,103 | 50,103 | PASS |
| val | G1 | attack | udp_flood | 17 | 17 | 17 | 17 | PASS |
| val | G1 | benign |  | 35,833 | 35,833 | 35,833 | 35,833 | PASS |
| val | G2 | attack | port_scan | 10,416 | 10,416 | 10,416 | 10,416 | PASS |
| val | G2 | attack | syn_flood | 712,314 | 712,314 | 50,074 | 50,074 | PASS |
| val | G2 | benign |  | 3,061 | 3,061 | 3,061 | 3,061 | PASS |
| val | GEN | benign |  | 291 | 291 | 291 | 291 | PASS |

## Caps (08's sampler, reproduced; == manifest_v1 cap_keys)

| cap_key | count | cap | p |
|---|---|---|---|
| attack|test|G1|syn_flood | 4,654,900 | 200,000 | 0.04296547723903843 |
| attack|test|G2|syn_flood | 4,507,838 | 200,000 | 0.04436716669942443 |
| attack|train|G1|syn_flood | 5,864,210 | 200,000 | 0.03410519063948938 |
| attack|train|G2|syn_flood | 4,195,098 | 200,000 | 0.04767469079387418 |
| attack|val|G1|syn_flood | 789,257 | 50,000 | 0.06335072099455565 |
| attack|val|G2|syn_flood | 712,314 | 50,000 | 0.07019376286300705 |
| benign|train|G1|Fibaro Home Center Lite | 123,480 | 20,000 | 0.16196954972465177 |

(56 more cap keys under their cap, p = 1)

## Files

- dir `/home/krithikk/lgids_cache/v2/datasets/v2_0_v1equiv`

| split | rows | bytes | file_sha256 | content_sha256 |
|---|---|---|---|---|
| train | 636,193 | 71,733,180 | d7ac09e07a8828ee4464ce2e678a3194ce133d0667244acd2ef5d8734ad21eaa | ad93b8244385c875bbc6f5044599295998be9e7cbb45444590345aad3828c58e |
| val | 157,558 | 16,484,076 | 9eecf620a162073756fcb8f9c2ade1facc0d18f08bd3b3a1cef2e0206de540be | 8b8005fc4045fe66fb28e66a459eaf68171941d13916662c793bf27ef7a6687f |
| test | 694,169 | 89,676,419 | 6537b20b270610500e7eb72a61cbccea0c8765ea72ff544c250b1318dad1f3fd | 817d680aa27f4de1d587194ff008d77137493013d91ed3fa78d26378bc752d80 |

- index line appended to `/home/krithikk/lgids_cache/v2/datasets/index.jsonl`
- figures: split_class_balance.png, split_group_class_table.png
