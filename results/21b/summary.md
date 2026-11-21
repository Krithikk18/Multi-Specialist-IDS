# Step 21b -- orientation-normalised dataset v2_1_oriented -- PASS

- run `20261121T075025Z`; source `v2_0_v1equiv` (train + val, sha256-checked; test not read); output `/home/krithikk/lgids_cache/v2/datasets/v2_1_oriented`
- rule R3 = `Protocol == 6 AND FWD Init Win Bytes == 0 AND Bwd Init Win Bytes > 0 AND SYN Flag Count >= 1 AND Total Fwd Packet == 1`; map sha256 `09d62055760943be26ff55335b4f5fccc5ac598ed5e981d7df7bffc92bd2a022`; common/orientation.py sha256 `4c96a3d79a2af2f3f60067234302d83e15d8153d883d31efa7e79e164c25c695`
- **test policy**: test split NOT built in v2_1_oriented: it is normalised once, with this same pinned code (common/orientation.py) and map (config/orientation_map.json, sha256 in the manifest), at the single final test run; Phase 2 never reads it (docs/V2_PREREG_PHASE2_AMENDMENT_1.md)

## Checks

- PASS  train: rows, order, columns unchanged (+ orientation_flipped appended)  636,193 rows, 92 columns
- PASS  train: unflipped rows bit-identical to the source  633,269 rows
- PASS  train: every flipped row is TCP and no longer satisfies R3  2,924 flipped
- PASS  train: validate_frame check results identical on source and normalised rows  7/10 pass on both
- PASS  train: validate_frame content checks pass (features present / ordered / numeric, timestamps, NaN-inf policy, blank-MAC rule)  layout checks (V1 raw-CSV meta / label columns) are expected to differ; see summary
- PASS  val: rows, order, columns unchanged (+ orientation_flipped appended)  157,558 rows, 92 columns
- PASS  val: unflipped rows bit-identical to the source  153,207 rows
- PASS  val: every flipped row is TCP and no longer satisfies R3  4,351 flipped
- PASS  val: validate_frame check results identical on source and normalised rows  7/10 pass on both
- PASS  val: validate_frame content checks pass (features present / ordered / numeric, timestamps, NaN-inf policy, blank-MAC rule)  layout checks (V1 raw-CSV meta / label columns) are expected to differ; see summary
- PASS  flip counts per split x group x class == the R3 gate run  gate run 20261121T074502Z: 7,275 rows
- PASS  config.py / class_map.json unchanged  

## Flips per split x group x class

| split | group | class | n | flipped | % |
|---|---|---|---|---|---|
| train | G1 | benign | 120,028 | 8 | 0.0067 |
| train | G1 | syn_flood | 200,605 | 1 | 0.0005 |
| train | G1 | udp_flood | 95 | 0 | 0.0000 |
| train | G1 | port_scan | 50,472 | 2,579 | 5.1098 |
| train | G2 | benign | 16,279 | 0 | 0.0000 |
| train | G2 | syn_flood | 199,985 | 0 | 0.0000 |
| train | G2 | port_scan | 43,218 | 0 | 0.0000 |
| train | GEN | benign | 1,155 | 0 | 0.0000 |
| train | GEN | port_scan | 4,356 | 336 | 7.7135 |
| val | G1 | benign | 35,833 | 0 | 0.0000 |
| val | G1 | syn_flood | 50,103 | 3 | 0.0060 |
| val | G1 | udp_flood | 17 | 0 | 0.0000 |
| val | G1 | port_scan | 7,763 | 4,348 | 56.0093 |
| val | G2 | benign | 3,061 | 0 | 0.0000 |
| val | G2 | syn_flood | 50,074 | 0 | 0.0000 |
| val | G2 | port_scan | 10,416 | 0 | 0.0000 |
| val | GEN | benign | 291 | 0 | 0.0000 |

## Files

| split | rows | flipped | file sha256 | content sha256 |
|---|---|---|---|---|
| train | 636,193 | 2,924 | `77fc070c190a886dae8e90dabc8f9fafbb687f3bd376a82e1cbdc1c411100578` | `6a08cc37d3d07d16de2bb2875d73a01df80e1bfb1115f587d3a74bc8b85fbc31` |
| val | 157,558 | 4,351 | `46c65f945a984e54924bd037d64bc9d9c47ac28d0947a9e2523aadb5832ccbba` | `28845266a55e5efe1272b1b106a31af256aad4260084ed4f5318374f5aff71ee` |

- dataset_manifest.json sha256 `49065567fa88a820ea8cd6b15f20cfc7bdb3a863bcd9b9c7ac8d5dc3d6afb872`

## validate_frame (common/schemas.py) on the source vs the normalised rows

- train: identical check results: True; checks failing on BOTH (dataset layout != V1 raw-CSV contract): ['no extra / duplicate columns', 'required metadata columns present', 'labels map through the class map']; extra columns ['start_ts', 'device_mac', 'device', 'device_category', 'group', 'row_in_file', 'label_id', 'label_name', 'y', 'split']; missing meta ['owner_status', 'exclude_reason', 'owner_device', 'owner_category', 'label']; NaN/inf counts {'source': 0, 'normalised': 0}; blank-MAC violations {'src_mac': {'lan_unicast': 0, 'invalid_ip': 0}, 'dst_mac': {'lan_unicast': 0, 'invalid_ip': 0}}
- val: identical check results: True; checks failing on BOTH (dataset layout != V1 raw-CSV contract): ['no extra / duplicate columns', 'required metadata columns present', 'labels map through the class map']; extra columns ['start_ts', 'device_mac', 'device', 'device_category', 'group', 'row_in_file', 'label_id', 'label_name', 'y', 'split']; missing meta ['owner_status', 'exclude_reason', 'owner_device', 'owner_category', 'label']; NaN/inf counts {'source': 0, 'normalised': 0}; blank-MAC violations {'src_mac': {'lan_unicast': 0, 'invalid_ip': 0}, 'dst_mac': {'lan_unicast': 0, 'invalid_ip': 0}}

## FWD Init Win Bytes, focus-group class-A flows (share)

| value | train v2_0 | train v2_1 | val v2_0 | val v2_1 |
|---|---|---|---|---|
| 0 | 5.1 % | 0.0 % | 56.0 % | 0.0 % |
| 1024 | 94.9 % | 100.0 % | 43.7 % | 99.8 % |
| 29200 | 0.0 % | 0.0 % | 0.1 % | 0.1 % |
| other | 0.0 % | 0.0 % | 0.1 % | 0.1 % |

## Figures

- `figures/flips_per_split_group_class.png` -- rows flipped per split x group x class (symlog; flipped / n and %).
- `figures/fwd_init_win_focus_A_v2_0_vs_v2_1.png` -- FWD Init Win Bytes value shares of the focus group's class-A flows, train vs val, v2_0 (left) vs v2_1 (right).
