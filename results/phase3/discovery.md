# Phase 3 step A -- discovery (read-only)

Done 2026-11-21 (WSL clock), before any Phase 3 runtime code ran. Every claim cites its evidence.

## 1. Splits, and whether packets can be confined to train / val

- **Rule** (`~/lgids_cache/v2/datasets/v2_1_oriented/split_definition.json`, sha256 field `67f329c0...`, copied
  from `results/step8/manifest_v1.json` `session_cuts`): per **session** (one capture), by **flow start time**:
  `label = labels[bisect_right(boundaries_epoch, start_ts)]`; `gap@*` rows (120 s, `gap_seconds`) are dropped;
  then seeded caps (val: attack <= 50,000 per family per group; `port_scan` / `udp_flood` never capped).
  Not per device, not per file.
- Session modes: `benign_night`, `Recon-PortScan` = time_split (train | gap | val | gap | **test**);
  `DDoS-SYN_Flood`, `DDoS-SYN_Flood5`, `Mirai-udpplain` = train (train | gap | val, no test);
  `DDoS-SYN_Flood10`, `DDoS-SYN_Flood15`, `Mirai-udpplain24` = test; `BenignTraffic1-3` = test_only.
- **Packets can be confined to train / val**: the same cuts apply to `frame.time_epoch` (V1 step 13 did exactly
  this: `13_rate_guard_calibrate.py` `check_inputs`, `run_session`). For the two time_split captures, reading
  stops at the first packet at or after the start of `gap@val|test` (`benign_night` 1665191229.65,
  `Recon-PortScan` 1664291060.8), so no test-window packet is read. V1's step 13 used a tshark display filter
  (tshark still scans the test range); the V2 reader is stricter (it stops).
- **Val-only pcap material: no separate val-only files exist, but 5 val windows inside train / val captures do**
  (packet counts from `results/step13/calib_per_session.csv`, before exclusion):

| session | val window (UTC) | IPv4 packets | of which attacker / Pi MAC |
|---|---|---|---|
| benign_night | 2022-10-07 23:45:50 -> 2022-10-08 01:07:09 | 597,492 | 5,438 |
| DDoS-SYN_Flood | 2022-08-29 12:27:00 -> 12:31:44 | 2,895,782 | 2,878,513 |
| DDoS-SYN_Flood5 | 2022-08-29 17:46:54 -> 17:57:10 | 2,273,559 | 2,265,396 |
| Recon-PortScan | 2022-09-27 14:30:38 -> 15:04:00 | 137,970 | 34,989 |
| Mirai-udpplain | 2023-01-19 16:22:00 -> 16:23:26 | 347,514 | 344,256 |

  -> the default "no val-only pcaps" is **not** triggered: the rate guard is evaluated on real val packets and the
  pcap flow path runs on a val-window slice.

## 2. Raw pcaps and packet library

- `~/lgids_cache/BenignTraffic.pcap` (2,048,000,100 B; benign_night) and `~/lgids_cache/ciciot2023/attack/<family>/`
  (DDoS-SYN_Flood 2.05 GB, DDoS-SYN_Flood5 2.05 GB, Recon-PortScan 201 MB, Mirai-udpplain 2.05 GB; test captures
  DDoS-SYN_Flood10 / 15, Mirai-udpplain24 exist and are never opened). All are classic little-endian microsecond
  pcap (magic `d4c3b2a1`). sha256 records: `config/config.py` `DATASET.benign_pcap_sha256`, `config/attack_set.json`.
- V1 read packets with **tshark 4.2.2** (`13_rate_guard_calibrate.tshark_ipv4_packets`: fields frame.time_epoch,
  eth.src, eth.dst, ip.src, ip.dst, ip.proto; outer header; IPv4 only). dpkt / scapy are **not** installed.
  V2 adds a stdlib pcap reader (Ethernet + 802.1Q + IPv4 outer header); its output is tested equal to V1's tshark
  reader on a val slice.

## 3. Flow -> device -> group (ingest rule) and inventory

- `04_tag_flows.py` (V1) tags each side: Src IP / Dst IP -> MAC via `config/ip_mac_map.csv` (time-windowed),
  MAC -> role via `config/device_table.csv`. **Owner**: both sides role `iot` -> Src side
  (`device_device_initiator`); exactly one side `iot` -> that side (`device_side`); otherwise unowned (gateway,
  testbed Pis, phones and unknown MACs are never owners); either side ambiguous -> ambiguous (excluded).
- `08_build_datasets.usable` (imported by `20_ingest_csv.py`): keep owned & no exclude_reason & label != excluded;
  group = `device_table.behaviour_group[owner_mac]`; a group outside `GROUPS.labels` (G1, G2, GEN) is dropped.
  `08b_extend_test.usable_day` (daytime test sessions only) adds: unowned flows with an **unlisted** endpoint MAC ->
  that MAC, group **GEN**.
- The dataset carries `src_mac`, `dst_mac` (blank for off-LAN endpoints), `owner_mac`, `device_mac`, `device`,
  `group`. On v2_1 val `device_mac == lower(owner_mac)` for 100 % of rows; the owner is the Src side on 20.5 % and
  the Dst side on 79.5 %.
- Inventory: `config/device_table.csv` (74 rows: 26 iot G1, 27 iot G2, 3 iot GEN, 10 testbed_pi, 6 unknown,
  1 gateway, 1 excluded) + `config/behaviour_groups.json` (labels G1 / G2 / GEN, v1.0, locked by V1 verify_lock).
- Note: the orientation normaliser swaps src / dst MACs of flipped rows, so the owner rule must be applied to the
  extractor's orientation (before normalising) to reproduce ingest exactly.

## 4. Does the locked CICFlowMeter write rows as flows terminate?

- Jar `~/tools/CICFlowMeter-sweep/build/install/CICFlowMeter/lib/CICFlowMeter-4.0.jar`, sha256 `01acf941...` ==
  `EXTRACTOR.jar_sha256`. Source `src/main/java/cic/cs/unb/ca/ifm/Cmd.java`: offline mode registers
  `FlowListener.onFlowGenerated`, which calls `InsertCsvRow.insert(...)` **once per emitted flow**; `insert` opens the
  CSV with `new FileOutputStream(file, true)` (append), writes the row, `flush()`, `close()`. Flows still open at
  end of file are emitted last.
- **Confirmed on a tiny pcap** (first 20,000 packets of the Recon-PortScan VAL window, written to
  `~/lgids_scratch_cfm_tail/` outside the repo and the cache; run through `extraction/run_cicflowmeter.py`): the CSV
  grew while the JVM was running (2 rows at 1.39 s, 404 at 1.58 s, 2,920 at 1.96 s, 5,958 at 2.08 s; exit after)
  -> **rows are written as flows terminate (tail-able)**.
- In emission (row) order flow starts were monotonic (0 regressions over 5,957 rows) but flow ends were not
  (2,392 regressions): emission order is not end order, so `start + duration` is only a lower bound of the
  emission time. Offline mode processes the pcap as fast as it can, so the CSV carries no emission packet time;
  the pcap path reconstructs it from the row order (Phase 3 prereg).
  -> the default "only at the end" is **not** triggered; true live capture (pcap -> `cfm` online mode) stays a Pi item.

## 5. What 24_calibrate.py saved

- Both: per model x seed a **single full-val temperature** (`<model key>.temperature.json`, "fitted on the model's
  own val set (all rows)", `apply: P = softmax(margin / temperature)`, carrying the model sha256), and the 2-fold
  cross-fit numbers in `calibration.json` (reported metrics only). The registry entry copies the full-val file as
  `calibrator.json` (GLOBAL__none__s0: T = 1.4231229528557798). -> the default "fit one on full val" is **not**
  triggered.

## 6. V1 rate_guard

- `rate_guard.py` (stdlib only, importable read-only): tumbling windows (`window_s`), non-TCP/UDP IPv4 packets only
  (TCP / UDP are clock ticks), two levels: stream (src, dst, proto) and victim (dst, proto); alert iff packets in a
  window > threshold.
- Frozen config `config/rate_guard_v1.json`: window 10 s; stream 159 / victim 321 (default, incl. GRE); ICMP 159 /
  321; IGMP 12 / 33. Rule: train max x 3, DEFAULT floored at the ICMP threshold (`13_rate_guard_calibrate.py`
  proposal, chosen by the user 2026-10-21).
- Evaluated by `13c_rate_guard_benign_fp.py` on the Step 10 **test** period (already opened by Step 10):
  0 benign-key alerts / 21.730 h, Garwood 95 % upper 0.170 / h (C4 limit 0.5 / h); attacker / testbed-Pi MAC
  packets dropped before the guard; hours = packet-active segments (pause > 300 s).

## 7. Registry API (`common/registry.py`, CLI `26_model_registry.py`)

- `ensure_keys(keys_dir, repo_root)`, `register(...)` (candidate), `transition(d, to_state, secret, by)`
  (candidate -> approved -> promoted only; signed, hash-chained `state.log`), `read_state`, `verify_entry`
  (manifest Ed25519 signature + file sha256s), `load_model(d, public, class_map_path, features_path,
  allow_states=("promoted",))` -> booster + temperature + manifest. CLI: `register`, `transition --entry --to --by`
  (the promote operation exists), `verify`.
- Entry manifest records: model id / key, seed, kind, serves_groups, class names, `class_map_sha256`,
  `features_file_sha256`, `features_list_sha256`, `dataset_version`, `dataset_manifest_sha256`,
  `prereg_phase2_sha256`, `config_sha256`, train / eval / calib runs + manifest sha256s, temperature, best
  iteration, training counts, class weights, val metrics, `runtime_contract`, file sha256s, signer public key; v2_1
  entries add `prereg_amendment_1_sha256`, `orientation_map_sha256`, `primary_selection`.
- Not recorded in the entry: Amendment 2 (written after registration; the promotion record names it).

## Defaults triggered

None of the three: val-window packets exist (rate guard evaluated on real packets, pcap flow path run on a val
slice); 24 saved a full-val temperature; CICFlowMeter writes rows as flows terminate.
