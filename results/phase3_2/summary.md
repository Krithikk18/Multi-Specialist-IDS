# LG-IDS V2 Phase 3.2 -- last Phase 3 items (val only) -- summary

Train / val only; the test split was not read. No model, dataset, registry entry or pre-registration changed.
Decisions D138-D150 (`docs/V2_DECISIONS.md`). New runtime config `config/v2_phase3_2.json` (sha256 `71f47711...aaf6`,
pinned as `V2_PHASE3_2_CONFIG_SHA256`) = v2_phase3_1.json + `gateway_warmup_s` 300 + `inventory_gateway_roles`.

## A. Memory soak -- PLATEAU (`memory/`)
Rule (fixed first): OLS of RSS-after-run on run number, runs 4-10; LEAK iff slope > 5 MB/run and its 95 % CI > 0.
10 x 157,558-flow GLOBAL s0 runs in one process (gc + malloc_trim after each): **slope -0.16 MB/run, 95 % CI
[-6.97, +6.65] -> PLATEAU.** RSS after run is 561 / 612 / 652 MB, then flat at 654-690 MB; glibc heap in use is flat at
~46 MB. Phase 3.1's per-run growth was the start of an allocator warm-up, not a leak. No code change, so no parity
re-run was needed. (The soak's own "predictions == Phase 3.1" check reads False only because `incident_id` is
renumbered: the reference ran with the packet rate guard. All other columns are identical: D140.)
Figure: `memory/figures/rss_per_run_fixed.png`.

## B. Gateway rule on floods -- SAFE (`gateway/`)
Rule (fixed first): SAFE iff routing agreement (group AND device) >= 99 % of matched flows on every flood slice.
Group+device agreement on matched flows: DDoS-SYN_Flood 100.00 % (52,527 / 52,529), DDoS-SYN_Flood5 100.00 %
(32,809 / 32,809), Mirai-udpplain 100.00 % (592 / 592); Recon-PortScan reference 100.00 % (28,135; = Phase 3.1).
The only gateway MAC on every slice is the inventory router. **No val flood spoofs source IPs**: each attack-source
MAC uses exactly one source IP (`gateway/attack_sources.json`). So 0 `unexpected_gateway` events fired, which matches
the expectation of one per spoofing source when there are none. The spoofing case is covered by the synthetic unit
tests only. CSV-replay parity under v2_phase3_2.json: PASS, identical to Phase 3.1 row for row
(`results/phase3/28/phase3_2_parity/`). pcap-path predictions are identical under 3.1 and 3.2 on every slice.
Figure: `gateway/figures/distinct_src_ips_fixed.png`.

## C. Test counts (`tests/reconciliation.md`)
276 / 276 pass now: V2 260 + V1 `test_rate_guard.py` 16. No test was ever removed. Phase 3's 197 used a stale "17"
for the V1 file (it has 16), Phase 3.1's 195 excluded the V1 file, and Phase 4's "+58" omitted one test added to
`test_schemas.py` (+59).

## D. Phase 4 wording
The kill-rule line of `results/phase4/summary.md` and `results/phase4/rerun_fig_fix3/summary.md` was corrected (D150).
