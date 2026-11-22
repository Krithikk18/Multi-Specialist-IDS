# Phase 3.2 Part C -- test-count reconciliation

Data: `results/phase3_2/tests/counts.json`, written by `diagnostics/phase3_2_test_counts.py` (verify_v2_lock at start
and end; config.py `c19bf4ff...ddcf`, class_map.json `64063149...7580` unchanged).

**How the counts were obtained.**
- *Then*: the test functions (`def test_*` at module level) of every `tests/test_*.py` in the commit of each phase,
  read read-only from the repository's loose object files (zlib; no git command was run). The per-file numbers in
  earlier reports were not written down anywhere in the repo: `results/phase3/summary.md`, `results/phase3_1/summary.md`,
  `results/phase4/summary.md` and `docs/V2_DECISIONS.md` hold no test totals. The totals 197 / 195 / 254 below are the
  ones quoted in the Phase 3.2 prompt, i.e. the earlier chat reports.
- *Now*: every file run in its own process. V2 files use their own plain runner (`python tests/<file>`, "N/M passed").
  V1 `tests/test_rate_guard.py` has no `__main__`, and its usage line says pytest. pytest is not installed in any
  environment here, so it was run with an import-and-call driver that applies the plain runners' collection rule.
  The file and `rate_guard.py` are sha256-identical before and after, and byte-identical to V1 commit `6438c9f`.
- The static count equals the executed count for every file (276 = 276), so "counted" and "ran" mean the same thing.

## Per-file table

| file | Phase 3 `e9c845b` | Phase 3.1 `eabd7c9` | Phase 4 `14029ad` | now (ran / passed) | change |
|---|---|---|---|---|---|
| test_alert_log.py | 7 | 7 | 7 | 7 / 7 | |
| test_cl_gate.py | - | - | 13 | 13 / 13 | new in Phase 4 |
| test_cl_loop_e2e.py | - | - | 5 | 5 / 5 | new in Phase 4 |
| test_cl_split.py | - | - | 7 | 7 / 7 | new in Phase 4 |
| test_cl_validator.py | - | - | 7 | 7 / 7 | new in Phase 4 |
| test_diag_01.py | 6 | 6 | 6 | 6 / 6 | |
| test_diag_02.py | 6 | 6 | 6 | 6 / 6 | |
| test_flow_source.py | 8 | 8 | 8 | 8 / 8 | |
| test_inference.py | 5 | 5 | 5 | 5 / 5 | |
| test_label_store.py | - | - | 8 | 8 / 8 | new in Phase 4 |
| test_mac_learner.py | - | 8 | 8 | 14 / 14 | new in 3.1; +6 in 3.2 (unexpected_gateway) |
| test_model_loader.py | 7 | 7 | 7 | 7 / 7 | |
| test_operator_sim.py | - | - | 7 | 7 / 7 | new in Phase 4 |
| test_orientation.py | 8 | 8 | 8 | 8 / 8 | |
| test_phase2_1_config.py | 14 | 14 | 14 | 14 / 14 | |
| test_phase2_2_train.py | 6 | 6 | 6 | 6 / 6 | |
| test_phase2_3_evaluate.py | 10 | 10 | 10 | 10 / 10 | |
| test_phase2_4_calibrate.py | 7 | 7 | 7 | 7 / 7 | |
| test_phase2_5_shap.py | 5 | 5 | 5 | 5 / 5 | |
| test_phase2_6_registry.py | 11 | 11 | 11 | 11 / 11 | |
| test_phase2_amendment1.py | 6 | 6 | 6 | 6 / 6 | |
| test_phase3_config.py | 7 | 7 | 7 | 7 / 7 | |
| test_policy.py | 6 | 6 | 6 | 6 / 6 | |
| test_predictions_io.py | - | 7 | 7 | 7 / 7 | new in 3.1 |
| test_rate_guard_v2.py | 10 | 10 | 10 | 10 / 10 | |
| test_replay_buffer.py | - | - | 5 | 5 / 5 | new in Phase 4 |
| test_review_queue.py | - | - | 6 | 6 / 6 | new in Phase 4 |
| test_routing.py | 4 | 4 | 4 | 4 / 4 | |
| test_runtime_e2e.py | 3 | 3 | 3 | 3 / 3 | |
| test_schemas.py | 44 | 44 | 45 | 45 / 45 | +1 in Phase 4 (`test_verify_v2_lock_checks_phase4_prereg_and_config`) |
| **V2 subtotal** | **180** | **195** | **254** | **260 / 260** | |
| test_rate_guard.py (V1) | 16 | 16 | 16 | 16 / 16 | unchanged since V1 `6438c9f` |
| **all files** | **196** | **211** | **270** | **276 / 276** | |
| **as reported** | 197 | 195 + V1 | 254 + V1 | | |

## Explanation of every difference

1. **Phase 3, reported 197 vs 196 in the commit.** The commit has 180 V2 tests + 16 in V1 `test_rate_guard.py` = 196.
   197 = 180 + 17, and 17 is the V1-era figure for `test_rate_guard.py` (e.g. `aftersemCONTEXT.md`: "17 tests").
   That figure was never the file's count. The file had 13 test functions at `e25782d` / `3746184` and has had 16
   since `6438c9f`, byte-identical to today's. So the Phase 3 total included the V1 file and used a stale number for
   it: **overstated by 1. No test is missing.** (This is an inference from the arithmetic; the Phase 3 per-file
   breakdown was not recorded.)
2. **Phase 3 (197) -> Phase 3.1 (195 "plus V1 rate_guard").** The counting method changed: Phase 3 counted the V1 file
   and Phase 3.1 did not. 180 + 15 added in 3.1 (`test_mac_learner.py` 8, `test_predictions_io.py` 7) = **195**,
   which matches the commit exactly. The total went down only because the V1 file left the count; no test was removed.
3. **Phase 3.1 (195) -> Phase 4 (254 "plus test_rate_guard") "after adding 58".** The commit has +59: 58 in the eight
   new files (13 + 5 + 7 + 7 + 8 + 7 + 5 + 6) plus 1 added to the existing `test_schemas.py` (the Phase 4 pin test,
   D116). The "58" left out the test added to an existing file. The total 254 (= 195 + 59) is correct.
4. **Phase 4 (254) -> now (260 V2).** +6 in `tests/test_mac_learner.py` (Phase 3.2 Part B): warm-up; inventory gateway
   exempt; spoofing source fires once per MAC; none on port-scan-like traffic; absent under v2_phase3_1.json + config
   pin; runtime health log + predictions unchanged.
5. **No test disappeared** in any step (Phase 3 -> 3.1 -> 4 -> now: additions only; `removed_tests` in counts.json is
   empty). No file was renamed or merged.

**Total now: 276 tests, 276 passed** (260 V2 tests in 30 files with their plain runners + 16 V1 tests in
`tests/test_rate_guard.py`). Counting method from here on: report both numbers, "V2 N + V1 16".
