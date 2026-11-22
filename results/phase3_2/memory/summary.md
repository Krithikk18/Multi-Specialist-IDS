# Phase 3.2 Part A -- memory soak -- PLATEAU

Run `20261122T134922Z`; `config/v2_phase3_1.json` (sha256 `14e45250569f3dee...`, pinned True); GLOBAL s0, CSV replay of full val at max speed, no packet path; 10 consecutive runs in one process; gc + `malloc_trim(0)` after each run.

**Rule (fixed before any number):** fit RSS-after-run against run number for runs 4-10 (OLS, 95 % t CI). LEAK iff slope > 5 MB/run AND the CI lies entirely above 0; otherwise PLATEAU (fragmentation / allocator caching, not a leak).

**Fit runs 4-10: slope -0.16 MB/run, 95 % CI [-6.97, +6.65] (df 5) -> VERDICT PLATEAU.**

| run | flows | wall s | in-run RSS max MB | RSS before trim MB | RSS after run MB | glibc heap in use MB | free in heap MB | mmapped MB | arrow pool MB | gc objects | predictions == Phase 3.1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 157,558 | 60.3 | 1275 | 665.3 | 560.9 | 46.2 | 109.7 | 19.1 | 27.7 | 127,254 | False |
| 2 | 157,558 | 51.9 | 1329 | 719.7 | 612.1 | 46.4 | 113.0 | 19.1 | 27.7 | 127,281 | False |
| 3 | 157,558 | 66.8 | 1345 | 759.3 | 651.8 | 46.4 | 110.8 | 19.1 | 27.7 | 127,295 | False |
| 4 | 157,558 | 85.7 | 1352 | 762.1 | 654.4 | 46.4 | 111.4 | 19.1 | 27.7 | 127,309 | False |
| 5 | 157,558 | 65.9 | 1375 | 790.9 | 683.0 | 46.4 | 111.4 | 19.1 | 27.7 | 127,323 | False |
| 6 | 157,558 | 54.7 | 1365 | 784.9 | 678.4 | 46.5 | 111.5 | 19.1 | 27.7 | 127,337 | False |
| 7 | 157,558 | 79.4 | 1375 | 797.3 | 690.0 | 46.5 | 111.5 | 19.1 | 27.7 | 127,351 | False |
| 8 | 157,558 | 87.2 | 1355 | 770.1 | 659.0 | 46.5 | 119.0 | 19.1 | 27.7 | 127,365 | False |
| 9 | 157,558 | 55.7 | 1359 | 780.7 | 669.5 | 46.5 | 119.2 | 19.1 | 27.7 | 127,379 | False |
| 10 | 157,558 | 81.4 | 1353 | 773.5 | 668.3 | 46.5 | 111.9 | 19.1 | 27.7 | 127,393 | False |

- RSS after model load: 423.5 MB; process peak 1377 MB; per-run growth (MB): +51.2, +39.7, +2.5, +28.6, -4.6, +11.6, -30.9, +10.4, -1.2
- evidence (not part of the rule): glibc heap in use, runs 4-10: +0.01 MB/run [+0.01, +0.01]
- evidence: gc-tracked Python objects, runs 4-10: +14.0 objects/run [+14.0, +14.0]
- every run's predictions vs the Phase 3.1 parity run GLOBAL s0 (`/home/krithikk/lgids_cache/v2/runtime/20261122T072459Z_GLOBAL_s0`), row for row, every column: False

Figure: `results/phase3_2/memory/figures/rss_per_run.png`

Lock: config.py `c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf`, class_map.json `64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580` (start == end: True)
