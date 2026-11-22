# Step 36 -- leave-one-attack-out Stage 1 retrains -- PASS

Offline; train + val only; nothing registered. Stage 1 miss = a val flow of the held-out class predicted benign; caught = predicted as another attack class (still alerts).

- held-out classes (verdict): syn_flood, port_scan; rare (report-only): udp_flood (< 50 val flows (Phase 2 rule): report-only)
- val support: {'benign': 39185, 'syn_flood': 100177, 'udp_flood': 17, 'port_scan': 18179}
- val benign hours: 1.953

| held out | seed | train rows (removed) | trees | fit s | val k flows | misses (share) | caught (as) | benign recall | Stage 1 FA (FA/h) |
|---|---|---|---|---|---|---|---|---|---|
| syn_flood | 0 | 235,603 (400,590) | 54 | 4.4 | 100,177 | 221 (0.0022) | 99,956 {'port_scan': 99956} | 0.99992 | 3 (1.536) |
| syn_flood | 1 | 235,603 (400,590) | 51 | 4.1 | 100,177 | 236 (0.0024) | 99,941 {'port_scan': 99941} | 0.99987 | 5 (2.560) |
| syn_flood | 2 | 235,603 (400,590) | 69 | 5.2 | 100,177 | 9,718 (0.0970) | 90,459 {'port_scan': 90459} | 0.99992 | 3 (1.536) |
| syn_flood | 3 | 235,603 (400,590) | 41 | 3.6 | 100,177 | 214 (0.0021) | 99,963 {'port_scan': 99963} | 0.99982 | 7 (3.585) |
| syn_flood | 4 | 235,603 (400,590) | 46 | 3.5 | 100,177 | 229 (0.0023) | 99,948 {'port_scan': 99948} | 0.99987 | 5 (2.560) |
| port_scan | 0 | 538,147 (98,046) | 57 | 9.0 | 18,179 | 8,370 (0.4604) | 9,809 {'syn_flood': 9809} | 0.99992 | 3 (1.536) |
| port_scan | 1 | 538,147 (98,046) | 53 | 9.4 | 18,179 | 8,367 (0.4603) | 9,812 {'syn_flood': 9812} | 0.99992 | 3 (1.536) |
| port_scan | 2 | 538,147 (98,046) | 42 | 6.7 | 18,179 | 8,368 (0.4603) | 9,811 {'syn_flood': 9811} | 0.99992 | 3 (1.536) |
| port_scan | 3 | 538,147 (98,046) | 55 | 10.5 | 18,179 | 8,368 (0.4603) | 9,811 {'syn_flood': 9811} | 0.99997 | 1 (0.512) |
| port_scan | 4 | 538,147 (98,046) | 47 | 8.3 | 18,179 | 8,370 (0.4604) | 9,809 {'syn_flood': 9809} | 0.99992 | 3 (1.536) |
| udp_flood (rare) | 0 | 636,098 (95) | 59 | 9.8 | 17 | 17 (1.0000) | 0 {} | 1.00000 | 0 (0.000) |
| udp_flood (rare) | 1 | 636,098 (95) | 61 | 12.1 | 17 | 17 (1.0000) | 0 {} | 1.00000 | 0 (0.000) |
| udp_flood (rare) | 2 | 636,098 (95) | 41 | 7.3 | 17 | 17 (1.0000) | 0 {} | 1.00000 | 0 (0.000) |
| udp_flood (rare) | 3 | 636,098 (95) | 65 | 10.6 | 17 | 17 (1.0000) | 0 {} | 0.99997 | 1 (0.512) |
| udp_flood (rare) | 4 | 636,098 (95) | 74 | 19.5 | 17 | 17 (1.0000) | 0 {} | 1.00000 | 0 (0.000) |

- control (report-only): {'seed': 0, 'refit_sha256': 'a0b0afc91a469ef322d043a599d9c585245c9251d1b775611e0742864106faff', 'step22_sha256': 'a0b0afc91a469ef322d043a599d9c585245c9251d1b775611e0742864106faff', 'bytes_identical': True, 'val_argmax_agreement': 1.0, 'val_disagreements': 0, 'best_iteration': 68, 'step22_rounds': 69, 'fit_seconds': 18.095}

## Checks

- PASS  free space on the cache filesystem >= 10 GB  938.1 GB
- PASS  at least one non-rare held-out class  ['syn_flood', 'port_scan']
- PASS  every class x seed retrained and saved  15 pairs
- PASS  held-out class absent from every training set  
- PASS  LOAO benign recall >= 0.99 on val (removing k does not break benign)  all
- PASS  step 22 GLOBAL seed 0 == deployed registry entry (sha256)  a0b0afc91a469ef3...
- PASS  control: full refit reproduces the deployed model's val predictions (report-only)  agreement 1.000000, bytes identical True
