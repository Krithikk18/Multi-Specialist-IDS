# Step 32 -- simulated operator, signed label batches, validator -- PASS

- queue run `20261122T132156Z`; operator key fingerprint `ae8fd77e97bcd660` (~/lgids_cache/keys/operator/, outside the repo)

## Label batches

| batch | store | labels | alert / random | accuracy vs truth | per class | validator | fired |
|---|---|---|---|---|---|---|---|
| 20261122T132232Z__primary | primary | 58,405 | 57,193 / 1,212 | 1.0000 | {'benign': 1213, 'syn_flood': 46863, 'udp_flood': 9, 'port_scan': 10320} | VALID | - |
| 20261122T132232Z__noise_0.02 | experiments | 58,405 | 57,193 / 1,212 | 0.9807 | {'benign': 1560, 'syn_flood': 46011, 'udp_flood': 382, 'port_scan': 10452} | VALID | - |
| 20261122T132232Z__budget_1000 | experiments | 1,000 | 979 / 21 | 1.0000 | {'benign': 21, 'syn_flood': 795, 'udp_flood': 0, 'port_scan': 184} | VALID | - |
| 20261122T132232Z__budget_10000 | experiments | 10,000 | 9,792 / 208 | 1.0000 | {'benign': 208, 'syn_flood': 8005, 'udp_flood': 1, 'port_scan': 1786} | VALID | - |
| 20261122T132232Z__no_random | experiments | 57,193 | 57,193 / 0 | 1.0000 | {'benign': 2, 'syn_flood': 46862, 'udp_flood': 9, 'port_scan': 10320} | VALID | - |
| 20261122T132232Z__P1 | poison | 58,405 | 57,193 / 1,212 | 0.9198 | {'benign': 5899, 'syn_flood': 42177, 'udp_flood': 9, 'port_scan': 10320} | QUARANTINED | c_confident_disagreement |
| 20261122T132232Z__P2 | poison | 58,405 | 57,193 / 1,212 | 0.8233 | {'benign': 11533, 'syn_flood': 46863, 'udp_flood': 9, 'port_scan': 0} | QUARANTINED | c_confident_disagreement |

- poisoning targets: {'p1': 'syn_flood', 'p2': 'port_scan', 'batch_counts': {'benign': 1213, 'syn_flood': 46863, 'udp_flood': 9, 'port_scan': 10320}, 'nonrare_val_B': ['benign', 'syn_flood', 'port_scan']}

Validator details (check (c): confident items, disagreements, rate): `validation.json`.

## Checks

- PASS  queues sha256-checked against their manifests  primary 58,405, no_random 57,193
- PASS  every queued flow has a ground-truth label  missing 0
- PASS  operator key outside the repository (created if absent, file 600)  fingerprint ae8fd77e97bcd660
- PASS  primary batch validator result (report)  VALID; fired []; (c) {'fired': False, 'n_confident': 58299, 'n_disagree': 2, 'rate': 3.4305905761676875e-05, 'threshold_pmax': 0.99, 'max_rate': 0.05, 'n_labels_not_in_queue': 0}
- PASS  label store refuses a tampered copy (edited_label)  /home/krithikk/lgids_cache/v2/cl/tamper_test/20261122T132232Z/edited_label/20261122T132232Z__primary: labels.parquet sha256 differs from the signed manifest (ta
- PASS  label store refuses a tampered copy (no_signature)  /home/krithikk/lgids_cache/v2/cl/tamper_test/20261122T132232Z/no_signature/20261122T132232Z__primary: manifest.sig missing (unsigned or incomplete batch)
