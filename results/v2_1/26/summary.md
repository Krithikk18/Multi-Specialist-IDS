# Step 26 -- model registry -- PASS

- run `20261121T081057Z`; models of step 22 run `20261121T075821Z`, metrics of step 23 run `20261121T080839Z`, calibrators of step 24 run `20261121T080937Z`
- registry root `/home/krithikk/lgids_cache/v2/registry`; signature Ed25519 (pure-python RFC 8032 (cryptography not installed)); key outside the repo
- every entry is **candidate**: approval and promotion are the author's manual steps (`26_model_registry.py transition --entry <dir> --to approved|promoted`); load_model refuses anything not promoted unless offline evaluation explicitly allows it.
- Amendment 1: registered weighting `none` (amendment selection in step 23 run 20261121T080839Z); entries tagged with dataset `v2_1_oriented`, amendment sha256 `c436599da4216c3e...`, orientation map sha256 `09d62055760943be...`

## Registry

| entry | state | serves | model sha256 | temperature | macro-F1 all (own val set) | macro-F1 non-rare | signer |
|---|---|---|---|---|---|---|---|
| SPEC_G1__none__s0__20261121T075821Z | candidate | G1 | a92031f6f8bbac4d... | 1.4554 | 0.9102 [0.8971, 0.9232] | 0.9974 [0.9974, 0.9975] | a4aea1b4253a158c |
| SPEC_G2__none__s0__20261121T075821Z | candidate | G2 | 34a835fd1563b757... | 1.2848 | 0.9435 [0.9372, 0.9497] | 0.9990 [0.9990, 0.9991] | a4aea1b4253a158c |
| GLOBAL__none__s0__20261121T075821Z | candidate | GEN | a0b0afc91a469ef3... | 1.4231 | 0.9144 [0.8984, 0.9305] | 0.9978 [0.9972, 0.9984] | a4aea1b4253a158c |

## Checks

- PASS  runs chain: steps 23 and 24 used this step 22 run  22 20261121T075821Z; 23 -> 20261121T075821Z; 24 -> 20261121T075821Z
- PASS  signing key outside the repository (created if absent, mode 600)  fingerprint a4aea1b4253a158c, backend pure-python RFC 8032 (cryptography not installed)
- PASS  SPEC_G1__none__s0: model sha256 == step 22 manifest == calibrator's model_sha256  a92031f6f8bbac4d...
- PASS  SPEC_G1__none__s0__20261121T075821Z: registered as candidate; runtime load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/SPEC_G1__none__s0__20261121T075821Z
- PASS  SPEC_G2__none__s0: model sha256 == step 22 manifest == calibrator's model_sha256  34a835fd1563b757...
- PASS  SPEC_G2__none__s0__20261121T075821Z: registered as candidate; runtime load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/SPEC_G2__none__s0__20261121T075821Z
- PASS  GLOBAL__none__s0: model sha256 == step 22 manifest == calibrator's model_sha256  a0b0afc91a469ef3...
- PASS  GLOBAL__none__s0__20261121T075821Z: registered as candidate; runtime load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/GLOBAL__none__s0__20261121T075821Z
