# Step 26 -- model registry -- PASS

- run `20261120T184412Z`; models of step 22 run `20261120T144232Z`, metrics of step 23 run `20261120T183529Z`, calibrators of step 24 run `20261120T183628Z`
- registry root `/home/krithikk/lgids_cache/v2/registry`; signature Ed25519 (pure-python RFC 8032 (cryptography not installed)); key outside the repo
- every entry is **candidate**: approval and promotion are the author's manual steps (`26_model_registry.py transition --entry <dir> --to approved|promoted`); load_model refuses anything not promoted unless offline evaluation explicitly allows it.

## Registry

| entry | state | serves | model sha256 | temperature | macro-F1 all (own val set) | macro-F1 non-rare | signer |
|---|---|---|---|---|---|---|---|
| SPEC_G1__sqrt__s0__20261120T144232Z | candidate | G1 | af227804372d7cb1... | 1.3897 | 0.8450 [0.8022, 0.8878] | 0.9579 [0.9578, 0.9580] | a4aea1b4253a158c |
| SPEC_G2__sqrt__s0__20261120T144232Z | candidate | G2 | 666e19f59cef3014... | 0.7049 | 0.8817 [0.8470, 0.9164] | 0.9893 [0.9668, 1.0118] | a4aea1b4253a158c |
| GLOBAL__sqrt__s0__20261120T144232Z | candidate | GEN | 05405b7a4b3ebcf3... | 1.1511 | 0.8650 [0.8327, 0.8974] | 0.9853 [0.9638, 1.0067] | a4aea1b4253a158c |

## Checks

- PASS  runs chain: steps 23 and 24 used this step 22 run  22 20261120T144232Z; 23 -> 20261120T144232Z; 24 -> 20261120T144232Z
- PASS  signing key outside the repository (created if absent, mode 600)  fingerprint a4aea1b4253a158c, backend pure-python RFC 8032 (cryptography not installed)
- PASS  SPEC_G1__sqrt__s0: model sha256 == step 22 manifest == calibrator's model_sha256  af227804372d7cb1...
- PASS  SPEC_G1__sqrt__s0__20261120T144232Z: registered as candidate; runtime load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/SPEC_G1__sqrt__s0__20261120T144232Z
- PASS  SPEC_G2__sqrt__s0: model sha256 == step 22 manifest == calibrator's model_sha256  666e19f59cef3014...
- PASS  SPEC_G2__sqrt__s0__20261120T144232Z: registered as candidate; runtime load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/SPEC_G2__sqrt__s0__20261120T144232Z
- PASS  GLOBAL__sqrt__s0: model sha256 == step 22 manifest == calibrator's model_sha256  05405b7a4b3ebcf3...
- PASS  GLOBAL__sqrt__s0__20261120T144232Z: registered as candidate; runtime load refused, offline load allowed  /home/krithikk/lgids_cache/v2/registry/GLOBAL__sqrt__s0__20261120T144232Z
