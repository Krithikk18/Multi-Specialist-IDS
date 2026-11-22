# Step 37 -- models of normal (train benign only) -- PASS

- train benign rows 137,462, groups {'G1': 120028, 'G2': 16279, 'GEN': 1155}; non-finite before cleaning: none (NaN and +-inf -> 0 before the model (features_v1.json 'clean', V1 08); counted, not a failure); transform sign(x) * log1p(|x|); sklearn 1.9.1, n_jobs 4

| arm | seed | model | n train benign | threshold | fit s | size KB | 90/10 held-out flag rate (n) |
|---|---|---|---|---|---|---|---|
| GLOBAL_NORMAL | 0 | __global__ | 137,462 | 0.65920 | 0.46 | 2609 | 0.00102 (13,746) |
| PER_GROUP_NORMAL | 0 | G1 | 120,028 | 0.65012 | 0.52 | 2470 | 0.00092 (12,003) |
| PER_GROUP_NORMAL | 0 | G2 | 16,279 | 0.67672 | 0.26 | 2503 | 0.00246 (1,628) |
| PER_GROUP_NORMAL | 0 | GEN | 1,155 | 0.68457 | 0.21 | 2056 | 0.00870 (115) |
| RANDOM_GROUP_NORMAL | 0 | G1 | 120,028 | 0.64648 | 0.34 | 2609 | 0.00142 (12,003) |
| RANDOM_GROUP_NORMAL | 0 | G2 | 16,279 | 0.65380 | 0.26 | 2597 | 0.00123 (1,628) |
| RANDOM_GROUP_NORMAL | 0 | GEN | 1,155 | 0.65670 | 0.21 | 2597 | 0.00000 (115) |
| GLOBAL_NORMAL | 1 | __global__ | 137,462 | 0.65140 | 0.36 | 2554 | 0.00065 (13,746) |
| PER_GROUP_NORMAL | 1 | G1 | 120,028 | 0.65928 | 0.35 | 2493 | 0.00125 (12,003) |
| PER_GROUP_NORMAL | 1 | G2 | 16,279 | 0.68097 | 0.26 | 2502 | 0.00000 (1,628) |
| PER_GROUP_NORMAL | 1 | GEN | 1,155 | 0.67844 | 0.21 | 2095 | 0.00000 (115) |
| RANDOM_GROUP_NORMAL | 1 | G1 | 120,028 | 0.66747 | 0.34 | 2603 | 0.00092 (12,003) |
| RANDOM_GROUP_NORMAL | 1 | G2 | 16,279 | 0.64564 | 0.26 | 2612 | 0.00123 (1,628) |
| RANDOM_GROUP_NORMAL | 1 | GEN | 1,155 | 0.67266 | 0.21 | 2565 | 0.00000 (115) |
| GLOBAL_NORMAL | 2 | __global__ | 137,462 | 0.66072 | 0.35 | 2547 | 0.00065 (13,746) |
| PER_GROUP_NORMAL | 2 | G1 | 120,028 | 0.65098 | 0.35 | 2460 | 0.00100 (12,003) |
| PER_GROUP_NORMAL | 2 | G2 | 16,279 | 0.67718 | 0.26 | 2497 | 0.00000 (1,628) |
| PER_GROUP_NORMAL | 2 | GEN | 1,155 | 0.68126 | 0.20 | 2083 | 0.00000 (115) |
| RANDOM_GROUP_NORMAL | 2 | G1 | 120,028 | 0.65215 | 0.33 | 2574 | 0.00142 (12,003) |
| RANDOM_GROUP_NORMAL | 2 | G2 | 16,279 | 0.66021 | 0.28 | 2515 | 0.00061 (1,628) |
| RANDOM_GROUP_NORMAL | 2 | GEN | 1,155 | 0.64867 | 0.24 | 2563 | 0.00000 (115) |
| GLOBAL_NORMAL | 3 | __global__ | 137,462 | 0.65277 | 0.36 | 2647 | 0.00124 (13,746) |
| PER_GROUP_NORMAL | 3 | G1 | 120,028 | 0.65405 | 0.38 | 2535 | 0.00067 (12,003) |
| PER_GROUP_NORMAL | 3 | G2 | 16,279 | 0.67705 | 0.26 | 2551 | 0.00123 (1,628) |
| PER_GROUP_NORMAL | 3 | GEN | 1,155 | 0.68679 | 0.21 | 2143 | 0.00000 (115) |
| RANDOM_GROUP_NORMAL | 3 | G1 | 120,028 | 0.66378 | 0.35 | 2659 | 0.00092 (12,003) |
| RANDOM_GROUP_NORMAL | 3 | G2 | 16,279 | 0.65100 | 0.28 | 2674 | 0.00000 (1,628) |
| RANDOM_GROUP_NORMAL | 3 | GEN | 1,155 | 0.67685 | 0.21 | 2611 | 0.00000 (115) |
| GLOBAL_NORMAL | 4 | __global__ | 137,462 | 0.64898 | 0.34 | 2674 | 0.00073 (13,746) |
| PER_GROUP_NORMAL | 4 | G1 | 120,028 | 0.65032 | 0.34 | 2569 | 0.00125 (12,003) |
| PER_GROUP_NORMAL | 4 | G2 | 16,279 | 0.67602 | 0.25 | 2565 | 0.00123 (1,628) |
| PER_GROUP_NORMAL | 4 | GEN | 1,155 | 0.68152 | 0.21 | 2123 | 0.00000 (115) |
| RANDOM_GROUP_NORMAL | 4 | G1 | 120,028 | 0.66234 | 0.34 | 2630 | 0.00083 (12,003) |
| RANDOM_GROUP_NORMAL | 4 | G2 | 16,279 | 0.64314 | 0.25 | 2669 | 0.00061 (1,628) |
| RANDOM_GROUP_NORMAL | 4 | GEN | 1,155 | 0.65489 | 0.21 | 2655 | 0.00000 (115) |

| arm | seed | fallback (group, n) | held-out flag rate pooled (nominal 0.001) |
|---|---|---|---|
| GLOBAL_NORMAL | 0 | - | 0.00102 (14 / 13,746) |
| PER_GROUP_NORMAL | 0 | - | 0.00116 (16 / 13,746) |
| RANDOM_GROUP_NORMAL | 0 | - | 0.00138 (19 / 13,746) |
| GLOBAL_NORMAL | 1 | - | 0.00065 (9 / 13,746) |
| PER_GROUP_NORMAL | 1 | - | 0.00109 (15 / 13,746) |
| RANDOM_GROUP_NORMAL | 1 | - | 0.00095 (13 / 13,746) |
| GLOBAL_NORMAL | 2 | - | 0.00065 (9 / 13,746) |
| PER_GROUP_NORMAL | 2 | - | 0.00087 (12 / 13,746) |
| RANDOM_GROUP_NORMAL | 2 | - | 0.00131 (18 / 13,746) |
| GLOBAL_NORMAL | 3 | - | 0.00124 (17 / 13,746) |
| PER_GROUP_NORMAL | 3 | - | 0.00073 (10 / 13,746) |
| RANDOM_GROUP_NORMAL | 3 | - | 0.00080 (11 / 13,746) |
| GLOBAL_NORMAL | 4 | - | 0.00073 (10 / 13,746) |
| PER_GROUP_NORMAL | 4 | - | 0.00124 (17 / 13,746) |
| RANDOM_GROUP_NORMAL | 4 | - | 0.00080 (11 / 13,746) |

- determinism (seed-0 refit): {'GLOBAL_NORMAL': {'seed': 0, 'identical': True, 'per_model': {'__global__': True}}, 'PER_GROUP_NORMAL': {'seed': 0, 'identical': True, 'per_model': {'G1': True, 'G2': True, 'GEN': True}}, 'RANDOM_GROUP_NORMAL': {'seed': 0, 'identical': True, 'per_model': {'G1': True, 'G2': True, 'GEN': True}}}

## Checks

- PASS  every arm x seed fitted and saved  15 arm x seed fits
- PASS  every model's in-sample flag rate == the nominal 1 - q (+- 1 row)  ties at the top of a model's scores would lower it (report-only)
- PASS  determinism: seed-0 refit of every arm gives identical scores  {'GLOBAL_NORMAL': True, 'PER_GROUP_NORMAL': True, 'RANDOM_GROUP_NORMAL': True}
