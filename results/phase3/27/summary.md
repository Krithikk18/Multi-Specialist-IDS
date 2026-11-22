# Step 27 -- rate guard v2 thresholds (train benign) -- PASS

- run `20261121T191447Z`; rule: threshold = 2 x max train-benign packets per 1 s window into one device of the group, per protocol family; alert after 3 consecutive windows above it; < 60 non-empty windows -> fallback group, else pooled
- packets: train windows of the train / time_split captures only (reading stops at the end of train); attacker / testbed-Pi MAC packets excluded (V1 step 13's rule)

- thresholds file `/home/krithikk/lgids_cache/v2/rate_guard/v2_1/thresholds.json`, sha256 `c83eddc157a032c42462fe42953398f3d7776964ebfee95592c6a9ee03c3e618`

## Per group x family

| group | family | non-empty windows | max | threshold | source | max at |
|---|---|---|---|---|---|---|
| G1 | TCP | 119,954 | 1,724 | 3,448 | own | Recon-PortScan 2c:71:ff:05:f1:15 |
| G1 | UDP | 77,826 | 349 | 698 | own | benign_night cc:f4:11:9c:d0:00 |
| G1 | other | 5,793 | 10 | 20 | own | DDoS-SYN_Flood 40:5d:82:35:14:c8 |
| G2 | TCP | 58,893 | 322 | 644 | own | benign_night b0:09:da:3e:82:6c |
| G2 | UDP | 4,660 | 13 | 26 | own | Recon-PortScan b0:09:da:3e:82:6c |
| G2 | other | 1,200 | 8 | 16 | own | DDoS-SYN_Flood 44:bb:3b:00:39:07 |
| GEN | TCP | 4,626 | 356 | 712 | own | DDoS-SYN_Flood5 ee:06:3b:b8:d1:df |
| GEN | UDP | 2,944 | 27 | 54 | own | DDoS-SYN_Flood5 ee:06:3b:b8:d1:df |
| GEN | other | 332 | 4 | 8 | own | DDoS-SYN_Flood c0:e7:bf:0a:79:d1 |

## Captures

| session | train packets kept | excluded (attacker / Pi) | counted (protected dst) |
|---|---|---|---|
| benign_night | 2,395,158 | 23,469 | 987,063 |
| DDoS-SYN_Flood | 22,805,264 | 22,659,532 | 72,788 |
| DDoS-SYN_Flood5 | 22,257,594 | 22,180,901 | 37,216 |
| Recon-PortScan | 490,626 | 192,030 | 150,884 |
| Mirai-udpplain | 3,275,152 | 3,214,995 | 22,003 |

## Figures

- `figures/train_benign_rates.png` -- per group x family, the train-benign 1 s rate distribution (log x, log y) with the max (dotted) and the threshold (solid).

## Checks

- PASS  zero train-benign windows above an own-data threshold (by construction)  0 windows over
- PASS  train-benign windows above a fallback / pooled threshold (groups with < min windows; report-only)  {}
- PASS  every group label x family has a threshold  3 groups x 3 families
