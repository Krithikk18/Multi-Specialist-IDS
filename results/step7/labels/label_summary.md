# Step 7 -- attack label summary

- rebuilt 2026-10-11T15:14:03+00:00 from 7 report(s) in `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/labels`

| pcap | family | flows | attack | benign | excluded | attacker_offwindow | attacker_normal_traffic | victim_ambiguous | attack_normal_service_ambiguous | spoof_collision | attack_G1 | attack_G2 | attack_GEN | attack_ungrouped | attack_unowned | gateway_victim_attack | pad_only_attack | attacker_ips | t1b_only_flows | victims | groups_vs_07a | hard | runtime_s | peak_rss_mb | run_utc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS-SYN_Flood10 | syn_flood | 6,099,055 | 6,067,638 | 17,953 | 13,464 | 61 | 2 | 0 | 13,401 | 0 | 1,559,800 | 4,507,838 | 0 | 0 | 0 | 0 | 0 | 18 | 0 | 3 | G1:FAIL/FAIL G2:PASS/PASS GEN:FAIL/FAIL | PASS | 708.7 | 6473.9 | 2026-10-11T15:03:26+00:00 |
| DDoS-SYN_Flood15 | syn_flood | 3,104,718 | 3,095,108 | 8,812 | 798 | 186 | 60 | 0 | 552 | 0 | 3,095,100 | 0 | 3 | 0 | 5 | 0 | 3 | 24 | 0 | 4 | G1:PASS/PASS G2:FAIL/FAIL GEN:FAIL/FAIL | PASS | 603.3 | 6473.9 | 2026-10-11T15:13:32+00:00 |
| DDoS-SYN_Flood5 | syn_flood | 5,297,297 | 5,283,182 | 14,060 | 55 | 51 | 1 | 0 | 3 | 0 | 0 | 5,283,182 | 0 | 0 | 0 | 0 | 36 | 18 | 0 | 3 | G1:FAIL/FAIL G2:PASS/PASS GEN:FAIL/FAIL | PASS | 1709.4 | 6357.0 | 2026-10-11T14:51:27+00:00 |
| DDoS-SYN_Flood | syn_flood | 6,800,503 | 6,756,387 | 28,563 | 15,553 | 1,852 | 12 | 0 | 13,689 | 0 | 6,756,387 | 0 | 0 | 0 | 0 | 0 | 168 | 17 | 0 | 4 | G1:PASS/PASS G2:FAIL/FAIL GEN:FAIL/FAIL | PASS | 1831.7 | 6357.0 | 2026-10-11T14:22:29+00:00 |
| Mirai-udpplain24 | udp_flood | 6,251 | 58 | 5,928 | 265 | 231 | 16 | 0 | 18 | 0 | 35 | 23 | 0 | 0 | 0 | 0 | 14 | 31 | 0 | 4 | G1:PASS/PASS G2:PASS/PASS GEN:FAIL/FAIL | PASS | 10.0 | 6473.9 | 2026-10-11T15:14:03+00:00 |
| Mirai-udpplain | udp_flood | 8,806 | 112 | 8,636 | 58 | 25 | 17 | 0 | 16 | 0 | 112 | 0 | 0 | 0 | 0 | 0 | 6 | 14 | 0 | 5 | G1:PASS/PASS G2:FAIL/FAIL GEN:FAIL/FAIL | PASS | 20.4 | 6473.9 | 2026-10-11T15:13:53+00:00 |
| Recon-PortScan | port_scan | 207,429 | 143,138 | 63,341 | 950 | 840 | 24 | 0 | 86 | 0 | 70,026 | 64,584 | 4,356 | 0 | 4,172 | 0 | 272 | 21 | 0 | 57 | G1:PASS/PASS G2:PASS/PASS GEN:PASS/PASS | PASS | 40.1 | 1680.8 | 2026-10-11T13:51:34+00:00 |
