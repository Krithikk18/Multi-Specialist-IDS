# Step 7a -- attack coverage (attacker MAC -> victim device -> behaviour group)

- rebuilt: 2026-10-10T20:44:36+00:00 from 8 per-pcap stats file(s) in `/mnt/d/Projects/Company Project/Paper_Implemetation/results/step7/coverage`
- attacker MACs: exact ['e4:5f:01:55:90:c4'], prefixes ['dc:a6:32']; device table `/mnt/d/Projects/Company Project/Paper_Implemetation/config/device_table.csv` (sha256 `506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532`) (10 testbed-Pi rows match, safety check passed)
- victim rule (per attacker MAC -> device pair vs control `/home/krithikk/lgids_cache/BenignTraffic.pcap`): rate > 10 x control rate (control packets floored at 1) OR >= 1 new (ip.proto, min(src_port, dst_port) for TCP/UDP else none) pair(s)
- min victims per group: 2; spoofing flag: > 10 distinct ip.src; tshark env TZ=UTC; params=STALE rows were computed with a different completion key (rule parameters / control / device_table) -- re-run them

## Overview

| pcap | G1 | G2 | GEN | gateway | overall | attacker_pkts | pkt_per_min | x_control | bursts | spoofed | ip_mac_disagree | background_pct | params |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS-SYN_Flood10 | 1 FAIL | 2 PASS | 0 | 1 | G2-only | 26,420,022 | 750516.19 | 21672.4 | 1 | yes | 0 | 0.519 | current |
| DDoS-SYN_Flood15 | 3 PASS | 0 FAIL | 1 | 1 | G1-only | 13,545,175 | 5200.26 | 150.2 | 2 | yes | 0 | 0.697 | current |
| DDoS-SYN_Flood5 | 0 FAIL | 3 PASS | 0 | 1 | G2-only | 26,604,267 | 726719.69 | 20985.3 | 3 | no | 0 | 0.432 | current |
| DDoS-SYN_Flood | 5 PASS | 0 FAIL | 0 | 0 | G1-only | 26,003,644 | 6543.89 | 189.0 | 4 | no | 0 | 0.742 | current |
| DictionaryBruteForce | 0 FAIL | 1 FAIL | 0 | 0 | NONE | 26,759 | 6.31 | 0.2 | 5 | no | 0 | 77.447 | current |
| Mirai-udpplain24 | 3 PASS | 2 PASS | 0 | 1 | BOTH | 1,456,835 | 143.47 | 4.1 | 2 | no | 0 | 3.159 | current |
| Mirai-udpplain | 5 PASS | 0 FAIL | 0 | 1 | G1-only | 3,563,700 | 109878.86 | 3172.9 | 3 | no | 0 | 2.13 | current |
| Recon-PortScan | 25 PASS | 27 PASS | 3 | 1 | BOTH | 147,498 | 99.32 | 2.9 | 22 | no | 0 | 67.182 | current |

## Control: BenignTraffic

- packets 3,664,164; 555.5 min; attacker-MAC packets 19,235 = **34.63 pkt/min** (burst threshold 346.3 pkt/min); sha256 `549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8`; baseline built 2026-10-10T13:12:28+00:00

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | 3c:18:a0:41:c3:a0 | gateway | 1,500,837 | 40.96 |
| 2 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 666,068 | 18.178 |
| 3 | ac:17:02:05:34:27 | Fibaro Home Center Lite | 215,849 | 5.891 |
| 4 | 44:bb:3b:00:39:07 | Nest Indoor Camera | 194,661 | 5.313 |
| 5 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 135,130 | 3.688 |
| 6 | 24:05:88:30:6f:89 | Unknown | 112,295 | 3.065 |
| 7 | a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | 103,548 | 2.826 |
| 8 | 56:4f:8a:e1:f3:2d | Randomised MAC (phone/laptop) | 48,696 | 1.329 |
| 9 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 39,889 | 1.089 |
| 10 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 38,591 | 1.053 |
| 11 | 00:17:88:60:d6:4f | Philips Hue Bridge | 30,401 | 0.83 |
| 12 | ac:f1:08:4e:00:82 | LG Smart TV | 30,327 | 0.828 |
| 13 | b0:f1:ec:d3:e7:98 | Harman Kardon speaker (Ampak) | 29,729 | 0.811 |
| 14 | 7c:78:b2:86:0d:81 | Wyze Camera | 29,657 | 0.809 |
| 15 | 34:75:63:73:f3:36 | Home Eye Camera | 25,336 | 0.691 |
| 16 | 84:7a:b6:62:3a:6c | Yi Indoor 2 Camera | 25,287 | 0.69 |
| 17 | 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | 24,806 | 0.677 |
| 18 | 70:ee:50:68:0e:32 | Netatmo Camera | 24,114 | 0.658 |
| 19 | 00:a3:d1:07:6f:03 | Unknown | 22,837 | 0.623 |
| 20 | dc:a6:32:dc:27:d5 | attacker | 18,563 | 0.507 |
| 21 | 28:6d:97:7a:2b:2d | SmartThings Hub | 17,821 | 0.486 |
| 22 | 28:6d:97:9e:f4:d5 | Aeotec Smart Home Hub | 16,842 | 0.46 |
| 23 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 16,416 | 0.448 |
| 24 | 10:5a:17:97:a5:c6 | Rbcior Camera | 14,566 | 0.398 |
| 25 | 8c:85:80:6c:b6:47 | Eufy HomeBase 2 | 11,687 | 0.319 |
| 26 | f4:cf:a2:34:48:6b | LampUX RGB | 11,122 | 0.304 |
| 27 | c4:dd:57:0c:39:94 | Unidentified ESP plug (3) | 11,086 | 0.303 |
| 28 | 24:a1:60:14:7f:f9 | Unidentified ESP plug (1) | 11,085 | 0.303 |
| 29 | 50:02:91:10:09:8f | Unidentified ESP plug (2) | 11,084 | 0.302 |
| 30 | b8:f0:09:03:29:79 | GoSund Smart Plug WP2 (1) | 11,082 | 0.302 |

## Attack: DDoS-SYN_Flood10

- sha256: `ea6223afa0458d117e90bb2972145cfa002d2172f7a5a706ca32d5fa4c59f1c9`
- rate plot: `attack_rate_DDoS-SYN_Flood10.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood10.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T20:35:38+00:00; peak RSS so far 298.7 MB (python), 426.1 MB (tshark)
- packets: 26,762,773; capture 2022-08-30T13:10:09.100902+00:00 -> 2022-08-30T13:45:21.248973+00:00 (35.2 min); tshark+aggregation 765.3 s
- attacker-MAC packets: sent 26,420,022 (98.719%), received 203,868
- **background share** (neither from nor to an attacker MAC): 0.519%
- attacker packets span 2022-08-30T13:10:09.100902+00:00 -> 2022-08-30T13:45:21.248973+00:00; 32 active minutes; 750,516.19 pkt/min over the capture, peak 1,128,595
- attacker protocols: {'TCP': 26413650, 'none': 6231, 'UDP': 139, 'IGMP': 2}; TCP flags: {'SYN': 26266966, 'RST': 146684}
- broadcast / multicast destinations of attacker packets (never victims): {'broadcast': 4573, 'multicast': 49}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 21, 'lan_xcheck_keys': 41}

**Coverage (min victims 2):** overall **G2-only**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 1 | 6,361,949 | 2022-08-30T13:38:27.055655+00:00 | 2022-08-30T13:45:21.248973+00:00 | FAIL |
| G2 | 2 | 20,053,286 | 2022-08-30T13:10:09.100902+00:00 | 2022-08-30T13:35:00.085142+00:00 | PASS |
| GEN | 0 | 0 |  |  | FAIL |
| gateway | 1 | 165 | 2022-08-30T13:12:03.235713+00:00 | 2022-08-30T13:45:16.130750+00:00 | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 1

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2022-08-30T13:10:00.000000+00:00 | 2022-08-30T13:46:00.000000+00:00 | 36 | 26,420,022 | 1,128,595 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 3,517,920 | 99933.9 | 0.05 | 3 | G1 1, G2 2 | 2 | 13:10:00-13:35:00 (2,777,598 pkts); 13:38:00-13:46:00 (740,322 pkts) |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 4,093,872 | 116295.03 | 0.03 | 3 | G1 1, G2 2 | 2 | 13:10:00-13:21:00 (1,187,074 pkts); 13:24:00-13:46:00 (2,906,758 pkts) |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 171 | 4.86 | 0.46 | 1 | gateway 1 | 0 | - |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 5,030,100 | 142890.55 | 0.05 | 3 | G1 1, G2 2 | 2 | 13:10:00-13:34:00 (4,451,782 pkts); 13:38:00-13:46:00 (578,261 pkts) |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 105 | 2.98 | 0.27 | 1 | gateway 1 | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 3,677,130 | 104456.6 | 0.05 | 3 | G1 1, G2 2 | 2 | 13:10:00-13:35:00 (2,745,249 pkts); 13:38:00-13:46:00 (931,881 pkts) |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 2,851,409 | 81000.26 | 0.05 | 3 | G1 1, G2 2 | 1 | 13:10:00-13:46:00 (2,851,409 pkts) |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 69 | 1.96 | 0.22 | 1 | gateway 1 | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 3,671,284 | 104290.53 | 33.42 | 3 | G1 1, G2 2 | 3 | 13:10:00-13:20:00 (1,134,607 pkts); 13:23:00-13:32:00 (1,030,397 pkts); 13:38:00-13:46:00 (1,506,104 pkts) |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 3,577,962 | 101639.52 | 0.03 | 3 | G1 1, G2 2 | 3 | 13:10:00-13:20:00 (1,205,311 pkts); 13:23:00-13:35:00 (1,591,071 pkts); 13:38:00-13:46:00 (781,500 pkts) |

**Victims (4):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| 18:69:d8:eb:d4:3e | Teckin Light Strip | G2 | 11,634,391 | both | 44901019.11 | 14000+ | 1 | TCP:11634070;none:321 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| c4:dd:57:13:07:c6 | Unidentified ESP plug (4) | G2 | 8,418,895 | both | 25337942.05 | 14000+ | 1 | TCP:8418495;none:400 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 2c:71:ff:05:f1:15 | Amazon Echo Show | G1 | 6,361,949 | both | 17906389.19 | 14000+ | 1 | TCP:6361085;none:864 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 3c:18:a0:41:c3:a0 | Gateway / router | gateway | 165 | rate | 14.61 | 0 | 2 | UDP:115;none:50 | dc:a6:32:c9:e4:c6;dc:a6:32:c9:e5:02;dc:a6:32:c9:e6:f4 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:d5 | Teckin Light Strip | G2 | 2,845,586 | 0 | 44901019.11 | 2000+ | TCP/6668:2555136;TCP/2544:46;TCP/2545:46;TCP/2546:46;TCP/2556:46;TCP/2901:46;TCP/3608:46;TCP/3609:46 | both |
| dc:a6:32:c9:e4:ab | Teckin Light Strip | G2 | 1,771,587 | 0 | 27954193.53 | 2000+ | TCP/6668:1590737;TCP/6090:29;TCP/6091:29;TCP/6092:29;TCP/6130:29;TCP/6131:29;TCP/6132:29;TCP/6133:29 | both |
| dc:a6:32:c9:e5:a4 | Teckin Light Strip | G2 | 1,734,579 | 0 | 27370237.56 | 2000+ | TCP/6668:1557357;TCP/2229:29;TCP/2230:29;TCP/2231:29;TCP/2171:28;TCP/2184:28;TCP/2185:28;TCP/2186:28 | both |
| dc:a6:32:c9:e4:d5 | Unidentified ESP plug (4) | G2 | 1,605,783 | 0 | 25337942.05 | 2000+ | TCP/6668:1439904;none:66;TCP/0:25;TCP/1:25;TCP/2:25;TCP/3:25;TCP/4:25;TCP/5:25 | both |
| e4:5f:01:55:90:c4 | Teckin Light Strip | G2 | 1,590,743 | 0 | 25100623.16 | 2000+ | TCP/6668:1426153;TCP/2311:26;TCP/2312:26;TCP/2313:26;TCP/2314:26;TCP/2315:26;TCP/2511:26;TCP/2512:26 | both |
| dc:a6:32:dc:27:d5 | Amazon Echo Show | G1 | 1,505,975 | 302 | 78685.61 | 2000+ | TCP/3744:26;TCP/4182:26;TCP/2780:25;TCP/2781:25;TCP/3523:25;TCP/3524:25;TCP/2776:24;TCP/2777:24 | both |
| dc:a6:32:c9:e4:90 | Teckin Light Strip | G2 | 1,433,460 | 0 | 22618826.09 | 2000+ | TCP/6668:1282801;TCP/2312:25;TCP/2313:25;TCP/2314:25;TCP/2161:24;TCP/2162:24;TCP/2163:24;TCP/2164:24 | both |
| dc:a6:32:c9:e4:90 | Unidentified ESP plug (4) | G2 | 1,343,687 | 0 | 21202281.59 | 2000+ | TCP/6668:1204470;TCP/0:21;TCP/1:21;TCP/2:21;TCP/3:21;TCP/4:21;TCP/5:21;TCP/6:21 | both |
| dc:a6:32:c9:e5:ef | Teckin Light Strip | G2 | 1,228,334 | 0 | 19382105.62 | 2000+ | TCP/6668:1099877;TCP/4248:22;TCP/4249:22;TCP/5450:22;TCP/5451:22;TCP/5924:22;TCP/5925:22;TCP/5926:22 | both |
| e4:5f:01:55:90:c4 | Unidentified ESP plug (4) | G2 | 1,205,212 | 0 | 19017259.38 | 2000+ | TCP/6668:1078952;TCP/0:19;TCP/1:19;TCP/2:19;TCP/3:19;TCP/4:19;TCP/5:19;TCP/6:19 | both |
| dc:a6:32:c9:e4:ab | Unidentified ESP plug (4) | G2 | 1,186,897 | 0 | 18728263.66 | 2000+ | TCP/6668:1067153;none:57;TCP/3913:20;TCP/0:18;TCP/1:18;TCP/2:18;TCP/3:18;TCP/4:18 | both |
| dc:a6:32:c9:e4:ab | Amazon Echo Show | G1 | 1,134,811 | 0 | 17906389.19 | 2000+ | TCP/8009:993638;TCP/2992:20;TCP/6260:20;TCP/6261:20;TCP/6262:20;TCP/2980:19;TCP/2981:19;TCP/2982:19 | both |
| dc:a6:32:dc:27:d5 | Unidentified ESP plug (4) | G2 | 1,134,424 | 0 | 17900282.65 | 2000+ | TCP/6668:1012138;none:52;TCP/645:19;TCP/646:19;TCP/647:19;TCP/648:19;TCP/649:19;TCP/650:19 | both |
| dc:a6:32:dc:27:d5 | Teckin Light Strip | G2 | 1,030,102 | 0 | 16254166.84 | 2000+ | TCP/6668:928789;TCP/2647:17;TCP/3287:17;TCP/3288:17;TCP/3289:17;TCP/3290:17;TCP/3291:17;TCP/3292:17 | both |
| dc:a6:32:c9:e5:a4 | Unidentified ESP plug (4) | G2 | 1,010,213 | 0 | 15940334.69 | 2000+ | TCP/6668:910698;none:52;TCP/0:15;TCP/1:15;TCP/2:15;TCP/3:15;TCP/4:15;TCP/5:15 | both |
| dc:a6:32:c9:e5:ef | Unidentified ESP plug (4) | G2 | 932,679 | 0 | 14716911.6 | 2000+ | TCP/6668:833306;TCP/0:15;TCP/1:15;TCP/2:15;TCP/3:15;TCP/4:15;TCP/5:15;TCP/6:15 | both |
| dc:a6:32:c9:e5:a4 | Amazon Echo Show | G1 | 931,781 | 0 | 14702741.89 | 2000+ | TCP/8009:812665;TCP/3037:17;TCP/3355:17;TCP/3356:17;TCP/3357:17;TCP/3358:17;TCP/3359:17;TCP/3360:17 | both |
| e4:5f:01:55:90:c4 | Amazon Echo Show | G1 | 781,359 | 0 | 12329205.79 | 2000+ | TCP/8009:687589;none:124;TCP/5186:15;TCP/5187:15;TCP/5188:15;TCP/5189:15;TCP/5190:15;TCP/5191:15 | both |
| dc:a6:32:c9:e4:90 | Amazon Echo Show | G1 | 740,244 | 0 | 11680444.73 | 2000+ | TCP/8009:646116;TCP/3483:14;TCP/4288:14;TCP/4289:14;TCP/4290:14;TCP/4357:14;TCP/4358:14;TCP/4359:14 | both |
| dc:a6:32:c9:e5:ef | Amazon Echo Show | G1 | 689,674 | 0 | 10882491.5 | 2000+ | TCP/8009:605752;TCP/7243:14;TCP/7245:14;TCP/7246:14;TCP/7247:14;TCP/7244:13;TCP/7577:13;TCP/7578:13 | both |
| dc:a6:32:c9:e4:d5 | Amazon Echo Show | G1 | 578,105 | 0 | 9122023.95 | 2000+ | TCP/8009:512045;TCP/2741:10;TCP/2742:10;TCP/2743:10;TCP/2744:10;TCP/2745:10;TCP/2746:10;TCP/2747:10 | both |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 75 | 81 | 14.61 | 0 |  | rate |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 50 | 60 | 13.15 | 0 |  | rate |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 40 | 59 | 10.7 | 0 |  | rate |

**Spoofing:** 11 distinct ip.src on attacker-MAC packets (exact) -> **SPOOFED SOURCES** (threshold > 10); 0 are real smart-home device IPs in this pcap's map (0 packets), 0 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.224 | 5,029,239 | False |
| 192.168.137.240 | 4,093,091 | False |
| 192.168.137.96 | 3,676,375 | False |
| 192.168.137.17 | 3,670,310 | False |
| 192.168.137.134 | 3,577,019 | False |
| 192.168.137.195 | 3,517,146 | False |
| 192.168.137.58 | 2,850,472 | False |
| 192.168.137.213 | 68 | False |
| 192.168.137.242 | 37 | False |
| 192.168.137.90 | 33 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| agree | 26,413,746 |
| no_ip_dst (non-IPv4) | 6,231 |
| multicast ip.dst | 25 |
| external ip.dst via gateway MAC | 19 |
| limited_broadcast ip.dst | 1 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | dc:a6:32:c9:e4:d5 | attacker | 5,030,100 | 18.795 |
| 2 | dc:a6:32:c9:e4:ab | attacker | 4,093,872 | 15.297 |
| 3 | dc:a6:32:c9:e5:a4 | attacker | 3,677,130 | 13.74 |
| 4 | dc:a6:32:dc:27:d5 | attacker | 3,671,284 | 13.718 |
| 5 | e4:5f:01:55:90:c4 | attacker | 3,577,962 | 13.369 |
| 6 | dc:a6:32:c9:e4:90 | attacker | 3,517,920 | 13.145 |
| 7 | dc:a6:32:c9:e5:ef | attacker | 2,851,409 | 10.654 |
| 8 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 125,515 | 0.469 |
| 9 | 18:69:d8:eb:d4:3e | Teckin Light Strip | 82,317 | 0.308 |
| 10 | 3c:18:a0:41:c3:a0 | gateway | 55,703 | 0.208 |
| 11 | ac:17:02:05:34:27 | Fibaro Home Center Lite | 14,380 | 0.054 |
| 12 | a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | 5,798 | 0.022 |
| 13 | b0:f1:ec:d3:e7:98 | Harman Kardon speaker (Ampak) | 3,547 | 0.013 |
| 14 | 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | 3,386 | 0.013 |
| 15 | ee:06:3b:b8:d1:df | unknown | 3,203 | 0.012 |
| 16 | e8:1b:69:f8:d4:e3 | Unknown | 2,944 | 0.011 |
| 17 | 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | 2,679 | 0.01 |
| 18 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 2,603 | 0.01 |
| 19 | 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | 2,489 | 0.009 |
| 20 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 1,696 | 0.006 |
| 21 | 10:2c:6b:1b:43:be | unknown | 1,636 | 0.006 |
| 22 | 7c:78:b2:86:0d:81 | Wyze Camera | 1,406 | 0.005 |
| 23 | 6c:5a:b0:44:1d:90 | TP-Link Tapo Camera | 1,305 | 0.005 |
| 24 | 84:e3:42:42:ed:0b | Lumiman Bulb | 1,289 | 0.005 |
| 25 | 44:bb:3b:00:39:07 | Nest Indoor Camera | 1,235 | 0.005 |
| 26 | 00:a3:d1:07:6f:03 | Unknown | 1,201 | 0.004 |
| 27 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 1,183 | 0.004 |
| 28 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 1,171 | 0.004 |
| 29 | c4:dd:57:13:07:c6 | Unidentified ESP plug (4) | 955 | 0.004 |
| 30 | 28:6d:97:7a:2b:2d | SmartThings Hub | 928 | 0.003 |

## Attack: DDoS-SYN_Flood15

- sha256: `cac4947ac5b84447b7da9e49ff31dfdc394b4f8f60f9af83987d1fb02be355aa`
- rate plot: `attack_rate_DDoS-SYN_Flood15.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood15.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T20:42:26+00:00; peak RSS so far 298.7 MB (python), 426.1 MB (tshark)
- packets: 13,722,634; capture 2022-11-29T19:18:18.222383+00:00 -> 2022-12-01T14:43:00.883049+00:00 (2604.71 min); tshark+aggregation 405.0 s
- attacker-MAC packets: sent 13,545,175 (98.707%), received 81,844
- **background share** (neither from nor to an attacker MAC): 0.697%
- attacker packets span 2022-11-29T19:18:18.222383+00:00 -> 2022-12-01T14:43:00.883049+00:00; 24 active minutes; 5,200.26 pkt/min over the capture, peak 1,118,432
- attacker protocols: {'TCP': 13541919, 'none': 3083, 'UDP': 154, 'ICMP': 19}; TCP flags: {'SYN': 13467305, 'RST': 73948, 'PSH+ACK': 317, 'ACK': 260, 'FIN+ACK': 56, 'FIN+PSH+ACK': 31, 'RST+ACK': 2}
- broadcast / multicast destinations of attacker packets (never victims): {'broadcast': 1596, 'multicast': 98}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 7, 'lan_xcheck_keys': 63}

**Coverage (min victims 2):** overall **G1-only**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 3 | 13,542,373 | 2022-11-29T19:18:18.222383+00:00 | 2022-12-01T14:43:00.883049+00:00 | PASS |
| G2 | 0 | 0 |  |  | FAIL |
| GEN | 1 | 126 | 2022-11-29T19:18:20.661873+00:00 | 2022-11-29T19:28:39.823959+00:00 | FAIL |
| gateway | 1 | 425 | 2022-11-29T19:18:31.145220+00:00 | 2022-12-01T14:43:00.473846+00:00 | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 2

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2022-11-29T19:18:00.000000+00:00 | 2022-11-29T19:22:00.000000+00:00 | 4 | 3,177,940 | 1,047,578 |
| 2022-12-01T14:32:00.000000+00:00 | 2022-12-01T14:44:00.000000+00:00 | 12 | 10,366,387 | 1,118,432 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 2,278,584 | 874.79 | 0.05 | 2 | G1 2 | 2 | 19:18:00-19:22:00 (419,864 pkts); 14:32:00-14:44:00 (1,858,711 pkts) |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 3,125,703 | 1200.02 | 0.03 | 2 | G1 2 | 2 | 19:18:00-19:22:00 (1,214,684 pkts); 14:32:00-14:44:00 (1,911,012 pkts) |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 34 | 0.01 | 0.46 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 1,423,029 | 546.33 | 0.05 | 2 | G1 2 | 2 | 19:18:00-19:22:00 (300,690 pkts); 14:32:00-14:44:00 (1,122,213 pkts) |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 11 | 0.0 | 0.27 | 0 | - | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 1,266,695 | 486.31 | 0.05 | 2 | G1 2 | 2 | 19:18:00-19:22:00 (200,176 pkts); 14:32:00-14:44:00 (1,066,488 pkts) |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 1,856,158 | 712.62 | 0.05 | 2 | G1 2 | 2 | 19:18:00-19:22:00 (245,917 pkts); 14:32:00-14:43:00 (1,610,177 pkts) |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 15 | 0.01 | 0.22 | 0 | - | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 1,604,581 | 616.03 | 33.42 | 5 | G1 3, GEN 1, unknown 1 | 2 | 19:19:00-19:22:00 (180,396 pkts); 14:32:00-14:44:00 (1,423,658 pkts) |
| dc:a6:32:dc:28:48 | not in device_table | 571 | 0.22 | 0.0 | 1 | gateway 1 | 0 | - |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 1,989,794 | 763.92 | 0.03 | 2 | G1 2 | 2 | 19:18:00-19:22:00 (615,980 pkts); 14:32:00-14:44:00 (1,373,796 pkts) |

**Victims (6):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| 48:a6:b8:f9:1b:88 | Sonos One Speaker | G1 | 10,365,155 | both | 407514.06 | 10,115 | 1 | TCP:10364186;none:969 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | G1 | 3,177,190 | both | 259029.7 | 14000+ | 1 | TCP:3176843;none:347 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 3c:18:a0:41:c3:a0 | Gateway / router | gateway | 425 | both | 90.63 | 5 | 3 | TCP:309;UDP:89;none:26;ICMP:1 | dc:a6:32:dc:28:48 |
| 00:02:75:f6:e3:cb | Smart Board | GEN | 126 | both | 26.87 | 2 | 1 | TCP:118;none:8 | dc:a6:32:dc:27:d5 |
| 00:02:75:f4:97:45 | unknown | unknown | 106 | both | 22.6 | 3 | 2 | TCP:102;none:4 | dc:a6:32:dc:27:d5 |
| 2c:71:ff:05:f1:15 | Amazon Echo Show | G1 | 28 | new_service | 0.02 | 2 | 1 | TCP:16;none:12 | dc:a6:32:dc:27:d5 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:ab | Sonos One Speaker | G1 | 1,910,929 | 0 | 407514.06 | 1,445 | TCP/1443:1868848;none:136;TCP/698:33;TCP/1104:33;TCP/1105:33;TCP/1106:33;TCP/1107:33;TCP/1108:33 | both |
| dc:a6:32:c9:e4:90 | Sonos One Speaker | G1 | 1,858,636 | 0 | 396362.35 | 1,445 | TCP/1443:1818246;none:145;TCP/639:32;TCP/640:32;TCP/1248:31;TCP/1249:31;TCP/1410:31;TCP/879:30 | both |
| dc:a6:32:c9:e5:ef | Sonos One Speaker | G1 | 1,610,128 | 0 | 343366.92 | 1,445 | TCP/1443:1575307;none:131;TCP/726:27;TCP/727:27;TCP/728:27;TCP/729:27;TCP/968:27;TCP/969:27 | both |
| dc:a6:32:dc:27:d5 | Sonos One Speaker | G1 | 1,423,220 | 0 | 303507.96 | 1,445 | TCP/1443:1393943;none:140;TCP/1328:24;TCP/1334:24;TCP/1335:24;TCP/1336:24;TCP/1337:24;TCP/1338:24 | both |
| e4:5f:01:55:90:c4 | Sonos One Speaker | G1 | 1,373,717 | 0 | 292951.23 | 1,445 | TCP/1443:1343699;none:130;TCP/941:28;TCP/942:28;TCP/940:25;TCP/943:24;TCP/944:24;TCP/945:24 | both |
| dc:a6:32:c9:e4:ab | Amazon Alexa Echo Dot 2 | G1 | 1,214,651 | 0 | 259029.7 | 2000+ | TCP/4070:1140578;none:51;TCP/3794:22;TCP/3854:21;TCP/3855:21;TCP/3856:21;TCP/3857:21;TCP/3793:21 | both |
| dc:a6:32:c9:e4:d5 | Sonos One Speaker | G1 | 1,122,128 | 0 | 239298.76 | 1,445 | TCP/1443:1097417;none:141;TCP/82:20;TCP/83:20;TCP/84:20;TCP/609:20;TCP/610:20;TCP/611:20 | both |
| dc:a6:32:c9:e5:a4 | Sonos One Speaker | G1 | 1,066,397 | 0 | 227413.88 | 1,445 | TCP/1443:1043201;none:146;TCP/842:20;TCP/843:20;TCP/844:20;TCP/845:20;TCP/846:20;TCP/847:20 | both |
| e4:5f:01:55:90:c4 | Amazon Alexa Echo Dot 2 | G1 | 615,875 | 0 | 131338.07 | 2000+ | TCP/4070:579777;none:35;TCP/449:10;TCP/450:10;TCP/451:10;TCP/452:10;TCP/264:10;TCP/265:10 | both |
| dc:a6:32:c9:e4:90 | Amazon Alexa Echo Dot 2 | G1 | 419,819 | 0 | 89528.26 | 2000+ | TCP/4070:394976;TCP/2724:9;TCP/2725:9;TCP/2726:9;TCP/2727:9;TCP/2728:9;TCP/2729:9;TCP/2730:9 | both |
| dc:a6:32:c9:e4:d5 | Amazon Alexa Echo Dot 2 | G1 | 300,622 | 0 | 64108.97 | 2000+ | TCP/4070:283021;none:45;TCP/3634:7;TCP/3749:7;TCP/3750:7;TCP/3751:7;TCP/3769:7;TCP/3770:7 | both |
| dc:a6:32:c9:e5:ef | Amazon Alexa Echo Dot 2 | G1 | 245,850 | 0 | 52428.6 | 2000+ | TCP/4070:231948;none:52;TCP/76:5;TCP/77:5;TCP/78:5;TCP/79:5;TCP/80:5;TCP/81:5 | both |
| dc:a6:32:c9:e5:a4 | Amazon Alexa Echo Dot 2 | G1 | 200,132 | 0 | 42679.03 | 2000+ | TCP/4070:187686;none:40;TCP/720:5;TCP/87:4;TCP/88:4;TCP/89:4;TCP/90:4;TCP/91:4 | both |
| dc:a6:32:dc:27:d5 | Amazon Alexa Echo Dot 2 | G1 | 180,241 | 0 | 38437.19 | 2000+ | TCP/4070:167953;none:62;TCP/741:4;TCP/742:4;TCP/743:4;TCP/744:4;TCP/745:4;TCP/746:4 | both |
| dc:a6:32:dc:28:48 | Gateway / router | gateway | 425 | 0 | 90.63 | 5 | TCP/443:309;UDP/53:84;none:26;UDP/123:5;ICMP:1 | both |
| dc:a6:32:dc:27:d5 | Smart Board | GEN | 126 | 0 | 26.87 | 2 | TCP/8009:118;none:8 | both |
| dc:a6:32:dc:27:d5 | unknown | unknown | 106 | 0 | 22.6 | 3 | TCP/8009:101;none:4;TCP/8008:1 | both |
| dc:a6:32:dc:27:d5 | Amazon Echo Show | G1 | 28 | 302 | 0.02 | 2 | TCP/58786:8;TCP/58788:8 | new_service |
| dc:a6:32:dc:27:d5 | Google Nest Mini Speaker | G1 | 366 | 13,401 | 0.01 | 0 |  |  |
| dc:a6:32:dc:27:d5 | Philips Hue Bridge | G1 | 64 | 3,488 | 0.0 | 0 |  |  |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 9 | 81 | 0.02 | 0 |  |  |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 9 | 60 | 0.03 | 0 |  |  |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 3 | 59 | 0.01 | 0 |  |  |

**Spoofing:** 15 distinct ip.src on attacker-MAC packets (exact) -> **SPOOFED SOURCES** (threshold > 10); 2 are real smart-home device IPs in this pcap's map (122 packets), 2 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.201 | 3,125,394 | False |
| 192.168.137.99 | 2,278,249 | False |
| 192.168.137.36 | 1,989,428 | False |
| 192.168.137.34 | 1,855,796 | False |
| 192.168.137.7 | 1,603,903 | False |
| 192.168.137.153 | 1,422,565 | False |
| 192.168.137.87 | 1,266,344 | False |
| 192.168.137.105 | 279 | False |
| 192.168.137.68 | 120 | True |
| 192.168.137.238 | 3 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| agree | 13,541,702 |
| no_ip_dst (non-IPv4) | 3,083 |
| external ip.dst via gateway MAC | 322 |
| multicast ip.dst | 57 |
| lan ip.dst unmapped_at_time | 11 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | dc:a6:32:c9:e4:ab | attacker | 3,125,703 | 22.778 |
| 2 | dc:a6:32:c9:e4:90 | attacker | 2,278,584 | 16.605 |
| 3 | e4:5f:01:55:90:c4 | attacker | 1,989,794 | 14.5 |
| 4 | dc:a6:32:c9:e5:ef | attacker | 1,856,158 | 13.526 |
| 5 | dc:a6:32:dc:27:d5 | attacker | 1,604,581 | 11.693 |
| 6 | dc:a6:32:c9:e4:d5 | attacker | 1,423,029 | 10.37 |
| 7 | dc:a6:32:c9:e5:a4 | attacker | 1,266,695 | 9.231 |
| 8 | a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | 57,680 | 0.42 |
| 9 | 3c:18:a0:41:c3:a0 | gateway | 34,457 | 0.251 |
| 10 | 48:a6:b8:f9:1b:88 | Sonos One Speaker | 30,884 | 0.225 |
| 11 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 4,853 | 0.035 |
| 12 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 3,352 | 0.024 |
| 13 | 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | 3,247 | 0.024 |
| 14 | b0:f1:ec:d3:e7:98 | Harman Kardon speaker (Ampak) | 2,393 | 0.017 |
| 15 | 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | 2,025 | 0.015 |
| 16 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 1,928 | 0.014 |
| 17 | 84:7a:b6:64:62:58 | Yi Indoor Camera | 1,818 | 0.013 |
| 18 | 56:4f:8a:e1:f3:2d | Randomised MAC (phone/laptop) | 1,723 | 0.013 |
| 19 | 2c:d2:6b:66:d2:87 | Yi Outdoor Camera | 1,720 | 0.013 |
| 20 | e8:1b:69:f8:d4:e3 | Unknown | 1,623 | 0.012 |
| 21 | 10:2c:6b:1b:43:be | unknown | 1,551 | 0.011 |
| 22 | 7c:78:b2:86:0d:81 | Wyze Camera | 1,372 | 0.01 |
| 23 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 1,312 | 0.01 |
| 24 | 28:6d:97:7a:2b:2d | SmartThings Hub | 1,212 | 0.009 |
| 25 | 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | 945 | 0.007 |
| 26 | c0:e7:bf:0a:79:d1 | unknown | 899 | 0.007 |
| 27 | 00:a3:d1:07:6f:03 | Unknown | 890 | 0.006 |
| 28 | 70:ee:50:68:0e:32 | Netatmo Camera | 885 | 0.006 |
| 29 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 868 | 0.006 |
| 30 | 6c:5a:b0:44:1d:90 | TP-Link Tapo Camera | 819 | 0.006 |

## Attack: DDoS-SYN_Flood5

- sha256: `298d6249ddb4e721d67c05b0cd015b7f9ad1dcdcf3eb305c739d803f1b8ee9ad`
- rate plot: `attack_rate_DDoS-SYN_Flood5.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood5.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T20:22:46+00:00; peak RSS so far 298.7 MB (python), 426.1 MB (tshark)
- packets: 26,720,136; capture 2022-08-29T17:20:34.262862+00:00 -> 2022-08-29T17:57:10.785191+00:00 (36.61 min); tshark+aggregation 752.8 s
- attacker-MAC packets: sent 26,604,267 (99.566%), received 548
- **background share** (neither from nor to an attacker MAC): 0.432%
- attacker packets span 2022-08-29T17:20:34.262862+00:00 -> 2022-08-29T17:57:10.785191+00:00; 28 active minutes; 726,719.69 pkt/min over the capture, peak 1,280,428
- attacker protocols: {'TCP': 26600536, 'none': 3652, 'UDP': 76, 'ICMP': 3}; TCP flags: {'SYN': 26600392, 'RST': 144}
- broadcast / multicast destinations of attacker packets (never victims): {'broadcast': 2470, 'multicast': 20}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 20, 'lan_xcheck_keys': 32}

**Coverage (min victims 2):** overall **G2-only**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 0 | 0 |  |  | FAIL |
| G2 | 3 | 26,601,654 | 2022-08-29T17:20:34.262862+00:00 | 2022-08-29T17:57:10.785191+00:00 | PASS |
| GEN | 0 | 0 |  |  | FAIL |
| gateway | 1 | 101 | 2022-08-29T17:21:01.345653+00:00 | 2022-08-29T17:56:46.903671+00:00 | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 3

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2022-08-29T17:20:00.000000+00:00 | 2022-08-29T17:33:00.000000+00:00 | 13 | 12,451,249 | 1,208,857 |
| 2022-08-29T17:36:00.000000+00:00 | 2022-08-29T17:49:00.000000+00:00 | 13 | 13,275,901 | 1,280,428 |
| 2022-08-29T17:56:00.000000+00:00 | 2022-08-29T17:58:00.000000+00:00 | 2 | 877,117 | 700,045 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 4,323,055 | 118088.17 | 0.05 | 3 | G2 3 | 3 | 17:20:00-17:33:00 (2,024,280 pkts); 17:36:00-17:49:00 (2,158,691 pkts); 17:56:00-17:58:00 (140,084 pkts) |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 3,785,269 | 103398.06 | 0.03 | 3 | G2 3 | 3 | 17:20:00-17:32:00 (1,701,127 pkts); 17:36:00-17:49:00 (1,942,154 pkts); 17:56:00-17:58:00 (141,987 pkts) |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 56 | 1.53 | 0.46 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 3,973,818 | 108548.44 | 0.05 | 3 | G2 3 | 3 | 17:20:00-17:32:00 (1,684,013 pkts); 17:36:00-17:49:00 (2,104,798 pkts); 17:56:00-17:58:00 (185,006 pkts) |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 86 | 2.35 | 0.27 | 1 | gateway 1 | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 4,289,716 | 117177.48 | 0.05 | 3 | G2 3 | 3 | 17:20:00-17:32:00 (1,702,795 pkts); 17:36:00-17:49:00 (2,470,013 pkts); 17:56:00-17:58:00 (116,908 pkts) |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 3,650,171 | 99707.73 | 0.05 | 3 | G2 3 | 3 | 17:20:00-17:32:00 (1,647,468 pkts); 17:36:00-17:48:00 (1,868,222 pkts); 17:56:00-17:58:00 (134,412 pkts) |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 87 | 2.38 | 0.22 | 1 | gateway 1 | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 4,011,759 | 109584.84 | 33.42 | 3 | G2 3 | 3 | 17:20:00-17:32:00 (1,768,578 pkts); 17:36:00-17:48:00 (2,084,926 pkts); 17:56:00-17:58:00 (158,194 pkts) |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 2,570,250 | 70208.71 | 0.03 | 3 | G2 3 | 3 | 17:20:00-17:32:00 (1,922,937 pkts); 17:36:00-17:48:00 (646,792 pkts); 17:56:00-17:57:00 (480 pkts) |

**Victims (4):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| 50:02:91:10:09:8f | Unidentified ESP plug (2) | G2 | 13,274,570 | both | 37476126.93 | 14000+ | 1 | TCP:13274070;none:500 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| b8:f0:09:03:29:79 | GoSund Smart Plug WP2 (1) | G2 | 12,450,028 | both | 30712416.09 | 14000+ | 1 | TCP:12449443;none:585 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| c4:dd:57:0c:39:94 | Unidentified ESP plug (3) | G2 | 877,056 | both | 2807001.22 | 12276+ | 1 | TCP:877023;none:33 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 3c:18:a0:41:c3:a0 | Gateway / router | gateway | 101 | both | 14.67 | 2 | 2 | UDP:56;none:42;ICMP:3 | dc:a6:32:c9:e5:02;dc:a6:32:c9:e6:f4 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e5:a4 | Unidentified ESP plug (2) | G2 | 2,469,912 | 0 | 37476126.93 | 2000+ | TCP/6668:2218521;TCP/1427:38;TCP/1428:38;TCP/1429:38;TCP/1430:38;TCP/1431:38;TCP/1432:38;TCP/1433:38 | both |
| dc:a6:32:c9:e4:90 | Unidentified ESP plug (2) | G2 | 2,158,529 | 0 | 32751493.49 | 2000+ | TCP/6668:1933258;TCP/1427:34;TCP/1428:34;TCP/1429:34;TCP/1430:34;TCP/1431:34;TCP/1432:34;TCP/1433:34 | both |
| dc:a6:32:c9:e4:d5 | Unidentified ESP plug (2) | G2 | 2,104,627 | 0 | 31933635.12 | 2000+ | TCP/6668:1885989;TCP/1427:33;TCP/1428:33;TCP/1429:33;TCP/1430:33;TCP/1431:33;TCP/1432:33;TCP/1433:33 | both |
| dc:a6:32:dc:27:d5 | Unidentified ESP plug (2) | G2 | 2,084,813 | 0 | 31632996.08 | 2000+ | TCP/6668:1867778;none:94;TCP/1777:35;TCP/1427:33;TCP/1440:33;TCP/1441:33;TCP/1442:33;TCP/1443:33 | both |
| dc:a6:32:c9:e4:90 | GoSund Smart Plug WP2 (1) | G2 | 2,024,141 | 0 | 30712416.09 | 2000+ | TCP/6668:1818680;none:86;TCP/0:31;TCP/1:31;TCP/2:31;TCP/3:31;TCP/4:31;TCP/5:31 | both |
| dc:a6:32:c9:e4:ab | Unidentified ESP plug (2) | G2 | 1,941,951 | 0 | 29465342.15 | 2000+ | TCP/6668:1743284;TCP/1427:30;TCP/1428:30;TCP/1429:30;TCP/1430:30;TCP/1431:30;TCP/1432:30;TCP/1433:30 | both |
| e4:5f:01:55:90:c4 | GoSund Smart Plug WP2 (1) | G2 | 1,922,804 | 0 | 29174823.54 | 2000+ | TCP/6668:1722766;TCP/0:30;TCP/1:30;TCP/2:30;TCP/3:30;TCP/8:30;TCP/9:30;TCP/10:30 | both |
| dc:a6:32:c9:e5:ef | Unidentified ESP plug (2) | G2 | 1,868,116 | 0 | 28345039.15 | 2000+ | TCP/6668:1676338;TCP/1427:29;TCP/1428:29;TCP/1429:29;TCP/1430:29;TCP/1431:29;TCP/1432:29;TCP/1433:29 | both |
| dc:a6:32:dc:27:d5 | GoSund Smart Plug WP2 (1) | G2 | 1,768,402 | 0 | 26832072.49 | 2000+ | TCP/6668:1590568;none:107;TCP/0:28;TCP/1:28;TCP/2:28;TCP/3:28;TCP/4:28;TCP/5:28 | both |
| dc:a6:32:c9:e5:a4 | GoSund Smart Plug WP2 (1) | G2 | 1,702,602 | 0 | 25833685.03 | 2000+ | TCP/6668:1531892;TCP/974:26;TCP/975:26;TCP/976:26;TCP/977:26;TCP/978:26;TCP/979:26;TCP/980:26 | both |
| dc:a6:32:c9:e4:ab | GoSund Smart Plug WP2 (1) | G2 | 1,700,948 | 0 | 25808588.79 | 2000+ | TCP/6668:1522016;none:93;TCP/0:27;TCP/1:27;TCP/2:27;TCP/3:27;TCP/4:27;TCP/5:27 | both |
| dc:a6:32:c9:e4:d5 | GoSund Smart Plug WP2 (1) | G2 | 1,683,843 | 0 | 25549053.57 | 2000+ | TCP/6668:1510434;none:71;TCP/0:26;TCP/1:26;TCP/2:26;TCP/3:26;TCP/4:26;TCP/5:26 | both |
| dc:a6:32:c9:e5:ef | GoSund Smart Plug WP2 (1) | G2 | 1,647,288 | 0 | 24994402.3 | 2000+ | TCP/6668:1474633;TCP/0:26;TCP/1:26;TCP/2:26;TCP/3:26;TCP/4:26;TCP/5:26;TCP/6:26 | both |
| e4:5f:01:55:90:c4 | Unidentified ESP plug (2) | G2 | 646,622 | 0 | 9811235.44 | 2000+ | TCP/6668:581034;TCP/1447:11;TCP/1448:11;TCP/1480:11;TCP/1488:11;TCP/1520:11;TCP/1521:11;TCP/1553:11 | both |
| dc:a6:32:c9:e4:d5 | Unidentified ESP plug (3) | G2 | 184,999 | 0 | 2807001.22 | 2000+ | TCP/6668:166646;TCP/1654:3;TCP/1655:3;TCP/1656:3;TCP/1657:3;TCP/1658:3;TCP/1659:3;TCP/1660:3 | both |
| dc:a6:32:dc:27:d5 | Unidentified ESP plug (3) | G2 | 158,185 | 0 | 2400150.75 | 2000+ | TCP/6668:138263;none:15;TCP/1654:5;TCP/2211:4;TCP/1655:3;TCP/1656:3;TCP/1657:3;TCP/1658:3 | both |
| dc:a6:32:c9:e4:ab | Unidentified ESP plug (3) | G2 | 141,979 | 0 | 2154256.11 | 2000+ | TCP/6668:123626;TCP/1654:3;TCP/1655:3;TCP/1656:3;TCP/1657:3;TCP/1658:3;TCP/1659:3;TCP/1660:3 | both |
| dc:a6:32:c9:e4:90 | Unidentified ESP plug (3) | G2 | 140,074 | 0 | 2125351.43 | 2000+ | TCP/6668:122071;TCP/1654:3;TCP/1655:3;TCP/1656:3;TCP/1657:3;TCP/1658:3;TCP/1659:3;TCP/1660:3 | both |
| dc:a6:32:c9:e5:ef | Unidentified ESP plug (3) | G2 | 134,404 | 0 | 2039320.17 | 2000+ | TCP/6668:117218;TCP/1654:3;TCP/1655:3;TCP/1656:3;TCP/1657:3;TCP/1658:3;TCP/1659:3;TCP/1660:3 | both |
| dc:a6:32:c9:e5:a4 | Unidentified ESP plug (3) | G2 | 116,900 | 0 | 1773730.9 | 2000+ | TCP/6668:105212;TCP/1654:2;TCP/1655:2;TCP/1656:2;TCP/1657:2;TCP/1658:2;TCP/1659:2;TCP/1660:2 | both |
| e4:5f:01:55:90:c4 | Unidentified ESP plug (3) | G2 | 515 | 0 | 7814.13 | 276 | TCP/6668:240;TCP/1654:1;TCP/1686:1;TCP/1694:1;TCP/1726:1;TCP/1727:1;TCP/1759:1;TCP/1767:1 | both |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 58 | 60 | 14.67 | 1 | ICMP:1 | both |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 43 | 59 | 11.06 | 1 | ICMP:2 | both |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 22 | 81 | 4.12 | 0 |  |  |

**Spoofing:** 10 distinct ip.src on attacker-MAC packets (exact) -> not spoofed (threshold > 10); 0 are real smart-home device IPs in this pcap's map (0 packets), 0 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.195 | 4,322,582 | False |
| 192.168.137.96 | 4,289,280 | False |
| 192.168.137.17 | 4,011,184 | False |
| 192.168.137.224 | 3,973,326 | False |
| 192.168.137.240 | 3,784,680 | False |
| 192.168.137.58 | 3,649,637 | False |
| 192.168.137.134 | 2,569,848 | False |
| 192.168.137.242 | 37 | False |
| 192.168.137.90 | 28 | False |
| 192.168.137.213 | 13 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| agree | 26,600,568 |
| no_ip_dst (non-IPv4) | 3,652 |
| external ip.dst via gateway MAC | 37 |
| multicast ip.dst | 10 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | dc:a6:32:c9:e4:90 | attacker | 4,323,055 | 16.179 |
| 2 | dc:a6:32:c9:e5:a4 | attacker | 4,289,716 | 16.054 |
| 3 | dc:a6:32:dc:27:d5 | attacker | 4,011,759 | 15.014 |
| 4 | dc:a6:32:c9:e4:d5 | attacker | 3,973,818 | 14.872 |
| 5 | dc:a6:32:c9:e4:ab | attacker | 3,785,269 | 14.166 |
| 6 | dc:a6:32:c9:e5:ef | attacker | 3,650,171 | 13.661 |
| 7 | e4:5f:01:55:90:c4 | attacker | 2,570,250 | 9.619 |
| 8 | 3c:18:a0:41:c3:a0 | gateway | 46,880 | 0.175 |
| 9 | ac:17:02:05:34:27 | Fibaro Home Center Lite | 12,144 | 0.045 |
| 10 | ee:06:3b:b8:d1:df | unknown | 5,303 | 0.02 |
| 11 | a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | 3,977 | 0.015 |
| 12 | 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | 3,525 | 0.013 |
| 13 | 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | 2,666 | 0.01 |
| 14 | e8:1b:69:f8:d4:e3 | Unknown | 2,646 | 0.01 |
| 15 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 2,095 | 0.008 |
| 16 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 2,078 | 0.008 |
| 17 | 3c:37:86:6f:b9:51 | Arlo Base Station | 1,843 | 0.007 |
| 18 | 10:2c:6b:1b:43:be | unknown | 1,801 | 0.007 |
| 19 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 1,482 | 0.006 |
| 20 | 7c:78:b2:86:0d:81 | Wyze Camera | 1,227 | 0.005 |
| 21 | 00:a3:d1:07:6f:03 | Unknown | 1,012 | 0.004 |
| 22 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 982 | 0.004 |
| 23 | e8:1b:69:f8:d6:e6 | Unknown | 965 | 0.004 |
| 24 | 28:6d:97:9e:f4:d5 | Aeotec Smart Home Hub | 949 | 0.004 |
| 25 | 84:e3:42:42:ed:0b | Lumiman Bulb | 946 | 0.004 |
| 26 | b8:f0:09:03:29:79 | GoSund Smart Plug WP2 (1) | 933 | 0.003 |
| 27 | 44:bb:3b:00:39:07 | Nest Indoor Camera | 869 | 0.003 |
| 28 | 50:02:91:10:09:8f | Unidentified ESP plug (2) | 824 | 0.003 |
| 29 | 28:6d:97:7a:2b:2d | SmartThings Hub | 766 | 0.003 |
| 30 | 50:02:91:10:ac:d8 | GoSund Smart Plug WP2 (2) | 757 | 0.003 |

## Attack: DDoS-SYN_Flood

- sha256: `5e8124a87e12483af05cb5b4f36dc095c2a979b08f2ee4e18918c26ad3b041b8`
- rate plot: `attack_rate_DDoS-SYN_Flood.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/DDoS-SYN_Flood/DDoS-SYN_Flood.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T20:10:05+00:00; peak RSS so far 282.4 MB (python), 426.1 MB (tshark)
- packets: 26,597,011; capture 2022-08-26T18:18:00.516492+00:00 -> 2022-08-29T12:31:44.275216+00:00 (3973.73 min); tshark+aggregation 741.9 s
- attacker-MAC packets: sent 26,003,644 (97.769%), received 395,918
- **background share** (neither from nor to an attacker MAC): 0.742%
- attacker packets span 2022-08-26T18:18:19.212022+00:00 -> 2022-08-29T12:31:44.275216+00:00; 44 active minutes; 6,543.89 pkt/min over the capture, peak 840,847
- attacker protocols: {'TCP': 25995934, 'none': 7685, 'UDP': 25}; TCP flags: {'SYN': 25642312, 'RST': 353622}
- broadcast / multicast destinations of attacker packets (never victims): {'broadcast': 4771, 'multicast': 31}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 18, 'lan_xcheck_keys': 43}

**Coverage (min victims 2):** overall **G1-only**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 5 | 25,998,818 | 2022-08-26T18:18:19.212022+00:00 | 2022-08-29T12:31:44.275216+00:00 | PASS |
| G2 | 0 | 0 |  |  | FAIL |
| GEN | 0 | 0 |  |  | FAIL |
| gateway | 0 | 0 |  |  | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 4

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2022-08-26T18:18:00.000000+00:00 | 2022-08-26T18:31:00.000000+00:00 | 13 | 7,651,647 | 764,640 |
| 2022-08-26T18:39:00.000000+00:00 | 2022-08-26T18:52:00.000000+00:00 | 13 | 8,783,908 | 840,847 |
| 2022-08-26T18:57:00.000000+00:00 | 2022-08-26T19:10:00.000000+00:00 | 13 | 6,699,483 | 625,321 |
| 2022-08-29T12:28:00.000000+00:00 | 2022-08-29T12:32:00.000000+00:00 | 4 | 2,868,605 | 824,605 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 4,163,427 | 1047.74 | 0.05 | 4 | G1 4 | 4 | 18:19:00-18:30:00 (1,484,276 pkts); 18:39:00-18:52:00 (1,106,996 pkts); 18:57:00-19:09:00 (1,282,037 pkts); 12:28:00-12:32:00 (290,097 pkts) |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 7,079,462 | 1781.57 | 0.03 | 4 | G1 4 | 4 | 18:18:00-18:31:00 (1,504,288 pkts); 18:39:00-18:52:00 (2,795,065 pkts); 18:57:00-19:10:00 (1,631,302 pkts); 12:28:00-12:32:00 (1,148,807 pkts) |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 9 | 0.0 | 0.46 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 2,963,457 | 745.76 | 0.05 | 4 | G1 4 | 4 | 18:18:00-18:30:00 (878,967 pkts); 18:39:00-18:52:00 (979,719 pkts); 18:57:00-19:09:00 (797,941 pkts); 12:28:00-12:32:00 (306,655 pkts) |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 14 | 0.0 | 0.27 | 0 | - | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 2,936 | 0.74 | 0.05 | 5 | G1 5 | 0 | - |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 3,659,456 | 920.91 | 0.05 | 4 | G1 4 | 4 | 18:18:00-18:30:00 (1,174,859 pkts); 18:39:00-18:52:00 (1,009,855 pkts); 18:57:00-19:10:00 (1,040,468 pkts); 12:28:00-12:32:00 (434,272 pkts) |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 11 | 0.0 | 0.22 | 0 | - | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 4,307,275 | 1083.94 | 33.42 | 4 | G1 4 | 4 | 18:18:00-18:31:00 (1,233,731 pkts); 18:39:00-18:52:00 (1,689,602 pkts); 18:57:00-19:10:00 (1,055,527 pkts); 12:28:00-12:32:00 (328,415 pkts) |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 3,827,597 | 963.23 | 0.03 | 4 | G1 4 | 4 | 18:18:00-18:31:00 (1,374,846 pkts); 18:39:00-18:52:00 (1,201,694 pkts); 18:57:00-19:10:00 (891,054 pkts); 12:28:00-12:32:00 (360,003 pkts) |

**Victims (5):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | G1 | 8,782,212 | both | 390688.86 | 12642+ | 1 | TCP:8781344;none:868 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | G1 | 7,650,195 | both | 210252.11 | 12002+ | 1 | TCP:7649271;none:924 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | G1 | 6,698,192 | both | 228014.4 | 12002+ | 1 | TCP:6697572;none:620 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | G1 | 2,868,217 | both | 160579.51 | 3,338 | 1 | TCP:2867747;none:470 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | G1 | 2 | new_service | 0.28 | 1 | 0 | none:2 | dc:a6:32:c9:e5:a4 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:ab | Unidentified Amazon device (1c:12:b0) | G1 | 2,794,935 | 0 | 390688.86 | 2000+ | TCP/3325:48;TCP/6271:47;TCP/6272:47;TCP/2126:47;TCP/2127:47;TCP/2128:47;TCP/2129:47;TCP/2326:47 | both |
| dc:a6:32:dc:27:d5 | Unidentified Amazon device (1c:12:b0) | G1 | 1,689,383 | 0 | 236149.72 | 2000+ | TCP/6417:33;TCP/6420:33;TCP/6421:33;TCP/6412:32;TCP/6413:32;TCP/6415:32;TCP/7104:32;TCP/7105:32 | both |
| dc:a6:32:c9:e4:ab | Google Nest Mini Speaker | G1 | 1,631,184 | 0 | 228014.4 | 2000+ | TCP/8008:1431318;TCP/3082:28;TCP/2554:25;TCP/2555:25;TCP/2556:25;TCP/2557:25;TCP/2558:25;TCP/2559:25 | both |
| dc:a6:32:c9:e4:ab | Amazon Alexa Echo Dot 1 | G1 | 1,504,115 | 0 | 210252.11 | 2000+ | TCP/4070:1413797;none:157;TCP/3788:31;TCP/3789:31;TCP/3790:31;TCP/3791:31;TCP/3125:31;TCP/3126:31 | both |
| dc:a6:32:c9:e4:90 | Amazon Alexa Echo Dot 1 | G1 | 1,484,116 | 0 | 207456.55 | 2000+ | TCP/4070:1394271;none:162;TCP/904:25;TCP/912:25;TCP/281:24;TCP/282:24;TCP/283:24;TCP/578:24 | both |
| e4:5f:01:55:90:c4 | Amazon Alexa Echo Dot 1 | G1 | 1,374,658 | 0 | 192156.01 | 2000+ | TCP/4070:1293703;none:153;TCP/3326:25;TCP/3327:25;TCP/187:24;TCP/188:24;TCP/189:24;TCP/190:24 | both |
| dc:a6:32:c9:e4:90 | Google Nest Mini Speaker | G1 | 1,281,917 | 0 | 179192.25 | 2000+ | TCP/8008:1127457;TCP/3697:22;TCP/2631:20;TCP/3475:20;TCP/2554:19;TCP/2555:19;TCP/2556:19;TCP/2557:19 | both |
| dc:a6:32:dc:27:d5 | Amazon Alexa Echo Dot 1 | G1 | 1,233,458 | 0 | 172418.43 | 2000+ | TCP/4070:1159237;none:136;TCP/3177:25;TCP/3178:25;TCP/2600:25;TCP/3569:24;TCP/3570:24;TCP/3571:24 | both |
| e4:5f:01:55:90:c4 | Unidentified Amazon device (1c:12:b0) | G1 | 1,201,444 | 0 | 167943.36 | 2000+ | none:141;TCP/7844:24;TCP/7845:23;TCP/3044:23;TCP/3045:23;TCP/3052:23;TCP/3060:23;TCP/3066:23 | both |
| dc:a6:32:c9:e5:ef | Amazon Alexa Echo Dot 1 | G1 | 1,174,714 | 0 | 164206.92 | 2000+ | TCP/4070:1102728;none:150;TCP/3850:22;TCP/3851:22;TCP/3852:22;TCP/3853:22;TCP/3854:22;TCP/3813:21 | both |
| dc:a6:32:c9:e4:ab | AMCREST WiFi Camera | G1 | 1,148,764 | 0 | 160579.51 | 556 | TCP/554:1139249;none:107;TCP/140:21;TCP/139:20;TCP/0:17;TCP/1:17;TCP/2:17;TCP/3:17 | both |
| dc:a6:32:c9:e4:90 | Unidentified Amazon device (1c:12:b0) | G1 | 1,106,759 | 0 | 154707.86 | 2000+ | TCP/2933:22;TCP/2935:22;TCP/2211:21;TCP/2212:21;TCP/2213:21;TCP/2214:21;TCP/2215:21;TCP/2934:21 | both |
| dc:a6:32:dc:27:d5 | Google Nest Mini Speaker | G1 | 1,055,304 | 13,401 | 11.01 | 2000+ | TCP/8008:918502;TCP/2555:22;TCP/2556:22;TCP/2557:22;TCP/2559:22;TCP/2560:22;TCP/2554:21;TCP/2558:21 | both |
| dc:a6:32:c9:e5:ef | Google Nest Mini Speaker | G1 | 1,040,343 | 0 | 145423.93 | 2000+ | TCP/8008:912333;TCP/2615:19;TCP/2616:19;TCP/2617:19;TCP/2618:19;TCP/2554:16;TCP/2555:16;TCP/2556:16 | both |
| dc:a6:32:c9:e5:ef | Unidentified Amazon device (1c:12:b0) | G1 | 1,009,567 | 0 | 141121.91 | 2000+ | none:118;TCP/19697:20;TCP/19702:20;TCP/19705:20;TCP/19708:20;TCP/19709:20;TCP/19711:20;TCP/16274:20 | both |
| dc:a6:32:c9:e4:d5 | Unidentified Amazon device (1c:12:b0) | G1 | 979,441 | 0 | 136910.76 | 2000+ | TCP/1818:20;TCP/1650:19;TCP/1651:19;TCP/1652:19;TCP/1653:19;TCP/1654:19;TCP/1655:19;TCP/1656:19 | both |
| e4:5f:01:55:90:c4 | Google Nest Mini Speaker | G1 | 890,889 | 0 | 124532.56 | 2000+ | TCP/8008:784270;TCP/3037:17;TCP/3039:17;TCP/3038:16;TCP/3040:16;TCP/6170:16;TCP/6171:16;TCP/6172:16 | both |
| dc:a6:32:c9:e4:d5 | Amazon Alexa Echo Dot 1 | G1 | 878,801 | 0 | 122842.84 | 2000+ | TCP/4070:822606;none:150;TCP/2612:19;TCP/2613:19;TCP/3524:18;TCP/3525:18;TCP/3177:17;TCP/2614:17 | both |
| dc:a6:32:c9:e4:d5 | Google Nest Mini Speaker | G1 | 797,990 | 0 | 111546.71 | 2000+ | TCP/8008:699500;TCP/3893:16;TCP/3895:16;TCP/3894:15;TCP/2815:13;TCP/2816:13;TCP/2817:13;TCP/2818:13 | both |
| dc:a6:32:c9:e5:ef | AMCREST WiFi Camera | G1 | 434,192 | 0 | 60693.35 | 556 | TCP/554:430756;none:75;TCP/469:9;TCP/472:9;TCP/473:9;TCP/377:8;TCP/378:8;TCP/379:8 | both |
| e4:5f:01:55:90:c4 | AMCREST WiFi Camera | G1 | 359,955 | 0 | 50316.16 | 556 | TCP/554:357083;none:90;TCP/553:9;TCP/226:8;TCP/366:8;TCP/552:8;TCP/0:5;TCP/1:5 | both |
| dc:a6:32:dc:27:d5 | AMCREST WiFi Camera | G1 | 328,352 | 0 | 45898.55 | 556 | TCP/554:325513;none:69;TCP/0:5;TCP/1:5;TCP/2:5;TCP/3:5;TCP/4:5;TCP/5:5 | both |
| dc:a6:32:c9:e4:d5 | AMCREST WiFi Camera | G1 | 306,606 | 0 | 42858.8 | 556 | TCP/554:304333;none:57;TCP/0:4;TCP/1:4;TCP/2:4;TCP/3:4;TCP/4:4;TCP/5:4 | both |
| dc:a6:32:c9:e4:90 | AMCREST WiFi Camera | G1 | 290,041 | 0 | 40543.26 | 556 | TCP/554:287758;none:67;TCP/0:4;TCP/1:4;TCP/2:4;TCP/3:4;TCP/4:4;TCP/5:4 | both |
| dc:a6:32:c9:e5:a4 | Unidentified Amazon device (1c:12:b0) | G1 | 683 | 0 | 95.47 | 642 | none:26;TCP/9657:2;TCP/9658:2;TCP/9659:2;TCP/9660:2;TCP/9661:2;TCP/9662:2;TCP/9663:2 | both |
| dc:a6:32:c9:e5:a4 | Google Nest Mini Speaker | G1 | 565 | 0 | 78.98 | 2 | TCP/8008:562;none:3 | both |
| dc:a6:32:c9:e5:a4 | Amazon Alexa Echo Dot 1 | G1 | 333 | 0 | 46.55 | 2 | TCP/4070:317;none:16 | both |
| dc:a6:32:c9:e5:a4 | AMCREST WiFi Camera | G1 | 307 | 0 | 42.91 | 2 | TCP/554:302;none:5 | both |
| dc:a6:32:c9:e5:a4 | Arlo Q Indoor Camera | G1 | 2 | 0 | 0.28 | 1 | none:2 | new_service |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 8 | 81 | 0.01 | 0 |  |  |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 8 | 59 | 0.02 | 0 |  |  |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 8 | 60 | 0.02 | 0 |  |  |

**Spoofing:** 10 distinct ip.src on attacker-MAC packets (exact) -> not spoofed (threshold > 10); 0 are real smart-home device IPs in this pcap's map (0 packets), 0 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.240 | 7,078,448 | False |
| 192.168.137.17 | 4,305,989 | False |
| 192.168.137.195 | 4,162,388 | False |
| 192.168.137.134 | 3,826,465 | False |
| 192.168.137.58 | 3,658,374 | False |
| 192.168.137.224 | 2,962,444 | False |
| 192.168.137.96 | 1,840 | False |
| 192.168.137.242 | 5 | False |
| 192.168.137.213 | 3 | False |
| 192.168.137.90 | 3 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| agree | 25,995,934 |
| no_ip_dst (non-IPv4) | 7,685 |
| multicast ip.dst | 16 |
| external ip.dst via gateway MAC | 9 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | dc:a6:32:c9:e4:ab | attacker | 7,079,462 | 26.618 |
| 2 | dc:a6:32:dc:27:d5 | attacker | 4,307,275 | 16.195 |
| 3 | dc:a6:32:c9:e4:90 | attacker | 4,163,427 | 15.654 |
| 4 | e4:5f:01:55:90:c4 | attacker | 3,827,597 | 14.391 |
| 5 | dc:a6:32:c9:e5:ef | attacker | 3,659,456 | 13.759 |
| 6 | dc:a6:32:c9:e4:d5 | attacker | 2,963,457 | 11.142 |
| 7 | 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | 223,059 | 0.839 |
| 8 | 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | 170,629 | 0.642 |
| 9 | 3c:18:a0:41:c3:a0 | gateway | 81,589 | 0.307 |
| 10 | ac:17:02:05:34:27 | Fibaro Home Center Lite | 20,120 | 0.076 |
| 11 | 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | 14,686 | 0.055 |
| 12 | a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | 6,847 | 0.026 |
| 13 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 5,618 | 0.021 |
| 14 | 7c:78:b2:86:0d:81 | Wyze Camera | 4,660 | 0.018 |
| 15 | ee:06:3b:b8:d1:df | unknown | 4,158 | 0.016 |
| 16 | 10:2c:6b:1b:43:be | unknown | 3,587 | 0.013 |
| 17 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 3,330 | 0.013 |
| 18 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 3,286 | 0.012 |
| 19 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 3,042 | 0.011 |
| 20 | 6c:5a:b0:44:1d:90 | TP-Link Tapo Camera | 3,006 | 0.011 |
| 21 | dc:a6:32:c9:e5:a4 | attacker | 2,936 | 0.011 |
| 22 | 8c:85:80:6c:b6:47 | Eufy HomeBase 2 | 1,934 | 0.007 |
| 23 | 70:ee:50:68:0e:32 | Netatmo Camera | 1,853 | 0.007 |
| 24 | e8:1b:69:f8:d4:e3 | Unknown | 1,702 | 0.006 |
| 25 | 00:a3:d1:07:6f:03 | Unknown | 1,675 | 0.006 |
| 26 | 44:bb:3b:00:39:07 | Nest Indoor Camera | 1,646 | 0.006 |
| 27 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 1,567 | 0.006 |
| 28 | 34:75:63:73:f3:36 | Home Eye Camera | 1,466 | 0.006 |
| 29 | 70:ee:50:6b:a8:1a | Netatmo Weather Station | 1,403 | 0.005 |
| 30 | 00:17:88:60:d6:4f | Philips Hue Bridge | 1,317 | 0.005 |

## Attack: DictionaryBruteForce

- sha256: `09ad3cfabd139b950da3078fec0f0fd196fe36cd82237d898035437f4c69161b`
- rate plot: `attack_rate_DictionaryBruteForce.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/DictionaryBruteForce/DictionaryBruteForce.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T19:57:41+00:00; peak RSS so far 229.0 MB (python), 239.6 MB (tshark)
- packets: 133,138; capture 2022-10-14T16:18:00.400262+00:00 -> 2022-10-17T15:02:00.421502+00:00 (4244.0 min); tshark+aggregation 3.8 s
- attacker-MAC packets: sent 26,759 (20.099%), received 25,555
- **background share** (neither from nor to an attacker MAC): 77.447%
- attacker packets span 2022-10-14T16:18:04.337759+00:00 -> 2022-10-17T15:01:57.365142+00:00; 34 active minutes; 6.31 pkt/min over the capture, peak 2,221
- attacker protocols: {'TCP': 26483, 'ICMP': 121, 'UDP': 82, 'none': 73}; TCP flags: {'PSH+ACK': 11951, 'ACK': 10993, 'FIN+ACK': 1650, 'SYN': 1119, 'SYN+ACK': 548, 'RST': 140, 'RST+ACK': 54, 'FIN+PSH+ACK': 28}
- broadcast / multicast destinations of attacker packets (never victims): {'multicast': 87, 'broadcast': 4}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 0, 'lan_xcheck_keys': 108}

**Coverage (min victims 2):** overall **NONE**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 0 | 0 |  |  | FAIL |
| G2 | 1 | 2,192 | 2022-10-17T15:01:07.895819+00:00 | 2022-10-17T15:01:24.706692+00:00 | FAIL |
| GEN | 0 | 0 |  |  | FAIL |
| gateway | 0 | 0 |  |  | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 5

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2022-10-14T16:18:00.000000+00:00 | 2022-10-14T16:19:00.000000+00:00 | 1 | 360 | 360 |
| 2022-10-14T16:32:00.000000+00:00 | 2022-10-14T16:33:00.000000+00:00 | 1 | 358 | 358 |
| 2022-10-17T13:21:00.000000+00:00 | 2022-10-17T13:45:00.000000+00:00 | 24 | 22,378 | 1,213 |
| 2022-10-17T14:56:00.000000+00:00 | 2022-10-17T14:57:00.000000+00:00 | 1 | 1,219 | 1,219 |
| 2022-10-17T15:01:00.000000+00:00 | 2022-10-17T15:02:00.000000+00:00 | 1 | 2,221 | 2,221 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 2 | 0.0 | 0.05 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 1 | 0.0 | 0.03 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 12,167 | 2.87 | 0.46 | 1 | attacker 1 | 1 | 13:21:00-13:45:00 (12,147 pkts) |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 0 | 0.0 | 0.05 | 0 | - | 0 | - |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 171 | 0.04 | 0.27 | 1 | attacker 1 | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 0 | 0.0 | 0.05 | 0 | - | 0 | - |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 1 | 0.0 | 0.05 | 0 | - | 0 | - |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 175 | 0.04 | 0.22 | 1 | attacker 1 | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 14,241 | 3.36 | 33.42 | 5 | G2 1, attacker 3, unknown 1 | 3 | 13:21:00-13:45:00 (10,218 pkts); 14:56:00-14:57:00 (1,219 pkts); 15:01:00-15:02:00 (2,221 pkts) |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 1 | 0.0 | 0.03 | 0 | - | 0 | - |

**Victims (6):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | attacker | 12,492 | both | 1591.4 | 3 | 533 | TCP:12492 | dc:a6:32:c9:e4:c6;dc:a6:32:c9:e5:02;dc:a6:32:c9:e6:f4 |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | attacker | 9,489 | both | 1241.95 | 1 | 1 | TCP:9489 | dc:a6:32:dc:27:d5 |
| 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | G2 | 2,192 | both | 286.89 | 1 | 1 | TCP:2192 | dc:a6:32:dc:27:d5 |
| 7c:a7:b0:cd:18:32 | unknown | unknown | 1,182 | both | 154.7 | 1 | 1 | TCP:1182 | dc:a6:32:dc:27:d5 |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | attacker | 153 | both | 20.03 | 2 | 1 | TCP:151;none:2 | dc:a6:32:dc:27:d5 |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | attacker | 153 | both | 20.03 | 1 | 1 | TCP:153 | dc:a6:32:dc:27:d5 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (8 GB) | attacker | 12,159 | 0 | 1591.4 | 1 | TCP/22:12159 | both |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (2 GB) | attacker | 9,489 | 0 | 1241.95 | 1 | TCP/22:9489 | both |
| dc:a6:32:dc:27:d5 | HeimVision Smart WiFi Camera | G2 | 2,192 | 0 | 286.89 | 1 | TCP/554:2192 | both |
| dc:a6:32:dc:27:d5 | unknown | unknown | 1,182 | 0 | 154.7 | 1 | TCP/554:1182 | both |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (8 GB) | attacker | 170 | 0 | 22.25 | 1 | TCP/22:170 | both |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (8 GB) | attacker | 163 | 0 | 21.33 | 1 | TCP/22:163 | both |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (2 GB) | attacker | 153 | 0 | 20.03 | 2 | TCP/22:151;none:2 | both |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (2 GB) | attacker | 153 | 0 | 20.03 | 1 | TCP/22:153 | both |
| dc:a6:32:dc:27:d5 | Google Nest Mini Speaker | G1 | 824 | 13,401 | 0.01 | 0 |  |  |
| dc:a6:32:dc:27:d5 | Philips Hue Bridge | G1 | 157 | 3,488 | 0.01 | 0 |  |  |
| dc:a6:32:dc:27:d5 | Amazon Echo Show | G1 | 14 | 302 | 0.01 | 0 |  |  |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 4 | 81 | 0.01 | 0 |  |  |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 4 | 60 | 0.01 | 0 |  |  |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 4 | 59 | 0.01 | 0 |  |  |

**Spoofing:** 7 distinct ip.src on attacker-MAC packets (exact) -> not spoofed (threshold > 10); 2 are real smart-home device IPs in this pcap's map (13,970 packets), 2 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.65 | 13,807 | True |
| 192.168.137.67 | 12,163 | False |
| 192.168.137.225 | 377 | False |
| 192.168.137.161 | 170 | False |
| 192.168.137.238 | 163 | True |
| 192.168.137.116 | 4 | False |
| 192.168.137.19 | 2 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| lan ip.dst unmapped_at_time | 12,310 |
| lan ip.dst unmapped | 9,975 |
| agree | 4,319 |
| multicast ip.dst | 76 |
| no_ip_dst (non-IPv4) | 73 |
| external ip.dst via gateway MAC | 6 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | 3c:18:a0:41:c3:a0 | gateway | 35,512 | 26.673 |
| 2 | dc:a6:32:dc:27:d5 | attacker | 14,241 | 10.696 |
| 3 | dc:a6:32:c9:e4:c6 | attacker | 12,167 | 9.139 |
| 4 | 70:ee:50:68:0e:32 | Netatmo Camera | 6,563 | 4.929 |
| 5 | 44:bb:3b:00:39:07 | Nest Indoor Camera | 4,908 | 3.686 |
| 6 | a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | 4,409 | 3.312 |
| 7 | 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | 4,265 | 3.203 |
| 8 | 7c:78:b2:86:0d:81 | Wyze Camera | 3,027 | 2.274 |
| 9 | 10:2c:6b:1b:43:be | unknown | 2,837 | 2.131 |
| 10 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 2,790 | 2.096 |
| 11 | 56:4f:8a:e1:f3:2d | Randomised MAC (phone/laptop) | 2,532 | 1.902 |
| 12 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 1,943 | 1.459 |
| 13 | c0:e7:bf:0a:79:d1 | unknown | 1,892 | 1.421 |
| 14 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 1,764 | 1.325 |
| 15 | d4:a6:51:30:64:b7 | HeimVision SmartLife Radio/Lamp | 1,743 | 1.309 |
| 16 | 34:75:63:73:f3:36 | Home Eye Camera | 1,559 | 1.171 |
| 17 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 1,542 | 1.158 |
| 18 | 00:a3:d1:07:6f:03 | Unknown | 1,398 | 1.05 |
| 19 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 1,383 | 1.039 |
| 20 | 94:39:e5:5d:27:a6 | unknown | 1,329 | 0.998 |
| 21 | 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | 1,321 | 0.992 |
| 22 | 00:17:88:60:d6:4f | Philips Hue Bridge | 1,104 | 0.829 |
| 23 | 28:6d:97:7a:2b:2d | SmartThings Hub | 1,097 | 0.824 |
| 24 | 7c:a7:b0:cd:18:32 | unknown | 1,091 | 0.819 |
| 25 | 10:5a:17:97:a5:c6 | Rbcior Camera | 1,088 | 0.817 |
| 26 | 28:6d:97:9e:f4:d5 | Aeotec Smart Home Hub | 1,060 | 0.796 |
| 27 | 84:7a:b6:62:3a:6c | Yi Indoor 2 Camera | 776 | 0.583 |
| 28 | c4:dd:57:13:07:c6 | Unidentified ESP plug (4) | 685 | 0.515 |
| 29 | b8:f0:09:03:29:79 | GoSund Smart Plug WP2 (1) | 683 | 0.513 |
| 30 | 50:02:91:b1:68:0c | unknown | 683 | 0.513 |

## Attack: Mirai-udpplain24

- sha256: `adff7dcd1a9f2c19ca01c6df051555bfefdc2acf59277bd9dbe0dab3bd9791f5`
- rate plot: `attack_rate_Mirai-udpplain24.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/Mirai-udpplain/Mirai-udpplain24.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T20:44:36+00:00; peak RSS so far 298.7 MB (python), 426.1 MB (tshark)
- packets: 1,506,334; capture 2023-02-07T16:23:57.789760+00:00 -> 2023-02-14T17:38:00.630347+00:00 (10154.05 min); tshark+aggregation 35.9 s
- attacker-MAC packets: sent 1,456,835 (96.714%), received 1,908
- **background share** (neither from nor to an attacker MAC): 3.159%
- attacker packets span 2023-02-07T16:23:57.789760+00:00 -> 2023-02-14T17:38:00.238625+00:00; 17 active minutes; 143.47 pkt/min over the capture, peak 298,300
- attacker protocols: {'UDP': 1451198, 'none': 5157, 'ICMP': 241, 'TCP': 239}; TCP flags: {'SYN': 69, 'ACK': 64, 'RST': 54, 'PSH+ACK': 36, 'FIN+ACK': 14, 'FIN+PSH+ACK': 2}
- broadcast / multicast destinations of attacker packets (never victims): {'broadcast': 4568, 'multicast': 79}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 0, 'lan_xcheck_keys': 42}

**Coverage (min victims 2):** overall **BOTH**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 3 | 380 | 2023-02-07T16:23:58.491995+00:00 | 2023-02-14T17:37:26.310350+00:00 | PASS |
| G2 | 2 | 1,451,421 | 2023-02-07T16:23:57.789760+00:00 | 2023-02-14T17:38:00.238625+00:00 | PASS |
| GEN | 0 | 0 |  |  | FAIL |
| gateway | 1 | 383 | 2023-02-07T16:27:13.305443+00:00 | 2023-02-14T17:37:57.260160+00:00 | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 2

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2023-02-07T16:23:00.000000+00:00 | 2023-02-07T16:28:00.000000+00:00 | 5 | 1,162,956 | 298,300 |
| 2023-02-14T17:27:00.000000+00:00 | 2023-02-14T17:38:00.000000+00:00 | 11 | 293,588 | 92,288 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 389,077 | 38.32 | 0.05 | 2 | G2 2 | 3 | 16:24:00-16:28:00 (323,685 pkts); 17:27:00-17:29:00 (53,193 pkts); 17:37:00-17:38:00 (11,453 pkts) |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 167,544 | 16.5 | 0.03 | 2 | G2 2 | 2 | 16:23:00-16:28:00 (137,112 pkts); 17:27:00-17:29:00 (29,924 pkts) |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 8 | 0.0 | 0.46 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 190,777 | 18.79 | 0.05 | 2 | G2 2 | 2 | 16:24:00-16:28:00 (133,883 pkts); 17:28:00-17:30:00 (56,401 pkts) |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 46 | 0.0 | 0.27 | 1 | gateway 1 | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 221,484 | 21.81 | 0.05 | 5 | G1 3, G2 2 | 2 | 16:23:00-16:28:00 (169,624 pkts); 17:28:00-17:30:00 (51,036 pkts) |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 132,701 | 13.07 | 0.05 | 1 | G2 1 | 1 | 16:24:00-16:28:00 (132,098 pkts) |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 518 | 0.05 | 0.22 | 1 | gateway 1 | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 209,856 | 20.67 | 33.42 | 2 | G2 2 | 3 | 16:23:00-16:28:00 (153,285 pkts); 17:27:00-17:28:00 (8,082 pkts); 17:33:00-17:35:00 (48,020 pkts) |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 144,824 | 14.26 | 0.03 | 2 | G2 2 | 2 | 16:24:00-16:28:00 (113,210 pkts); 17:27:00-17:29:00 (31,116 pkts) |

**Victims (6):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| b0:c5:54:59:2e:99 | D-Link DCS8000LHA1 Mini Camera | G2 | 1,162,421 | both | 17704.27 | 14 | 7 | UDP:1162005;none:416 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| d4:a6:51:76:06:64 | Teckin Plug 1 | G2 | 289,000 | both | 3546.56 | 12 | 6 | UDP:288979;none:21 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 3c:18:a0:41:c3:a0 | Gateway / router | gateway | 383 | new_service | 0.34 | 2 | 2 | ICMP:182;UDP:165;none:36 | dc:a6:32:c9:e5:02;dc:a6:32:c9:e6:f4 |
| cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | G1 | 219 | both | 11.98 | 2 | 1 | TCP:182;none:37 | dc:a6:32:c9:e5:a4 |
| 00:17:88:60:d6:4f | Philips Hue Bridge | G1 | 101 | new_service | 5.53 | 3 | 1 | ICMP:52;TCP:34;none:15 | dc:a6:32:c9:e5:a4 |
| 2c:71:ff:05:f1:15 | Amazon Echo Show | G1 | 60 | new_service | 3.28 | 4 | 1 | none:30;TCP:23;ICMP:7 | dc:a6:32:c9:e5:a4 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | D-Link DCS8000LHA1 Mini Camera | G2 | 323,638 | 0 | 17704.27 | 2 | UDP/25402:323571;none:67 | both |
| dc:a6:32:c9:e5:a4 | D-Link DCS8000LHA1 Mini Camera | G2 | 169,517 | 0 | 9273.24 | 2 | UDP/1457:169445;none:72 | both |
| dc:a6:32:dc:27:d5 | D-Link DCS8000LHA1 Mini Camera | G2 | 153,179 | 0 | 8379.49 | 2 | UDP/10583:153124;none:55 | both |
| dc:a6:32:c9:e4:ab | D-Link DCS8000LHA1 Mini Camera | G2 | 137,062 | 0 | 7497.83 | 2 | UDP/1013:137029;none:33 | both |
| dc:a6:32:c9:e4:d5 | D-Link DCS8000LHA1 Mini Camera | G2 | 133,819 | 0 | 7320.42 | 2 | UDP/37099:133769;none:50 | both |
| dc:a6:32:c9:e5:ef | D-Link DCS8000LHA1 Mini Camera | G2 | 132,056 | 0 | 7223.98 | 2 | UDP/4033:131984;none:72 | both |
| e4:5f:01:55:90:c4 | D-Link DCS8000LHA1 Mini Camera | G2 | 113,150 | 0 | 6189.75 | 2 | UDP/15896:113083;none:67 | both |
| dc:a6:32:c9:e4:90 | Teckin Plug 1 | G2 | 64,832 | 0 | 3546.56 | 2 | UDP/1179:64829;none:3 | both |
| dc:a6:32:c9:e4:d5 | Teckin Plug 1 | G2 | 56,330 | 0 | 3081.47 | 2 | UDP/29329:56327;none:3 | both |
| dc:a6:32:dc:27:d5 | Teckin Plug 1 | G2 | 55,992 | 0 | 3062.98 | 2 | UDP/53618:55986;none:6 | both |
| dc:a6:32:c9:e5:a4 | Teckin Plug 1 | G2 | 50,924 | 0 | 2785.74 | 2 | UDP/10549:50921;none:3 | both |
| e4:5f:01:55:90:c4 | Teckin Plug 1 | G2 | 31,061 | 0 | 1699.16 | 2 | UDP/55922:31058;none:3 | both |
| dc:a6:32:c9:e4:ab | Teckin Plug 1 | G2 | 29,861 | 0 | 1633.51 | 2 | UDP/24163:29858;none:3 | both |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 371 | 59 | 0.34 | 1 | ICMP:181 | new_service |
| dc:a6:32:c9:e5:a4 | Google Nest Mini Speaker | G1 | 219 | 0 | 11.98 | 2 | TCP/8009:182;none:37 | both |
| dc:a6:32:c9:e5:a4 | Philips Hue Bridge | G1 | 101 | 0 | 5.53 | 3 | ICMP:52;TCP/80:34;none:15 | new_service |
| dc:a6:32:c9:e5:a4 | Amazon Echo Show | G1 | 60 | 0 | 3.28 | 4 | none:30;TCP/40680:13;TCP/40684:10;ICMP:7 | new_service |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 12 | 60 | 0.01 | 1 | ICMP:1 | new_service |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 4 | 81 | 0.0 | 0 |  |  |

**Spoofing:** 10 distinct ip.src on attacker-MAC packets (exact) -> not spoofed (threshold > 10); 0 are real smart-home device IPs in this pcap's map (0 packets), 0 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.238 | 388,401 | False |
| 192.168.137.162 | 220,703 | False |
| 192.168.137.147 | 209,111 | False |
| 192.168.137.128 | 190,097 | False |
| 192.168.137.207 | 166,888 | False |
| 192.168.137.247 | 144,142 | False |
| 192.168.137.106 | 131,985 | False |
| 192.168.137.13 | 336 | False |
| 192.168.137.11 | 13 | False |
| 192.168.137.236 | 2 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| agree | 1,451,493 |
| no_ip_dst (non-IPv4) | 5,157 |
| external ip.dst via gateway MAC | 137 |
| multicast ip.dst | 48 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | dc:a6:32:c9:e4:90 | attacker | 389,077 | 25.829 |
| 2 | dc:a6:32:c9:e5:a4 | attacker | 221,484 | 14.704 |
| 3 | dc:a6:32:dc:27:d5 | attacker | 209,856 | 13.932 |
| 4 | dc:a6:32:c9:e4:d5 | attacker | 190,777 | 12.665 |
| 5 | dc:a6:32:c9:e4:ab | attacker | 167,544 | 11.123 |
| 6 | e4:5f:01:55:90:c4 | attacker | 144,824 | 9.614 |
| 7 | dc:a6:32:c9:e5:ef | attacker | 132,701 | 8.81 |
| 8 | 3c:18:a0:41:c3:a0 | gateway | 19,342 | 1.284 |
| 9 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 2,873 | 0.191 |
| 10 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 1,990 | 0.132 |
| 11 | 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | 1,518 | 0.101 |
| 12 | 6c:5a:b0:44:1d:90 | TP-Link Tapo Camera | 1,371 | 0.091 |
| 13 | 7c:78:b2:86:0d:81 | Wyze Camera | 1,271 | 0.084 |
| 14 | b0:c5:54:59:2e:99 | D-Link DCS8000LHA1 Mini Camera | 1,193 | 0.079 |
| 15 | 56:4f:8a:e1:f3:2d | Randomised MAC (phone/laptop) | 1,135 | 0.075 |
| 16 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 1,080 | 0.072 |
| 17 | 70:ee:50:68:0e:32 | Netatmo Camera | 1,016 | 0.067 |
| 18 | 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | 1,005 | 0.067 |
| 19 | 00:17:88:60:d6:4f | Philips Hue Bridge | 904 | 0.06 |
| 20 | e8:1b:69:f8:d6:e6 | Unknown | 868 | 0.058 |
| 21 | e8:1b:69:f8:d4:e3 | Unknown | 778 | 0.052 |
| 22 | 84:e3:42:42:ed:0b | Lumiman Bulb | 663 | 0.044 |
| 23 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 657 | 0.044 |
| 24 | 28:6d:97:7a:2b:2d | SmartThings Hub | 645 | 0.043 |
| 25 | 00:a3:d1:07:6f:03 | Unknown | 617 | 0.041 |
| 26 | 28:6d:97:9e:f4:d5 | Aeotec Smart Home Hub | 613 | 0.041 |
| 27 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 609 | 0.04 |
| 28 | 44:bb:3b:00:39:07 | Nest Indoor Camera | 577 | 0.038 |
| 29 | c0:e7:bf:0a:79:d1 | unknown | 565 | 0.038 |
| 30 | dc:a6:32:c9:e6:f4 | attacker | 518 | 0.034 |

## Attack: Mirai-udpplain

- sha256: `845a8c833c5841203b75d776a353526f55a7fbcd9ca3079b53848e85a62ed3a7`
- rate plot: `attack_rate_Mirai-udpplain.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/Mirai-udpplain/Mirai-udpplain.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T20:43:56+00:00; peak RSS so far 298.7 MB (python), 426.1 MB (tshark)
- packets: 3,642,269; capture 2023-01-19T15:51:00.595065+00:00 -> 2023-01-19T16:23:26.574506+00:00 (32.43 min); tshark+aggregation 83.4 s
- attacker-MAC packets: sent 3,563,700 (97.843%), received 988
- **background share** (neither from nor to an attacker MAC): 2.13%
- attacker packets span 2023-01-19T15:51:04.794441+00:00 -> 2023-01-19T16:23:26.574506+00:00; 26 active minutes; 109,878.86 pkt/min over the capture, peak 291,487
- attacker protocols: {'UDP': 3558044, 'none': 5219, 'TCP': 356, 'ICMP': 81}; TCP flags: {'ACK': 130, 'PSH+ACK': 100, 'SYN': 72, 'RST': 26, 'FIN+ACK': 17, 'FIN+PSH+ACK': 11}
- broadcast / multicast destinations of attacker packets (never victims): {'broadcast': 4666, 'multicast': 95}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 0, 'lan_xcheck_keys': 44}

**Coverage (min victims 2):** overall **G1-only**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 5 | 3,558,905 | 2023-01-19T15:51:04.794441+00:00 | 2023-01-19T16:23:26.574506+00:00 | PASS |
| G2 | 0 | 0 |  |  | FAIL |
| GEN | 0 | 0 |  |  | FAIL |
| gateway | 1 | 30 | 2023-01-19T15:53:18.859183+00:00 | 2023-01-19T15:55:20.936336+00:00 | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 3

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2023-01-19T15:51:00.000000+00:00 | 2023-01-19T16:02:00.000000+00:00 | 11 | 1,954,531 | 291,487 |
| 2023-01-19T16:08:00.000000+00:00 | 2023-01-19T16:19:00.000000+00:00 | 11 | 1,265,013 | 232,812 |
| 2023-01-19T16:22:00.000000+00:00 | 2023-01-19T16:24:00.000000+00:00 | 2 | 344,152 | 236,665 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 659,130 | 20322.83 | 0.05 | 3 | G1 3 | 4 | 15:51:00-15:56:00 (263,959 pkts); 15:59:00-16:02:00 (64,209 pkts); 16:08:00-16:14:00 (254,974 pkts); 16:22:00-16:24:00 (75,528 pkts) |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 393,554 | 12134.37 | 0.03 | 3 | G1 3 | 3 | 15:51:00-16:01:00 (202,930 pkts); 16:08:00-16:14:00 (150,304 pkts); 16:22:00-16:24:00 (39,985 pkts) |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 42 | 1.29 | 0.46 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 753,722 | 23239.36 | 0.05 | 3 | G1 3 | 3 | 15:51:00-16:02:00 (468,307 pkts); 16:08:00-16:14:00 (224,138 pkts); 16:22:00-16:24:00 (60,991 pkts) |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 3 | 0.09 | 0.27 | 0 | - | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 644,873 | 19883.24 | 0.05 | 5 | G1 5 | 4 | 15:51:00-15:56:00 (207,260 pkts); 15:59:00-16:02:00 (176,840 pkts); 16:08:00-16:15:00 (214,832 pkts); 16:22:00-16:24:00 (45,343 pkts) |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 372,460 | 11483.99 | 0.05 | 3 | G1 3 | 4 | 15:51:00-15:56:00 (114,959 pkts); 15:59:00-16:02:00 (84,847 pkts); 16:08:00-16:14:00 (137,601 pkts); 16:22:00-16:24:00 (34,593 pkts) |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 48 | 1.48 | 0.22 | 1 | gateway 1 | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 442,703 | 13649.77 | 33.42 | 3 | G1 3 | 3 | 15:51:00-16:02:00 (229,868 pkts); 16:08:00-16:15:00 (166,523 pkts); 16:22:00-16:24:00 (46,077 pkts) |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 297,165 | 9162.43 | 0.03 | 3 | G1 3 | 4 | 15:51:00-15:57:00 (117,824 pkts); 16:00:00-16:02:00 (22,668 pkts); 16:08:00-16:14:00 (114,603 pkts); 16:22:00-16:24:00 (41,635 pkts) |

**Victims (6):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | G1 | 1,952,092 | both | 8015940.68 | 14 | 7 | UDP:1951922;none:170 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | G1 | 1,262,306 | both | 4365787.37 | 14 | 7 | UDP:1262142;none:164 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | G1 | 344,367 | both | 1293279.28 | 14 | 8 | UDP:343903;TCP:325;none:139 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5;e4:5f:01:55:90:c4 |
| 00:17:88:60:d6:4f | Philips Hue Bridge | G1 | 132 | both | 2260.71 | 3 | 1 | ICMP:80;TCP:30;none:22 | dc:a6:32:c9:e5:a4 |
| 3c:18:a0:41:c3:a0 | Gateway / router | gateway | 30 | new_service | 8.71 | 1 | 2 | UDP:23;none:6;ICMP:1 | dc:a6:32:c9:e6:f4 |
| 2c:71:ff:05:f1:15 | Amazon Echo Show | G1 | 8 | both | 137.01 | 2 | 1 | none:7;TCP:1 | dc:a6:32:c9:e5:a4 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:d5 | Amazon Alexa Echo Dot 1 | G1 | 468,041 | 0 | 8015940.68 | 2 | UDP/24683:468015;none:26 | both |
| dc:a6:32:c9:e5:a4 | Amazon Alexa Echo Dot 1 | G1 | 383,866 | 0 | 6574310.98 | 2 | UDP/38424:383836;none:30 | both |
| dc:a6:32:c9:e4:90 | Amazon Alexa Echo Dot 1 | G1 | 328,017 | 0 | 5617808.72 | 2 | UDP/7473:327990;none:27 | both |
| dc:a6:32:c9:e4:90 | Amazon Alexa Echo Studio | G1 | 254,913 | 0 | 4365787.37 | 2 | UDP/7473:254892;none:21 | both |
| dc:a6:32:dc:27:d5 | Amazon Alexa Echo Dot 1 | G1 | 229,522 | 0 | 3930926.43 | 2 | UDP/7487:229498;none:24 | both |
| dc:a6:32:c9:e4:d5 | Amazon Alexa Echo Studio | G1 | 224,079 | 0 | 3837706.46 | 2 | UDP/24683:224055;none:24 | both |
| dc:a6:32:c9:e5:a4 | Amazon Alexa Echo Studio | G1 | 214,551 | 0 | 3674524.43 | 2 | UDP/38424:214533;none:18 | both |
| dc:a6:32:c9:e4:ab | Amazon Alexa Echo Dot 1 | G1 | 202,663 | 0 | 3470923.67 | 2 | UDP/43323:202639;none:24 | both |
| dc:a6:32:c9:e5:ef | Amazon Alexa Echo Dot 1 | G1 | 199,686 | 0 | 3419937.85 | 2 | UDP/16562:199662;none:24 | both |
| dc:a6:32:dc:27:d5 | Amazon Alexa Echo Studio | G1 | 166,419 | 0 | 2850187.98 | 2 | UDP/7487:166395;none:24 | both |
| dc:a6:32:c9:e4:ab | Amazon Alexa Echo Studio | G1 | 150,260 | 0 | 2573439.61 | 2 | UDP/43323:150230;none:30 | both |
| e4:5f:01:55:90:c4 | Amazon Alexa Echo Dot 1 | G1 | 140,297 | 0 | 2402807.51 | 2 | UDP/9947:140282;none:15 | both |
| dc:a6:32:c9:e5:ef | Amazon Alexa Echo Studio | G1 | 137,550 | 0 | 2355760.8 | 2 | UDP/16562:137530;none:20 | both |
| e4:5f:01:55:90:c4 | Amazon Alexa Echo Studio | G1 | 114,534 | 0 | 1961575.48 | 2 | UDP/9947:114507;none:27 | both |
| dc:a6:32:c9:e4:90 | Google Nest Mini Speaker | G1 | 75,513 | 0 | 1293279.28 | 2 | UDP/7473:75492;none:21 | both |
| dc:a6:32:c9:e4:d5 | Google Nest Mini Speaker | G1 | 60,984 | 0 | 1044447.23 | 2 | UDP/24683:60969;none:15 | both |
| dc:a6:32:dc:27:d5 | Google Nest Mini Speaker | G1 | 46,068 | 13,401 | 58.88 | 1 | UDP/7487:46048 | both |
| dc:a6:32:c9:e5:a4 | Google Nest Mini Speaker | G1 | 45,629 | 0 | 781468.63 | 3 | UDP/38424:45268;TCP/8009:325;none:36 | both |
| e4:5f:01:55:90:c4 | Google Nest Mini Speaker | G1 | 41,624 | 0 | 712876.68 | 2 | UDP/9947:41609;none:15 | both |
| dc:a6:32:c9:e4:ab | Google Nest Mini Speaker | G1 | 39,972 | 0 | 684583.57 | 2 | UDP/43323:39946;none:26 | both |
| dc:a6:32:c9:e5:ef | Google Nest Mini Speaker | G1 | 34,577 | 0 | 592185.69 | 2 | UDP/16562:34571;none:6 | both |
| dc:a6:32:c9:e5:a4 | Philips Hue Bridge | G1 | 132 | 0 | 2260.71 | 3 | ICMP:80;TCP/80:30;none:22 | both |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 30 | 59 | 8.71 | 1 | ICMP:1 | new_service |
| dc:a6:32:c9:e5:a4 | Amazon Echo Show | G1 | 8 | 0 | 137.01 | 2 | none:7;TCP/34542:1 | both |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 2 | 60 | 0.57 | 0 |  |  |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 2 | 81 | 0.42 | 0 |  |  |

**Spoofing:** 10 distinct ip.src on attacker-MAC packets (exact) -> not spoofed (threshold > 10); 0 are real smart-home device IPs in this pcap's map (0 packets), 0 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.150 | 753,040 | False |
| 192.168.137.238 | 658,375 | False |
| 192.168.137.162 | 644,118 | False |
| 192.168.137.147 | 441,943 | False |
| 192.168.137.207 | 392,816 | False |
| 192.168.137.106 | 371,764 | False |
| 192.168.137.128 | 296,399 | False |
| 192.168.137.13 | 24 | False |
| 192.168.137.11 | 1 | False |
| 192.168.137.236 | 1 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| agree | 3,558,426 |
| no_ip_dst (non-IPv4) | 5,219 |
| multicast ip.dst | 52 |
| external ip.dst via gateway MAC | 3 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | dc:a6:32:c9:e4:d5 | attacker | 753,722 | 20.694 |
| 2 | dc:a6:32:c9:e4:90 | attacker | 659,130 | 18.097 |
| 3 | dc:a6:32:c9:e5:a4 | attacker | 644,873 | 17.705 |
| 4 | dc:a6:32:dc:27:d5 | attacker | 442,703 | 12.155 |
| 5 | dc:a6:32:c9:e4:ab | attacker | 393,554 | 10.805 |
| 6 | dc:a6:32:c9:e5:ef | attacker | 372,460 | 10.226 |
| 7 | e4:5f:01:55:90:c4 | attacker | 297,165 | 8.159 |
| 8 | 3c:18:a0:41:c3:a0 | gateway | 32,196 | 0.884 |
| 9 | 56:4f:8a:e1:f3:2d | Randomised MAC (phone/laptop) | 3,988 | 0.109 |
| 10 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 3,736 | 0.103 |
| 11 | 7c:78:b2:86:0d:81 | Wyze Camera | 2,364 | 0.065 |
| 12 | 70:ee:50:68:0e:32 | Netatmo Camera | 2,155 | 0.059 |
| 13 | 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | 1,992 | 0.055 |
| 14 | 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | 1,528 | 0.042 |
| 15 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 1,492 | 0.041 |
| 16 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 1,430 | 0.039 |
| 17 | 6c:5a:b0:44:1d:90 | TP-Link Tapo Camera | 1,284 | 0.035 |
| 18 | 00:17:88:60:d6:4f | Philips Hue Bridge | 1,223 | 0.034 |
| 19 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 1,196 | 0.033 |
| 20 | 18:69:d8:eb:d4:3e | Teckin Light Strip | 967 | 0.027 |
| 21 | 00:a3:d1:07:6f:03 | Unknown | 962 | 0.026 |
| 22 | 28:6d:97:7a:2b:2d | SmartThings Hub | 919 | 0.025 |
| 23 | 84:e3:42:42:ed:0b | Lumiman Bulb | 914 | 0.025 |
| 24 | e8:1b:69:f8:d4:e3 | Unknown | 891 | 0.024 |
| 25 | 28:6d:97:9e:f4:d5 | Aeotec Smart Home Hub | 883 | 0.024 |
| 26 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 876 | 0.024 |
| 27 | d4:a6:51:30:64:b7 | HeimVision SmartLife Radio/Lamp | 826 | 0.023 |
| 28 | 34:75:63:73:f3:36 | Home Eye Camera | 778 | 0.021 |
| 29 | b8:5f:98:d0:76:e6 | Amazon Smart Plug | 739 | 0.02 |
| 30 | c4:dd:57:0c:39:94 | Unidentified ESP plug (3) | 729 | 0.02 |

## Attack: Recon-PortScan

- sha256: `e13368bdc571a6ec53f8dd9e5491137dd0656c9d997bd62b323e957722bd4fc1`
- rate plot: `attack_rate_Recon-PortScan.png`
- file: `/home/krithikk/lgids_cache/ciciot2023/attack/Recon-PortScan/Recon-PortScan.pcap`
- rule parameters: {'rate_k': 10.0, 'min_new_services': 1, 'control_sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'device_table_sha256': '506d16bbaa3c0052fa63a619645ba5220cc1b70f084786c5ec86c8d686857532', 'stats_version': 2}; run 2026-10-10T19:57:37+00:00; peak RSS so far 229.0 MB (python), 239.6 MB (tshark)
- packets: 831,856; capture 2022-09-26T16:31:00.218342+00:00 -> 2022-09-27T17:16:00.794553+00:00 (1485.01 min); tshark+aggregation 22.5 s
- attacker-MAC packets: sent 147,498 (17.731%), received 125,498
- **background share** (neither from nor to an attacker MAC): 67.182%
- attacker packets span 2022-09-26T16:31:03.143732+00:00 -> 2022-09-27T17:15:38.019073+00:00; 127 active minutes; 99.32 pkt/min over the capture, peak 6,095
- attacker protocols: {'TCP': 146575, 'UDP': 479, 'none': 438, 'IGMP': 4, 'ICMP': 2}; TCP flags: {'SYN': 143325, 'ACK': 1448, 'PSH+ACK': 1394, 'RST': 216, 'FIN+ACK': 180, 'FIN+PSH+ACK': 12}
- broadcast / multicast destinations of attacker packets (never victims): {'multicast': 83, 'broadcast': 246}
- gateway 192.168.137.1 seen with MAC(s) ['3c:18:a0:41:c3:a0'] (table gateway MAC is used for 'gateway')
- caps: {'census_overflow': 0, 'xkey_overflow_packets': 0, 'pairs_with_dport_cap': 0, 'pairs_with_new_service_cap': 0, 'lan_xcheck_keys': 191}

**Coverage (min victims 2):** overall **BOTH**

| group | n_victims | attack_packets | window_start | window_end | verdict |
|---|---|---|---|---|---|
| G1 | 25 | 70,244 | 2022-09-26T16:31:40.375520+00:00 | 2022-09-27T17:14:36.806219+00:00 | PASS |
| G2 | 27 | 64,681 | 2022-09-26T17:17:12.438837+00:00 | 2022-09-27T17:08:17.695354+00:00 | PASS |
| GEN | 3 | 4,360 | 2022-09-26T19:04:26.848976+00:00 | 2022-09-27T14:20:27.120962+00:00 | PASS |
| gateway | 1 | 3,685 | 2022-09-26T16:31:21.582408+00:00 | 2022-09-27T17:15:38.019073+00:00 | - |

**Burst windows** (report only; attacker packets/min > 346.29 = K x control mean, gaps <= 2 min merged): 22

| start | end | minutes | packets | peak_per_min |
|---|---|---|---|---|
| 2022-09-26T16:31:00.000000+00:00 | 2022-09-26T16:32:00.000000+00:00 | 1 | 1,986 | 1,986 |
| 2022-09-26T16:42:00.000000+00:00 | 2022-09-26T16:43:00.000000+00:00 | 1 | 2,030 | 2,030 |
| 2022-09-26T16:49:00.000000+00:00 | 2022-09-26T16:51:00.000000+00:00 | 2 | 7,003 | 6,095 |
| 2022-09-26T16:54:00.000000+00:00 | 2022-09-26T16:55:00.000000+00:00 | 1 | 3,049 | 3,049 |
| 2022-09-26T17:02:00.000000+00:00 | 2022-09-26T17:30:00.000000+00:00 | 28 | 36,090 | 4,315 |
| 2022-09-26T18:12:00.000000+00:00 | 2022-09-26T18:40:00.000000+00:00 | 28 | 23,675 | 3,525 |
| 2022-09-26T18:44:00.000000+00:00 | 2022-09-26T18:45:00.000000+00:00 | 1 | 2,229 | 2,229 |
| 2022-09-26T18:58:00.000000+00:00 | 2022-09-26T18:59:00.000000+00:00 | 1 | 1,150 | 1,150 |
| 2022-09-26T19:04:00.000000+00:00 | 2022-09-26T19:08:00.000000+00:00 | 4 | 2,477 | 1,345 |
| 2022-09-27T13:44:00.000000+00:00 | 2022-09-27T13:55:00.000000+00:00 | 11 | 7,664 | 2,188 |
| 2022-09-27T13:59:00.000000+00:00 | 2022-09-27T14:09:00.000000+00:00 | 10 | 8,453 | 2,494 |
| 2022-09-27T14:14:00.000000+00:00 | 2022-09-27T14:24:00.000000+00:00 | 10 | 8,643 | 2,354 |
| 2022-09-27T14:29:00.000000+00:00 | 2022-09-27T14:46:00.000000+00:00 | 17 | 13,124 | 2,381 |
| 2022-09-27T14:49:00.000000+00:00 | 2022-09-27T14:51:00.000000+00:00 | 2 | 3,863 | 2,525 |
| 2022-09-27T14:58:00.000000+00:00 | 2022-09-27T14:59:00.000000+00:00 | 1 | 2,053 | 2,053 |
| 2022-09-27T15:02:00.000000+00:00 | 2022-09-27T15:03:00.000000+00:00 | 1 | 2,135 | 2,135 |
| 2022-09-27T15:08:00.000000+00:00 | 2022-09-27T15:10:00.000000+00:00 | 2 | 2,425 | 1,890 |
| 2022-09-27T15:24:00.000000+00:00 | 2022-09-27T15:28:00.000000+00:00 | 4 | 5,291 | 2,203 |
| 2022-09-27T16:47:00.000000+00:00 | 2022-09-27T16:48:00.000000+00:00 | 1 | 2,304 | 2,304 |
| 2022-09-27T17:00:00.000000+00:00 | 2022-09-27T17:01:00.000000+00:00 | 1 | 2,101 | 2,101 |
| 2022-09-27T17:04:00.000000+00:00 | 2022-09-27T17:05:00.000000+00:00 | 1 | 2,067 | 2,067 |
| 2022-09-27T17:08:00.000000+00:00 | 2022-09-27T17:15:00.000000+00:00 | 7 | 6,710 | 2,505 |

**Per attacker MAC:**

| attacker_mac | device | packets | pkt_per_min | control_pkt_per_min | victims | victims_by_group | burst_windows | bursts |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:c9:e4:90 | Raspberry Pi 4 (2 GB) | 6 | 0.0 | 0.05 | 1 | G1 1 | 0 | - |
| dc:a6:32:c9:e4:ab | Raspberry Pi 4 (2 GB) | 8 | 0.01 | 0.03 | 1 | G1 1 | 0 | - |
| dc:a6:32:c9:e4:c6 | Raspberry Pi 4 (2 GB) | 18 | 0.01 | 0.46 | 0 | - | 0 | - |
| dc:a6:32:c9:e4:d5 | Raspberry Pi 4 (2 GB) | 5 | 0.0 | 0.05 | 1 | G1 1 | 0 | - |
| dc:a6:32:c9:e5:02 | Raspberry Pi 4 (2 GB) | 197 | 0.13 | 0.27 | 1 | gateway 1 | 0 | - |
| dc:a6:32:c9:e5:a4 | Raspberry Pi 4 (2 GB) | 9 | 0.01 | 0.05 | 1 | G1 1 | 0 | - |
| dc:a6:32:c9:e5:ef | Raspberry Pi 4 (2 GB) | 6 | 0.0 | 0.05 | 1 | G1 1 | 0 | - |
| dc:a6:32:c9:e6:f4 | Raspberry Pi 4 (2 GB) | 10 | 0.01 | 0.22 | 0 | - | 0 | - |
| dc:a6:32:dc:27:d5 | Raspberry Pi 4 (8 GB) | 143,683 | 96.76 | 33.42 | 57 | G1 25, G2 27, GEN 3, unknown 2 | 22 | 16:31:00-16:32:00 (1,963 pkts); 16:42:00-16:43:00 (2,010 pkts); 16:49:00-16:51:00 (6,962 pkts); 16:54:00-16:55:00 (3,022 pkts); 17:02:00-17:30:00 (35,490 pkts); 18:12:00-18:40:00 (23,080 pkts); 18:44:00-18:45:00 (2,201 pkts); 18:58:00-18:59:00 (1,116 pkts); 19:04:00-19:08:00 (2,365 pkts); 13:44:00-13:55:00 (7,370 pkts); 13:59:00-14:09:00 (8,253 pkts); 14:14:00-14:24:00 (8,501 pkts); 14:29:00-14:46:00 (12,591 pkts); 14:49:00-14:51:00 (3,787 pkts); 14:58:00-14:59:00 (2,017 pkts); 15:02:00-15:03:00 (2,100 pkts); 15:08:00-15:10:00 (2,387 pkts); 15:24:00-15:28:00 (5,211 pkts); 16:47:00-16:48:00 (2,285 pkts); 17:00:00-17:01:00 (2,066 pkts); 17:04:00-17:05:00 (2,020 pkts); 17:08:00-17:15:00 (6,610 pkts) |
| dc:a6:32:dc:28:48 | not in device_table | 3,552 | 2.39 | 0.0 | 1 | gateway 1 | 0 | - |
| e4:5f:01:55:90:c4 | Raspberry Pi 4 (4 GB) | 4 | 0.0 | 0.03 | 0 | - | 0 | - |

**Victims (58):**

| mac | device | group | attack_packets | reason | rate_ratio | new_service_pairs | distinct_dst_ports | protocols | attacker_macs |
|---|---|---|---|---|---|---|---|---|---|
| 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | G1 | 7,012 | both | 2622.83 | 952 | 1,000 | TCP:7006;none:6 | dc:a6:32:dc:27:d5 |
| 34:75:63:73:f3:36 | Home Eye Camera | G1 | 5,009 | both | 1873.61 | 994 | 1,000 | TCP:5007;none:2 | dc:a6:32:dc:27:d5 |
| 44:bb:3b:00:39:07 | Nest Indoor Camera | G2 | 4,365 | both | 1632.72 | 947 | 1,000 | TCP:4363;none:2 | dc:a6:32:dc:27:d5 |
| b8:5f:98:d0:76:e6 | Amazon Smart Plug | G2 | 4,282 | both | 1601.68 | 1,000 | 1,000 | TCP:4282 | dc:a6:32:dc:27:d5 |
| 70:ee:50:68:0e:32 | Netatmo Camera | G1 | 4,039 | both | 1510.78 | 939 | 1,000 | TCP:4038;none:1 | dc:a6:32:dc:27:d5 |
| 50:02:91:10:09:8f | Unidentified ESP plug (2) | G2 | 3,822 | both | 1429.61 | 953 | 1,000 | TCP:3818;none:4 | dc:a6:32:dc:27:d5 |
| b0:f1:ec:d3:e7:98 | Harman Kardon speaker (Ampak) | G1 | 3,783 | both | 1415.03 | 998 | 1,000 | TCP:3777;none:6 | dc:a6:32:dc:27:d5 |
| 3c:18:a0:41:c3:a0 | Gateway / router | gateway | 3,685 | both | 1327.87 | 5 | 4 | TCP:3224;UDP:424;none:37 | dc:a6:32:c9:e5:02;dc:a6:32:dc:28:48 |
| 68:57:2d:56:ac:47 | Atomi Coffee Maker | G2 | 3,469 | both | 1297.58 | 1,000 | 1,000 | TCP:3469 | dc:a6:32:dc:27:d5 |
| 84:7a:b6:62:3a:6c | Yi Indoor 2 Camera | G1 | 3,326 | both | 1244.09 | 998 | 1,000 | TCP:3323;none:3 | dc:a6:32:dc:27:d5 |
| 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | G1 | 3,321 | both | 1242.22 | 997 | 1,000 | TCP:3318;none:3 | dc:a6:32:dc:27:d5 |
| 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | G1 | 3,282 | both | 1227.63 | 994 | 1,000 | TCP:3280;none:2 | dc:a6:32:dc:27:d5 |
| 10:5a:17:97:a5:c6 | Rbcior Camera | G1 | 3,198 | both | 1196.21 | 979 | 1,000 | TCP:3194;none:4 | dc:a6:32:dc:27:d5 |
| 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | G2 | 3,101 | both | 1159.93 | 997 | 1,000 | TCP:3100;none:1 | dc:a6:32:dc:27:d5 |
| cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | G1 | 3,018 | new_service | 0.08 | 997 | 1,000 | TCP:3017;none:1 | dc:a6:32:dc:27:d5 |
| 3c:37:86:6f:b9:51 | Arlo Base Station | G1 | 3,014 | both | 1127.38 | 993 | 1,000 | TCP:3013;none:1 | dc:a6:32:dc:27:d5 |
| 8c:85:80:6c:b6:47 | Eufy HomeBase 2 | G1 | 3,013 | both | 1127.01 | 996 | 1,000 | TCP:3012;none:1 | dc:a6:32:dc:27:d5 |
| 48:a6:b8:f9:1b:88 | Sonos One Speaker | G1 | 3,009 | both | 1125.51 | 990 | 1,000 | TCP:3007;none:2 | dc:a6:32:dc:27:d5 |
| 1c:9d:c2:8c:9a:94 | Levoit Air Purifier | G2 | 2,758 | both | 1031.63 | 1,002 | 1,000 | TCP:2756;none:2 | dc:a6:32:dc:27:d5 |
| 2c:d2:6b:66:d2:87 | Yi Outdoor Camera | G1 | 2,471 | both | 924.27 | 992 | 1,000 | TCP:2468;none:3 | dc:a6:32:dc:27:d5 |
| 28:6d:97:9e:f4:d5 | Aeotec Smart Home Hub | G1 | 2,465 | both | 57.63 | 950 | 1,000 | TCP:2461;none:4 | dc:a6:32:dc:27:d5 |
| 08:3a:f2:1f:bc:68 | Cocoon Smart HVAC Fan | G2 | 2,383 | both | 891.36 | 1,001 | 1,000 | TCP:2382;none:1 | dc:a6:32:dc:27:d5 |
| d4:a6:51:30:64:b7 | HeimVision SmartLife Radio/Lamp | G2 | 2,281 | both | 853.21 | 949 | 1,000 | TCP:2281 | dc:a6:32:dc:27:d5 |
| c4:dd:57:13:07:c6 | Unidentified ESP plug (4) | G2 | 2,237 | both | 836.75 | 941 | 1,000 | TCP:2237 | dc:a6:32:dc:27:d5 |
| 50:02:91:10:ac:d8 | GoSund Smart Plug WP2 (2) | G2 | 2,186 | both | 817.67 | 943 | 1,000 | TCP:2186 | dc:a6:32:dc:27:d5 |
| b8:f0:09:03:29:79 | GoSund Smart Plug WP2 (1) | G2 | 2,180 | both | 815.43 | 994 | 1,000 | TCP:2179;none:1 | dc:a6:32:dc:27:d5 |
| b8:f0:09:03:9a:af | GoSund Power Strip (2) | G2 | 2,180 | both | 815.43 | 965 | 1,000 | TCP:2180 | dc:a6:32:dc:27:d5 |
| 18:69:d8:eb:d4:3e | Teckin Light Strip | G2 | 2,177 | both | 814.3 | 948 | 1,000 | TCP:2177 | dc:a6:32:dc:27:d5 |
| 24:a1:60:14:7f:f9 | Unidentified ESP plug (1) | G2 | 2,173 | both | 812.81 | 966 | 1,000 | TCP:2173 | dc:a6:32:dc:27:d5 |
| d4:a6:51:21:6c:29 | Yutron Plug 2 | G2 | 2,172 | both | 812.43 | 947 | 1,000 | TCP:2172 | dc:a6:32:dc:27:d5 |
| 50:02:91:b1:68:0c | unknown | unknown | 2,171 | both | 812.06 | 997 | 1,000 | TCP:2171 | dc:a6:32:dc:27:d5 |
| 84:e3:42:42:ed:0b | Lumiman Bulb | G2 | 2,140 | both | 800.46 | 965 | 1,000 | TCP:2140 | dc:a6:32:dc:27:d5 |
| 28:6d:97:7a:2b:2d | SmartThings Hub | G1 | 2,135 | both | 199.65 | 993 | 1,000 | TCP:2134;none:1 | dc:a6:32:dc:27:d5 |
| 50:02:91:1a:ce:e1 | GoSund Power Strip (1) | G2 | 2,131 | both | 797.1 | 990 | 1,000 | TCP:2131 | dc:a6:32:dc:27:d5 |
| c4:dd:57:0c:39:94 | Unidentified ESP plug (3) | G2 | 2,130 | both | 796.72 | 949 | 1,000 | TCP:2130 | dc:a6:32:dc:27:d5 |
| d4:a6:51:78:97:4e | Teckin Plug 2 | G2 | 2,120 | both | 792.98 | 997 | 1,000 | TCP:2120 | dc:a6:32:dc:27:d5 |
| d4:ad:fc:29:c8:a2 | Govee Smart Humidifier | G2 | 2,096 | both | 784.01 | 964 | 1,000 | TCP:2096 | dc:a6:32:dc:27:d5 |
| b0:c5:54:59:2e:99 | D-Link DCS8000LHA1 Mini Camera | G2 | 2,064 | both | 772.04 | 977 | 1,000 | TCP:2060;none:4 | dc:a6:32:dc:27:d5 |
| d4:a6:51:20:91:d1 | Yutron Plug 1 | G2 | 2,032 | both | 760.07 | 983 | 1,000 | TCP:2032 | dc:a6:32:dc:27:d5 |
| 2c:71:ff:05:f1:15 | Amazon Echo Show | G1 | 2,019 | new_service | 2.49 | 968 | 1,000 | TCP:2006;none:13 | dc:a6:32:c9:e4:90;dc:a6:32:c9:e4:ab;dc:a6:32:c9:e4:d5;dc:a6:32:c9:e5:a4;dc:a6:32:c9:e5:ef;dc:a6:32:dc:27:d5 |
| ac:17:02:05:34:27 | Fibaro Home Center Lite | G1 | 2,018 | both | 754.83 | 994 | 1,000 | TCP:2016;none:2 | dc:a6:32:dc:27:d5 |
| ac:f1:08:4e:00:82 | LG Smart TV | G1 | 2,012 | new_service | 4.14 | 973 | 1,000 | TCP:2010;none:2 | dc:a6:32:dc:27:d5 |
| 6c:5a:b0:44:1d:90 | TP-Link Tapo Camera | G1 | 2,010 | both | 751.84 | 981 | 1,000 | TCP:2009;none:1 | dc:a6:32:dc:27:d5 |
| 70:ee:50:6b:a8:1a | Netatmo Weather Station | G2 | 2,009 | both | 751.46 | 977 | 1,000 | TCP:2006;none:3 | dc:a6:32:dc:27:d5 |
| 30:23:03:f3:57:cb | Wemo Smart Plug 2 | G1 | 2,008 | both | 751.09 | 987 | 1,000 | TCP:2007;none:1 | dc:a6:32:dc:27:d5 |
| d0:73:d5:35:fb:c8 | LIFX Lightbulb | G2 | 2,007 | both | 750.72 | 988 | 1,000 | TCP:2007 | dc:a6:32:dc:27:d5 |
| c0:e7:bf:0a:79:d1 | unknown | unknown | 2,006 | both | 750.34 | 987 | 1,000 | TCP:2005;none:1 | dc:a6:32:dc:27:d5 |
| 30:23:03:f3:84:2b | Wemo Smart Plug 1 | GEN | 2,003 | both | 749.22 | 995 | 1,000 | TCP:2002;none:1 | dc:a6:32:dc:27:d5 |
| 84:7a:b6:64:62:58 | Yi Indoor Camera | G1 | 2,003 | both | 749.22 | 938 | 1,000 | TCP:2001;none:2 | dc:a6:32:dc:27:d5 |
| 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | G1 | 2,002 | both | 748.85 | 989 | 1,000 | TCP:2000;none:2 | dc:a6:32:dc:27:d5 |
| b0:09:da:3e:82:6c | Ring Base Station | G2 | 2,002 | both | 748.85 | 937 | 1,000 | TCP:2000;none:2 | dc:a6:32:dc:27:d5 |
| 1c:fe:2b:98:16:dd | Amazon Alexa Echo Dot 1 | G1 | 1,961 | both | 733.51 | 941 | 1,000 | TCP:1959;none:2 | dc:a6:32:dc:27:d5 |
| 50:14:79:37:80:18 | iRobot Roomba | GEN | 1,352 | both | 505.71 | 650 | 680 | TCP:1350;none:2 | dc:a6:32:dc:27:d5 |
| f4:cf:a2:34:48:6b | LampUX RGB | G2 | 1,152 | both | 430.9 | 980 | 1,000 | TCP:1152 | dc:a6:32:dc:27:d5 |
| 00:17:88:60:d6:4f | Philips Hue Bridge | G1 | 1,114 | new_service | 0.12 | 991 | 1,000 | TCP:1112;none:2 | dc:a6:32:dc:27:d5 |
| d4:a6:51:76:06:64 | Teckin Plug 1 | G2 | 1,032 | both | 386.02 | 991 | 1,000 | TCP:1014;none:18 | dc:a6:32:dc:27:d5 |
| 00:02:75:f6:e3:cb | Smart Board | GEN | 1,005 | both | 375.92 | 982 | 1,000 | TCP:1004;none:1 | dc:a6:32:dc:27:d5 |
| 7c:78:b2:86:0d:81 | Wyze Camera | G1 | 1,002 | both | 374.8 | 976 | 1,000 | TCP:1001;none:1 | dc:a6:32:dc:27:d5 |

**All attacker -> unicast destination pairs** (control comparison):

| attacker_mac | device | group | attack_packets | control_packets | rate_ratio | new_service_pairs | new_services | reason |
|---|---|---|---|---|---|---|---|---|
| dc:a6:32:dc:27:d5 | Amazon Alexa Echo Studio | G1 | 7,012 | 0 | 2622.83 | 952 | TCP/41092:63;TCP/41094:63;TCP/41096:63;TCP/42709:61;TCP/42711:60;TCP/42707:59;TCP/35364:25;TCP/35366:25 | both |
| dc:a6:32:dc:27:d5 | Home Eye Camera | G1 | 5,009 | 0 | 1873.61 | 994 | TCP/42563:61;TCP/51775:26;TCP/55128:18;TCP/56005:16;TCP/58072:12;TCP/10002:10;TCP/7443:6;TCP/3333:6 | both |
| dc:a6:32:dc:27:d5 | Nest Indoor Camera | G2 | 4,365 | 0 | 1632.72 | 947 | TCP/33323:72;TCP/37437:66;TCP/38176:66;TCP/41287:63;TCP/2144:8;TCP/1503:7;TCP/2111:7;TCP/5500:7 | both |
| dc:a6:32:dc:27:d5 | Amazon Smart Plug | G2 | 4,282 | 0 | 1601.68 | 1,000 | TCP/44680:57;TCP/60679:9;TCP/6112:8;TCP/61722:8;TCP/12000:7;TCP/4848:6;TCP/3052:6;TCP/2121:6 | both |
| dc:a6:32:dc:27:d5 | Netatmo Camera | G1 | 4,039 | 0 | 1510.78 | 939 | TCP/33997:70;TCP/33999:70;TCP/37033:66;TCP/37035:66;TCP/80:42;TCP/22:4;TCP/8888:4;TCP/443:4 | both |
| dc:a6:32:dc:27:d5 | Unidentified ESP plug (2) | G2 | 3,822 | 0 | 1429.61 | 953 | TCP/39467:65;TCP/45333:56;TCP/46278:56;TCP/39469:35;TCP/46280:27;TCP/6668:7;TCP/32777:6;TCP/5566:6 | both |
| dc:a6:32:dc:27:d5 | Harman Kardon speaker (Ampak) | G1 | 3,783 | 0 | 1415.03 | 998 | TCP/38740:66;TCP/38742:28;TCP/53921:22;TCP/60943:9;TCP/1098:7;TCP/1132:7;TCP/53923:7;TCP/80:6 | both |
| dc:a6:32:dc:28:48 | Gateway / router | gateway | 3,550 | 0 | 1327.87 | 4 | TCP/443:3113;UDP/53:394;none:31;UDP/123:12 | both |
| dc:a6:32:dc:27:d5 | Atomi Coffee Maker | G2 | 3,469 | 0 | 1297.58 | 1,000 | TCP/44861:57;TCP/44863:11;TCP/6668:8;TCP/5987:7;TCP/62031:7;TCP/3333:7;TCP/264:6;TCP/911:6 | both |
| dc:a6:32:dc:27:d5 | Yi Indoor 2 Camera | G1 | 3,326 | 0 | 1244.09 | 998 | TCP/42868:61;TCP/51981:26;TCP/777:5;TCP/3325:5;TCP/4126:5;TCP/7999:5;TCP/254:5;TCP/7000:5 | both |
| dc:a6:32:dc:27:d5 | AMCREST WiFi Camera | G1 | 3,321 | 0 | 1242.22 | 997 | TCP/36696:68;TCP/38836:66;TCP/61040:9;TCP/5000:7;TCP/38838:7;TCP/80:6;TCP/554:6;TCP/3918:6 | both |
| dc:a6:32:dc:27:d5 | Arlo Q Indoor Camera | G1 | 3,282 | 0 | 1227.63 | 994 | TCP/36864:66;TCP/39429:65;TCP/57955:12;TCP/39431:9;TCP/30718:5;TCP/1301:5;TCP/1032:5;TCP/5221:5 | both |
| dc:a6:32:dc:27:d5 | Rbcior Camera | G1 | 3,198 | 0 | 1196.21 | 979 | TCP/49054:55;TCP/49419:39;TCP/51543:26;TCP/6668:5;TCP/555:5;TCP/8200:5;TCP/5225:5;TCP/5925:5 | both |
| dc:a6:32:dc:27:d5 | HeimVision Smart WiFi Camera | G2 | 3,101 | 0 | 1159.93 | 997 | TCP/46585:56;TCP/53914:22;TCP/61880:8;TCP/554:6;TCP/80:6;TCP/8001:6;TCP/7103:6;TCP/1111:5 | both |
| dc:a6:32:dc:27:d5 | Google Nest Mini Speaker | G1 | 3,018 | 13,401 | 0.08 | 997 | TCP/48043:56;TCP/52738:25;TCP/10001:6;TCP/8008:6;TCP/8443:6;TCP/9000:6;TCP/64229:5;TCP/7627:4 | new_service |
| dc:a6:32:dc:27:d5 | Arlo Base Station | G1 | 3,014 | 0 | 1127.38 | 993 | TCP/49491:39;TCP/51137:27;TCP/59089:11;TCP/53:6;TCP/554:6;TCP/5061:6;TCP/8100:6;TCP/1296:4 | both |
| dc:a6:32:dc:27:d5 | Eufy HomeBase 2 | G1 | 3,013 | 0 | 1127.01 | 996 | TCP/40794:64;TCP/58336:11;TCP/61736:8;TCP/554:6;TCP/53:6;TCP/80:6;TCP/9000:6;TCP/445:3 | both |
| dc:a6:32:dc:27:d5 | Sonos One Speaker | G1 | 3,009 | 0 | 1125.51 | 990 | TCP/35451:67;TCP/48462:55;TCP/56768:14;TCP/7000:6;TCP/1443:6;TCP/8800:4;TCP/143:3;TCP/443:3 | both |
| dc:a6:32:dc:27:d5 | Levoit Air Purifier | G2 | 2,758 | 0 | 1031.63 | 1,002 | TCP/37338:66;TCP/37340:16;TCP/443:8;TCP/49439:7;TCP/62242:6;TCP/544:6;TCP/32776:6;TCP/1433:6 | both |
| dc:a6:32:dc:27:d5 | Yi Outdoor Camera | G1 | 2,471 | 0 | 924.27 | 992 | TCP/36492:66;TCP/36494:27;TCP/57514:13;TCP/554:4;TCP/1310:4;TCP/32784:4;TCP/14238:4;TCP/8089:4 | both |
| dc:a6:32:dc:27:d5 | Aeotec Smart Home Hub | G1 | 2,465 | 16 | 57.63 | 950 | TCP/39425:65;TCP/48730:55;TCP/39427:14;TCP/39429:10;TCP/443:6;TCP/3370:5;TCP/1092:5;TCP/6100:5 | both |
| dc:a6:32:dc:27:d5 | Cocoon Smart HVAC Fan | G2 | 2,383 | 0 | 891.36 | 1,001 | TCP/51280:27;TCP/3071:7;TCP/2251:6;TCP/1132:6;TCP/6699:6;TCP/500:6;TCP/63152:6;TCP/911:5 | both |
| dc:a6:32:dc:27:d5 | HeimVision SmartLife Radio/Lamp | G2 | 2,281 | 0 | 853.21 | 949 | TCP/33036:72;TCP/47027:56;TCP/33038:9;TCP/163:5;TCP/89:5;TCP/2260:5;TCP/6:5;TCP/7911:5 | both |
| dc:a6:32:dc:27:d5 | Unidentified ESP plug (4) | G2 | 2,237 | 0 | 836.75 | 941 | TCP/33388:71;TCP/40545:64;TCP/33390:9;TCP/6668:5;TCP/1524:5;TCP/4449:5;TCP/3283:5;TCP/2366:5 | both |
| dc:a6:32:dc:27:d5 | GoSund Smart Plug WP2 (2) | G2 | 2,186 | 0 | 817.67 | 943 | TCP/34829:67;TCP/41393:63;TCP/34831:6;TCP/41395:5;TCP/9220:5;TCP/554:4;TCP/6006:4;TCP/9666:4 | both |
| dc:a6:32:dc:27:d5 | GoSund Power Strip (2) | G2 | 2,180 | 0 | 815.43 | 965 | TCP/47136:56;TCP/49749:39;TCP/1085:5;TCP/109:5;TCP/106:4;TCP/5269:4;TCP/20005:4;TCP/2010:4 | both |
| dc:a6:32:dc:27:d5 | GoSund Smart Plug WP2 (1) | G2 | 2,180 | 0 | 815.43 | 994 | TCP/48043:56;TCP/57509:13;TCP/3689:5;TCP/3128:4;TCP/1132:4;TCP/9111:4;TCP/9943:4;TCP/5544:4 | both |
| dc:a6:32:dc:27:d5 | Teckin Light Strip | G2 | 2,177 | 0 | 814.3 | 948 | TCP/41587:62;TCP/45277:56;TCP/6668:4;TCP/1114:4;TCP/5555:4;TCP/2323:4;TCP/19315:4;TCP/5550:4 | both |
| dc:a6:32:dc:27:d5 | Unidentified ESP plug (1) | G2 | 2,173 | 0 | 812.81 | 966 | TCP/43679:61;TCP/49440:39;TCP/43681:7;TCP/42510:5;TCP/4343:5;TCP/7:5;TCP/3006:4;TCP/1077:4 | both |
| dc:a6:32:dc:27:d5 | Yutron Plug 2 | G2 | 2,172 | 0 | 812.43 | 947 | TCP/35258:67;TCP/44533:57;TCP/35260:12;TCP/25:5;TCP/139:5;TCP/8080:4;TCP/587:4;TCP/443:4 | both |
| dc:a6:32:dc:27:d5 | unknown | unknown | 2,171 | 0 | 812.06 | 997 | TCP/51790:26;TCP/3527:5;TCP/1099:5;TCP/3351:5;TCP/32773:5;TCP/63360:5;TCP/143:4;TCP/7999:4 | both |
| dc:a6:32:dc:27:d5 | Lumiman Bulb | G2 | 2,140 | 0 | 800.46 | 965 | TCP/40473:64;TCP/49642:39;TCP/49644:5;TCP/10024:4;TCP/6668:4;TCP/749:4;TCP/3869:3;TCP/7676:3 | both |
| dc:a6:32:dc:27:d5 | SmartThings Hub | G1 | 2,135 | 4 | 199.65 | 993 | TCP/48397:54;TCP/59113:11;TCP/48399:10;TCP/443:4;TCP/1040:4;TCP/2021:4;TCP/5002:4;TCP/3077:4 | both |
| dc:a6:32:dc:27:d5 | GoSund Power Strip (1) | G2 | 2,131 | 0 | 797.1 | 990 | TCP/40636:64;TCP/57193:14;TCP/1032:6;TCP/8002:5;TCP/80:4;TCP/21:4;TCP/143:4;TCP/3306:4 | both |
| dc:a6:32:dc:27:d5 | Unidentified ESP plug (3) | G2 | 2,130 | 0 | 796.72 | 949 | TCP/42185:62;TCP/48871:55;TCP/48873:7;TCP/25735:4;TCP/125:4;TCP/3268:4;TCP/6668:4;TCP/2022:4 | both |
| dc:a6:32:dc:27:d5 | Teckin Plug 2 | G2 | 2,120 | 0 | 792.98 | 997 | TCP/57697:13;TCP/63395:5;TCP/2013:4;TCP/6668:4;TCP/311:4;TCP/30718:4;TCP/1025:3;TCP/8080:3 | both |
| dc:a6:32:dc:27:d5 | Govee Smart Humidifier | G2 | 2,096 | 0 | 784.01 | 964 | TCP/41976:62;TCP/49957:39;TCP/49959:6;TCP/15003:3;TCP/5004:3;TCP/6565:3;TCP/9200:3;TCP/16018:3 | both |
| dc:a6:32:dc:27:d5 | D-Link DCS8000LHA1 Mini Camera | G2 | 2,064 | 0 | 772.04 | 977 | TCP/46909:56;TCP/52022:26;TCP/554:6;TCP/8080:4;TCP/8088:4;TCP/8081:4;none:4;TCP/2135:3 | both |
| dc:a6:32:dc:27:d5 | Yutron Plug 1 | G2 | 2,032 | 0 | 760.07 | 983 | TCP/49771:39;TCP/54798:20;TCP/6668:4;TCP/2008:3;TCP/44176:3;TCP/10243:3;TCP/30718:3;TCP/211:3 | both |
| dc:a6:32:dc:27:d5 | Fibaro Home Center Lite | G1 | 2,018 | 0 | 754.83 | 994 | TCP/51884:26;TCP/61437:9;TCP/22:4;TCP/80:4;TCP/11111:4;TCP/8000:4;TCP/32778:3;TCP/3659:3 | both |
| dc:a6:32:dc:27:d5 | LG Smart TV | G1 | 2,012 | 182 | 4.14 | 973 | TCP/36853:67;TCP/50909:28;TCP/1455:4;TCP/7000:4;TCP/3001:4;TCP/3000:4;TCP/993:2;TCP/135:2 | new_service |
| dc:a6:32:dc:27:d5 | TP-Link Tapo Camera | G1 | 2,010 | 0 | 751.84 | 981 | TCP/35269:67;TCP/53422:22;TCP/554:4;TCP/443:4;TCP/2020:4;TCP/8800:4;TCP/3052:3;TCP/5900:2 | both |
| dc:a6:32:dc:27:d5 | Amazon Echo Show | G1 | 2,009 | 302 | 2.49 | 963 | TCP/46824:56;TCP/49447:39;TCP/8888:4;TCP/8009:4;TCP/1080:4;TCP/135:2;TCP/1025:2;TCP/256:2 | new_service |
| dc:a6:32:dc:27:d5 | Netatmo Weather Station | G2 | 2,009 | 0 | 751.46 | 977 | TCP/51747:26;TCP/51749:26;TCP/5001:8;none:3;TCP/111:2;TCP/3389:2;TCP/22:2;TCP/143:2 | both |
| dc:a6:32:dc:27:d5 | Wemo Smart Plug 2 | G1 | 2,008 | 0 | 751.09 | 987 | TCP/35856:69;TCP/56716:16;TCP/5544:3;TCP/49155:2;TCP/49154:2;TCP/22:2;TCP/111:2;TCP/993:2 | both |
| dc:a6:32:dc:27:d5 | LIFX Lightbulb | G2 | 2,007 | 0 | 750.72 | 988 | TCP/36407:66;TCP/57173:14;TCP/80:4;TCP/21:3;TCP/9878:3;TCP/19101:3;TCP/4126:3;TCP/5900:2 | both |
| dc:a6:32:dc:27:d5 | unknown | unknown | 2,006 | 0 | 750.34 | 987 | TCP/44202:60;TCP/56551:16;TCP/8800:4;TCP/1187:3;TCP/13456:3;TCP/9003:3;TCP/22:2;TCP/445:2 | both |
| dc:a6:32:dc:27:d5 | Wemo Smart Plug 1 | GEN | 2,003 | 0 | 749.22 | 995 | TCP/38955:65;TCP/61053:9;TCP/1002:3;TCP/111:2;TCP/8080:2;TCP/199:2;TCP/5900:2;TCP/1025:2 | both |
| dc:a6:32:dc:27:d5 | Yi Indoor Camera | G1 | 2,003 | 0 | 749.22 | 938 | TCP/33850:71;TCP/38358:65;TCP/8652:3;TCP/8080:2;TCP/3306:2;TCP/25:2;TCP/445:2;TCP/1720:2 | both |
| dc:a6:32:dc:27:d5 | Unidentified Amazon device (1c:12:b0) | G1 | 2,002 | 0 | 748.85 | 989 | TCP/52469:26;TCP/57274:14;TCP/111:2;TCP/3389:2;TCP/135:2;TCP/1720:2;TCP/110:2;TCP/139:2 | both |
| dc:a6:32:dc:27:d5 | Ring Base Station | G2 | 2,002 | 0 | 748.85 | 937 | TCP/37696:66;TCP/37103:66;TCP/1723:2;TCP/110:2;TCP/135:2;TCP/993:2;TCP/22:2;TCP/256:2 | both |
| dc:a6:32:dc:27:d5 | Amazon Alexa Echo Dot 1 | G1 | 1,961 | 0 | 733.51 | 941 | TCP/42404:62;TCP/42406:62;TCP/554:2;TCP/8080:2;TCP/3389:2;TCP/199:2;TCP/22:2;TCP/587:2 | both |
| dc:a6:32:dc:27:d5 | iRobot Roomba | GEN | 1,352 | 0 | 505.71 | 650 | TCP/46728:33;TCP/46730:33;TCP/199:2;TCP/5900:2;TCP/587:2;TCP/3389:2;TCP/256:2;TCP/1723:2 | both |
| dc:a6:32:dc:27:d5 | LampUX RGB | G2 | 1,152 | 0 | 430.9 | 980 | TCP/53531:22;TCP/3351:4;TCP/2525:4;TCP/2068:4;TCP/27000:4;TCP/1971:4;TCP/27715:4;TCP/5811:4 | both |
| dc:a6:32:dc:27:d5 | Philips Hue Bridge | G1 | 1,114 | 3,488 | 0.12 | 991 | TCP/60610:9;TCP/1782:3;TCP/32774:3;TCP/6566:3;TCP/144:3;TCP/2007:3;TCP/705:3;TCP/7402:3 | new_service |
| dc:a6:32:dc:27:d5 | Teckin Plug 1 | G2 | 1,032 | 0 | 386.02 | 991 | none:18;TCP/59282:11;TCP/53:2;TCP/199:2;TCP/445:2;TCP/443:2;TCP/143:2;TCP/8080:2 | both |
| dc:a6:32:dc:27:d5 | Smart Board | GEN | 1,005 | 0 | 375.92 | 982 | TCP/54138:21;TCP/6156:2;TCP/1033:2;TCP/1533:2;TCP/8080:1;TCP/3306:1;TCP/5900:1;TCP/993:1 | both |
| dc:a6:32:dc:27:d5 | Wyze Camera | G1 | 1,002 | 0 | 374.8 | 976 | TCP/51565:26;TCP/1119:2;TCP/22:1;TCP/995:1;TCP/443:1;TCP/3306:1;TCP/25:1;TCP/554:1 | both |
| dc:a6:32:c9:e5:02 | Gateway / router | gateway | 135 | 60 | 0.84 | 1 | TCP/80:111 | new_service |
| dc:a6:32:c9:e4:90 | Amazon Echo Show | G1 | 2 | 0 | 0.75 | 1 | none:2 | new_service |
| dc:a6:32:c9:e4:ab | Amazon Echo Show | G1 | 2 | 0 | 0.75 | 1 | none:2 | new_service |
| dc:a6:32:c9:e4:d5 | Amazon Echo Show | G1 | 2 | 0 | 0.75 | 1 | none:2 | new_service |
| dc:a6:32:c9:e5:a4 | Amazon Echo Show | G1 | 2 | 0 | 0.75 | 1 | none:2 | new_service |
| dc:a6:32:c9:e5:ef | Amazon Echo Show | G1 | 2 | 0 | 0.75 | 1 | none:2 | new_service |
| dc:a6:32:c9:e4:c6 | Gateway / router | gateway | 14 | 81 | 0.06 | 0 |  |  |
| dc:a6:32:c9:e6:f4 | Gateway / router | gateway | 6 | 59 | 0.04 | 0 |  |  |
| dc:a6:32:c9:e5:02 | Unknown | unknown | 2 | 2 | 0.37 | 0 |  |  |

**Spoofing:** 10 distinct ip.src on attacker-MAC packets (exact) -> not spoofed (threshold > 10); 0 are real smart-home device IPs in this pcap's map (0 packets), 0 are any LAN host IP.

| ip_src | packets | is_device_ip |
|---|---|---|
| 192.168.137.178 | 143,354 | False |
| 192.168.137.98 | 3,519 | False |
| 192.168.137.217 | 164 | False |
| 192.168.137.86 | 9 | False |
| 192.168.137.4 | 5 | False |
| 192.168.137.127 | 3 | False |
| 0.0.0.0 | 2 | False |
| 192.168.137.27 | 2 | False |
| 192.168.137.151 | 1 | False |
| 192.168.137.64 | 1 | False |

**IP/MAC cross-check** (attacker ip.dst -> this pcap's map vs eth.dst): **0 disagreeing packets**

| outcome | packets |
|---|---|
| agree | 143,757 |
| external ip.dst via gateway MAC | 3,254 |
| no_ip_dst (non-IPv4) | 438 |
| multicast ip.dst | 47 |
| limited_broadcast ip.dst | 2 |

Source-MAC census (top 30):

| rank | eth_src | tag | packets | pct |
|---|---|---|---|---|
| 1 | 3c:18:a0:41:c3:a0 | gateway | 196,077 | 23.571 |
| 2 | dc:a6:32:dc:27:d5 | attacker | 143,683 | 17.273 |
| 3 | ac:17:02:05:34:27 | Fibaro Home Center Lite | 62,159 | 7.472 |
| 4 | 30:23:03:f3:57:cb | Wemo Smart Plug 2 | 32,198 | 3.871 |
| 5 | 40:5d:82:35:14:c8 | Arlo Q Indoor Camera | 29,608 | 3.559 |
| 6 | 00:0c:29:1c:55:4a | unknown | 27,747 | 3.336 |
| 7 | 44:bb:3b:00:39:07 | Nest Indoor Camera | 25,179 | 3.027 |
| 8 | 1c:12:b0:9b:0c:ec | Unidentified Amazon device (1c:12:b0) | 20,792 | 2.499 |
| 9 | a0:d0:dc:c4:08:ff | Amazon Alexa Echo Dot 2 | 16,207 | 1.948 |
| 10 | 2c:71:ff:05:f1:15 | Amazon Echo Show | 15,344 | 1.845 |
| 11 | 7c:78:b2:86:0d:81 | Wyze Camera | 12,192 | 1.466 |
| 12 | 34:75:63:73:f3:36 | Home Eye Camera | 10,555 | 1.269 |
| 13 | 70:ee:50:68:0e:32 | Netatmo Camera | 10,362 | 1.246 |
| 14 | cc:f4:11:9c:d0:00 | Google Nest Mini Speaker | 8,917 | 1.072 |
| 15 | c0:e7:bf:0a:79:d1 | unknown | 8,761 | 1.053 |
| 16 | 56:4f:8a:e1:f3:2d | Randomised MAC (phone/laptop) | 8,378 | 1.007 |
| 17 | b0:f1:ec:d3:e7:98 | Harman Kardon speaker (Ampak) | 8,194 | 0.985 |
| 18 | 08:7c:39:ce:6e:2a | Amazon Alexa Echo Studio | 7,263 | 0.873 |
| 19 | 44:01:bb:ec:10:4a | HeimVision Smart WiFi Camera | 6,605 | 0.794 |
| 20 | 28:6d:97:7a:2b:2d | SmartThings Hub | 6,176 | 0.742 |
| 21 | 00:17:88:60:d6:4f | Philips Hue Bridge | 6,035 | 0.725 |
| 22 | 28:6d:97:9e:f4:d5 | Aeotec Smart Home Hub | 6,030 | 0.725 |
| 23 | 8c:85:80:6c:b6:47 | Eufy HomeBase 2 | 5,357 | 0.644 |
| 24 | 50:02:91:10:09:8f | Unidentified ESP plug (2) | 5,322 | 0.64 |
| 25 | ac:f1:08:4e:00:82 | LG Smart TV | 5,196 | 0.625 |
| 26 | 00:a3:d1:07:6f:03 | Unknown | 5,014 | 0.603 |
| 27 | 9c:8e:cd:1d:ab:9f | AMCREST WiFi Camera | 5,005 | 0.602 |
| 28 | 68:57:2d:56:ac:47 | Atomi Coffee Maker | 4,954 | 0.596 |
| 29 | 3c:37:86:6f:b9:51 | Arlo Base Station | 4,616 | 0.555 |
| 30 | b8:5f:98:d0:76:e6 | Amazon Smart Plug | 4,527 | 0.544 |
