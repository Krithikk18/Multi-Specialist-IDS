# LAN IP -> MAC -> device map report

- **run_timestamp_utc**: 2026-10-08T16:37:43+00:00
- **pcap**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/raw/ciciot2023/benign/BenignTraffic.pcap
- **pcap_sha256**: 549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8
- **pcap_cache**: {'cached_path': '/home/krithikk/lgids_cache/BenignTraffic.pcap', 'action': 'reused existing cache', 'source_hash_from': 'sidecar (source size+mtime unchanged)', 'sha256': '549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8', 'verified': True}
- **devices**: /mnt/d/Projects/Company Project/Paper_Implemetation/config/device_table.csv
- **devices_sha256**: 50dcde5b0dd547d580cdb9124e7d12ffdcb40f4a2d2b3c9804ec7af9df67945c
- **flows**: /mnt/d/Projects/Company Project/Paper_Implemetation/data/interim/flows/benign/BenignTraffic.pcap_Flow__singlepkt.csv
- **flows_sha256**: b8a757e7339c1a97c4941efa8f6bea2f07981651d86e699e606315a2ee8b2606
- **out_map**: /mnt/d/Projects/Company Project/Paper_Implemetation/config/ip_mac_map.csv
- **tshark_version**: TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).
- **packets_processed**: 3664164
- **packets_expected**: 3664164
- **runtime_s**: 141.0
- **python**: 3.11.17
- **pandas**: 3.0.6

## Summary

- **map_rows**: 109
- **map_rows_ipv4**: 75
- **map_rows_ipv6**: 34
- **distinct_ips**: 108
- **distinct_macs**: 72
- **smart_home_devices_mapped**: 55/55
- **listed_devices_mapped**: 72/73
- **ip_conflicts_sequential**: 0
- **ip_conflicts_overlapping**: 1
- **macs_with_multiple_ipv4**: 4
- **gateway_ipv4**: 192.168.137.1, 192.168.1.108
- **unmapped_listed_devices**: 1
- **lan_ips_with_unlisted_mac**: 0
- **flows_either_end_smart_home_pct**: 96.43
- **runtime_s**: 141.0

## Packet stats (tshark pass)

- **packets**: 3,664,164
- **ipv4**: 3,534,248
- **dst_skipped_non_unicast_mac**: 183,380
- **arp**: 88,527
- **ipv6**: 18,428
- **other_non_ip**: 22,961
- **tshark_seconds**: 136.4

## Inferred subnet(s)

Subnets inferred as the /24 networks containing private IPv4 addresses seen as a SOURCE (eth.src/ip.src or ARP sender) with a unicast MAC; the /24's .255 (plus 169.254.255.255) is treated as subnet broadcast and excluded.

| subnet | broadcast | hosts_seen | host_range | tightest_covering_prefix | source_evidence_packets |
|---|---|---|---|---|---|
| 192.168.137.0/24 | 192.168.137.255 | 71 | 192.168.137.1 - 192.168.137.253 | /24 | 2,228,735 |
| 10.22.22.0/24 | 10.22.22.255 | 1 | 10.22.22.1 - 10.22.22.1 | /32 | 2 |

## Filtering (raw pairs dropped)

| reason | pairs | evidence_packets |
|---|---|---|
| not_lan_scope | 1,066 | 2,920,685 |
| unspecified | 65 | 7,249 |

## Gateway (3c:18:a0:41:c3:a0) LAN IPs

| ip | ip_version | packets | first_seen_utc | last_seen_utc |
|---|---|---|---|---|
| 192.168.137.1 | 4 | 225,172 | 2022-10-07T17:15:00.886613+00:00 | 2022-10-08T02:30:28.260263+00:00 |
| fe80::9913:912c:c2be:a3d8 | 6 | 12 | 2022-10-07T18:24:59.241936+00:00 | 2022-10-08T00:10:21.992395+00:00 |
| 192.168.1.108 | 4 | 1 | 2022-10-07T18:54:33.559637+00:00 | 2022-10-07T18:54:33.559637+00:00 |

## IPs with more than one MAC (0 sequential, 1 overlapping)


### 192.168.137.249 -- OVERLAPPING

| mac | device_name | role | first_seen_utc | last_seen_utc | packets | evidence_src | evidence_dst | evidence_arp |
|---|---|---|---|---|---|---|---|---|
| 24:05:88:30:6f:89 | Unknown | unknown | 2022-10-07T17:15:00.886613+00:00 | 2022-10-07T21:06:24.758781+00:00 | 20,517 | 20,100 | 29 | 388 |
| 84:7a:b6:62:3a:6c | Yi Indoor 2 Camera | iot | 2022-10-07T17:15:00.889190+00:00 | 2022-10-08T02:30:25.239514+00:00 | 49,506 | 24,254 | 24,222 | 1,030 |

## MACs with more than one IP (4 flagged with >1 IPv4)


### 30:23:03:f3:57:cb (Wemo Smart Plug 2, iot) -- 2 IPv4 / 1 IPv6 **FLAG: multiple IPv4**

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.66 | 4 | 2022-10-07T17:15:29.785452+00:00 | 2022-10-08T02:29:36.996088+00:00 | 1,910 |
| fe80::3223:3ff:fef3:57cb | 6 | 2022-10-07T17:16:21.470443+00:00 | 2022-10-08T02:29:37.001732+00:00 | 778 |
| 10.22.22.1 | 4 | 2022-10-08T00:07:46.244434+00:00 | 2022-10-08T00:09:05.048897+00:00 | 2 |

### 3c:18:a0:41:c3:a0 (Gateway / router, gateway) -- 2 IPv4 / 1 IPv6 **FLAG: multiple IPv4**

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.1 | 4 | 2022-10-07T17:15:00.886613+00:00 | 2022-10-08T02:30:28.260263+00:00 | 225,172 |
| fe80::9913:912c:c2be:a3d8 | 6 | 2022-10-07T18:24:59.241936+00:00 | 2022-10-08T00:10:21.992395+00:00 | 12 |
| 192.168.1.108 | 4 | 2022-10-07T18:54:33.559637+00:00 | 2022-10-07T18:54:33.559637+00:00 | 1 |

### dc:a6:32:c9:e6:f4 (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.23 | 4 | 2022-10-07T17:21:21.594241+00:00 | 2022-10-08T02:21:46.865824+00:00 | 132 |
| fe80::dea6:32ff:fec9:e6f4 | 6 | 2022-10-07T18:01:59.812777+00:00 | 2022-10-08T02:21:03.609545+00:00 | 20 |

### 70:ee:50:68:0e:32 (Netatmo Camera, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.35 | 4 | 2022-10-07T17:15:05.815486+00:00 | 2022-10-08T02:30:21.144256+00:00 | 40,306 |
| fe80::72ee:50ff:fe68:e32 | 6 | 2022-10-07T17:16:13.265999+00:00 | 2022-10-08T02:29:39.166864+00:00 | 742 |

### b0:f1:ec:d3:e7:98 (Harman Kardon speaker (Ampak), iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.47 | 4 | 2022-10-07T17:15:03.634939+00:00 | 2022-10-08T02:30:28.260263+00:00 | 50,191 |
| fe80::b2f1:ecff:fed3:e798 | 6 | 2022-10-07T20:30:46.088894+00:00 | 2022-10-08T01:50:51.010073+00:00 | 24 |

### 56:4f:8a:e1:f3:2d (Randomised MAC (phone/laptop), excluded) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.51 | 4 | 2022-10-07T17:15:01.740510+00:00 | 2022-10-08T02:30:08.733964+00:00 | 101,470 |
| fe80::848:1d26:ac40:7c5e | 6 | 2022-10-07T17:15:08.959122+00:00 | 2022-10-08T02:30:08.733966+00:00 | 2,868 |

### 00:02:75:f6:e3:cb (Smart Board, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| fe80::202:75ff:fef6:e3cb | 6 | 2022-10-07T17:57:24.203622+00:00 | 2022-10-08T02:24:46.033333+00:00 | 65 |
| 192.168.137.56 | 4 | 2022-10-07T18:04:34.098225+00:00 | 2022-10-08T02:16:00.876926+00:00 | 484 |

### 30:23:03:f3:84:2b (Wemo Smart Plug 1, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.57 | 4 | 2022-10-07T20:02:05.023580+00:00 | 2022-10-08T02:20:51.140417+00:00 | 19 |
| fe80::3223:3ff:fef3:842b | 6 | 2022-10-07T20:32:16.115899+00:00 | 2022-10-08T02:20:51.142249+00:00 | 17 |

### cc:f4:11:9c:d0:00 (Google Nest Mini Speaker, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.61 | 4 | 2022-10-07T17:15:01.351204+00:00 | 2022-10-08T02:30:26.915916+00:00 | 78,945 |
| fe80::cef4:11ff:fe9c:d000 | 6 | 2022-10-08T00:05:50.407953+00:00 | 2022-10-08T00:06:02.524298+00:00 | 12 |

### 08:3a:f2:1f:bc:68 (Cocoon Smart HVAC Fan, iot) -- 3 IPv4 / 0 IPv6 **FLAG: multiple IPv4**

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.171 | 4 | 2022-10-07T17:15:08.506589+00:00 | 2022-10-07T18:33:21.237104+00:00 | 1,749 |
| 192.168.137.71 | 4 | 2022-10-07T18:33:21.269339+00:00 | 2022-10-07T22:42:57.477508+00:00 | 5,619 |
| 192.168.137.110 | 4 | 2022-10-07T22:42:57.519989+00:00 | 2022-10-08T02:30:14.910223+00:00 | 5,118 |

### 3c:37:86:6f:b9:51 (Arlo Base Station, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.78 | 4 | 2022-10-07T17:15:06.494494+00:00 | 2022-10-08T02:30:23.570017+00:00 | 11,564 |
| fe80::3e37:86ff:fe6f:b951 | 6 | 2022-10-07T17:15:59.157620+00:00 | 2022-10-08T02:29:55.759309+00:00 | 551 |

### 08:7c:39:ce:6e:2a (Amazon Alexa Echo Studio, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.83 | 4 | 2022-10-07T17:15:03.287521+00:00 | 2022-10-08T02:30:20.019779+00:00 | 72,417 |
| fe80::a7c:39ff:fece:6e2a | 6 | 2022-10-08T00:05:38.339809+00:00 | 2022-10-08T00:05:46.384855+00:00 | 5 |

### 28:6d:97:9e:f4:d5 (Aeotec Smart Home Hub, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.86 | 4 | 2022-10-07T17:15:06.311974+00:00 | 2022-10-08T02:30:25.483110+00:00 | 31,454 |
| fe80::2a6d:97ff:fe9e:f4d5 | 6 | 2022-10-07T17:48:48.491273+00:00 | 2022-10-08T02:08:04.966964+00:00 | 71 |

### e8:1b:69:f8:d4:e3 (Unknown, unknown) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.103 | 4 | 2022-10-07T17:15:01.683600+00:00 | 2022-10-08T02:28:46.556024+00:00 | 2,334 |
| fe80::ea1b:69ff:fef8:d4e3 | 6 | 2022-10-07T17:16:58.982115+00:00 | 2022-10-08T02:28:26.926334+00:00 | 276 |

### b0:09:da:3e:82:6c (Ring Base Station, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.118 | 4 | 2022-10-07T17:15:18.811115+00:00 | 2022-10-08T02:30:03.691711+00:00 | 11,614 |
| fe80::b209:daff:fe3e:826c | 6 | 2022-10-07T18:12:35.137055+00:00 | 2022-10-08T01:34:57.303384+00:00 | 10 |

### dc:a6:32:dc:27:d5 (Raspberry Pi 4 (8 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.128 | 4 | 2022-10-07T17:15:02.200756+00:00 | 2022-10-08T02:30:26.915916+00:00 | 34,940 |
| fe80::dea6:32ff:fedc:27d5 | 6 | 2022-10-07T17:22:23.364080+00:00 | 2022-10-08T02:22:23.388072+00:00 | 28 |

### e8:1b:69:f8:d6:e6 (Unknown, unknown) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.131 | 4 | 2022-10-07T17:15:02.043489+00:00 | 2022-10-08T02:30:22.084122+00:00 | 6,013 |
| fe80::ea1b:69ff:fef8:d6e6 | 6 | 2022-10-07T17:16:54.582225+00:00 | 2022-10-08T02:30:12.618301+00:00 | 276 |

### 70:ee:50:6b:a8:1a (Netatmo Weather Station, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.135 | 4 | 2022-10-07T17:15:00.769974+00:00 | 2022-10-08T02:30:28.305341+00:00 | 10,969 |
| fe80::72ee:50ff:fe6b:a81a | 6 | 2022-10-07T17:16:13.077495+00:00 | 2022-10-08T02:29:28.475879+00:00 | 675 |

### dc:a6:32:c9:e4:c6 (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| fe80::7751:923:3c0f:1915 | 6 | 2022-10-07T17:21:23.722530+00:00 | 2022-10-08T02:21:47.276346+00:00 | 61 |
| 192.168.137.138 | 4 | 2022-10-07T17:21:29.907169+00:00 | 2022-10-08T02:21:53.313649+00:00 | 226 |

### 48:a6:b8:f9:1b:88 (Sonos One Speaker, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.148 | 4 | 2022-10-07T17:15:24.831311+00:00 | 2022-10-08T02:30:09.917090+00:00 | 8,344 |
| fe80::4aa6:b8ff:fef9:1b88 | 6 | 2022-10-07T17:43:55.011107+00:00 | 2022-10-08T02:10:43.682688+00:00 | 18 |

### 00:17:88:60:d6:4f (Philips Hue Bridge, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.154 | 4 | 2022-10-07T17:15:06.035698+00:00 | 2022-10-08T02:30:08.903537+00:00 | 36,230 |
| fe80::217:88ff:fe60:d64f | 6 | 2022-10-07T17:16:27.315403+00:00 | 2022-10-08T02:28:52.402109+00:00 | 660 |

### e4:5f:01:55:90:c4 (Raspberry Pi 4 (4 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.165 | 4 | 2022-10-07T17:16:39.105821+00:00 | 2022-10-08T02:16:39.150493+00:00 | 9 |
| fe80::e65f:1ff:fe55:90c4 | 6 | 2022-10-07T17:43:37.415048+00:00 | 2022-10-08T02:00:36.289906+00:00 | 18 |

### 2c:71:ff:05:f1:15 (Amazon Echo Show, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.172 | 4 | 2022-10-07T17:15:00.523815+00:00 | 2022-10-08T02:30:20.820963+00:00 | 252,365 |
| fe80::2e71:ffff:fe05:f115 | 6 | 2022-10-07T17:28:39.243141+00:00 | 2022-10-08T02:23:51.781658+00:00 | 21 |

### dc:a6:32:c9:e5:02 (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| fe80::dea6:32ff:fec9:e502 | 6 | 2022-10-07T17:37:27.593605+00:00 | 2022-10-08T01:38:03.279678+00:00 | 21 |
| 192.168.137.173 | 4 | 2022-10-07T17:40:32.953264+00:00 | 2022-10-08T02:21:44.947898+00:00 | 155 |

### 28:6d:97:7a:2b:2d (SmartThings Hub, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.186 | 4 | 2022-10-07T17:15:03.679095+00:00 | 2022-10-08T02:30:19.124744+00:00 | 33,649 |
| fe80::2a6d:97ff:fe7a:2b2d | 6 | 2022-10-07T17:24:45.782660+00:00 | 2022-10-08T02:09:02.918504+00:00 | 25 |

### dc:a6:32:c9:e4:90 (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.203 | 4 | 2022-10-07T17:25:59.610385+00:00 | 2022-10-08T02:25:59.627233+00:00 | 17 |
| fe80::dea6:32ff:fec9:e490 | 6 | 2022-10-07T17:49:54.833502+00:00 | 2022-10-08T02:14:56.695552+00:00 | 18 |

### 24:05:88:30:6f:89 (Unknown, unknown) -- 2 IPv4 / 0 IPv6 **FLAG: multiple IPv4**

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.249 | 4 | 2022-10-07T17:15:00.886613+00:00 | 2022-10-07T21:06:24.758781+00:00 | 20,517 |
| 192.168.137.207 | 4 | 2022-10-07T21:06:20.398629+00:00 | 2022-10-08T02:30:26.177460+00:00 | 189,050 |

### d0:73:d5:35:fb:c8 (LIFX Lightbulb, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.210 | 4 | 2022-10-07T17:15:01.382010+00:00 | 2022-10-08T02:30:16.415543+00:00 | 1,276 |
| fe80::d273:d5ff:fe35:fbc8 | 6 | 2022-10-07T17:15:01.388022+00:00 | 2022-10-08T02:28:59.234332+00:00 | 576 |

### dc:a6:32:c9:e4:d5 (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.221 | 4 | 2022-10-07T17:17:14.319556+00:00 | 2022-10-08T02:25:55.326286+00:00 | 17 |
| fe80::dea6:32ff:fec9:e4d5 | 6 | 2022-10-07T17:52:03.576543+00:00 | 2022-10-08T01:55:33.309043+00:00 | 18 |

### 8c:85:80:6c:b6:47 (Eufy HomeBase 2, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.224 | 4 | 2022-10-07T17:15:06.850268+00:00 | 2022-10-08T02:30:10.922529+00:00 | 20,834 |
| fe80::8e85:80ff:fe6c:b647 | 6 | 2022-10-07T17:15:59.979950+00:00 | 2022-10-08T02:28:55.341299+00:00 | 631 |

### dc:a6:32:c9:e5:ef (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.240 | 4 | 2022-10-07T17:26:01.932388+00:00 | 2022-10-08T02:26:01.975104+00:00 | 20 |
| fe80::dea6:32ff:fec9:e5ef | 6 | 2022-10-07T17:49:44.696837+00:00 | 2022-10-08T02:20:13.351857+00:00 | 18 |

### dc:a6:32:c9:e5:a4 (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.246 | 4 | 2022-10-07T17:16:34.732062+00:00 | 2022-10-08T02:25:55.560177+00:00 | 18 |
| fe80::dea6:32ff:fec9:e5a4 | 6 | 2022-10-07T17:43:31.934857+00:00 | 2022-10-08T02:05:58.478663+00:00 | 18 |

### dc:a6:32:c9:e4:ab (Raspberry Pi 4 (2 GB), testbed_pi) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.248 | 4 | 2022-10-07T17:19:25.902628+00:00 | 2022-10-08T00:19:25.945295+00:00 | 4 |
| fe80::dea6:32ff:fec9:e4ab | 6 | 2022-10-07T17:27:44.429488+00:00 | 2022-10-08T02:27:44.444417+00:00 | 19 |

### ac:f1:08:4e:00:82 (LG Smart TV, iot) -- 1 IPv4 / 1 IPv6

| ip | ip_version | first_seen_utc | last_seen_utc | packets |
|---|---|---|---|---|
| 192.168.137.253 | 4 | 2022-10-07T20:30:22.459272+00:00 | 2022-10-08T02:30:28.319030+00:00 | 40,037 |
| fe80::aef1:8ff:fe4e:82 | 6 | 2022-10-07T20:30:24.822302+00:00 | 2022-10-08T02:29:38.857293+00:00 | 207 |

## Device-table entries with NO LAN IP (1)

| mac | device_name | category | role |
|---|---|---|---|
| 00:a3:d1:07:6f:03 | Unknown | Unknown | unknown |

## LAN IPs whose MAC is not in the device table (0)

_none_

## Flow coverage preview (IP-only lookup, no time window)

An IP with several MACs is resolved to its highest-packet MAC for this preview; 11,210 flows touch such an IP.

- **flows**: 223,108
- **src_smart_home**: 171,370
- **src_smart_home_pct**: 76.81
- **dst_smart_home**: 46,970
- **dst_smart_home_pct**: 21.053
- **either_smart_home**: 215,143
- **either_smart_home_pct**: 96.43
- **neither_smart_home**: 7,965
- **neither_smart_home_pct**: 3.57

### By role (unmapped = IP not in the map, e.g. internet hosts)

| role | src | src_pct | dst | dst_pct | either | either_pct |
|---|---|---|---|---|---|---|
| smart-home | 171,370 | 76.81 | 46,970 | 21.053 | 215,143 | 96.43 |
| gateway | 1,150 | 0.515 | 63,976 | 28.675 | 65,126 | 29.19 |
| testbed | 859 | 0.385 | 1,399 | 0.627 | 2,258 | 1.012 |
| phone | 3,666 | 1.643 | 189 | 0.085 | 3,855 | 1.728 |
| unknown | 2,537 | 1.137 | 171 | 0.077 | 2,672 | 1.198 |
| unlisted | 0 | 0.0 | 0 | 0.0 | 0 | 0.0 |
| unmapped | 43,526 | 19.509 | 110,403 | 49.484 | 153,355 | 68.736 |

### Top 10 LAN-scope flow IPs NOT in the map (0 distinct)

_none_
