# Packet reordering in the training / validation captures -- PASS

Written for network engineers. Read-only measurement of the capture files the IDS was trained and validated on (train and validation time windows only; the held-out test window is never read). "File order" = the order frames are stored in the .pcap; "inversion" = a frame whose timestamp is EARLIER than the frame stored just before it. Host roles: "inventory device" = a smart-home device in the testbed inventory; "attack source" = the testbed attack machines.

## 1. How often frames are out of timestamp order

| capture | format / timestamp unit | frames (train + val windows) | inversions | rate | median / p99 / max size (ms) | median / p99 behind the latest timestamp so far (ms) |
|---|---|---|---|---|---|---|
| DDoS-SYN_Flood | pcap / us | 25,738,494 | 74 | 0.000 % | 0.001 / 0.006 / 0.0 | 0.001 / 0.006 |
| DDoS-SYN_Flood5 | pcap / us | 24,555,297 | 56 | 0.000 % | 0.001 / 0.004 / 0.0 | 0.001 / 0.004 |
| Mirai-udpplain | pcap / us | 3,642,268 | 0 | 0.000 % | - | - |
| Recon-PortScan | pcap / us | 652,931 | 0 | 0.000 % | - | - |
| benign_night | pcap / us | 3,102,510 | 0 | 0.000 % | - | - |

Inversions by protocol (all captures):

| value | inverted frames | all frames | rate |
|---|---|---|---|
| non-IPv4 | 125 | 215,394 | 0.058 % |
| TCP | 5 | 53,073,713 | 0.000 % |

Inversions by TCP flags of the inverted frame (all captures):

| value | inverted frames | all frames | rate |
|---|---|---|---|
| S | 5 | 49,441,316 | 0.000 % |

Inversions by source host (all captures):

| value | inverted frames | all frames | rate |
|---|---|---|---|
| - | 125 | 215,394 | 0.058 % |
| attack source | 5 | 53,286,522 | 0.000 % |

Inversions by destination host (all captures):

| value | inverted frames | all frames | rate |
|---|---|---|---|
| - | 125 | 215,394 | 0.058 % |
| inventory device | 5 | 54,872,389 | 0.000 % |

## 2. TCP handshakes: is the reply stamped before the SYN?

A SYN from A to B is paired with B's first SYN/ACK or RST back on the same address / port pair (within 10 s). "Reply first" = the reply's timestamp is earlier than the SYN's. Class = the capture's attack type when A is an attack source, otherwise benign.

| responder | class | reply type | handshakes | reply first | share |
|---|---|---|---|---|---|
| other listed host | benign | SYN/ACK | 66,702 | 8,175 | 12.256 % |
| Unidentified Amazon device (1c:12:b0) | syn_flood | SYN/ACK | 147,759 | 5,381 | 3.642 % |
| Amazon Alexa Echo Dot 1 | syn_flood | SYN/ACK | 196,653 | 2,180 | 1.109 % |
| AMCREST WiFi Camera | syn_flood | SYN/ACK | 4,373 | 2,095 | 47.908 % |
| Unidentified ESP plug (2) | port_scan | RST/ACK | 2,862 | 2,015 | 70.405 % |
| GoSund Power Strip (1) | port_scan | RST/ACK | 2,003 | 1,851 | 92.411 % |
| LG Smart TV | port_scan | RST/ACK | 1,990 | 1,842 | 92.563 % |
| GoSund Smart Plug WP2 (2) | port_scan | RST/ACK | 2,029 | 1,628 | 80.237 % |
| Unidentified ESP plug (1) | port_scan | RST/ACK | 2,004 | 1,532 | 76.447 % |
| Unidentified ESP plug (3) | port_scan | RST/ACK | 2,008 | 1,401 | 69.771 % |
| Amazon Echo Show | port_scan | RST/ACK | 1,994 | 1,395 | 69.960 % |
| Lumiman Bulb | port_scan | RST/ACK | 2,087 | 1,285 | 61.572 % |
| GoSund Smart Plug WP2 (1) | port_scan | RST/ACK | 1,998 | 1,247 | 62.412 % |
| Harman Kardon speaker (Ampak) | port_scan | RST/ACK | 3,008 | 1,113 | 37.001 % |
| unlisted host | benign | SYN/ACK | 3,371 | 1,092 | 32.394 % |
| Wemo Smart Plug 2 | port_scan | RST/ACK | 1,994 | 1,066 | 53.460 % |
| GoSund Power Strip (2) | port_scan | RST/ACK | 2,018 | 1,039 | 51.487 % |
| Philips Hue Bridge | port_scan | RST/ACK | 1,004 | 1,004 | 100.000 % |
| Yutron Plug 2 | port_scan | RST/ACK | 2,141 | 640 | 29.893 % |
| Amazon Alexa Echo Dot 2 | benign | SYN/ACK | 683 | 461 | 67.496 % |
| LampUX RGB | port_scan | RST/ACK | 1,061 | 351 | 33.082 % |
| Wemo Smart Plug 1 | port_scan | RST/ACK | 2,000 | 296 | 14.800 % |
| Yi Indoor 2 Camera | port_scan | RST/ACK | 3,285 | 292 | 8.889 % |
| Teckin Light Strip | port_scan | RST/ACK | 2,173 | 169 | 7.777 % |
| Yi Outdoor Camera | port_scan | RST/ACK | 2,461 | 156 | 6.339 % |
| Philips Hue Bridge | benign | SYN/ACK | 102 | 81 | 79.412 % |
| Govee Smart Humidifier | port_scan | RST/ACK | 2,088 | 71 | 3.400 % |
| Google Nest Mini Speaker | syn_flood | SYN/ACK | 569 | 69 | 12.127 % |
| Levoit Air Purifier | port_scan | RST/ACK | 1,976 | 55 | 2.783 % |
| Amazon Echo Show | benign | SYN/ACK | 77 | 45 | 58.442 % |
| LG Smart TV | benign | RST/ACK | 44 | 43 | 97.727 % |
| Smart Board | port_scan | RST/ACK | 1,004 | 40 | 3.984 % |
| Wyze Camera | port_scan | RST/ACK | 1,001 | 36 | 3.596 % |
| Amazon Alexa Echo Studio | benign | SYN/ACK | 62 | 26 | 41.935 % |
| Unidentified ESP plug (3) | benign | RST/ACK | 35 | 25 | 71.429 % |
| TP-Link Tapo Camera | port_scan | RST/ACK | 1,993 | 25 | 1.254 % |
| LG Smart TV | benign | SYN/ACK | 27 | 24 | 88.889 % |
| Amazon Alexa Echo Dot 1 | benign | SYN/ACK | 64 | 23 | 35.938 % |
| Unidentified ESP plug (2) | syn_flood | SYN/ACK | 46 | 22 | 47.826 % |
| Harman Kardon speaker (Ampak) | benign | SYN/ACK | 36 | 18 | 50.000 % |

How this lines up with the two reversed-flow patterns the IDS sees (per capture x device, attack-source handshakes; dataset = the sampled flow rows): RST-type reply first <-> rows the R3 rule flips; SYN/ACK reply first <-> the diag_03 'H1' shape. Spearman over 53 cells: RST-first share vs R3-flip share +0.44; SYN/ACK-first share vs H1 share +0.63.

| capture | device | RST replies | first | SYN/ACK replies | first | dataset TCP attack flows | R3 flips | H1 shape |
|---|---|---|---|---|---|---|---|---|
| DDoS-SYN_Flood | Unidentified Amazon device (1c:12:b0) | 0 | 0 | 147,759 | 5,381 | 70,487 | 1 | 533 |
| DDoS-SYN_Flood | Amazon Alexa Echo Dot 1 | 0 | 0 | 196,653 | 2,180 | 70,558 | 0 | 503 |
| DDoS-SYN_Flood | AMCREST WiFi Camera | 0 | 0 | 4,373 | 2,095 | 50,103 | 3 | 259 |
| Recon-PortScan | Unidentified ESP plug (2) | 2,862 | 2,015 | 3 | 2 | 3,815 | 0 | 2 |
| Recon-PortScan | GoSund Power Strip (1) | 2,003 | 1,851 | 2 | 2 | 2,129 | 0 | 2 |
| Recon-PortScan | LG Smart TV | 1,990 | 1,842 | 10 | 9 | 1,998 | 1,840 | 9 |
| Recon-PortScan | GoSund Smart Plug WP2 (2) | 2,029 | 1,628 | 2 | 1 | 2,184 | 0 | 1 |
| Recon-PortScan | Unidentified ESP plug (1) | 2,004 | 1,532 | 2 | 2 | 2,171 | 0 | 2 |
| Recon-PortScan | Unidentified ESP plug (3) | 2,008 | 1,401 | 2 | 2 | 2,128 | 0 | 2 |
| Recon-PortScan | Amazon Echo Show | 1,994 | 1,395 | 6 | 5 | 2,000 | 1,395 | 5 |
| Recon-PortScan | Lumiman Bulb | 2,087 | 1,285 | 2 | 1 | 2,138 | 0 | 1 |
| Recon-PortScan | GoSund Smart Plug WP2 (1) | 1,998 | 1,247 | 2 | 1 | 2,177 | 0 | 1 |
| Recon-PortScan | Harman Kardon speaker (Ampak) | 3,008 | 1,113 | 12 | 5 | 3,765 | 1,113 | 5 |
| Recon-PortScan | Wemo Smart Plug 2 | 1,994 | 1,066 | 6 | 5 | 2,001 | 1,066 | 5 |
| Recon-PortScan | GoSund Power Strip (2) | 2,018 | 1,039 | 2 | 1 | 2,178 | 0 | 1 |
| Recon-PortScan | Philips Hue Bridge | 1,004 | 1,004 | 3 | 3 | 1,108 | 1,004 | 2 |
| Recon-PortScan | Yutron Plug 2 | 2,141 | 640 | 2 | 1 | 2,170 | 0 | 1 |
| Recon-PortScan | LampUX RGB | 1,061 | 351 | 1 | 0 | 1,151 | 0 | 0 |
| Recon-PortScan | Wemo Smart Plug 1 | 2,000 | 296 | 0 | 0 | 2,002 | 296 | 0 |
| Recon-PortScan | Yi Indoor 2 Camera | 3,285 | 292 | 0 | 0 | 3,323 | 292 | 0 |
| Recon-PortScan | Teckin Light Strip | 2,173 | 169 | 2 | 0 | 2,175 | 0 | 0 |
| Recon-PortScan | Yi Outdoor Camera | 2,461 | 156 | 0 | 0 | 2,468 | 156 | 0 |
| Recon-PortScan | Govee Smart Humidifier | 2,088 | 71 | 0 | 0 | 2,096 | 0 | 0 |
| DDoS-SYN_Flood | Google Nest Mini Speaker | 0 | 0 | 569 | 69 | 59,560 | 0 | 17 |
| Recon-PortScan | Levoit Air Purifier | 1,976 | 55 | 0 | 0 | 2,756 | 0 | 0 |
| Recon-PortScan | Smart Board | 1,004 | 40 | 0 | 0 | 1,004 | 40 | 0 |
| Recon-PortScan | Wyze Camera | 1,001 | 36 | 0 | 0 | 1,001 | 36 | 0 |
| Recon-PortScan | TP-Link Tapo Camera | 1,993 | 25 | 8 | 1 | 2,001 | 25 | 1 |
| DDoS-SYN_Flood5 | Unidentified ESP plug (2) | 0 | 0 | 46 | 22 | 105,953 | 0 | 2 |
| Recon-PortScan | Teckin Plug 2 | 2,109 | 18 | 2 | 0 | 2,118 | 0 | 0 |

## 3. Signs of a merged or multi-interface capture

| capture | file format | interface ids | timestamp unit (header) | share of timestamps on a whole ms | duplicate frames within 1 ms | non-IPv4 frames | unpaired SYN / reply |
|---|---|---|---|---|---|---|---|
| DDoS-SYN_Flood | pcap | none (classic pcap has no interface ids) | us | 0.10 % | 1,519 (0.006 %) | 37,449 | 20,109,761 / 353,487 |
| DDoS-SYN_Flood5 | pcap | none (classic pcap has no interface ids) | us | 0.10 % | 365 (0.001 %) | 24,145 | 21,069,925 / 1,933 |
| Mirai-udpplain | pcap | none (classic pcap has no interface ids) | us | 0.10 % | 501 (0.014 %) | 19,603 | 104 / 1,620 |
| Recon-PortScan | pcap | none (classic pcap has no interface ids) | us | 0.10 % | 300 (0.046 %) | 24,336 | 21,679 / 983 |
| benign_night | pcap | none (classic pcap has no interface ids) | us | 0.10 % | 788 (0.025 %) | 109,861 | 2,167 / 3,254 |

## Figures

- `figures/inversion_rate_per_capture.png`
- `figures/inversion_magnitude.png`
- `figures/responder_before_syn.png`

## Checks

- PASS  config.py / class_map.json unchanged  {'config/config.py': 'c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf', 'config/class_map.json': '64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580'}
