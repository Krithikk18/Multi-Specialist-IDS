# Phase 3.2 Part B -- gateway rule on spoofed floods -- SAFE

Run `20261122T140322Z`. Configs: `v2_phase3_1.json` `14e45250569f3dee...` (pinned True), `v2_phase3_2.json` `71f47711c6dca64c...` (pinned True).
Learner: gateway = > 8 distinct source IPs within 300 s; unexpected_gateway warm-up 300 s, exempt inventory roles ['gateway', 'router'].

**Rule (fixed before any number):** routing agreement (group AND device == dataset) >= 0.99 of matched flows on every flood slice -> SAFE, otherwise UNSAFE. **VERDICT: SAFE.**

## B1 -- routing on each val slice (config v2_phase3_1.json, learned routing)

| slice | frames | CICFlowMeter flows | matched / dataset rows | agree group+device | group | device | gateway MACs (attack source?) | src / dst / both unbound | verdict |
|---|---|---|---|---|---|---|---|---|---|
| Recon-PortScan | 143,215 | 29,677 | 28,135 / 28,528 | 100.00% | 100.00% | 100.00% | `3c:18:a0:41:c3:a0` gateway (no) | 1,980 / 4,974 / 56 | reference |
| Mirai-udpplain | 348,598 | 646 | 592 / 597 | 100.00% | 100.00% | 100.00% | `3c:18:a0:41:c3:a0` gateway (no) | 37 / 388 / 3 | SAFE |
| DDoS-SYN_Flood5 | 2,275,892 | 788,588 | 32,809 / 51,205 | 100.00% | 100.00% | 100.00% | `3c:18:a0:41:c3:a0` gateway (no) | 199 / 607 / 8 | SAFE |
| DDoS-SYN_Flood | 2,901,590 | 792,359 | 52,529 / 52,542 | 100.00% | 100.00% | 100.00% | `3c:18:a0:41:c3:a0` gateway (no) | 505 / 984 / 10 | SAFE |

Rows fed to the runtime come from a numpy-backed copy of CicfmPcapSource (memory); identical to the stock source's rows where both were loaded: Recon-PortScan True, Mirai-udpplain True, DDoS-SYN_Flood5 None, DDoS-SYN_Flood None

## Gateway MACs

| slice | MAC | inventory name / role | attack source | detected (s after first frame) | frames from it | max distinct src IPs / window | matched flows touching it | unexpected_gateway (3.2) |
|---|---|---|---|---|---|---|---|---|
| Recon-PortScan | `3c:18:a0:41:c3:a0` | Gateway / router / gateway | False (other_device) | 1.34 (warm-up) | 38,161 | 183 | 2,486 | no |
| Mirai-udpplain | `3c:18:a0:41:c3:a0` | Gateway / router / gateway | False (other_device) | 1.47 (warm-up) | 1,437 | 86 | 192 | no |
| DDoS-SYN_Flood5 | `3c:18:a0:41:c3:a0` | Gateway / router / gateway | False (other_device) | 0.71 (warm-up) | 3,166 | 94 | 392 | no |
| DDoS-SYN_Flood | `3c:18:a0:41:c3:a0` | Gateway / router / gateway | False (other_device) | 2.18 (warm-up) | 7,516 | 118 | 969 | no |

## B2 -- unexpected_gateway (config v2_phase3_2.json)

| slice | spoofing sources (attack-source gateways) | expected events | fired | health events (3.2) | chain ok | pcap predictions 3.1 == 3.2 |
|---|---|---|---|---|---|---|
| Recon-PortScan | 0 | 0 | 0 | {'gateway_detected': 1, 'unexpected_gateway': 0, 'ip_mac_change': 0, 'ip_mac_flap': 0} | True | True |
| Mirai-udpplain | 0 | 0 | 0 | {'gateway_detected': 1, 'unexpected_gateway': 0, 'ip_mac_change': 0, 'ip_mac_flap': 0} | True | True |
| DDoS-SYN_Flood5 | 0 | 0 | 0 | {'gateway_detected': 1, 'unexpected_gateway': 0, 'ip_mac_change': 0, 'ip_mac_flap': 0} | True | True |
| DDoS-SYN_Flood | 0 | 0 | 0 | {'gateway_detected': 1, 'unexpected_gateway': 0, 'ip_mac_change': 0, 'ip_mac_flap': 0} | True | True |
- DDoS-SYN_Flood disagreement: dataset (G1, `ac:17:02:05:34:27`) vs runtime (GEN, ``, -): 2

Figure: `results/phase3_2/gateway/figures/distinct_src_ips.png`

Lock: config.py `c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf`, class_map.json `64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580` (start == end: True)
