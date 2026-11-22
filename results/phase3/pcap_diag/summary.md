# Phase 3 pcap path -- diagnostic follow-up (read-only, report-only)

- step 28 re-run `20261122T050150Z`, slice `Recon-PortScan` val window, 29,677 CICFlowMeter rows, 28,135 matched to dataset rows

## 1. Emission-time lag (emission - (start + duration))

- (a) prereg rule, as reported by 28: p50 1018.0 / p95 1805.0 / p99 1837.0 / max 1922.0 s; the successor clause raised 92.3% of rows
- (b) running max of end only: p50 70.0 / p95 187.6 / p99 189.3 / max 190.3 s
- (c) sweeper-aware (cap at start + 120 + 60 + 10 s): p50 221.4 / p95 377.0 / p99 379.0 / max 380.0 s
- Reading: the prereg's successor clause assumes a timed-out flow stays open until its successor's first packet; the locked jar's idle sweeper emits it within flow timeout + 70 s, so (a) overstates the lag; (c) is the realistic bound for this extractor. The pcap path is report-only; no metric depends on it.

## 2. Routing and predictions on the pcap path

- IP -> MAC from `config/ip_mac_map.csv` (benign_night capture only): group == dataset 0.87%, device == dataset 0.00% (resolver {'ipmap_src_unmapped': 28135, 'ipmap_dst_unmapped': 28135, 'no_device': 28135})
- IP -> MAC from the capture's own map `/home/krithikk/lgids_cache/maps/Recon-PortScan_ip_mac_map.csv` (what V1's 07 used): group == dataset 100.00%, device == dataset 100.00%
- predicted class, pcap-path runtime vs CSV-replay runtime (GLOBAL s0) on the matched flows: 100.0000% agree (0 differ)
- Reading: the runtime router's rule is right; the static map only covers one capture. On the Pi the router needs a live IP -> MAC source (ARP / DHCP table) -- a deployment item.
