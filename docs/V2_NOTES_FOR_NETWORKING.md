# LG-IDS V2 -- notes for the Networking team (Phase 3.1)

What the AIML runtime needs from the capture side, what it now does by itself, and what we measured in the testbed
captures that we would like you to look at. Details: `results/phase3_1/` (summary, reordering, routing).

## 1. What the runtime consumes

- **Flows** from the locked CICFlowMeter build (jar sha256 pinned in `config/config.py`, `EXTRACTOR`): one row per
  finished flow with the **70 features** listed in `config/features_v1.json` plus `Flow ID`, `Src IP`, `Src Port`,
  `Dst IP`, `Dst Port`, `Protocol`, `Timestamp`. Rows are consumed as they are emitted (tail of the CSV).
- **Source / destination MAC per flow** (`src_mac`, `dst_mac`) when you can provide them. CICFlowMeter itself writes
  none; without them the runtime now learns them (section 2).
- **Packets** (Ethernet + IPv4 headers only; no payload is read) for the packet-rate guard and for MAC learning: the
  same mirror the flow extractor sees, in capture-time order.

## 2. IP -> MAC is now learned passively (no static table needed)

Every frame the runtime already reads carries a source MAC and, for IPv4, a source IP; ARP frames carry the
sender's MAC and IP (ARP wins on a conflict). A flow is routed to a device using only what was learned from packets
captured before the flow was emitted. On the Recon-PortScan validation capture this gives **100 %** routing agreement
with the labelled data, against **0.87 %** with the old static table (which only covered one capture).

What this requires from the capture point:
- it must sit on the **LAN segment** and see the hosts' own Ethernet headers (a switch mirror / AP bridge on the LAN
  side, not after the router, where every frame carries the router's MAC);
- ARP traffic in the mirror helps (bindings are then exact from the first ARP exchange);
- a MAC that sends from more than 8 different source IPs within 5 minutes is treated as a **router / gateway**, and
  the remote IPs behind it are not bound (those flows go to the "unknown device" path). In the test capture exactly
  one MAC qualified: the inventory's gateway;
- an IP whose MAC changes is logged as `ip_mac_change`; 3 or more changes within 60 s as `ip_mac_flap` (a possible
  ARP-spoofing sign). These are health events in the signed health log, not alerts. None occurred in the test capture.

## 3. Packet ordering in the testbed captures (measurement, `results/phase3_1/reordering/summary.md`)

- **File order is time-sorted**: 130 timestamp inversions in 57.7 million frames (each at most 8 microseconds, all in
  the two SYN-flood captures); classic pcap, microsecond timestamps, no interface ids; duplicate frames within 1 ms are rare
  (0.001 - 0.05 %).
- **But replies are often stamped before the request that caused them**: 20.6 % of port-scan RST/ACK replies and
  14 % of benign SYN/ACK replies carry an EARLIER timestamp than the SYN they answer; per device this ranges from
  0 % to 100 % (stable per device). CICFlowMeter decides a flow's direction from the first packet it sees, so these
  flows come out "backwards" (the device looks like the initiator). Our orientation rule (R3) repairs one variant
  (RST/ACK with a zero window: on the devices it applies to, its flips match the reply-first counts within a few
  flows, e.g. 1,840 flips vs 1,842 reply-first handshakes); devices whose RST/ACK carries a non-zero window, and the
  SYN/ACK-first variant, are not repaired yet.

Questions for you:
1. Is the testbed capture a **switch mirror (SPAN) that merges several ports or both directions**? Reply-before-request
   with otherwise sorted files looks like two ingress paths with different buffering into one timestamped stream.
2. Where are timestamps taken (NIC hardware, kernel, after a merge / re-sort such as `reordercap`)?
3. On the Pi deployment, where will the capture point be (inline bridge, AP, mirror port), and can it timestamp
   both directions of a connection at the same point? A single-point, single-clock capture would remove most
   reversed flows at the source.
4. Can you provide per-flow MACs (or a DHCP / ARP feed) as a cross-check of the learned bindings?

## 4. Alerts we send you

The incident / alert message format is proposed in `docs/V2_ALERT_CONTRACT.md` (status **PROPOSED**): we need your
agreement on it (fields, transport, acknowledgement) before Phase 4.
