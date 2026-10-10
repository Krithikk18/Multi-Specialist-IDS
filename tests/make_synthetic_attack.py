#!/usr/bin/env python
"""tests/make_synthetic_attack.py -- synthetic attack pcap with known ground truth for 07a.

Builds <out> = first 200k packets of the benign pcap (editcap) merged (mergecap) with crafted
attacker packets (stdlib struct, no checksums). The benign slice keeps the Pis' NORMAL
traffic, which 07a must not count as attack when run with --control <benign pcap>.

Crafted traffic, 2022-10-07 17:30-17:40 UTC unless noted:
  e4:5f:01:55:90:c4 (testbed Pi, never talks to these devices in the benign capture)
    SYN floods, random dst ports 1-1024, spoofed ip.src:
      Home Eye Camera (G1) 3000, Sonos One (G1) 2400, Fibaro HCL (G1) 1800,
      Nest Indoor Camera (G2) 1200                       -> both (pair absent from control:
                                                            rate AND every service is new)
    eth.dst Home Eye / ip.dst Nest Indoor's IP: 100       -> IP/MAC disagreement 100
    broadcast UDP/1900: 50 (never a victim); gateway UDP/53 to 8.8.8.8: 30
  dc:a6:32:dc:27:d5 (testbed Pi, IP .128, with normal traffic to the devices below)
    rate-only flood: Google Nest Mini TCP/8009 (its normal Cast service), 20000 ACK/PSH
                                                          -> rate (no new service)
    low-rate port scan: Amazon Echo Show, 50 distinct ports 1 SYN each, 17:20-17:50
                                                          -> new_service (rate ~3x < K=10)
    Telnet: Philips Hue Bridge, 20 SYNs to TCP/23        -> new_service (rate ~1x)
  spoofed ip.src: 48 x 203.0.113.0/24 + Sonos IP + LIFX IP (2 device-IP collisions)

Expected with K=10, min new services 1, min victims 2: G1 victims = Home Eye, Sonos, Fibaro
(both), Google Nest Mini (rate), Echo Show + Hue Bridge (new_service) = 6; G2 = Nest Indoor
(both) = 1 -> G1-only. No other benign Pi pair is a victim.

Usage (repo root): python tests/make_synthetic_attack.py [--benign PCAP] [--out PCAP]
The pcap goes to CACHE_DIR/synthetic_test/ (outside the repo; *.pcap is gitignored anyway).
"""

from __future__ import annotations

import argparse
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import CACHE_DIR, DATASET  # noqa: E402

ATT, PI = "e4:5f:01:55:90:c4", "dc:a6:32:dc:27:d5"
PI_IP, ATT_IP = "192.168.137.128", "192.168.137.165"
GW = "3c:18:a0:41:c3:a0"
DEV = {"homeeye": ("34:75:63:73:f3:36", "192.168.137.133"),
       "sonos": ("48:a6:b8:f9:1b:88", "192.168.137.148"),
       "fibaro": ("ac:17:02:05:34:27", "192.168.137.41"),
       "nest": ("44:bb:3b:00:39:07", "192.168.137.46"),
       "nestmini": ("cc:f4:11:9c:d0:00", "192.168.137.61"),
       "echoshow": ("2c:71:ff:05:f1:15", "192.168.137.172"),
       "hue": ("00:17:88:60:d6:4f", "192.168.137.154")}
T0 = 1665163800.0          # 2022-10-07 17:30:00 UTC
SLICE_PACKETS = 200_000
SYN, ACK, PSH = 0x02, 0x10, 0x08
rng = random.Random(7)
SPOOF = [f"203.0.113.{i}" for i in rng.sample(range(1, 255), 48)] + [DEV["sonos"][1],
                                                                     "192.168.137.210"]


def mac(m: str) -> bytes:
    return bytes(int(x, 16) for x in m.split(":"))


def ip4(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def frame(src_mac, dst_mac, src_ip, dst_ip, proto, dport, sport=None, flags=SYN) -> bytes:
    sport = sport or rng.randint(1025, 65535)
    l4 = (struct.pack("!HHIIBBHHH", sport, dport, rng.getrandbits(32), 0, 5 << 4, flags,
                      64240, 0, 0) if proto == 6 else struct.pack("!HHHH", sport, dport, 8, 0))
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), rng.getrandbits(16), 0, 64, proto,
                      0, ip4(src_ip), ip4(dst_ip))
    return mac(dst_mac) + mac(src_mac) + b"\x08\x00" + iph + l4


def crafted() -> list[tuple[float, bytes]]:
    pk = []

    def burst(n, make, start=T0, span=600.0):
        pk.extend((start + rng.random() * span, make()) for _ in range(n))

    for key, n in (("homeeye", 3000), ("sonos", 2400), ("fibaro", 1800), ("nest", 1200)):
        m, ip = DEV[key]
        burst(n, lambda m=m, ip=ip: frame(ATT, m, rng.choice(SPOOF), ip, 6, rng.randint(1, 1024)))
    burst(100, lambda: frame(ATT, DEV["homeeye"][0], rng.choice(SPOOF), DEV["nest"][1], 6, 80))
    burst(50, lambda: frame(ATT, "ff:ff:ff:ff:ff:ff", ATT_IP, "192.168.137.255", 17, 1900))
    burst(30, lambda: frame(ATT, GW, ATT_IP, "8.8.8.8", 17, 53))
    m, ip = DEV["nestmini"]
    burst(20000, lambda: frame(PI, m, PI_IP, ip, 6, 8009, sport=39024, flags=PSH | ACK))
    m, ip = DEV["echoshow"]
    for port in rng.sample(range(1, 1025), 50):
        pk.append((T0 - 600 + rng.random() * 1800, frame(PI, m, PI_IP, ip, 6, port)))
    m, ip = DEV["hue"]
    burst(20, lambda: frame(PI, m, PI_IP, ip, 6, 23))
    return sorted(pk, key=lambda x: x[0])


def write_pcap(path: Path, pkts: list[tuple[float, bytes]]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # Ethernet
        for t, p in pkts:
            s = int(t)
            us = min(int(round((t - s) * 1e6)), 999_999)
            f.write(struct.pack("<IIII", s, us, len(p), len(p)) + p)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--benign", type=Path, default=DATASET.benign_pcap_cached)
    ap.add_argument("--out", type=Path, default=CACHE_DIR / "synthetic_test" / "SyntheticAttack_test.pcap")
    args = ap.parse_args()
    if not args.benign.is_file():
        sys.exit(f"FATAL: benign pcap not found: {args.benign}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    pkts = crafted()
    with tempfile.TemporaryDirectory(dir=args.out.parent) as tmp:
        sl, at = Path(tmp) / "slice.pcap", Path(tmp) / "attack.pcap"
        subprocess.run(["editcap", "-r", str(args.benign), str(sl), f"1-{SLICE_PACKETS}"], check=True)
        write_pcap(at, pkts)
        subprocess.run(["mergecap", "-F", "pcap", "-w", str(args.out), str(sl), str(at)], check=True)
    print(f"wrote {args.out}: {SLICE_PACKETS:,} benign + {len(pkts):,} crafted packets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
