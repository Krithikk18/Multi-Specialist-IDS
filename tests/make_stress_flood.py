#!/usr/bin/env python
"""tests/make_stress_flood.py -- large spoofed SYN flood to exercise 07a's scaling paths.

N packets (default 3,000,000) from attacker e4:5f:01:55:90:c4 to Home Eye Camera (G1) over
10 minutes, random spoofed public ip.src (32-bit), random src/dst ports 1-65535. This drives
the exact -> HyperLogLog switch for distinct ip.src (> 100k), the 2,000-entry caps on dst
ports and new services, and memory under a ~96%-attacker packet mix (no benign slice).
The exact distinct ip.src count is printed and written to <out>.truth.json for comparison.

Usage (repo root): python tests/make_stress_flood.py [--packets N] [--out PCAP]
"""

from __future__ import annotations

import argparse
import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import CACHE_DIR  # noqa: E402

ATT, VICTIM, VICTIM_IP = "e4:5f:01:55:90:c4", "34:75:63:73:f3:36", "192.168.137.133"
T0, SPAN = 1665163800.0, 600.0     # 2022-10-07 17:30 UTC, 10 minutes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--packets", type=int, default=3_000_000)
    ap.add_argument("--out", type=Path, default=CACHE_DIR / "synthetic_test" / "StressSynFlood_test.pcap")
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(11)
    eth = bytes(int(x, 16) for x in VICTIM.split(":")) + bytes(int(x, 16) for x in ATT.split(":")) + b"\x08\x00"
    dst = bytes(int(x) for x in VICTIM_IP.split("."))
    tcp = struct.Struct("!HHIIBBHHH")
    iph = struct.Struct("!BBHHHBBH4s4s")
    rec = struct.Struct("<IIII")
    seen = set()
    step = SPAN / args.packets
    with open(args.out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(args.packets):
            src = rng.getrandbits(32) | 0x01000000            # avoid 0.x.x.x
            seen.add(src)
            l4 = tcp.pack(rng.randint(1, 65535), rng.randint(1, 65535), rng.getrandbits(32), 0,
                          5 << 4, 0x02, 64240, 0, 0)
            p = eth + iph.pack(0x45, 0, 40, i & 0xFFFF, 0, 64, 6, 0, src.to_bytes(4, "big"), dst) + l4
            t = T0 + i * step
            s = int(t)
            f.write(rec.pack(s, min(int((t - s) * 1e6), 999_999), len(p), len(p)) + p)
    truth = {"packets": args.packets, "distinct_ip_src": len(seen), "victim": VICTIM}
    args.out.with_name(args.out.name + ".truth.json").write_text(json.dumps(truth) + "\n")
    print(f"wrote {args.out}: {args.packets:,} packets, {len(seen):,} distinct ip.src")
    return 0


if __name__ == "__main__":
    sys.exit(main())
