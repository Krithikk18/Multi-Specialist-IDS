"""common/routing.py -- flow -> MAC -> device -> group at runtime, with ingest's exact rule (Phase 3).

    router = Router(cfg)                                    # inventory + groups + IP -> MAC map from config/v2_phase3.json
    r = router.route(raw_row)                               # Route(device_mac, device, group, rule, side)
    p = router.protected_for_dst_mac(mac)                   # rate guard: (device_mac, device, group) or None

Rule (V1 04_tag_flows.assign_owner + 08_build_datasets.usable + 08b_extend_test.usable_day), applied to the flow as the
extractor wrote it (BEFORE orientation normalising: the normaliser swaps the MAC columns):
  role(mac)  inventory role (lower-case); "" -> none; a unicast MAC the inventory does not list -> unlisted
  owner      both sides have an owner role -> Src side (device_device_initiator); exactly one -> that side
             (device_side); otherwise unowned: an unlisted unicast endpoint -> that MAC (Src first; 08b's rule,
             group = fallback) else no device (unknown device, fallback group)
  group      inventory group of the owner MAC if it is one of the groups file's labels, else the fallback group
MACs: the row's src_mac / dst_mac when present (dataset replay); when a row has no MAC keys (CICFlowMeter output), they
are resolved from the IP -> MAC map like 04: map rows of that IP whose [first_seen - tol, last_seen + tol] holds the
flow start; one distinct MAC -> it, several -> ambiguous (no MAC), none -> "".
Nothing here names a device, group or role: all come from the config and the files it points to.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from config.config import REPO_ROOT


@dataclass(frozen=True)
class Route:
    device_mac: str
    device: str
    group: str
    rule: str
    side: str           # "src" | "dst" | ""


def norm_mac(m) -> str:
    return str(m or "").strip().lower()


def is_unicast_mac(m: str) -> bool:
    try:
        return len(m) == 17 and (int(m[:2], 16) & 1) == 0
    except ValueError:
        return False


class IpMacMap:
    def __init__(self, path: Path, tol: float):
        self.tol = float(tol)
        self.by_ip = defaultdict(list)
        with open(path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                self.by_ip[r["ip"].strip()].append((float(r["first_seen_epoch"]), float(r["last_seen_epoch"]),
                                                    norm_mac(r["mac"])))

    def resolve(self, ip: str, t: float) -> tuple[str, str]:
        """(mac, status) status: mapped | ambiguous | unmapped."""
        macs = {m for lo, hi, m in self.by_ip.get(str(ip).strip(), ()) if lo - self.tol <= t <= hi + self.tol}
        if len(macs) == 1:
            return next(iter(macs)), "mapped"
        return ("", "ambiguous") if macs else ("", "unmapped")


class Router:
    def __init__(self, cfg: dict):
        ro = cfg["routing"]
        self.cfg = ro
        self.owner_roles = {r.lower() for r in ro["owner_roles"]}
        self.fallback = ro["fallback_group"]
        self.unknown = ro["unknown_device"]
        self.labels = set(json.loads((REPO_ROOT / ro["groups"]).read_text(encoding="utf-8"))["labels"])
        if self.fallback not in self.labels:
            raise ValueError(f"fallback group {self.fallback!r} is not a label of {ro['groups']}")
        self.inv: dict = {}
        with open(REPO_ROOT / ro["inventory"], newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                mac = norm_mac(r[ro["mac_column"]])
                if mac in self.inv:
                    raise ValueError(f"duplicate MAC {mac} in {ro['inventory']}")
                self.inv[mac] = (r[ro["name_column"]].strip(), r[ro["role_column"]].strip().lower(),
                                 r[ro["group_column"]].strip())
        self.ipmap = IpMacMap(REPO_ROOT / ro["ip_mac_map"], ro["ip_map_tolerance_s"])
        self._cache: dict = {}
        self.stats = defaultdict(int)

    def role(self, mac: str) -> str:
        if not mac:
            return "none"
        e = self.inv.get(mac)
        if e is not None:
            return e[1]
        return "unlisted" if is_unicast_mac(mac) else "non_unicast"

    def _group_of(self, mac: str) -> str:
        e = self.inv.get(mac)
        g = e[2] if e else ""
        return g if g in self.labels else self.fallback

    def macs_of(self, row: dict) -> tuple[str, str]:
        if "src_mac" in row or "dst_mac" in row:
            return norm_mac(row.get("src_mac")), norm_mac(row.get("dst_mac"))
        t = float(row["_meta"]["start_ts"])
        s, ss = self.ipmap.resolve(row["Src IP"], t)
        d, ds = self.ipmap.resolve(row["Dst IP"], t)
        self.stats[f"ipmap_src_{ss}"] += 1
        self.stats[f"ipmap_dst_{ds}"] += 1
        return s, d

    def route_macs(self, smac: str, dmac: str) -> Route:
        k = (smac, dmac)
        r = self._cache.get(k)
        if r is not None:
            return r
        so, do = self.role(smac) in self.owner_roles, self.role(dmac) in self.owner_roles
        if so or do:
            mac, side = (smac, "src") if so else (dmac, "dst")
            rule = "device_device_initiator" if (so and do) else "device_side"
            r = Route(mac, self.inv[mac][0], self._group_of(mac), rule, side)
        elif self.role(smac) == "unlisted" or self.role(dmac) == "unlisted":
            mac, side = (smac, "src") if self.role(smac) == "unlisted" else (dmac, "dst")
            r = Route(mac, mac, self.fallback, "unregistered_mac", side)
        else:
            r = Route("", self.unknown, self.fallback, "no_device", "")
        self._cache[k] = r
        return r

    def route(self, row: dict) -> Route:
        r = self.route_macs(*self.macs_of(row))
        self.stats[r.rule] += 1
        return r

    def protected_for_dst_mac(self, mac: str):
        """Rate guard: the protected device a packet to `mac` is counted for, or None (not counted)."""
        mac = norm_mac(mac)
        role = self.role(mac)
        if role in self.owner_roles:
            return mac, self.inv[mac][0], self._group_of(mac)
        if role == "unlisted":
            return mac, mac, self.fallback
        return None

    def groups(self) -> list[str]:
        return sorted(self.labels)

    def device_name(self, mac: str) -> str:
        e = self.inv.get(norm_mac(mac))
        return e[0] if e else (mac or self.unknown)
