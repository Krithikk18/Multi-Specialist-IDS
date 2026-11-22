"""common/mac_learner.py -- passive IP -> MAC learning for runtime routing (Phase 3.1 part B).

    L = MacLearner(gateway_distinct_ip_threshold=8, gateway_window_s=300, flap_count=3, flap_window_s=60)
    L.observe(pkt)                 # pkt = (ts, src_ip, dst_ip, proto, src_mac, dst_mac); proto == ARP_PROTO -> ARP
    mac = L.resolve(ip)            # "" when nothing is bound (the router's unknown rule then applies)
    for ev in L.drain_events(): ...   # {"kind": "ip_mac_change" | "ip_mac_flap" | "gateway_detected", ...}

Rules (fixed by the Phase 3.1 prompt; choices beyond it are in docs/V2_DECISIONS.md):
  binding     every IPv4 frame binds its source IP to its Ethernet source MAC; an ARP frame binds its sender IP to
              its sender MAC; ARP wins on conflict (an IPv4 frame never replaces an ARP binding; an ARP frame replaces
              an IPv4 binding). Frames with a non-unicast source MAC, an empty MAC or the unspecified source address
              are ignored.
  gateway     a MAC seen with more than gateway_distinct_ip_threshold distinct IPv4 source IPs within gateway_window_s
              is a gateway / router (sticky); IPv4-frame bindings to it are dropped and no IPv4 frame from it binds
              again (the IPs behind it are remote hosts); ARP bindings to it (its own address) are kept.
  causality   the learner only knows the frames observed so far: the runtime feeds packets in event time up to a
              flow's emission time before routing that flow (no lookahead).
  changes     a binding moving to another MAC emits ip_mac_change (ip, old MAC, new MAC, time); >= flap_count changes
              of one IP within flap_window_s emit ip_mac_flap (once per IP per flap_window_s). Health events only,
              never an alert class.
Phase 3.2 (only when gateway_warmup_s is set, i.e. routing.mac_learner.gateway_warmup_s in config/v2_phase3_2.json;
absent = Phase 3.1 behaviour, no new event):
  unexpected  a MAC that becomes a gateway at event time t >= (first frame the learner saw) + gateway_warmup_s and
  gateway     whose inventory role is not one of inventory_gateway_roles emits unexpected_gateway ONCE (gateway status
              is sticky): mac, distinct_source_ips (in the window at detection), first_time / last_time (oldest frame of
              that window / detection time), mac_first_seen, in_inventory, inventory_role. Health event only, never
              an alert class; routing is unchanged (the gateway rule itself is the Phase 3.1 one).
  inventory   {mac: role}: from_config reads routing.inventory (mac_column / role_column, repo-relative) when the
              warm-up is set; set_inventory() replaces it (tests / callers holding the table already).
Standard library only; memory = bindings + the per-MAC window of recent (time, source IP) pairs + first-seen per MAC.
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict, deque
from pathlib import Path

ARP_PROTO = -1                     # common/packet_source yields ARP frames with this protocol marker when asked
UNSPECIFIED_IP = "0.0.0.0"         # IPv4's "no address yet" source (DHCP discover); structural, not a site address
_REPO = Path(__file__).resolve().parents[1]


def _unicast(mac: str) -> bool:
    try:
        return len(mac) == 17 and (int(mac[:2], 16) & 1) == 0
    except ValueError:
        return False


class MacLearner:
    def __init__(self, gateway_distinct_ip_threshold: int = 8, gateway_window_s: float = 300.0, flap_count: int = 3,
                 flap_window_s: float = 60.0, gateway_warmup_s: float | None = None,
                 inventory_gateway_roles=("gateway", "router"), inventory: dict | None = None):
        self.gw_n, self.gw_w = int(gateway_distinct_ip_threshold), float(gateway_window_s)
        self.flap_n, self.flap_w = int(flap_count), float(flap_window_s)
        self.warmup = None if gateway_warmup_s is None else float(gateway_warmup_s)
        self.gw_roles = {str(r).strip().lower() for r in inventory_gateway_roles}
        self.inventory: dict = {}
        self.set_inventory(inventory or {})
        self.t_first = None                       # event time of the first frame observed (warm-up origin)
        self.first_seen: dict = {}                # mac -> first frame time (only kept when the warm-up is set)
        self.bind: dict = {}                      # ip -> [mac, source ("arp" | "ip"), time bound / refreshed]
        self._win: dict = defaultdict(deque)      # mac -> deque[(t, ip)] within gateway_window_s
        self._cnt: dict = defaultdict(Counter)    # mac -> Counter(ip) of that window
        self.gateways: dict = {}                  # mac -> time detected
        self._chg: dict = defaultdict(deque)      # ip -> deque[change times]
        self._flap_quiet: dict = {}               # ip -> time until which no new flap event
        self.events: list = []
        self.stats = Counter()

    @classmethod
    def from_config(cls, ro: dict) -> "MacLearner":
        ml = ro.get("mac_learner") or {}
        kw = {k: ml[k] for k in ("gateway_distinct_ip_threshold", "gateway_window_s", "flap_count", "flap_window_s",
                                 "gateway_warmup_s", "inventory_gateway_roles") if k in ml}
        if kw.get("gateway_warmup_s") is not None and ro.get("inventory"):
            kw["inventory"] = read_inventory_roles(_REPO / ro["inventory"], ro.get("mac_column", "mac"),
                                                   ro.get("role_column", "role"))
        return cls(**kw)

    def set_inventory(self, roles: dict) -> None:
        """{mac: inventory role}; MACs lower-cased, roles lower-cased."""
        self.inventory = {str(m).strip().lower(): str(r).strip().lower() for m, r in roles.items()}

    # ---------------------------------------------------------------- input
    def observe(self, pkt) -> None:
        t, sip, _dip, proto, smac = pkt[0], pkt[1], pkt[2], pkt[3], pkt[4]
        smac = str(smac or "").lower()
        if self.warmup is not None:
            if self.t_first is None:
                self.t_first = t
            if smac not in self.first_seen:
                self.first_seen[smac] = t
        if proto == ARP_PROTO:
            self.stats["arp_frames"] += 1
            self.observe_arp(t, sip, smac)
        else:
            self.stats["ip_frames"] += 1
            self.observe_ip(t, sip, smac)

    def observe_arp(self, t: float, sender_ip: str, sender_mac: str) -> None:
        if not _unicast(sender_mac) or not sender_ip or sender_ip == UNSPECIFIED_IP:
            self.stats["ignored_arp"] += 1
            return
        self._bind(t, sender_ip, sender_mac, "arp")

    def observe_ip(self, t: float, src_ip: str, src_mac: str) -> None:
        if not _unicast(src_mac) or not src_ip or src_ip == UNSPECIFIED_IP:
            self.stats["ignored_ip"] += 1
            return
        self._gateway_window(t, src_ip, src_mac)
        if src_mac in self.gateways:
            self.stats["behind_gateway"] += 1
            return
        self._bind(t, src_ip, src_mac, "ip")

    # ---------------------------------------------------------------- rules
    def _gateway_window(self, t: float, ip: str, mac: str) -> None:
        dq, cn = self._win[mac], self._cnt[mac]
        dq.append((t, ip))
        cn[ip] += 1
        while dq and dq[0][0] < t - self.gw_w:
            _, old = dq.popleft()
            cn[old] -= 1
            if cn[old] <= 0:
                del cn[old]
        if mac not in self.gateways and len(cn) > self.gw_n:
            self.gateways[mac] = t
            dropped = [ip_ for ip_, b in self.bind.items() if b[0] == mac and b[1] == "ip"]
            for ip_ in dropped:
                del self.bind[ip_]
            self.stats["gateways"] += 1
            self.events.append({"kind": "gateway_detected", "mac": mac, "event_time": t, "distinct_ips": len(cn),
                                "window_s": self.gw_w, "bindings_dropped": len(dropped)})
            self._maybe_unexpected(t, mac, dq, cn)
        if mac in self.gateways:                                       # keep the window bounded for known gateways
            dq.clear()
            cn.clear()

    def _maybe_unexpected(self, t: float, mac: str, dq: deque, cn: Counter) -> None:
        """Phase 3.2 health event: a new gateway after the warm-up that the inventory does not list as one."""
        if self.warmup is None or self.t_first is None:
            return
        role = self.inventory.get(mac, "")
        if t < self.t_first + self.warmup:
            self.stats["gateway_in_warmup"] += 1
            return
        if role in self.gw_roles:
            self.stats["gateway_inventory_exempt"] += 1
            return
        self.stats["unexpected_gateway"] += 1
        self.events.append({"kind": "unexpected_gateway", "mac": mac, "event_time": t, "distinct_source_ips": len(cn),
                            "first_time": dq[0][0] if dq else t, "last_time": t,
                            "mac_first_seen": self.first_seen.get(mac, t), "in_inventory": mac in self.inventory,
                            "inventory_role": role, "warmup_s": self.warmup, "window_s": self.gw_w})

    def _bind(self, t: float, ip: str, mac: str, src: str) -> None:
        cur = self.bind.get(ip)
        if cur is None:
            self.bind[ip] = [mac, src, t]
            self.stats[f"bound_{src}"] += 1
            return
        if cur[0] == mac:
            cur[2] = t
            if src == "arp":
                cur[1] = "arp"
            return
        if src == "ip" and cur[1] == "arp":
            self.stats["arp_kept_over_ip"] += 1
            return
        old = cur[0]
        self.bind[ip] = [mac, src, t]
        self.stats["ip_mac_change"] += 1
        self.events.append({"kind": "ip_mac_change", "ip": ip, "old_mac": old, "new_mac": mac, "event_time": t,
                            "source": src})
        dq = self._chg[ip]
        dq.append(t)
        while dq and dq[0] < t - self.flap_w:
            dq.popleft()
        if len(dq) >= self.flap_n and t >= self._flap_quiet.get(ip, float("-inf")):
            self._flap_quiet[ip] = t + self.flap_w
            self.stats["ip_mac_flap"] += 1
            self.events.append({"kind": "ip_mac_flap", "ip": ip, "changes": len(dq), "window_s": self.flap_w,
                                "macs_now": mac, "event_time": t})

    # ---------------------------------------------------------------- output
    def resolve(self, ip) -> str:
        b = self.bind.get(str(ip).strip())
        return b[0] if b is not None else ""

    def drain_events(self) -> list:
        ev, self.events = self.events, []
        return ev

    def describe(self) -> dict:
        d = {"bindings": len(self.bind), "bindings_arp": sum(1 for b in self.bind.values() if b[1] == "arp"),
             "gateways": dict(self.gateways), "stats": dict(self.stats),
             "params": {"gateway_distinct_ip_threshold": self.gw_n, "gateway_window_s": self.gw_w,
                        "flap_count": self.flap_n, "flap_window_s": self.flap_w}}
        if self.warmup is not None:                                    # Phase 3.2 keys only when configured
            d["params"].update({"gateway_warmup_s": self.warmup, "inventory_gateway_roles": sorted(self.gw_roles),
                                "inventory_macs": len(self.inventory)})
            d["t_first"] = self.t_first
        return d


def read_inventory_roles(path: Path, mac_column: str = "mac", role_column: str = "role") -> dict:
    """{mac (lower): role (lower)} from the inventory CSV."""
    with open(path, newline="", encoding="utf-8") as fh:
        return {str(r[mac_column]).strip().lower(): str(r[role_column]).strip().lower() for r in csv.DictReader(fh)}
