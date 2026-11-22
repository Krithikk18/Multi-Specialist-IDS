"""common/rate_guard_v2.py -- packet rate guard v2 (docs/V2_PREREG_PHASE3.md section 6) + V1's rule, unchanged.

    rg = RateGuardV2(router, thresholds, families, other, window_s=1, consecutive=3)
    for pkt in packets: alerts += rg.update(*pkt)           # pkt = (ts, src_ip, dst_ip, proto, src_mac, dst_mac)
    alerts += rg.flush()
    v1 = V1Guard(cfg)                                       # V1 rate_guard.RateGuard(**config/rate_guard_v1.json args)

v2: tumbling windows of window_s (index floor(ts / window_s)); a packet is counted for the protected device of its
destination MAC (router.protected_for_dst_mac: owner-role inventory devices -> their group, unlisted unicast MACs ->
the fallback group, everything else not counted) and its protocol family (families {name: [proto, ...]}, else
`other`). When a window closes: per (device, family) seen with a running streak or a packet in it, above = count >
threshold[group][family]; the streak grows or resets; streak >= consecutive -> one alert per window (event time =
window end). A jump over empty windows resets every streak. Packets of an already-closed window are counted as late
and dropped (V1's rule). Standard library only; memory = keys of the open window + running streaks.
record=True keeps (window_start, device, group, family, count) for every non-empty key x window (27's fit).

V1: rate_guard.py is imported read-only and run with the frozen config/rate_guard_v1.json (proto keys -> int, as its
loader note says); its alerts are passed through unchanged; the runtime maps an alert's dst IP to a protected device
from the packets it has seen (dst IP -> protected dst MAC).
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass

from config.config import REPO_ROOT


@dataclass(frozen=True)
class RGAlert:
    t: float                 # window end (decision time)
    window_start: float
    device: str
    group: str
    family: str
    count: int
    threshold: int
    streak: int
    rule: str = "v2"


class RateGuardV2:
    def __init__(self, router, thresholds: dict, families: dict, other: str, window_s: float = 1.0,
                 consecutive: int = 3, record: bool = False, fallback_group: str | None = None):
        self.router, self.w, self.k = router, float(window_s), int(consecutive)
        self.thr = {g: {f: int(v) for f, v in d.items()} for g, d in thresholds.items()}
        self.fallback = fallback_group
        self.fam = {int(p): name for name, ps in families.items() for p in ps}
        self.other = other
        self.record = record
        self.records: list = []
        self._win = None
        self._counts: dict = defaultdict(int)
        self._streak: dict = {}
        self._dev: dict = {}                 # dst mac -> (device, group) or None (cache)
        self.ip_device: dict = {}            # dst ip -> device mac (learned from packets; maps V1 alerts)
        self.stats = defaultdict(int)

    def threshold(self, group: str, family: str) -> int:
        g = self.thr.get(group)
        if g is None or family not in g:
            g = self.thr.get(self.fallback, {})
        if family not in g:
            raise KeyError(f"no threshold for ({group}, {family}) and none for the fallback group")
        return g[family]

    def _protected(self, mac: str):
        if mac not in self._dev:
            p = self.router.protected_for_dst_mac(mac)
            self._dev[mac] = None if p is None else (p[0], p[2])
        return self._dev[mac]

    def update(self, ts: float, src_ip: str, dst_ip: str, proto: int, src_mac: str = "", dst_mac: str = "") -> list:
        self.stats["packets"] += 1
        k = math.floor(ts / self.w)
        out = []
        if self._win is not None and k != self._win:
            if k < self._win:
                self.stats["late"] += 1
                return out
            out = self._close(k)
        if self._win is None:
            self._win = k
        p = self._protected(dst_mac)
        if p is None:
            self.stats["not_protected"] += 1
            return out
        self.ip_device[dst_ip] = p[0]
        self._counts[(p[0], p[1], self.fam.get(proto, self.other))] += 1
        self.stats["counted"] += 1
        return out

    def advance(self, now: float) -> list:
        k = math.floor(now / self.w)
        return self._close(k) if self._win is not None and k > self._win else []

    def flush(self) -> list:
        return self._close(None) if self._win is not None else []

    def _close(self, next_k) -> list:
        k, start = self._win, self._win * self.w
        end = start + self.w
        alerts = []
        keys = set(self._counts) | set(self._streak)
        for key in sorted(keys):
            dev, grp, fam = key
            n = self._counts.get(key, 0)
            if self.record and n:
                self.records.append((start, dev, grp, fam, n))
            thr = self.threshold(grp, fam)
            s = self._streak.get(key, 0) + 1 if n > thr else 0
            if s:
                self._streak[key] = s
            else:
                self._streak.pop(key, None)
            if s >= self.k:
                alerts.append(RGAlert(end, start, dev, grp, fam, n, thr, s))
        self._counts = defaultdict(int)
        self.stats["windows_closed"] += 1
        self.stats["alerts"] += len(alerts)
        if next_k is None or next_k > k + 1:
            self._streak = {}
        self._win = next_k
        return alerts


def load_v1_args(path) -> dict:
    a = json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))["args"]
    a = dict(a)
    for k in ("stream_proto_thresholds", "victim_proto_thresholds"):
        if a.get(k) is not None:
            a[k] = {int(p): v for p, v in a[k].items()}
    return a


class V1Guard:
    """V1 rate_guard.RateGuard with the frozen config, imported read-only; alerts passed through unchanged."""

    def __init__(self, cfg: dict):
        import rate_guard as V1                                       # repo-root V1 module (never edited)
        self.V1 = V1
        self.args = load_v1_args(cfg["rate_guard"]["v1_config"])
        self.g = V1.RateGuard(**self.args)

    def update(self, ts, src_ip, dst_ip, proto, src_mac=None, dst_mac=None) -> list:
        return self.g.update(ts, src_ip, dst_ip, proto, src_mac, dst_mac)

    def advance(self, now: float) -> list:
        return self.g.advance(now)

    def flush(self) -> list:
        return self.g.flush()

    def stats(self) -> dict:
        return self.g.stats()


def load_thresholds(cfg: dict) -> tuple[dict, dict]:
    """thresholds.json from 27's fit dir, sha256 == its manifest record (fail closed). Returns (thresholds, manifest)."""
    import hashlib
    from common.phase3_config import expand
    d = expand(cfg["rate_guard"]["fit_dir"])
    tp, mp = d / "thresholds.json", d / "manifest.json"
    if not tp.is_file() or not mp.is_file():
        raise FileNotFoundError(f"rate guard v2 thresholds / manifest missing in {d} (run 27_fit_rate_guard.py)")
    M = json.loads(mp.read_text(encoding="utf-8"))
    got = hashlib.sha256(tp.read_bytes()).hexdigest()
    if got != M.get("thresholds_sha256") or M.get("status") != "PASS":
        raise RuntimeError(f"{tp}: sha256 {got} != manifest {M.get('thresholds_sha256')} or manifest not PASS")
    rg = cfg["rate_guard"]
    T = json.loads(tp.read_text(encoding="utf-8"))
    for k, want in (("window_s", rg["window_s"]), ("multiplier", rg["multiplier"]), ("consecutive", rg["consecutive"]),
                    ("families", rg["families"]), ("other_family", rg["other_family"])):
        if T["rule"].get(k) != want:
            raise RuntimeError(f"{tp}: rule.{k} {T['rule'].get(k)} != config {want}")
    return T, M
