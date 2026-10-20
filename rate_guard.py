#!/usr/bin/env python
"""rate_guard.py -- packet-level rate guard for non-TCP/UDP IPv4 traffic, next to the flow-based ML.

Why: CICFlowMeter reads every non-TCP/UDP packet as "Protocol 0" with 40/70 features zero, so a GRE flood
(IP proto 47) is invisible to the frozen Step 10 models (12b / 12c: 0/52 flood flows flagged). Benign non-TCP/UDP
is small (~1.4 % of benign flows, ~98 % ICMP + ~2 % IGMP, low volume), so a plain packet-rate rule on it is cheap.

Core logic only: no I/O, no capture, no calibration. Python standard library only, streaming (one packet per
update() call), memory O(active keys of the open window). Meant to run live on a Raspberry Pi later.

Semantics
  scope      packets with proto in {6, 17} (TCP / UDP) are ignored: counted in stats only, they do not move the
             window clock. Everything else is in scope. The caller feeds IPv4 only (outer ip.proto); IPv6 is out
             of scope here (58 = ICMPv6 has a name only for readability).
  keys       "stream" = (src_ip, dst_ip, proto), "victim" = (dst_ip, proto); each level can be disabled.
  windows    tumbling, length window_s, window index k = floor(ts / window_s), start k * window_s,
             end (k + 1) * window_s. One window is open at a time. A packet in a later window closes the open
             one first (empty windows in between emit nothing). flush() closes the open window at end of input.
  late       an in-scope packet older than the open window (or, after a close / flush, in a window that was
             already closed) is counted in late_packets and dropped; closed windows are never reopened.
             Packets out of order inside the open window are accepted.
  alerting   per level a threshold in packets per window (int) or None = no alerts for that level, optionally
             overridden per proto ({proto: int | None}). Alert iff packets > threshold (strictly greater).
  counts     record_counts=True keeps one WindowCount per key and closed window (also below threshold), for
             calibrating benign rates; drain them with pop_counts().
  order      per closed window: stream records sorted by (src_ip, dst_ip, proto), then victim records sorted by
             (dst_ip, proto); windows in ascending order. IPs sort as strings.

Usage
  guard = RateGuard(stream_threshold=500, victim_threshold=1000)
  for ts, src, dst, proto, smac, dmac in packets:
      for alert in guard.update(ts, src, dst, proto, smac, dmac):
          ...
  alerts = guard.flush()
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = ["Alert", "WindowCount", "RateGuard", "proto_name", "PROTO_NAMES", "STREAM", "VICTIM"]

STREAM, VICTIM = "stream", "victim"
PROTO_NAMES = {1: "ICMP", 2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6"}
TCP_UDP = frozenset((6, 17))
MAX_SAMPLE_MACS = 5


def proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, str(proto))


@dataclass(frozen=True)
class Alert:
    window_start: float
    window_end: float
    level: str                  # STREAM or VICTIM
    src_ip: str | None          # None at victim level
    dst_ip: str
    proto: int
    proto_name: str
    packets: int
    rate_pps: float             # packets / window_s
    threshold: int
    first_seen_ts: float
    last_seen_ts: float
    src_macs: tuple[str, ...]   # victim level: up to 5 distinct sender MACs (first seen, sorted); stream: ()


@dataclass(frozen=True)
class WindowCount:
    window_start: float
    window_end: float
    level: str
    src_ip: str | None
    dst_ip: str
    proto: int
    proto_name: str
    packets: int
    rate_pps: float
    first_seen_ts: float
    last_seen_ts: float


def _check_threshold(name: str, value: object) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative int or None, got {value!r}")


class RateGuard:
    """Streaming tumbling-window packet counter with per-level thresholds (see module docstring)."""

    def __init__(
        self,
        window_s: float = 10.0,
        stream_threshold: int | None = None,
        victim_threshold: int | None = None,
        stream_proto_thresholds: dict[int, int | None] | None = None,
        victim_proto_thresholds: dict[int, int | None] | None = None,
        enable_stream: bool = True,
        enable_victim: bool = True,
        record_counts: bool = False,
    ) -> None:
        if isinstance(window_s, bool) or not isinstance(window_s, (int, float)) \
                or not math.isfinite(window_s) or window_s <= 0:
            raise ValueError(f"window_s must be a finite number > 0, got {window_s!r}")
        if not (enable_stream or enable_victim):
            raise ValueError("at least one of enable_stream / enable_victim must be True")
        _check_threshold("stream_threshold", stream_threshold)
        _check_threshold("victim_threshold", victim_threshold)
        for name, overrides in (("stream_proto_thresholds", stream_proto_thresholds),
                                ("victim_proto_thresholds", victim_proto_thresholds)):
            for p, t in (overrides or {}).items():
                if isinstance(p, bool) or not isinstance(p, int):
                    raise ValueError(f"{name} keys must be int protocol numbers, got {p!r}")
                _check_threshold(f"{name}[{p}]", t)

        self.window_s = float(window_s)
        self.enable_stream = enable_stream
        self.enable_victim = enable_victim
        self.record_counts = record_counts
        self._default = {STREAM: stream_threshold, VICTIM: victim_threshold}
        self._overrides = {STREAM: dict(stream_proto_thresholds or {}),
                           VICTIM: dict(victim_proto_thresholds or {})}

        # open window: index k (None = no window open) and per-key state [packets, first_ts, last_ts, macs]
        self._win: int | None = None
        self._next_win: int | None = None     # smallest window index still accepted after a close
        self._streams: dict[tuple[str, str, int], list] = {}
        self._victims: dict[tuple[str, int], list] = {}
        self._counts: list[WindowCount] = []

        self._packets_seen = 0
        self._packets_in_scope = 0
        self._packets_ignored_tcp_udp = 0
        self._late_packets = 0
        self._windows_closed = 0
        self._alerts = 0
        self._max_active_keys = 0

    def threshold_for(self, level: str, proto: int) -> int | None:
        overrides = self._overrides[level]
        return overrides[proto] if proto in overrides else self._default[level]

    def update(self, ts: float, src_ip: str, dst_ip: str, proto: int,
               src_mac: str | None = None, dst_mac: str | None = None) -> list[Alert]:
        """Feed one IPv4 packet; returns the alerts of any window this packet closes. dst_mac is accepted for
        interface stability and not used."""
        self._packets_seen += 1
        if proto in TCP_UDP:
            self._packets_ignored_tcp_udp += 1
            return []
        self._packets_in_scope += 1

        k = math.floor(ts / self.window_s)
        out: list[Alert] = []
        if self._win is None:
            if self._next_win is not None and k < self._next_win:
                self._late_packets += 1
                return out
            self._win = k
        elif k < self._win:
            self._late_packets += 1
            return out
        elif k > self._win:
            out = self._close()
            self._win = k

        new_keys = 0
        if self.enable_stream:
            key = (src_ip, dst_ip, proto)
            st = self._streams.get(key)
            if st is None:
                self._streams[key] = [1, ts, ts, None]
                new_keys += 1
            else:
                st[0] += 1
                if ts < st[1]:
                    st[1] = ts
                elif ts > st[2]:
                    st[2] = ts
        if self.enable_victim:
            vkey = (dst_ip, proto)
            st = self._victims.get(vkey)
            if st is None:
                self._victims[vkey] = [1, ts, ts, [src_mac] if src_mac is not None else []]
                new_keys += 1
            else:
                st[0] += 1
                if ts < st[1]:
                    st[1] = ts
                elif ts > st[2]:
                    st[2] = ts
                macs = st[3]
                if src_mac is not None and len(macs) < MAX_SAMPLE_MACS and src_mac not in macs:
                    macs.append(src_mac)
        if new_keys:
            active = len(self._streams) + len(self._victims)
            if active > self._max_active_keys:
                self._max_active_keys = active
        return out

    def flush(self) -> list[Alert]:
        """Close the open window (end of input); returns its alerts. Later packets in that window count as late."""
        return self._close() if self._win is not None else []

    def pop_counts(self) -> list[WindowCount]:
        """Return and clear the WindowCount records of the windows closed so far (record_counts=True only)."""
        counts, self._counts = self._counts, []
        return counts

    def stats(self) -> dict[str, int]:
        return {
            "packets_seen": self._packets_seen,
            "packets_in_scope": self._packets_in_scope,      # includes late_packets
            "packets_ignored_tcp_udp": self._packets_ignored_tcp_udp,
            "late_packets": self._late_packets,
            "windows_closed": self._windows_closed,
            "alerts": self._alerts,
            "max_active_keys": self._max_active_keys,
        }

    @property
    def active_keys(self) -> int:
        return len(self._streams) + len(self._victims)

    def _close(self) -> list[Alert]:
        k = self._win
        start, end = k * self.window_s, (k + 1) * self.window_s
        alerts: list[Alert] = []
        for (src, dst, proto), (n, first, last, _) in sorted(self._streams.items()):
            self._emit(alerts, STREAM, start, end, src, dst, proto, n, first, last, ())
        for (dst, proto), (n, first, last, macs) in sorted(self._victims.items()):
            self._emit(alerts, VICTIM, start, end, None, dst, proto, n, first, last, tuple(sorted(macs)))
        self._streams = {}
        self._victims = {}
        self._win = None
        self._next_win = k + 1
        self._windows_closed += 1
        self._alerts += len(alerts)
        return alerts

    def _emit(self, alerts: list[Alert], level: str, start: float, end: float, src: str | None, dst: str,
              proto: int, n: int, first: float, last: float, macs: tuple[str, ...]) -> None:
        name, rate = proto_name(proto), n / self.window_s
        if self.record_counts:
            self._counts.append(WindowCount(start, end, level, src, dst, proto, name, n, rate, first, last))
        threshold = self.threshold_for(level, proto)
        if threshold is not None and n > threshold:
            alerts.append(Alert(start, end, level, src, dst, proto, name, n, rate, threshold, first, last, macs))
