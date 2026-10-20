"""tests/test_rate_guard.py -- unit tests for rate_guard.py (synthetic packets only, no data / pcaps).

Plain asserts, no pytest fixtures or imports, so the file also runs without pytest.
Usage (repo root): python -m pytest -q -s tests/test_rate_guard.py
"""

from __future__ import annotations

import random
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rate_guard import STREAM, VICTIM, Alert, RateGuard, WindowCount, proto_name  # noqa: E402

GRE, ICMP, IGMP, TCP, UDP = 47, 1, 2, 6, 17
T0 = 1665163800.0          # multiple of 10 s


def _feed(guard: RateGuard, packets) -> list[Alert]:
    out: list[Alert] = []
    for p in packets:
        out.extend(guard.update(*p))
    return out


def _raises(fn, exc=ValueError) -> bool:
    try:
        fn()
    except exc:
        return True
    return False


def test_window_alignment_and_closing_order():
    g = RateGuard(window_s=10.0, stream_threshold=0, victim_threshold=0)
    assert g.update(1005.3, "10.0.0.1", "10.0.0.9", GRE) == []        # window [1000, 1010) opens
    assert g.update(1009.999, "10.0.0.1", "10.0.0.9", GRE) == []      # same window
    a = g.update(1010.0, "10.0.0.1", "10.0.0.9", GRE)                 # boundary belongs to the next window
    assert [(x.level, x.window_start, x.window_end, x.packets) for x in a] == \
        [(STREAM, 1000.0, 1010.0, 2), (VICTIM, 1000.0, 1010.0, 2)]
    assert a[0].first_seen_ts == 1005.3 and a[0].last_seen_ts == 1009.999
    assert a[0].rate_pps == 0.2 and a[0].proto_name == "GRE"
    # gap: window 1010 closes when a packet of window 1040 arrives; 1020 / 1030 emit nothing
    a = g.update(1047.0, "10.0.0.1", "10.0.0.9", GRE)
    assert {x.window_start for x in a} == {1010.0}
    a = g.flush()
    assert {x.window_start for x in a} == {1040.0}
    assert g.stats()["windows_closed"] == 3
    # non-integer window length, small epoch
    g = RateGuard(window_s=2.5, victim_threshold=0, enable_stream=False)
    g.update(7.4, "a", "b", ICMP)
    a = g.flush()
    assert (a[0].window_start, a[0].window_end) == (5.0, 7.5)


def test_flush():
    g = RateGuard(stream_threshold=1)
    for i in range(3):
        g.update(T0 + i, "1.1.1.1", "2.2.2.2", GRE)
    a = g.flush()
    assert len(a) == 1 and a[0].level == STREAM and a[0].packets == 3
    assert g.flush() == []                                 # nothing open any more
    assert g.active_keys == 0
    assert g.update(T0 + 5, "1.1.1.1", "2.2.2.2", GRE) == []   # flushed window is closed: late
    assert g.stats()["late_packets"] == 1
    g.update(T0 + 10, "1.1.1.1", "2.2.2.2", GRE)           # next window is accepted
    assert g.stats()["late_packets"] == 1 and g.active_keys == 2


def test_threshold_boundary():
    for n, expect in ((5, 0), (6, 1)):
        g = RateGuard(stream_threshold=5, victim_threshold=5)
        _feed(g, [(T0 + i * 0.1, "1.1.1.1", "2.2.2.2", GRE) for i in range(n)])
        a = g.flush()
        assert len([x for x in a if x.level == STREAM]) == expect
        assert len([x for x in a if x.level == VICTIM]) == expect
        if expect:
            assert a[0].packets == 6 and a[0].threshold == 5
    g = RateGuard(stream_threshold=0)                      # 0 means any packet alerts
    g.update(T0, "1.1.1.1", "2.2.2.2", ICMP)
    assert len(g.flush()) == 1


def test_stream_vs_victim_aggregation():
    g = RateGuard(stream_threshold=5, victim_threshold=15)
    pkts = []
    for i in range(7):                                     # 7 sources x 3 packets -> one victim
        for j in range(3):
            pkts.append((T0 + i + j * 0.01, f"10.0.0.{i + 1}", "192.168.1.50", GRE,
                         f"aa:00:00:00:00:{i + 1:02x}", "bb:00:00:00:00:01"))
    assert _feed(g, pkts) == []
    a = g.flush()
    assert len(a) == 1
    v = a[0]
    assert v.level == VICTIM and v.src_ip is None and v.dst_ip == "192.168.1.50"
    assert v.packets == 21 and v.threshold == 15
    assert v.src_macs == tuple(f"aa:00:00:00:00:{i:02x}" for i in range(1, 6))    # first 5 distinct, sorted
    assert g.stats()["max_active_keys"] == 8               # 7 streams + 1 victim
    # victim MACs: duplicates and None are not sampled
    g = RateGuard(victim_threshold=0, enable_stream=False)
    for m in ("cc", None, "cc", "aa"):
        g.update(T0, "1.1.1.1", "2.2.2.2", GRE, m)
    assert g.flush()[0].src_macs == ("aa", "cc")


def test_tcp_udp_ignored():
    g = RateGuard(stream_threshold=0, victim_threshold=0, record_counts=True)
    for i in range(100):
        assert g.update(T0 + i, "1.1.1.1", "2.2.2.2", TCP if i % 2 else UDP) == []
    assert g.flush() == [] and g.pop_counts() == []
    s = g.stats()
    assert s["packets_seen"] == 100 and s["packets_ignored_tcp_udp"] == 100
    assert s["packets_in_scope"] == 0 and s["windows_closed"] == 0 and s["max_active_keys"] == 0
    # TCP / UDP are a clock tick: a later TCP packet closes the GRE window, an older GRE packet after it is late
    g = RateGuard(stream_threshold=0)
    g.update(T0, "1.1.1.1", "2.2.2.2", GRE)
    a = g.update(T0 + 100, "1.1.1.1", "2.2.2.2", TCP)
    assert [(x.window_start, x.packets) for x in a] == [(T0, 1)]
    assert g.update(T0 + 1, "1.1.1.1", "2.2.2.2", GRE) == []
    assert g.flush() == [] and g.stats()["late_packets"] == 1
    # an older TCP / UDP tick is a no-op
    g = RateGuard(stream_threshold=0)
    g.update(T0 + 15, "1.1.1.1", "2.2.2.2", GRE)
    assert g.update(T0 + 2, "1.1.1.1", "2.2.2.2", UDP) == [] and g.active_keys == 2    # stream + victim


def _flood(g: RateGuard, n: int = 1000, t0: float = T0, span: float = 5.0) -> None:
    for i in range(n):
        assert g.update(t0 + i * span / n, f"203.0.113.{i % 7 + 1}", "192.168.137.10", GRE) == []


def test_advance_quiet_line():
    g = RateGuard(stream_threshold=100, victim_threshold=500, record_counts=True)
    assert g.advance(T0) == []                             # nothing open: no-op
    _flood(g)                                              # 1,000 GRE packets in [T0, T0 + 5), then silence
    assert g.advance(T0 + 9.999) == []                     # window [T0, T0 + 10) not ended yet
    assert g.active_keys == 8
    a = g.advance(T0 + 10.0)                               # window_end <= now: closes without flush()
    assert [(x.level, x.window_start, x.packets) for x in a] == \
        [(STREAM, T0, n) for n in (143, 143, 143, 143, 143, 143, 142)] + [(VICTIM, T0, 1000)]
    assert len(g.pop_counts()) == 8
    assert g.flush() == [] and g.active_keys == 0
    s = g.stats()
    assert s["packets_seen"] == 1000 and s["packets_in_scope"] == 1000 and s["windows_closed"] == 1
    assert s["alerts"] == 8 and s["late_packets"] == 0
    # far ahead: still exactly one close, empty windows emit nothing
    g = RateGuard(victim_threshold=0, enable_stream=False)
    g.update(T0, "1.1.1.1", "2.2.2.2", ICMP)
    assert len(g.advance(T0 + 3600)) == 1 and g.stats()["windows_closed"] == 1


def test_advance_earlier_time_is_noop():
    g = RateGuard(stream_threshold=0, victim_threshold=0)
    g.update(T0 + 12, "1.1.1.1", "2.2.2.2", GRE)           # window T0 + 10 open
    before = g.stats()
    assert g.advance(T0 + 5) == [] and g.advance(T0 + 11.9) == [] and g.advance(T0 - 1e6) == []
    assert g.stats() == before and g.active_keys == 2
    assert len(g.advance(T0 + 25)) == 2                    # clock now in window T0 + 20
    assert g.advance(T0 + 15) == []                        # earlier than the latest tick: no-op
    assert g.update(T0 + 18, "1.1.1.1", "2.2.2.2", GRE) == []   # window T0 + 10 is closed: late
    assert g.stats()["late_packets"] == 1 and g.active_keys == 0
    g.update(T0 + 21, "1.1.1.1", "2.2.2.2", GRE)           # the clock's own window is accepted
    assert g.active_keys == 2 and len(g.flush()) == 2


def test_tcp_udp_after_flood_closes_window():
    g = RateGuard(stream_threshold=100, victim_threshold=500)
    _flood(g)
    assert g.update(T0 + 8, "192.168.137.30", "52.1.1.1", TCP) == []     # same window: nothing closes
    a = g.update(T0 + 10.5, "192.168.137.30", "52.1.1.1", UDP)
    assert [x.level for x in a] == [STREAM] * 7 + [VICTIM] and a[-1].packets == 1000
    assert g.flush() == [] and g.active_keys == 0
    s = g.stats()
    assert s["packets_seen"] == 1002 and s["packets_ignored_tcp_udp"] == 2 and s["packets_in_scope"] == 1000
    assert s["windows_closed"] == 1 and s["max_active_keys"] == 8


def test_per_proto_override():
    g = RateGuard(stream_threshold=10, victim_threshold=None,
                  stream_proto_thresholds={ICMP: 100, IGMP: None},
                  victim_proto_thresholds={GRE: 40})
    pkts = []
    for proto in (ICMP, GRE, IGMP):
        pkts += [(T0 + i * 0.01, "1.1.1.1", "2.2.2.2", proto) for i in range(50)]
    _feed(g, pkts)
    a = g.flush()
    got = [(x.level, x.proto, x.threshold) for x in a]
    assert got == [(STREAM, GRE, 10), (VICTIM, GRE, 40)]   # ICMP 50 <= 100; IGMP disabled; victim only for GRE
    assert g.threshold_for(STREAM, 50) == 10 and g.threshold_for(STREAM, IGMP) is None
    assert g.threshold_for(VICTIM, ICMP) is None


def test_late_packets_dropped_and_counted():
    g = RateGuard(stream_threshold=0, record_counts=True)
    g.update(T0 + 1, "1.1.1.1", "2.2.2.2", GRE)
    g.update(T0 + 12, "1.1.1.1", "2.2.2.2", GRE)           # closes window T0, opens T0 + 10
    assert g.update(T0 + 3, "1.1.1.1", "2.2.2.2", GRE) == []     # older than open window
    assert g.update(T0 - 50, "1.1.1.1", "2.2.2.2", GRE) == []
    assert g.update(T0 + 11, "1.1.1.1", "2.2.2.2", GRE) == []    # out of order but in open window: kept
    g.flush()
    s = g.stats()
    assert s["late_packets"] == 2 and s["packets_in_scope"] == 5
    counts = [c for c in g.pop_counts() if c.level == STREAM]
    assert [(c.window_start, c.packets) for c in counts] == [(T0, 1), (T0 + 10, 2)]
    assert counts[1].first_seen_ts == T0 + 11 and counts[1].last_seen_ts == T0 + 12


def test_counts_mode_emits_below_threshold():
    g = RateGuard(stream_threshold=1000, victim_threshold=None, record_counts=True)
    _feed(g, [(T0 + 0.5, "10.0.0.2", "10.0.0.1", ICMP),
              (T0 + 0.6, "10.0.0.1", "10.0.0.2", ICMP),
              (T0 + 0.7, "10.0.0.2", "10.0.0.1", ICMP),
              (T0 + 15, "10.0.0.3", "224.0.0.22", IGMP)])
    assert g.flush() == []
    c = g.pop_counts()
    assert all(isinstance(x, WindowCount) for x in c)
    assert [(x.window_start, x.level, x.src_ip, x.dst_ip, x.proto_name, x.packets) for x in c] == [
        (T0, STREAM, "10.0.0.1", "10.0.0.2", "ICMP", 1),
        (T0, STREAM, "10.0.0.2", "10.0.0.1", "ICMP", 2),
        (T0, VICTIM, None, "10.0.0.1", "ICMP", 2),
        (T0, VICTIM, None, "10.0.0.2", "ICMP", 1),
        (T0 + 10, STREAM, "10.0.0.3", "224.0.0.22", "IGMP", 1),
        (T0 + 10, VICTIM, None, "224.0.0.22", "IGMP", 1),
    ]
    assert c[1].rate_pps == 0.2
    assert g.pop_counts() == []                            # drained
    g = RateGuard(stream_threshold=0)                      # counts off by default
    g.update(T0, "a", "b", GRE)
    g.flush()
    assert g.pop_counts() == []


def test_disabled_level():
    g = RateGuard(stream_threshold=0, victim_threshold=0, enable_victim=False, record_counts=True)
    g.update(T0, "1.1.1.1", "2.2.2.2", GRE)
    assert [x.level for x in g.flush()] == [STREAM]
    assert [x.level for x in g.pop_counts()] == [STREAM]
    assert g.stats()["max_active_keys"] == 1


def test_empty_input():
    g = RateGuard(stream_threshold=1, victim_threshold=1, record_counts=True)
    assert g.flush() == [] and g.pop_counts() == []
    assert g.stats() == {"packets_seen": 0, "packets_in_scope": 0, "packets_ignored_tcp_udp": 0,
                         "late_packets": 0, "windows_closed": 0, "alerts": 0, "max_active_keys": 0}


def test_deterministic_order():
    pkts = [(T0 + random.Random(i).random() * 9, f"10.0.{i % 3}.{i % 7}", f"192.168.1.{i % 4}",
             (GRE, ICMP, 50, 99)[i % 4]) for i in range(400)]
    results = []
    for seed in (1, 2, 3):
        shuffled = pkts[:]
        random.Random(seed).shuffle(shuffled)              # same window, any arrival order
        g = RateGuard(stream_threshold=0, victim_threshold=0, record_counts=True)
        _feed(g, shuffled)
        results.append((g.flush(), g.pop_counts()))
    assert results[0] == results[1] == results[2]
    alerts = results[0][0]
    keys = [(a.src_ip, a.dst_ip, a.proto) for a in alerts if a.level == STREAM]
    assert keys == sorted(keys)
    assert [a.level for a in alerts] == sorted(a.level for a in alerts)    # stream block before victim block
    assert proto_name(50) == "ESP" and proto_name(99) == "99"


def test_constructor_validation():
    assert _raises(lambda: RateGuard(window_s=0))
    assert _raises(lambda: RateGuard(window_s=float("inf")))
    assert _raises(lambda: RateGuard(stream_threshold=-1))
    assert _raises(lambda: RateGuard(victim_threshold=2.5))
    assert _raises(lambda: RateGuard(stream_threshold=True))
    assert _raises(lambda: RateGuard(stream_proto_thresholds={GRE: -3}))
    assert _raises(lambda: RateGuard(victim_proto_thresholds={"47": 3}))
    assert _raises(lambda: RateGuard(enable_stream=False, enable_victim=False))


def _gre_flood(n: int):
    """7 attackers -> 2 victims (attacker i -> victim i % 2), interleaved, 1,000 pps per stream, plus one benign
    ICMP pair every 0.5 s and TCP background every 50th packet."""
    attackers = [f"203.0.113.{i + 1}" for i in range(7)]
    victims = ["192.168.137.10", "192.168.137.20"]
    rate = 7 * 1000.0
    for i in range(n):
        ts = T0 + i / rate
        if i % 50 == 0:
            yield ts, "192.168.137.30", "52.1.1.1", TCP, "cc:00:00:00:00:30", "dd:00:00:00:00:01"
        elif i % 3500 == 1:
            yield ts, "192.168.137.40", "192.168.137.1", ICMP, "cc:00:00:00:00:40", "dd:00:00:00:00:01"
        else:
            a = i % 7
            yield ts, attackers[a], victims[a % 2], GRE, f"ee:00:00:00:00:{a:02x}", "dd:00:00:00:00:01"


def test_large_gre_flood_fast_and_bounded():
    n = 200_000
    pkts = list(_gre_flood(n))                             # generation is not timed
    g = RateGuard(stream_threshold=2000, victim_threshold=5000)
    t = time.perf_counter()
    alerts = []
    upd = g.update
    for p in pkts:
        r = upd(*p)
        if r:
            alerts.extend(r)
    alerts.extend(g.flush())
    elapsed = time.perf_counter() - t
    s = g.stats()
    print(f"\n[rate_guard] {n:,} packets in {elapsed:.3f} s ({n / elapsed:,.0f} pkt/s), "
          f"{s['windows_closed']} windows, {len(alerts)} alerts, max_active_keys {s['max_active_keys']}")
    assert elapsed < 10.0
    assert s["packets_seen"] == n and s["windows_closed"] == 3      # 200k / 7k pps = 28.6 s
    assert s["max_active_keys"] == 7 + 1 + 2 + 1                    # 7 GRE + 1 ICMP stream, 2 + 1 victims
    # every full window: every GRE stream (~10k) and both victims alert; ICMP never
    full = [a for a in alerts if a.window_start == T0]
    assert len([a for a in full if a.level == STREAM]) == 7
    assert len([a for a in full if a.level == VICTIM]) == 2
    assert all(a.proto == GRE for a in alerts)
    assert {len(a.src_macs) for a in full if a.level == VICTIM} == {3, 4}   # 4 attackers -> v0, 3 -> v1

    # memory: same flood with tracemalloc; the peak traced while streaming stays far below the input size
    # and the guard holds no per-packet state after flush
    tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0]
    g = RateGuard(stream_threshold=2000, victim_threshold=5000, record_counts=True)
    for p in _gre_flood(n):
        g.update(*p)
    g.flush()
    peak = tracemalloc.get_traced_memory()[1] - base
    tracemalloc.stop()
    print(f"[rate_guard] tracemalloc peak while streaming {n:,} packets: {peak / 1024:.1f} KiB")
    assert peak < 256 * 1024
    assert g.active_keys == 0 and len(g.pop_counts()) == 3 * 11
