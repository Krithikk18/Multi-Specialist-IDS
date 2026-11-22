"""tests/test_rate_guard_v2.py -- common/rate_guard_v2.py and common/packet_source.py: synthetic floods alert on the
3rd consecutive window above threshold (and every further one), benign rates at the threshold never alert, an empty
window resets the streak, families are separate, unprotected destinations are not counted, late packets are dropped,
the threshold falls back to the fallback group, record mode; V1 parity (the wrapper == V1 rate_guard.RateGuard with the
frozen config on the same packets); the stdlib pcap reader == V1's tshark reader on a real val slice; split
confinement (test sessions / split refused; reading stops at the val -> test cut).

Plain asserts. Usage (repo root): python tests/test_rate_guard_v2.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import traceback
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import packet_source as PK  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import rate_guard_v2 as RG  # noqa: E402

CFG = C.load_phase3_config()
REPO = Path(__file__).resolve().parents[1]
FAM = {"TCP": [6], "UDP": [17]}


class StubRouter:
    def protected_for_dst_mac(self, mac):
        return {"d1": ("d1", "Dev1", "GA"), "d2": ("d2", "Dev2", "GB"), "u9": ("u9", "u9", "FB")}.get(mac)


def _raises(fn, exc=Exception, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or match.lower() in str(e).lower()
    return False


def _guard(**kw) -> RG.RateGuardV2:
    thr = {"GA": {"TCP": 10, "UDP": 10, "other": 10}, "FB": {"TCP": 5, "UDP": 5, "other": 5}}
    return RG.RateGuardV2(StubRouter(), thr, FAM, "other", 1.0, 3, fallback_group="FB", **kw)


def _feed(g, spec) -> list:
    """spec: [(second, n packets, proto, dst_mac)]"""
    out = []
    for sec, n, proto, mac in spec:
        for i in range(n):
            out += g.update(sec + i / (n + 1), "1.1.1.1", "10.0.0.9", proto, "aa", mac)
    return out + g.flush()


def test_flood_alerts_on_third_consecutive_window():
    a = _feed(_guard(), [(s, 20, 6, "d1") for s in range(5)])
    assert [x.t for x in a] == [3.0, 4.0, 5.0] and [x.streak for x in a] == [3, 4, 5]
    assert all(x.device == "d1" and x.group == "GA" and x.family == "TCP" and x.count == 20 and x.threshold == 10 for x in a)


def test_benign_at_threshold_never_alerts():
    assert _feed(_guard(), [(s, 10, 6, "d1") for s in range(30)]) == []       # alert iff count > threshold


def test_empty_window_resets_streak():
    spec = [(0, 20, 6, "d1"), (1, 20, 6, "d1"), (3, 20, 6, "d1"), (4, 20, 6, "d1")]   # second 2 empty
    assert _feed(_guard(), spec) == []
    spec = [(0, 20, 6, "d1"), (1, 20, 6, "d1"), (2, 1, 6, "d1"), (3, 20, 6, "d1"), (4, 20, 6, "d1")]
    assert _feed(_guard(), spec) == []                                         # a quiet window also resets


def test_families_separate_and_unprotected_not_counted():
    spec = [(s, 20, 17, "d1") for s in range(3)] + [(s, 5, 6, "d1") for s in range(3)] + \
           [(s, 50, 47, "gw") for s in range(3)]
    g = _guard()
    a = _feed(g, sorted(spec))
    assert [(x.family, x.t) for x in a] == [("UDP", 3.0)]
    assert g.stats["not_protected"] == 150
    a = _feed(_guard(), [(s, 20, 47, "d1") for s in range(3)])
    assert [x.family for x in a] == ["other"]


def test_fallback_threshold_and_late_packets():
    g = _guard()
    a = _feed(g, [(s, 6, 6, "d2") for s in range(3)])                         # group GB -> fallback FB (5)
    assert [x.threshold for x in a] == [5]
    g = _guard()
    g.update(5.5, "a", "b", 6, "x", "d1")
    g.update(6.1, "a", "b", 6, "x", "d1")
    assert g.update(5.9, "a", "b", 6, "x", "d1") == [] and g.stats["late"] == 1


def test_record_mode():
    g = _guard(record=True)
    _feed(g, [(0, 3, 6, "d1"), (0, 2, 17, "d1"), (2, 4, 6, "u9")])
    assert sorted(g.records) == [(0.0, "d1", "GA", "TCP", 3), (0.0, "d1", "GA", "UDP", 2), (2.0, "u9", "FB", "TCP", 4)]


def test_v1_parity_wrapper_equals_v1_guard():
    import rate_guard as V1
    args = RG.load_v1_args(CFG["rate_guard"]["v1_config"])
    assert args["stream_proto_thresholds"] == {1: 159, 2: 12} and args["victim_proto_thresholds"] == {1: 321, 2: 33}
    assert args["window_s"] == 10.0 and args["stream_threshold"] == 159 and args["victim_threshold"] == 321
    pk = []
    for s in range(40):                                                        # ICMP + GRE floods, IGMP, TCP ticks
        pk += [(s + i / 400, f"10.0.0.{i % 3}", "10.0.0.50", 1, "m1", "m2") for i in range(40)]
        pk += [(s + i / 100, "10.0.0.7", "10.0.0.60", 47, "m3", "m4") for i in range(50)]
        pk += [(s + 0.5, "10.0.0.8", "224.0.0.22", 2, "m5", "m6"), (s + 0.6, "1.1.1.1", "10.0.0.50", 6, "m7", "m2")]
    pk.sort(key=lambda p: p[0])
    w, ref = RG.V1Guard(CFG), V1.RateGuard(**args)
    a = [x for p in pk for x in w.update(*p)] + w.flush()
    b = [x for p in pk for x in ref.update(*p)] + ref.flush()
    assert a == b and len(a) > 0 and w.stats() == ref.stats()


def _m13():
    spec = importlib.util.spec_from_file_location("rate_guard_calibrate", REPO / "13_rate_guard_calibrate.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_reader_equals_v1_tshark_reader_on_val_slice():
    d = Path(tempfile.mkdtemp(prefix="p3pk_"))
    out = d / "recon_val_slice.pcap"
    man = PK.write_slice(CFG, "Recon-PortScan", "val", out, max_packets=30000)
    assert man["split"] == "val" and man["frames_written"] == 30000
    lo, hi = man["boundaries_epoch"][1], man["boundaries_epoch"][2]
    assert lo <= man["first_ts"] and man["last_ts"] < hi
    ours = list(PK.iter_pcap(out))
    c = Counter()
    v1 = list(_m13().tshark_ipv4_packets(out, None, c))
    assert len(ours) == len(v1) > 25000, (len(ours), len(v1))
    assert ours == v1, next((i, a, b) for i, (a, b) in enumerate(zip(ours, v1)) if a != b)


def test_split_confinement():
    p = PK.session_plan(CFG, "benign_night", "val")
    D = PK.split_definition(CFG)["sessions"]["benign_night"]
    assert p["stop"] == D["boundaries_epoch"][D["labels"].index("gap@val|test") - 1]
    assert PK.session_plan(CFG, "DDoS-SYN_Flood", "val")["stop"] is None       # no test part in that capture
    assert PK.session_plan(CFG, "DDoS-SYN_Flood", "train")["stop"] == \
        PK.split_definition(CFG)["sessions"]["DDoS-SYN_Flood"]["boundaries_epoch"][0]
    for s in ("DDoS-SYN_Flood10", "Mirai-udpplain24", "BenignTraffic1"):
        assert _raises(lambda: PK.session_plan(CFG, s, "val"), exc=C.TestSplitRefused), s
    assert _raises(lambda: PK.session_plan(CFG, "Recon-PortScan", "test"), exc=C.TestSplitRefused)
    assert _raises(lambda: PK.PacketSource(CFG, "test"), exc=C.TestSplitRefused)
    assert set(PK.sessions_with(CFG, "val")) == {"benign_night", "DDoS-SYN_Flood", "DDoS-SYN_Flood5", "Recon-PortScan",
                                                 "Mirai-udpplain"}


def test_reader_stops_at_cut():
    d = Path(tempfile.mkdtemp(prefix="p3pk_"))
    out = d / "recon_val_tail.pcap"
    plan = PK.session_plan(CFG, "Recon-PortScan", "val")
    man = PK.write_slice(CFG, "Recon-PortScan", "val", out, t0=plan["stop"] - 30)
    assert man["reader_counts"].get("stopped_at_cut") == 1 and man["last_ts"] < plan["stop"]


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items(), key=lambda kv: kv[1].__code__.co_firstlineno
                                       if callable(kv[1]) and hasattr(kv[1], "__code__") else 0)
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}\n{traceback.format_exc()}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
