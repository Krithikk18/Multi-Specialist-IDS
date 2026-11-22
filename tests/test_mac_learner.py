"""tests/test_mac_learner.py -- common/mac_learner.py and its use by the router / runtime / packet reader:
binding from IPv4 frames; ARP precedence; the gateway rule (threshold, window, dropped bindings, own ARP address kept);
change and flap events; unknown binding -> the router's unknown rule (fallback group); causality in the runtime (a
flow is routed only with packets up to its event time); learned_then_static fallback; ARP frames from a pcap
(packet_source arp=True; off by default).

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_mac_learner.py
"""

from __future__ import annotations

import copy
import struct
import sys
import tempfile
import traceback
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from common import mac_learner as MLR  # noqa: E402
from common import packet_source as PK  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import routing as RT  # noqa: E402

A, B, G = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:99"


def _ip(t, ip, mac):
    return (t, ip, "10.0.0.250", 6, mac, "02:00:00:00:00:ff")


def _arp(t, ip, mac):
    return (t, ip, "10.0.0.250", MLR.ARP_PROTO, mac, "ff:ff:ff:ff:ff:ff")


def test_binding_and_ignored_sources():
    L = MLR.MacLearner()
    assert L.resolve("10.0.0.1") == ""
    L.observe(_ip(1.0, "10.0.0.1", A))
    assert L.resolve("10.0.0.1") == A
    L.observe(_ip(2.0, "10.0.0.2", "01:00:5e:00:00:01"))           # multicast source MAC: ignored
    L.observe(_ip(3.0, MLR.UNSPECIFIED_IP, B))                     # unspecified source address: ignored
    assert L.resolve("10.0.0.2") == "" and L.resolve(MLR.UNSPECIFIED_IP) == ""
    assert MLR.ARP_PROTO == PK.ARP_PROTO


def test_arp_wins_on_conflict():
    L = MLR.MacLearner()
    L.observe(_arp(1.0, "10.0.0.1", A))
    L.observe(_ip(2.0, "10.0.0.1", B))                             # IPv4 frame never replaces an ARP binding
    assert L.resolve("10.0.0.1") == A and L.stats["arp_kept_over_ip"] == 1 and not L.drain_events()
    L.observe(_ip(3.0, "10.0.0.2", A))
    L.observe(_arp(4.0, "10.0.0.2", B))                            # ARP replaces an IPv4 binding (change event)
    ev = L.drain_events()
    assert L.resolve("10.0.0.2") == B and [e["kind"] for e in ev] == ["ip_mac_change"]
    assert ev[0]["old_mac"] == A and ev[0]["new_mac"] == B and ev[0]["event_time"] == 4.0


def test_gateway_rule():
    L = MLR.MacLearner(gateway_distinct_ip_threshold=8, gateway_window_s=300)
    L.observe(_arp(0.5, "10.0.0.1", G))                            # the gateway's own address via ARP
    for k in range(8):                                             # 8 distinct source IPs: not yet a gateway
        L.observe(_ip(1.0 + k, f"8.8.8.{k}", G))
    assert G not in L.gateways and L.resolve("8.8.8.0") == G
    L.observe(_ip(20.0, "8.8.8.8", G))                             # the 9th distinct IP within 300 s -> gateway
    ev = L.drain_events()
    assert G in L.gateways and any(e["kind"] == "gateway_detected" for e in ev)
    assert all(L.resolve(f"8.8.8.{k}") == "" for k in range(9))    # IPs seen only behind it are not bound
    assert L.resolve("10.0.0.1") == G                              # its own ARP address is kept
    L.observe(_ip(30.0, "9.9.9.9", G))
    assert L.resolve("9.9.9.9") == ""
    M = MLR.MacLearner(gateway_distinct_ip_threshold=8, gateway_window_s=10)
    for k in range(12):                                            # 12 IPs but never > 8 inside a 10 s window
        M.observe(_ip(5.0 * k, f"8.8.8.{k}", A))
    assert A not in M.gateways and M.resolve("8.8.8.11") == A


def test_change_and_flap_events():
    L = MLR.MacLearner(flap_count=3, flap_window_s=60)
    L.observe(_ip(0.0, "10.0.0.5", A))
    for k, m in enumerate((B, A, B, A), start=1):                  # 4 changes at t = 10, 20, 30, 40
        L.observe(_ip(10.0 * k, "10.0.0.5", m))
    ev = L.drain_events()
    assert [e["kind"] for e in ev].count("ip_mac_change") == 4
    fl = [e for e in ev if e["kind"] == "ip_mac_flap"]
    assert len(fl) == 1 and fl[0]["event_time"] == 30.0 and fl[0]["changes"] == 3   # once per IP per flap window
    L.observe(_ip(200.0, "10.0.0.5", B))                           # isolated change much later: no flap
    assert [e["kind"] for e in L.drain_events()] == ["ip_mac_change"]


def _cfg():
    cfg = copy.deepcopy(C.load_phase3_config(C.CONFIG_PATH_3_1))
    return cfg


def test_unknown_binding_routes_to_fallback_and_learned_routes():
    cfg = _cfg()
    r = RT.Router(cfg, ip_mac_source="learned")
    dev = next(m for m, (n, role, g) in r.inv.items() if role in r.owner_roles)
    row = {"Src IP": "10.0.0.7", "Dst IP": "10.0.0.8", "_meta": {"start_ts": 100.0}}
    x = r.route(row)
    assert x.rule == "no_device" and x.group == r.fallback and r.stats["learned_both_unbound"] == 1
    r.learner.observe(_ip(99.0, "10.0.0.8", dev))
    r2 = RT.Router(cfg, ip_mac_source="learned")
    r2.learner.observe(_ip(99.0, "10.0.0.8", dev))
    y = r2.route(row)
    assert y.device_mac == dev and y.side == "dst" and y.group == r2._group_of(dev)
    st = RT.Router(cfg)                                             # default stays static (Phase 3)
    assert st.ip_mac_source == "static" and st.learner is None
    assert C.ip_mac_source(cfg, "cicfm_pcap") == "learned" and C.ip_mac_source(cfg, "csv_replay") == "static"
    assert C.ip_mac_source(C.load_phase3_config(), "cicfm_pcap") == "static"


def test_learned_then_static_falls_back():
    cfg = _cfg()
    r = RT.Router(cfg, ip_mac_source="learned_then_static")
    ip, lo, hi, mac = next((ip, lo, hi, m) for ip, L in r.ipmap.by_ip.items() for lo, hi, m in L)
    s, d = r.macs_of({"Src IP": ip, "Dst IP": "203.0.113.9", "_meta": {"start_ts": (lo + hi) / 2}})
    assert s == mac and d == "" and r.stats["learned_src_unbound"] == 1 and r.stats["static_fallback_src_mapped"] == 1


def test_runtime_causality_no_lookahead():
    """A MAC-less flow is routed with only the packets up to its event time: the same binding packet routes it when it
    comes earlier, and leaves it unknown (fallback group) when it comes later."""
    sys.path.insert(0, str(REPO / "tests"))
    import test_runtime_e2e as E
    from common import flow_source as FS
    from common import model_loader as ML
    from common import predictions_io as PIO
    from common import runtime as RTM
    from common import alert_log as AL
    raw = E._data()["raw"].iloc[:1]
    good = next(r for k, t, r in FS.CsvReplaySource(E.CFG, frame=raw).events() if k == "flow")
    row = {k: v for k, v in good.items() if k not in ("src_mac", "dst_mac")}
    t = float(row["_meta"]["event_time"])
    r0 = RT.Router(_cfg())
    side = "src" if r0.role(RT.norm_mac(good["src_mac"])) in r0.owner_roles else "dst"
    dev = RT.norm_mac(good[f"{side}_mac"])
    assert r0.role(dev) in r0.owner_roles
    ip = row["Src IP"] if side == "src" else row["Dst IP"]

    class One(FS.FlowSource):
        def __init__(self):
            super().__init__("max")

        def events(self):
            yield "flow", t, dict(row, _meta=dict(row["_meta"]))

    out = {}
    for label, pt in (("before", t - 1.0), ("after", t + 1.0)):
        d = Path(tempfile.mkdtemp(prefix="mlr_"))
        sk, _ = AL.ensure_runtime_keys(d / "keys")
        run = d / "run"
        run.mkdir()
        cfg = _cfg()
        router = RT.Router(cfg, ip_mac_source="learned")
        rt = RTM.Runtime(cfg, ML.load_runtime_model(cfg), run, sk, router=router)
        rt.run(One(), [(pt, ip, "198.51.100.1", 6, dev, "02:00:00:00:00:ff")])
        out[label] = PIO.read_predictions(run).iloc[0]
    assert out["before"]["device_mac"] == dev, out["before"]["device_mac"]
    assert out["after"]["device_mac"] == "" and out["after"]["group"] == RT.Router(_cfg()).fallback


def _pcap(path: Path, frames: list) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)))
            fh.write(fr)


def test_packet_reader_arp_option():
    mac = lambda s: bytes.fromhex(s.replace(":", ""))  # noqa: E731
    eth = lambda d, s, et: mac(d) + mac(s) + struct.pack("!H", et)  # noqa: E731
    arp = eth("ff:ff:ff:ff:ff:ff", A, 0x0806) + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(A) + bytes([10, 0, 0, 1]) \
        + mac("00:00:00:00:00:00") + bytes([10, 0, 0, 2])
    ipv4 = eth(B, A, 0x0800) + bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]) + bytes(20)
    p = Path(tempfile.mkdtemp(prefix="arp_")) / "t.pcap"
    _pcap(p, [(100.0, arp), (100.5, ipv4)])
    c0 = Counter()
    assert [x[3] for x in PK.iter_pcap(p, c0)] == [6] and c0["non_ipv4"] == 1          # default: ARP skipped
    c1 = Counter()
    got = list(PK.iter_pcap(p, c1, arp=True, release_pages=True))
    assert got[0] == (100.0, "10.0.0.1", "10.0.0.2", PK.ARP_PROTO, A, "00:00:00:00:00:00") and got[1][3] == 6
    assert c1["arp"] == 1 and c1["non_ipv4"] == 0
    L = MLR.MacLearner()
    for x in got:
        L.observe(x)
    assert L.resolve("10.0.0.1") == A and L.bind["10.0.0.1"][1] == "arp"


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
