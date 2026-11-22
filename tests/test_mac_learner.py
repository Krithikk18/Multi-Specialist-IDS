"""tests/test_mac_learner.py -- common/mac_learner.py and its use by the router / runtime / packet reader:
binding from IPv4 frames; ARP precedence; the gateway rule (threshold, window, dropped bindings, own ARP address kept);
change and flap events; unknown binding -> the router's unknown rule (fallback group); causality in the runtime (a
flow is routed only with packets up to its event time); learned_then_static fallback; ARP frames from a pcap
(packet_source arp=True; off by default).
Phase 3.2: the unexpected_gateway health event (warm-up; inventory gateway exempt; a spoofing source fires exactly
once per MAC; port-scan-like traffic fires none; absent under config/v2_phase3_1.json); config/v2_phase3_2.json is
pinned and differs from v2_phase3_1.json only in its note and the two new keys; in the runtime the event goes to the
hash-chained health log and predictions are identical to the Phase 3.1 config's.

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


# --------------------------------------------------------------------------- Phase 3.2: unexpected_gateway
def _spoof(L, t0: float, mac: str, n: int, base: str = "172.16", dt_: float = 0.01) -> None:
    """n frames from one MAC, each with a different (spoofed) source IP."""
    for k in range(n):
        L.observe(_ip(t0 + k * dt_, f"{base}.{k // 250}.{k % 250 + 1}", mac))


def _unexpected(ev) -> list:
    return [e for e in ev if e["kind"] == "unexpected_gateway"]


def test_unexpected_gateway_warmup():
    L = MLR.MacLearner(gateway_warmup_s=300, inventory={})
    L.observe(_ip(1000.0, "10.0.0.1", A))                          # warm-up origin = first frame (t = 1000)
    _spoof(L, 1001.0, B, 20)                                       # B becomes a gateway inside the warm-up
    ev = L.drain_events()
    assert B in L.gateways and not _unexpected(ev) and L.stats["gateway_in_warmup"] == 1
    _spoof(L, 1400.0, B, 50)                                       # sticky: never fires later either
    assert not _unexpected(L.drain_events())
    _spoof(L, 1299.0, G, 9, base="172.17", dt_=0.0)                # at 1299 < 1300: still warm-up
    assert G in L.gateways and not _unexpected(L.drain_events())
    C2 = "02:00:00:00:00:0c"
    _spoof(L, 1300.0, C2, 9, base="172.18", dt_=0.0)               # exactly at the end of the warm-up: fires
    u = _unexpected(L.drain_events())
    assert len(u) == 1 and u[0]["mac"] == C2 and u[0]["event_time"] == 1300.0
    assert u[0]["distinct_source_ips"] == 9 and u[0]["first_time"] == 1300.0 and u[0]["last_time"] == 1300.0
    assert u[0]["in_inventory"] is False and u[0]["inventory_role"] == "" and u[0]["mac_first_seen"] == 1300.0
    M = MLR.MacLearner(gateway_warmup_s=0, inventory={})          # warm-up 0: the first new gateway fires
    _spoof(M, 5.0, B, 9)
    assert len(_unexpected(M.drain_events())) == 1


def test_unexpected_gateway_inventory_gateway_exempt():
    inv = {G: "gateway", "02:00:00:00:00:0d": "router", A: "iot"}
    L = MLR.MacLearner(gateway_warmup_s=10, inventory=inv)
    L.observe(_arp(0.0, "10.0.0.1", G))
    for k in range(30):                                            # the router forwards remote hosts after warm-up
        L.observe(_ip(100.0 + k, f"8.8.{k}.1", G))
        L.observe(_ip(100.0 + k, f"9.9.{k}.1", "02:00:00:00:00:0d"))
    ev = L.drain_events()
    assert G in L.gateways and "02:00:00:00:00:0d" in L.gateways and not _unexpected(ev)
    assert L.stats["gateway_inventory_exempt"] == 2
    _spoof(L, 200.0, A, 12)                                        # an inventory IoT device spoofing: not exempt
    u = _unexpected(L.drain_events())
    assert len(u) == 1 and u[0]["mac"] == A and u[0]["in_inventory"] is True and u[0]["inventory_role"] == "iot"
    assert u[0]["first_time"] == 200.0 and u[0]["last_time"] == 200.0 + 8 * 0.01
    assert MLR.MacLearner(gateway_warmup_s=10, inventory={G.upper(): "Gateway"}).inventory == {G: "gateway"}


def test_unexpected_gateway_spoofing_source_fires_once_per_mac():
    L = MLR.MacLearner(gateway_warmup_s=300, inventory={})
    L.observe(_ip(0.0, "10.0.0.1", "02:00:00:00:00:01"))
    srcs = [f"02:00:00:00:01:{k:02x}" for k in range(3)]
    for rnd in range(4):                                           # three flood sources, spoofing for a long time
        for j, m in enumerate(srcs):
            _spoof(L, 400.0 + 200.0 * rnd + j, m, 200, base=f"10.{100 + j}")
    u = _unexpected(L.drain_events())
    assert sorted(e["mac"] for e in u) == sorted(srcs), u
    assert all(e["distinct_source_ips"] == 9 and e["first_time"] < e["last_time"] for e in u)
    assert L.stats["unexpected_gateway"] == 3


def test_unexpected_gateway_none_on_port_scan_like_traffic():
    """A scanner (one source IP, many destinations / ports) and normal hosts never pass the distinct-source-IP rule."""
    L = MLR.MacLearner(gateway_warmup_s=300, inventory={G: "gateway"})
    L.observe(_arp(0.0, "192.168.1.1", G))
    for k in range(5000):
        t = 400.0 + k * 0.05
        L.observe((t, "192.168.1.50", f"192.168.1.{k % 254 + 1}", 6, A, "02:00:00:00:00:ff"))   # scanner
        L.observe((t, f"192.168.1.{k % 254 + 1}", "192.168.1.50", 6, f"02:00:00:00:02:{k % 254:02x}", A))  # replies
        if k % 10 == 0:
            L.observe(_ip(t, f"93.184.{k % 200}.{k % 7 + 1}", G))    # the inventory router forwarding remote hosts
    ev = L.drain_events()
    assert not _unexpected(ev) and A not in L.gateways and list(L.gateways) == [G]
    assert L.resolve("192.168.1.50") == A


def test_unexpected_gateway_absent_under_phase3_1_config_and_config_pin():
    from common import schemas as S
    c31 = C.load_phase3_config(C.CONFIG_PATH_3_1)
    L31 = MLR.MacLearner.from_config(c31["routing"])
    assert L31.warmup is None and "gateway_warmup_s" not in L31.describe()["params"]
    L31.observe(_ip(0.0, "10.0.0.1", A))
    _spoof(L31, 1000.0, B, 20)
    assert B in L31.gateways and not _unexpected(L31.drain_events()) and "gateway_in_warmup" not in L31.stats
    c32 = C.load_phase3_config(C.CONFIG_PATH_3_2)                  # pinned: verify_pin=True
    assert c32["_pinned"] and c32["_sha256"] == S.V2_PHASE3_2_CONFIG_SHA256 == C.pin_for(C.CONFIG_PATH_3_2)
    L32 = MLR.MacLearner.from_config(c32["routing"])
    ml = c32["routing"]["mac_learner"]
    assert L32.warmup == ml["gateway_warmup_s"] == 300 and L32.gw_roles == set(ml["inventory_gateway_roles"])
    gw = [m for m, r in L32.inventory.items() if r in L32.gw_roles]
    assert len(gw) >= 1 and len(L32.inventory) == len(RT.Router(c32).inv)
    a, b = (json_load(C.CONFIG_PATH_3_1), json_load(C.CONFIG_PATH_3_2))
    for d in (a, b):
        d.pop("note")
    extra = {k: b["routing"]["mac_learner"].pop(k) for k in ("gateway_warmup_s", "inventory_gateway_roles")}
    assert a == b and extra == {"gateway_warmup_s": 300, "inventory_gateway_roles": ["gateway", "router"]}
    res = S.verify_v2_lock(strict=False, v1=False)
    assert any("v2_phase3_2.json" in n and ok for n, ok, _ in res["checks"])
    edited = Path(tempfile.mkdtemp(prefix="p32_")) / "v2_phase3_2.json"
    edited.write_bytes(C.CONFIG_PATH_3_2.read_bytes().replace(b'"gateway_warmup_s": 300', b'"gateway_warmup_s": 30'))
    assert not S.verify_v2_lock(strict=False, v1=False, phase3_2_config=edited)["ok"]
    bad = copy.deepcopy(c32)
    bad["routing"]["mac_learner"]["gateway_warmup_s"] = -1
    assert C.validate(bad)
    bad["routing"]["mac_learner"].update(gateway_warmup_s=0, inventory_gateway_roles=[])
    assert C.validate(bad)


def json_load(p: Path) -> dict:
    import json
    return json.loads(Path(p).read_text(encoding="utf-8"))


def test_runtime_unexpected_gateway_health_log_predictions_unchanged():
    """Under v2_phase3_2.json a spoofing MAC after the warm-up produces one unexpected_gateway record in the signed,
    hash-chained health log; predictions are identical to the same run under v2_phase3_1.json."""
    sys.path.insert(0, str(REPO / "tests"))
    import json
    import test_runtime_e2e as E
    from common import alert_log as AL
    from common import flow_source as FS
    from common import model_loader as ML
    from common import predictions_io as PIO
    from common import runtime as RTM
    raw = E._data()["raw"].iloc[:40]
    rows = [r for k, t, r in FS.CsvReplaySource(E.CFG, frame=raw).events() if k == "flow"]
    rows = [{k: v for k, v in r.items() if k not in ("src_mac", "dst_mac")} for r in rows]
    ts = [float(r["_meta"]["event_time"]) for r in rows]
    t0 = min(ts) - 400.0                                          # warm-up origin 400 s before the flows
    spoofer = "02:00:00:00:0e:01"
    pk = [(t0, "10.0.0.1", "10.0.0.2", 6, A, B)] + [(min(ts) - 50.0 + k * 0.01, f"172.20.0.{k + 1}", "10.0.0.2", 6,
                                                     spoofer, B) for k in range(12)]

    class Rows(FS.FlowSource):
        def __init__(self):
            super().__init__("max")

        def __len__(self):
            return len(rows)

        def events(self):
            for r in sorted(rows, key=lambda r: r["_meta"]["event_time"]):
                yield "flow", r["_meta"]["event_time"], dict(r, _meta=dict(r["_meta"]))

    out = {}
    for label, path in (("3_1", C.CONFIG_PATH_3_1), ("3_2", C.CONFIG_PATH_3_2)):
        d = Path(tempfile.mkdtemp(prefix="p32rt_"))
        sk, _ = AL.ensure_runtime_keys(d / "keys")
        run = d / "run"
        run.mkdir()
        cfg = C.load_phase3_config(path)
        router = RT.Router(cfg, ip_mac_source="learned")
        rt = RTM.Runtime(cfg, ML.load_runtime_model(cfg), run, sk, router=router)
        summ = rt.run(Rows(), list(pk))
        hl = [json.loads(x) for x in (run / "health.jsonl").read_text(encoding="utf-8").splitlines()]
        out[label] = (PIO.read_predictions(run), [h for h in hl if h.get("kind") == "unexpected_gateway"], summ, run, sk)
    P1, u1, s1, _, _ = out["3_1"]
    P2, u2, s2, run2, sk2 = out["3_2"]
    assert len(P1) == len(rows) and P1.equals(P2)
    assert u1 == [] and len(u2) == 1 and u2[0]["mac"] == spoofer and u2[0]["distinct_source_ips"] == 9
    assert s2["counts"].get("unexpected_gateway") == 1 and "unexpected_gateway" not in s1["counts"]
    assert AL.verify_chain(run2 / "health.jsonl", AL.REG.public_key(sk2))["ok"]


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
