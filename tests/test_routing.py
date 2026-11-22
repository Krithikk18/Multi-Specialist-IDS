"""tests/test_routing.py -- common/routing.py: the ingest owner / group rule as a truth table on a synthetic inventory
(owner roles, unlisted MACs, non-owner roles, blank / multicast MACs, groups outside the labels), the IP -> MAC map
resolver (time window + tolerance, ambiguity), the rate guard's protected-device rule, and on the real val split: the
route of every flow (extractor orientation, v2_0 rows) == the dataset group and device_mac columns (100 %).

Plain asserts. Usage (repo root): python tests/test_routing.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase3_config as C  # noqa: E402
from common import routing as RT  # noqa: E402

CFG = C.load_phase3_config()
A1, A2, B1, GW, PI, ODD = ("02:00:00:00:00:a1", "02:00:00:00:00:a2", "02:00:00:00:00:b1", "02:00:00:00:00:99",
                           "02:00:00:00:00:77", "02:00:00:00:00:55")
UNL, MCAST = "02:00:00:00:00:44", "01:00:5e:00:00:16"


def _router() -> RT.Router:
    d = Path(tempfile.mkdtemp(prefix="p3rt_"))
    (d / "inv.csv").write_text("mac,device_name,role,behaviour_group\n"
                               f"{A1},Dev A1,iot,GX\n{A2},Dev A2,IoT,GX\n{B1},Dev B1,iot,GY\n{GW},Gateway,gateway,\n"
                               f"{PI},Pi,testbed_pi,\n{ODD},Odd,iot,NOT_A_LABEL\n", encoding="utf-8")
    (d / "groups.json").write_text(json.dumps({"labels": {"GX": "", "GY": "", "FB": ""}}), encoding="utf-8")
    (d / "map.csv").write_text("ip,mac,first_seen_epoch,last_seen_epoch\n10.0.0.1,02:00:00:00:00:a1,100,200\n"
                               "10.0.0.2,02:00:00:00:00:b1,100,200\n10.0.0.2,02:00:00:00:00:a2,150,300\n", encoding="utf-8")
    c = copy.deepcopy(CFG)
    c["routing"].update({"inventory": str(d / "inv.csv"), "groups": str(d / "groups.json"), "ip_mac_map": str(d / "map.csv"),
                         "mac_column": "mac", "name_column": "device_name", "role_column": "role",
                         "group_column": "behaviour_group", "owner_roles": ["iot"], "fallback_group": "FB",
                         "unknown_device": "unknown", "ip_map_tolerance_s": 1.0})
    return RT.Router(c)


def test_owner_truth_table():
    r = _router()
    cases = [((A1, B1), (A1, "GX", "device_device_initiator", "src")),     # both owners -> Src side
             ((B1, A1), (B1, "GY", "device_device_initiator", "src")),
             ((A1, GW), (A1, "GX", "device_side", "src")),
             ((GW, A2), (A2, "GX", "device_side", "dst")),                 # role compared case-insensitively
             (("", B1), (B1, "GY", "device_side", "dst")),                 # off-LAN peer (blank MAC)
             ((PI, B1), (B1, "GY", "device_side", "dst")),                 # attacker side never owns
             ((UNL, GW), (UNL, "FB", "unregistered_mac", "src")),          # 08b: unlisted MAC -> fallback group
             ((GW, UNL), (UNL, "FB", "unregistered_mac", "dst")),
             ((GW, PI), ("", "FB", "no_device", "")),
             (("", ""), ("", "FB", "no_device", "")),
             ((GW, MCAST), ("", "FB", "no_device", "")),                   # multicast is not an unlisted device
             ((ODD, GW), (ODD, "FB", "device_side", "src")),               # group outside the labels -> fallback
             ((A1.upper(), " " + GW), (A1, "GX", "device_side", "src"))]   # MACs normalised
    for (s, d), (mac, grp, rule, side) in cases:
        x = r.route({"src_mac": s, "dst_mac": d})
        assert (x.device_mac, x.group, x.rule, x.side) == (mac, grp, rule, side), ((s, d), x)
    assert r.route({"src_mac": GW, "dst_mac": PI}).device == "unknown"
    assert r.route({"src_mac": A1, "dst_mac": ""}).device == "Dev A1"


def test_ip_mac_map_resolver():
    r = _router()
    row = lambda s, d, t: {"Src IP": s, "Dst IP": d, "_meta": {"start_ts": t}}   # noqa: E731  (no MAC keys)
    x = r.route(row("10.0.0.1", "8.8.8.8", 120))
    assert x.device_mac == A1 and x.group == "GX"
    assert r.route(row("10.0.0.1", "8.8.8.8", 201)).device_mac == A1       # within the 1 s tolerance
    assert r.route(row("10.0.0.1", "8.8.8.8", 202)).rule == "no_device"
    assert r.route(row("8.8.8.8", "10.0.0.2", 120)).device_mac == B1
    assert r.route(row("8.8.8.8", "10.0.0.2", 160)).rule == "no_device"     # two MACs -> ambiguous -> no owner
    assert r.ipmap.resolve("10.0.0.2", 160) == ("", "ambiguous")
    assert r.ipmap.resolve("10.9.9.9", 160) == ("", "unmapped")


def test_protected_device_rule():
    r = _router()
    assert r.protected_for_dst_mac(A1) == (A1, "Dev A1", "GX")
    assert r.protected_for_dst_mac(UNL) == (UNL, UNL, "FB")
    for m in (GW, PI, MCAST, "ff:ff:ff:ff:ff:ff", ""):
        assert r.protected_for_dst_mac(m) is None, m


def test_real_val_routing_matches_dataset_100pct():
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    from config.config import REPO_ROOT
    r = RT.Router(CFG)
    raw = D.load_split(load_phase2_config(REPO_ROOT / CFG["source"]["replay_phase2_config"]), "val",
                       ["src_mac", "dst_mac", "group", "device_mac", "session", "row_in_file"])
    v21 = D.load_split(load_phase2_config(REPO_ROOT / CFG["phase2_config"]), "val",
                       ["src_mac", "dst_mac", "group", "device_mac", "session", "row_in_file"])
    assert (raw["session"] + raw["row_in_file"].astype(str)).equals(v21["session"] + v21["row_in_file"].astype(str))
    out = [r.route_macs(RT.norm_mac(s), RT.norm_mac(d)) for s, d in zip(raw["src_mac"], raw["dst_mac"])]
    g_ok = sum(o.group == g for o, g in zip(out, v21["group"]))
    m_ok = sum(o.device_mac == m for o, m in zip(out, v21["device_mac"]))
    assert g_ok == len(v21) and m_ok == len(v21), (g_ok, m_ok, len(v21))
    # the same rule on the NORMALISED (v2_1) MAC columns: report only (why routing runs before normalising)
    out2 = [r.route_macs(RT.norm_mac(s), RT.norm_mac(d)) for s, d in zip(v21["src_mac"], v21["dst_mac"])]
    print(f"    (info) rule on normalised MACs: {sum(o.device_mac != m for o, m in zip(out2, v21['device_mac']))} "
          f"device mismatches of {len(v21):,}")


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
