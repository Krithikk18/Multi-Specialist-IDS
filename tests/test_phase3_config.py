"""tests/test_phase3_config.py -- common/phase3_config.py: the pinned runtime config loads; split == test is refused
(source and pcap source); an edited / CRLF file fails the pin (DFD P5); invalid values are listed; operational
overrides are recorded and policy fields cannot be overridden.

Plain asserts. Usage (repo root): python tests/test_phase3_config.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase3_config as C  # noqa: E402
from common import schemas as S  # noqa: E402

RAW = C.CONFIG_PATH.read_bytes()


def _raises(fn, exc=Exception, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or match.lower() in str(e).lower()
    return False


def _tmp(obj_or_bytes, name="v2_phase3.json") -> Path:
    d = Path(tempfile.mkdtemp(prefix="p3cfg_"))
    p = d / name
    p.write_bytes(obj_or_bytes if isinstance(obj_or_bytes, bytes) else
                  (json.dumps(obj_or_bytes, indent=1) + "\n").encode("utf-8"))
    return p


def _cfg() -> dict:
    return json.loads(RAW)


def test_pinned_config_loads():
    cfg = C.load_phase3_config()
    assert cfg["_pinned"] and cfg["_sha256"] == S.V2_PHASE3_CONFIG_SHA256
    assert cfg["mode"] in C.MODES and cfg["source"]["split"] == "val"


def test_refuses_test_split_in_source():
    c = _cfg()
    c["source"]["split"] = "test"
    assert _raises(lambda: C.load_phase3_config(_tmp(c), verify_pin=False), exc=C.TestSplitRefused, match="test")


def test_refuses_test_split_in_pcap_source():
    c = _cfg()
    c["pcap_source"]["split"] = "test"
    assert _raises(lambda: C.load_phase3_config(_tmp(c), verify_pin=False), exc=C.TestSplitRefused)
    assert _raises(lambda: C.refuse_test("test"), exc=C.TestSplitRefused)
    C.refuse_test("val")
    C.refuse_test("train")


def test_edited_or_crlf_file_fails_pin():
    edited = _tmp(RAW.replace(b'"cooldown_s": 300', b'"cooldown_s": 301', 1))
    assert _raises(lambda: C.load_phase3_config(edited), exc=C.ConfigError, match="pinned")
    assert C.load_phase3_config(edited, verify_pin=False)["_pinned"] is False
    crlf = _tmp(RAW.replace(b"\n", b"\r\n"))
    assert _raises(lambda: C.load_phase3_config(crlf, verify_pin=False), exc=C.ConfigError, match="CR")


def test_invalid_values_listed_together():
    c = _cfg()
    c["mode"] = "FLAT"
    c["policy"]["severity"]["syn_flood"] = "Critical"
    c["batch"]["max_flows"] = 0
    c["rate_guard"]["families"]["UDP"] = [6]                          # protocol in two families
    try:
        C.load_phase3_config(_tmp(c), verify_pin=False)
        raise AssertionError("no error")
    except C.ConfigError as e:
        msg = str(e)
    for frag in ("mode must be", "severity values", "batch.max_flows", "two families"):
        assert frag in msg, (frag, msg)


def test_speed_factor():
    assert C.speed_factor("max") is None
    assert C.speed_factor("1x") == 1.0 and C.speed_factor("10x") == 10.0 and C.speed_factor("2.5x") == 2.5
    for bad in ("0x", "fast", "-1x", "10"):
        assert _raises(lambda: C.speed_factor(bad), exc=C.ConfigError)


def test_overrides_recorded_and_policy_locked():
    cfg = C.load_phase3_config()
    o = C.with_overrides(cfg, mode="ROUTED", speed="10x", batch_max_flows=16, seed=3, rate_guard_enabled=False)
    assert o["mode"] == "ROUTED" and o["source"]["speed"] == "10x" and o["batch"]["max_flows"] == 16
    assert o["_seed"] == 3 and o["rate_guard"]["enabled"] is False
    assert o["_overrides"] == {"mode": "ROUTED", "speed": "10x", "batch_max_flows": 16, "seed": 3,
                               "rate_guard_enabled": False}
    assert cfg["mode"] == "GLOBAL" and cfg["_overrides"] == {}               # original untouched
    assert _raises(lambda: C.with_overrides(cfg, confidence_threshold=0.9), exc=C.ConfigError, match="not overridable")
    assert _raises(lambda: C.with_overrides(cfg, seed=99), exc=C.ConfigError)
    assert _raises(lambda: C.with_overrides(cfg, speed="fast"), exc=C.ConfigError)


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
