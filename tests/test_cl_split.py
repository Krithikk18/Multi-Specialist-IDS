"""tests/test_cl_split.py -- common/cl_split.py (val-A / val-B rule) and common/cl_config.py (pinned Phase 4 config):
the val interval of a time_split and of an open-ended session; the data clip (a window opening long before its first
flow, an open end); the midpoint cut; rows outside the val window refused; the pinned config loads and an edited / CRLF
copy fails the pin; invalid values are listed. Synthetic data (+ the real config file's bytes).

Plain asserts. Usage (repo root): python tests/test_cl_split.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import cl_config as CC  # noqa: E402
from common import cl_split as SP  # noqa: E402

SD = {"sessions": {
    "ts": {"labels": ["train", "gap@train|val", "val", "gap@val|test", "test"], "boundaries_epoch": [100, 110, 200, 210]},
    "open": {"labels": ["train", "gap@train|val", "val"], "boundaries_epoch": [100, 110]},
    "testonly": {"labels": ["test"], "boundaries_epoch": []}}}


def test_val_interval():
    assert SP.val_interval(SD["sessions"]["ts"]) == (110.0, 200.0)
    lo, hi = SP.val_interval(SD["sessions"]["open"])
    assert lo == 110.0 and hi == np.inf
    try:
        SP.val_interval(SD["sessions"]["testonly"])
        raise AssertionError("no val window accepted")
    except SP.SplitError:
        pass


def test_windows_clip_and_midpoint():
    sess = np.array(["ts"] * 4 + ["open"] * 4)
    t = np.array([110, 150, 160, 199, 5000, 5010, 5020, 5100])        # 'open' starts long after its boundary
    W = SP.val_windows(SD, sess, t)
    assert W["ts"]["lo"] == 110 and W["ts"]["hi"] == 199 and W["ts"]["mid"] == 154.5
    assert W["open"]["lo"] == 5000 and W["open"]["hi"] == 5100 and W["open"]["mid"] == 5050
    part = SP.assign(sess, t, W)
    assert part.tolist() == ["val_A", "val_A", "val_B", "val_B", "val_A", "val_A", "val_A", "val_B"]


def test_rows_outside_window_refused():
    try:
        SP.val_windows(SD, np.array(["ts"]), np.array([205]))
        raise AssertionError("row outside the val window accepted")
    except SP.SplitError:
        pass
    try:
        SP.val_windows(SD, np.array(["nope"]), np.array([1]))
        raise AssertionError("unknown session accepted")
    except SP.SplitError:
        pass


def test_jsonable():
    W = SP.val_windows(SD, np.array(["open", "open"]), np.array([120, 130]))
    j = json.loads(json.dumps(SP.jsonable_windows(W)))
    assert j["open"]["manifest_hi"] is None and j["open"]["mid"] == 125


def test_config_pinned_loads():
    c = CC.load_phase4_config()
    assert c["_pinned"] and c["queue"]["random_review_rate"] == 0.05 and c["validator"]["confident_pmax"] == 0.99


def test_config_edited_or_crlf_fails_pin():
    raw = CC.CONFIG_PATH.read_bytes()
    d = Path(tempfile.mkdtemp(prefix="p4cfg_"))
    p = d / "v2_phase4.json"
    p.write_bytes(raw.replace(b'"random_review_rate": 0.05', b'"random_review_rate": 0.06'))
    try:
        CC.load_phase4_config(p)
        raise AssertionError("edited config accepted")
    except CC.ConfigError as e:
        assert "pinned" in str(e)
    assert CC.load_phase4_config(p, verify_pin=False)["_pinned"] is False
    p.write_bytes(raw.replace(b"\n", b"\r\n"))
    try:
        CC.load_phase4_config(p, verify_pin=False)
        raise AssertionError("CRLF accepted")
    except CC.ConfigError:
        pass


def test_config_invalid_values_listed():
    c = json.loads(CC.CONFIG_PATH.read_bytes())
    c["gate"]["max_recall_drop"] = -1
    c["retrain"]["nthread"] = 0
    c["operator"]["sweeps"][0]["noise"] = 1.5
    E = CC.validate(c)
    assert any("max_recall_drop" in e for e in E) and any("nthread" in e for e in E) and any("noise" in e for e in E)


def main() -> int:
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]
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
