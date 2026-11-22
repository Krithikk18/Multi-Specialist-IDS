"""tests/test_policy.py -- common/policy.py: the alert rule (attack argmax AND max-prob >= threshold), incident
aggregation within the window, closing, the cooldown (suppressed alerts extend nothing, a new incident after it),
separate keys per class and device, severity from config with the Medium default, and run_policy == the tracker.

Plain asserts. Usage (repo root): python tests/test_policy.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import phase3_config as C  # noqa: E402
from common import policy as P  # noqa: E402

CFG = C.load_phase3_config()
NAMES = ["benign", "a1", "a2", "a3"]


def _pol(**over) -> P.Policy:
    return P.Policy(over.get("threshold", 0.5), over.get("window", 60), over.get("cooldown", 300),
                    {"a1": "High", "a3": "Low"}, "Medium", NAMES, "rate_guard")


def test_alert_rule():
    pol = _pol()
    assert pol.alert_of([0.1, 0.7, 0.1, 0.1]) == (True, 1, 0.7)
    assert pol.alert_of([0.2, 0.2, 0.5, 0.1]) == (True, 2, 0.5)            # >= threshold
    assert pol.alert_of([0.3, 0.49, 0.11, 0.1])[0] is False                # attack argmax below the threshold
    assert pol.alert_of([0.9, 0.05, 0.05, 0.0]) == (False, 0, 0.9)          # benign never alerts
    assert _pol(threshold=0.9).alert_of([0.1, 0.85, 0.05, 0.0])[0] is False
    assert P.alert_decision([0.4, 0.4, 0.2], 0.3) == (False, 0, 0.4)       # tie -> lowest id


def test_aggregation_close_and_cooldown():
    tr = _pol().tracker
    d = [tr.process(t, "a1", "dev1", "G", "flow")["decision"] for t in (0, 30, 89)]
    assert d == ["opened", "extended", "extended"]                          # 89 - 30 <= 60
    assert tr.process(150, "a1", "dev1", "G", "flow")["decision"] == "suppressed_cooldown"   # closed at 149
    assert tr.process(448, "a1", "dev1", "G", "flow")["decision"] == "suppressed_cooldown"   # cooldown to 449
    r = tr.process(449, "a1", "dev1", "G", "flow")
    assert r["decision"] == "opened" and r["incident_id"] == "inc000002"
    inc = tr.finish()
    assert len(inc) == 2 and inc[0].n_alerts == 3 and inc[0].n_suppressed_after == 2
    assert inc[0].first == 0 and inc[0].last == 89 and inc[0].closed_at == 149
    assert tr.counts == {"opened": 2, "extended": 2, "suppressed_cooldown": 2, "late": 0}


def test_keys_are_class_and_device():
    tr = _pol().tracker
    assert tr.process(0, "a1", "dev1", "G", "flow")["decision"] == "opened"
    assert tr.process(1, "a2", "dev1", "G", "flow")["decision"] == "opened"     # other class
    assert tr.process(2, "a1", "dev2", "G", "flow")["decision"] == "opened"     # other device
    assert tr.process(3, "rate_guard", "dev1", "G", "rate_guard")["decision"] == "opened"
    assert len(tr.finish()) == 4


def test_severity_from_config_with_medium_default():
    pol = _pol()
    assert pol.severity_fn("a1") == "High" and pol.severity_fn("a3") == "Low"
    assert pol.severity_fn("a2") == "Medium" and pol.severity_fn("never_seen") == "Medium"
    real = P.Policy.from_config(CFG, NAMES)
    assert real.severity_fn("unknown_class") == CFG["policy"]["severity_default"] == "Medium"
    assert all(v in ("High", "Medium", "Low") for v in CFG["policy"]["severity"].values())


def test_advance_closes_and_late_alerts_fold_in():
    tr = _pol(window=10).tracker
    tr.process(0, "a1", "d", "G", "flow")
    tr.process(5, "a1", "d", "G", "flow")
    assert tr.process(4, "a1", "d", "G", "flow")["decision"] == "extended" and tr.counts["late"] == 1
    assert tr.advance(15) == [] and len(tr.advance(15.1)) == 1
    assert not tr.open


def test_run_policy_equals_tracker_and_window_sweep():
    alerts = [(t, "a1", "d", "G", "flow") for t in (0, 40, 100, 200, 700)]
    inc60, c60 = P.run_policy(alerts, 60, 300, lambda c: "High")
    inc30, _ = P.run_policy(alerts, 30, 300, lambda c: "High")
    inc120, _ = P.run_policy(alerts, 120, 300, lambda c: "High")
    assert [i.n_alerts for i in inc60] == [3, 1] and c60["suppressed_cooldown"] == 1
    assert [i.n_alerts for i in inc30] == [1, 1] and [i.n_alerts for i in inc120] == [4, 1]


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
