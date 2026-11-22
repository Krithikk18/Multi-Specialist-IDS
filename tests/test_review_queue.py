"""tests/test_review_queue.py -- common/review_queue.py: every alert queued with reason "alert"; exactly round(rate x
non-alerted) random non-alerted items with reason "random"; seeded (same seed -> same queue, other seed -> other
sample); rate 0 -> alerts only; ascending positions; bad rate refused. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_review_queue.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import review_queue as RQ  # noqa: E402


def _alerts(n=10_000, p=0.3, seed=1):
    return np.random.default_rng(seed).random(n) < p


def test_every_alert_queued_with_reason_alert():
    a = _alerts()
    Q = RQ.build_queue(a, 0.05, 0)
    pos, rs = Q["pos"], Q["reason"]
    assert set(np.flatnonzero(a)) == set(pos[rs == "alert"])
    assert a[pos[rs == "alert"]].all()
    assert Q["n_alert"] == int(a.sum())


def test_random_items_are_non_alerted_exact_count():
    a = _alerts()
    Q = RQ.build_queue(a, 0.05, 0)
    r = Q["pos"][Q["reason"] == "random"]
    assert not a[r].any()
    assert len(r) == round(0.05 * int((~a).sum())) == Q["n_random"]
    assert len(set(r.tolist())) == len(r)


def test_seeded_determinism():
    a = _alerts()
    q1, q2, q3 = RQ.build_queue(a, 0.05, 0), RQ.build_queue(a, 0.05, 0), RQ.build_queue(a, 0.05, 1)
    assert (q1["pos"] == q2["pos"]).all() and (q1["reason"] == q2["reason"]).all()
    assert set(q1["pos"].tolist()) != set(q3["pos"].tolist())


def test_rate_zero_alerts_only_and_ascending():
    a = _alerts()
    Q = RQ.build_queue(a, 0.0, 0)
    assert Q["n_random"] == 0 and (Q["reason"] == "alert").all()
    Q5 = RQ.build_queue(a, 0.05, 0)
    assert (np.diff(Q5["pos"]) > 0).all()


def test_rate_one_and_bad_rate():
    a = _alerts(100)
    assert len(RQ.build_queue(a, 1.0, 0)["pos"]) == 100
    for bad in (-0.1, 1.5):
        try:
            RQ.build_queue(a, bad, 0)
            raise AssertionError("bad rate accepted")
        except ValueError:
            pass


def test_no_alerts_and_all_alerts():
    Q = RQ.build_queue(np.zeros(1000, bool), 0.05, 0)
    assert Q["n_alert"] == 0 and Q["n_random"] == 50
    Q = RQ.build_queue(np.ones(10, bool), 0.05, 0)
    assert Q["n_alert"] == 10 and Q["n_random"] == 0


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
