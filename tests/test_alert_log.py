"""tests/test_alert_log.py -- common/alert_log.py: a written chain verifies; an edited, deleted, reordered or inserted
line fails; a bad signature (other key, flipped hex) fails; a cut tail fails against the expected count / head; the log
refuses an existing file; runtime keys are created private and refused inside the repo, and differ from the registry
key.

Plain asserts. Usage (repo root): python tests/test_alert_log.py
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import alert_log as AL  # noqa: E402
from common import registry as REG  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def _raises(fn, exc=Exception, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or match.lower() in str(e).lower()
    return False


def _log(n=6) -> tuple[Path, bytes, bytes, dict]:
    d = Path(tempfile.mkdtemp(prefix="p3al_"))
    sk, pk = AL.ensure_runtime_keys(d / "keys")
    p = d / "alerts.jsonl"
    L = AL.ChainLog(p, sk, "alerts", flush_every=2)
    for i in range(n):
        L.append({"event_time": 100.0 + i, "class": "a1", "probs": [0.1, 0.9], "top3": [("f", 1.0, 0.5)]})
    return p, sk, pk, L.close()


def _lines(p: Path) -> list[bytes]:
    return p.read_bytes().splitlines(keepends=True)


def test_chain_verifies():
    p, _, pk, info = _log()
    r = AL.verify_chain(p, pk, expect_n=info["n"], expect_head=info["head_sha256"])
    assert r["ok"] and r["n"] == 6, r
    recs = [json.loads(x) for x in _lines(p)]
    assert recs[0]["prev_sha256"] == AL.GENESIS and [r["seq"] for r in recs] == list(range(6))


def test_edited_line_fails():
    p, _, pk, _ = _log()
    L = _lines(p)
    L[2] = L[2].replace(b'"class":"a1"', b'"class":"a2"')
    p.write_bytes(b"".join(L))
    r = AL.verify_chain(p, pk)
    assert not r["ok"] and r["line"] == 2 and "signature" in r["error"], r


def test_deleted_reordered_inserted_lines_fail():
    for mutate in (lambda L: L[:2] + L[3:], lambda L: [L[0], L[2], L[1]] + L[3:], lambda L: L[:3] + [L[1]] + L[3:]):
        p, _, pk, _ = _log()
        p.write_bytes(b"".join(mutate(_lines(p))))
        r = AL.verify_chain(p, pk)
        assert not r["ok"] and ("seq" in r["error"] or "chain" in r["error"]), r


def test_bad_signature_and_other_key_fail():
    p, _, pk, _ = _log()
    _, other = AL.ensure_runtime_keys(Path(tempfile.mkdtemp(prefix="p3al_")) / "k2")
    assert not AL.verify_chain(p, other)["ok"]
    L = _lines(p)
    rec = json.loads(L[4])
    rec["sig"] = ("0" if rec["sig"][0] != "0" else "1") + rec["sig"][1:]
    L[4] = AL.canon(rec) + b"\n"
    p.write_bytes(b"".join(L))
    r = AL.verify_chain(p, pk)
    assert not r["ok"] and r["line"] == 4, r


def test_cut_tail_detected_with_expected_count_or_head():
    p, _, pk, info = _log()
    p.write_bytes(b"".join(_lines(p)[:-1]))
    assert AL.verify_chain(p, pk)["ok"]                                       # the chain alone cannot see a cut tail
    assert not AL.verify_chain(p, pk, expect_n=info["n"])["ok"]
    assert not AL.verify_chain(p, pk, expect_head=info["head_sha256"])["ok"]
    p.write_bytes(p.read_bytes()[:-5])
    assert not AL.verify_chain(p, pk)["ok"]


def test_refuses_existing_file_and_keys_in_repo():
    p, sk, _, _ = _log()
    assert _raises(lambda: AL.ChainLog(p, sk, "alerts"), exc=FileExistsError)
    assert _raises(lambda: AL.ensure_runtime_keys(REPO / "keys_should_not_exist", REPO), exc=PermissionError)
    assert not (REPO / "keys_should_not_exist").exists()


def test_runtime_key_private_and_separate_from_registry_key():
    d = Path(tempfile.mkdtemp(prefix="p3al_"))
    sk, pk = AL.ensure_runtime_keys(d / "rt")
    assert stat.S_IMODE(os.stat(d / "rt" / f"{AL.KEY_NAME}.key").st_mode) == 0o600
    assert AL.ensure_runtime_keys(d / "rt") == (sk, pk)                      # stable once created
    rsk, rpk = REG.ensure_keys(d / "reg")
    assert pk != rpk and AL.KEY_NAME != REG.KEY_NAME
    assert AL.runtime_public_key(d / "rt") == pk


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
