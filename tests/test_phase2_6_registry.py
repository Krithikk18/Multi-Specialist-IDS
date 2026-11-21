"""tests/test_phase2_6_registry.py -- Phase 2 step 6 (common/registry.py): Ed25519 against RFC 8032 test vectors,
and every load_model refusal (bad signature, tampered file, class-map / feature hash mismatch, non-promoted state,
tampered / illegal state log, foreign key), plus the manual transitions. Temp dirs and a tiny synthetic model only.

Plain asserts, no pytest fixtures or imports. Usage (repo root): python tests/test_phase2_6_registry.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import registry as REG  # noqa: E402
from common import schemas as S  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

# RFC 8032 section 7.1, TEST 1-3: (secret, public, message, signature)
RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def _raises(fn, exc=REG.RegistryRefused, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or re.search(match, str(e)) is not None
    return False


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="test_p2_reg_"))


def test_rfc8032_vectors_pure_and_active_backend():
    for sk, pk, msg, sig in RFC_VECTORS:
        sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
        assert REG._pure_public(sk) == pk and REG._pure_sign(sk, msg) == sig and REG._pure_verify(pk, msg, sig)
        assert REG.public_key(sk) == pk and REG.sign(sk, msg) == sig and REG.verify(pk, msg, sig)
        bad = bytearray(sig)
        bad[5] ^= 1
        assert not REG._pure_verify(pk, msg, bytes(bad)) and not REG.verify(pk, msg + b"x", sig)


def _entry(root: Path, secret: bytes, entry_id: str = "SPEC_X__s0__RUN") -> Path:
    import xgboost as xgb
    rng = np.random.default_rng(0)
    X = rng.normal(size=(200, 70)).astype(np.float32)
    y = (X[:, 0] > 0).astype(int) + 2 * (X[:, 1] > 1)
    b = xgb.train({"objective": "multi:softprob", "num_class": 4, "max_depth": 2, "nthread": 1}, xgb.DMatrix(X, label=y), 5)
    src = _tmp()
    b.save_model(str(src / "m.ubj"))
    (src / "cal.json").write_text(json.dumps({"temperature": 1.7}))
    fields = {"model_id": "SPEC_X__sqrt", "seed": 0, "class_map_sha256": REG.sha256_file(S.CLASS_MAP_PATH),
              "features_file_sha256": REG.sha256_file(S.FEATURES_PATH)}
    return REG.register(root, entry_id, src / "m.ubj", src / "cal.json", fields, secret)


def _keys():
    return REG.ensure_keys(_tmp() / "keys", REPO)


def test_keys_created_private_and_outside_repo():
    d = _tmp() / "k"
    sk, pk = REG.ensure_keys(d, REPO)
    assert len(sk) == 32 and REG.public_key(sk) == pk
    assert oct(os.stat(d / "registry_ed25519.key").st_mode & 0o777) == "0o600"
    assert REG.ensure_keys(d, REPO) == (sk, pk)                       # reused, not regenerated
    assert _raises(lambda: REG.ensure_keys(REPO / "keys_should_not_exist", REPO), match="inside the repository")
    assert not (REPO / "keys_should_not_exist").exists()


def test_candidate_loads_offline_only():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    r = REG.load_model(d, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH, allow_states=("candidate",))
    assert r["state"] == "candidate" and r["temperature"] == 1.7 and r["booster"].num_boosted_rounds() == 5
    assert _raises(lambda: REG.load_model(d, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH), match="not in")


def test_refuses_bad_manifest_signature():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    raw = (d / "manifest.json").read_bytes().replace(b'"seed":0', b'"seed":1')
    (d / "manifest.json").write_bytes(raw)
    assert _raises(lambda: REG.load_model(d, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH, ("candidate",)), match="bad manifest signature")
    d2 = _entry(_tmp(), sk)
    (d2 / "manifest.sig").unlink()
    assert _raises(lambda: REG.load_model(d2, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH, ("candidate",)), match="missing")


def test_refuses_tampered_model_or_calibrator():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    with open(d / "model.ubj", "ab") as fh:
        fh.write(b"\0")
    assert _raises(lambda: REG.load_model(d, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH, ("candidate",)), match="model.ubj sha256")
    d2 = _entry(_tmp(), sk)
    (d2 / "calibrator.json").write_text(json.dumps({"temperature": 0.1}))
    assert _raises(lambda: REG.load_model(d2, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH, ("candidate",)), match="calibrator")


def test_refuses_class_map_mismatch():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    other = _tmp() / "class_map.json"
    other.write_bytes(S.CLASS_MAP_PATH.read_bytes().replace(b"port_scan", b"port_scam"))
    assert _raises(lambda: REG.load_model(d, pk, other, S.FEATURES_PATH, ("candidate",)), match="class map")


def test_refuses_features_mismatch():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    other = _tmp() / "features_v1.json"
    other.write_bytes(S.FEATURES_PATH.read_bytes() + b" ")
    assert _raises(lambda: REG.load_model(d, pk, S.CLASS_MAP_PATH, other, ("candidate",)), match="features")


def test_refuses_foreign_key():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    _, pk2 = _keys()
    assert _raises(lambda: REG.load_model(d, pk2, S.CLASS_MAP_PATH, S.FEATURES_PATH, ("candidate",)), match="signature|another key")


def test_transitions_and_promoted_load():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    assert _raises(lambda: REG.transition(d, "promoted", sk, "me"), match="candidate -> promoted")
    REG.transition(d, "approved", sk, "me")
    assert _raises(lambda: REG.load_model(d, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH), match="'approved'")
    REG.transition(d, "promoted", sk, "me")
    assert REG.load_model(d, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH)["state"] == "promoted"
    assert _raises(lambda: REG.transition(d, "approved", sk, "me"), match="promoted -> approved")


def test_refuses_tampered_state_log():
    sk, pk = _keys()
    d = _entry(_tmp(), sk)
    lines = (d / "state.log").read_text().splitlines()
    rec = json.loads(lines[0])
    forged = {**rec, "state": "promoted"}                             # forged promotion, old signature
    (d / "state.log").write_text(json.dumps(forged, sort_keys=True) + "\n")
    assert _raises(lambda: REG.load_model(d, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH), match="bad signature")
    d2 = _entry(_tmp(), sk)
    REG.transition(d2, "approved", sk, "me")
    REG.transition(d2, "promoted", sk, "me")
    L = (d2 / "state.log").read_text().splitlines()
    (d2 / "state.log").write_text("\n".join([L[0], L[2]]) + "\n")      # drop the approval: chain broken
    assert _raises(lambda: REG.read_state(d2, pk), match="chain|illegal")


def test_entries_are_immutable():
    sk, _ = _keys()
    root = _tmp()
    _entry(root, sk, "E1")
    assert _raises(lambda: _entry(root, sk, "E1"), match="already exists")


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
