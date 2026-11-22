"""tests/test_label_store.py -- common/label_store.py: signed batches load; a tampered parquet, an edited manifest, a
missing / foreign signature, an un-indexed batch and an edited index are refused; the store is append-only (an existing
batch id is refused; the index only grows); a keys dir inside the repository is refused; the key file is mode 600.
Synthetic data in temp dirs (never the real store or key).

Plain asserts. Usage (repo root): python tests/test_label_store.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common import label_store as LS  # noqa: E402
from common import registry as REG  # noqa: E402

NAMES = ["benign", "a1", "a2"]
CM_SHA = "0" * 64


def _rows(n=50, seed=0):
    rng = np.random.default_rng(seed)
    return LS.make_rows([f"s:{i}" for i in range(n)], [f"f{i}" for i in range(n)], np.arange(n) + 1000, "run1",
                        rng.integers(0, 3, n), np.where(rng.random(n) < 0.8, "alert", "random"), "op", NAMES)


def _store():
    d = Path(tempfile.mkdtemp(prefix="lstore_"))
    sk, pk = LS.ensure_operator_keys(d / "keys")
    return d / "store", sk, pk


def _raises(fn, exc=LS.LabelStoreRefused, match=None):
    try:
        fn()
    except exc as e:
        return match is None or match.lower() in str(e).lower()
    return False


def test_roundtrip_signed():
    root, sk, pk = _store()
    df = _rows()
    W = LS.write_batch(root, "b1", df, sk, {"x": 1}, NAMES, CM_SHA)
    got, M = LS.load_batch(root, "b1", pk, NAMES)
    assert got.equals(df[LS.COLUMNS].reset_index(drop=True))
    assert M["counts_per_class"] == {n: int((df["label"] == n).sum()) for n in NAMES}
    assert W["manifest_sha256"] == LS.manifest_sha256(root, "b1")


def test_tampered_parquet_refused():
    root, sk, pk = _store()
    LS.write_batch(root, "b1", _rows(), sk, {}, NAMES, CM_SHA)
    p = root / "b1" / "labels.parquet"
    df = pd.read_parquet(p)
    df.loc[0, "label_id"] = (int(df.loc[0, "label_id"]) + 1) % 3
    df.loc[0, "label"] = NAMES[int(df.loc[0, "label_id"])]
    p.unlink()
    df.to_parquet(p, index=False)
    assert _raises(lambda: LS.load_batch(root, "b1", pk), match="tampered")


def test_edited_manifest_refused():
    root, sk, pk = _store()
    LS.write_batch(root, "b1", _rows(), sk, {}, NAMES, CM_SHA)
    p = root / "b1" / "manifest.json"
    M = json.loads(p.read_bytes())
    M["n"] += 1
    p.write_bytes(LS.canon(M))
    assert _raises(lambda: LS.load_batch(root, "b1", pk), match="signature")


def test_missing_or_foreign_signature_refused():
    root, sk, pk = _store()
    LS.write_batch(root, "b1", _rows(), sk, {}, NAMES, CM_SHA)
    other = REG.public_key(os.urandom(32))
    assert _raises(lambda: LS.load_batch(root, "b1", other))
    (root / "b1" / "manifest.sig").unlink()
    assert _raises(lambda: LS.load_batch(root, "b1", pk), match="unsigned")


def test_unindexed_batch_refused():
    root, sk, pk = _store()
    LS.write_batch(root, "b1", _rows(), sk, {}, NAMES, CM_SHA)
    shutil.copytree(root / "b1", root / "b2")                  # a correctly signed batch dropped in without the index
    assert _raises(lambda: LS.load_batch(root, "b2", pk), match="index")


def test_append_only_and_index_chain():
    root, sk, pk = _store()
    LS.write_batch(root, "b1", _rows(seed=1), sk, {}, NAMES, CM_SHA)
    assert _raises(lambda: LS.write_batch(root, "b1", _rows(seed=2), sk, {}, NAMES, CM_SHA), match="append-only")
    LS.write_batch(root, "b2", _rows(seed=2), sk, {}, NAMES, CM_SHA)
    idx = LS.read_index(root, pk)
    assert list(idx) == ["b1", "b2"]
    lines = (root / LS.INDEX).read_text(encoding="utf-8").splitlines()
    (root / LS.INDEX).write_text(lines[1] + "\n", encoding="utf-8")        # drop the first record
    assert _raises(lambda: LS.read_index(root, pk), match="chain")
    assert _raises(lambda: LS.load_batch(root, "b2", pk))


def test_duplicate_uid_refused():
    root, sk, pk = _store()
    df = _rows()
    df.loc[1, "flow_uid"] = df.loc[0, "flow_uid"]
    assert _raises(lambda: LS.write_batch(root, "b1", df, sk, {}, NAMES, CM_SHA), match="duplicate")


def test_keys_inside_repo_refused_and_mode():
    assert _raises(lambda: LS.ensure_operator_keys(ROOT / "keys_test_never", ROOT), match="inside the repository")
    assert not (ROOT / "keys_test_never").exists()
    d = Path(tempfile.mkdtemp(prefix="lkeys_"))
    sk, pk = LS.ensure_operator_keys(d / "k")
    assert oct(os.stat(d / "k" / f"{LS.KEY_NAME}.key").st_mode & 0o777) == "0o600"
    assert LS.ensure_operator_keys(d / "k") == (sk, pk)                     # reused, never re-created
    assert LS.operator_public_key(d / "k") == pk


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
