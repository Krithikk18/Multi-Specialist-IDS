"""tests/test_cl_validator.py -- common/cl_validator.py, each pre-registered quarantine rule: a clean batch is VALID;
(a) a tampered / unsigned batch fires; (b) a label outside the class map (unknown name, or id != the name's id) fires;
(c) confident disagreement above 5 % fires, at / below 5 % does not, no confident items passes; several rules are all
reported. Synthetic data in temp dirs.

Plain asserts. Usage (repo root): python tests/test_cl_validator.py
"""

from __future__ import annotations

import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import cl_validator as CV  # noqa: E402
from common import label_store as LS  # noqa: E402

NAMES = ["benign", "a1", "a2"]
VCFG = {"confident_pmax": 0.99, "max_confident_disagreement": 0.05}


def _setup(n=200, disagree=0, pmax=0.995, label_override=None, seed=0):
    rng = np.random.default_rng(seed)
    d = Path(tempfile.mkdtemp(prefix="clval_"))
    sk, pk = LS.ensure_operator_keys(d / "keys")
    uid = [f"s:{i}" for i in range(n)]
    pred = rng.integers(0, 3, n)
    lab = pred.copy()
    lab[:disagree] = (lab[:disagree] + 1) % 3
    rows = LS.make_rows(uid, uid, np.arange(n), "r", lab, ["alert"] * n, "op", NAMES)
    if label_override is not None:
        label_override(rows)
    LS.write_batch(d / "store", "b", rows, sk, {}, NAMES, "0" * 64)
    dep = {"flow_uid": uid, "pred": pred, "pmax": np.full(n, pmax)}
    return d / "store", pk, dep


def test_clean_batch_valid():
    root, pk, dep = _setup()
    R = CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)
    assert R["status"] == CV.VALID and R["fired"] == [], R


def test_a_tampered_or_unsigned_fires():
    root, pk, dep = _setup()
    p = root / "b" / "labels.parquet"
    df = pd.read_parquet(p)
    df.loc[0, "operator_id"] = "mallory"
    p.unlink()
    df.to_parquet(p, index=False)
    R = CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)
    assert R["status"] == CV.QUARANTINED and "a_signature_hash" in R["fired"]
    root2, pk2, dep2 = _setup()
    (root2 / "b" / "manifest.sig").unlink()
    R2 = CV.validate_batch(root2, "b", pk2, NAMES, dep2, VCFG)
    assert R2["fired"] == ["a_signature_hash"], R2["fired"]


def test_b_unknown_label_fires():
    def bad(rows):
        rows.loc[3, "label"] = "zero_day"
    root, pk, dep = _setup(label_override=bad)
    R = CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)
    assert "b_label_in_class_map" in R["fired"] and R["checks"]["b_label_in_class_map"]["unknown_names"] == 1


def test_b_id_mismatch_fires():
    def bad(rows):
        rows.loc[0, "label_id"] = (NAMES.index(rows.loc[0, "label"]) + 1) % 3
    root, pk, dep = _setup(label_override=bad)
    R = CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)
    assert "b_label_in_class_map" in R["fired"] and R["checks"]["b_label_in_class_map"]["id_mismatch"] == 1


def test_c_threshold():
    root, pk, dep = _setup(n=200, disagree=10)                     # 5.0 % -> not above 5 %
    assert CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)["status"] == CV.VALID
    root, pk, dep = _setup(n=200, disagree=11)                     # 5.5 %
    R = CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)
    assert R["fired"] == ["c_confident_disagreement"] and abs(R["checks"]["c_confident_disagreement"]["rate"] - 0.055) < 1e-12


def test_c_only_confident_items_count():
    root, pk, dep = _setup(n=200, disagree=100, pmax=0.98)          # none confident -> passes
    R = CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)
    assert R["status"] == CV.VALID and R["checks"]["c_confident_disagreement"]["n_confident"] == 0
    c = CV.check_confident_disagreement([0, 1, 1, 1], [0, 0, 1, 1], [0.999, 0.5, 0.995, 0.999], 0.99, 0.05)
    assert c["n_confident"] == 3 and c["n_disagree"] == 0 and not c["fired"]


def test_multiple_rules_reported():
    def bad(rows):
        rows.loc[150, "label"] = "zero_day"
    root, pk, dep = _setup(n=200, disagree=30, label_override=bad)
    R = CV.validate_batch(root, "b", pk, NAMES, dep, VCFG)
    assert set(R["fired"]) == {"b_label_in_class_map", "c_confident_disagreement"}


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
