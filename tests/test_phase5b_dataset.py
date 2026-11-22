"""tests/test_phase5b_dataset.py -- Phase 5B step B helpers (39_build_context_dataset.py + common/context_config.py):
context column naming from the config (and the pinned list = generated list); the config validator rejects edits; the
warm-up flag; reset at the split boundary inside one session; the reference check passes on a synthetic segment and
picks a contiguous slice; manifest counts per class x group; the feature summary. Synthetic data.

Plain asserts. Usage (repo root): python tests/test_phase5b_dataset.py
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from common import context_config as CC  # noqa: E402
from common import context_features as CF  # noqa: E402
from test_phase5b_context import stream  # noqa: E402

CFG = CC.load_phase5b_config(verify_pin=False)
C = CFG["columns"]
spec = importlib.util.spec_from_file_location("s39", ROOT / "39_build_context_dataset.py")
S39 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S39)
NAMES = ["benign", "a1", "a2", "a3"]


def test_naming_from_config_and_pinned_list():
    F = CC.build_feature_list(CFG)
    assert F["features"][:70] == F["features"][:F["n_flow"]] and F["n_context"] == 44
    assert all(n.startswith(CFG["context"]["prefix"] + "_") for n in F["context_features"])
    P = CC.load_feature_list()                                          # the pinned file == what the config generates
    assert P["features"] == F["features"] and P["sha256"] == F["sha256"]
    c2 = copy.deepcopy(CFG)
    c2["context"]["prefix"] = "cx"
    assert CC.build_feature_list(c2)["features"][70] == "cx_hostmax_n_flows_10s"


def test_validator_rejects_edits():
    assert CC.validate(CFG) == []
    for path, val in ((("context", "windows_s"), [60, 10]), (("context", "host_stats"), ["n_flows"]),
                      (("columns", "start_unit_us"), 0), (("stage1", "weights"), "sqrt"),
                      (("zeroday", "recall_lo_min"), 1.5), (("shap", "models"), ["GLOBAL"])):
        c2 = copy.deepcopy(CFG)
        c2[path[0]][path[1]] = val
        assert CC.validate(c2), path


def test_warmup_flag():
    df = stream(n=300, seed=11, span_s=200)
    F, warm, info = CF.compute_segments(df, CFG)
    inp = CF.prepare(df, CFG)
    start = int(inp["start"].min()) * C["start_unit_us"]
    assert np.array_equal(warm, (inp["t_end"] < start + max(CFG["context"]["windows_s"]) * 1_000_000).astype(np.int8))
    assert 0 < warm.sum() < len(df) and info["segments"][0]["warmup"] == int(warm.sum())


def test_split_reset_within_session():
    tr = stream(n=150, seed=1, split="train", span_s=50)
    va = stream(n=150, seed=2, split="val", span_s=50)
    va[C["start"]] += 50
    F, _, info = CF.compute_segments(pd.concat([tr, va], ignore_index=True), CFG)
    assert [s["segment"] for s in info["segments"]] == [["s1", "train"], ["s1", "val"]]
    first_val = 150 + int(np.argmin(CF.prepare(va, CFG)["t_end"]))
    assert (F[first_val] == 0).all()                                     # no train flow leaks into val context


def test_reference_check_on_synthetic_segment():
    c2 = copy.deepcopy(CFG)
    c2["reference_check"]["slice_rows"] = 120
    df = stream(n=400, seed=3)
    R = S39.reference_check(df, c2, log=lambda *_: None)
    assert R["equal"] and R["rows"] == 120 and R["mismatches"] == 0 and 0 <= R["start"] <= 400 - 120
    R2 = S39.reference_check(df, c2, log=lambda *_: None)
    assert R2["start"] == R["start"]                                      # seeded


def test_manifest_counts():
    df = pd.DataFrame({C["label_id"]: [0, 0, 1, 3, 3, 3], C["group"]: ["G1", "G2", "G1", "G1", "G1", "G2"]})
    assert S39.class_group_counts(df, C["label_id"], C["group"], NAMES) == {"benign|G1": 1, "benign|G2": 1, "a1|G1": 1,
                                                                             "a3|G1": 2, "a3|G2": 1}


def test_feature_summary():
    df = stream(n=400, seed=4)
    F, _, _ = CF.compute_segments(df, CFG)
    names = CC.context_feature_names(CFG)
    for j, f in enumerate(names):
        df[f] = F[:, j]
    df[C["label_id"]] = np.where(np.arange(400) % 4 == 0, 1, 0)
    df.loc[df[C["label_id"]] == 1, names[0]] += 100.0                    # make one feature separate class 1
    Sm = S39.feature_summary(df, names, NAMES, C["label_id"], top=3)
    assert Sm["top"][0] == names[0] and len(Sm["hist"]) == 3
    assert Sm["per_feature"][names[0]]["auc_vs_benign"]["a1"] > 0.99


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items(), key=lambda kv: kv[1].__code__.co_firstlineno
                                       if callable(kv[1]) and hasattr(kv[1], "__code__") else 0)
             if n.startswith("test_") and callable(f) and getattr(f, "__module__", "") == __name__]
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
