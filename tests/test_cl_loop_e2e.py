"""tests/test_cl_loop_e2e.py -- the Phase 4 loop end to end on a tiny synthetic dataset (temp dirs, temp keys; never
the real store, registry or keys):
  base model (cl_retrain.fit == step 22's train_one, model bytes) -> split val into A / B -> score val-A -> review queue
  -> simulated operator -> signed batch -> validator VALID (and a poisoned copy QUARANTINED) -> replay buffer -> R1 / R2 /
  R3 (warm start keeps the base trees, adds >= 1, leaves the base booster untouched) -> gate on val-B -> a passing model
  registered as a signed CANDIDATE that deployment loads refuse and offline loads accept.

Plain asserts. Usage (repo root): python tests/test_cl_loop_e2e.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common import cl_gate as CG  # noqa: E402
from common import cl_retrain as RT  # noqa: E402
from common import cl_split as SP  # noqa: E402
from common import cl_validator as CV  # noqa: E402
from common import label_store as LS  # noqa: E402
from common import operator_sim as OP  # noqa: E402
from common import phase2_metrics as PM  # noqa: E402
from common import registry as REG  # noqa: E402
from common import replay_buffer as RB  # noqa: E402
from common import review_queue as RQ  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import load_phase2_config  # noqa: E402

K = 4
NAMES = ["benign", "a1", "a2", "a3"]
CFG2 = load_phase2_config(ROOT / "config" / "v2_phase2_v2_1.json")
GATE = {"min_val_flows": 50, "max_recall_drop": 0.01, "max_macro_f1_drop": 0.002, "max_fa_per_h_rise": 0.5}


def _data(n, seed, shift=0.0):
    rng = np.random.default_rng(seed)
    y = rng.choice(K, size=n, p=[0.5, 0.25, 0.1, 0.15])
    X = rng.normal(size=(n, 8)).astype(np.float32)
    X[:, 0] += 3.0 * y + shift
    X[:, 1] += 2.0 * (y == 2) - 1.5 * (y == 3)
    g = rng.choice(["G1", "G2", "GEN"], size=n, p=[0.6, 0.35, 0.05])
    return X, y.astype(np.int64), g


_STATE: dict = {}


def _loop():
    if _STATE:
        return _STATE
    Xtr, ytr, gtr = _data(4000, 0)
    Xva, yva, gva = _data(3000, 1, shift=0.2)
    base = RT.fit(Xtr, ytr, K, "none", 0, CFG2, 2)
    sd = {"sessions": {"s": {"labels": ["train", "gap@train|val", "val"], "boundaries_epoch": [0, 10]}}}
    t = np.sort(np.random.default_rng(2).integers(1000, 4000, len(yva)))
    sess = np.array(["s"] * len(yva))
    part = SP.assign(sess, t, SP.val_windows(sd, sess, t))
    A, B = part == "val_A", part == "val_B"
    P = PM.softmax(base["booster"].predict(__import__("xgboost").DMatrix(Xva[A]), output_margin=True), base["temperature"])
    pred, pmax = P.argmax(1), P.max(1)
    alert = (pred != 0) & (pmax >= 0.5)
    Q = RQ.build_queue(alert, 0.05, 0)
    L = OP.simulate(yva[A][Q["pos"]], Q["reason"], K)
    d = Path(tempfile.mkdtemp(prefix="cl_e2e_"))
    sk, pk = LS.ensure_operator_keys(d / "opkeys")
    uidA = np.array([f"s:{i}" for i in np.flatnonzero(A)])
    qu = uidA[Q["pos"]]
    rows = LS.make_rows(qu[L["sel"]], qu[L["sel"]], t[A][Q["pos"]][L["sel"]], "rt", L["label"], Q["reason"][L["sel"]],
                        "op", NAMES)
    LS.write_batch(d / "labels", "b1", rows, sk, {}, NAMES, S.CLASS_MAP_SHA256)
    dep = {"flow_uid": qu.tolist(), "pred": pred[Q["pos"]], "pmax": pmax[Q["pos"]]}
    V = CV.validate_batch(d / "labels", "b1", pk, NAMES, dep, {"confident_pmax": 0.99, "max_confident_disagreement": 0.05})
    lab, fl = CG.flip_labels(L["label"], CG.poison_targets(L["label"], K, [0, 1, 2, 3])["p2"], 0, 1.0, 0)
    LS.write_batch(d / "poison", "p2", LS.make_rows(qu[L["sel"]], qu[L["sel"]], t[A][Q["pos"]][L["sel"]], "rt", lab,
                                                    Q["reason"][L["sel"]], "op", NAMES), sk, {}, NAMES, S.CLASS_MAP_SHA256)
    Vp = CV.validate_batch(d / "poison", "p2", pk, NAMES, dep, {"confident_pmax": 0.99, "max_confident_disagreement": 0.05})
    df, _ = LS.load_batch(d / "labels", "b1", pk, NAMES)
    XL = Xva[A][Q["pos"]][L["sel"]]
    yL = df["label_id"].to_numpy(np.int64)
    Rb = RB.select(ytr, gtr, 0.25, 1000, 0)
    raw0 = bytes(base["booster"].save_raw("ubj"))
    r1 = RT.fit(np.vstack([Xtr, XL]), np.concatenate([ytr, yL]), K, "none", 0, CFG2, 2)
    r2 = RT.fit(np.vstack([Xtr[Rb["pos"]], XL]), np.concatenate([ytr[Rb["pos"]], yL]), K, "none", 0, CFG2, 2,
                base=base["booster"], rounds=100)
    r3 = RT.fit(XL, yL, K, "none", 0, CFG2, 2, base=base["booster"], rounds=100)
    raw1 = bytes(base["booster"].save_raw("ubj"))
    nr = CG.nonrare_classes(yva[B], K, 50)
    ev = lambda b: CG.eval_set(yva[B], RT.predict_proba(b, Xva[B]).argmax(1), K, nr, sess[B], t[B], 300)  # noqa: E731
    E0 = ev(base["booster"])
    gates = {k: CG.gate(ev(r["booster"]), E0, nr, GATE) for k, r in (("R1", r1), ("R2", r2), ("R3", r3))}
    _STATE.update(locals())
    return _STATE


def test_fit_equals_step22_train_one():
    spec = importlib.util.spec_from_file_location("t22", ROOT / "22_train_multiclass.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    X, y, _ = _data(2000, 5)
    a = m.train_one(X, y, K, "none", 3, CFG2, nthread=2)
    b = RT.fit(X, y, K, "none", 3, CFG2, 2)
    assert bytes(a["booster"].save_raw("ubj")) == bytes(b["booster"].save_raw("ubj"))
    assert a["best_iteration"] == b["best_iteration"] and b["base_rounds"] == 0


def test_queue_labels_and_validator():
    s = _loop()
    assert s["Q"]["n_alert"] > 0 and s["Q"]["n_random"] > 0
    assert s["V"]["status"] == CV.VALID, s["V"]
    assert s["Vp"]["status"] == CV.QUARANTINED and "c_confident_disagreement" in s["Vp"]["fired"], s["Vp"]["fired"]


def test_warm_start_semantics():
    s = _loop()
    for r in (s["r2"], s["r3"]):
        assert r["base_rounds"] == s["base"]["booster"].num_boosted_rounds()
        assert r["rounds_total"] == r["base_rounds"] + r["new_rounds"] and r["new_rounds"] >= 1
        assert r["best_iteration"] == r["rounds_total"] - 1
    assert s["raw0"] == s["raw1"], "the base booster was modified"
    assert np.isfinite(s["r1"]["fit_seconds"]) and s["r1"]["temperature"] > 0


def test_gate_and_candidate_registration():
    s = _loop()
    assert all(k in s["gates"] for k in ("R1", "R2", "R3"))
    g = s["gates"]["R1"]
    assert g["pass"], g["reason"]
    d = Path(tempfile.mkdtemp(prefix="cl_reg_"))
    sk, pk = REG.ensure_keys(d / "keys")
    mf = d / "m.ubj"
    s["r1"]["booster"].save_model(str(mf))
    cal = d / "cal.json"
    cal.write_text(json.dumps({"temperature": s["r1"]["temperature"]}), encoding="utf-8")
    e = REG.register(d / "registry", "E__s0__test", mf, cal,
                     {"model_id": "E", "seed": 0, "kind": "global", "class_map_sha256": S.CLASS_MAP_SHA256,
                      "features_file_sha256": S.FEATURES_V1_SHA256, "phase4": {"arm": "R1", "gate": g["status"]}},
                     sk, by="test (Phase 4)")
    assert REG.read_state(e, pk) == "candidate"
    assert "test (Phase 4)" in (e / "state.log").read_text(encoding="utf-8")
    assert REG.load_model(e, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH, allow_states=("candidate",))["state"] == "candidate"
    try:
        REG.load_model(e, pk, S.CLASS_MAP_PATH, S.FEATURES_PATH)
        raise AssertionError("deployment load accepted a candidate")
    except REG.RegistryRefused:
        pass


def test_register_default_by_unchanged():
    d = Path(tempfile.mkdtemp(prefix="cl_reg2_"))
    sk, pk = REG.ensure_keys(d / "keys")
    (d / "m.ubj").write_bytes(b"x")
    (d / "c.json").write_text("{}", encoding="utf-8")
    e = REG.register(d / "r", "e", d / "m.ubj", d / "c.json", {}, sk)
    assert "26_model_registry.py (automatic registration)" in (e / "state.log").read_text(encoding="utf-8")


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
