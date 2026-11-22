"""tests/test_phase5b_context.py -- common/context_features.py (Phase 5B step A): streaming == naive O(n^2) reference
on random streams (exact, all 44 features); a flow and its fwd/bwd-swapped copy give identical features (whole stream
and one flow in place); causality; self-exclusion and ties; tie-break determinism (input order does not matter);
window edges ([t - w, t)); eviction behaviour and counts; insert mask; reset at split boundaries; warm-up flag; names
generated from the config (44). Synthetic data.

Plain asserts. Usage (repo root): python tests/test_phase5b_context.py
"""

from __future__ import annotations

import copy
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import context_config as CC  # noqa: E402
from common import context_features as CF  # noqa: E402

CFG = CC.load_phase5b_config(verify_pin=False)
C = CFG["columns"]


def stream(n=400, hosts=8, span_s=120, seed=0, session="s1", split="train"):
    rng = np.random.default_rng(seed)
    ips = [f"10.0.0.{i}" for i in range(hosts)]
    a = rng.integers(0, hosts, n)
    b = (a + rng.integers(0, hosts, n)) % hosts                        # includes some self-flows
    df = pd.DataFrame({
        C["src_ip"]: [ips[i] for i in a], C["dst_ip"]: [ips[i] for i in b],
        C["src_port"]: rng.choice(["80", "443", "1234", "5555", "22"], n).astype(str),
        C["dst_port"]: rng.choice(["80", "443", "40000", "40001"], n).astype(str),
        C["start"]: rng.integers(1_000_000, 1_000_000 + span_s, n),
        C["duration"]: rng.choice([0, 1, 500, 2_000_000, 7_000_000], n).astype(float),
        C["fwd_pkts"]: rng.integers(1, 5, n).astype(float), C["bwd_pkts"]: rng.integers(0, 4, n).astype(float),
        C["fwd_bytes"]: rng.integers(0, 2000, n).astype(float), C["bwd_bytes"]: rng.integers(0, 900, n).astype(float),
        C["syn"]: rng.integers(0, 2, n).astype(float), C["ack"]: rng.integers(0, 2, n).astype(float),
        C["session"]: session, C["split"]: split})
    df[C["flow_id"]] = (df[C["src_ip"]] + "-" + df[C["dst_ip"]] + "-" + df[C["src_port"]] + "-" + df[C["dst_port"]] + "-6")
    df[C["row"]] = np.arange(n)
    return df


def swapped(df, rows=None):
    out = df.copy()
    ix = np.arange(len(df)) if rows is None else np.asarray(rows)
    for x, y in (("src_ip", "dst_ip"), ("src_port", "dst_port"), ("fwd_pkts", "bwd_pkts"), ("fwd_bytes", "bwd_bytes")):
        out.loc[ix, C[x]], out.loc[ix, C[y]] = df.loc[ix, C[y]].to_numpy(), df.loc[ix, C[x]].to_numpy()
    out.loc[ix, C["flow_id"]] = (out[C["src_ip"]] + "-" + out[C["dst_ip"]] + "-" + out[C["src_port"]] + "-" +
                                 out[C["dst_port"]] + "-6")[ix]
    return out


def feats(df, cfg=CFG, **kw):
    return CF.compute(CF.prepare(df, cfg), cfg, **kw)[0]


def test_names_from_config():
    n = CC.context_feature_names(CFG)
    assert len(n) == 44 and len(set(n)) == 44
    assert n[0] == "ctx_hostmax_n_flows_10s" and n[7] == "ctx_hostmin_n_flows_10s" and n[14] == "ctx_pair_n_flows_10s"
    assert n[21] == "ctx_pair_mean_duration_10s" and n[22] == "ctx_hostmax_n_flows_60s" and n[-1] == "ctx_pair_mean_duration_60s"
    c2 = copy.deepcopy(CFG)
    c2["context"]["windows_s"] = [5]
    c2["context"]["prefix"] = "zz"
    assert len(CC.context_feature_names(c2)) == 22 and CC.context_feature_names(c2)[0] == "zz_hostmax_n_flows_5s"
    F = CC.build_feature_list(CFG)
    assert F["n_features"] == 114 and F["features"][70:] == n


def test_streaming_equals_naive():
    for seed in range(4):
        df = stream(n=350, seed=seed, hosts=6 + seed)
        inp = CF.prepare(df, CFG)
        Fs, info = CF.compute(inp, CFG)
        Fn = CF.naive(inp, CFG)
        assert info["evictions"] == {"host": 0, "pair": 0}
        assert Fs.shape == (350, 44) and np.array_equal(Fs, Fn), (seed, np.argwhere(Fs != Fn)[:5])
        assert Fs[:, 0].max() > 3                                     # the stream is dense enough to test something


def test_swapped_copy_identical():
    df = stream(n=300, seed=7)
    F0 = feats(df)
    assert np.array_equal(F0, feats(swapped(df)))                       # every flow swapped
    assert np.array_equal(F0, feats(swapped(df, rows=[3, 17, 150])))    # some flows swapped in place


def test_causality_later_flows_do_not_change_earlier():
    df = stream(n=300, seed=3)
    inp = CF.prepare(df, CFG)
    o = CF.order(inp)
    F = feats(df)
    first = np.sort(o[:150])
    F_part = feats(df.iloc[first].reset_index(drop=True))
    assert np.array_equal(F[first], F_part)


def test_self_exclusion_and_ties():
    df = stream(n=3, seed=1)
    df[C["src_ip"]], df[C["dst_ip"]] = "10.0.0.1", "10.0.0.2"
    df[C["start"]], df[C["duration"]] = 1_000_000, 1000.0               # identical t_end: nobody sees anybody
    F = feats(df)
    assert (F == 0).all()
    df.loc[2, C["duration"]] = 2000.0                                   # now flow 2 ends later and sees flows 0, 1
    F = feats(df)
    assert (F[:2] == 0).all() and F[2, 0] == 2 and F[2, 14] == 2        # hostmax n_flows, pair n_flows (10 s)


def test_tie_break_input_order_invariant():
    df = stream(n=250, seed=5, span_s=20)
    F = feats(df)
    perm = np.random.default_rng(1).permutation(len(df))
    Fp = feats(df.iloc[perm].reset_index(drop=True))
    assert np.array_equal(F[perm], Fp)


def test_window_edges():
    base = stream(n=2, seed=0)
    base[C["src_ip"]], base[C["dst_ip"]] = "10.0.0.1", "10.0.0.2"
    base[C["start"]] = 1_000_000
    for gap_us, inside10 in ((10_000_000, True), (10_000_001, False), (9_999_999, True)):
        df = base.copy()
        df.loc[0, C["duration"]] = 0.0
        df.loc[1, C["duration"]] = float(gap_us)                         # t_end(1) - t_end(0) = gap
        F = feats(df)
        assert F[1, 0] == (1 if inside10 else 0), (gap_us, F[1, 0])      # 10 s window: [t - 10 s, t)
        assert F[1, 22] == 1                                             # always inside the 60 s window


def test_eviction_counts_and_behaviour():
    df = stream(n=300, seed=2, hosts=10)
    c2 = copy.deepcopy(CFG)
    c2["context"]["max_tracked_hosts"] = 3
    c2["context"]["max_tracked_pairs"] = 4
    inp = CF.prepare(df, c2)
    F1, info1 = CF.compute(inp, c2)
    F2, info2 = CF.compute(inp, c2)
    assert info1["evictions"]["host"] > 0 and info1["evictions"]["pair"] > 0
    assert info1["evictions"] == info2["evictions"] and np.array_equal(F1, F2)      # deterministic
    assert info1["peak_hosts"] <= 3 and info1["peak_pairs"] <= 4
    assert not np.array_equal(F1, feats(df))                                         # eviction loses state
    st = CF.ContextState(c2)
    for h in ("h1", "h2", "h3"):
        st.insert("host", h, (10, "x", ("1", "2"), 1, 1, 1, 0, 0))
    st.insert("host", "h1", (11, "x", ("1", "2"), 1, 1, 1, 0, 0))                 # h1 refreshed -> h2 is LRU
    st.insert("host", "h4", (12, "x", ("1", "2"), 1, 1, 1, 0, 0))
    assert list(st.keys["host"]) == ["h3", "h1", "h4"] and st.evictions["host"] == 1


def test_insert_mask():
    df = stream(n=200, seed=4)
    inp = CF.prepare(df, CFG)
    mask = np.zeros(len(df), bool)
    F = CF.compute(inp, CFG, insert_mask=mask)[0]
    assert (F == 0).all()
    mask[:] = True
    assert np.array_equal(CF.compute(inp, CFG, insert_mask=mask)[0], feats(df))


def test_reset_at_split_boundary_and_warmup():
    tr = stream(n=200, seed=8, session="s1", split="train", span_s=100)
    va = stream(n=200, seed=9, session="s1", split="val", span_s=100)
    va[C["start"]] = va[C["start"]] + 100                                 # val directly after train, same hosts
    both = pd.concat([tr, va], ignore_index=True)
    F, warm, info = CF.compute_segments(both, CFG)
    assert len(info["segments"]) == 2
    assert np.array_equal(F[200:], feats(va.reset_index(drop=True)))       # val context ignores every train flow
    assert np.array_equal(F[:200], feats(tr))
    inp = CF.prepare(va, CFG)
    seg0 = int(inp["start"].min()) * C["start_unit_us"]
    assert np.array_equal(warm[200:], (inp["t_end"] < seg0 + 60_000_000).astype(np.int8))
    assert warm[200:].sum() > 0 and warm[200:].sum() < 200
    assert info["segments"][1]["warmup"] == int(warm[200:].sum())


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
