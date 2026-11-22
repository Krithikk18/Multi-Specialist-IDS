"""common/context_features.py -- Phase 5B orientation-free host / host-pair time-window context features
(docs/V2_PREREG_PHASE5B.md section 2). ONE streaming implementation, used for the dataset and by any future runtime.

    inp = prepare(df, cfg)                         # direction-symmetric inputs (integer microseconds, exact integers)
    F, info = compute(inp, cfg)                    # (n x 44) in df row order; info: evictions, peak state
    F_ref = naive(inp, cfg)                        # O(n^2) reference (no eviction), for checks only
    F, warm, info = compute_segments(df, cfg)      # state reset per (session, split) segment + ctx_warmup flag

Semantics. t_end = start * start_unit_us + duration * duration_unit_us (integer us). Flow f's context uses the flows
with t_end in [t_end(f) - w, t_end(f)) -- strictly earlier; flows with the same t_end never see each other (a tie
group is scored first, then inserted). Processing order = (t_end, start, canonical Flow ID, input position); the
canonical Flow ID sorts the two "ip:port" endpoints, so the order is the same for a flow and its swapped copy.
Per host H (either endpoint) and per unordered pair {A, B}, per window: n_flows, n_peers (distinct other endpoints;
for a pair entity the "peer" is the pair itself, so n_peers is 1 when its window is non-empty -- a degenerate
indicator kept because the prereg asks for "the same 7 quantities"), n_port_pairs (distinct unordered port
pairs), sum_pkts, sum_bytes, share_short, share_syn_no_ack (+ mean_duration in seconds for pairs). Per flow: hostmax /
hostmin = element-wise max / min of the two endpoints' host vectors. Empty window -> 0. Sums are Python ints (exact).
Bounded state: hosts / pairs capped; a new key beyond the cap evicts the least-recently-updated key (last insert).
No column name, class, host, port or window value appears here: everything comes from the config.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque

import numpy as np
import pandas as pd

from common.context_config import context_feature_names


# --------------------------------------------------------------------------- inputs
def prepare(df: pd.DataFrame, cfg: dict) -> dict:
    c, cx = cfg["columns"], cfg["context"]
    a_ip = df[c["src_ip"]].astype(str).to_numpy()
    b_ip = df[c["dst_ip"]].astype(str).to_numpy()
    a_pt = df[c["src_port"]].astype(str).to_numpy()
    b_pt = df[c["dst_port"]].astype(str).to_numpy()

    def ints(col):
        v = df[col].to_numpy(np.float64)
        if not np.all(np.isfinite(v)) or np.any(v != np.round(v)):
            raise ValueError(f"column {col!r} has non-integer or non-finite values: exact sums need integers")
        return v.astype(np.int64)

    start = ints(c["start"])
    dur = ints(c["duration"])
    pk = ints(c["fwd_pkts"]) + ints(c["bwd_pkts"])
    by = ints(c["fwd_bytes"]) + ints(c["bwd_bytes"])
    syn, ack = ints(c["syn"]), ints(c["ack"])
    ea = np.char.add(np.char.add(a_ip.astype(str), ":"), a_pt.astype(str))
    eb = np.char.add(np.char.add(b_ip.astype(str), ":"), b_pt.astype(str))
    lo, hi = np.where(ea <= eb, ea, eb), np.where(ea <= eb, eb, ea)
    return {"a": a_ip, "b": b_ip, "pa": a_pt, "pb": b_pt,
            "t_end": start * int(c["start_unit_us"]) + dur * int(c["duration_unit_us"]),
            "start": start, "canon": np.char.add(np.char.add(lo, "|"), hi), "pos": np.arange(len(df)),
            "pkts": pk, "bytes": by, "short": pk <= int(cx["short_flow_max_pkts"]), "sna": (syn > 0) & (ack == 0),
            "dur_us": dur * int(c["duration_unit_us"]), "n": int(len(df))}


def order(inp: dict) -> np.ndarray:
    return np.lexsort((inp["pos"], inp["canon"], inp["start"], inp["t_end"]))


def _pp(pa: str, pb: str) -> tuple:
    return (pa, pb) if pa <= pb else (pb, pa)


# --------------------------------------------------------------------------- streaming state
class _Win:
    __slots__ = ("ev", "n", "peers", "pps", "pk", "by", "sh", "sna", "du")

    def __init__(self):
        self.ev = deque()
        self.n = self.pk = self.by = self.sh = self.sna = self.du = 0
        self.peers: dict = {}
        self.pps: dict = {}

    def add(self, e):
        t, other, pp, pk, by, sh, sna, du = e
        self.ev.append(e)
        self.n += 1
        self.pk += pk
        self.by += by
        self.sh += sh
        self.sna += sna
        self.du += du
        self.peers[other] = self.peers.get(other, 0) + 1
        self.pps[pp] = self.pps.get(pp, 0) + 1

    def expire(self, t_lo: int):
        ev = self.ev
        while ev and ev[0][0] < t_lo:
            _, other, pp, pk, by, sh, sna, du = ev.popleft()
            self.n -= 1
            self.pk -= pk
            self.by -= by
            self.sh -= sh
            self.sna -= sna
            self.du -= du
            k = self.peers[other] - 1
            if k:
                self.peers[other] = k
            else:
                del self.peers[other]
            k = self.pps[pp] - 1
            if k:
                self.pps[pp] = k
            else:
                del self.pps[pp]

    def stats(self, pair: bool) -> list:
        n = self.n
        if n == 0:
            return [0.0] * (8 if pair else 7)
        out = [float(n), float(len(self.peers)), float(len(self.pps)), float(self.pk), float(self.by),
               self.sh / n, self.sna / n]
        if pair:
            out.append((self.du / n) / 1e6)
        return out


class ContextState:
    """Bounded streaming state for one segment (reset = a new instance)."""

    def __init__(self, cfg: dict):
        cx = cfg["context"]
        self.w_us = [int(w) * 1_000_000 for w in cx["windows_s"]]
        self.cap = {"host": int(cx["max_tracked_hosts"]), "pair": int(cx["max_tracked_pairs"])}
        self.keys = {"host": OrderedDict(), "pair": OrderedDict()}
        self.evictions = {"host": 0, "pair": 0}
        self.peak = {"host": 0, "pair": 0, "events": 0}
        self.events = 0

    def _get(self, kind: str, key):
        return self.keys[kind].get(key)

    def query(self, kind: str, key, t: int, pair: bool) -> list:
        ent = self._get(kind, key)
        out = []
        for wi, w in enumerate(self.w_us):
            if ent is None:
                out.append([0.0] * (8 if pair else 7))
                continue
            before = len(ent[wi].ev)
            ent[wi].expire(t - w)
            self.events -= before - len(ent[wi].ev)
            out.append(ent[wi].stats(pair))
        return out

    def insert(self, kind: str, key, e: tuple):
        d = self.keys[kind]
        ent = d.get(key)
        if ent is None:
            if len(d) >= self.cap[kind]:
                _, old = d.popitem(last=False)
                self.evictions[kind] += 1
                self.events -= sum(len(x.ev) for x in old)
            ent = [_Win() for _ in self.w_us]
            d[key] = ent
            self.peak[kind] = max(self.peak[kind], len(d))
        else:
            d.move_to_end(key)
        t = e[0]
        for wi, w in enumerate(self.w_us):
            before = len(ent[wi].ev)
            ent[wi].expire(t - w)
            ent[wi].add(e)
            self.events += len(ent[wi].ev) - before
        self.peak["events"] = max(self.peak["events"], self.events)


def _row(state: ContextState, inp: dict, i: int) -> list:
    t, a, b = int(inp["t_end"][i]), inp["a"][i], inp["b"][i]
    ha = state.query("host", a, t, False)
    hb = ha if b == a else state.query("host", b, t, False)
    pr = state.query("pair", (a, b) if a <= b else (b, a), t, True)
    out = []
    for wi in range(len(state.w_us)):
        out += [max(x, y) for x, y in zip(ha[wi], hb[wi])]
        out += [min(x, y) for x, y in zip(ha[wi], hb[wi])]
        out += pr[wi]
    return out


def _insert(state: ContextState, inp: dict, i: int) -> None:
    t, a, b = int(inp["t_end"][i]), inp["a"][i], inp["b"][i]
    pp = _pp(inp["pa"][i], inp["pb"][i])
    base = (int(inp["pkts"][i]), int(inp["bytes"][i]), int(inp["short"][i]), int(inp["sna"][i]), int(inp["dur_us"][i]))
    for h in ({a, b} if a != b else {a}):
        other = b if h == a and b != a else a
        state.insert("host", h, (t, other, pp) + base)
    pk = (a, b) if a <= b else (b, a)
    state.insert("pair", pk, (t, pk, pp) + base)


def compute(inp: dict, cfg: dict, state: ContextState | None = None, insert_mask=None) -> tuple[np.ndarray, dict]:
    """Context features in input row order. insert_mask (optional): only these flows enter the state (all are scored)."""
    st = state or ContextState(cfg)
    n = inp["n"]
    width = len(context_feature_names(cfg))
    F = np.zeros((n, width), dtype=np.float64)
    ordr = order(inp)
    te = inp["t_end"]
    ins = np.ones(n, bool) if insert_mask is None else np.asarray(insert_mask, bool)
    t0 = time.perf_counter()
    i = 0
    while i < n:
        j = i
        t = te[ordr[i]]
        while j < n and te[ordr[j]] == t:
            j += 1
        grp = ordr[i:j]
        for r in grp:
            F[r] = _row(st, inp, int(r))
        for r in grp:
            if ins[r]:
                _insert(st, inp, int(r))
        i = j
    dt = time.perf_counter() - t0
    info = {"n": n, "seconds": dt, "us_per_flow": 1e6 * dt / max(1, n), "evictions": dict(st.evictions),
            "peak_hosts": st.peak["host"], "peak_pairs": st.peak["pair"], "peak_events": st.peak["events"]}
    return F, info


# --------------------------------------------------------------------------- naive reference (checks only)
def naive(inp: dict, cfg: dict) -> np.ndarray:
    """O(n^2) reference with the same definitions (no eviction): recompute every window from scratch."""
    cx = cfg["context"]
    n = inp["n"]
    te = inp["t_end"]
    codes, uniq = pd.factorize(np.concatenate([inp["a"], inp["b"]]))
    A, B = codes[:n], codes[n:]
    pp = pd.factorize(pd.Series([_pp(x, y) for x, y in zip(inp["pa"], inp["pb"])], dtype=object))[0]
    lo, hi = np.minimum(A, B), np.maximum(A, B)
    pk, by, sh, sna, du = inp["pkts"], inp["bytes"], inp["short"].astype(np.int64), inp["sna"].astype(np.int64), inp["dur_us"]
    width = len(context_feature_names(cfg))
    F = np.zeros((n, width))

    def stats(m, other, pair):
        k = int(m.sum())
        if k == 0:
            return [0.0] * (8 if pair else 7)
        out = [float(k), float(len(np.unique(other[m]))), float(len(np.unique(pp[m]))), float(int(pk[m].sum())),
               float(int(by[m].sum())), int(sh[m].sum()) / k, int(sna[m].sum()) / k]
        if pair:
            out.append((int(du[m].sum()) / k) / 1e6)
        return out

    for i in range(n):
        row = []
        for w in cx["windows_s"]:
            win = (te >= te[i] - int(w) * 1_000_000) & (te < te[i])
            hv = []
            for H in (A[i], B[i]):
                m = win & ((A == H) | (B == H))
                other = np.where(A == H, B, A)
                hv.append(stats(m, other, False))
            row += [max(x, y) for x, y in zip(*hv)] + [min(x, y) for x, y in zip(*hv)]
            mp = win & (lo == lo[i]) & (hi == hi[i])
            row += stats(mp, lo * (int(codes.max()) + 1) + hi, True)
        F[i] = row
    return F


# --------------------------------------------------------------------------- dataset helper
def compute_segments(df: pd.DataFrame, cfg: dict, log=None, insert_mask=None) -> tuple[np.ndarray, np.ndarray, dict]:
    """State reset per segment (config segment_keys -> columns); ctx_warmup = t_end < segment start + largest window,
    segment start = the segment's first flow start (its split window opens at or before it). insert_mask (optional,
    df row order): only those flows enter the state (e.g. attack flows, for the contamination measure)."""
    im = None if insert_mask is None else np.asarray(insert_mask, bool)
    keys = [cfg["columns"][k] for k in cfg["context"]["segment_keys"]]
    width = len(context_feature_names(cfg))
    F = np.zeros((len(df), width))
    warm = np.zeros(len(df), np.int8)
    segs = []
    wmax = max(cfg["context"]["windows_s"]) * 1_000_000
    for key, ix in df.groupby(keys, sort=True).indices.items():
        sub = df.iloc[ix]
        inp = prepare(sub, cfg)
        Fs, info = compute(inp, cfg, insert_mask=None if im is None else im[ix])
        F[ix] = Fs
        seg_start = int(inp["start"].min()) * int(cfg["columns"]["start_unit_us"])
        warm[ix] = (inp["t_end"] < seg_start + wmax).astype(np.int8)
        info["segment"] = [str(k) for k in (key if isinstance(key, tuple) else (key,))]
        info["warmup"] = int(warm[ix].sum())
        segs.append(info)
        if log:
            log(f"    segment {info['segment']}: {info['n']:,} flows, {info['us_per_flow']:.1f} us/flow, evictions "
                f"{info['evictions']}, peak hosts {info['peak_hosts']} pairs {info['peak_pairs']} events "
                f"{info['peak_events']:,}, warm-up {info['warmup']:,}")
    return F, warm, {"segments": segs}
