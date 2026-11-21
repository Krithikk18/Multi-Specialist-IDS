"""common/orientation.py -- CICFlowMeter orientation normaliser (rule R3), driven entirely by config/orientation_map.json.

CICFlowMeter always writes a flow's first captured packet as "forward". When that packet is the victim's window-0
RST/ACK (the scanner's SYN arrives after it), the row is written backwards. R3 flags such rows and `swap` rewrites
them as if the other endpoint were the source (results/diag_02, results/orient_gate).

    omap = load_map()                                   # sha256-pinned in common/schemas.py (ORIENTATION_MAP_SHA256)
    df2 = normalise(df, omap)                           # offline, vectorised; adds bool column omap.machine.flag_column
    flow2 = normalise_flow(flow_dict, omap)             # Phase 3 runtime (one flow, pure Python, no pandas)

Both APIs give identical results (tests/test_orientation.py). Nothing here names a dataset value: column names,
rule clauses, handler columns and the Flow ID format all come from the map. Non-TCP rows are never changed
(machine.protocol_guard), the feature set and column order are unchanged (the flag column is appended), and
device / group / timestamp columns are never touched.
"""

from __future__ import annotations

import hashlib
import json
import math
import operator
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import CONFIG_DIR

MAP_PATH = CONFIG_DIR / "orientation_map.json"
_OPS = {"==": operator.eq, "!=": operator.ne, ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le}
_PAIR_CLASSES = ("pair", "pair_asymmetric")
_KNOWN = {"pair", "pair_asymmetric", "direction_free", "derived", "unpaired"}
_METHODS = {"int_div_swapped_counts", "min_header_from_bwd", "data_pkts_from_bwd", "first_pkt_flag_from_bwd"}


class OrientationError(ValueError):
    pass


# --------------------------------------------------------------------------- map
def load_map(path: Path = MAP_PATH, expected_sha256: str | None = None) -> dict:
    """Parse and check the map (LF only; sha256 == expected if given). Adds "_sha256" and "_path"."""
    raw = Path(path).read_bytes()
    if b"\r" in raw:
        raise OrientationError(f"{path}: CR bytes (the pin is over LF bytes)")
    sha = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and sha != expected_sha256:
        raise OrientationError(f"{path}: sha256 {sha} != pinned {expected_sha256}")
    m = json.loads(raw)
    check_map(m)
    m["_sha256"], m["_path"] = sha, str(path)
    return m


def check_map(m: dict) -> None:
    """Structural checks: every feature classified, pairs mutual, every derived / unpaired feature has a handler."""
    P = []
    F = m.get("features") or {}
    mc = m.get("machine") or {}
    for f, e in F.items():
        if e.get("class") not in _KNOWN:
            P.append(f"{f}: unknown class {e.get('class')!r}")
        if e.get("class") in _PAIR_CLASSES:
            p = e.get("partner")
            if p not in F or F[p].get("partner") != f or F[p].get("class") != e["class"]:
                P.append(f"{f}: partner {p!r} not mutual")
        if e.get("class") in ("derived", "unpaired") and f not in (mc.get("handlers") or {}):
            P.append(f"{f}: {e['class']} without a machine handler")
        if e.get("status") == "UNRESOLVED":
            P.append(f"{f}: UNRESOLVED")
    for f, h in (mc.get("handlers") or {}).items():
        if h.get("method") not in _METHODS:
            P.append(f"handler {f}: unknown method {h.get('method')!r}")
    for k in ("rule", "protocol_guard", "counts", "identity_pairs", "flow_id", "flag_column"):
        if k not in mc:
            P.append(f"machine.{k} missing")
    for c in (mc.get("rule") or {}).get("all", []):
        if c.get("op") not in _OPS:
            P.append(f"rule clause {c}: unknown op")
    if P:
        raise OrientationError("orientation map: " + "; ".join(P))


def feature_order(omap: dict) -> list[str]:
    return list(omap["features"])


# --------------------------------------------------------------------------- rule
def _num(v) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return math.nan
    return x


def _col(df: pd.DataFrame, c: str) -> np.ndarray:
    return pd.to_numeric(df[c], errors="coerce").to_numpy(np.float64)


def is_reversed(df: pd.DataFrame, omap: dict) -> np.ndarray:
    """Boolean array: the rule (every clause) holds; NaN / non-numeric in any rule column -> False."""
    m = np.ones(len(df), bool)
    for c in omap["machine"]["rule"]["all"]:
        v = _col(df, c["column"])
        with np.errstate(invalid="ignore"):
            m &= ~np.isnan(v) & _OPS[c["op"]](v, float(c["value"]))
    return m


def is_reversed_flow(flow: dict, omap: dict) -> bool:
    for c in omap["machine"]["rule"]["all"]:
        v = _num(flow.get(c["column"]))
        if math.isnan(v) or not _OPS[c["op"]](v, float(c["value"])):
            return False
    return True


def _guard(df: pd.DataFrame, omap: dict) -> np.ndarray:
    g = omap["machine"]["protocol_guard"]
    v = _col(df, g["column"])
    return ~np.isnan(v) & (v == float(g["value"]))


def _guard_flow(flow: dict, omap: dict) -> bool:
    g = omap["machine"]["protocol_guard"]
    v = _num(flow.get(g["column"]))
    return not math.isnan(v) and v == float(g["value"])


# --------------------------------------------------------------------------- handlers (scalar = vector, tested)
def _h_scalar(method: str, h: dict, f: dict, fname: str, nf: float, nb: float) -> float:
    if method == "int_div_swapped_counts":
        return float(math.floor(nf / nb)) if nb > 0 else 0.0
    if method == "min_header_from_bwd":
        bh = _num(f[h["bwd_header"]])
        return bh if nb == 1 else (float(math.floor(bh / nb)) if nb > 1 else 0.0)
    if method == "data_pkts_from_bwd":
        bmax, bmin, btot = _num(f[h["bwd_max"]]), _num(f[h["bwd_min"]]), _num(f[h["bwd_total"]])
        if nb <= 1 or bmax == 0:
            return 0.0
        if bmin >= 1:
            return nb - 1
        return max(0.0, float(math.ceil(btot / bmax)) - 1) if bmax > 0 else 0.0
    if method == "first_pkt_flag_from_bwd":
        rest = _num(f[h["flag_total"]]) - _num(f[fname])
        if rest <= 0:
            return 0.0
        return 1.0 if (nf == 1 and nb >= 1 and rest >= nb) else 0.0
    raise OrientationError(f"unknown method {method}")


def _h_vector(method: str, h: dict, sub: pd.DataFrame, fname: str, nf: np.ndarray, nb: np.ndarray) -> np.ndarray:
    with np.errstate(invalid="ignore", divide="ignore"):
        if method == "int_div_swapped_counts":
            return np.where(nb > 0, np.floor(nf / np.where(nb > 0, nb, 1)), 0.0)
        if method == "min_header_from_bwd":
            bh = _col(sub, h["bwd_header"])
            return np.where(nb == 1, bh, np.where(nb > 1, np.floor(bh / np.maximum(nb, 1)), 0.0))
        if method == "data_pkts_from_bwd":
            bmax, bmin, btot = _col(sub, h["bwd_max"]), _col(sub, h["bwd_min"]), _col(sub, h["bwd_total"])
            lb = np.where(bmax > 0, np.maximum(0.0, np.ceil(btot / np.where(bmax > 0, bmax, 1)) - 1), 0.0)
            return np.where((nb <= 1) | (bmax == 0), 0.0, np.where(bmin >= 1, nb - 1, lb))
        if method == "first_pkt_flag_from_bwd":
            rest = _col(sub, h["flag_total"]) - _col(sub, fname)
            return np.where(rest <= 0, 0.0, np.where((nf == 1) & (nb >= 1) & (rest >= nb), 1.0, 0.0))
    raise OrientationError(f"unknown method {method}")


def _flow_id(vals: dict, fid: dict) -> str:
    out = []
    for p in fid["parts"]:
        v = vals[p]
        if p in fid.get("int_parts", []):
            v = int(float(v))
        out.append(str(v))
    return fid["sep"].join(out)


# --------------------------------------------------------------------------- swap
def swap(df: pd.DataFrame, mask: np.ndarray, omap: dict) -> pd.DataFrame:
    """Copy of df with the rows in mask (AND the protocol guard) rewritten per the map. Columns absent from df are
    skipped (identity columns are optional); every feature column of the map must be present."""
    F, mc = omap["features"], omap["machine"]
    miss = [f for f in F if f not in df.columns]
    if miss:
        raise OrientationError(f"feature columns missing: {miss}")
    out = df.copy()
    idx = np.flatnonzero(np.asarray(mask, bool) & _guard(df, omap))
    if not len(idx):
        return out
    sub = df.iloc[idx]
    nf, nb = _col(sub, mc["counts"]["fwd"]), _col(sub, mc["counts"]["bwd"])
    new = {}
    for f, e in F.items():
        if e["class"] in _PAIR_CLASSES:
            new[f] = sub[e["partner"]].to_numpy()
        elif e["class"] in ("derived", "unpaired"):
            h = mc["handlers"][f]
            new[f] = _h_vector(h["method"], h, sub, f, nf, nb)
    for a, b in mc["identity_pairs"]:
        if a in df.columns and b in df.columns:
            new[a], new[b] = sub[b].to_numpy(), sub[a].to_numpy()
    for c, v in new.items():
        j = out.columns.get_loc(c)
        out.iloc[idx, j] = np.asarray(v, dtype=out[c].dtype) if pd.api.types.is_numeric_dtype(out[c].dtype) else v
    fid = mc["flow_id"]
    if fid["column"] in df.columns and all(p in df.columns for p in fid["parts"]):
        s = out.iloc[idx]
        parts = [(pd.to_numeric(s[p]).astype(np.int64).astype(str) if p in fid.get("int_parts", []) else s[p].astype(str))
                 for p in fid["parts"]]
        acc = parts[0]
        for p in parts[1:]:
            acc = acc + fid["sep"] + p
        out.iloc[idx, out.columns.get_loc(fid["column"])] = acc.to_numpy()
    return out


def swap_flow(flow: dict, omap: dict) -> dict:
    """One flow (dict column -> value) rewritten per the map; non-TCP flows are returned unchanged (copy)."""
    out = dict(flow)
    if not _guard_flow(flow, omap):
        return out
    F, mc = omap["features"], omap["machine"]
    nf, nb = _num(flow[mc["counts"]["fwd"]]), _num(flow[mc["counts"]["bwd"]])
    for f, e in F.items():
        if e["class"] in _PAIR_CLASSES:
            out[f] = flow[e["partner"]]
        elif e["class"] in ("derived", "unpaired"):
            h = mc["handlers"][f]
            out[f] = _h_scalar(h["method"], h, flow, f, nf, nb)
    for a, b in mc["identity_pairs"]:
        if a in flow and b in flow:
            out[a], out[b] = flow[b], flow[a]
    fid = mc["flow_id"]
    if fid["column"] in flow and all(p in out for p in fid["parts"]):
        out[fid["column"]] = _flow_id(out, fid)
    return out


# --------------------------------------------------------------------------- normalise
def normalise(df: pd.DataFrame, omap: dict) -> pd.DataFrame:
    """Flag (rule) + swap; appends the bool flag column. Refuses a frame that already has the flag column."""
    fc = omap["machine"]["flag_column"]
    if fc in df.columns:
        raise OrientationError(f"column {fc!r} already present: the frame is already normalised")
    m = is_reversed(df, omap) & _guard(df, omap)
    out = swap(df, m, omap)
    out[fc] = m
    return out


def normalise_flow(flow: dict, omap: dict) -> dict:
    fc = omap["machine"]["flag_column"]
    if fc in flow:
        raise OrientationError(f"key {fc!r} already present: the flow is already normalised")
    rev = is_reversed_flow(flow, omap) and _guard_flow(flow, omap)
    out = swap_flow(flow, omap) if rev else dict(flow)
    out[fc] = bool(rev)
    return out
