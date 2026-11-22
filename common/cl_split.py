"""common/cl_split.py -- the Phase 4 val-A / val-B split (docs/V2_PREREG_PHASE4.md section 1).

    W = val_windows(split_definition, session, start_ts)   # {session: {"lo", "hi", "mid", "manifest_lo", ...}}
    part = assign(session, start_ts, W)                    # array of "val_A" / "val_B"

Rule: each session's val window is the interval the split definition labels "val" (boundaries_epoch + labels; an
open end when "val" is the last label). Its extent on the data is [max(window start, first val start_ts),
min(window end, last val start_ts)] -- an open window has no end of its own, and a window may begin long before its
first flow (a capture gap), so the data clip keeps the midpoint inside the window's flows. The window is cut at the
midpoint of that extent: start_ts < midpoint -> val_A (the "live period" the operator labels), else val_B (where every
model is judged). Data-agnostic: sessions come from the data and the split definition.
"""

from __future__ import annotations

import numpy as np

VAL = "val"
PARTS = ("val_A", "val_B")


class SplitError(ValueError):
    pass


def val_interval(sess_def: dict) -> tuple[float, float]:
    """[lo, hi) of the label "val" in one session's split definition (hi = +inf if val is the last label)."""
    labels, b = list(sess_def.get("labels", [])), list(sess_def.get("boundaries_epoch", []))
    if VAL not in labels:
        raise SplitError(f"session has no val window: labels {labels}")
    if len(b) != len(labels) - 1:
        raise SplitError(f"{len(labels)} labels need {len(labels) - 1} boundaries, got {len(b)}")
    i = labels.index(VAL)
    lo = -np.inf if i == 0 else float(b[i - 1])
    hi = np.inf if i == len(labels) - 1 else float(b[i])
    return lo, hi


def val_windows(split_def: dict, session, start_ts) -> dict:
    session = np.asarray(session).astype(str)
    start_ts = np.asarray(start_ts, dtype=np.float64)
    out = {}
    for s in sorted(set(session.tolist())):
        if s not in split_def["sessions"]:
            raise SplitError(f"session {s!r} not in the split definition")
        lo_m, hi_m = val_interval(split_def["sessions"][s])
        t = start_ts[session == s]
        outside = int(((t < lo_m) | (t >= hi_m)).sum())
        if outside:
            raise SplitError(f"session {s}: {outside} val rows outside the split definition's val window")
        lo, hi = max(lo_m, float(t.min())), min(hi_m, float(t.max()))
        out[s] = {"manifest_lo": lo_m, "manifest_hi": hi_m, "first_start": float(t.min()), "last_start": float(t.max()),
                  "lo": lo, "hi": hi, "mid": (lo + hi) / 2.0, "n": int(len(t))}
    return out


def assign(session, start_ts, windows: dict) -> np.ndarray:
    session = np.asarray(session).astype(str)
    start_ts = np.asarray(start_ts, dtype=np.float64)
    mid = np.array([windows[s]["mid"] for s in session], dtype=np.float64) if len(session) else np.zeros(0)
    return np.where(start_ts < mid, PARTS[0], PARTS[1])


def jsonable_windows(W: dict) -> dict:
    f = lambda x: None if not np.isfinite(x) else float(x)  # noqa: E731
    return {s: {k: (f(v) if isinstance(v, float) else v) for k, v in w.items()} for s, w in W.items()}
