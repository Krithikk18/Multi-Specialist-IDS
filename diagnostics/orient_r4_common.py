"""diagnostics/orient_r4_common.py -- shared, READ-ONLY helpers for the R4 orientation rule (derive + gate).

Structural predicates only (== 0, > 0, == 1, comparisons between two fields): no class, device, address or specific
window / port value appears in any predicate. Clause format = the format of config/orientation_rules.json:
  {"column": c, "op": op, "value": v}                       c op v
  {"column": a, "op": op, "column2": b}                     a op b
  {"column": a, "per": n, "op": op, "column2": b, "per2": m} a / n op b / m   (false when n or m is 0 / NaN)
Ground truth (EVALUATION ONLY, never inside a rule): the attack-source identity of V1 step 13 / Phase 3 D74
(diagnostics/diag_03_common.Hosts) and the inventory devices = device_table MACs whose role is one of the Phase 3
routing owner roles (config/v2_phase3.json routing.owner_roles).
"""

from __future__ import annotations

import json
import operator
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import REPO_ROOT  # noqa: E402

OPS = {"==": operator.eq, "!=": operator.ne, ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le}
PROTO, TCP = "Protocol", 6
NF, NB = "Total Fwd Packet", "Total Bwd packets"
FIW, BIW = "FWD Init Win Bytes", "Bwd Init Win Bytes"
FHL, BHL = "Fwd Header Length", "Bwd Header Length"
SPORT, DPORT = "Src Port", "Dst Port"
FLAGS = ["SYN Flag Count", "ACK Flag Count", "RST Flag Count", "FIN Flag Count", "PSH Flag Count", "CWR Flag Count",
         "ECE Flag Count"]
TCP_CLAUSE = {"column": PROTO, "op": "==", "value": TCP}
RULE_COLUMNS = [PROTO, NF, NB, FIW, BIW, FHL, BHL, SPORT, DPORT] + FLAGS


def predicates() -> list[dict]:
    """The candidate predicates (prompt step A2), in a fixed order; each {"name", "clause", "port": bool}."""
    P = []

    def add(name, clause, port=False):
        P.append({"name": name, "clause": clause, "port": port})

    add(f"{NF} == 1", {"column": NF, "op": "==", "value": 1})
    add(f"{NF} <= 2", {"column": NF, "op": "<=", "value": 2})
    add(f"{NB} == 0", {"column": NB, "op": "==", "value": 0})
    add(f"{NB} == 1", {"column": NB, "op": "==", "value": 1})
    add(f"{NB} >= 1", {"column": NB, "op": ">=", "value": 1})
    for f in FLAGS:
        for op, v in (("==", 0), ("==", 1), (">=", 1), ("==", 2)):
            add(f"{f} {op} {v}", {"column": f, "op": op, "value": v})
    add(f"{FIW} == 0", {"column": FIW, "op": "==", "value": 0})
    add(f"{FIW} > 0", {"column": FIW, "op": ">", "value": 0})
    add(f"{BIW} == 0", {"column": BIW, "op": "==", "value": 0})
    add(f"{BIW} > 0", {"column": BIW, "op": ">", "value": 0})
    add(f"{FIW} > {BIW}", {"column": FIW, "op": ">", "column2": BIW})
    for op in (">", "<", "=="):
        add(f"{FHL} / {NF} {op} {BHL} / {NB}", {"column": FHL, "per": NF, "op": op, "column2": BHL, "per2": NB})
    add(f"{SPORT} < {DPORT}", {"column": SPORT, "op": "<", "column2": DPORT}, port=True)
    return P


def _num(df: pd.DataFrame, c: str) -> np.ndarray:
    return pd.to_numeric(df[c], errors="coerce").to_numpy(np.float64)


def clause_mask(df: pd.DataFrame, c: dict) -> np.ndarray:
    a = _num(df, c["column"])
    with np.errstate(invalid="ignore", divide="ignore"):
        if "per" in c:
            n = _num(df, c["per"])
            a = np.where(n > 0, a / np.where(n > 0, n, 1), np.nan)
        if "column2" in c:
            b = _num(df, c["column2"])
            if "per2" in c:
                m = _num(df, c["per2"])
                b = np.where(m > 0, b / np.where(m > 0, m, 1), np.nan)
        else:
            b = np.full(len(a), float(c["value"]))
        return ~np.isnan(a) & ~np.isnan(b) & OPS[c["op"]](a, b)


def rule_mask(df: pd.DataFrame, clauses: list[dict]) -> np.ndarray:
    m = np.ones(len(df), bool)
    for c in clauses:
        m &= clause_mask(df, c)
    return m


def r3_clauses() -> list[dict]:
    """R3 from the pinned orientation map (machine.rule.all), as clauses."""
    from common import orientation as O
    from common import schemas as S
    omap = O.load_map(S.ORIENTATION_MAP_PATH, S.ORIENTATION_MAP_SHA256)
    return [{"column": c["column"], "op": c["op"], "value": c["value"]} for c in omap["machine"]["rule"]["all"]]


def describe(clauses: list[dict]) -> str:
    out = []
    for c in clauses:
        a = c["column"] + (f" / {c['per']}" if "per" in c else "")
        b = (c["column2"] + (f" / {c['per2']}" if "per2" in c else "")) if "column2" in c else f"{c['value']:g}"
        out.append(f"{a} {c['op']} {b}")
    return " AND ".join(out)


class Truth:
    """Evaluation-only labels for TCP attack rows: REVERSED = inventory device -> attack source; FORWARD = attack
    source -> inventory device. Attack source = the D74 identity; inventory = device_table owner-role MACs."""

    def __init__(self):
        from diagnostics.diag_03_common import Hosts
        self.hosts = Hosts()
        p3 = json.loads((REPO_ROOT / "config" / "v2_phase3.json").read_text(encoding="utf-8"))
        self.owner_roles = set(p3["routing"]["owner_roles"])
        self.inventory = {m for m, r in self.hosts.book.dev.role.items() if r in self.owner_roles}
        self._att: dict = {}

    def is_att(self, macs: np.ndarray) -> np.ndarray:
        out = np.empty(len(macs), bool)
        for i, m in enumerate(macs):
            v = self._att.get(m)
            if v is None:
                v = self._att[m] = self.hosts.is_attacker(str(m).lower())
            out[i] = v
        return out

    def is_inv(self, macs: np.ndarray) -> np.ndarray:
        return np.isin(np.char.lower(np.asarray(macs, dtype=str)), list(self.inventory))

    def labels(self, src: np.ndarray, dst: np.ndarray, proto: np.ndarray, y: np.ndarray, benign: int = 0) -> dict:
        tcp_att = (proto == TCP) & (y != benign)
        return {"REV": tcp_att & self.is_inv(src) & self.is_att(dst), "FWD": tcp_att & self.is_att(src) & self.is_inv(dst)}

    def describe(self) -> dict:
        return {"attack_source": self.hosts.describe(), "inventory_roles": sorted(self.owner_roles),
                "inventory_macs": len(self.inventory)}


def encode(df: pd.DataFrame, P: list[dict]) -> np.ndarray:
    """uint64 bit pattern per row: bit k = predicate k holds (<= 64 predicates)."""
    if len(P) > 64:
        raise ValueError("more than 64 predicates")
    code = np.zeros(len(df), np.uint64)
    for k, p in enumerate(P):
        code |= clause_mask(df, p["clause"]).astype(np.uint64) << np.uint64(k)
    return code
