#!/usr/bin/env python
"""common/schemas.py -- V2 dataset contract: class map, label encoding, column contract, two-stage
frame validation, and the V2 lock (verify_v2_lock).

Import from scripts run at the repo root:
    from common.schemas import load_class_map, encode_labels, to_binary, validate_schema, validate_rows

`python -m common.schemas` prints verify_v2_lock(); exit 1 on failure.

Pins (V1's config/config.py is never edited; it must stay byte-identical to the step 10 prereg):
  CLASS_MAP_SHA256     sha256 of config/class_map.json's exact bytes (LF only; a CR byte fails)
  FEATURES_V1_SHA256   sha256 of config/features_v1.json's bytes = step10_prereg features.file_sha256
  CONFIG_PY_SHA256     sha256 of config/config.py = step10_prereg inputs_sha256["config/config.py"]
  STEP10_PREREG_SHA256 sha256 of config/step10_prereg.json itself (so the pins above cannot be
                       re-recorded there to match an edited file)

Sources (SOURCE_RULES): per source, the raw label vocabulary and the LAN subnets used by the MAC rule.
  v1_cicflowmeter  07_label_attacks.py output; labels {attack, benign, excluded}; LAN = V1 config
                   NETWORK.subnets (CICIoT2023 testbed). Another source (e.g. the Networking team's
                   captures) adds its own entry, or callers pass lan_subnets explicitly.

Labels
  key = attack_family if label == "attack" else label; key -> canonical name via the class map's
  aliases[source]; name -> id. Hard errors (all problems collected, values and counts listed):
  label outside the source vocabulary; label "excluded" reaching the encoder (V1's 08 filter must
  reject those rows first); attack with empty attack_family; benign with a non-empty attack_family;
  a key not in aliases[source] (e.g. an attack_family the class map lacks).
  benign_night has no label columns: callers declare assume_label="benign" for that input only;
  a declaration on a frame that HAS a label column is an error.

Column contract (V1 names)
  features   the 70 columns of config/features_v1.json, all present, numeric, in that relative order
             (CICFlowMeter interleaves identity columns, e.g. Protocol is feature 1 and sits between
             Dst Port and Timestamp). The 7 columns 08 dropped as constant in train are tolerated.
  required   Flow ID, Src IP, Src Port, Dst IP, Dst Port, Timestamp, src_mac, dst_mac, owner_status,
             exclude_reason, owner_mac, owner_device, owner_category, session (+ label,
             attack_family unless assume_label). Protocol is a feature, checked there.
  tolerated  CICFlowMeter's Label ("NeedManualLabel") and 04 / 07's other tag and label columns.
  anything else is an extra column -> fail.

Two stages (neither mutates its input; each returns a JSON-able report with "checks" and "ok")
  validate_schema  RAW chunk, before any filter -- schema problems must not hide inside rejected rows:
                   column presence / order / extras, numeric feature dtypes, Timestamp parsing
                   (TS_FORMAT = 04_tag_flows.TS_FORMAT, dd/mm/YYYY hh:mm:ss AM/PM, tz=UTC attached
                   explicitly, justification TS_JUSTIFICATION; any unparseable value fails), and the
                   raw label vocabulary over ALL rows (label in the source vocabulary; attack_family
                   set iff label == attack, 07's own invariant)
  validate_rows    rows kept by V1's filter: identity columns non-null (Flow ID, IPs, ports, the
                   owner / device MAC column, session); blank src_mac / dst_mac allowed only for an
                   off-LAN endpoint, counted per reason (public, broadcast, multicast, off_lan_private)
                   -- lan_unicast or invalid_ip fails; labels encode; NaN / +-inf counted per feature
                   (V1 policy NaN / +-inf -> 0, not a failure; apply_nan_inf_policy() cleans a copy)
  validate_frame   both on one frame (tests, small inputs). merge_reports() sums per-chunk reports.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import CONFIG_DIR, EXTRACTOR, NETWORK, REPO_ROOT, LockError, sha256_file, verify_lock

# --------------------------------------------------------------------------- pins
CLASS_MAP_PATH = CONFIG_DIR / "class_map.json"
CLASS_MAP_SHA256 = "64063149b74d09f6caf458906809361e121844eab5c31fdcc28c50578e357580"
FEATURES_PATH = CONFIG_DIR / "features_v1.json"
FEATURES_V1_SHA256 = "623d0d2483670f34b1e0332da87eb9897854c31b35486e01b8675850e0eb7db8"   # file bytes
FEATURES_V1_LIST_SHA256 = "cf73976fd384a46609789d952d803b695cf462557595b02838066d4b3285ce5c"  # its own field
CONFIG_PY_PATH = CONFIG_DIR / "config.py"
CONFIG_PY_SHA256 = "c19bf4ffe4ee25a959c19d38d820e903511211e42018876364d272e61003ddcf"
STEP10_PREREG_PATH = CONFIG_DIR / "step10_prereg.json"
STEP10_PREREG_SHA256 = "17f627f841263e943ae0df0fa0758bb94e924cce9da0cce414856052976b59aa"
PREREG_PHASE2_PATH = REPO_ROOT / "docs" / "V2_PREREG_PHASE2.md"
PREREG_PHASE2_SHA256 = "ba6993e98b96a575f31091b215362d6c99702a51ba3042496a6e11440e4d3e49"   # file bytes (LF)
# Phase 2 closeout (docs/V2_DECISIONS.md D39+): the orientation normaliser's map (rule R3) -- file bytes (LF)
ORIENTATION_MAP_PATH = CONFIG_DIR / "orientation_map.json"
ORIENTATION_MAP_SHA256 = "09d62055760943be26ff55335b4f5fccc5ac598ed5e981d7df7bffc92bd2a022"
# Phase 2 closeout: Amendment 1 to the Phase 2 pre-registration (v2_1_oriented data + A1 selection rule) -- bytes (LF)
PREREG_PHASE2_AMENDMENT_1_PATH = REPO_ROOT / "docs" / "V2_PREREG_PHASE2_AMENDMENT_1.md"
PREREG_PHASE2_AMENDMENT_1_SHA256 = "c436599da4216c3e4a1a91db51e852436e88bc0c5ac4992cc64e4716b865b20f"
# Phase 3 step 0: Amendment 2 (Stage 1 primary = FLAT_GLOBAL; pre-registered routing tests for Phases 4 / 5) -- bytes (LF)
PREREG_PHASE2_AMENDMENT_2_PATH = REPO_ROOT / "docs" / "V2_PREREG_PHASE2_AMENDMENT_2.md"
PREREG_PHASE2_AMENDMENT_2_SHA256 = "075f738ea48639fd0f9422ccff42052c32aa9ebec508e9da9e10f5576ba35e46"
# Phase 3 step B: streaming-runtime pre-registration + the runtime policy config (integrity-checked at startup, DFD P5)
PREREG_PHASE3_PATH = REPO_ROOT / "docs" / "V2_PREREG_PHASE3.md"
PREREG_PHASE3_SHA256 = "14ff67c4f1200a89ac47226b480bf45575ba1c8c48794193aa9903c4ed4017ab"
V2_PHASE3_CONFIG_PATH = CONFIG_DIR / "v2_phase3.json"
V2_PHASE3_CONFIG_SHA256 = "398ee6b73ff7a1458563da9073d2221518d6e6e437478a14bd827f46899ac692"
V2_PHASE3_1_CONFIG_PATH = CONFIG_DIR / "v2_phase3_1.json"
V2_PHASE3_1_CONFIG_SHA256 = "14e45250569f3deef0cdbd80bd32880c8ff24c76a4c0c7dbe3bf9c56a898a9e4"   # Phase 3.1 runtime config
# Phase 4 step A: continual-learning pre-registration + its parameter file, pinned before any val-A run / label / retrain
PREREG_PHASE4_PATH = REPO_ROOT / "docs" / "V2_PREREG_PHASE4.md"
PREREG_PHASE4_SHA256 = "63fe91834e4a7e45c5b237fec5af9e5283a537f82dd942e72c155204154810ac"
V2_PHASE4_CONFIG_PATH = CONFIG_DIR / "v2_phase4.json"
V2_PHASE4_CONFIG_SHA256 = "1c2ab2cb232a906d6d532a2d2e2076c1be4bbd22bd1199a5f3117f44a59e3555"

# --------------------------------------------------------------------------- column contract (V1 names)
TS_FORMAT = "%d/%m/%Y %I:%M:%S %p"          # == 04_tag_flows.TS_FORMAT (asserted in tests)
TS_TZ = "UTC"
TS_JUSTIFICATION = (f"extractor TZ={EXTRACTOR.tz} lock (config/config.py EXTRACTOR.tz): CICFlowMeter writes "
                    f"naive local-time strings and the JVM is always started with TZ=UTC")
ID_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp"]   # 08 IDENTITY_COLS - Label
MAC_COLS = ["src_mac", "dst_mac"]
V1_META_COLS = ["owner_status", "exclude_reason", "owner_mac", "owner_device", "owner_category"]  # == 08
LABEL_COLS = ["label", "attack_family"]                                          # == 08 LABEL_COLS
SESSION_COL = "session"
REQUIRED_META = ID_COLS + MAC_COLS + V1_META_COLS + [SESSION_COL]
NON_NULL_BASE = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", SESSION_COL]   # + owner column
TOLERATED_COLS = ["Label", "src_device", "src_role", "dst_device", "dst_role", "owner_rule",
                  "owner_resolution", "ambiguous_reason", "label_tests", "label_exclude_reason", "pad_only"]
MAC_IP = {"src_mac": "Src IP", "dst_mac": "Dst IP"}
BLANK_MAC_OK = ("public", "broadcast", "multicast", "off_lan_private")
BLANK_MAC_BAD = ("lan_unicast", "invalid_ip")
NAN_INF_POLICY = "NaN and +-inf -> 0 before the model (features_v1.json 'clean', V1 08); counted, not a failure"

# Per-source label rules and LAN subnets; the alias tables themselves live in config/class_map.json.
SOURCE_RULES = {
    "v1_cicflowmeter": {"label_values": ("attack", "benign", "excluded"), "attack": "attack",
                        "benign": "benign", "excluded": "excluded",
                        "lan_subnets": tuple(NETWORK.subnets),
                        "lan_subnets_from": "config/config.py NETWORK.subnets (V1 / CICIoT2023 testbed)"},
}


class SchemaError(ValueError):
    pass


def _rules(source: str) -> dict:
    if source not in SOURCE_RULES:
        raise SchemaError(f"unknown source {source!r}: rules exist for {sorted(SOURCE_RULES)}")
    return SOURCE_RULES[source]


# --------------------------------------------------------------------------- class map
@dataclass(frozen=True)
class ClassMap:
    version: int
    names: tuple[str, ...]           # index == id
    aliases: dict
    sha256: str
    path: str

    @property
    def n_classes(self) -> int:
        return len(self.names)

    def id_of(self, name: str) -> int:
        return self.names.index(name)


def load_class_map(path: Path = CLASS_MAP_PATH, expected_sha256: str = CLASS_MAP_SHA256) -> ClassMap:
    """Load and verify the class map: no CR bytes, sha256 of the bytes == expected_sha256, ids
    contiguous from 0 in list order, benign == 0, names unique, alias targets are classes."""
    path = Path(path)
    raw = path.read_bytes()
    if b"\r" in raw:
        raise SchemaError(f"{path}: contains CR bytes (CRLF line endings); the pinned bytes are LF only")
    got = hashlib.sha256(raw).hexdigest()
    if got != expected_sha256:
        raise SchemaError(f"{path}: sha256 {got} != pinned {expected_sha256} (file edited or reordered? "
                          f"a new class map version must update CLASS_MAP_SHA256 in common/schemas.py)")
    cm = json.loads(raw)
    if set(cm) != {"version", "classes", "aliases", "notes"}:
        raise SchemaError(f"{path}: fields {sorted(cm)} != ['aliases', 'classes', 'notes', 'version']")
    ids = [c["id"] for c in cm["classes"]]
    names = [c["name"] for c in cm["classes"]]
    if ids != list(range(len(ids))):
        raise SchemaError(f"{path}: class ids {ids} are not contiguous from 0 in list order")
    if not names or names[0] != "benign":
        raise SchemaError(f"{path}: id 0 is {names[:1]}, must be 'benign'")
    if len(set(names)) != len(names):
        raise SchemaError(f"{path}: duplicate class names {names}")
    for src, table in cm["aliases"].items():
        bad = {k: v for k, v in table.items() if v not in names}
        if bad:
            raise SchemaError(f"{path}: aliases[{src}] map to unknown classes {bad}")
    return ClassMap(version=cm["version"], names=tuple(names), aliases=cm["aliases"], sha256=got, path=str(path))


@functools.lru_cache(maxsize=1)
def _default_class_map() -> ClassMap:
    return load_class_map()


def _cm(cm: ClassMap | None) -> ClassMap:
    return cm if cm is not None else _default_class_map()


# --------------------------------------------------------------------------- features
def load_features(path: Path = FEATURES_PATH, expected_sha256: str = FEATURES_V1_SHA256) -> dict:
    """features_v1.json, verified: file-bytes sha256 == pin (step10_prereg), its list hash ==
    its own sha256 field == FEATURES_V1_LIST_SHA256, 70 unique names."""
    path = Path(path)
    got = sha256_file(path)
    if got != expected_sha256:
        raise SchemaError(f"{path}: sha256 {got} != pinned {expected_sha256} (step10_prereg features.file_sha256)")
    F = json.loads(path.read_bytes())
    feats = F["features"]
    lsha = hashlib.sha256(json.dumps(feats, separators=(",", ":")).encode("utf-8")).hexdigest()
    if not (lsha == F.get("sha256") == FEATURES_V1_LIST_SHA256):
        raise SchemaError(f"{path}: list sha256 {lsha} / own field {F.get('sha256')} != {FEATURES_V1_LIST_SHA256}")
    if len(feats) != F["n_features"] or len(set(feats)) != len(feats) or len(feats) != 70:
        raise SchemaError(f"{path}: {len(feats)} features ({len(set(feats))} unique), expected 70 unique")
    return F


@functools.lru_cache(maxsize=1)
def _features_json() -> dict:
    return load_features()


def feature_columns() -> list[str]:
    return list(_features_json()["features"])


def dropped_constant_columns() -> list[str]:
    return list(_features_json()["dropped_constant_in_train"])


# --------------------------------------------------------------------------- labels
def _counts(s: pd.Series) -> dict:
    return {str(k): int(v) for k, v in s.value_counts(dropna=False).items()}


def labels_for(df: pd.DataFrame, assume_label: str | None = None) -> tuple[pd.Series, pd.Series]:
    """(label, attack_family) of a frame. assume_label (e.g. "benign" for benign_night) is allowed
    only when the frame has no label column; the family is then blank."""
    if assume_label is not None:
        present = [c for c in LABEL_COLS if c in df.columns]
        if present:
            raise SchemaError(f"assume_label={assume_label!r} declared but the frame has {present}")
        return (pd.Series(assume_label, index=df.index, dtype=object),
                pd.Series("", index=df.index, dtype=object))
    miss = [c for c in LABEL_COLS if c not in df.columns]
    if miss:
        raise SchemaError(f"label columns {miss} missing and no assume_label declared for this input")
    return df["label"], df["attack_family"]


def _norm_labels(label: pd.Series, attack_family: pd.Series) -> tuple[pd.Series, pd.Series]:
    if len(label) != len(attack_family):
        raise SchemaError(f"label ({len(label)}) and attack_family ({len(attack_family)}) lengths differ")
    lab = pd.Series(label.to_numpy(object), dtype=object)
    lab = lab.where(lab.notna(), "<NA>").astype(str)
    fam = pd.Series(attack_family.to_numpy(object), dtype=object)
    fam = fam.where(fam.notna(), "").astype(str)
    return lab, fam


def raw_label_problems(label: pd.Series, attack_family: pd.Series, source: str) -> list[str]:
    """07's invariants over ALL raw rows (before any filter): label in the source vocabulary, and
    attack_family non-empty iff label == attack. Returns the problems (empty list = clean)."""
    R = _rules(source)
    lab, fam = _norm_labels(label, attack_family)
    errs = []
    bad = ~lab.isin(R["label_values"])
    if bad.any():
        errs.append(f"label values outside {list(R['label_values'])}: {_counts(lab[bad])}")
    att = lab == R["attack"]
    if (att & fam.eq("")).any():
        errs.append(f"{int((att & fam.eq('')).sum())} rows with label {R['attack']!r} and an empty attack_family")
    nonatt_fam = ~att & ~bad & fam.ne("")
    if nonatt_fam.any():
        errs.append(f"rows with a non-attack label but a non-empty attack_family (inconsistent labelling): "
                    f"{_counts(lab[nonatt_fam] + '/' + fam[nonatt_fam])}")
    return errs


def encode_labels(label: pd.Series, attack_family: pd.Series, source: str, cm: ClassMap | None = None) -> pd.Series:
    """Raw (label, attack_family) -> class id (int8 Series, label's index, name "label_id").
    Raises SchemaError listing every offending value with its count; never drops a row."""
    cm = _cm(cm)
    R = _rules(source)
    if source not in cm.aliases:
        raise SchemaError(f"unknown source {source!r}: class map has aliases for {sorted(cm.aliases)}")
    table = cm.aliases[source]
    lab, fam = _norm_labels(label, attack_family)
    errs = []
    bad = ~lab.isin(R["label_values"])
    if bad.any():
        errs.append(f"label values outside {list(R['label_values'])}: {_counts(lab[bad])}")
    exc = lab == R["excluded"]
    if exc.any():
        errs.append(f"{int(exc.sum())} rows with label {R['excluded']!r} reached the encoder "
                    f"(V1's 08 filter must reject them first)")
    att = lab == R["attack"]
    if (att & fam.eq("")).any():
        errs.append(f"{int((att & fam.eq('')).sum())} rows with label {R['attack']!r} and an empty attack_family")
    benf = (lab == R["benign"]) & fam.ne("")
    if benf.any():
        errs.append(f"rows with label {R['benign']!r} but a non-empty attack_family "
                    f"(inconsistent labelling): {_counts(fam[benf])}")
    key = fam.where(att, lab)
    ok_rows = ~bad & ~exc & ~(att & fam.eq(""))
    unk = ok_rows & ~key.isin(list(table))
    if unk.any():
        errs.append(f"keys not in class_map aliases[{source}] {sorted(table)}: {_counts(key[unk])}")
    if errs:
        raise SchemaError(f"encode_labels({source}): " + "; ".join(errs))
    name_to_id = {n: i for i, n in enumerate(cm.names)}
    ids = key.map(table).map(name_to_id).to_numpy(np.int8)
    return pd.Series(ids, index=label.index, name="label_id")


def to_binary(ids, cm: ClassMap | None = None):
    """0 for benign (id 0), 1 for every other class (the bridge to V1's y). Integer ids only; any id
    outside [0, n_classes) raises. Returns int8, as a Series (same index, name "y") for a Series."""
    cm = _cm(cm)
    arr = np.asarray(ids)
    if arr.dtype == bool or not np.issubdtype(arr.dtype, np.integer):
        raise SchemaError(f"to_binary: ids must be integers, got dtype {arr.dtype}")
    out_of_range = (arr < 0) | (arr >= cm.n_classes)
    if out_of_range.any():
        raise SchemaError(f"to_binary: ids outside [0, {cm.n_classes}): "
                          f"{sorted(set(arr[out_of_range].tolist()))[:10]}")
    y = (arr != 0).astype(np.int8)
    return pd.Series(y, index=ids.index, name="y") if isinstance(ids, pd.Series) else y


# --------------------------------------------------------------------------- timestamps
def parse_timestamps(ts: pd.Series) -> pd.Series:
    """CICFlowMeter Timestamp strings -> tz-aware UTC datetimes (explicit TS_FORMAT, tz attached per
    TS_JUSTIFICATION). Raises SchemaError on any unparseable value. Tz-aware input must be UTC."""
    if isinstance(ts.dtype, pd.DatetimeTZDtype):
        if str(ts.dt.tz) != TS_TZ:
            raise SchemaError(f"Timestamp tz is {ts.dt.tz}, expected {TS_TZ}")
        return ts
    if pd.api.types.is_datetime64_dtype(ts.dtype):
        raise SchemaError("Timestamp is a naive datetime; expected strings in TS_FORMAT or tz-aware UTC")
    t = pd.to_datetime(ts, format=TS_FORMAT, errors="coerce").dt.tz_localize(TS_TZ)
    bad = t.isna()
    if bad.any():
        raise SchemaError(f"{int(bad.sum())} unparseable Timestamps (format {TS_FORMAT!r}), "
                          f"e.g. {ts[bad].head(3).tolist()}")
    return t


def _timestamp_report(df: pd.DataFrame) -> dict:
    T = {"format": TS_FORMAT, "tz": TS_TZ, "justification": TS_JUSTIFICATION, "unparseable": 0,
         "examples": [], "error": None, "min_utc": None, "max_utc": None}
    if "Timestamp" not in df.columns:
        return T
    ts, t = df["Timestamp"], None
    if isinstance(ts.dtype, pd.DatetimeTZDtype) or pd.api.types.is_datetime64_dtype(ts.dtype):
        try:
            t = parse_timestamps(ts)
        except SchemaError as e:
            T["error"] = str(e)
    else:
        t = pd.to_datetime(ts, format=TS_FORMAT, errors="coerce").dt.tz_localize(TS_TZ)
        bad = t.isna()
        T["unparseable"] = int(bad.sum())
        T["examples"] = [str(x) for x in ts[bad].head(3).tolist()]
    if t is not None and t.notna().any():
        T["min_utc"], T["max_utc"] = t.min().isoformat(), t.max().isoformat()
    return T


# --------------------------------------------------------------------------- MAC rule
def _blank(s: pd.Series) -> pd.Series:
    """True where null or whitespace-only; a plain bool Series (pandas 3 string dtype can yield NA)."""
    isna = s.isna().to_numpy(dtype=bool)
    empty = (s.astype(object).where(~isna, "").astype(str).str.strip() == "").to_numpy(dtype=bool)
    return pd.Series(isna | empty, index=s.index)


def lan_networks(source: str, override=None) -> tuple:
    """The LAN subnets for the MAC rule: `override` if given, else the source's SOURCE_RULES entry."""
    nets = list(override) if override is not None else list(_rules(source)["lan_subnets"])
    try:
        return tuple(ipaddress.ip_network(n) for n in nets)
    except ValueError as e:
        raise SchemaError(f"bad LAN subnet in {nets}: {e}") from None


def blank_mac_reason(ip, nets: tuple) -> str:
    """Why an endpoint may have no MAC: public | broadcast | multicast | off_lan_private (allowed:
    04 resolves MACs from the LAN IP map only) or lan_unicast | invalid_ip (fail)."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "invalid_ip"
    if a.is_multicast:
        return "multicast"
    if a.version == 4 and str(a) == "255.255.255.255":
        return "broadcast"
    for net in nets:
        if a.version == net.version and a in net:
            return "broadcast" if a == net.broadcast_address else "lan_unicast"
    return "off_lan_private" if a.is_private else "public"


# --------------------------------------------------------------------------- stage 1: schema (raw chunk)
def _check_columns(cols: list[str], feats: list[str], assume_label: str | None) -> dict:
    present = [c for c in cols if c in feats]
    required = REQUIRED_META + ([] if assume_label is not None else LABEL_COLS)
    known = set(feats) | set(REQUIRED_META) | set(LABEL_COLS) | set(TOLERATED_COLS) | set(dropped_constant_columns())
    return {
        "missing_features": [c for c in feats if c not in cols],
        "features_in_order": present == [c for c in feats if c in cols],
        "duplicate_columns": sorted({c for c in cols if cols.count(c) > 1}),
        "extra_columns": [c for c in cols if c not in known],
        "missing_meta": [c for c in required if c not in cols],
        "label_columns_declared_absent": assume_label is not None,
        "tolerated_present": [c for c in cols if c in set(TOLERATED_COLS) | set(dropped_constant_columns())],
    }


def validate_schema(df: pd.DataFrame, source: str = "v1_cicflowmeter", assume_label: str | None = None,
                    columns: list[str] | None = None) -> dict:
    """Stage 1 on a RAW chunk (all rows, before any filter). `columns` = the file's full header (+ the
    session column the reader adds) when df holds only a subset of it; default df.columns."""
    _rules(source)
    feats = feature_columns()
    cols = [str(c) for c in (columns if columns is not None else df.columns)]
    R: dict = {"stage": "schema", "n_rows": int(len(df)), "source": source, "assume_label": assume_label,
               "columns": _check_columns(cols, feats, assume_label)}
    R["non_numeric"] = {c: str(df[c].dtype) for c in feats if c in df.columns
                        and (df[c].dtype == bool or not pd.api.types.is_numeric_dtype(df[c].dtype))}
    R["timestamps"] = _timestamp_report(df)
    V = {"counts": {}, "problems": []}
    if assume_label is not None:
        if any(c in df.columns or c in cols for c in LABEL_COLS):
            V["problems"].append(f"assume_label={assume_label!r} declared but the input has label columns")
        else:
            V["counts"] = {f"{assume_label} (declared)": int(len(df))}
    elif all(c in df.columns for c in LABEL_COLS):
        lab, fam = _norm_labels(df["label"], df["attack_family"])
        V["counts"] = _counts(lab + "/" + fam)
        V["problems"] = raw_label_problems(df["label"], df["attack_family"], source)
    R["raw_labels"] = V
    R["checks"] = _checks(R)
    R["ok"] = all(c["pass"] for c in R["checks"])
    return R


# --------------------------------------------------------------------------- stage 2: rows (after filter)
def validate_rows(df: pd.DataFrame, source: str = "v1_cicflowmeter", assume_label: str | None = None,
                  cm: ClassMap | None = None, lan_subnets=None, owner_col: str = "owner_mac") -> dict:
    """Stage 2 on the rows kept by V1's filter. owner_col = the column holding the device MAC (08b keeps
    unregistered-MAC rows whose raw owner_mac is blank; their device MAC comes from its filter)."""
    feats = feature_columns()
    nets = lan_networks(source, lan_subnets)
    R: dict = {"stage": "rows", "n_rows": int(len(df)), "source": source, "assume_label": assume_label,
               "lan_subnets": [str(n) for n in nets], "owner_col": owner_col, "nan_inf_policy": NAN_INF_POLICY}
    R["nan_inf"] = {}
    for c in feats:
        if c in df.columns and pd.api.types.is_numeric_dtype(df[c].dtype) and df[c].dtype != bool:
            v = df[c].to_numpy(dtype=np.float64, copy=False)
            R["nan_inf"][c] = {"nan": int(np.isnan(v).sum()), "inf": int(np.isinf(v).sum())}
    R["nulls"] = {c: (int(_blank(df[c]).sum()) if c in df.columns else int(len(df)))
                  for c in NON_NULL_BASE + [owner_col]}
    R["blank_mac"], R["blank_mac_examples"] = {}, {}
    for m, ipc in MAC_IP.items():
        counts = {r: 0 for r in BLANK_MAC_OK + BLANK_MAC_BAD}
        ex: list = []
        if m in df.columns and ipc in df.columns:
            b = _blank(df[m])
            ips = df.loc[b.to_numpy(), ipc].astype(str)
            if len(ips):
                reason = ips.map({u: blank_mac_reason(u, nets) for u in ips.unique()})
                for r, n in reason.value_counts().items():
                    counts[r] += int(n)
                ex = ips[reason.isin(BLANK_MAC_BAD)].head(3).tolist()
        R["blank_mac"][m], R["blank_mac_examples"][m] = counts, ex
    L = {"counts": {}, "error": None}
    try:
        lab, fam = labels_for(df, assume_label)
        ids = encode_labels(lab, fam, source, cm)
        names = _cm(cm).names
        L["counts"] = {names[i]: int(n) for i, n in sorted(ids.value_counts().items())}
    except SchemaError as e:
        L["error"] = str(e)
    R["labels"] = L
    R["checks"] = _checks(R)
    R["ok"] = all(c["pass"] for c in R["checks"])
    return R


def validate_frame(df: pd.DataFrame, source: str = "v1_cicflowmeter", assume_label: str | None = None,
                   cm: ClassMap | None = None, lan_subnets=None, owner_col: str = "owner_mac") -> dict:
    """Both stages on one frame (already filtered rows). Flat union of the two reports."""
    A = validate_schema(df, source, assume_label)
    B = validate_rows(df, source, assume_label, cm, lan_subnets, owner_col)
    R = {**A, **B, "stage": "frame"}
    R["checks"] = _checks(R)
    R["ok"] = all(c["pass"] for c in R["checks"])
    return R


# --------------------------------------------------------------------------- checks + merge
def _checks(R: dict) -> list[dict]:
    def ck(name, ok, detail):
        return {"check": name, "pass": bool(ok), "detail": detail}

    out = []
    if "columns" in R:
        C, T, V = R["columns"], R["timestamps"], R["raw_labels"]
        out += [
            ck("feature columns present", not C["missing_features"],
               f"missing {C['missing_features']}" if C["missing_features"] else "70/70"),
            ck("feature columns in features_v1 order", C["features_in_order"],
               "ok" if C["features_in_order"] else "order differs"),
            ck("no extra / duplicate columns", not C["extra_columns"] and not C["duplicate_columns"],
               f"extra {C['extra_columns']}, duplicate {C['duplicate_columns']}"),
            ck("required metadata columns present", not C["missing_meta"],
               f"missing {C['missing_meta']}" if C["missing_meta"] else "ok"),
            ck("feature dtypes numeric", not R["non_numeric"], str(R["non_numeric"]) if R["non_numeric"] else "ok"),
            ck("Timestamp parses (TS_FORMAT, tz=UTC)", T["unparseable"] == 0 and T["error"] is None,
               (T["error"] or f"{T['unparseable']} unparseable, e.g. {T['examples']}")
               if (T["unparseable"] or T["error"]) else f"ok ({T['justification']})"),
            ck("raw label vocabulary (all rows, before the filter)", not V["problems"],
               "; ".join(V["problems"]) if V["problems"] else f"ok {V['counts']}"),
        ]
    if "nulls" in R:
        L = R["labels"]
        nulls = {c: n for c, n in R["nulls"].items() if n}
        bad_mac = {m: {r: v[r] for r in BLANK_MAC_BAD if v[r]} for m, v in R["blank_mac"].items()}
        bad_mac = {m: v for m, v in bad_mac.items() if v}
        ok_mac = {m: {r: v[r] for r in BLANK_MAC_OK if v[r]} for m, v in R["blank_mac"].items()}
        out += [
            ck("identity columns non-null", not nulls, f"null/blank {nulls}" if nulls else "ok"),
            ck("blank MAC only for off-LAN endpoints", not bad_mac,
               f"{bad_mac}, e.g. {R['blank_mac_examples']}" if bad_mac else f"ok (allowed blanks {ok_mac})"),
            ck("labels map through the class map", L["error"] is None, L["error"] or f"ok {L['counts']}"),
        ]
    return out


def merge_reports(reports: list[dict]) -> dict:
    """Combine per-chunk reports of one input and one stage (counts summed, column layouts must agree)."""
    if not reports:
        raise SchemaError("merge_reports: no reports")
    M = copy.deepcopy(reports[0])
    for r in reports[1:]:
        if r.get("stage") != M.get("stage"):
            raise SchemaError(f"merge_reports: stages differ ({M.get('stage')} vs {r.get('stage')})")
        M["n_rows"] += r["n_rows"]
        if "columns" in M:
            if r["columns"] != M["columns"] and "<column layout differs between chunks>" not in M["columns"]["extra_columns"]:
                M["columns"]["extra_columns"].append("<column layout differs between chunks>")
            M["non_numeric"].update(r["non_numeric"])
            T, t = M["timestamps"], r["timestamps"]
            T["unparseable"] += t["unparseable"]
            T["examples"] = (T["examples"] + t["examples"])[:3]
            T["error"] = T["error"] or t["error"]
            for k, f in (("min_utc", min), ("max_utc", max)):
                vals = [x for x in (T[k], t[k]) if x is not None]
                T[k] = f(vals) if vals else None
            V, v = M["raw_labels"], r["raw_labels"]
            for k, n in v["counts"].items():
                V["counts"][k] = V["counts"].get(k, 0) + n
            V["problems"] = V["problems"] + [p for p in v["problems"] if p not in V["problems"]]
        if "nulls" in M:
            for c, v in r["nan_inf"].items():
                M["nan_inf"].setdefault(c, {"nan": 0, "inf": 0})
                M["nan_inf"][c]["nan"] += v["nan"]
                M["nan_inf"][c]["inf"] += v["inf"]
            for c, n in r["nulls"].items():
                M["nulls"][c] = M["nulls"].get(c, 0) + n
            for m, v in r["blank_mac"].items():
                for k, n in v.items():
                    M["blank_mac"][m][k] = M["blank_mac"][m].get(k, 0) + n
                M["blank_mac_examples"][m] = (M["blank_mac_examples"][m] + r["blank_mac_examples"][m])[:3]
            L, l2 = M["labels"], r["labels"]
            L["error"] = L["error"] or l2["error"]
            for k, n in l2["counts"].items():
                L["counts"][k] = L["counts"].get(k, 0) + n
    M["checks"] = _checks(M)
    M["ok"] = all(c["pass"] for c in M["checks"])
    return M


def apply_nan_inf_policy(df: pd.DataFrame, features: list[str] | None = None) -> pd.DataFrame:
    """V1 policy: a copy of df with NaN / +-inf in the feature columns replaced by 0 (input untouched)."""
    feats = features or feature_columns()
    out = df.copy()
    for c in feats:
        v = out[c].to_numpy(dtype=np.float64, copy=True)
        v[~np.isfinite(v)] = 0.0
        out[c] = v
    return out


# --------------------------------------------------------------------------- V2 lock
def verify_v2_lock(strict: bool = True, *, config_py: Path = CONFIG_PY_PATH, prereg: Path = STEP10_PREREG_PATH,
                   features: Path = FEATURES_PATH, class_map: Path = CLASS_MAP_PATH,
                   prereg_phase2: Path = PREREG_PHASE2_PATH, v1: bool = True,
                   orientation_map: Path = ORIENTATION_MAP_PATH,
                   prereg_amendment_1: Path = PREREG_PHASE2_AMENDMENT_1_PATH,
                   prereg_amendment_2: Path = PREREG_PHASE2_AMENDMENT_2_PATH,
                   prereg_phase3: Path = PREREG_PHASE3_PATH,
                   phase3_config: Path = V2_PHASE3_CONFIG_PATH,
                   phase3_1_config: Path = V2_PHASE3_1_CONFIG_PATH,
                   prereg_phase4: Path = PREREG_PHASE4_PATH,
                   phase4_config: Path = V2_PHASE4_CONFIG_PATH) -> dict:
    """V2 pins + V1's verify_lock(). Returns {"ok", "checks": [(name, ok, detail)], "env"} like V1;
    raises LockError on any failed check when strict. The path arguments exist for tests."""
    checks = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    def pin(name: str, path: Path, want: str) -> None:
        if not Path(path).is_file():
            check(name, False, f"not found: {path}")
            return
        got = sha256_file(Path(path))
        check(name, got == want, f"{got[:16]}..." if got == want else f"{path}: expected {want}, got {got}")

    pin("config/config.py sha256 == step10_prereg pin (V1 config untouched)", config_py, CONFIG_PY_SHA256)
    pin("config/step10_prereg.json sha256", prereg, STEP10_PREREG_SHA256)
    pin("docs/V2_PREREG_PHASE2.md sha256 (Phase 2 pre-registration)", prereg_phase2, PREREG_PHASE2_SHA256)
    if Path(prereg_phase2).is_file() and b"\r" in Path(prereg_phase2).read_bytes():
        check("docs/V2_PREREG_PHASE2.md LF only", False, "CR bytes found (the pin is over LF bytes)")
    pin("config/orientation_map.json sha256 (orientation normaliser, rule R3)", orientation_map, ORIENTATION_MAP_SHA256)
    pin("docs/V2_PREREG_PHASE2_AMENDMENT_1.md sha256 (Phase 2 prereg amendment 1)", prereg_amendment_1,
        PREREG_PHASE2_AMENDMENT_1_SHA256)
    if Path(prereg_amendment_1).is_file() and b"\r" in Path(prereg_amendment_1).read_bytes():
        check("docs/V2_PREREG_PHASE2_AMENDMENT_1.md LF only", False, "CR bytes found (the pin is over LF bytes)")
    pin("docs/V2_PREREG_PHASE2_AMENDMENT_2.md sha256 (Phase 2 prereg amendment 2)", prereg_amendment_2,
        PREREG_PHASE2_AMENDMENT_2_SHA256)
    if Path(prereg_amendment_2).is_file() and b"\r" in Path(prereg_amendment_2).read_bytes():
        check("docs/V2_PREREG_PHASE2_AMENDMENT_2.md LF only", False, "CR bytes found (the pin is over LF bytes)")
    pin("docs/V2_PREREG_PHASE3.md sha256 (Phase 3 pre-registration)", prereg_phase3, PREREG_PHASE3_SHA256)
    pin("config/v2_phase3.json sha256 (Phase 3 runtime policy config)", phase3_config, V2_PHASE3_CONFIG_SHA256)
    pin("config/v2_phase3_1.json sha256 (Phase 3.1 runtime config)", phase3_1_config, V2_PHASE3_1_CONFIG_SHA256)
    pin("docs/V2_PREREG_PHASE4.md sha256 (Phase 4 pre-registration)", prereg_phase4, PREREG_PHASE4_SHA256)
    pin("config/v2_phase4.json sha256 (Phase 4 continual-learning config)", phase4_config, V2_PHASE4_CONFIG_SHA256)
    for name, p in (("docs/V2_PREREG_PHASE3.md", prereg_phase3), ("config/v2_phase3.json", phase3_config),
                    ("config/v2_phase3_1.json", phase3_1_config), ("docs/V2_PREREG_PHASE4.md", prereg_phase4),
                    ("config/v2_phase4.json", phase4_config)):
        if Path(p).is_file() and b"\r" in Path(p).read_bytes():
            check(f"{name} LF only", False, "CR bytes found (the pin is over LF bytes)")
    try:
        P = json.loads(Path(prereg).read_bytes())
        check("step10_prereg records the same config.py / features pins",
              P["inputs_sha256"]["config/config.py"] == CONFIG_PY_SHA256
              and P["features"]["file_sha256"] == FEATURES_V1_SHA256
              and P["features"]["sha256"] == FEATURES_V1_LIST_SHA256, "inputs_sha256 / features")
    except (OSError, KeyError, ValueError) as e:
        check("step10_prereg records the same config.py / features pins", False, repr(e))
    for name, fn in (("features_v1.json (file sha256, list sha256, 70)", lambda: load_features(features)),
                     ("class_map.json (sha256, LF, structure)", lambda: load_class_map(class_map))):
        try:
            fn()
            check(name, True, "ok")
        except (OSError, SchemaError, KeyError, ValueError) as e:
            check(name, False, str(e))
    env = None
    if v1:
        res = verify_lock(strict=False)
        checks += [(f"v1: {n}", o, d) for n, o, d in res["checks"]]
        env = res["env"]
    ok = all(c[1] for c in checks)
    if strict and not ok:
        raise LockError("V2 lock verification failed: " + "; ".join(f"{n}: {d}" for n, o, d in checks if not o))
    return {"ok": ok, "checks": checks, "env": env}


def main() -> int:
    res = verify_v2_lock(strict=False)
    print(f"VERIFY_V2_LOCK  ({Path(__file__).relative_to(REPO_ROOT)})")
    for name, ok, detail in res["checks"]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<66} {detail}")
    print(f"\n{'V2 LOCK OK' if res['ok'] else 'V2 LOCK FAILED'}")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
