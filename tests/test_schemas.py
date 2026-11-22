"""tests/test_schemas.py -- unit tests for common/schemas.py (synthetic frames and temp copies only;
no flow data, no parquet, nothing under ~/lgids_cache is read).

Plain asserts, no pytest fixtures or imports, so the file also runs without pytest.
Usage (repo root): python tests/test_schemas.py        (or python -m pytest -q tests/test_schemas.py)
"""

from __future__ import annotations

import hashlib
import re
import sys
import tempfile
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import schemas as S  # noqa: E402
from config.config import LockError  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
FEATS = S.feature_columns()
SRC = "v1_cicflowmeter"


def _raises(fn, exc=S.SchemaError, match: str | None = None) -> bool:
    try:
        fn()
    except exc as e:
        return match is None or re.search(match, str(e)) is not None
    return False


def _tmp_bytes(data: bytes, name: str = "class_map.json") -> Path:
    d = Path(tempfile.mkdtemp(prefix="test_schemas_"))
    p = d / name
    p.write_bytes(data)
    return p


def _frame(n: int = 6) -> pd.DataFrame:
    """A valid V1-filtered frame in raw CICFlowMeter layout (identity columns interleaved)."""
    rng = np.random.default_rng(0)
    cols = {"Flow ID": [f"f{i}" for i in range(n)], "Src IP": ["192.168.137.10"] * n, "Src Port": ["5000"] * n,
            "Dst IP": ["192.168.137.20"] * n, "Dst Port": ["80"] * n}
    cols[FEATS[0]] = rng.integers(0, 17, n).astype(np.float64)              # Protocol
    cols["Timestamp"] = ["19/01/2023 03:51:14 PM"] * n
    for c in FEATS[1:]:
        cols[c] = rng.random(n)
    cols.update({"Label": ["NeedManualLabel"] * n, "src_mac": ["aa:bb:cc:00:00:01"] * n,
                 "dst_mac": ["aa:bb:cc:00:00:02"] * n, "owner_status": ["owned"] * n, "exclude_reason": [""] * n,
                 "owner_mac": ["aa:bb:cc:00:00:02"] * n, "owner_device": ["Cam"] * n, "owner_category": ["Camera"] * n,
                 "label": ["benign", "attack", "benign", "attack", "attack", "benign"][:n],
                 "attack_family": ["", "syn_flood", "", "udp_flood", "port_scan", ""][:n],
                 "session": ["s"] * n})
    return pd.DataFrame(cols)


def _check(R: dict, name_part: str) -> bool:
    return next(c["pass"] for c in R["checks"] if name_part in c["check"])


# --------------------------------------------------------------------------- class map
def test_class_map_loads():
    cm = S.load_class_map()
    assert cm.names == ("benign", "syn_flood", "udp_flood", "port_scan")
    assert cm.id_of("benign") == 0 and cm.n_classes == 4
    assert cm.sha256 == S.CLASS_MAP_SHA256


def test_class_map_one_byte_edit_fails_hash():
    raw = bytearray(S.CLASS_MAP_PATH.read_bytes())
    i = raw.index(b"syn_flood") + 8
    raw[i] = ord("x")                                           # syn_flood -> syn_floox (1 byte)
    p = _tmp_bytes(bytes(raw))
    assert _raises(lambda: S.load_class_map(p), match="sha256")


def test_class_map_reordered_fails_hash():
    raw = S.CLASS_MAP_PATH.read_text(encoding="ascii")
    a = '{"id": 1, "name": "syn_flood"}'
    b = '{"id": 2, "name": "udp_flood"}'
    p = _tmp_bytes(raw.replace(a, "@@").replace(b, a).replace("@@", b).encode("ascii"))
    assert _raises(lambda: S.load_class_map(p), match="sha256")


def test_class_map_crlf_fails():
    crlf = S.CLASS_MAP_PATH.read_bytes().replace(b"\n", b"\r\n")
    p = _tmp_bytes(crlf)
    assert _raises(lambda: S.load_class_map(p), match="CR")
    # fails on the CR check even if its own hash were pinned
    assert _raises(lambda: S.load_class_map(p, hashlib.sha256(crlf).hexdigest()), match="CR")


def test_class_map_structure_checks():
    base = S.CLASS_MAP_PATH.read_text(encoding="ascii")
    for edit, why in ((base.replace('"id": 3', '"id": 4'), "contiguous"),
                      (base.replace('"name": "benign"', '"name": "normal"'), "benign"),
                      (base.replace('"port_scan": "port_scan"', '"port_scan": "portscan"'), "unknown classes")):
        raw = edit.encode("ascii")
        p = _tmp_bytes(raw)
        assert _raises(lambda: S.load_class_map(p, hashlib.sha256(raw).hexdigest()), match=why), why


def test_features_pin():
    F = S.load_features()
    assert len(F["features"]) == 70 and F["features"][0] == "Protocol"
    raw = S.FEATURES_PATH.read_bytes().replace(b'"Protocol"', b'"Protocoll"', 1)
    assert _raises(lambda: S.load_features(_tmp_bytes(raw, "features_v1.json")), match="sha256")


def test_ts_format_matches_v1():
    src = (REPO / "04_tag_flows.py").read_text(encoding="utf-8")
    m = re.search(r'^TS_FORMAT = "([^"]+)"', src, re.M)
    assert m and m.group(1) == S.TS_FORMAT, (m and m.group(1), S.TS_FORMAT)


# --------------------------------------------------------------------------- encode_labels
def _enc(label, fam, source=SRC):
    return S.encode_labels(pd.Series(label, dtype=object), pd.Series(fam, dtype=object), source)


def test_encode_valid_and_no_mutation():
    lab = pd.Series(["benign", "attack", "attack", "attack", "benign"], index=[10, 11, 12, 13, 14], dtype=object)
    fam = pd.Series(["", "syn_flood", "udp_flood", "port_scan", np.nan], index=lab.index, dtype=object)
    lab0, fam0 = lab.copy(), fam.copy()
    ids = S.encode_labels(lab, fam, SRC)
    assert ids.tolist() == [0, 1, 2, 3, 0] and ids.dtype == np.int8
    assert list(ids.index) == [10, 11, 12, 13, 14]
    assert lab.equals(lab0) and fam.equals(fam0)


def test_unknown_label_raises_with_counts():
    assert _raises(lambda: _enc(["benign", "malicious", "malicious", None], ["", "", "", ""]),
                   match=r"outside.*'malicious': 2.*'<NA>': 1|outside.*'<NA>': 1.*'malicious': 2")


def test_excluded_reaching_encoder_raises():
    assert _raises(lambda: _enc(["benign", "excluded", "excluded"], ["", "", ""]), match=r"2 rows with label 'excluded'")


def test_attack_empty_family_raises():
    assert _raises(lambda: _enc(["attack", "attack"], ["", None]), match=r"2 rows with label 'attack' and an empty")


def test_attack_family_not_in_class_map_raises():
    assert _raises(lambda: _enc(["attack", "attack", "attack"], ["mirai_greeth", "mirai_greeth", "syn_flood"]),
                   match=r"not in class_map aliases.*'mirai_greeth': 2")


def test_benign_with_family_raises():
    assert _raises(lambda: _enc(["benign", "benign"], ["syn_flood", ""]), match=r"inconsistent labelling.*'syn_flood': 1")


def test_unknown_source_raises():
    assert _raises(lambda: _enc(["benign"], [""], source="ciciot2023_csv"), match="unknown source")


def test_all_errors_listed_together():
    try:
        _enc(["bogus", "excluded", "attack"], ["", "", ""])
    except S.SchemaError as e:
        msg = str(e)
        assert "bogus" in msg and "excluded" in msg and "empty attack_family" in msg, msg
    else:
        raise AssertionError("no error raised")


# --------------------------------------------------------------------------- to_binary
def test_to_binary_all_ids():
    assert S.to_binary(np.array([0, 1, 2, 3])).tolist() == [0, 1, 1, 1]
    s = S.to_binary(pd.Series([3, 0, 2], index=[7, 8, 9], dtype=np.int8))
    assert s.tolist() == [1, 0, 1] and list(s.index) == [7, 8, 9] and s.name == "y" and s.dtype == np.int8


def test_to_binary_out_of_range_and_type():
    assert _raises(lambda: S.to_binary(np.array([0, 4])), match="outside")
    assert _raises(lambda: S.to_binary(np.array([-1, 0])), match="outside")
    assert _raises(lambda: S.to_binary(np.array([0.0, 1.5])), match="integers")
    assert _raises(lambda: S.to_binary(np.array([True, False])), match="integers")


# --------------------------------------------------------------------------- validate_frame
def test_valid_frame_ok_and_not_mutated():
    df = _frame()
    df0 = df.copy(deep=True)
    R = S.validate_frame(df)
    assert R["ok"], [c for c in R["checks"] if not c["pass"]]
    assert R["labels"]["counts"] == {"benign": 3, "syn_flood": 1, "udp_flood": 1, "port_scan": 1}
    assert R["timestamps"]["min_utc"] == "2023-01-19T15:51:14+00:00"
    assert df.equals(df0) and list(df.columns) == list(df0.columns)


def test_missing_feature_rejected():
    R = S.validate_frame(_frame().drop(columns=["Flow IAT Mean"]))
    assert not R["ok"] and not _check(R, "feature columns present")
    assert R["columns"]["missing_features"] == ["Flow IAT Mean"]


def test_extra_column_rejected():
    df = _frame()
    df["Fwd Magic Ratio"] = 1.0
    R = S.validate_frame(df)
    assert not R["ok"] and R["columns"]["extra_columns"] == ["Fwd Magic Ratio"]


def test_reordered_features_rejected():
    df = _frame()
    c = list(df.columns)
    i, j = c.index("Flow Duration"), c.index("Flow IAT Max")
    c[i], c[j] = c[j], c[i]
    R = S.validate_frame(df[c])
    assert not R["ok"] and not _check(R, "in features_v1 order")


def test_dropped_constant_columns_tolerated():
    df = _frame()
    for c in S.dropped_constant_columns():
        df[c] = 0.0
    assert S.validate_frame(df)["ok"]


def test_non_numeric_feature_rejected():
    df = _frame()
    df["Flow Bytes/s"] = df["Flow Bytes/s"].astype(str)
    R = S.validate_frame(df)
    assert not R["ok"] and "Flow Bytes/s" in R["non_numeric"]


def test_nan_inf_counted_not_failed():
    df = _frame()
    df.loc[[0, 3], "Flow Bytes/s"] = np.nan
    df.loc[[1, 2, 5], "Flow Packets/s"] = [np.inf, -np.inf, np.inf]
    df.loc[4, "Flow Bytes/s"] = np.inf
    R = S.validate_frame(df)
    assert R["ok"]
    assert R["nan_inf"]["Flow Bytes/s"] == {"nan": 2, "inf": 1}
    assert R["nan_inf"]["Flow Packets/s"] == {"nan": 0, "inf": 3}
    assert sum(v["nan"] + v["inf"] for v in R["nan_inf"].values()) == 6
    clean = S.apply_nan_inf_policy(df)
    assert np.isfinite(clean[FEATS].to_numpy()).all() and clean.loc[0, "Flow Bytes/s"] == 0.0
    assert np.isnan(df.loc[0, "Flow Bytes/s"])                       # input untouched


def test_timestamps():
    t = S.parse_timestamps(pd.Series(["19/01/2023 03:51:14 PM", "07/10/2022 12:00:00 AM"]))
    assert str(t.dt.tz) == "UTC"
    assert t.iloc[0] == pd.Timestamp("2023-01-19 15:51:14", tz="UTC")
    assert t.iloc[1] == pd.Timestamp("2022-10-07 00:00:00", tz="UTC")     # dd/mm, 12 AM = 00 h
    assert _raises(lambda: S.parse_timestamps(pd.Series(["2023-01-19 15:51:14"])), match="unparseable")
    assert _raises(lambda: S.parse_timestamps(pd.Series(["32/01/2023 03:51:14 PM"])), match="unparseable")
    assert _raises(lambda: S.parse_timestamps(pd.Series(pd.to_datetime(["2023-01-19"]))), match="naive")
    assert _raises(lambda: S.parse_timestamps(pd.Series(pd.to_datetime(["2023-01-19"]).tz_localize("Asia/Kolkata"))),
                   match="tz")
    df = _frame()
    df.loc[2, "Timestamp"] = "not a time"
    R = S.validate_frame(df)
    assert not R["ok"] and R["timestamps"]["unparseable"] == 1 and R["timestamps"]["examples"] == ["not a time"]


def test_null_ip_rejected():
    df = _frame()
    df.loc[1, "Src IP"] = ""
    df.loc[2, "owner_mac"] = None
    R = S.validate_frame(df)
    assert not R["ok"] and R["nulls"]["Src IP"] == 1 and R["nulls"]["owner_mac"] == 1


def test_blank_mac_rule_reasons():
    df = _frame()
    df.loc[0, ["dst_mac", "Dst IP"]] = ["", "8.8.8.8"]                 # public
    df.loc[1, ["dst_mac", "Dst IP"]] = ["", "255.255.255.255"]         # limited broadcast
    df.loc[2, ["dst_mac", "Dst IP"]] = ["", "224.0.0.251"]             # multicast
    df.loc[3, ["dst_mac", "Dst IP"]] = ["", "192.168.137.255"]         # LAN subnet broadcast
    df.loc[4, ["dst_mac", "Dst IP"]] = ["", "172.16.5.9"]              # private, not a LAN subnet
    R = S.validate_rows(df)
    assert R["ok"], [c for c in R["checks"] if not c["pass"]]
    assert R["blank_mac"]["dst_mac"] == {"public": 1, "broadcast": 2, "multicast": 1, "off_lan_private": 1,
                                         "lan_unicast": 0, "invalid_ip": 0}
    df.loc[5, ["src_mac", "Src IP"]] = ["", "192.168.137.55"]          # LAN unicast: fails
    R = S.validate_rows(df)
    assert not R["ok"] and R["blank_mac"]["src_mac"]["lan_unicast"] == 1
    assert R["blank_mac_examples"]["src_mac"] == ["192.168.137.55"]
    df.loc[5, "Src IP"] = "not-an-ip"
    assert S.validate_rows(df)["blank_mac"]["src_mac"]["invalid_ip"] == 1


def test_lan_subnets_per_source_and_override():
    assert [str(n) for n in S.lan_networks("v1_cicflowmeter")] == ["192.168.137.0/24", "10.22.22.0/24"]
    df = _frame()
    df.loc[0, ["dst_mac", "Dst IP"]] = ["", "172.16.5.9"]
    assert S.validate_rows(df)["ok"]                                   # off-LAN under V1's subnets
    R = S.validate_rows(df, lan_subnets=["172.16.0.0/16"])             # another source's LAN
    assert not R["ok"] and R["blank_mac"]["dst_mac"]["lan_unicast"] == 1 and R["lan_subnets"] == ["172.16.0.0/16"]
    assert _raises(lambda: S.lan_networks("v1_cicflowmeter", ["300.1.1.0/24"]), match="bad LAN subnet")
    assert _raises(lambda: S.lan_networks("no_such_source"), match="unknown source")


def test_owner_col():
    df = _frame()
    df.loc[0, "owner_mac"] = ""                                        # 08b unregistered-MAC row
    df["device_mac"] = "aa:bb:cc:00:00:09"
    assert not S.validate_rows(df)["ok"]
    assert S.validate_rows(df, owner_col="device_mac")["ok"]


def test_schema_stage_sees_rows_the_filter_would_reject():
    df = _frame()
    df.loc[0, ["label", "owner_status"]] = ["bogus", "unowned"]        # would be rejected as not_owned
    df.loc[1, ["label", "attack_family"]] = ["excluded", "syn_flood"]  # 07 invariant broken
    R = S.validate_schema(df)
    assert not R["ok"] and not _check(R, "raw label vocabulary")
    problems = " ".join(R["raw_labels"]["problems"])
    assert "'bogus': 1" in problems and "excluded/syn_flood" in problems, problems
    assert S.validate_schema(_frame())["ok"] and S.validate_schema(_frame())["raw_labels"]["counts"] == {
        "benign/": 3, "attack/syn_flood": 1, "attack/udp_flood": 1, "attack/port_scan": 1}


def test_schema_stage_columns_from_header():
    df = _frame()
    header = list(df.columns)
    sub = df[["Timestamp"] + FEATS]                                    # chunk read with a column subset
    assert S.validate_schema(sub, columns=header + ["src_role"])["ok"]
    R = S.validate_schema(sub, columns=header + ["Mystery Col"])
    assert not R["ok"] and R["columns"]["extra_columns"] == ["Mystery Col"]


def test_stages_split_checks():
    s, r = S.validate_schema(_frame()), S.validate_rows(_frame())
    assert {c["check"] for c in s["checks"]}.isdisjoint({c["check"] for c in r["checks"]})
    assert "nan_inf" in r and "nan_inf" not in s and "timestamps" in s and "timestamps" not in r
    assert _raises(lambda: S.merge_reports([s, r]), match="stages differ")


def test_bad_label_reported_not_raised():
    df = _frame()
    df.loc[0, "label"] = "excluded"
    R = S.validate_frame(df)
    assert not R["ok"] and "excluded" in R["labels"]["error"]


def test_assume_label():
    df = _frame().drop(columns=["label", "attack_family"])
    assert not S.validate_frame(df)["ok"]                             # no silent default
    R = S.validate_frame(df, assume_label="benign")
    assert R["ok"] and R["labels"]["counts"] == {"benign": 6}
    R = S.validate_frame(_frame(), assume_label="benign")             # declaration contradicts data
    assert not R["ok"] and "declared but the frame has" in R["labels"]["error"]


def test_merge_reports():
    a, b = _frame(), _frame()
    a.loc[0, "Flow Bytes/s"] = np.nan
    b.loc[[1, 2], "Flow Bytes/s"] = np.inf
    b.loc[3, "Timestamp"] = "20/01/2023 01:00:00 AM"
    M = S.merge_reports([S.validate_frame(a), S.validate_frame(b)])
    assert M["ok"] and M["n_rows"] == 12
    assert M["nan_inf"]["Flow Bytes/s"] == {"nan": 1, "inf": 2}
    assert M["labels"]["counts"] == {"benign": 6, "syn_flood": 2, "udp_flood": 2, "port_scan": 2}
    assert M["timestamps"]["max_utc"] == "2023-01-20T01:00:00+00:00"
    bad = b.copy()
    bad.loc[0, "Timestamp"] = "x"
    assert not S.merge_reports([S.validate_frame(a), S.validate_frame(bad)])["ok"]


# --------------------------------------------------------------------------- verify_v2_lock
def test_verify_v2_lock_pins_pass():
    res = S.verify_v2_lock(strict=False, v1=False)
    assert res["ok"], [c for c in res["checks"] if not c[1]]
    assert any("config/config.py" in c[0] for c in res["checks"])


def test_verify_v2_lock_detects_edited_config_py():
    raw = S.CONFIG_PY_PATH.read_bytes() + b"# edited\n"
    p = _tmp_bytes(raw, "config.py")
    res = S.verify_v2_lock(strict=False, v1=False, config_py=p)
    assert not res["ok"] and not next(c[1] for c in res["checks"] if "config/config.py" in c[0])
    assert _raises(lambda: S.verify_v2_lock(strict=True, v1=False, config_py=p), exc=LockError)


def test_verify_v2_lock_detects_edited_class_map():
    p = _tmp_bytes(S.CLASS_MAP_PATH.read_bytes().replace(b"udp_flood", b"udp_floox", 1))
    res = S.verify_v2_lock(strict=False, v1=False, class_map=p)
    assert not res["ok"] and not next(c[1] for c in res["checks"] if "class_map" in c[0])


def test_verify_v2_lock_checks_phase2_prereg():
    res = S.verify_v2_lock(strict=False, v1=False)
    assert any("V2_PREREG_PHASE2" in c[0] and c[1] for c in res["checks"]), res["checks"]
    edited = _tmp_bytes(S.PREREG_PHASE2_PATH.read_bytes() + b"\nedited after the fact\n", "V2_PREREG_PHASE2.md")
    res = S.verify_v2_lock(strict=False, v1=False, prereg_phase2=edited)
    assert not res["ok"] and not next(c[1] for c in res["checks"] if "V2_PREREG_PHASE2" in c[0])
    assert _raises(lambda: S.verify_v2_lock(strict=True, v1=False, prereg_phase2=edited), exc=LockError)
    crlf = _tmp_bytes(S.PREREG_PHASE2_PATH.read_bytes().replace(b"\n", b"\r\n"), "V2_PREREG_PHASE2.md")
    assert not S.verify_v2_lock(strict=False, v1=False, prereg_phase2=crlf)["ok"]


def test_verify_v2_lock_checks_orientation_map():
    res = S.verify_v2_lock(strict=False, v1=False)
    assert any("orientation_map" in c[0] and c[1] for c in res["checks"]), res["checks"]
    raw = S.ORIENTATION_MAP_PATH.read_bytes()
    edited = _tmp_bytes(raw.replace(b'"value": 6', b'"value": 17', 1), "orientation_map.json")
    res = S.verify_v2_lock(strict=False, v1=False, orientation_map=edited)
    assert not res["ok"] and not next(c[1] for c in res["checks"] if "orientation_map" in c[0])
    assert _raises(lambda: S.verify_v2_lock(strict=True, v1=False, orientation_map=edited), exc=LockError)
    missing = S.ORIENTATION_MAP_PATH.with_name("no_such_orientation_map.json")
    assert not S.verify_v2_lock(strict=False, v1=False, orientation_map=missing)["ok"]


def test_verify_v2_lock_checks_prereg_amendment_1():
    res = S.verify_v2_lock(strict=False, v1=False)
    assert any("AMENDMENT_1" in c[0] and c[1] for c in res["checks"]), res["checks"]
    raw = S.PREREG_PHASE2_AMENDMENT_1_PATH.read_bytes()
    edited = _tmp_bytes(raw.replace(b"0.005", b"0.050", 1), "V2_PREREG_PHASE2_AMENDMENT_1.md")
    res = S.verify_v2_lock(strict=False, v1=False, prereg_amendment_1=edited)
    assert not res["ok"] and not next(c[1] for c in res["checks"] if "AMENDMENT_1" in c[0])
    assert _raises(lambda: S.verify_v2_lock(strict=True, v1=False, prereg_amendment_1=edited), exc=LockError)
    crlf = _tmp_bytes(raw.replace(b"\n", b"\r\n"), "V2_PREREG_PHASE2_AMENDMENT_1.md")
    assert not S.verify_v2_lock(strict=False, v1=False, prereg_amendment_1=crlf)["ok"]


def test_verify_v2_lock_checks_prereg_amendment_2():
    res = S.verify_v2_lock(strict=False, v1=False)
    assert any("AMENDMENT_2" in c[0] and c[1] for c in res["checks"]), res["checks"]
    raw = S.PREREG_PHASE2_AMENDMENT_2_PATH.read_bytes()
    edited = _tmp_bytes(raw.replace(b"FLAT_GLOBAL", b"ROUTED", 1), "V2_PREREG_PHASE2_AMENDMENT_2.md")
    res = S.verify_v2_lock(strict=False, v1=False, prereg_amendment_2=edited)
    assert not res["ok"] and not next(c[1] for c in res["checks"] if "AMENDMENT_2" in c[0])
    assert _raises(lambda: S.verify_v2_lock(strict=True, v1=False, prereg_amendment_2=edited), exc=LockError)
    crlf = _tmp_bytes(raw.replace(b"\n", b"\r\n"), "V2_PREREG_PHASE2_AMENDMENT_2.md")
    assert not S.verify_v2_lock(strict=False, v1=False, prereg_amendment_2=crlf)["ok"]
    missing = S.PREREG_PHASE2_AMENDMENT_2_PATH.with_name("no_such_amendment_2.md")
    assert not S.verify_v2_lock(strict=False, v1=False, prereg_amendment_2=missing)["ok"]


def test_verify_v2_lock_checks_phase3_prereg_and_config():
    res = S.verify_v2_lock(strict=False, v1=False)
    for tag in ("V2_PREREG_PHASE3", "v2_phase3.json"):
        assert any(tag in c[0] and c[1] for c in res["checks"]), (tag, res["checks"])
    for kw, path, a, b in (("prereg_phase3", S.PREREG_PHASE3_PATH, b"0.5", b"0.6"),
                           ("phase3_config", S.V2_PHASE3_CONFIG_PATH, b"\"cooldown_s\": 300", b"\"cooldown_s\": 30")):
        raw = path.read_bytes()
        assert a in raw
        edited = _tmp_bytes(raw.replace(a, b, 1), path.name)
        assert not S.verify_v2_lock(strict=False, v1=False, **{kw: edited})["ok"]
        assert _raises(lambda: S.verify_v2_lock(strict=True, v1=False, **{kw: edited}), exc=LockError)
        crlf = _tmp_bytes(raw.replace(b"\n", b"\r\n"), path.name)
        assert not S.verify_v2_lock(strict=False, v1=False, **{kw: crlf})["ok"]


def test_verify_v2_lock_checks_phase4_prereg_and_config():
    res = S.verify_v2_lock(strict=False, v1=False)
    for tag in ("V2_PREREG_PHASE4", "v2_phase4.json"):
        assert any(tag in c[0] and c[1] for c in res["checks"]), (tag, res["checks"])
    for kw, path, a, b in (("prereg_phase4", S.PREREG_PHASE4_PATH, b"0.99", b"0.98"),
                           ("phase4_config", S.V2_PHASE4_CONFIG_PATH, b"\"random_review_rate\": 0.05",
                            b"\"random_review_rate\": 0.5")):
        raw = path.read_bytes()
        assert a in raw
        edited = _tmp_bytes(raw.replace(a, b, 1), path.name)
        assert not S.verify_v2_lock(strict=False, v1=False, **{kw: edited})["ok"]
        assert _raises(lambda: S.verify_v2_lock(strict=True, v1=False, **{kw: edited}), exc=LockError)
        crlf = _tmp_bytes(raw.replace(b"\n", b"\r\n"), path.name)
        assert not S.verify_v2_lock(strict=False, v1=False, **{kw: crlf})["ok"]
        missing = Path(tempfile.mkdtemp(prefix="p4pin_")) / path.name
        assert not S.verify_v2_lock(strict=False, v1=False, **{kw: missing})["ok"]


def test_verify_v2_lock_with_v1():
    """Full lock incl. V1 verify_lock (needs the extractor jar: runs in WSL)."""
    res = S.verify_v2_lock(strict=False)
    assert any(c[0].startswith("v1: ") for c in res["checks"])
    assert res["ok"], [c for c in res["checks"] if not c[1]]


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
