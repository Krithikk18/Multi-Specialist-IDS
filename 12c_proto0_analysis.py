#!/usr/bin/env python
"""12c_proto0_analysis.py -- EXPLORATORY: "Protocol 0" traffic (not TCP / UDP for CICFlowMeter: GRE, ICMP, ...).

EXPLORATORY -- not part of the pre-registered evaluation. Nothing is trained, no threshold is changed, test.parquet is
never opened, read or stat'ed (only train / val parquets), and of the greeth_flood parts only the base part's pilot
outputs from 12b are used (parts 9 / 18 / 27 / 28 untouched). Outputs go to results/step12c/ only.

Questions
  Q1 do the frozen Step 10 models already catch the GRE flood (12b pilot, base part)?
  Q2 does benign Protocol-0 traffic exist in a volume / rate that overlaps the flood?
  Q3 is a one-feature rate rule on Protocol-0 flows enough (margin, benign FPs)?

Steps
  1 inventory  benign Protocol == 0 rows of train and val (separately): count and share of benign rows, by device /
               device_category / group / session; Total Fwd Packet, Flow Duration, Flow Packets/s, Fwd Packets/s
               quantiles (min, p50, p90, p99, p99.9, max); Protocol == 0 ATTACK rows by family.
  2 packets    (cheap, lean tshark; --skip-tshark to skip) the train window of ONE benign train capture
               (BenignTraffic.pcap = session benign_night, packets before its train / val cut in manifest_v1
               session_cuts): IPv4 packets whose outer ip.proto is not 6 / 17, by ip.proto and by sender device.
  3 GRE flood  the 12b pilot flows (base part): attacker flows by 12b's rule (Src or Dst IP in the attacker IP set
               from 12b's cached packet pass); flood flows = attacker flows not TCP / UDP (52), of which the GRE
               streams are the (attacker IP, victim IP) pairs that carried outer ip.proto 47. Single-feature ROC-AUC
               (09b method: roc_auc_score on the float64 feature, max(a, 1 - a), direction) of flood vs benign
               Protocol-0 train + val rows for every feature; the zero-benign-FP one-feature threshold per feature
               (above the benign max, or below the benign min) and its detection on the flood flows; the margin
               between the benign max and the flood min for Flow Packets/s and Total Fwd Packet.
  4 models     the frozen Step 10 models (sha256 == config/step10_prereg.json, read-only), 70 features in
               features_v1 order, cleaned as 08 (NaN / +-inf -> 0) then float32; FINAL routes by the k2 group of the
               flow's owner (the non-attacker endpoint for attacker flows; for other flows the source if it is a
               registered iot device, else the destination; anything else GEN -> GLOBAL), BASELINE = GLOBAL; both
               operating points from the prereg (flag iff score >= threshold). Populations: the 52 flood flows,
               the GRE-stream subset, the 100 TCP / UDP attacker side flows, and the pilot's non-attacker
               Protocol-0 flows. Owner IP -> MAC from a lean sender-evidence tshark pass on the pilot base part
               (02 / 07a approach: ip.src -> eth.src of non-attacker senders), then 12b's attacker-destination map.

Outputs -> results/step12c/: summary.md, proto0_benign_by_device.csv, proto0_distributions.csv, gre_vs_benign_auc.csv,
frozen_models_on_greeth.csv, run_meta.json (+ run.log, gitignored).

Exit status: 0 ok, 1 bad input / check failed, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
import resource
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from config.config import ATTACKER_MACS, CACHE_DIR, CONFIG_DIR, DATASET, DEVICE_TABLE, REPO_ROOT, RESULTS_DIR, sha256_file


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m10 = _load("step10_evaluate", "10_evaluate.py")        # load_matrix / load_eval_meta / attack_col, test-locked
m12b = _load("greeth_pilot", "12b_greeth_pilot.py")      # attacker IP set, 07a Devices, norm_mac
m02 = _load("mac_ip_map", "02_mac_ip_map.py")

SCRIPT = "12c_proto0_analysis.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
LABEL = "EXPLORATORY -- not part of the pre-registered evaluation"
SPLITS = ("train", "val")
SPLIT_PATH = {s: m10.SPLIT_PATH[s] for s in SPLITS}      # never the test path
PREREG = CONFIG_DIR / "step10_prereg.json"
FEATURES = CONFIG_DIR / "features_v1.json"
K2_JSON = CONFIG_DIR / "groupings" / "behaviour_k2.json"
MANIFEST_V1 = RESULTS_DIR / "step8" / "manifest_v1.json"
PILOT = CACHE_DIR / "pilot_greeth"
PILOT_PCAP = PILOT / "Mirai-greeth_flood.pcap"
PILOT_CSV = PILOT / "flows" / "Mirai-greeth_flood.pcap_Flow__singlepkt.csv"
PILOT_PACKETS = PILOT / "packets.json"
BENIGN_PCAP = DATASET.benign_pcap_cached
BENIGN_SESSION = "benign_night"
OUT = RESULTS_DIR / "step12c"
DIST_FEATS = ["Total Fwd Packet", "Flow Duration", "Flow Packets/s", "Fwd Packets/s"]
RULE_FEATS = ["Flow Packets/s", "Total Fwd Packet"]
QUANTS = [("min", 0), ("p50", 50), ("p90", 90), ("p99", 99), ("p99.9", 99.9), ("max", 100)]
META = ["y", "attack_family", "group", "device", "device_category", "session"]
SHORTCUT_AUC = 0.99                                     # 09b CONFIG shortcut_auc
PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6", 103: "PIM", 112: "VRRP"}

_LOG_PATH: Path | None = None


def log(msg: str) -> None:
    line = f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    if _LOG_PATH is not None:
        with open(_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def fatal(msg: str) -> None:
    log(f"FATAL: {msg}")
    sys.exit(1)


def read_json(p: Path) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def write_json(p: Path, obj) -> None:
    p.write_text(json.dumps(obj, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)) + "\n",
                 encoding="utf-8")


def guard(p: Path) -> Path:
    """No test split file, and of the greeth parts only the base part's pilot outputs."""
    name = Path(p).name.lower()
    if "test" in name or any(f"greeth_flood{n}" in name for n in ("9", "18", "27", "28")):
        fatal(f"refusing to touch {p}")
    return Path(p)


def pct(n: float, d: float) -> float:
    return 100.0 * n / d if d else math.nan


def fnum(v, nd: int = 2) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    if isinstance(v, (bool, np.bool_)):
        return str(v)
    if isinstance(v, (float, np.floating)):
        return "inf" if math.isinf(v) else f"{v:,.{nd}f}"
    return f"{v:,}" if isinstance(v, (int, np.integer)) else str(v)


def md_table(rows: list[dict], cols: list[str], nd: int = 2) -> list[str]:
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(r.get(c, "") if isinstance(r.get(c, ""), str) else fnum(r.get(c), nd) for c in cols)
            + " |" for r in rows]
    return out


def write_csv(name: str, rows) -> None:
    pd.DataFrame(rows).to_csv(OUT / name, index=False, lineterminator="\n")


def quantiles(x: np.ndarray) -> dict:
    if not len(x):
        return {k: math.nan for k, _ in QUANTS}
    q = np.percentile(x, [p for _, p in QUANTS])
    return {k: float(v) for (k, _), v in zip(QUANTS, q)}


def clean(X: np.ndarray) -> np.ndarray:
    """08's clean: +-inf / NaN -> 0 (float64), then float32 as the models were fit."""
    X = np.array(X, dtype=np.float64)
    X[~np.isfinite(X)] = 0.0
    return X.astype(np.float32)


def k2_by_mac() -> tuple[dict, dict]:
    J = read_json(K2_JSON)
    return ({m12b.norm_mac(m): g for m, g in J["devices"].items()},
            {m12b.norm_mac(m): J["device_info"][m]["device_name"] for m in J["devices"]})


# --------------------------------------------------------------------------- inputs

def check_inputs(M: dict, P: dict) -> dict:
    checks = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail})
        log(f"CHECK {'PASS' if ok else 'FAIL'}  {name}: {detail}")

    for s in SPLITS:
        got = sha256_file(guard(SPLIT_PATH[s]))
        want = P["datasets"][s]["sha256"]
        check(f"{s}.parquet sha256 == prereg", got == want, f"{got[:16]}... vs {want[:16]}...")
    models = {}
    for mid, spec in P["models"].items():
        path = Path(spec["path"].replace("~", str(Path.home()), 1))
        got = sha256_file(path)
        check(f"model {mid} sha256 == prereg", got == spec["sha256"], f"{got[:16]}... vs {spec['sha256'][:16]}...")
        models[mid] = {"path": str(path), "sha256": got}
    feats_sha = sha256_file(FEATURES)
    check("features_v1.json file sha256 == prereg", feats_sha == P["features"]["file_sha256"], feats_sha[:16])
    k2_sha = sha256_file(K2_JSON)
    check("behaviour_k2.json sha256 == prereg", k2_sha == P["grouping"]["sha256"], k2_sha[:16])
    import xgboost
    check("xgboost version == prereg", xgboost.__version__ == P["xgboost_version"],
          f"{xgboost.__version__} vs {P['xgboost_version']}")
    side = PILOT_PCAP.with_name(PILOT_PCAP.name + ".sha256.json")
    want_pcap = m12b.expected_sha()
    check("pilot pcap sidecar sha256 == config/sha256_greeth.txt (base part)",
          side.is_file() and read_json(side).get("sha256") == want_pcap, want_pcap[:16])
    PK = read_json(PILOT_PACKETS)
    check("12b packets.json keyed to the base part", PK["key"]["pcap_sha256"] == want_pcap,
          PK["key"]["pcap_sha256"][:16])
    meta = read_json(PILOT_CSV.with_name(PILOT_CSV.name + ".meta.json"))
    check("pilot flow CSV extracted from the base part with the locked jar",
          meta["input_pcap_sha256"] == want_pcap and meta["jar_sha256"] == m12b.EXTRACTOR.jar_sha256,
          meta["jar_sha256"][:16])
    M["checks"] = checks
    M["models"] = models
    M["inputs_sha256"] = {"train.parquet": P["datasets"]["train"]["sha256"],
                          "val.parquet": P["datasets"]["val"]["sha256"],
                          "config/step10_prereg.json": sha256_file(PREREG), "config/features_v1.json": feats_sha,
                          "config/groupings/behaviour_k2.json": k2_sha,
                          "config/device_table.csv": sha256_file(DEVICE_TABLE),
                          "results/step8/manifest_v1.json": sha256_file(MANIFEST_V1),
                          "pilot flow CSV": sha256_file(PILOT_CSV), "pilot packets.json": sha256_file(PILOT_PACKETS),
                          "pilot pcap (base part)": want_pcap}
    if not all(c["pass"] for c in checks):
        fatal("an input check failed; STOP")
    return PK


# --------------------------------------------------------------------------- 1: benign Protocol-0 inventory

def load_split(split: str, feats: list[str]) -> tuple[pd.DataFrame, np.ndarray]:
    meta = m10.load_eval_meta(split)                     # guard_read refuses any test path
    X = m10.load_matrix(SPLIT_PATH[split], feats).astype(np.float64)
    return meta, X


def inventory(split: str, meta: pd.DataFrame, X: np.ndarray, feats: list[str]) -> tuple[list, list, list]:
    proto = X[:, feats.index("Protocol")]
    p0 = proto == 0
    ben = meta["y"].to_numpy() == 0
    rows, dists, attack = [], [], []
    for level in ("device", "device_category", "group", "session"):
        b = meta.loc[ben, level]
        b0 = meta.loc[ben & p0, level]
        tot, tot0 = b.value_counts(), b0.value_counts()
        for key, n0 in tot0.items():
            rows.append({"split": split, "label": "benign", "level": level, "key": key, "proto0_rows": int(n0),
                         "benign_rows": int(tot[key]), "pct_of_key_benign": pct(n0, tot[key]),
                         "pct_of_split_proto0_benign": pct(n0, int((ben & p0).sum()))})
    rows.append({"split": split, "label": "benign", "level": "ALL", "key": "ALL", "proto0_rows": int((ben & p0).sum()),
                 "benign_rows": int(ben.sum()), "pct_of_key_benign": pct((ben & p0).sum(), ben.sum()),
                 "pct_of_split_proto0_benign": 100.0})
    a0 = meta.loc[~ben & p0]
    for fam, n in a0["attack_family"].value_counts().items():
        attack.append({"split": split, "label": "attack", "level": "attack_family", "key": fam, "proto0_rows": int(n),
                       "attack_rows_of_family": int((meta.loc[~ben, "attack_family"] == fam).sum())})
    for f in DIST_FEATS:
        dists.append({"population": f"benign Protocol 0, {split}", "feature": f, "n": int((ben & p0).sum()),
                      **quantiles(X[ben & p0, feats.index(f)])})
    log(f"  {split}: benign {int(ben.sum()):,}, benign Protocol 0 {int((ben & p0).sum()):,} "
        f"({pct((ben & p0).sum(), ben.sum()):.2f} %); attack Protocol 0 {len(a0):,}")
    return rows, dists, attack


# --------------------------------------------------------------------------- 2: tshark on one benign train capture

def tshark_rows(cmd: list[str], names: list[str]):
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, env={**os.environ, "TZ": "UTC"})
        for c in pd.read_csv(proc.stdout, sep="\t", header=None, names=names, dtype=str, keep_default_na=False,
                             quoting=csv.QUOTE_NONE, chunksize=500_000, engine="c"):
            yield c
        rc = proc.wait()
        errf.seek(0)
        err = "\n".join(l for l in errf.read().decode(errors="replace").splitlines()
                        if l.strip() != "resetting session.")
    if rc != 0:
        fatal(f"tshark exited {rc}: {err[-1500:]}")


def benign_packets(dev) -> dict:
    pcap = guard(BENIGN_PCAP)
    got = sha256_file(pcap)
    if got != DATASET.benign_pcap_sha256:
        fatal(f"{pcap} sha256 {got[:16]}... != config DATASET.benign_pcap_sha256")
    cut = read_json(MANIFEST_V1)["session_cuts"][BENIGN_SESSION]
    if cut["splits"][0] != "train":
        fatal(f"{BENIGN_SESSION}: first split is {cut['splits'][0]!r}, not train")
    t_end = float(cut["boundaries_epoch"][0])
    flt = f"frame.time_epoch < {t_end} && ip && !(ip.proto#1 == 6) && !(ip.proto#1 == 17)"
    cmd = ["tshark", "-n", *m02.TSHARK_LEAN, "-r", str(pcap), "-Y", flt, "-T", "fields", "-E", "separator=/t",
           "-E", "occurrence=f", "-E", "quote=n", "-e", "frame.time_epoch", "-e", "eth.src", "-e", "eth.dst",
           "-e", "ip.proto"]
    log(f"  tshark: {' '.join(cmd)}")
    t0 = time.monotonic()
    by_proto, by_src, n = Counter(), Counter(), 0
    for c in tshark_rows(cmd, ["t", "esrc", "edst", "proto"]):
        n += len(c)
        by_proto.update(c["proto"].value_counts().to_dict())
        src = c["esrc"].map(m12b.norm_mac)
        by_src.update(pd.DataFrame({"p": c["proto"], "s": src}).value_counts().to_dict())
    el = time.monotonic() - t0
    # all IPv4 packets of the same window, for the share (counted by capinfos would include non-IP; use tshark)
    cmd_all = ["tshark", "-n", *m02.TSHARK_LEAN, "-r", str(pcap), "-Y", f"frame.time_epoch < {t_end} && ip",
               "-T", "fields", "-e", "frame.time_epoch"]
    n_ip = sum(len(c) for c in tshark_rows(cmd_all, ["t"]))
    src_rows = []
    for (p, s), k in sorted(by_src.items(), key=lambda kv: -kv[1])[:25]:
        name, cls = dev.dest_class(s) if m02.mac_is_unicast(s) else ("non-unicast", "")
        src_rows.append({"ip_proto": p, "name": PROTO_NAMES.get(int(p), p) if p.isdigit() else p, "src_mac": s,
                         "device": "attacker (testbed Pi)" if ATTACKER_MACS.matches(s) else name, "class": cls,
                         "packets": k})
    log(f"  benign train window: {n:,} non-TCP/UDP IPv4 packets of {n_ip:,} IPv4 ({pct(n, n_ip):.3f} %); "
        f"census {el:.0f} s, total {time.monotonic() - t0:.0f} s")
    return {"pcap": str(pcap), "pcap_sha256": got, "session": BENIGN_SESSION,
            "window_utc": ["pcap start", cut["boundaries_utc"][0]],
            "train_end_epoch": t_end, "display_filter": flt, "ipv4_packets": n_ip, "non_tcp_udp_packets": n,
            "by_ip_proto": [{"ip_proto": p, "name": PROTO_NAMES.get(int(p), p) if p.isdigit() else p, "packets": k,
                             "pct_of_non_tcp_udp": pct(k, n)} for p, k in by_proto.most_common()],
            "by_sender": src_rows, "seconds": round(time.monotonic() - t0, 1)}


# --------------------------------------------------------------------------- 3 + 4: pilot flows

def pilot_ip_owner(PK: dict, dev, k2: dict) -> dict:
    """ip -> (mac, device, k2 group): sender evidence of non-attacker senders in the pilot base part (lean tshark),
    then the eth.dst of attacker packets to that ip (12b packets.json)."""
    cmd = ["tshark", "-n", *m02.TSHARK_LEAN, "-r", str(guard(PILOT_PCAP)), "-Y", "ip", "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=f", "-E", "quote=n", "-e", "eth.src", "-e", "ip.src"]
    log(f"  pilot sender map: {' '.join(cmd)}")
    t0 = time.monotonic()
    ev = Counter()
    for c in tshark_rows(cmd, ["mac", "ip"]):
        mac = c["mac"].map(m12b.norm_mac)
        keep = ~mac.map(ATTACKER_MACS.matches).astype(bool) & (c["ip"] != "")
        ev.update(pd.DataFrame({"i": c.loc[keep, "ip"], "m": mac[keep]}).value_counts().to_dict())
    best: dict[str, tuple[int, str, str]] = {}
    for (ip, mac), n in ev.items():
        if n > best.get(ip, (0, "", ""))[0]:
            best[ip] = (n, mac, "sender")
    for ip, mac, n in PK["att_ip_dst_mac"]:
        mac = m12b.norm_mac(mac)
        if ip and ip not in best and m02.mac_is_unicast(mac):
            best[ip] = (n, mac, "attacker eth.dst")
    out = {}
    for ip, (n, mac, how) in best.items():
        role = dev.role.get(mac)
        out[ip] = {"mac": mac, "device": dev.name.get(mac, "unknown"), "role": role or "unknown",
                   "group": k2.get(mac, "GEN") if role == "iot" else "", "evidence": how, "packets": n}
    log(f"  pilot sender map: {len(out):,} IPs in {time.monotonic() - t0:.0f} s")
    return out


def pilot_flows(PK: dict, feats: list[str], owner: dict) -> pd.DataFrame:
    att_ips, _ = m12b.attacker_ip_set(PK)
    gre_pairs = {(s, d) for s, d, p, *_ in PK["att_streams"] if p == "47"}
    use = ["Src IP", "Dst IP", "Src Port", "Dst Port"] + feats
    D = pd.read_csv(guard(PILOT_CSV), usecols=use, low_memory=False, dtype={"Src IP": str, "Dst IP": str})
    D = D[["Src IP", "Dst IP", "Src Port", "Dst Port"] + feats]
    s_att, d_att = D["Src IP"].isin(att_ips), D["Dst IP"].isin(att_ips)
    att = s_att | d_att
    tcpudp = D["Protocol"].isin([6, 17])
    D["population"] = np.select([att & ~tcpudp, att & tcpudp, ~att & (D["Protocol"] == 0)],
                                ["flood", "attacker_tcp_udp_side", "non_attacker_proto0"], "other")
    a_ip = D["Src IP"].where(s_att, D["Dst IP"])
    o_ip = D["Dst IP"].where(s_att, D["Src IP"])
    D["gre_stream"] = [(a, o) in gre_pairs for a, o in zip(a_ip, o_ip)] & att.to_numpy()

    def own(src: str, dst: str, is_att: bool, other: str) -> dict:
        if is_att:
            return owner.get(other, {})
        for ip in (src, dst):
            r = owner.get(ip, {})
            if r.get("role") == "iot":
                return r
        return {}

    O = [own(s, d, a, o) for s, d, a, o in zip(D["Src IP"], D["Dst IP"], att, o_ip)]
    D["owner_ip"] = [o if a else (s if owner.get(s, {}).get("role") == "iot" else d)
                     for s, d, a, o in zip(D["Src IP"], D["Dst IP"], att, o_ip)]
    D["owner_device"] = [r.get("device", "unknown") for r in O]
    D["owner_role"] = [r.get("role", "unknown") for r in O]
    D["group"] = [r.get("group") or "GEN" for r in O]
    # CICFlowMeter reads some non-IPv4 frames as IPv4 (ARP: "8.6.0.1 -> 8.0.6.4" = the ARP header bytes 08 06 00 01 /
    # 08 00 06 04), giving Protocol-0 pseudo-flows between addresses no packet of the capture carries as IPv4
    seen = set(owner) | {ip for ip, _, _ in PK["att_ip_dst_mac"]} | set(att_ips)
    D["non_ipv4_artifact"] = ~(D["Src IP"].isin(seen) | D["Dst IP"].isin(seen))
    log(f"  pilot flows {len(D):,}: " + ", ".join(f"{k} {v:,}" for k, v in D["population"].value_counts().items())
        + f"; GRE-stream flood flows {int((D['gre_stream'] & (D['population'] == 'flood')).sum())}")
    return D


def auc_rows(feats: list[str], Xb: np.ndarray, flood: pd.DataFrame, Xb_split: np.ndarray,
             other: pd.DataFrame) -> list[dict]:
    """09b single-feature AUC, flood (y = 1) vs benign Protocol-0 train + val (y = 0), plus the zero-FP rule and its
    hits on `other` (the pilot's non-attacker Protocol-0 flows: same capture, not in train / val)."""
    Xf = clean(flood[feats].to_numpy()).astype(np.float64)
    Xo = clean(other[feats].to_numpy()).astype(np.float64)
    art = other["non_ipv4_artifact"].to_numpy()
    gre = flood["gre_stream"].to_numpy()
    y = np.r_[np.zeros(len(Xb)), np.ones(len(Xf))]
    rows = []
    for j, f in enumerate(feats):
        xb, xf = Xb[:, j] + 0.0, Xf[:, j] + 0.0
        varies = bool(xf.min() != xf.max())
        r = {"feature": f, "varies_on_flood": varies, "n_benign_p0": len(xb), "n_flood": len(xf),
             "benign_min": float(xb.min()), "benign_p99_9": float(np.percentile(xb, 99.9)), "benign_max": float(xb.max()),
             "flood_min": float(xf.min()), "flood_median": float(np.median(xf)), "flood_max": float(xf.max()),
             "flood_gre_min": float(xf[gre].min()) if gre.any() else math.nan}
        a = roc_auc_score(y, np.r_[xb, xf])
        a_tr = roc_auc_score(np.r_[np.zeros((Xb_split == "train").sum()), np.ones(len(xf))],
                             np.r_[xb[Xb_split == "train"], xf])
        a_va = roc_auc_score(np.r_[np.zeros((Xb_split == "val").sum()), np.ones(len(xf))],
                             np.r_[xb[Xb_split == "val"], xf])
        up = a >= 0.5
        r.update({"auc": a, "max_auc": max(a, 1 - a), "auc_train": a_tr, "auc_val": a_va,
                  "direction": "flood higher" if up else "flood lower",
                  "flag": "SHORTCUT_CANDIDATE" if max(a, 1 - a) >= SHORTCUT_AUC else ""})
        thr = r["benign_max"] if up else r["benign_min"]
        det = xf > thr if up else xf < thr
        hit_o = Xo[:, j] > thr if up else Xo[:, j] < thr
        r.update({"zero_fp_rule": f"{f} {'>' if up else '<'} {thr:g}", "zero_fp_detected": int(det.sum()),
                  "zero_fp_detected_pct": pct(det.sum(), len(xf)), "zero_fp_detected_gre": int(det[gre].sum()),
                  "zero_fp_detected_gre_pct": pct(det[gre].sum(), gre.sum()),
                  "zero_fp_rule_hits_pilot_non_attacker_p0": int(hit_o.sum()), "n_pilot_non_attacker_p0": len(Xo),
                  "of_which_non_ipv4_artifact": int((hit_o & art).sum()), "n_pilot_non_ipv4_artifact": int(art.sum()),
                  "margin_ratio_flood_min_over_benign_max": (r["flood_min"] / r["benign_max"])
                  if up and r["benign_max"] > 0 else math.nan,
                  "margin_ratio_gre_min_over_benign_max": (r["flood_gre_min"] / r["benign_max"])
                  if up and r["benign_max"] > 0 else math.nan})
        rows.append(r)
    return sorted(rows, key=lambda r: (-r["varies_on_flood"], -r["max_auc"]))


def score(D: pd.DataFrame, feats: list[str], P: dict, models: dict) -> tuple[list[dict], pd.DataFrame]:
    X = clean(D[feats].to_numpy())
    full = {m: models[m].predict_proba(X)[:, m10.attack_col(models[m])].astype(np.float64) for m in models}
    routed = D["group"].map(P["routing"]["group_to_model"]).to_numpy(object)
    if pd.isna(routed).any():
        fatal("pilot rows without a routed model")
    s_final = np.full(len(D), np.nan)
    for m in models:
        s_final[routed == m] = full[m][routed == m]
    S = {"FINAL": s_final, "BASELINE": full["GLOBAL"]}
    D = D.assign(routed_model=routed, score_FINAL=S["FINAL"], score_BASELINE=S["BASELINE"])
    pops = [("flood (attacker, not TCP / UDP)", D["population"] == "flood"),
            ("flood, GRE streams only", (D["population"] == "flood") & D["gre_stream"]),
            ("flood, not GRE streams", (D["population"] == "flood") & ~D["gre_stream"]),
            ("attacker TCP / UDP side flows", D["population"] == "attacker_tcp_udp_side"),
            ("non-attacker Protocol-0 flows", D["population"] == "non_attacker_proto0"),
            ("  of which non-IPv4 artefacts (ARP / LLC read as IPv4)",
             (D["population"] == "non_attacker_proto0") & D["non_ipv4_artifact"])]
    rows = []
    for name, m in pops:
        m = m.to_numpy()
        for system in ("FINAL", "BASELINE"):
            for op, thr in P["systems"][system]["thresholds"].items():
                s = S[system][m]
                flag = s >= thr
                rows.append({"population": name, "system": system, "operating_point": op, "threshold": thr,
                             "n": int(m.sum()), "flagged": int(flag.sum()), "flagged_pct": pct(flag.sum(), m.sum()),
                             "packets_in_flagged": int((D.loc[m, "Total Fwd Packet"] + D.loc[m, "Total Bwd packets"])
                                                       .to_numpy()[flag].sum()),
                             "packets_total": int((D.loc[m, "Total Fwd Packet"] + D.loc[m, "Total Bwd packets"]).sum()),
                             "score_min": float(s.min()) if len(s) else math.nan,
                             "score_median": float(np.median(s)) if len(s) else math.nan,
                             "score_max": float(s.max()) if len(s) else math.nan,
                             "routed_models": "; ".join(f"{k} {v}" for k, v in
                                                        pd.Series(routed[m]).value_counts().items()) if system == "FINAL"
                             else f"GLOBAL {int(m.sum())}"})
    return rows, D


# --------------------------------------------------------------------------- main

def main() -> int:
    global _LOG_PATH
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--skip-tshark", action="store_true", help="skip step 2 (benign packet census)")
    args = ap.parse_args()
    t0 = time.monotonic()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "run.log").unlink(missing_ok=True)
    _LOG_PATH = OUT / "run.log"
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...  {LABEL}")
    P = read_json(PREREG)
    M = {"label": LABEL, "script": SCRIPT, "code_sha256": CODE_SHA256,
         "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "argv": sys.argv,
         "git_head": subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True,
                                    text=True).stdout.strip(),
         "test_parquet": "never opened, read or stat'ed by this script", "steps": {}}
    PK = check_inputs(M, P)
    feats = read_json(FEATURES)["features"]
    dev = m12b.m07a.Devices(DEVICE_TABLE)
    k2, _ = k2_by_mac()

    # ---- 1
    s = time.monotonic()
    log("1 benign Protocol-0 inventory ...")
    inv, dists, att0, Xb, Xb_split = [], [], [], [], []
    for split in SPLITS:
        meta, X = load_split(split, feats)
        r, d, a = inventory(split, meta, X, feats)
        inv += r
        dists += d
        att0 += a
        m = (meta["y"].to_numpy() == 0) & (X[:, feats.index("Protocol")] == 0)
        Xb.append(X[m])
        Xb_split.append(np.full(int(m.sum()), split, dtype=object))
        del meta, X
    Xb, Xb_split = np.vstack(Xb), np.concatenate(Xb_split)
    for f in DIST_FEATS:
        dists.append({"population": "benign Protocol 0, train + val", "feature": f, "n": len(Xb),
                      **quantiles(Xb[:, feats.index(f)])})
    M["steps"]["1_inventory_s"] = round(time.monotonic() - s, 1)

    # ---- 2
    s = time.monotonic()
    if args.skip_tshark:
        BP = None
        log("2 skipped (--skip-tshark)")
    else:
        log("2 benign packet census (one train capture, train window) ...")
        BP = benign_packets(dev)
    M["steps"]["2_benign_packets_s"] = round(time.monotonic() - s, 1)

    # ---- 3
    s = time.monotonic()
    log("3 pilot flows: GRE flood vs benign Protocol 0 ...")
    owner = pilot_ip_owner(PK, dev, k2)
    D = pilot_flows(PK, feats, owner)
    flood = D[D["population"] == "flood"]
    if len(flood) != 52:
        log(f"  NOTE: {len(flood)} flood flows (12b reported 52)")
    for name, sub in (("GRE flood flows (52, pilot)", flood),
                      ("GRE flood, GRE streams only", flood[flood["gre_stream"]]),
                      ("pilot non-attacker Protocol 0", D[D["population"] == "non_attacker_proto0"])):
        Xs = clean(sub[feats].to_numpy()).astype(np.float64)
        for f in DIST_FEATS:
            dists.append({"population": name, "feature": f, "n": len(sub), **quantiles(Xs[:, feats.index(f)])})
    AUC = auc_rows(feats, Xb, flood, Xb_split, D[D["population"] == "non_attacker_proto0"])
    M["steps"]["3_auc_s"] = round(time.monotonic() - s, 1)

    # ---- 4
    s = time.monotonic()
    log("4 frozen Step 10 models on the pilot flows (read-only) ...")
    models = {mid: joblib.load(M["models"][mid]["path"]) for mid in P["models"]}
    FM, D = score(D, feats, P, models)
    for r in FM:
        log(f"  {r['population']:<34} {r['system']:<8} {r['operating_point']:<7} {r['flagged']:>4} / {r['n']:<4} "
            f"({fnum(r['flagged_pct'], 1)} %)")
    M["steps"]["4_models_s"] = round(time.monotonic() - s, 1)

    # ---- outputs
    write_csv("proto0_benign_by_device.csv", inv + att0)
    write_csv("proto0_distributions.csv", dists)
    write_csv("gre_vs_benign_auc.csv", AUC)
    write_csv("frozen_models_on_greeth.csv", FM)
    VD = verdicts(inv, AUC, FM)
    M.update({"benign_proto0_totals": [r for r in inv if r["level"] == "ALL"], "attack_proto0": att0,
              "benign_packet_census": BP, "pilot_population_counts": D["population"].value_counts().to_dict(),
              "pilot_owner_map_size": len(owner),
              "flood_flows": D.loc[D["population"] == "flood",
                                   ["Src IP", "Dst IP", "gre_stream", "owner_device", "group", "routed_model",
                                    "Total Fwd Packet", "Flow Duration", "Flow Packets/s", "score_FINAL",
                                    "score_BASELINE"]].to_dict("records"),
              "non_attacker_proto0_flagged": D.loc[(D["population"] == "non_attacker_proto0") &
                                                   ((D["score_FINAL"] >= P["systems"]["FINAL"]["thresholds"]["0.5"]) |
                                                    (D["score_BASELINE"] >= P["systems"]["BASELINE"]["thresholds"]["0.5"])),
                                                   ["Src IP", "Dst IP", "owner_device", "group", "Total Fwd Packet",
                                                    "Flow Duration", "score_FINAL", "score_BASELINE"]].to_dict("records"),
              "verdicts": VD,
              "peak_rss_mb": {"python_self": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
                              "children_max": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024, 1)}})
    M["runtime_s"] = round(time.monotonic() - t0, 1)
    write_json(OUT / "run_meta.json", M)
    write_summary(M, inv, att0, dists, BP, AUC, FM, VD, D)
    log(f"done in {M['runtime_s']:.0f} s -> results/step12c/summary.md")
    return 0


def verdicts(inv, AUC, FM) -> dict:
    get = {(r["population"], r["system"], r["operating_point"]): r for r in FM}
    fl = {k: get[("flood (attacker, not TCP / UDP)", k[0], k[1])] for k in
          (("FINAL", "T_house"), ("FINAL", "0.5"), ("BASELINE", "T_house"), ("BASELINE", "0.5"))}
    gre = {k: get[("flood, GRE streams only", k[0], k[1])] for k in fl}
    q1 = "; ".join(f"{s} @ {op}: flood {r['flagged']}/{r['n']} flows ({fnum(r['flagged_pct'], 1)} %), GRE streams "
                   f"{gre[(s, op)]['flagged']}/{gre[(s, op)]['n']}, packets in flagged flows "
                   f"{fnum(pct(r['packets_in_flagged'], r['packets_total']), 1)} %" for (s, op), r in fl.items())
    a = {r["feature"]: r for r in AUC}
    tot = [r for r in inv if r["level"] == "ALL"]
    q2 = (f"benign Protocol-0 rows: " + ", ".join(f"{r['split']} {r['proto0_rows']:,} "
                                                  f"({fnum(r['pct_of_key_benign'], 2)} % of benign)" for r in tot)
          + "; " + "; ".join(f"{f}: benign max {fnum(a[f]['benign_max'], 1)}, p99.9 {fnum(a[f]['benign_p99_9'], 1)} "
                             f"vs flood min {fnum(a[f]['flood_min'], 1)} / median {fnum(a[f]['flood_median'], 1)} "
                             f"(GRE-stream min {fnum(a[f]['flood_gre_min'], 1)})" for f in RULE_FEATS))
    q3 = "; ".join(f"{a[f]['zero_fp_rule']}: detects {a[f]['zero_fp_detected']}/{a[f]['n_flood']} flood flows "
                   f"({fnum(a[f]['zero_fp_detected_pct'], 1)} %), GRE streams {a[f]['zero_fp_detected_gre']} "
                   f"({fnum(a[f]['zero_fp_detected_gre_pct'], 1)} %); AUC {fnum(a[f]['auc'], 4)}; margin min / "
                   f"benign max: all flood {fnum(a[f]['margin_ratio_flood_min_over_benign_max'], 3)}, GRE streams "
                   f"{fnum(a[f]['margin_ratio_gre_min_over_benign_max'], 3)}; hits on the pilot's non-attacker "
                   f"Protocol-0 flows {a[f]['zero_fp_rule_hits_pilot_non_attacker_p0']}/"
                   f"{a[f]['n_pilot_non_attacker_p0']} (of which non-IPv4 artefacts "
                   f"{a[f]['of_which_non_ipv4_artifact']}/{a[f]['n_pilot_non_ipv4_artifact']})" for f in RULE_FEATS)
    return {"Q1": q1, "Q2": q2, "Q3": q3}


def write_summary(M, inv, att0, dists, BP, AUC, FM, VD, D) -> None:
    L = [f"# Step 12c -- Protocol-0 traffic and the GRE flood ({LABEL})", "",
         f"**{LABEL}.** No training, no threshold change; frozen Step 10 models loaded read-only; test.parquet never "
         "opened. Greeth: only the base-part pilot outputs of 12b.", "",
         f"- run {M['run_utc']}, git HEAD `{M['git_head']}`, {SCRIPT} sha256 `{CODE_SHA256[:16]}...`, runtime "
         f"{M['runtime_s']:,.0f} s",
         "- input checks: " + "; ".join(f"{'PASS' if c['pass'] else 'FAIL'} {c['check']}" for c in M["checks"]), "",
         "## Answers (proposal -- you decide)", "",
         f"- **Q1 frozen models vs the GRE flood:** {VD['Q1']}",
         f"- **Q2 benign Protocol 0 vs the flood:** {VD['Q2']}",
         f"- **Q3 one-feature rate rule:** {VD['Q3']}", ""]
    L += ["## 1. Benign Protocol-0 inventory (train / val)", ""]
    L += md_table([r for r in inv if r["level"] == "ALL"], ["split", "proto0_rows", "benign_rows", "pct_of_key_benign"])
    L += ["", "Protocol-0 ATTACK rows (train / val):", ""]
    L += md_table(att0, ["split", "key", "proto0_rows", "attack_rows_of_family"])
    for level in ("device_category", "group", "session", "device"):
        L += ["", f"### by {level}", ""]
        sub = sorted([r for r in inv if r["level"] == level], key=lambda r: (r["split"], -r["proto0_rows"]))
        L += md_table(sub[:40], ["split", "key", "proto0_rows", "benign_rows", "pct_of_key_benign",
                                 "pct_of_split_proto0_benign"])
    L += ["", "### Distributions", ""]
    L += md_table(dists, ["population", "feature", "n"] + [k for k, _ in QUANTS], nd=1)
    L += ["", "Flow Duration in microseconds; rates per second; 1-packet flows have Flow Packets/s = 0 after 08's "
              "NaN / inf -> 0 cleaning (pilot rows cleaned the same way).", ""]
    L += ["## 2. What benign Protocol 0 is (one benign train capture, packets)", ""]
    if BP is None:
        L += ["Skipped (--skip-tshark)."]
    else:
        L += [f"`{Path(BP['pcap']).name}` (session {BP['session']}, sha256 `{BP['pcap_sha256'][:16]}...`), packets "
              f"before the train / val cut {BP['window_utc'][1]} only: {BP['non_tcp_udp_packets']:,} non-TCP/UDP IPv4 "
              f"packets of {BP['ipv4_packets']:,} IPv4 ({fnum(pct(BP['non_tcp_udp_packets'], BP['ipv4_packets']), 3)} %); "
              f"lean tshark, {BP['seconds']} s.", ""]
        L += md_table(BP["by_ip_proto"], ["ip_proto", "name", "packets", "pct_of_non_tcp_udp"])
        L += ["", "Top senders (ip.proto, source MAC):", ""]
        L += md_table(BP["by_sender"], ["ip_proto", "name", "device", "class", "src_mac", "packets"])
    L += ["", "## 3. GRE flood (12b pilot, base part) vs benign Protocol 0 (train + val)", ""]
    pc = M["pilot_population_counts"]
    L += [f"Pilot flows: {', '.join(f'{k} {v:,}' for k, v in pc.items())}. Flood = attacker flows (12b rule) that are "
          f"not TCP / UDP; GRE streams = (attacker IP, victim IP) pairs that carried outer ip.proto 47 "
          f"({int((D['gre_stream'] & (D['population'] == 'flood')).sum())} of the flood flows).", ""]
    L += ["### Single-feature ROC-AUC (09b method) and zero-benign-FP threshold, features that vary on the flood", ""]
    L += md_table([r for r in AUC if r["varies_on_flood"]],
                  ["feature", "auc", "auc_train", "auc_val", "direction", "flag", "benign_max", "benign_p99_9",
                   "flood_min", "flood_gre_min", "flood_median", "zero_fp_rule", "zero_fp_detected", "zero_fp_detected_gre",
                   "zero_fp_rule_hits_pilot_non_attacker_p0", "of_which_non_ipv4_artifact"], nd=4)
    L += ["", "zero_fp_rule_hits_pilot_non_attacker_p0 = the rule's hits on the pilot capture's non-attacker Protocol-0 "
              "flows (same capture as the flood, not in train / val); of_which_non_ipv4_artifact = hits on pseudo-flows "
              "whose two addresses never appear as an IPv4 address in the capture: CICFlowMeter reads non-IPv4 frames "
              "as IPv4 (ARP gives '8.6.0.1 -> 8.0.6.4' = the ARP header bytes 08 06 00 01 / 08 00 06 04; a spot check "
              "of 15:34-15:36 UTC found ARP to be almost all non-IP frames there).", ""]
    nconst = sum(not r["varies_on_flood"] for r in AUC)
    L += ["", f"{nconst} features are constant on the flood flows (listed in gre_vs_benign_auc.csv with "
              "varies_on_flood = False).", ""]
    L += ["## 4. Frozen Step 10 models on the pilot flows", ""]
    L += md_table(FM, ["population", "system", "operating_point", "threshold", "n", "flagged", "flagged_pct",
                       "packets_in_flagged", "packets_total", "score_median", "routed_models"], nd=4)
    L += ["", "Routing: k2 group of the flow's owner (attacker flows: the non-attacker endpoint; other flows: the "
              "source if a registered iot device, else the destination); no iot owner -> GEN -> GLOBAL. Owner IP -> MAC "
              "from a lean sender-evidence tshark pass on the pilot base part, then 12b's attacker-destination map.", ""]
    fl = [r for r in M["flood_flows"]]
    L += ["### The flood flows, scored", ""]
    L += md_table(sorted(fl, key=lambda r: -r["Total Fwd Packet"]),
                  ["Src IP", "Dst IP", "gre_stream", "owner_device", "group", "routed_model", "Total Fwd Packet",
                   "Flow Packets/s", "score_FINAL", "score_BASELINE"], nd=4)
    if M["non_attacker_proto0_flagged"]:
        L += ["", "### Non-attacker Protocol-0 pilot flows flagged at 0.5 by either system", ""]
        L += md_table(M["non_attacker_proto0_flagged"], ["Src IP", "Dst IP", "owner_device", "group",
                                                         "Total Fwd Packet", "Flow Duration", "score_FINAL",
                                                         "score_BASELINE"], nd=4)
    (OUT / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        log("UNEXPECTED ERROR\n" + traceback.format_exc())
        sys.exit(2)
