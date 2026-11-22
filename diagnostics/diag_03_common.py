#!/usr/bin/env python
"""diagnostics/diag_03_common.py -- shared, READ-ONLY plumbing for diag_03 (alert forensics; parts A and B).

Nothing here writes outside the diag_03 output folder, and nothing is decided here (results/diag_03/choices.md).
  - lock(): verify_v2_lock(strict) + sha256 of config/config.py and config/class_map.json (before / after)
  - load_context(): the pinned Phase 3 config, the step 28 rerun_full run (manifest sha256 re-checked, every
    alerts / health / outbox chain verified with the runtime key), the step 29 rerun_fig_fix metrics (manifest sha256
    re-checked), VAL ground truth and episodes through step 29's OWN functions (29_eval_stream.py imported read-only),
    and the attacker / testbed identity of V1 step 13 / Phase 3 D74 (13_rate_guard_calibrate.MacBook, read-only).
  - Only VAL is read: common/phase2_data (refuses test) and common/packet_source (refuses test sessions and stops
    at the first packet at / after the start of a later split).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from config.config import ATTACKER_MACS, DEVICE_TABLE, REPO_ROOT  # noqa: E402
from common import alert_log as AL  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import phase3_run as R3  # noqa: E402
from common import schemas as S  # noqa: E402

RUN28_ID, RUN28_TAG, RUN29_TAG = "20261122T050150Z", "rerun_full", "rerun_fig_fix"
SRC_CATS = ("attacker", "testbed", "other_device", "unknown")
FLOW_COLS = ["session", "row_in_file", "label_id", "device_mac", "group", "start_ts", "Flow Duration", "Protocol",
             "Src IP", "Src Port", "Dst IP", "Dst Port", "src_mac", "dst_mac", "orientation_flipped",
             "SYN Flag Count", "ACK Flag Count", "RST Flag Count", "FIN Flag Count", "PSH Flag Count",
             "FWD Init Win Bytes", "Bwd Init Win Bytes", "Total Fwd Packet", "Total Bwd packets", "Flow ID"]
V20_COLS = ["session", "row_in_file", "Src IP", "Src Port", "Dst IP", "Dst Port", "src_mac", "dst_mac", "Flow ID"]


def load_module(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def lock(when: str, log) -> dict:
    S.verify_v2_lock(strict=True)
    sh = {"config/config.py": sha256(S.CONFIG_PY_PATH), "config/class_map.json": sha256(S.CLASS_MAP_PATH)}
    log(f"[{when}] verify_v2_lock OK; config.py {sh['config/config.py']}; class_map.json {sh['config/class_map.json']}")
    return sh


class Out:
    """The output folder: new files only (refuses any existing target)."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.fig = self.root / "figures"
        self.fig.mkdir(parents=True, exist_ok=True)
        self.written: list[str] = []

    def path(self, name: str) -> Path:
        p = self.root / name
        if p.exists():
            raise FileExistsError(f"{p} exists (never overwritten)")
        self.written.append(str(p))
        return p

    def write_text(self, name: str, text: str) -> Path:
        p = self.path(name)
        with open(p, "x", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def write_json(self, name: str, obj) -> Path:
        return self.write_text(name, json.dumps(obj, indent=1, default=R3._default) + "\n")


class Hosts:
    """V1 step 13 / D74 identity (evaluation-only ground truth): attacker / testbed-Pi = MacBook exclusion reason
    non-empty (config ATTACKER_MACS exact or prefix, or device_table role testbed_pi). Sub-split for reporting only:
    'attacker' = ATTACKER_MACS.exact, 'testbed' = the rest of that identity; 'other_device' = any other inventory MAC;
    'unknown' = unlisted."""

    def __init__(self):
        m13 = load_module("rate_guard_calibrate_ro", "13_rate_guard_calibrate.py")
        self.book = m13.MacBook(m13.m07a.Devices(DEVICE_TABLE))
        self._c: dict = {}

    def is_attacker(self, mac: str) -> bool:
        return bool(mac) and bool(self.book.get(str(mac).lower())[0])

    def cat(self, mac: str) -> str:
        c = self._c.get(mac)
        if c is None:
            m = str(mac).lower()
            if self.is_attacker(m):
                c = "attacker" if m in ATTACKER_MACS.exact else "testbed"
            elif m in self.book.dev.name:
                c = "other_device"
            else:
                c = "unknown"
            self._c[mac] = c
        return c

    def describe(self) -> dict:
        tb = sorted(m for m, r in self.book.dev.role.items() if r == "testbed_pi")
        return {"rule": "13_rate_guard_calibrate.MacBook.get(mac)[0] != '' (ATTACKER_MACS.matches(mac) or device_table "
                        "role == testbed_pi)",
                "ATTACKER_MACS.exact": list(ATTACKER_MACS.exact), "ATTACKER_MACS.prefixes": list(ATTACKER_MACS.prefixes),
                "device_table_testbed_pi": tb}


def parse_alerts(path: Path, flow_uids: set | None = None) -> tuple[list, dict]:
    """(rate-guard alert records, {flow_uid: flow alert record} for flow_uids)."""
    rg, fl = [], {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            k = line.find('"flow_uid"')
            if k < 0:                                                 # rate-guard alerts carry no flow_uid
                if "rate_guard" in line:
                    a = json.loads(line)
                    if a.get("path") == "rate_guard":
                        rg.append(a)
                continue
            if flow_uids:
                q = line.index('"', line.index(":", k + 10) + 1)
                u = line[q + 1:line.index('"', q + 1)]
                if u in flow_uids:
                    a = json.loads(line)
                    if a.get("path") == "flow" and a.get("flow_uid") == u:
                        fl[u] = a
    return rg, fl


def load_context(log, need_flows: bool = True) -> dict:
    cfg = C.load_phase3_config()
    names = list(S.load_class_map().names)
    E = load_module("eval29_ro", "29_eval_stream.py")
    up = R3.resolve("28", RUN28_ID, False, RUN28_TAG)
    if up["manifest"].get("parity_gate") != "PASS":
        raise RuntimeError("step 28 rerun_full parity gate is not PASS")
    up29 = R3.resolve("29", None, False, RUN29_TAG)
    if up29["manifest"]["run28"]["run_id"] != RUN28_ID:
        raise RuntimeError(f"step 29 {RUN29_TAG} read run28 {up29['manifest']['run28']['run_id']}, not {RUN28_ID}")
    m29 = json.loads((up29["dir"] / "metrics.json").read_text(encoding="utf-8"))
    log(f"step 28 run {up['meta']['run_id']} ({RUN28_TAG}), step 29 run {up29['meta']['run_id']} ({RUN29_TAG}); "
        f"manifest sha256 re-checked")
    gt = E.ground_truth(cfg, False)
    eps = E.episodes(gt, cfg["episodes"]["gap_s"])
    same = len(eps) == len(m29["episodes"]) and all(
        a["episode_id"] == b["episode_id"] and a["device"] == b["device"] and a["class"] == b["class"]
        and abs(a["start"] - b["start"]) < 1e-9 and abs(a["end"] - b["end"]) < 1e-9 for a, b in zip(eps, m29["episodes"]))
    if not same:
        raise RuntimeError("episodes recomputed with step 29's own function differ from step 29's metrics.json")
    log(f"{len(eps)} episodes, identical to step 29 metrics.json; benign val hours {m29['hours']['all']:.6f}")
    pub = AL.runtime_public_key(C.expand(cfg["paths"]["runtime_keys_dir"]))
    runs = {}
    for tag, r in up["manifest"]["runs"].items():
        if tag.startswith("PCAP"):
            continue
        d = Path(r["dir"])
        for nm, fn in (("alerts", "alerts.jsonl"), ("health", "health.jsonl"), ("outbox", cfg["paths"]["outbox"])):
            v = AL.verify_chain(d / fn, pub, expect_n=r["logs"][nm]["n"], expect_head=r["logs"][nm]["head_sha256"])
            if not v["ok"]:
                raise RuntimeError(f"{tag} {nm}: chain verification failed: {v}")
        R = E.load_run(d, gt)
        R["dir"], R["counts"] = d, r["counts"]
        runs[tag] = R
    log(f"{len(runs)} runs loaded; alerts / health / outbox chains verify ({sorted(runs)})")
    ctx = {"cfg": cfg, "names": names, "E": E, "up": up, "up29": up29, "m29": m29, "gt": gt, "eps": eps, "runs": runs,
           "hours": m29["hours"], "hosts": Hosts()}
    if need_flows:
        from common import phase2_data as D
        from common.phase2_config import load_phase2_config
        cfg21 = load_phase2_config(REPO_ROOT / cfg["phase2_config"])
        F = D.load_split(cfg21, "val", FLOW_COLS)
        uid = (F["session"].astype(str) + ":" + F["row_in_file"].astype(str)).to_numpy()
        if not np.array_equal(uid, gt["uid"]):
            raise RuntimeError("v2_1 val extra columns are not in step 29's ground-truth row order")
        cfg20 = load_phase2_config(REPO_ROOT / cfg["source"]["replay_phase2_config"])
        F0 = D.load_split(cfg20, "val", V20_COLS)
        F0.index = (F0["session"].astype(str) + ":" + F0["row_in_file"].astype(str)).to_numpy()
        ctx["flows"], ctx["flows_v20"] = F, F0
        ctx["val_sha256"] = {"v2_1_oriented": D.verify_split_file(cfg21, "val"),
                             "v2_0_v1equiv": D.verify_split_file(cfg20, "val")}
        log(f"val flows: v2_1_oriented {len(F):,} rows, v2_0_v1equiv {len(F0):,} rows (sha256 == dataset manifests)")
    return ctx


def family_of(cfg: dict):
    fam = {int(p): n for n, ps in cfg["rate_guard"]["families"].items() for p in ps}
    other = cfg["rate_guard"]["other_family"]
    return lambda proto: fam.get(int(proto), other)


def episode_flow_mask(gt: dict, e: dict) -> np.ndarray:
    """The labelled flows of an episode (same class and device, start inside [start, end]; episodes of one
    (class, device) are > gap_s apart, so this is exactly the flows step 29 grouped into it)."""
    return (gt["y"] == e["class"]) & (gt["dev"] == e["device"]) & (gt["start"] >= e["start"]) & (gt["start"] <= e["end"])


def interval_distance(t: float, lo: float, hi: float) -> float:
    return 0.0 if lo <= t <= hi else (lo - t if t < lo else t - hi)
