#!/usr/bin/env python
"""12a_mirai_inventory.py -- READ-ONLY inventory of the Mirai data, to plan better Mirai detection.

No extraction, no CICFlowMeter, no training, no labelling run, and test.parquet is never opened or stat'ed:
test-side counts come from manifests / split plans / 07 outputs, and per-flow numbers from the 07 labelled
CSVs that already exist (re-read with 08's own filter and the manifest's cut points).

Report (results/step12a/summary.md)
  1 parts     every Mirai pcap found locally (recursive, name matches "mirai", under CACHE_DIR/ciciot2023 and
              data/raw): variant, part number, size, packets + capture span (07a stats when present; else
              capinfos -c -a -e, only while the total stays under CAPINFOS_BUDGET_S, else size only)
  2 use       v1 / v1_1 session mode and the splits it feeds (split_plan_v1_1.json, manifest_v1 session_cuts),
              or "unused"
  3 yield     per used part and victim: 07a attack packets, 07 attack flows, attack (and benign) dataset rows
              per split (08's usable() + assign(); == manifest_v1 by_split_group_label_family, asserted),
              packets per flow, flow durations, 5-tuples and the flow count the 120 s flow timeout alone
              would give; the packets-per-flow distribution of the TEST attack flows, G1 vs G2
  4 rates     attack flows per GB, per M attack packets and per victim, per part and pooled, G1 vs G2;
              with --parts-list, projected flows per listed part from those rates
  5 cost      time and disk per GB of pcap: extractor sidecar elapsed + 07a tshark + 07 runtime of the used
              parts, and the MIRAIcut1M projection run (extract / map / 03b, /usr/bin/time logs)
  6 reserve   which parts could be held back untouched as a future test set (proposal only): none of the
              local parts (all used); with --parts-list, the listed parts not present locally, latest part
              number first per variant

--parts-list <txt>: one "name,size" per line (size in bytes, or a number with B / KB / MB / GB / KiB / MiB /
GiB; "#" lines ignored). Listed parts that are local are matched by file name; the others are projected only.
Without it, items 4 and 6 are rates and a statement (the A path); the code path is the same, the list only
adds rows.

Outputs -> results/step12a/: summary.md, mirai_parts.csv, mirai_used_yield.csv, run_meta.json, run.log.

Exit status: 0 ok, 1 bad input / check failed, 2 unexpected exception.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import ATTACK_FLOWS_DIR, CACHE_DIR, CONFIG_DIR, DATA_RAW, EXTRACTOR, REPO_ROOT, RESULTS_DIR, sha256_file


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m08 = _load("build_datasets", "08_build_datasets.py")

SCRIPT = "12a_mirai_inventory.py"
CODE_SHA256 = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
SEARCH_ROOTS = [CACHE_DIR / "ciciot2023", DATA_RAW]
NAME_RE = re.compile(r"(?i)mirai")
PART_RE = re.compile(r"(?i)^mirai-(?P<variant>[a-z_]+?)(?P<part>\d*)\.pcap(ng)?$")
ATTACK_SET = CONFIG_DIR / "attack_set.json"
SPLIT_PLAN_V1 = CONFIG_DIR / "split_plan.json"
SPLIT_PLAN_V11 = CONFIG_DIR / "split_plan_v1_1.json"
MANIFEST_V1 = RESULTS_DIR / "step8" / "manifest_v1.json"
MANIFEST_V11 = RESULTS_DIR / "step8b" / "manifest_v1_1.json"
K2_JSON = CONFIG_DIR / "groupings" / "behaviour_k2.json"
COVERAGE_DIR = RESULTS_DIR / "step7" / "coverage"
LABEL_REPORTS = RESULTS_DIR / "step7" / "labels"
MAPS_DIR = CACHE_DIR / "maps"
PROJECTION_DIR = CACHE_DIR / "projection"
PROJ_STEM = "MIRAIcut1M"
OUT = RESULTS_DIR / "step12a"
FAMILY = "udp_flood"
SPLITS = ("train", "val", "test")
CAPINFOS_BUDGET_S = 600
FLOW_TIMEOUT_S = float(EXTRACTOR.flow_timeout_s)
NEAR_TIMEOUT_S = FLOW_TIMEOUT_S - 5           # durations >= this count as "cut by the 120 s flow timeout"
NUM = ["Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets"]
STR = ["Src IP", "Dst IP", "Src Port", "Dst Port"]
PKT_BINS = [0, 1, 10, 100, 1_000, 10_000, 100_000, np.inf]
PKT_LABELS = ["1", "2-10", "11-100", "101-1k", "1k-10k", "10k-100k", ">100k"]
UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "kib": 2 ** 10, "mib": 2 ** 20, "gib": 2 ** 30}

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


def rel(p) -> str:
    p = Path(p).expanduser().resolve()
    for base, tag in ((REPO_ROOT.resolve(), ""), (Path.home().resolve(), "~/")):
        if p.is_relative_to(base):
            return tag + str(p.relative_to(base))
    return str(p)


def gb(b: float) -> float:
    return b / 1e9


def fnum(v, nd: int = 2) -> str:
    if v is None or (isinstance(v, float) and (math.isnan(v) or math.isinf(v))):
        return "N/A"
    return f"{v:,.{nd}f}" if isinstance(v, float) else f"{v:,}" if isinstance(v, (int, np.integer)) else str(v)


def md_table(rows: list[dict], cols: list[str]) -> list[str]:
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(fnum(r.get(c, "")) if not isinstance(r.get(c, ""), str) else r.get(c, "")
                              for c in cols) + " |" for r in rows]
    return out


def write_csv(name: str, df: pd.DataFrame) -> None:
    df.to_csv(OUT / name, index=False, lineterminator="\n")


def parse_size(s: str) -> float:
    m = re.fullmatch(r"\s*([\d.,]+)\s*([A-Za-z]*)\s*", s)
    if not m:
        raise ValueError(f"cannot parse size {s!r}")
    unit = (m.group(2) or "b").lower()
    if unit not in UNITS:
        raise ValueError(f"unknown size unit {m.group(2)!r} in {s!r}")
    return float(m.group(1).replace(",", "")) * UNITS[unit]


def parse_name(name: str) -> tuple[str, str]:
    m = PART_RE.match(name)
    return (m.group("variant").lower(), m.group("part")) if m else ("unknown", "")


def time_log(path: Path) -> dict:
    """/usr/bin/time -v output -> elapsed s, peak RSS MB."""
    if not path.is_file():
        return {}
    T = path.read_text(encoding="utf-8", errors="replace")
    out = {}
    m = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:.]+)", T)
    if m:
        parts = [float(x) for x in m.group(1).split(":")]
        out["elapsed_s"] = sum(v * 60 ** i for i, v in enumerate(reversed(parts)))
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", T)
    if m:
        out["peak_rss_mb"] = int(m.group(1)) / 1024
    return out


# --------------------------------------------------------------------------- 1 + 2: parts

def find_parts() -> list[Path]:
    seen, out = set(), []
    for root in SEARCH_ROOTS:
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file() and NAME_RE.search(p.name) and p.suffix.lower() in (".pcap", ".pcapng"):
                rp = p.resolve()
                if rp not in seen:
                    seen.add(rp)
                    out.append(p)
    return out


def capinfos(p: Path, budget: dict) -> dict:
    """Packets + first / last packet time; only while the time budget lasts."""
    exe = shutil.which("capinfos")
    if not exe or budget["left"] <= 0:
        return {"packets_source": "skipped (budget / no capinfos): size only"}
    t = time.monotonic()
    try:
        r = subprocess.run([exe, "-M", "-c", "-a", "-e", "-T", "-m", str(p)], capture_output=True, text=True,
                           timeout=budget["left"])
    except subprocess.TimeoutExpired:
        budget["left"] = 0
        return {"packets_source": "capinfos timed out: size only"}
    budget["left"] -= time.monotonic() - t
    rows = [x.split(",") for x in r.stdout.strip().splitlines()]
    if len(rows) < 2:
        return {"packets_source": f"capinfos failed: {r.stderr.strip()[:120]}"}
    d = dict(zip(rows[0], rows[1]))
    return {"packets": int(d.get("Number of packets", 0) or 0), "first_utc": d.get("First packet time", ""),
            "last_utc": d.get("Last packet time", ""), "packets_source": "capinfos"}


def part_rows(paths: list[Path], aset: dict, plan11: dict, M1: dict) -> list[dict]:
    by_name = {Path(e["path"]).name: e for e in aset["pcaps"]}
    budget = {"left": CAPINFOS_BUDGET_S}
    rows = []
    for p in paths:
        stem = p.stem
        var, part = parse_name(p.name)
        e = by_name.get(p.name)
        stats = COVERAGE_DIR / f"{stem}_stats.json"
        r = {"file": p.name, "path": rel(p), "variant": var, "part": part or "(none)",
             "alias": plan11["session_aliases"].get(stem, ""), "size_bytes": p.stat().st_size,
             "size_gb": gb(p.stat().st_size), "in_attack_set": bool(e)}
        if stats.is_file():
            S = read_json(stats)
            if e and S.get("sha256") != e["sha256"]:
                fatal(f"{stats.name} sha256 != attack_set.json for {p.name}; STOP")
            r.update({"packets": int(S["S"]["packets"]), "attacker_packets": int(S["S"]["att_src"]),
                      "first_utc": S["capture"]["first_utc"], "last_utc": S["capture"]["last_utc"],
                      "capture_minutes": float(S["capture"]["minutes"]), "packets_source": "07a stats (S.packets)"})
        else:
            r.update(capinfos(p, budget))
        mode = plan11["sessions"].get(stem)
        if mode is None:
            r.update({"used": "unused", "session_mode": "", "splits": "", "used_in": ""})
        else:
            cuts = M1["session_cuts"].get(stem, {})
            sp = [s for s in cuts.get("splits", []) if not s.startswith("gap@")]
            r.update({"used": "used", "session_mode": mode, "splits": "+".join(sp), "used_in": "v1, v1_1"})
        r["listed"] = False
        rows.append(r)
    return rows


# --------------------------------------------------------------------------- 3: yield of used parts

def k2_groups() -> dict:
    J = read_json(K2_JSON)
    return {J["device_info"][m]["device_name"]: g for m, g in J["devices"].items()}


def used_flows(stem: str, src: dict, cuts: dict, dev: pd.DataFrame) -> pd.DataFrame:
    """Every usable row of the labelled CSV (08's usable(), as the dataset was built) with split, label, owner
    device and the flow-shape columns."""
    cols = ["Timestamp"] + m08.META_COLS + m08.LABEL_COLS + STR + NUM
    parts = []
    for off, f in m08.iter_chunks(src["path"], list(dict.fromkeys(cols)), NUM, 500_000, 32, None):
        _, pos, U = m08.usable(f, src, dev, Counter())
        U = U.reset_index(drop=True)
        U["split"] = m08.assign(U["t"].to_numpy(), (cuts["boundaries_epoch"], cuts["splits"]))
        for c in STR + NUM:
            U[c] = f[c].to_numpy()[pos]
        parts.append(U)
    D = pd.concat(parts, ignore_index=True)
    D["packets"] = D["Total Fwd Packet"].fillna(0) + D["Total Bwd packets"].fillna(0)
    D["dur_s"] = D["Flow Duration"].fillna(0) / 1e6
    return D


def pkt_stats(x: np.ndarray) -> dict:
    if not len(x):
        return {k: math.nan for k in ("pkts_min", "pkts_p25", "pkts_median", "pkts_p75", "pkts_p90", "pkts_max",
                                      "pkts_mean")}
    q = np.percentile(x, [0, 25, 50, 75, 90, 100])
    return {"pkts_min": float(q[0]), "pkts_p25": float(q[1]), "pkts_median": float(q[2]), "pkts_p75": float(q[3]),
            "pkts_p90": float(q[4]), "pkts_max": float(q[5]), "pkts_mean": float(x.mean())}


def timeout_flows(A: pd.DataFrame) -> tuple[int, int]:
    """Distinct 5-tuples of the attack flows and the flow count the 120 s flow timeout alone would give
    (per 5-tuple ceil(span / 120 s), span = first start .. last end)."""
    if A.empty:
        return 0, 0
    key = A["Src IP"].astype(str) + "|" + A["Dst IP"].astype(str) + "|" + A["Src Port"].astype(str) + "|" + \
        A["Dst Port"].astype(str) + "|" + A["Protocol"].astype(str)
    g = pd.DataFrame({"k": key, "lo": A["t"].astype(float), "hi": A["t"].astype(float) + A["dur_s"]}).groupby("k")
    span = (g["hi"].max() - g["lo"].min()).to_numpy()
    return int(len(span)), int(np.maximum(1, np.ceil(span / FLOW_TIMEOUT_S)).sum())


def victim_rows(stem: str, D: pd.DataFrame, S: dict, R: dict, grp: dict, part_gb: float) -> list[dict]:
    att = D[D["label"] == "attack"]
    vpk = {v["device"]: int(v["attack_packets"]) for v in S["victims"]}
    vfl = {v["device"]: int(v["attack_flows"]) for v in R["attack_per_victim"]}
    rows = []
    devs = sorted(set(vpk) | set(vfl) | set(att["device"].dropna()), key=lambda d: -vpk.get(d, 0))
    for d in devs:
        a = att[att["device"] == d]
        b = D[(D["label"] == "benign") & (D["device"] == d)]
        n5, tflows = timeout_flows(a)
        r = {"part": stem, "victim_device": d, "group": grp.get(d, "gateway / not grouped"),
             "attack_packets_07a": vpk.get(d, 0), "attack_flows_07": vfl.get(d, 0),
             **{f"attack_rows_{sp}": int((a["split"] == sp).sum()) for sp in SPLITS},
             "attack_rows_gap_dropped": int(a["split"].str.startswith("gap@").sum()),
             **{f"benign_rows_{sp}": int((b["split"] == sp).sum()) for sp in SPLITS},
             "attack_flow_packets_sum": float(a["packets"].sum()),
             "packets_per_attack_flow_07a": vpk.get(d, 0) / vfl[d] if vfl.get(d) else math.nan,
             **pkt_stats(a["packets"].to_numpy(float)),
             "dur_median_s": float(a["dur_s"].median()) if len(a) else math.nan,
             "dur_max_s": float(a["dur_s"].max()) if len(a) else math.nan,
             "flows_near_120s_timeout": int((a["dur_s"] >= NEAR_TIMEOUT_S).sum()),
             "attack_5tuples": n5, "flows_if_only_120s_timeout": tflows}
        rows.append(r)
    victims = list(rows)                       # totals below must not count each other
    for g in ("G1", "G2", "ALL"):
        sub = [r for r in victims if g == "ALL" or r["group"] == g]
        a = att if g == "ALL" else att[att["device"].map(grp) == g]
        n5, tflows = timeout_flows(a)
        rows.append({"part": stem, "victim_device": f"TOTAL {g}", "group": g,
                     "attack_packets_07a": sum(r["attack_packets_07a"] for r in sub),
                     "attack_flows_07": sum(r["attack_flows_07"] for r in sub),
                     **{f"attack_rows_{sp}": int((a["split"] == sp).sum()) for sp in SPLITS},
                     "attack_rows_gap_dropped": int(a["split"].str.startswith("gap@").sum()),
                     **{f"benign_rows_{sp}": sum(r[f"benign_rows_{sp}"] for r in sub) for sp in SPLITS},
                     "attack_flow_packets_sum": float(a["packets"].sum()),
                     **pkt_stats(a["packets"].to_numpy(float)),
                     "dur_median_s": float(a["dur_s"].median()) if len(a) else math.nan,
                     "dur_max_s": float(a["dur_s"].max()) if len(a) else math.nan,
                     "flows_near_120s_timeout": int((a["dur_s"] >= NEAR_TIMEOUT_S).sum()),
                     "attack_5tuples": n5, "flows_if_only_120s_timeout": tflows,
                     "n_victims_with_flows": sum(r["attack_flows_07"] > 0 for r in sub),
                     "part_gb": part_gb})
    return rows


def rates(Y: pd.DataFrame, parts: pd.DataFrame) -> list[dict]:
    """Attack flows per GB / per M attack packets / per victim, per used part and pooled, G1 / G2 / ALL."""
    out = []
    T = Y[Y["victim_device"].str.startswith("TOTAL ")]
    used = parts[parts["used"] == "used"].set_index("file")
    stems = sorted(set(T["part"]))
    for scope in stems + ["POOLED"]:
        for g in ("G1", "G2", "ALL"):
            t = T[(T["group"] == g) & ((T["part"] == scope) if scope != "POOLED" else True)]
            size = float(sum(used.loc[f"{s}.pcap", "size_gb"] for s in (stems if scope == "POOLED" else [scope])))
            fl, pk, nv = int(t["attack_flows_07"].sum()), int(t["attack_packets_07a"].sum()), int(t["n_victims_with_flows"].sum())
            out.append({"scope": scope, "group": g, "attack_flows": fl, "attack_packets": pk, "victims_with_flows": nv,
                        "pcap_gb": size, "flows_per_gb": fl / size if size else math.nan,
                        "flows_per_M_attack_packets": fl / pk * 1e6 if pk else math.nan,
                        "flows_per_victim": fl / nv if nv else math.nan,
                        "dataset_rows": int(t[[f"attack_rows_{sp}" for sp in SPLITS]].to_numpy().sum())})
    return out


# --------------------------------------------------------------------------- 5: cost

def cost(parts: pd.DataFrame) -> tuple[list[dict], dict]:
    rows = []
    for _, p in parts[parts["used"] == "used"].iterrows():
        stem = Path(p["file"]).stem
        meta = read_json(ATTACK_FLOWS_DIR / stem / f"{stem}.pcap_Flow__singlepkt.csv.meta.json")
        S, R = read_json(COVERAGE_DIR / f"{stem}_stats.json"), read_json(LABEL_REPORTS / f"{stem}_label_report.json")
        files = [ATTACK_FLOWS_DIR / stem / f"{stem}.pcap_Flow__singlepkt.csv", ATTACK_FLOWS_DIR / stem / f"{stem}_labelled.csv.gz",
                 MAPS_DIR / f"{stem}_ip_mac_map.csv", MAPS_DIR / f"{stem}_attacker_ips.json"]
        disk = sum(f.stat().st_size for f in files if f.is_file())
        sec = float(meta["elapsed_s"]) + float(S["S"].get("tshark_seconds", 0)) + float(R["runtime_s"])
        rows.append({"source": stem, "pcap_gb": p["size_gb"], "extract_s": float(meta["elapsed_s"]),
                     "07a_tshark_s": float(S["S"].get("tshark_seconds", 0)), "07_label_s": float(R["runtime_s"]),
                     "total_s": sec, "s_per_gb": sec / p["size_gb"], "derived_disk_bytes": disk,
                     "derived_disk_per_gb_mb": disk / 1e6 / p["size_gb"],
                     "peak_rss_07_mb": R["peak_rss"].get("self_mb"), "peak_rss_07_tshark_mb": R["peak_rss"].get("tshark_mb"),
                     "jar_sha256_ok": meta["jar_sha256"] == EXTRACTOR.jar_sha256})
    pj = {"pcap": PROJECTION_DIR / f"{PROJ_STEM}.pcap"}
    if pj["pcap"].is_file():
        b = pj["pcap"].stat().st_size
        tt = {k: time_log(PROJECTION_DIR / f"{PROJ_STEM}.{k}.time") for k in ("extract", "map", "03b")}
        fcsv = PROJECTION_DIR / f"flows_{PROJ_STEM}" / f"{PROJ_STEM}.pcap_Flow__singlepkt.csv"
        pmeta = PROJECTION_DIR / f"flows_{PROJ_STEM}" / f"{PROJ_STEM}.pcap_Flow__singlepkt.csv.meta.json"
        M = read_json(pmeta) if pmeta.is_file() else {}
        sec = sum(v.get("elapsed_s", 0) for v in tt.values())
        rows.append({"source": f"{PROJ_STEM} (1M-packet cut; singlepkt jar {str(M.get('jar_sha256', ''))[:8]}..., "
                               "before the idle sweeper)",
                     "pcap_gb": gb(b), "extract_s": tt["extract"].get("elapsed_s"), "07a_tshark_s": math.nan,
                     "07_label_s": math.nan, "map_s": tt["map"].get("elapsed_s"), "03b_s": tt["03b"].get("elapsed_s"),
                     "total_s": sec, "s_per_gb": sec / gb(b), "derived_disk_bytes": fcsv.stat().st_size if fcsv.is_file() else 0,
                     "derived_disk_per_gb_mb": (fcsv.stat().st_size / 1e6 / gb(b)) if fcsv.is_file() else math.nan,
                     "peak_rss_07_mb": math.nan, "peak_rss_07_tshark_mb": math.nan,
                     "extract_peak_rss_mb": tt["extract"].get("peak_rss_mb"), "packets": M.get("packets", {}).get("total"),
                     "flows": M.get("row_count"), "jar_sha256_ok": M.get("jar_sha256") == EXTRACTOR.jar_sha256})
    used = [r for r in rows if not r["source"].startswith(PROJ_STEM)]
    pooled = {"s_per_gb": sum(r["total_s"] for r in used) / sum(r["pcap_gb"] for r in used) if used else math.nan,
              "derived_disk_per_gb_mb": sum(r["derived_disk_bytes"] for r in used) / 1e6 / sum(r["pcap_gb"] for r in used)
              if used else math.nan}
    return rows, pooled


# --------------------------------------------------------------------------- main

def main() -> int:
    global _LOG_PATH
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--parts-list", type=Path, default=None, help='optional txt: one "name,size" per line')
    args = ap.parse_args()
    t0 = time.monotonic()
    run_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "run.log").unlink(missing_ok=True)
    _LOG_PATH = OUT / "run.log"
    log(f"{SCRIPT}  pid {os.getpid()}  code sha256 {CODE_SHA256[:16]}...  parts-list {args.parts_list}")
    aset, plan11, M1, M11 = read_json(ATTACK_SET), read_json(SPLIT_PLAN_V11), read_json(MANIFEST_V1), read_json(MANIFEST_V11)
    grp = k2_groups()

    # ---- 1 + 2
    paths = find_parts()
    log(f"local Mirai pcaps: {[p.name for p in paths]} (searched {[rel(r) for r in SEARCH_ROOTS]})")
    rows = part_rows(paths, aset, plan11, M1)
    listed = []
    if args.parts_list:
        local = {r["file"] for r in rows}
        for ln, line in enumerate(args.parts_list.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                name, size = [x.strip() for x in line.split(",", 1)]
                b = parse_size(size)
            except ValueError as e:
                fatal(f"{args.parts_list}:{ln}: {e}")
            listed.append(name)
            if name in local:
                next(r for r in rows if r["file"] == name)["listed"] = True
                continue
            var, part = parse_name(name)
            rows.append({"file": name, "path": "", "variant": var, "part": part or "(none)", "alias": "",
                         "size_bytes": int(b), "size_gb": gb(b), "in_attack_set": False, "packets_source": "not local",
                         "used": "not local (listed)", "session_mode": "", "splits": "", "used_in": "", "listed": True})
    parts = pd.DataFrame(rows)

    # ---- 3
    P1 = m08.load_plan(SPLIT_PLAN_V1, aset)
    sources = {s["session"]: s for s in m08.load_sources(P1, aset, ATTACK_FLOWS_DIR)}
    dev = m08.load_device_map()
    inputs = {i["session"]: i for i in M1["inputs"]}
    Y, D_all, checks = [], {}, []
    for _, p in parts[parts["used"] == "used"].iterrows():
        stem = Path(p["file"]).stem
        src = sources[stem]
        sha = sha256_file(src["path"])
        if sha != inputs[stem]["sha256"]:
            fatal(f"{stem}: labelled CSV sha256 != manifest_v1 inputs; STOP")
        D = used_flows(stem, src, M1["session_cuts"][stem], dev)
        D_all[stem] = D
        S, R = read_json(COVERAGE_DIR / f"{stem}_stats.json"), read_json(LABEL_REPORTS / f"{stem}_label_report.json")
        Y += victim_rows(stem, D, S, R, grp, p["size_gb"])
        n07 = int(R["by_label"]["attack"])
        nv = sum(int(v["attack_flows"]) for v in R["attack_per_victim"])
        nd = int((D["label"] == "attack").sum())
        checks.append({"check": f"{stem}: 07 attack flows == sum over victims == usable attack rows",
                       "pass": n07 == nv == nd, "detail": f"07 {n07}, per-victim {nv}, usable {nd}"})
    Y = pd.DataFrame(Y)
    # dataset rows per split / group == manifest_v1 (Mirai is never capped)
    man = {(r["split"], r["group"]): int(r["written"]) for r in M1["by_split_group_label_family"]
           if r.get("family") == FAMILY and r.get("label") == "attack"}
    T = Y[Y["victim_device"].str.startswith("TOTAL ") & Y["group"].isin(["G1", "G2"])]
    got = {}
    for _, t in T.iterrows():
        for sp in SPLITS:
            if t[f"attack_rows_{sp}"]:
                got[(sp, t["group"])] = got.get((sp, t["group"]), 0) + int(t[f"attack_rows_{sp}"])
    checks.append({"check": "Mirai dataset rows per (split, group) == manifest_v1 by_split_group_label_family",
                   "pass": got == man, "detail": f"derived {dict(sorted(got.items()))} vs manifest {dict(sorted(man.items()))}"})
    for c in checks:
        log(f"CHECK {'PASS' if c['pass'] else 'FAIL'}  {c['check']}: {c['detail']}")
    if not all(c["pass"] for c in checks):
        fatal("a consistency check failed; STOP")

    # test packets-per-flow distribution, G1 vs G2
    dist = []
    for stem, D in D_all.items():
        a = D[(D["label"] == "attack") & (D["split"] == "test")]
        for g in ("G1", "G2"):
            x = a.loc[a["device"].map(grp) == g, "packets"].to_numpy(float)
            if not len(x):
                continue
            h = pd.cut(x, PKT_BINS, labels=PKT_LABELS, right=True).value_counts().reindex(PKT_LABELS).fillna(0).astype(int)
            dist.append({"part": stem, "group": g, "n_flows": len(x), **pkt_stats(x),
                         "dur_median_s": float(np.median(a.loc[a["device"].map(grp) == g, "dur_s"])),
                         **{f"pkts_{k}": int(v) for k, v in h.items()},
                         "by_victim": "; ".join(f"{d} {n}" for d, n in a.loc[a["device"].map(grp) == g, "device"]
                                                .value_counts().items())})

    # ---- 4
    RT = rates(Y, parts)
    pooled = {(r["group"]): r for r in RT if r["scope"] == "POOLED"}
    per_part = {(r["scope"], r["group"]): r for r in RT if r["scope"] != "POOLED"}
    # ---- 5
    C, cpool = cost(parts)
    proj = []
    for i, r in parts.iterrows():
        if r["used"] != "not local (listed)":
            continue
        g = r["size_gb"]
        lo_hi = {grp_: sorted(per_part[(s, grp_)]["flows_per_gb"] for s in sorted({k[0] for k in per_part})) for grp_ in ("G1", "G2", "ALL")}
        x = {"file": r["file"], "variant": r["variant"], "part": r["part"], "size_gb": g,
             "variant_note": "same variant as the yield source" if r["variant"] == "udpplain"
             else f"EXTRAPOLATED from udpplain ({r['variant']} may yield differently)"}
        for grp_ in ("G1", "G2", "ALL"):
            x[f"proj_flows_{grp_}"] = pooled[grp_]["flows_per_gb"] * g
            x[f"proj_flows_{grp_}_range"] = f"{lo_hi[grp_][0] * g:.0f}-{lo_hi[grp_][-1] * g:.0f}"
        x["proj_extract_label_s"] = cpool["s_per_gb"] * g
        x["proj_derived_disk_mb"] = cpool["derived_disk_per_gb_mb"] * g
        proj.append(x)
        for k, v in x.items():
            if k.startswith("proj_"):
                parts.loc[i, k] = v
    # ---- 6
    reserve = []
    if proj:
        pr = pd.DataFrame(proj)
        pr["part_n"] = pd.to_numeric(pr["part"], errors="coerce")
        for var, d in pr.sort_values("part_n", ascending=False).groupby("variant", sort=True):
            for _, r in d.iterrows():
                reserve.append({"variant": var, "file": r["file"], "part": r["part"], "size_gb": r["size_gb"],
                                "proj_flows_ALL": r["proj_flows_ALL"],
                                "why": "highest part number of its variant (part number as a proxy for later capture; "
                                       "victims unknown until 07a runs)" if r["part_n"] == d["part_n"].max()
                                else "later-numbered part (proxy)"})

    write_csv("mirai_parts.csv", parts)
    write_csv("mirai_used_yield.csv", Y)
    M = {"script": SCRIPT, "code_sha256": CODE_SHA256, "run_utc": run_utc, "argv": sys.argv,
         "git_head": subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True,
                                    text=True).stdout.strip(),
         "search_roots": [rel(r) for r in SEARCH_ROOTS], "parts_list": str(args.parts_list) if args.parts_list else None,
         "parts_listed": listed, "checks": checks,
         "inputs_sha256": {rel(p): sha256_file(p) for p in (ATTACK_SET, SPLIT_PLAN_V1, SPLIT_PLAN_V11, MANIFEST_V1,
                                                            MANIFEST_V11, K2_JSON, CONFIG_DIR / "device_table.csv")},
         "labelled_csv_sha256": {s: inputs[s]["sha256"] for s in D_all},
         "rates": RT, "test_pkt_distribution": dist, "cost": C, "cost_pooled": cpool, "projection": proj,
         "reserve_candidates": reserve, "test_parquet": "never opened or stat'ed",
         "extractor": {"flow_timeout_s": EXTRACTOR.flow_timeout_s, "activity_timeout_s": EXTRACTOR.activity_timeout_s,
                       "jar_sha256": EXTRACTOR.jar_sha256}}
    M["runtime_s"] = round(time.monotonic() - t0, 1)
    (OUT / "run_meta.json").write_text(json.dumps(M, indent=1, default=lambda o: o.item() if hasattr(o, "item")
                                                  else str(o)) + "\n", encoding="utf-8")
    write_summary(M, parts, Y, dist)
    log(f"done in {M['runtime_s']:.0f} s -> {rel(OUT)}/summary.md")
    return 0


def write_summary(M: dict, parts: pd.DataFrame, Y: pd.DataFrame, dist: list[dict]) -> None:
    L = ["# Step 12a -- Mirai data inventory (read-only)", "",
         f"- run {M['run_utc']}, git HEAD `{M['git_head']}`, {SCRIPT} sha256 `{CODE_SHA256[:16]}...`; parts list: "
         f"{M['parts_list'] or 'none (path A: local parts only)'}",
         "- no extraction, no training, no labelling; test.parquet never opened. Per-flow numbers from the existing 07 "
         "labelled CSVs, re-read with 08's filter and the manifest cut points; checks: " +
         "; ".join(f"{'PASS' if c['pass'] else 'FAIL'} {c['check']}" for c in M["checks"]), "",
         "## 1-2. Mirai pcaps found locally, and their use", "",
         f"Searched (recursive, name contains 'mirai'): {', '.join(M['search_roots'])}.", ""]
    L += md_table(parts.to_dict("records"), ["file", "variant", "part", "alias", "size_gb", "packets", "attacker_packets",
                                             "first_utc", "last_utc", "used", "session_mode", "splits", "used_in"])
    loc = parts[parts["used"] != "not local (listed)"]
    var = sorted(set(loc["variant"]))
    L += ["", f"- {len(loc)} local Mirai pcap(s), variant(s) {var}; {int((loc['used'] == 'used').sum())} used, "
              f"{int((loc['used'] == 'unused').sum())} unused. No greeth_flood / greip_flood or other udpplain part is "
              "present locally.", ""]
    L += ["## 3. Yield of the used parts, per victim", ""]
    vc = ["part", "victim_device", "group", "attack_packets_07a", "attack_flows_07", "attack_rows_train", "attack_rows_val",
          "attack_rows_test", "packets_per_attack_flow_07a", "pkts_median", "pkts_max", "dur_median_s",
          "flows_near_120s_timeout", "attack_5tuples", "flows_if_only_120s_timeout"]
    L += md_table(Y.to_dict("records"), vc)
    L += ["", "attack_rows_<split> = dataset rows (08's filter + cuts; equal to manifest_v1 for every (split, group)); "
              "packets_per_attack_flow_07a = 07a attack packets / 07 attack flows; pkts_* = Total Fwd + Total Bwd packets "
              "of the victim's attack flows; flows_near_120s_timeout = flows lasting >= "
              f"{NEAR_TIMEOUT_S:.0f} s; flows_if_only_120s_timeout = per 5-tuple ceil(span / 120 s).", ""]
    tot = {(r["part"], r["group"]): r for r in Y[Y["victim_device"].str.startswith("TOTAL ")].to_dict("records")}
    why = []
    for (stem, g), r in sorted(tot.items()):
        if g == "ALL" and r["attack_flows_07"]:
            why.append(f"{stem}: {r['attack_packets_07a']:,} attack packets -> {r['attack_flows_07']:,} attack flows "
                       f"({r['attack_packets_07a'] / r['attack_flows_07']:,.0f} packets per flow); the flows use "
                       f"{r['attack_5tuples']:,} distinct 5-tuples, and the 120 s flow timeout alone would cut them into "
                       f"{r['flows_if_only_120s_timeout']:,} flows; {r['flows_near_120s_timeout']:,} flows last >= "
                       f"{NEAR_TIMEOUT_S:.0f} s; median {fnum(r['pkts_median'], 0)} packets, max {fnum(r['pkts_max'], 0)}")
    L += ["**Why so few flows.** A udpplain flood sends from a fixed source port to a fixed victim port, so each "
          "(attacker, victim) stream is ONE 5-tuple. CICFlowMeter starts a new flow only when the 120 s flow timeout "
          "expires or the stream idles > 5 s, so a flood of millions of packets becomes about (stream duration / 120 s) "
          "flows per 5-tuple:", ""] + [f"- {w}" for w in why] + [""]
    L += ["### Test Mirai flows (Mirai-udpplain24): packets per flow, G1 vs G2", ""]
    dc = ["part", "group", "n_flows", "pkts_min", "pkts_p25", "pkts_median", "pkts_p75", "pkts_p90", "pkts_max",
          "dur_median_s"] + [f"pkts_{k}" for k in PKT_LABELS] + ["by_victim"]
    L += md_table(dist, dc)
    L += ["", "## 4. Yield rates (attack flows), per part and pooled", ""]
    L += md_table(M["rates"], ["scope", "group", "attack_flows", "attack_packets", "victims_with_flows", "pcap_gb",
                               "flows_per_gb", "flows_per_M_attack_packets", "flows_per_victim", "dataset_rows"])
    L += ["", "Multiply flows_per_gb by a part's size for a first projection. The two parts disagree on group: the "
              "victims of each capture decide which group the flows land in, so per-group projections are only as good as "
              "the guess of who the victims are.", ""]
    if M["projection"]:
        L += ["### Projection for the listed, not-local parts", ""]
        L += md_table(M["projection"], ["file", "variant", "part", "size_gb", "proj_flows_ALL", "proj_flows_ALL_range",
                                        "proj_flows_G1", "proj_flows_G1_range", "proj_flows_G2", "proj_flows_G2_range",
                                        "proj_extract_label_s", "proj_derived_disk_mb", "variant_note"])
        L += [""]
    else:
        L += ["No parts list given (--parts-list): no per-part projection; use the rates above.", ""]
    L += ["## 5. Time and disk per GB of pcap", ""]
    L += md_table(M["cost"], ["source", "pcap_gb", "extract_s", "07a_tshark_s", "07_label_s", "map_s", "03b_s", "total_s",
                              "s_per_gb", "derived_disk_per_gb_mb", "peak_rss_07_tshark_mb"])
    cp = M["cost_pooled"]
    L += ["", f"Pooled over the used parts (locked sweeper jar): {fnum(cp['s_per_gb'], 1)} s per GB of pcap for extract + "
              f"07a + 07, and {fnum(cp['derived_disk_per_gb_mb'], 1)} MB of derived files (flow CSV, labelled CSV, maps) per "
              "GB, on top of the pcap itself. 07's tshark peaked at "
              f"{fnum(max((c.get('peak_rss_07_tshark_mb') or 0) for c in M['cost']), 0)} MB RSS. The MIRAIcut1M row is a "
              "1M-packet cut timed with the earlier singlepkt jar (before the idle sweeper); it is a cross-check, not the "
              "locked extractor.", ""]
    L += ["## 6. Parts that could be reserved as an untouched future test set (proposal only)", ""]
    if M["reserve_candidates"]:
        L += md_table(M["reserve_candidates"], ["variant", "file", "part", "size_gb", "proj_flows_ALL", "why"])
        L += ["", "Part number is only a proxy for capture time; capture dates and victims are unknown until the pcap is "
                  "downloaded and 07a runs. Nothing is decided here."]
    else:
        L += ["**No local part can be reserved.** Both local Mirai pcaps are already in v1 / v1_1: Mirai-udpplain feeds "
              "train + val and Mirai-udpplain24 is the Step 10 test session. A new, untouched Mirai test set has to come "
              "from parts not downloaded yet. Re-run with --parts-list to rank listed parts."]
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
