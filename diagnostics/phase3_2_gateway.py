#!/usr/bin/env python
"""diagnostics/phase3_2_gateway.py -- Phase 3.2 PART B: the passive IP -> MAC learner's gateway rule on spoofed floods.

B1 (config/v2_phase3_1.json): for each val session slice -- the SYN-flood val windows (DDoS-SYN_Flood, DDoS-SYN_Flood5),
the UDP-flood val window (Mirai-udpplain) and, for reference, the Recon-PortScan val window -- picked the way Phase 3
picked its slice (D79: the session's WHOLE val window, written by the split-confined reader + slice manifest, run
through the locked CICFlowMeter), run the pcap path with learned routing (the slice's own frames incl. ARP feed the
learner in event time). Report the MACs marked gateway, whether each is an attack-source host (D74 identity,
diagnostics/diag_03_common.Hosts), routing agreement (group and device) vs the dataset on matched flows, unknown-binding
counts and the learner's health events.
Rule (fixed by the Phase 3.2 prompt before any number): the gateway rule is SAFE for routing iff routing agreement
stays >= 99 % of matched flows on the flood slice (agreement = group AND device both equal the dataset's; group-only and
device-only are reported too); otherwise UNSAFE. Overall SAFE iff every flood slice is SAFE; the port-scan slice is a
reference, not part of the verdict.
B2 (config/v2_phase3_2.json): the same slices and the same CICFlowMeter rows through the runtime again; the
unexpected_gateway health events are read back from each run's hash-chained health log (chain verified). Expected (the
prompt): one per spoofing flood source, none on the port-scan slice -- reported against what fires.
B3 (pcap path): predictions under v2_phase3_2.json == under v2_phase3_1.json row for row (health events only differ).
The CSV-replay parity of B3 is 28_run_stream.py --config config/v2_phase3_2.json --compare-to phase3_1_parity.
Figure: distinct source IPs per MAC in the gateway window (300 s) over event time, threshold and events marked
(an independent pass over each slice's frames; window counts capped at CAP distinct IPs per MAC, memory bound).
Outputs: results/phase3_2/gateway/ summary.md, gateway.json, figures/distinct_src_ips.png, run.log (refused if they
exist). Runtime runs ~/lgids_cache/v2/runtime/<run_id>_p32_<session>_PCAP_GLOBAL_s0_<config>/, slices
~/lgids_cache/v2/runtime_inputs/<run_id>_p32/ (new folders only). --dry-run: 20,000-frame slices,
results/phase3_2/gateway/dry_run/<run_id>/, *_dry_run cache dirs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import sys
import traceback
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402
from common import alert_log as AL  # noqa: E402
from common import flow_source as FS  # noqa: E402
from common import packet_source as PK  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import phase3_run as R3  # noqa: E402
from common import predictions_io as PIO  # noqa: E402
from common import schemas as S  # noqa: E402
from common.routing import Router  # noqa: E402

SCRIPT = "diagnostics/phase3_2_gateway.py"
SESSIONS = ["DDoS-SYN_Flood", "DDoS-SYN_Flood5", "Mirai-udpplain", "Recon-PortScan"]
FLOOD = {"DDoS-SYN_Flood": "syn_flood", "DDoS-SYN_Flood5": "syn_flood", "Mirai-udpplain": "udp_flood"}
RULE = {"safe_iff": "routing agreement (group AND device == dataset) >= 0.99 of matched flows on every flood slice",
        "threshold": 0.99, "reference_slices": ["Recon-PortScan"]}
CAP = 5000                      # figure: distinct IPs tracked per MAC window (exact below CAP)
HEALTH_KINDS = ("gateway_detected", "unexpected_gateway", "ip_mac_change", "ip_mac_flap")
LEAN_CHECK_MAX_ROWS = 400_000   # slices up to this many CICFlowMeter rows are also loaded by the stock source and compared


def _same_row(a: dict, b: dict) -> bool:
    if list(a) != list(b):
        return False
    for k, v in a.items():
        w = b[k]
        if isinstance(v, float) and isinstance(w, float) and v != v and w != w:   # NaN == NaN here
            continue
        if k == "_meta":
            if v != w or any(type(v[x]) is not type(w[x]) for x in v):
                return False
        elif v != w or type(v) is not type(w):
            return False
    return True


def pins() -> dict:
    return {"config/config.py": R3.sha256_path(S.CONFIG_PY_PATH), "config/class_map.json": R3.sha256_path(S.CLASS_MAP_PATH)}


def load_s28():
    spec = importlib.util.spec_from_file_location("run_stream_28", REPO_ROOT / "28_run_stream.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LeanCicfmSource(FS.CicfmPcapSource):
    """CicfmPcapSource with numpy storage (a flood val window gives ~1 CICFlowMeter flow per frame, millions of rows:
    Python float lists would not fit in memory). Same CSV parse, same schema checks, same emission times, and _rows
    yields the same dicts (float(np.float64) == the value list.tolist() gives), so the runtime sees identical rows."""

    def _load(self) -> None:
        import pandas as pd
        feats = S.feature_columns()
        df = pd.read_csv(self.csv, dtype={c: str for c in FS.ID_COLS + ["Label"]}, keep_default_na=False)
        X = np.empty((len(df), len(feats)), dtype=np.float64)
        for k, f in enumerate(feats):
            X[:, k] = pd.to_numeric(df[f], errors="coerce").to_numpy(np.float64)
        sch = S.validate_schema(pd.DataFrame({**{f: X[:, k] for k, f in enumerate(feats)},
                                              **{k: df[k] for k in df.columns if k not in feats}}),
                                assume_label="unlabelled", columns=list(df.columns))
        need = ("feature columns present", "feature columns in features_v1 order", "feature dtypes numeric",
                "Timestamp parses (TS_FORMAT, tz=UTC)")
        req = {c["check"]: c for c in sch["checks"] if c["check"] in need}
        self.info["schema"] = {"required_pass": all(c["pass"] for c in req.values()),
                               "checks": [{"check": c["check"], "pass": c["pass"], "required": c["check"] in need}
                                          for c in sch["checks"]]}
        if not self.info["schema"]["required_pass"]:
            raise FS.FlowSourceError(f"{self.csv}: schema checks failed {[c for c in req.values() if not c['pass']]}")
        ts = S.parse_timestamps(df["Timestamp"])
        start = ((ts - pd.Timestamp(0, tz="UTC")) // pd.Timedelta(seconds=1)).to_numpy(np.int64)
        end = start + X[:, feats.index(FS.DURATION_COL)] / 1e6
        ev = FS.emission_times(df["Flow ID"].tolist(), start, end, self.flow_timeout_s)
        self._n = len(df)
        self._X, self._featnames = X, feats
        self._ids = {k: df[k].to_numpy(object) for k in FS.ID_COLS}
        self._start, self._end, self._ev = start, end, np.asarray(ev, np.float64)
        del df, sch
        self.info.update({"rows": self._n, "csv_sha256": FS._sha(self.csv), "lean_source": True})

    def lags(self) -> np.ndarray:
        return self._ev - self._end

    def _rows(self):
        feats, X = self._featnames, self._X
        sess = self.slice_manifest.get("session", "pcap")
        ids = list(self._ids.items())
        for i in range(self._n):
            xi = X[i].tolist()
            row = dict(zip(feats, xi))
            for k, v in ids:
                row[k] = v[i]
            row["_meta"] = {"flow_uid": f"{sess}:cfm{i}", "start_ts": int(self._start[i]), "event_time": float(self._ev[i]),
                            "session": sess, "row": i}
            yield row


class Stub:
    """The bits of common/phase3_run.Run that 28_run_stream.run_one uses (run_id for the run folder name, log)."""

    def __init__(self, run_id: str, log):
        self.run_id, self.log = run_id, log


def window_series(pcap: Path, window_s: float, thr: int) -> dict:
    """Per source MAC: [(t, distinct source IPs in (t - window_s, t])] sampled >= 1 s apart and at threshold crossings;
    plus per-MAC frame counts and max. Exact below CAP distinct IPs (then saturated)."""
    win: dict = defaultdict(OrderedDict)
    ser: dict = defaultdict(list)
    last: dict = {}
    frames = Counter()
    mx = Counter()
    for ts, sip, _dip, proto, smac, _dmac in PK.iter_pcap(Path(pcap), Counter()):
        smac = str(smac or "").lower()
        if not smac or (len(smac) == 17 and int(smac[:2], 16) & 1):
            continue
        frames[smac] += 1
        w = win[smac]
        if sip in w:
            w.move_to_end(sip)
            w[sip] = ts
        elif len(w) < CAP:
            w[sip] = ts
        while w:
            k0, t0 = next(iter(w.items()))
            if t0 > ts - window_s:
                break
            w.popitem(last=False)
        n = len(w)
        mx[smac] = max(mx[smac], n)
        lt, ln = last.get(smac, (None, None))
        if lt is None or ts - lt >= 1.0 or (ln <= thr < n) or (n <= thr < ln):
            ser[smac].append((ts, n))
            last[smac] = (ts, n)
    return {"series": dict(ser), "frames": dict(frames), "max": dict(mx)}


def read_health(run_dir: Path, public: bytes) -> dict:
    recs = [json.loads(x) for x in (run_dir / "health.jsonl").read_text(encoding="utf-8").splitlines()]
    chain = AL.verify_chain(run_dir / "health.jsonl", public)
    by = defaultdict(list)
    for r in recs:
        if r.get("kind") in HEALTH_KINDS:
            by[r["kind"]].append({k: v for k, v in r.items() if k not in ("sig", "prev_sha256", "seq", "wall_time")})
    return {"chain_ok": chain["ok"], "records": chain["n"], "events": dict(by),
            "counts": {k: len(by.get(k, [])) for k in HEALTH_KINDS}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="20,000-frame slices")
    ap.add_argument("--sessions", nargs="*", default=SESSIONS)
    ap.add_argument("--replot", default=None, help="gateway.json: re-draw the figure as figures/distinct_src_ips_fixed.png "
                    "(legend outside the panels, no overlapping labels); the per-MAC series are recomputed from the run's "
                    "slice pcaps, events / gateways come from the json; numbers unchanged; refuses an existing target")
    args = ap.parse_args()
    S.verify_v2_lock(strict=True)
    p0 = pins()
    if args.replot:
        return replot(Path(args.replot), p0)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = RESULTS_DIR / "phase3_2" / "gateway"
    out = base / "dry_run" / run_id if args.dry_run else base
    for p in (out / "gateway.json", out / "summary.md", out / "run.log"):
        if p.exists():
            raise SystemExit(f"{p} exists (never overwritten)")
    out.mkdir(parents=True, exist_ok=True)
    logf = open(out / "run.log", "x", encoding="utf-8")

    def log(msg: str) -> None:
        line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')}  {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
        logf.flush()

    log(f"{SCRIPT} run_id {run_id} dry_run={args.dry_run} sessions={args.sessions}")
    log(f"[start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    log(f"rule (fixed before any number): {RULE}")
    cfgs = {"phase3_1": C.load_phase3_config(C.CONFIG_PATH_3_1), "phase3_2": C.load_phase3_config(C.CONFIG_PATH_3_2)}
    for k, c in cfgs.items():
        log(f"  config {k}: {c['_path']} sha256 {c['_sha256']} pinned {c['_pinned']}")
    c31 = cfgs["phase3_1"]
    secret, public = AL.ensure_runtime_keys(C.expand(c31["paths"]["runtime_keys_dir"]), REPO_ROOT)
    s28 = load_s28()
    from diagnostics.diag_03_common import Hosts
    hosts = Hosts()
    inv = Router(c31).inv
    ml = c31["routing"]["mac_learner"]
    thr, wnd = int(ml["gateway_distinct_ip_threshold"]), float(ml["gateway_window_s"])
    warm = float(cfgs["phase3_2"]["routing"]["mac_learner"]["gateway_warmup_s"])
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    cfg2 = load_phase2_config(REPO_ROOT / c31["source"]["replay_phase2_config"])
    dsall = D.load_split(cfg2, "val", ["Flow ID", "start_ts", "session", "group", "device_mac", "src_mac", "dst_mac",
                                       "label_id"])
    names = list(S.load_class_map().names)
    root = C.expand(c31["paths"]["runtime_root"]).parent / ("runtime_inputs_dry_run" if args.dry_run else "runtime_inputs")
    sd = root / f"{run_id}_p32"
    res = {"script": SCRIPT, "run_id": run_id, "dry_run": args.dry_run, "rule": RULE,
           "configs": {k: {"path": c["_path"], "sha256": c["_sha256"], "pinned": c["_pinned"]} for k, c in cfgs.items()},
           "learner_params": {"threshold": thr, "window_s": wnd, "warmup_s": warm,
                              "inventory_gateway_roles": cfgs["phase3_2"]["routing"]["mac_learner"]["inventory_gateway_roles"]},
           "attack_identity": hosts.describe(),
           "code_sha256": R3.code_sha256([SCRIPT, "28_run_stream.py", "common/mac_learner.py", "common/runtime.py",
                                          "common/routing.py", "common/phase3_config.py", "common/packet_source.py",
                                          "common/flow_source.py", "common/schemas.py"]),
           "slices": {}}
    series = {}
    ok = True
    for sess in args.sessions:
        try:
            log(f"== {sess}")
            pcap = sd / f"{sess}_val.pcap"
            man = PK.write_slice(c31, sess, "val", pcap, max_packets=20000 if args.dry_run else None)
            log(f"  slice {pcap}: {man['frames_written']:,} frames, {man['first_ts']:.1f} .. {man['last_ts']:.1f} "
                f"({man['last_ts'] - man['first_ts']:.0f} s)")
            src = LeanCicfmSource(c31, pcap, sd / f"cfm_{sess}")
            info = src.extract()
            log(f"  CICFlowMeter: {info['rows']:,} flows in {info['cfm']['wall_s']:.1f} s")
            lean_ok = None
            if info["rows"] <= LEAN_CHECK_MAX_ROWS:                  # the stock source on the same CSV: same rows?
                stock = FS.CicfmPcapSource(c31, pcap, sd / f"cfm_{sess}_stockcheck", csv=src.csv)
                stock.extract()
                lean_ok = all(_same_row(a, b) for a, b in zip(stock._rows(), src._rows())) and len(stock) == len(src)
                del stock
                log(f"  lean source rows identical to CicfmPcapSource rows: {lean_ok}")
            ds = dsall[(dsall["session"] == sess) & (dsall["start_ts"] >= int(man["first_ts"]))
                       & (dsall["start_ts"] <= int(man["last_ts"]))].reset_index(drop=True)
            by = defaultdict(list)
            for i, (f, t) in enumerate(zip(ds["Flow ID"], ds["start_ts"])):
                by[(f, int(t))].append(i)
            pairs = []
            for j, (f, t) in enumerate(zip(src._ids["Flow ID"], src._start)):
                L = by.get((f, int(t)))
                if L:
                    pairs.append((L.pop(0), j))
            di = np.array([a for a, _ in pairs], dtype=np.int64)
            cj = np.array([b for _, b in pairs], dtype=np.int64)
            log(f"  matched {len(pairs):,} of {len(ds):,} dataset rows in the window")
            S_ = {"slice": man, "cfm": info["cfm"], "csv_rows": int(info["rows"]), "lean_source_rows_identical": lean_ok, "dataset_rows_in_window": int(len(ds)),
                  "matched": int(len(pairs)), "match_rate_of_dataset": float(len(pairs) / max(len(ds), 1)),
                  "dataset_labels_matched": {names[k]: int(v) for k, v in Counter(ds["label_id"].to_numpy()[di].tolist()).items()},
                  "runs": {}}
            preds = {}
            for clabel, cfg in cfgs.items():
                r = s28.run_one(cfg, Stub(f"{run_id}_p32_{sess}", log), f"PCAP_GLOBAL_s0_{clabel}", cfg["mode"], 0,
                                args.dry_run, False, False, secret, source=src, learn_pcap=pcap)
                P = PIO.read_predictions(r["dir"])
                preds[clabel] = P
                pos = {int(x): k for k, x in enumerate(P["row"].to_numpy())}
                k_rt = np.array([pos.get(int(j), -1) for j in cj], dtype=np.int64)
                have = k_rt >= 0
                g_rt = np.where(have, P["group"].to_numpy()[np.maximum(k_rt, 0)], None)
                m_rt = np.where(have, P["device_mac"].to_numpy()[np.maximum(k_rt, 0)], None)
                g_ok = g_rt == ds["group"].to_numpy()[di]
                m_ok = m_rt == ds["device_mac"].to_numpy()[di]
                both = g_ok & m_ok
                lab = ds["label_id"].to_numpy()[di]
                hl = read_health(r["dir"], public)
                summ = r["summary"]
                R = {"run_dir": str(r["dir"]), "flows": int(len(P)), "config_sha256": cfg["_sha256"],
                     "agree_both": float(both.mean()) if len(both) else None,
                     "agree_group": float(g_ok.mean()) if len(g_ok) else None,
                     "agree_device": float(m_ok.mean()) if len(m_ok) else None,
                     "disagree_n": int((~both).sum()),
                     "agree_by_label": {names[k]: {"n": int((lab == k).sum()), "agree_both": float(both[lab == k].mean())}
                                        for k in sorted(set(lab.tolist()))},
                     "router": summ["router"], "learner": summ.get("learner"),
                     "unknown_binding": {k: summ["router"].get(k, 0) for k in ("learned_src_unbound", "learned_dst_unbound",
                                                                                "learned_both_unbound", "learned_src_bound",
                                                                                "learned_dst_bound")},
                     "health": hl, "arp_records": summ["counts"].get("arp_records", 0),
                     "packets": summ["counts"].get("packets", 0)}
                if (~both).any():
                    pat = Counter()
                    rule_rt = P["rule"].to_numpy() if "rule" in P.columns else None
                    for ii in np.flatnonzero(~both)[:200000]:
                        a = di[ii]
                        pat[(ds["group"].iloc[a], ds["device_mac"].iloc[a], str(g_rt[ii]), str(m_rt[ii]),
                             str(rule_rt[k_rt[ii]]) if rule_rt is not None and k_rt[ii] >= 0 else "-")] += 1
                    R["disagree_patterns"] = [{"dataset_group": k[0], "dataset_device": k[1], "runtime_group": k[2],
                                               "runtime_device": k[3], "runtime_rule": k[4], "n": v}
                                              for k, v in pat.most_common(15)]
                S_["runs"][clabel] = R
                log(f"  [{clabel}] {R['flows']:,} flows; agreement both {R['agree_both']:.4%}, group {R['agree_group']:.4%}, "
                    f"device {R['agree_device']:.4%}; gateways {list((R['learner'] or {}).get('gateways', {}))}; health "
                    f"{hl['counts']} (chain ok {hl['chain_ok']}); unknown {R['unknown_binding']}")
            S_["pcap_predictions_equal_3_1_vs_3_2"] = bool(list(preds["phase3_1"].columns) == list(preds["phase3_2"].columns)
                                                           and preds["phase3_1"].equals(preds["phase3_2"]))
            log(f"  pcap path predictions identical 3.1 vs 3.2: {S_['pcap_predictions_equal_3_1_vs_3_2']}")
            ws = window_series(pcap, wnd, thr)
            gws = dict((S_["runs"]["phase3_1"]["learner"] or {}).get("gateways", {}))
            unexp = {e["mac"]: e for e in S_["runs"]["phase3_2"]["health"]["events"].get("unexpected_gateway", [])}
            t_first = (S_["runs"]["phase3_2"]["learner"] or {}).get("t_first") or man["first_ts"]
            gtab = []
            for mac, tdet in sorted(gws.items(), key=lambda kv: kv[1]):
                e = inv.get(mac)
                ds_touch = (ds["src_mac"].astype(str).str.lower().to_numpy()[di] == mac) | \
                           (ds["dst_mac"].astype(str).str.lower().to_numpy()[di] == mac)
                gtab.append({"mac": mac, "detected_at": tdet, "detected_s_after_first_frame": tdet - t_first,
                             "in_warmup": tdet < t_first + warm, "inventory_name": e[0] if e else None,
                             "inventory_role": e[1] if e else None, "attack_source": hosts.is_attacker(mac),
                             "attack_identity_category": hosts.cat(mac), "frames_from": ws["frames"].get(mac, 0),
                             "max_distinct_src_ips_in_window": ws["max"].get(mac, 0),
                             "matched_flows_touching": int(ds_touch.sum()),
                             "unexpected_gateway_event": mac in unexp, "event": unexp.get(mac)})
            S_["gateway_macs"] = gtab
            att_src = sorted({str(m).lower() for m in ds["src_mac"].to_numpy()[di] if hosts.is_attacker(str(m))})
            S_["attack_source_macs_in_matched_flows"] = att_src
            S_["spoofing_sources"] = [g["mac"] for g in gtab if g["attack_source"]]
            S_["t_first"] = t_first
            if sess in FLOOD:
                ag = S_["runs"]["phase3_1"]["agree_both"]
                S_["verdict"] = "SAFE" if ag is not None and ag >= RULE["threshold"] else "UNSAFE"
            n_unexp = len(unexp)
            S_["expected_events"] = len(S_["spoofing_sources"]) if sess in FLOOD else 0
            S_["fired_events"] = n_unexp
            log(f"  gateways: {[(g['mac'], g['inventory_role'], g['attack_source'], round(g['detected_s_after_first_frame'], 2)) for g in gtab]}")
            log(f"  unexpected_gateway: fired {n_unexp}, expected {S_['expected_events']}; verdict {S_.get('verdict', '(reference)')}")
            series[sess] = {"series": ws["series"], "max": ws["max"], "gateways": gws, "unexpected": unexp,
                            "t_first": t_first, "first_ts": man["first_ts"], "last_ts": man["last_ts"]}
            res["slices"][sess] = S_
            del src, preds
        except Exception as e:                                         # noqa: BLE001
            ok = False
            res["slices"][sess] = {"error": "".join(traceback.format_exception(e))}
            log(f"  ERROR {sess}: {e!r}")
    fl = [res["slices"][s].get("verdict") for s in args.sessions if s in FLOOD and "verdict" in res["slices"].get(s, {})]
    res["verdict"] = ("SAFE" if fl and all(v == "SAFE" for v in fl) else "UNSAFE") if fl else "NOT_EVALUATED"
    log(f"VERDICT (gateway rule for routing on flood slices): {res['verdict']}")
    try:
        res["figure"] = str(Path(figure(out, series, thr, wnd, warm, inv, hosts)).relative_to(REPO_ROOT))
    except Exception as e:                                             # noqa: BLE001
        res["figure_error"] = "".join(traceback.format_exception(e))
        log(f"figure error: {e!r}")
    S.verify_v2_lock(strict=True)
    p1 = pins()
    res["lock"] = {"start": p0, "end": p1}
    R3.write_json(out / "gateway.json", res)
    write_summary(out, res)
    log(f"[end] verify_v2_lock OK; config.py {p1['config/config.py']}; class_map.json {p1['config/class_map.json']} -> {out}")
    logf.close()
    return 0 if (ok and p0 == p1) else 1


def replot(gj: Path, p0: dict) -> int:
    res = json.loads(gj.read_text(encoding="utf-8"))
    out = gj.parent
    tgt = out / "figures" / "distinct_src_ips_fixed.png"
    if tgt.exists():
        raise SystemExit(f"{tgt} exists (never overwritten)")
    c31 = C.load_phase3_config(C.CONFIG_PATH_3_1)
    from diagnostics.diag_03_common import Hosts
    hosts, inv = Hosts(), Router(c31).inv
    lp = res["learner_params"]
    root = C.expand(c31["paths"]["runtime_root"]).parent / ("runtime_inputs_dry_run" if res["dry_run"] else "runtime_inputs")
    series = {}
    for sess, z in res["slices"].items():
        if "error" in z:
            continue
        pcap = root / f"{res['run_id']}_p32" / f"{sess}_val.pcap"
        if PK.sha256_file(pcap) != z["slice"]["pcap_sha256"]:
            raise SystemExit(f"{pcap}: sha256 differs from the slice manifest in {gj}")
        ws = window_series(pcap, float(lp["window_s"]), int(lp["threshold"]))
        series[sess] = {"series": ws["series"], "max": ws["max"],
                        "gateways": dict((z["runs"]["phase3_1"]["learner"] or {}).get("gateways", {})),
                        "unexpected": {e["mac"]: e for e in z["runs"]["phase3_2"]["health"]["events"].get("unexpected_gateway", [])},
                        "t_first": z["t_first"], "first_ts": z["slice"]["first_ts"], "last_ts": z["slice"]["last_ts"]}
        print(f"  {sess}: series recomputed ({len(ws['series'])} MACs)", flush=True)
    p = figure(out, series, int(lp["threshold"]), float(lp["window_s"]), float(lp["warmup_s"]), inv, hosts,
               name="distinct_src_ips_fixed.png")
    S.verify_v2_lock(strict=True)
    p1 = pins()
    print(f"{p}\n[end] verify_v2_lock OK; config.py {p1['config/config.py']}; class_map.json {p1['config/class_map.json']}")
    return 0 if p0 == p1 else 1


def _label(mac: str, inv: dict, hosts) -> str:
    e = inv.get(mac)
    if hosts.is_attacker(mac):
        return f"attack source ..{mac[-5:]}"
    if e:
        return f"{e[0][:22]} ({e[1]})"
    return f"unlisted ..{mac[-5:]}"


def figure(out: Path, series: dict, thr: int, wnd: float, warm: float, inv: dict, hosts,
           name: str = "distinct_src_ips.png") -> str:
    import matplotlib.pyplot as plt
    from common import plot_style as PS
    PS.apply()
    sess = list(series)
    fixed = name != "distinct_src_ips.png"
    fig, axes = plt.subplots(len(sess), 1, figsize=(9.6 if fixed else 7.2, 2.6 * len(sess) + 0.6), squeeze=False,
                             constrained_layout=fixed)
    for ax, s in zip(axes[:, 0], sess):
        z = series[s]
        t0 = z["t_first"]
        show = sorted(z["gateways"], key=lambda m: z["gateways"][m])[:7]
        rest = [m for m, _ in sorted(z["max"].items(), key=lambda kv: -kv[1]) if m not in show][:max(0, 8 - len(show))][:3]
        for k, m in enumerate(show + rest):
            pts = z["series"].get(m, [])
            if not pts:
                continue
            x = [p[0] - t0 for p in pts]
            y = [max(p[1], 1) for p in pts]
            col = PS.CATEGORICAL[k % len(PS.CATEGORICAL)]
            ax.step(x, y, where="post", color=col, lw=1.1 if m in show else 0.8, ls="-" if m in show else ":",
                    label=_label(m, inv, hosts) + ("" if m in show else " (not a gateway)"))
            if m in z["gateways"]:
                td = z["gateways"][m] - t0
                ax.plot([td], [thr + 1], marker="o", ms=5, color=col, mfc="white", zorder=5)
            if m in z["unexpected"]:
                te = z["unexpected"][m]["event_time"] - t0
                ax.plot([te], [thr + 1], marker="*", ms=11, color=col, zorder=6)
        ax.axhline(thr, color="0.25", lw=0.9, ls="--")
        if fixed:                                                      # label on the left, clear of the legend
            ax.text(0.005, thr * 1.08, f"threshold: > {thr} distinct IPs in {wnd:.0f} s", transform=ax.get_yaxis_transform(),
                    fontsize=7, va="bottom", ha="left", color="0.25")
        else:
            ax.text(1.0, thr, f" threshold: > {thr} distinct IPs in {wnd:.0f} s", transform=ax.get_yaxis_transform(),
                    fontsize=7, va="bottom", ha="right", color="0.25")
        ax.axvspan(0, warm, color="0.5", alpha=0.10, lw=0)
        ax.text(0.995 if fixed else 2, 0.97, f"warm-up {warm:.0f} s (shaded)", transform=ax.get_xaxis_transform() if not fixed
                else ax.transAxes, fontsize=7, va="top", ha="right" if fixed else "left", color="0.35")
        ax.set_yscale("log")
        ax.set_ylim(0.8, max([thr * 3] + [max(z["max"].get(m, 1), 1) for m in show + rest]) * 2.5)
        ax.set_xlim(-5, z["last_ts"] - t0 + 5)
        nu = len(z["unexpected"])
        ax.set_title(f"{s} val window: {len(z['gateways'])} gateway MAC(s), {nu} unexpected_gateway event(s)",
                     loc="left", fontsize=9)
        ax.set_ylabel(f"distinct src IPs / {wnd:.0f} s")
        if fixed:
            ax.legend(fontsize=6.5, loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False, ncol=1)
        else:
            ax.legend(fontsize=6.5, loc="center right", frameon=False, ncol=1)
    axes[-1, 0].set_xlabel("event seconds after the learner's first frame   (o = gateway_detected, * = unexpected_gateway)")
    if not fixed:
        fig.tight_layout()
    p = out / "figures" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    return str(PS.save(fig, p))


def write_summary(out: Path, res: dict) -> None:
    L = [f"# Phase 3.2 Part B -- gateway rule on spoofed floods -- {res['verdict']}" + (" (DRY RUN)" if res["dry_run"] else ""),
         "", f"Run `{res['run_id']}`. Configs: " + ", ".join(f"`{v['path'].split('/')[-1]}` `{v['sha256'][:16]}...` (pinned "
                                                            f"{v['pinned']})" for v in res["configs"].values()) + ".",
         f"Learner: gateway = > {res['learner_params']['threshold']} distinct source IPs within "
         f"{res['learner_params']['window_s']:.0f} s; unexpected_gateway warm-up {res['learner_params']['warmup_s']:.0f} s, "
         f"exempt inventory roles {res['learner_params']['inventory_gateway_roles']}.", "",
         f"**Rule (fixed before any number):** {RULE['safe_iff']} -> SAFE, otherwise UNSAFE. **VERDICT: {res['verdict']}.**",
         "", "## B1 -- routing on each val slice (config v2_phase3_1.json, learned routing)", "",
         "| slice | frames | CICFlowMeter flows | matched / dataset rows | agree group+device | group | device | gateway MACs "
         "(attack source?) | src / dst / both unbound | verdict |", "|---|---|---|---|---|---|---|---|---|---|"]
    for s, z in res["slices"].items():
        if "error" in z:
            L.append(f"| {s} | ERROR | | | | | | | | |")
            continue
        r = z["runs"]["phase3_1"]
        u = r["unknown_binding"]
        gw = "; ".join(f"`{g['mac']}` {g['inventory_role'] or 'unlisted'} ({'yes' if g['attack_source'] else 'no'})"
                       for g in z["gateway_macs"]) or "none"
        L.append(f"| {s} | {z['slice']['frames_written']:,} | {z['csv_rows']:,} | {z['matched']:,} / "
                 f"{z['dataset_rows_in_window']:,} | {r['agree_both']:.2%} | {r['agree_group']:.2%} | {r['agree_device']:.2%} | "
                 f"{gw} | {u['learned_src_unbound']:,} / {u['learned_dst_unbound']:,} / {u['learned_both_unbound']:,} | "
                 f"{z.get('verdict', 'reference')} |")
    L += ["", "Rows fed to the runtime come from a numpy-backed copy of CicfmPcapSource (memory); identical to the stock "
          "source's rows where both were loaded: " + ", ".join(f"{s} {z.get('lean_source_rows_identical')}"
                                                              for s, z in res["slices"].items() if "error" not in z)]
    L += ["", "## Gateway MACs", "", "| slice | MAC | inventory name / role | attack source | detected (s after first frame) | "
          "frames from it | max distinct src IPs / window | matched flows touching it | unexpected_gateway (3.2) |",
          "|---|---|---|---|---|---|---|---|---|"]
    for s, z in res["slices"].items():
        for g in z.get("gateway_macs", []):
            L.append(f"| {s} | `{g['mac']}` | {g['inventory_name'] or '-'} / {g['inventory_role'] or 'unlisted'} | "
                     f"{g['attack_source']} ({g['attack_identity_category']}) | {g['detected_s_after_first_frame']:.2f}"
                     f"{' (warm-up)' if g['in_warmup'] else ''} | {g['frames_from']:,} | {g['max_distinct_src_ips_in_window']:,}"
                     f"{'+' if g['max_distinct_src_ips_in_window'] >= CAP else ''} | {g['matched_flows_touching']:,} | "
                     f"{'fired' if g['unexpected_gateway_event'] else 'no'} |")
    L += ["", "## B2 -- unexpected_gateway (config v2_phase3_2.json)", "",
          "| slice | spoofing sources (attack-source gateways) | expected events | fired | health events (3.2) | chain ok | "
          "pcap predictions 3.1 == 3.2 |", "|---|---|---|---|---|---|---|"]
    for s, z in res["slices"].items():
        if "error" in z:
            continue
        h = z["runs"]["phase3_2"]["health"]
        L.append(f"| {s} | {len(z['spoofing_sources'])} | {z['expected_events']} | {z['fired_events']} | {h['counts']} | "
                 f"{h['chain_ok']} | {z['pcap_predictions_equal_3_1_vs_3_2']} |")
    for s, z in res["slices"].items():
        for e in z.get("runs", {}).get("phase3_2", {}).get("health", {}).get("events", {}).get("unexpected_gateway", []):
            L.append(f"- {s}: `{e['mac']}` distinct source IPs {e['distinct_source_ips']}, first {e['first_time']:.3f}, "
                     f"last {e['last_time']:.3f}, in inventory {e['in_inventory']} ({e['inventory_role'] or '-'})")
    for s, z in res["slices"].items():
        for d in z.get("runs", {}).get("phase3_1", {}).get("disagree_patterns", [])[:5]:
            L.append(f"- {s} disagreement: dataset ({d['dataset_group']}, `{d['dataset_device']}`) vs runtime "
                     f"({d['runtime_group']}, `{d['runtime_device']}`, {d['runtime_rule']}): {d['n']:,}")
    for s, z in res["slices"].items():
        if "error" in z:
            L += ["", f"ERROR {s}:", "```", z["error"][-1500:], "```"]
    if res.get("figure"):
        L += ["", f"Figure: `{res['figure']}`"]
    L += ["", f"Lock: config.py `{res['lock']['end']['config/config.py']}`, class_map.json "
          f"`{res['lock']['end']['config/class_map.json']}` (start == end: {res['lock']['start'] == res['lock']['end']})"]
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
