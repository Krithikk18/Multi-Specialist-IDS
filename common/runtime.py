"""common/runtime.py -- Phase 3 streaming runtime: source -> route -> normalise -> features -> predict -> calibrate ->
policy -> log, plus the packet rate-guard path, on one event clock (docs/V2_PREREG_PHASE3.md).

    rt = Runtime(cfg, rm, run_dir, secret, rate_guard=(rg2, v1), store_features=False)
    summary = rt.run(flow_source, packets=iterable_of_packets_or_None)

Threads: a producer thread iterates the flow source (pacing / ticks happen there) into a bounded queue; the consumer
(caller's thread) does everything else. Queue overflow: "block" (lossless back-pressure, replay at max speed) or "drop"
(a live source cannot wait: the newest item is dropped), per config; drops and the peak backlog are counted and
logged, never silent. Malformed rows (missing / non-numeric features, bad metadata, a normaliser refusal) are
quarantined (health record) and never stop the loop.
Micro-batching: a batch is scored when it holds batch.max_flows flows (decision time = the filling flow's event time)
or when the next event is later than its first flow + batch.max_event_s (decision time = first + max_event_s).
Routing uses the extractor's orientation (ingest's rule), then the flow is normalised (common/orientation dict API).
Packets: consumed lazily in event-time order up to each flow's event time; v2 and V1 rate-guard alerts go through the
same policy with class policy.rate_guard_class. Hot path: dicts / lists / numpy only; pandas never runs per flow.
Outputs in run_dir: predictions.parquet (every flow; Phase 4's review queue), alerts.jsonl, health.jsonl and the
outbox (hash-chained, signed: common/alert_log.py), incidents.json, latency.npz (per-stage ns), rss.json.
"""

from __future__ import annotations

import json
import math
import queue
import threading
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

from common import alert_log as AL
from common import orientation as OR
from common import schemas as S
from common.inference import Inference
from common.policy import Policy
from common.routing import Router

STAGES = ("route", "normalise", "features", "predict", "calibrate", "shap", "policy", "log")
_END = ("end", None, None, None)


def rss_mb() -> float:
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return float("nan")


def peak_rss_mb() -> float:
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:                                                  # noqa: BLE001
        return float("nan")


class Runtime:
    def __init__(self, cfg: dict, rm, run_dir: Path, secret: bytes, rate_guard=None, store_features: bool = False,
                 router: Router | None = None, consumer_delay_s: float = 0.0):
        self.cfg, self.rm, self.dir = cfg, rm, Path(run_dir)
        self.names = list(rm.class_names)
        self.router = router or Router(cfg)
        self.inf = Inference(rm, cfg)
        self.pol = Policy.from_config(cfg, self.names)
        self.omap = OR.load_map(S.ORIENTATION_MAP_PATH, S.ORIENTATION_MAP_SHA256)
        self.feats = S.feature_columns()
        self.rg2, self.v1 = rate_guard if rate_guard is not None else (None, None)
        self.store_features = store_features
        self.delay = float(consumer_delay_s)
        self.bmax, self.bspan = int(cfg["batch"]["max_flows"]), float(cfg["batch"]["max_event_s"])
        paced = cfg["source"]["speed"] != "max"
        self.overflow = cfg["queue"]["overflow_paced" if paced else "overflow_max_speed"]
        self.qmax = int(cfg["queue"]["max_items"])
        self.alerts = AL.ChainLog(self.dir / "alerts.jsonl", secret, "alerts")
        self.health = AL.ChainLog(self.dir / "health.jsonl", secret, "health")
        self.outbox = AL.ChainLog(self.dir / cfg["paths"]["outbox"], secret, "outbox")
        self.lat = {s: [] for s in STAGES}
        self.lat_batch = {s: [] for s in ("predict", "calibrate", "shap", "policy", "log")}
        self.batch_sizes: list = []
        self.e2e: list = []
        self.qwait: list = []
        self.rss: list = []
        self.counts = defaultdict(int)
        self.cols = defaultdict(list)
        self.featbuf: list = []
        self._batch: list = []
        self._pk = None
        self._pk_next = None
        self._last_t = -math.inf
        self._hb_t = None
        self._adv_t = -math.inf
        self._n_closed = 0
        self.model_ref = {mid: {"source": m.source, "model_sha256": m.model_sha256} for mid, m in rm.models.items()}

    # ------------------------------------------------------------------ helpers
    def _health(self, kind: str, **f) -> None:
        self.health.append({"kind": kind, "wall_time": time.time(), **f})

    def _outbox_incident(self, kind: str, inc: dict, t: float) -> None:
        self.outbox.append({"schema": "lgids.alert.v1", "type": kind, "event_time": t, "wall_time": time.time(),
                            "incident": inc, "producer": "LG-IDS AIML runtime", "contract": "docs/V2_ALERT_CONTRACT.md"})

    def _policy(self, t: float, key_class: str, device: str, group: str, path: str) -> dict:
        d = self.pol.tracker.process(t, key_class, device, group, path)
        if d["decision"] == "opened":
            inc = self.pol.tracker.open[(key_class, device)].as_dict()
            self._outbox_incident("incident.opened", inc, t)
        return d

    def _emit_closed(self) -> None:
        cl = self.pol.tracker.closed                                     # every close (advance, process, finish)
        for inc in cl[self._n_closed:]:
            self._outbox_incident("incident.closed", inc.as_dict(), inc.closed_at)
        self._n_closed = len(cl)

    def _advance_incidents(self, t: float) -> None:
        if t - self._adv_t < 1.0:
            return
        self._adv_t = t
        self.pol.tracker.advance(t)
        self._emit_closed()

    def _maybe_rss(self) -> None:
        now = time.monotonic()
        if not self.rss or now - self.rss[-1][0] >= float(self.cfg["benchmark"]["rss_sample_s"]):
            self.rss.append((now, rss_mb(), self.counts["flows_scored"], self._q.qsize() if hasattr(self, "_q") else 0))

    # ------------------------------------------------------------------ packets
    def _packets_until(self, t: float) -> None:
        if self._pk is None:
            return
        while True:
            if self._pk_next is None:
                try:
                    self._pk_next = next(self._pk)
                except StopIteration:
                    self._pk = None
                    return
            p = self._pk_next
            if p[0] > t:
                return
            self._pk_next = None
            self.counts["packets"] += 1
            for a in self.rg2.update(*p) if self.rg2 is not None else ():
                self._rg_alert_v2(a)
            for a in self.v1.update(*p) if self.v1 is not None else ():
                self._rg_alert_v1(a)

    def _rg_alert_v2(self, a) -> None:
        cls = self.pol.rate_guard_class
        d = self._policy(a.t, cls, a.device, a.group, "rate_guard")
        self.alerts.append({"path": "rate_guard", "rule": "v2", "event_time": a.t, "decision_time": a.t,
                            "wall_time": time.time(), "device": a.device, "device_name": self.router.device_name(a.device),
                            "group": a.group, "class": cls, "family": a.family, "count": a.count, "threshold": a.threshold,
                            "streak": a.streak, "window_start": a.window_start, "policy": d})
        self.counts["rg_alerts_v2"] += 1

    def _rg_alert_v1(self, a) -> None:
        cls = self.pol.rate_guard_class
        dev = self.rg2.ip_device.get(a.dst_ip, "") if self.rg2 is not None else ""
        p = self.router.protected_for_dst_mac(dev) if dev else None
        device, group = (p[0], p[2]) if p else (f"ip:{a.dst_ip}", self.router.fallback)
        d = self._policy(a.window_end, cls, device, group, "rate_guard")
        self.alerts.append({"path": "rate_guard", "rule": "v1", "event_time": a.window_end, "decision_time": a.window_end,
                            "wall_time": time.time(), "device": device, "device_name": self.router.device_name(dev),
                            "group": group, "class": cls, "level": a.level, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
                            "proto": a.proto, "packets": a.packets, "threshold": a.threshold, "policy": d})
        self.counts["rg_alerts_v1"] += 1

    # ------------------------------------------------------------------ flows
    def _quarantine(self, row, err: str) -> None:
        self.counts["quarantined"] += 1
        uid = row.get("_meta", {}).get("flow_uid") if isinstance(row, dict) and isinstance(row.get("_meta"), dict) else None
        self._health("quarantine", flow_uid=uid, error=err[:500])

    def _prepare(self, row: dict):
        lat = self.lat
        meta = row.get("_meta")
        if not isinstance(meta, dict) or not isinstance(meta.get("flow_uid"), str):
            raise ValueError("missing _meta.flow_uid")
        t = float(meta["event_time"])
        if not math.isfinite(t):
            raise ValueError(f"event_time {meta.get('event_time')!r}")
        missing = [f for f in self.feats if f not in row]
        if missing:
            raise ValueError(f"missing features {missing[:5]}")
        t0 = time.perf_counter_ns()
        r = self.router.route(row)
        t1 = time.perf_counter_ns()
        flow = OR.normalise_flow({k: v for k, v in row.items() if k != "_meta"}, self.omap)
        t2 = time.perf_counter_ns()
        x = self.inf.vector(flow)
        t3 = time.perf_counter_ns()
        lat["route"].append(t1 - t0)
        lat["normalise"].append(t2 - t1)
        lat["features"].append(t3 - t2)
        return t, meta, r, flow, x

    def _flush(self, decision_t: float) -> None:
        B = self._batch
        if not B:
            return
        self._batch = []
        n = len(B)
        X = np.vstack([b[4] for b in B])
        mids = [self.rm.model_for(b[2].group) for b in B]
        t0 = time.perf_counter_ns()
        z = self.inf.margins(X, mids)
        t1 = time.perf_counter_ns()
        P = self.inf.calibrate(z, mids)
        t2 = time.perf_counter_ns()
        dec = [self.pol.alert_of(P[i]) for i in range(n)]
        al = [i for i in range(n) if dec[i][0]]
        top = self.inf.explain(X[al], [mids[i] for i in al], [dec[i][1] for i in al]) if al else []
        t3 = time.perf_counter_ns()
        pd_ = {}
        for i in al:
            b = B[i]
            pd_[i] = self._policy(decision_t, self.names[dec[i][1]], b[2].device_mac, b[2].group, "flow")
        t4 = time.perf_counter_ns()
        wall = time.time()
        for j, i in enumerate(al):
            t, meta, r, flow, x, _ = B[i]
            self.alerts.append({"path": "flow", "event_time": t, "decision_time": decision_t, "wall_time": wall,
                                "flow_uid": meta["flow_uid"], "flow_id": flow.get("Flow ID"), "device": r.device_mac,
                                "device_name": r.device, "group": r.group, "class": self.names[dec[i][1]],
                                "probs": [round(float(v), 9) for v in P[i]], "model": {"model_id": mids[i], **self.model_ref[mids[i]]},
                                "policy": pd_[i], "top3": [[f, v, c] for f, v, c in top[j]],
                                "orientation_flipped": bool(flow.get(self.omap["machine"]["flag_column"]))})
        C = self.cols
        fc = self.omap["machine"]["flag_column"]
        for i, b in enumerate(B):
            t, meta, r, flow, x, wq = b
            C["flow_uid"].append(meta["flow_uid"])
            C["session"].append(meta.get("session", ""))
            C["row"].append(int(meta.get("row", -1)))
            C["start_ts"].append(float(meta.get("start_ts", np.nan)))
            C["event_time"].append(t)
            C["decision_time"].append(decision_t)
            C["device_mac"].append(r.device_mac)
            C["device"].append(r.device)
            C["group"].append(r.group)
            C["route_rule"].append(r.rule)
            C["model_id"].append(mids[i])
            C["pred"].append(dec[i][1])
            C["pmax"].append(dec[i][2])
            C["alert"].append(dec[i][0])
            C["incident_id"].append(pd_[i]["incident_id"] if i in pd_ else "")
            C["policy_decision"].append(pd_[i]["decision"] if i in pd_ else "")
            C["orientation_flipped"].append(bool(flow.get(fc)))
            for k in range(len(self.names)):
                C[f"p_{k}"].append(float(P[i, k]))
                C[f"z_{k}"].append(float(z[i, k]))
        if self.store_features:
            self.featbuf.append(X)
        t5 = time.perf_counter_ns()
        done = time.monotonic()
        for b in B:
            self.e2e.append(done - b[5])
        for s, v in (("predict", t1 - t0), ("calibrate", t2 - t1), ("shap", t3 - t2), ("policy", t4 - t3), ("log", t5 - t4)):
            self.lat_batch[s].append(v)
            self.lat[s].append(v / n)
        self.batch_sizes.append(n)
        self.counts["flows_scored"] += n
        self.counts["flow_alerts"] += len(al)
        self.counts["batches"] += 1
        self._advance_incidents(decision_t)

    def _on_time(self, t: float) -> None:
        """Event clock moved to t: flush an expired batch, consume packets, heartbeat."""
        if self._batch and t > self._batch[0][0] + self.bspan:
            self._flush(self._batch[0][0] + self.bspan)
        self._packets_until(t)
        if self._hb_t is None:
            self._hb_t = t
        if t - self._hb_t >= 60.0:
            self._hb_t = t
            self._health("heartbeat", event_time=t, flows=self.counts["flows_scored"], alerts=self.counts["flow_alerts"],
                         rg_alerts=self.counts["rg_alerts_v2"] + self.counts["rg_alerts_v1"], packets=self.counts["packets"],
                         backlog=self._q.qsize(), backlog_peak=self.counts["backlog_peak"], dropped=self.counts["dropped"],
                         quarantined=self.counts["quarantined"], rss_mb=rss_mb())

    # ------------------------------------------------------------------ run
    def _producer(self, source) -> None:
        q, drop = self._q, self.overflow == "drop"
        try:
            for item in source.events():
                rec = (item[0], item[1], item[2], time.monotonic())
                if drop:
                    try:
                        q.put_nowait(rec)
                    except queue.Full:
                        self.counts["dropped"] += 1
                        continue
                else:
                    q.put(rec)
                s = q.qsize()
                if s > self.counts["backlog_peak"]:
                    self.counts["backlog_peak"] = s
        except Exception as e:                                         # noqa: BLE001
            self._prod_err = repr(e)
        finally:
            q.put(_END)

    def run(self, source, packets=None, info: dict | None = None) -> dict:
        self._q = queue.Queue(maxsize=self.qmax)
        self._prod_err = None
        self._pk = iter(packets) if packets is not None else None
        self._health("start", config_sha256=self.cfg["_sha256"], config_pinned=self.cfg["_pinned"],
                     overrides=self.cfg.get("_overrides"), model=self.rm.describe(), source=info or {},
                     overflow=self.overflow, queue_max=self.qmax, batch_max=self.bmax, batch_span_s=self.bspan)
        w0 = time.monotonic()
        th = threading.Thread(target=self._producer, args=(source,), daemon=True)
        th.start()
        while True:
            kind, t, payload, wq = self._q.get()
            if kind == "end":
                break
            self._maybe_rss()
            if t < self._last_t:
                self.counts["out_of_order"] += 1
            self._last_t = max(self._last_t, t)
            if kind == "tick":
                self._on_time(t)
                continue
            self.counts["flows_in"] += 1
            self.qwait.append(time.monotonic() - wq)
            try:
                tt, meta, r, flow, x = self._prepare(payload)
            except (ValueError, TypeError, KeyError, OR.OrientationError) as e:
                self._quarantine(payload, repr(e))
                continue
            self._on_time(tt)
            self._batch.append((tt, meta, r, flow, x, wq))
            if len(self._batch) >= self.bmax:
                self._flush(tt)
            if self.delay:
                time.sleep(self.delay)
        th.join()
        if self._batch:
            self._flush(self._batch[0][0] + self.bspan)
        self._packets_until(math.inf)
        for a in self.rg2.flush() if self.rg2 is not None else ():
            self._rg_alert_v2(a)
        for a in self.v1.flush() if self.v1 is not None else ():
            self._rg_alert_v1(a)
        incidents = self.pol.tracker.finish()
        self._emit_closed()
        wall = time.monotonic() - w0
        self._maybe_rss()
        self._health("end", flows_in=self.counts["flows_in"], flows_scored=self.counts["flows_scored"],
                     quarantined=self.counts["quarantined"], dropped=self.counts["dropped"],
                     backlog_peak=self.counts["backlog_peak"], packets=self.counts["packets"],
                     flow_alerts=self.counts["flow_alerts"], rg_alerts_v2=self.counts["rg_alerts_v2"],
                     rg_alerts_v1=self.counts["rg_alerts_v1"], incidents=len(incidents), wall_s=wall,
                     producer_error=self._prod_err, peak_rss_mb=peak_rss_mb())
        return self._write(incidents, wall, source)

    def _write(self, incidents: list, wall: float, source) -> dict:
        import pyarrow as pa
        import pyarrow.parquet as pq
        C = self.cols
        tbl = pa.table({k: v for k, v in C.items()}) if C else pa.table({"flow_uid": pa.array([], pa.string())})
        pq.write_table(tbl, self.dir / "predictions.parquet")
        if self.store_features and self.featbuf:
            np.save(self.dir / "features.npy", np.vstack(self.featbuf))
        (self.dir / "incidents.json").write_text(json.dumps([i.as_dict() for i in incidents], indent=0) + "\n",
                                                 encoding="utf-8")
        np.savez_compressed(self.dir / "latency.npz", **{f"flow_{s}": np.asarray(v, np.int64) for s, v in self.lat.items()},
                            **{f"batch_{s}": np.asarray(v, np.int64) for s, v in self.lat_batch.items()},
                            batch_sizes=np.asarray(self.batch_sizes, np.int64), e2e_s=np.asarray(self.e2e),
                            queue_wait_s=np.asarray(self.qwait))
        (self.dir / "rss.json").write_text(json.dumps(self.rss) + "\n", encoding="utf-8")
        logs = {"alerts": self.alerts.close(), "health": self.health.close(), "outbox": self.outbox.close()}
        rg = {}
        if self.rg2 is not None:
            rg["v2"] = dict(self.rg2.stats)
        if self.v1 is not None:
            rg["v1"] = self.v1.stats()
        return {"counts": dict(self.counts), "wall_s": wall, "logs": logs, "incidents": len(incidents),
                "incident_decisions": dict(self.pol.tracker.counts), "rate_guard": rg, "router": dict(self.router.stats),
                "source_stats": getattr(source, "stats", {}), "peak_rss_mb": peak_rss_mb(),
                "flows_per_s": self.counts["flows_scored"] / wall if wall > 0 else float("nan")}
