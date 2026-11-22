"""common/policy.py -- Phase 3 policy (docs/V2_PREREG_PHASE3.md section 4): threshold -> alert -> incident
aggregation / cooldown -> severity. Pure functions plus one small state object; no I/O.

    pol = Policy.from_config(cfg, class_names)
    ok, cls, pmax = pol.alert_of(probs_row)               # attack argmax AND calibrated max-prob >= threshold
    d = pol.tracker.process(t, key_class, device, group, path)    # {"decision": opened|extended|suppressed_cooldown, ...}
    closed = pol.tracker.finish()                         # every incident, closed
    incidents = run_policy(alerts, window_s, cooldown_s, severity_fn)   # the same tracker over a list (sweeps)

Incidents are keyed (class, protected device); an open incident absorbs every alert of its key arriving within
window_s of its previous alert and closes window_s after its last alert; the key then cannot open a new incident until
close + cooldown_s (alerts in between are suppressed: logged, counted, they extend nothing). Event times per key must
be non-decreasing; an older alert for a key is folded into its open incident (counted as `late`).
"""

from __future__ import annotations

from dataclasses import dataclass, field


def severity_of(cls_name: str, severity: dict, default: str) -> str:
    return severity.get(cls_name, default)


def alert_decision(probs, threshold: float, benign_id: int = 0) -> tuple[bool, int, float]:
    """(is_alert, argmax class, its probability). Ties in argmax -> the lowest class id (numpy argmax)."""
    best, pmax = 0, probs[0]
    for c in range(1, len(probs)):
        if probs[c] > pmax:
            best, pmax = c, probs[c]
    return (best != benign_id and pmax >= threshold), best, float(pmax)


@dataclass
class Incident:
    incident_id: str
    key_class: str
    device: str
    group: str
    severity: str
    first: float
    last: float
    n_alerts: int = 0
    n_suppressed_after: int = 0
    paths: set = field(default_factory=set)
    closed_at: float | None = None

    def as_dict(self) -> dict:
        return {"incident_id": self.incident_id, "class": self.key_class, "device": self.device, "group": self.group,
                "severity": self.severity, "first": self.first, "last": self.last, "closed_at": self.closed_at,
                "n_alerts": self.n_alerts, "n_suppressed_after": self.n_suppressed_after, "paths": sorted(self.paths)}


class IncidentTracker:
    def __init__(self, window_s: float, cooldown_s: float, severity_fn, id_prefix: str = "inc"):
        self.window, self.cooldown, self.sev = float(window_s), float(cooldown_s), severity_fn
        self.prefix = id_prefix
        self.open: dict = {}
        self.cool_until: dict = {}
        self.last_closed: dict = {}
        self.closed: list = []
        self.n = 0
        self.counts = {"opened": 0, "extended": 0, "suppressed_cooldown": 0, "late": 0}

    def _close(self, key, inc: Incident) -> None:
        inc.closed_at = inc.last + self.window
        self.cool_until[key] = inc.closed_at + self.cooldown
        self.last_closed[key] = inc
        self.closed.append(inc)
        del self.open[key]

    def process(self, t: float, key_class: str, device: str, group: str, path: str) -> dict:
        key = (key_class, device)
        inc = self.open.get(key)
        if inc is not None and t - inc.last > self.window:
            self._close(key, inc)
            inc = None
        if inc is not None:
            if t < inc.last:
                self.counts["late"] += 1
            inc.last = max(inc.last, t)
            inc.n_alerts += 1
            inc.paths.add(path)
            self.counts["extended"] += 1
            return {"decision": "extended", "incident_id": inc.incident_id, "severity": inc.severity}
        if t < self.cool_until.get(key, float("-inf")):
            prev = self.last_closed[key]
            prev.n_suppressed_after += 1
            self.counts["suppressed_cooldown"] += 1
            return {"decision": "suppressed_cooldown", "incident_id": prev.incident_id, "severity": prev.severity}
        self.n += 1
        inc = Incident(f"{self.prefix}{self.n:06d}", key_class, device, group, self.sev(key_class), t, t, 1, 0, {path})
        self.open[key] = inc
        self.counts["opened"] += 1
        return {"decision": "opened", "incident_id": inc.incident_id, "severity": inc.severity}

    def advance(self, t: float) -> list:
        """Close every open incident whose window has passed at event time t; returns them."""
        done = [(k, i) for k, i in self.open.items() if t - i.last > self.window]
        for k, i in done:
            self._close(k, i)
        return [i for _, i in done]

    def finish(self) -> list:
        for k, i in list(self.open.items()):
            self._close(k, i)
        return sorted(self.closed, key=lambda i: (i.first, i.incident_id))


class Policy:
    def __init__(self, threshold: float, window_s: float, cooldown_s: float, severity: dict, default: str,
                 class_names: list, rate_guard_class: str, benign_id: int = 0):
        self.threshold, self.class_names, self.benign_id = float(threshold), list(class_names), benign_id
        self.severity, self.default, self.rate_guard_class = dict(severity), default, rate_guard_class
        self.tracker = IncidentTracker(window_s, cooldown_s, self.severity_fn)

    @classmethod
    def from_config(cls, cfg: dict, class_names: list, **over) -> "Policy":
        p = cfg["policy"]
        return cls(over.get("threshold", p["confidence_threshold"]), over.get("window_s", p["aggregation_window_s"]),
                   over.get("cooldown_s", p["cooldown_s"]), p["severity"], p["severity_default"], class_names,
                   p["rate_guard_class"])

    def severity_fn(self, cls_name: str) -> str:
        return severity_of(cls_name, self.severity, self.default)

    def alert_of(self, probs) -> tuple[bool, int, float]:
        return alert_decision(probs, self.threshold, self.benign_id)


def run_policy(alerts: list, window_s: float, cooldown_s: float, severity_fn) -> tuple[list, dict]:
    """alerts: (t, key_class, device, group, path) sorted by t -> (closed incidents, decision counts)."""
    tr = IncidentTracker(window_s, cooldown_s, severity_fn)
    for a in alerts:
        tr.process(*a)
    return tr.finish(), dict(tr.counts)
