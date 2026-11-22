#!/usr/bin/env python
"""29_eval_stream.py -- Phase 3 step F: incident-level evaluation of the step 28 runtime runs on VAL
(docs/V2_PREREG_PHASE3.md sections 3-5, 8).

Inputs: the step 28 run (results/phase3/28/run_meta.json, manifest sha256 re-checked) and its runtime run folders
(predictions.parquet, alerts.jsonl -- chain verified --, incidents.json); ground truth from v2_1_oriented val (label,
protected device = device_mac, group, session, start, duration). Computes:
  episodes        attack flows per (class, device), new episode when a start is > gap_s after the latest end
  detection       per episode x path (flow model / rate guard / either): an alert for its device in
                  [start, end + detect_slack_s]; time-to-detect = first alert decision time - start; also own-class
  incidents       correct / misclassified / false (overlap of [first, last alert] with episode windows on the device)
  rates           false and misclassified incidents / h, flow-level (argmax) and alert-level false alarms / h, overall
                  and per group; benign hours = Phase 2's benign_hours (pause > 300 s)
  rate guard      its alerts / incidents on no episode, per benign hour
  CIs             GLOBAL / ROUTED over the 5 seeds (t-CI); seed 0 Garwood on counts; bootstrap over episodes for the
                  rate guard and for time-to-detect quantiles (seed 0)
  sweeps          report-only: confidence threshold x aggregation window via the pure policy on GLOBAL s0 predictions
                  (sanity: the default cell reproduces the runtime's flow incidents exactly)
Outputs: results/phase3/29/ summary.md, metrics.json, episodes.csv, run_manifest.json, run_meta.json, run.log,
figures/{replay_timeline, ttd_ecdf, false_alarms_per_group, detection_rate, sweeps}.png. --dry-run reads the dry
step 28 run (--run28 <id>).
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import defaultdict
from pathlib import Path

import numpy as np

from config.config import REPO_ROOT
from common import alert_log as AL
from common import phase2_metrics as PM
from common import phase3_config as C
from common import phase3_run as R3
from common import plot_style as PS
from common import schemas as S
from common.policy import Policy, run_policy
from common.routing import Router

SCRIPT = "29_eval_stream.py"
PATHS = ("flow", "rate_guard", "either")


# --------------------------------------------------------------------------- data
def ground_truth(cfg: dict, dry: bool) -> dict:
    from common import phase2_data as D
    from common.phase2_config import load_phase2_config
    cfg2 = load_phase2_config(REPO_ROOT / cfg["phase2_config"])
    va = D.load_split(cfg2, "val", ["session", "row_in_file", "label_id", "device_mac", "group", "start_ts",
                                    "Flow Duration"], sample=dry)
    uid = (va["session"].astype(str) + ":" + va["row_in_file"].astype(str)).to_numpy()
    st = va["start_ts"].to_numpy(np.float64)
    return {"uid": uid, "y": va["label_id"].to_numpy(np.int64), "dev": va["device_mac"].astype(str).to_numpy(),
            "group": va["group"].astype(str).to_numpy(), "session": va["session"].astype(str).to_numpy(),
            "start": st, "end": st + va["Flow Duration"].to_numpy(np.float64) / 1e6,
            "start_int": va["start_ts"].to_numpy(np.int64), "val_sha256": D.verify_split_file(cfg2, "val")}


def episodes(gt: dict, gap: float) -> list[dict]:
    out = []
    att = np.flatnonzero(gt["y"] != 0)
    key = defaultdict(list)
    for i in att:
        key[(int(gt["y"][i]), gt["dev"][i])].append(i)
    for (c, dev), ix in sorted(key.items()):
        ix = sorted(ix, key=lambda i: (gt["start"][i], gt["end"][i]))
        cur = None
        for i in ix:
            if cur is None or gt["start"][i] > cur["end"] + gap:
                cur = {"class": c, "device": dev, "group": gt["group"][i], "session": gt["session"][i],
                       "start": float(gt["start"][i]), "end": float(gt["end"][i]), "n_flows": 0}
                out.append(cur)
            cur["end"] = max(cur["end"], float(gt["end"][i]))
            cur["n_flows"] += 1
    for k, e in enumerate(out):
        e["episode_id"] = f"ep{k:03d}"
    return out


def load_run(d: Path, gt: dict) -> dict:
    from common.predictions_io import read_predictions
    P = read_predictions(d)                                            # single file (Phase 3) or parts (Phase 3.1)
    pos = {u: i for i, u in enumerate(gt["uid"])}
    gi = np.array([pos[u] for u in P["flow_uid"]], dtype=np.int64)
    A = [json.loads(x) for x in (d / "alerts.jsonl").read_text(encoding="utf-8").splitlines()]
    rg = [(a["decision_time"], a["device"], a.get("rule", "")) for a in A if a["path"] == "rate_guard"]
    inc = json.loads((d / "incidents.json").read_text(encoding="utf-8"))
    return {"P": P, "gi": gi, "rg": rg, "incidents": inc, "manifest": json.loads((d / "manifest.json").read_text())}


# --------------------------------------------------------------------------- metrics
def detect(eps: list, alerts: dict, slack: float) -> list:
    """alerts: device -> sorted array of decision times (+ parallel class array or None). Returns per episode
    (detected, ttd, detected_own_class, ttd_own)."""
    out = []
    for e in eps:
        t, cl = alerts.get(e["device"], (np.zeros(0), None))
        lo, hi = e["start"], e["end"] + slack
        j = np.searchsorted(t, lo, side="left")
        hit = j < len(t) and t[j] <= hi
        own, ttd_own = None, None
        if cl is not None:
            k = np.flatnonzero((t >= lo) & (t <= hi) & (cl == e["class"]))
            own = bool(len(k))
            ttd_own = float(t[k[0]] - lo) if len(k) else None
        out.append((bool(hit), float(t[j] - lo) if hit else None, own, ttd_own))
    return out


def alert_index(times, devs, classes=None) -> dict:
    by = defaultdict(list)
    for i, (t, d) in enumerate(zip(times, devs)):
        by[d].append((t, classes[i] if classes is not None else -1))
    out = {}
    for d, v in by.items():
        v.sort()
        out[d] = (np.array([a for a, _ in v]), np.array([b for _, b in v]) if classes is not None else None)
    return out


def incident_outcomes(incs: list, eps: list, slack: float, names: list, rg_class: str) -> list:
    by = defaultdict(list)
    for e in eps:
        by[e["device"]].append(e)
    out = []
    for i in incs:
        ov = [e for e in by.get(i["device"], []) if i["first"] <= e["end"] + slack and i["last"] >= e["start"]]
        if not ov:
            o = "false"
        elif i["class"] == rg_class or any(names[e["class"]] == i["class"] for e in ov):
            o = "correct"
        else:
            o = "misclassified"
        out.append(o)
    return out


def run_metrics(R: dict, gt: dict, eps: list, rg_alerts: list, cfg: dict, names: list, hours: dict) -> dict:
    """One runtime run (flow path from R; rate-guard alerts given separately so seeds share s0's packet path)."""
    P, gi = R["P"], R["gi"]
    slack, rgc = cfg["episodes"]["detect_slack_s"], cfg["policy"]["rate_guard_class"]
    y, grp = gt["y"][gi], gt["group"][gi]
    pred, alert = P["pred"].to_numpy(), P["alert"].to_numpy(bool)
    fa = P["alert"].to_numpy(bool)
    m = {"n_flows": int(len(P))}
    fl = alert_index(P["decision_time"].to_numpy()[fa], P["device_mac"].to_numpy()[fa], pred[fa])
    rgi = alert_index([a[0] for a in rg_alerts], [a[1] for a in rg_alerts])
    dF, dR = detect(eps, fl, slack), detect(eps, rgi, slack)
    det = []
    for e, f, r in zip(eps, dF, dR):
        ttds = [x for x in (f[1], r[1]) if x is not None]
        det.append({"episode_id": e["episode_id"], "flow": f[0], "ttd_flow": f[1], "flow_own": f[2], "ttd_flow_own": f[3],
                    "rate_guard": r[0], "ttd_rate_guard": r[1], "either": f[0] or r[0],
                    "ttd_either": min(ttds) if ttds else None})
    m["detection"] = det
    flow_inc = [i for i in R["incidents"] if i["class"] != rgc]
    outc = incident_outcomes(flow_inc, eps, slack, names, rgc)
    m["flow_incidents"] = {"n": len(flow_inc), "correct": outc.count("correct"), "misclassified": outc.count("misclassified"),
                           "false": outc.count("false")}
    m["flow_incidents_by_group"] = {}
    for g in hours:
        if g == "all":
            continue
        oo = [o for o, i in zip(outc, flow_inc) if i["group"] == g]
        m["flow_incidents_by_group"][g] = {"false": oo.count("false"), "misclassified": oo.count("misclassified"),
                                           "n": len(oo)}
    m["false_incident_ids"] = [i["incident_id"] for o, i in zip(outc, flow_inc) if o == "false"]
    ben = y == 0
    m["flow_fa"] = {"all": int((ben & (pred != 0)).sum()), **{g: int((ben & (pred != 0) & (grp == g)).sum())
                                                               for g in hours if g != "all"}}
    m["alert_fa"] = {"all": int((ben & alert).sum()), **{g: int((ben & alert & (grp == g)).sum()) for g in hours if g != "all"}}
    m["below_threshold_attack_argmax"] = int(((pred != 0) & ~alert).sum())
    return m


def rg_metrics(rg_alerts: list, incs: list, eps: list, cfg: dict, names: list, hours: dict, dev_group: dict) -> dict:
    slack, rgc = cfg["episodes"]["detect_slack_s"], cfg["policy"]["rate_guard_class"]
    by = defaultdict(list)
    for e in eps:
        by[e["device"]].append(e)
    off = [a for a in rg_alerts if not any(e["start"] <= a[0] <= e["end"] + slack for e in by.get(a[1], []))]
    rinc = [i for i in incs if i["class"] == rgc]
    outc = incident_outcomes(rinc, eps, slack, names, rgc)
    return {"alerts": len(rg_alerts), "alerts_v2": sum(a[2] == "v2" for a in rg_alerts),
            "alerts_v1": sum(a[2] == "v1" for a in rg_alerts), "alerts_on_no_episode": len(off),
            "alerts_on_no_episode_by_rule": {r: sum(a[2] == r for a in off) for r in ("v2", "v1")},
            "incidents": len(rinc), "false_incidents": outc.count("false"),
            "false_incidents_by_group": {g: sum(1 for o, i in zip(outc, rinc) if o == "false" and i["group"] == g)
                                         for g in hours if g != "all"},
            "false_alert_examples": [{"t": a[0], "device": a[1], "rule": a[2]} for a in off[:10]]}


def ci_seeds(vals: list, lvl: float) -> dict:
    return PM.t_ci(vals, lvl)


def garwood_rate(k: int, h: float, lvl: float) -> dict:
    lo, hi = PM.garwood(k, lvl)
    return {"count": k, "hours": h, "rate": k / h if h else float("nan"), "lo": lo / h if h else float("nan"),
            "hi": hi / h if h else float("nan")}


def boot(vals: np.ndarray, fn, B: int, seed: int, lvl: float) -> tuple:
    vals = np.asarray(vals, float)
    if len(vals) == 0:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    st = [fn(vals[rng.integers(0, len(vals), len(vals))]) for _ in range(B)]
    a = (1 - lvl) / 2
    return float(fn(vals)), float(np.nanquantile(st, a)), float(np.nanquantile(st, 1 - a))


# --------------------------------------------------------------------------- figures
def fig_timeline(path, eps, runs, gt, names, router, rg_alerts):
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    PS.apply()
    R = runs["GLOBAL_s0"]
    P = R["P"]
    fa = P["alert"].to_numpy(bool)
    sess = sorted(set(gt["session"]), key=lambda s: gt["start"][gt["session"] == s].min())
    fig, axes = plt.subplots(1, len(sess), figsize=(3.3 * len(sess), 4.6), squeeze=False)
    sess_of_uid = P["session"].to_numpy()
    for ax, s in zip(axes[0], sess):
        t0 = gt["start"][gt["session"] == s].min()
        t1 = gt["end"][gt["session"] == s].max()
        ep_s = [e for e in eps if e["session"] == s]
        al = fa & (sess_of_uid == s)
        rg_s = [a for a in rg_alerts if t0 - 60 <= a[0] <= t1 + 300]
        devs = sorted({e["device"] for e in ep_s} | set(P["device_mac"].to_numpy()[al]) | {a[1] for a in rg_s},
                      key=lambda d: (router._group_of(d) if d and not d.startswith("ip:") else "~", router.device_name(d)))
        devs = devs[:14]
        yi = {d: k for k, d in enumerate(devs)}
        for e in ep_s:
            if e["device"] in yi:
                ax.barh(yi[e["device"]], max((e["end"] - e["start"]) / 60, 0.012 * max((t1 - t0) / 60, 1)),
                        left=(e["start"] - t0) / 60, height=0.7,
                        color=PS.class_color(e["class"]), alpha=0.35, edgecolor="none")
        tt = P["decision_time"].to_numpy()[al]
        dd = P["device_mac"].to_numpy()[al]
        for d in devs:
            k = dd == d
            if k.any():
                u = np.unique(np.round((tt[k] - t0) / 6.0)) * 0.1        # thinned to 6 s bins
                ax.plot(u, np.full(len(u), yi[d] + 0.18), "|", color=PS.TEXT1, ms=5, mew=0.8)
        for a in rg_s:
            if a[1] in yi:
                ax.plot((a[0] - t0) / 60, yi[a[1]] - 0.22, "v", color=PS.CATEGORICAL[4], ms=3.5)
        ax.set_yticks(range(len(devs)), [f"{router.device_name(d)[:16]} ..{d[-5:]} "
                                         f"({router._group_of(d) if d and not d.startswith('ip:') else '?'})"
                                         for d in devs], fontsize=6.5)
        if not devs:
            ax.text(0.5, 0.5, "no episodes, no alerts", transform=ax.transAxes, ha="center", color=PS.TEXT2, fontsize=8)
            ax.set_yticks([])
        ax.set_xlabel("minutes since first val flow", fontsize=8)
        ax.set_title(s, loc="left", fontsize=8.5)
        ax.set_ylim(max(len(devs), 1) - 0.5, -0.5)
    hand = [Patch(color=PS.class_color(c), alpha=0.35, label=f"episode: {names[c]}") for c in range(1, len(names))] + \
           [Line2D([], [], marker="|", ls="none", color=PS.TEXT1, label="flow-model alert (6 s bins)"),
            Line2D([], [], marker="v", ls="none", color=PS.CATEGORICAL[4], label="rate-guard alert")]
    fig.legend(handles=hand, loc="lower center", ncol=len(hand), frameon=False, fontsize=7.5, bbox_to_anchor=(0.5, -0.04))
    fig.suptitle("Replay timeline (val, GLOBAL s0): ground-truth episodes and alerts per protected device; "
                 "each panel is one capture on its own clock", x=0.01, ha="left", fontsize=9)
    fig.tight_layout(rect=(0, 0.04, 1, 0.97))
    return PS.save(fig, path)


def fig_ttd(path, eps, det0, names):
    import matplotlib.pyplot as plt
    PS.apply()
    classes = sorted({e["class"] for e in eps})
    fig, axes = plt.subplots(1, len(classes), figsize=(3.4 * len(classes), 3.0), squeeze=False, sharey=True)
    sty = {"flow": (PS.CATEGORICAL[0], "-", "flow model"), "rate_guard": (PS.CATEGORICAL[4], "--", "rate guard"),
           "either": (PS.TEXT1, ":", "either (hybrid)")}
    for ax, c in zip(axes[0], classes):
        ix = [k for k, e in enumerate(eps) if e["class"] == c]
        n = len(ix)
        for p, (col, ls, lab) in sty.items():
            v = np.sort([det0[k][f"ttd_{p}"] for k in ix if det0[k][f"ttd_{p}"] is not None])
            x = np.concatenate([[0.01], np.maximum(v, 0.01)])
            yv = np.concatenate([[0], np.arange(1, len(v) + 1) / n])
            ax.step(x, yv, where="post", color=col, ls=ls, lw=1.6, label=f"{lab} ({len(v)}/{n})")
        ax.set_xscale("log")
        ax.set_ylim(0, 1.05)
        ax.set_title(f"{names[c]} ({n} episodes)", loc="left", fontsize=9)
        ax.set_xlabel("time to detect (s, log; 0 shown at 0.01)", fontsize=8)
        ax.legend(frameon=False, fontsize=7, loc="upper left")
        ax.yaxis.grid(True)
    axes[0][0].set_ylabel("share of episodes detected")
    fig.suptitle("Time to detect per class: flow model vs rate guard vs either (val, GLOBAL s0; the curve's plateau "
                 "= detection rate)", x=0.01, ha="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_fa(path, agg, groups):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 3.2), sharey=True)
    for ax, mode in zip(axes, ("GLOBAL", "ROUTED")):
        x = np.arange(len(groups) + 1)
        labels = ["all"] + groups
        for k, (met, col, lab) in enumerate((("flow_fa_per_h", PS.NEUTRAL_LIGHT, "flow-level false alarms / h"),
                                              ("false_incidents_per_h", PS.CATEGORICAL[0], "false incidents / h"))):
            v = [agg[mode][met][g] for g in labels]
            m_ = np.array([a["mean"] for a in v])
            err = np.vstack([np.nan_to_num(m_ - np.array([a["lo"] for a in v])), np.nan_to_num(np.array([a["hi"] for a in v]) - m_)])
            off = -0.2 if k == 0 else 0.2
            ax.bar(x + off, m_, 0.38, yerr=err, color=col, label=lab, error_kw={"lw": 0.8, "capsize": 2})
            for xx, mm, hi in zip(x + off, m_, m_ + err[1]):
                ax.text(xx, hi, f"{mm:.2f}", ha="center", va="bottom", fontsize=6.5)
        ax.set_xticks(x, labels)
        top = max(a["hi"] if np.isfinite(a["hi"]) else a["mean"] for met in ("flow_fa_per_h", "false_incidents_per_h")
                  for a in agg[mode][met].values())
        ax.set_ylim(0, max(top, 0.1) * 1.18)
        ax.set_title(f"{mode} (mean +- 95 % t-CI over 5 seeds)", loc="left", fontsize=9)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("per benign val hour")
    axes[1].legend(frameon=False, fontsize=7.5, loc="upper right")
    fig.suptitle("False alarms counted as flows vs as incidents, per group (val; flow path)", x=0.01, ha="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_detect(path, drate, names, classes):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, ax = plt.subplots(figsize=(6.6, 0.3 * len(classes) * 3 + 1.2))
    rows = [(c, p) for c in classes for p in PATHS]
    y = np.arange(len(rows))[::-1]
    for yy, (c, p) in zip(y, rows):
        d = drate[names[c]][p]
        ax.errorbar(d["mean"], yy, xerr=[[d["mean"] - d["lo"]], [d["hi"] - d["mean"]]], fmt="o",
                    color={"flow": PS.CATEGORICAL[0], "rate_guard": PS.CATEGORICAL[4], "either": PS.TEXT1}[p], ms=5, capsize=2)
        ax.text(1.02, yy, f"{d['mean']:.2f} [{d['lo']:.2f}, {d['hi']:.2f}]  n={d['n']}", va="center", fontsize=7,
                transform=ax.get_yaxis_transform())
    ax.set_yticks(y, [f"{names[c]} / {p}" for c, p in rows], fontsize=7.5)
    ax.set_xlim(-0.02, 1.02)
    ax.set_xlabel("episode detection rate (GLOBAL; flow / either: mean over 5 seeds +- t-CI; rate guard: bootstrap)")
    ax.xaxis.grid(True)
    ax.set_title("Detection rate per class x path (val)", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_sweeps(path, sw, thr_list, win_list):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, axes = plt.subplots(1, 3, figsize=(10.5, 3.0))
    for k, (met, lab) in enumerate((("false_incidents_per_h", "false incidents / h"),
                                     ("detection_rate", "episode detection rate (flow path)"),
                                     ("median_ttd_s", "median time to detect (s)"))):
        ax = axes[k]
        allv = []
        for j, w in enumerate(win_list):
            v = [sw[f"{t}|{w}"][met] for t in thr_list]
            allv += v
            ax.plot(thr_list, v, "o-", color=PS.CATEGORICAL[j], label=f"window {w} s", ms=4 + 2 * (len(win_list) - 1 - j),
                    lw=1.2, alpha=0.85)
        for t in thr_list:
            vs = [sw[f"{t}|{w}"][met] for w in win_list]
            same = all(abs(x - vs[0]) < 1e-12 for x in vs)
            txt = f"{vs[0]:.2f} (all windows)" if same else " / ".join(f"{x:.2f}" for x in vs)
            ax.annotate(txt, (t, vs[0]), textcoords="offset points", xytext=(0, 7), ha="center", fontsize=6.5,
                        color=PS.TEXT1)
        fin = [x for x in allv if np.isfinite(x)]
        if fin:
            lo, hi = min(fin), max(fin)
            pad = (hi - lo) * 0.35 if hi > lo else max(abs(hi) * 0.2, 0.05)
            ax.set_ylim(lo - pad * 0.4, hi + pad)
        ax.set_xlim(thr_list[0] - 0.08, thr_list[-1] + 0.08)
        ax.set_xlabel("confidence threshold")
        ax.set_title(lab, loc="left", fontsize=9)
        ax.set_xticks(thr_list)
        ax.yaxis.grid(True)
    axes[0].legend(frameon=False, fontsize=7)
    fig.suptitle("Report-only policy sweeps (GLOBAL s0, flow path; defaults 0.5 / 60 s unchanged)", x=0.01, ha="left",
                 fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--run28", default=None, help="step 28 run id (required with --dry-run)")
    ap.add_argument("--run28-tag", default=None, help="results subfolder of a step 28 re-run (D85)")
    ap.add_argument("--rerun-tag", default=None, help="re-run of this step: results/phase3/29/<tag>/ (D88)")
    args = ap.parse_args()
    cfg = C.load_phase3_config()
    run = R3.Run("29", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest()
    R3.lock_banner(run, M, "start")
    ok = False
    lvl, B, bs = cfg["eval"]["ci_level"], cfg["eval"]["bootstrap"], cfg["eval"]["bootstrap_seed"]
    try:
        up = R3.resolve("28", args.run28, args.dry_run, args.run28_tag)
        M["run28"] = {"run_id": up["meta"]["run_id"], "manifest_sha256": up["meta"]["run_manifest_sha256"],
                      "parity_gate": up["manifest"].get("parity_gate")}
        run.check(M, "step 28 parity gate passed", up["manifest"].get("parity_gate") == "PASS", str(M["run28"]))
        names = list(S.load_class_map().names)
        router = Router(cfg)
        gt = ground_truth(cfg, args.dry_run)
        groups = sorted(set(gt["group"]))
        ben = gt["y"] == 0
        gap = cfg["eval"]["benign_hours_idle_gap_s"]
        hours = {"all": PM.benign_hours(gt["session"], gt["start_int"], ben, gap)}
        for g in groups:
            hours[g] = PM.benign_hours(gt["session"], gt["start_int"], ben & (gt["group"] == g), gap)
        M["hours"] = hours
        eps = episodes(gt, cfg["episodes"]["gap_s"])
        run.log(f"  {len(eps)} episodes: " + ", ".join(f"{names[c]} {sum(e['class'] == c for e in eps)}"
                                                       for c in sorted({e['class'] for e in eps})))
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
            runs[tag] = load_run(d, gt)
        run.check(M, "every run's alerts / health / outbox chain verifies (runtime key, expected count + head)", True,
                  f"{len(runs)} runs x 3 logs")
        modes = sorted({t.split("_s")[0] for t in runs})
        seeds = sorted({int(t.split("_s")[1]) for t in runs})
        per = {}
        rgA = {m: runs[f"{m}_s0"]["rg"] for m in modes}
        run.check(M, "rate-guard alerts identical across modes (model-independent packet path)",
                  len({json.dumps(sorted(v)) for v in rgA.values()}) == 1, f"{[len(v) for v in rgA.values()]} alerts")
        for tag, R in runs.items():
            m = tag.split("_s")[0]
            per[tag] = run_metrics(R, gt, eps, rgA[m], cfg, names, hours)
        rgm = rg_metrics(rgA[modes[0]], runs[f"{modes[0]}_s0"]["incidents"], eps, cfg, names, hours, {})
        rgm["benign_alerts_per_h"] = garwood_rate(rgm["alerts_on_no_episode"], hours["all"], lvl)
        rgm["false_incidents_per_h"] = garwood_rate(rgm["false_incidents"], hours["all"], lvl)
        M["rate_guard"] = rgm
        agg = {}
        classes = sorted({e["class"] for e in eps})
        for mode in modes:
            tags = [f"{mode}_s{s}" for s in seeds if f"{mode}_s{s}" in per]
            A = {"seeds": [int(t.split("_s")[1]) for t in tags]}
            for met, src in (("flow_fa_per_h", "flow_fa"), ("alert_fa_per_h", "alert_fa")):
                A[met] = {g: ci_seeds([per[t][src][g] / hours[g] for t in tags], lvl) for g in ["all"] + groups}
            A["false_incidents_per_h"] = {"all": ci_seeds([per[t]["flow_incidents"]["false"] / hours["all"] for t in tags], lvl),
                                          **{g: ci_seeds([per[t]["flow_incidents_by_group"][g]["false"] / hours[g]
                                                          for t in tags], lvl) for g in groups}}
            A["misclassified_incidents_per_h"] = {"all": ci_seeds([per[t]["flow_incidents"]["misclassified"] / hours["all"]
                                                                   for t in tags], lvl)}
            A["incidents"] = ci_seeds([per[t]["flow_incidents"]["n"] for t in tags], lvl)
            s0 = per[f"{mode}_s0"]
            A["seed0"] = {"flow_fa": garwood_rate(s0["flow_fa"]["all"], hours["all"], lvl),
                          "alert_fa": garwood_rate(s0["alert_fa"]["all"], hours["all"], lvl),
                          "false_incidents": garwood_rate(s0["flow_incidents"]["false"], hours["all"], lvl),
                          "misclassified_incidents": garwood_rate(s0["flow_incidents"]["misclassified"], hours["all"], lvl),
                          "flow_incidents": s0["flow_incidents"],
                          "false_incidents_total_incl_rate_guard": garwood_rate(
                              s0["flow_incidents"]["false"] + rgm["false_incidents"], hours["all"], lvl),
                          "below_threshold_attack_argmax": s0["below_threshold_attack_argmax"]}
            dr, tt = {}, {}
            for c in classes:
                ix = [k for k, e in enumerate(eps) if e["class"] == c]
                dr[names[c]], tt[names[c]] = {}, {}
                for p in PATHS + ("flow_own",):
                    if p == "rate_guard":
                        v = np.array([per[f"{mode}_s0"]["detection"][k]["rate_guard"] for k in ix], float)
                        mu, lo, hi = boot(v, np.mean, B, bs, lvl)
                        dr[names[c]][p] = {"mean": mu, "lo": lo, "hi": hi, "n": len(ix), "ci": "bootstrap over episodes"}
                    else:
                        vals = [np.mean([bool(per[t]["detection"][k][p]) for k in ix]) for t in tags]
                        dr[names[c]][p] = {**ci_seeds(vals, lvl), "n": len(ix), "ci": "t over seeds", "per_seed": vals}
                    key = {"flow": "ttd_flow", "rate_guard": "ttd_rate_guard", "either": "ttd_either",
                           "flow_own": "ttd_flow_own"}[p]
                    v0 = np.array([per[f"{mode}_s0"]["detection"][k][key] for k in ix
                                   if per[f"{mode}_s0"]["detection"][k][key] is not None], float)
                    md = boot(v0, np.median, B, bs, lvl)
                    p95 = boot(v0, lambda a: np.quantile(a, 0.95), B, bs, lvl)
                    tt[names[c]][p] = {"n_detected": int(len(v0)), "median": md[0], "median_ci": md[1:],
                                       "p95": p95[0], "p95_ci": p95[1:],
                                       "median_over_seeds": ci_seeds([np.median([per[t]["detection"][k][key] for k in ix
                                                                                 if per[t]["detection"][k][key] is not None]
                                                                                or [np.nan]) for t in tags], lvl)
                                       if p != "rate_guard" else None}
            A["detection_rate"], A["ttd"] = dr, tt
            agg[mode] = A
        M["aggregate"] = agg
        # sweeps (report-only) on GLOBAL s0
        R0 = runs[f"{modes[0]}_s0"]
        P0 = R0["P"]
        K = len(names)
        Pm = P0[[f"p_{k}" for k in range(K)]].to_numpy()
        pred0 = P0["pred"].to_numpy()
        sw = {}
        pol = Policy.from_config(cfg, names)
        for thr in cfg["sweeps"]["confidence_threshold"]:
            al = (pred0 != 0) & (Pm.max(1) >= thr)
            order = np.argsort(P0["decision_time"].to_numpy()[al], kind="stable")
            A_ = [(float(t), names[int(c)], d, g, "flow") for t, c, d, g in
                  zip(P0["decision_time"].to_numpy()[al][order], pred0[al][order], P0["device_mac"].to_numpy()[al][order],
                      P0["group"].to_numpy()[al][order])]
            idx = alert_index([a[0] for a in A_], [a[2] for a in A_])
            dd = detect(eps, idx, cfg["episodes"]["detect_slack_s"])
            for w in cfg["sweeps"]["aggregation_window_s"]:
                incs, _ = run_policy(A_, w, cfg["policy"]["cooldown_s"], pol.severity_fn)
                incd = [i.as_dict() for i in incs]
                oc = incident_outcomes(incd, eps, cfg["episodes"]["detect_slack_s"], names, cfg["policy"]["rate_guard_class"])
                ttd = [x[1] for x in dd if x[1] is not None]
                sw[f"{thr}|{w}"] = {"incidents": len(incd), "false_incidents": oc.count("false"),
                                    "false_incidents_per_h": oc.count("false") / hours["all"],
                                    "detection_rate": float(np.mean([x[0] for x in dd])) if dd else float("nan"),
                                    "median_ttd_s": float(np.median(ttd)) if ttd else float("nan"),
                                    "alert_fa": int(((gt["y"][R0["gi"]] == 0) & al).sum())}
        dflt = f"{cfg['policy']['confidence_threshold']}|{cfg['policy']['aggregation_window_s']}"
        n_rt = sum(1 for i in R0["incidents"] if i["class"] != cfg["policy"]["rate_guard_class"])
        run.check(M, "sweep default cell reproduces the runtime's flow incidents (pure policy == runtime policy)",
                  sw[dflt]["incidents"] == n_rt, f"{sw[dflt]['incidents']} vs {n_rt}")
        M["sweeps"] = sw
        M["episodes"] = eps
        M["per_run"] = {t: {k: v for k, v in p.items() if k != "detection"} for t, p in per.items()}
        import pandas as pd
        rows = []
        for k, e in enumerate(eps):
            d0 = per[f"{modes[0]}_s0"]["detection"][k]
            rows.append({**e, "class_name": names[e["class"]], "device_name": router.device_name(e["device"]),
                         "duration_s": e["end"] - e["start"], **{f"{modes[0]}_s0_{kk}": v for kk, v in d0.items()
                                                                if kk != "episode_id"}})
        pd.DataFrame(rows).to_csv(run.res / "episodes.csv", index=False)
        figs = [fig_timeline(run.fig / "replay_timeline.png", eps, runs, gt, names, router, rgA[modes[0]]),
                fig_ttd(run.fig / "ttd_ecdf.png", eps, per[f"{modes[0]}_s0"]["detection"], names),
                fig_fa(run.fig / "false_alarms_per_group.png", agg, groups) if len(modes) == 2 else None,
                fig_detect(run.fig / "detection_rate.png", agg[modes[0]]["detection_rate"], names, classes),
                fig_sweeps(run.fig / "sweeps.png", sw, cfg["sweeps"]["confidence_threshold"],
                           cfg["sweeps"]["aggregation_window_s"])]
        M["figures"] = [str(Path(f).relative_to(run.res)) for f in figs if f]
        R3.write_json(run.res / "metrics.json", {k: M[k] for k in ("hours", "aggregate", "rate_guard", "sweeps", "per_run",
                                                                  "episodes", "run28")})
        R3.lock_banner(run, M, "end")
        ok = all(c["pass"] for c in M["checks"] if c["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def _f(a, d=3):
    return f"{a['mean']:.{d}f} [{a['lo']:.{d}f}, {a['hi']:.{d}f}]" if np.isfinite(a.get("lo", np.nan)) else f"{a['mean']:.{d}f}"


def _g(a, d=3):
    return f"{a['rate']:.{d}f} [{a['lo']:.{d}f}, {a['hi']:.{d}f}] ({a['count']} / {a['hours']:.3f} h)"


def _s(x, d=1):
    return "-" if x is None or not np.isfinite(x) else f"{x:.{d}f}"


def write_summary(run, M: dict, dry: bool) -> None:
    st = "PASS" if not M.get("error") and all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") else "FAIL"
    L = [f"# Step 29 -- incident-level evaluation of the streaming runtime (val) -- {st}" + (" (DRY RUN)" if dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    A = M.get("aggregate")
    if A:
        h = M["hours"]
        eps = M["episodes"]
        L += [f"- step 28 run `{M['run28']['run_id']}` (parity gate {M['run28']['parity_gate']}); benign val hours "
              f"{h['all']:.3f} (" + ", ".join(f"{g} {v:.3f}" for g, v in h.items() if g != "all") + ")",
              f"- {len(eps)} ground-truth episodes (gap 60 s, detection window end + 120 s); CIs: 5 seeds (t) for the flow "
              "path, bootstrap over episodes for the rate guard and time-to-detect, Garwood for seed-0 counts", ""]
        for mode, a in A.items():
            L += [f"## {mode}", "", "| class | path | detection rate | median TTD s [boot CI] | p95 TTD s [boot CI] | "
                  "detected (seed 0) |", "|---|---|---|---|---|---|"]
            for cname, dd in a["detection_rate"].items():
                for p, d in dd.items():
                    t = a["ttd"][cname][p]
                    L.append(f"| {cname} | {p} | {_f(d)} (n={d['n']}) | {_s(t['median'])} [{_s(t['median_ci'][0])}, "
                             f"{_s(t['median_ci'][1])}] | {_s(t['p95'])} [{_s(t['p95_ci'][0])}, {_s(t['p95_ci'][1])}] | "
                             f"{t['n_detected']} |")
            s0 = a["seed0"]
            L += ["", "| measure (per benign val hour) | all | " + " | ".join(g for g in h if g != "all") + " |",
                  "|---|---|" + "---|" * (len(h) - 1)]
            for met, lab in (("flow_fa_per_h", "flow-level false alarms / h (5 seeds)"),
                             ("alert_fa_per_h", "alert-level false alarms / h (5 seeds)"),
                             ("false_incidents_per_h", "false incidents / h, flow path (5 seeds)")):
                L.append(f"| {lab} | " + " | ".join(_f(a[met][g]) for g in h) + " |")
            L += ["", f"- seed 0: flow-level FA {_g(s0['flow_fa'])}; false incidents {_g(s0['false_incidents'])}; "
                  f"misclassified incidents {_g(s0['misclassified_incidents'])}; false incidents incl. rate guard "
                  f"{_g(s0['false_incidents_total_incl_rate_guard'])}; flow incidents {s0['flow_incidents']}; "
                  f"attack-argmax flows below the 0.5 threshold: {s0['below_threshold_attack_argmax']}",
                  f"- misclassified incidents / h (5 seeds): {_f(a['misclassified_incidents_per_h']['all'])}; "
                  f"incidents per run: {_f(a['incidents'], 1)}", ""]
        r = M["rate_guard"]
        L += ["## Rate guard (packet path, model-independent)", "",
              f"- alerts {r['alerts']:,} (v2 {r['alerts_v2']:,}, V1 rule {r['alerts_v1']:,}); on no episode of their device: "
              f"{r['alerts_on_no_episode']:,} ({r['alerts_on_no_episode_by_rule']}) -> benign alerts / h "
              f"{_g(r['benign_alerts_per_h'])}", f"- incidents {r['incidents']}, false {r['false_incidents']} -> "
              f"{_g(r['false_incidents_per_h'])}; by group {r['false_incidents_by_group']}", ""]
        L += ["## Report-only sweeps (GLOBAL s0, flow path)", "", "| threshold | window s | incidents | false incidents / h | "
              "detection rate | median TTD s | alert-level FA |", "|---|---|---|---|---|---|---|"]
        for k, v in M["sweeps"].items():
            t, w = k.split("|")
            L.append(f"| {t} | {w} | {v['incidents']} | {v['false_incidents_per_h']:.3f} | {v['detection_rate']:.3f} | "
                     f"{_s(v['median_ttd_s'])} | {v['alert_fa']} |")
        L += ["", "## Figures", ""] + [f"- `{f}`" for f in M.get("figures", [])]
    L += ["", "## Checks", ""] + [f"- {'PASS' if c['pass'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
