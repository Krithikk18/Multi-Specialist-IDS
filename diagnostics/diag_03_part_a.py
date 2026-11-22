#!/usr/bin/env python
"""diagnostics/diag_03_part_a.py -- READ-ONLY diag_03 part A: the rate-guard alerts that overlap no episode.

A0  the rule (fixed before any number; written verbatim at the top of A_summary.md before anything is computed)
A1  per-alert evidence (A_alerts.csv): triggering windows, packet share by source host, nearest episodes, the three
    checks, the verdict; the alerts compared across every GLOBAL / ROUTED run
A2  episode-start what-if (REPORT-ONLY): per episode, the first attacker packet into its device in the 60 s before
    its labelled start; every prereg incident metric recomputed with that start (both paths), side by side with the
    prereg numbers, through step 29's own functions
A3  amendment_3_proposal_DRAFT.md if >= 1 alert is PRECURSOR, else A3_prereg_definition_stands.md
Figures: figures/A_alert_panels.png, figures/A_episode_start_shift.png.

Inputs: the step 28 rerun_full runs (20261122T050150Z), step 29 rerun_fig_fix metrics, v2_1_oriented val flows, and
the VAL packets of the captures holding an episode (common/packet_source: test sessions refused, reading stops at the
first packet of a later split). Changes nothing; every output is a new file under --out (default results/diag_03).
"""

from __future__ import annotations

import argparse
import copy
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diagnostics import diag_03_common as K  # noqa: E402
from common import packet_source as PK  # noqa: E402
from common import plot_style as PS  # noqa: E402

RULE_A0 = """### A0. Rule, fixed before any numbers. Write it verbatim at the top of results/diag_03/A_summary.md before computing anything.
For each rate-guard alert that overlaps no episode under the prereg rule:
- **Source check:** at least 90% of the packets INTO the protected device during the alert's triggering windows (the 3+ consecutive
  1 s windows above threshold) come from the attacker host.
- **Timing check:** there is an episode on the SAME protected device whose labelled start is at most 10 s after the alert's decision
  time (−10 s ≤ alert time − episode start < 0).
- **Protocol check:** the alert's protocol family equals the majority protocol family of that episode's labelled flows. This is
  computed from the data, with no hard-coded class→protocol map.
Verdict per alert: **PRECURSOR** iff all three checks hold; otherwise **FALSE_ALARM**, recording which checks failed.
Headline: rate-guard benign alerts/h = (FALSE_ALARM count) / 1.953 h. The prereg figure (3.07/h) stays the primary number, and both
numbers are always reported side by side.
"""

SOURCE_MIN, TIMING_S, LOOKBACK_S, PANEL_S = 0.90, 10.0, 60.0, 60.0
CAT_COLOR = {"attacker": PS.CATEGORICAL[7], "testbed": PS.CATEGORICAL[3], "other_device": PS.NEUTRAL_LIGHT,
             "unknown": PS.BENIGN_GRAY}
CAT_LABEL = {"attacker": "attacker host (ATTACKER_MACS.exact)", "testbed": "other testbed Pi (D74 identity)",
             "other_device": "other inventory device", "unknown": "unlisted MAC"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(K.REPO / "results" / "diag_03"))
    args = ap.parse_args()
    out = K.Out(Path(args.out))
    summ = out.write_text("A_summary.md", "# diag_03 part A -- rate-guard alerts on no episode (READ-ONLY, val)\n\n"
                          + RULE_A0 + "\n---\n\n")
    logs: list[str] = []

    def log(m: str) -> None:
        print(m, flush=True)
        logs.append(m)

    checks: list = []

    def check(name: str, ok: bool, detail: str = "", hard: bool = True) -> None:
        checks.append({"check": name, "pass": bool(ok), "level": "hard" if hard else "warn", "detail": detail})
        log(f"  {'PASS' if ok else ('FAIL' if hard else 'WARN')}  {name}  {detail}")
        if hard and not ok:
            raise RuntimeError(f"hard check failed: {name}: {detail}")

    lock0 = K.lock("start", log)
    ctx = K.load_context(log, need_flows=True)
    cfg, E, gt, eps, runs, names, hours = (ctx[k] for k in ("cfg", "E", "gt", "eps", "runs", "names", "hours"))
    F, hosts, m29 = ctx["flows"], ctx["hosts"], ctx["m29"]
    H = hours["all"]
    slack, rgc = cfg["episodes"]["detect_slack_s"], cfg["policy"]["rate_guard_class"]
    fam = K.family_of(cfg)

    # ------------------------------------------------------------------ A1: alerts per run
    rg_full = {}
    for tag, R in runs.items():
        rg_full[tag], _ = K.parse_alerts(R["dir"] / "alerts.jsonl")
    sig = lambda a: (a["decision_time"], a["device"], a["family"], a["rule"], a.get("count"), a.get("threshold"),  # noqa: E731
                     a.get("streak"), a.get("window_start"))
    s0 =[t for t in runs if t.endswith("_s0")]
    ref = sorted(map(sig, rg_full["GLOBAL_s0"]))
    for t in s0:
        check(f"{t}: rate-guard alerts identical to GLOBAL_s0", sorted(map(sig, rg_full[t])) == ref,
              f"{len(rg_full[t])} alerts")
    by_dev = defaultdict(list)
    for e in eps:
        by_dev[e["device"]].append(e)
    on_no_ep = lambda a: not any(e["start"] <= a["decision_time"] <= e["end"] + slack for e in by_dev.get(a["device"], []))  # noqa: E731
    off = sorted([a for a in rg_full["GLOBAL_s0"] if on_no_ep(a)], key=lambda a: (a["decision_time"], a["device"]))
    check("off-episode alerts (prereg rule, step 29's window [start, end + 120 s]) == step 29's count",
          len(off) == m29["rate_guard"]["alerts_on_no_episode"], f"{len(off)} vs {m29['rate_guard']['alerts_on_no_episode']}")
    off_by_run = {}
    for t in runs:
        o = sorted(map(sig, [a for a in rg_full[t] if on_no_ep(a)]))
        off_by_run[t] = {"rg_alerts": len(rg_full[t]), "off_episode_alerts": len(o), "same_6_as_GLOBAL_s0":
                         o == sorted(map(sig, off)), "packet_path_ran": runs[t]["counts"].get("packets", 0) > 0}
    for i, a in enumerate(off):
        a["alert_id"] = f"rgA{i + 1}"

    # nearest episodes (same device, any device), timing candidate
    def nearest(t, cand):
        if not cand:
            return None
        return min(cand, key=lambda e: (K.interval_distance(t, e["start"], e["end"] + slack), abs(t - e["start"])))

    for a in off:
        t = a["decision_time"]
        a["_near_same"] = nearest(t, by_dev.get(a["device"], []))
        a["_near_any"] = nearest(t, eps)
        tc = [e for e in by_dev.get(a["device"], []) if -TIMING_S <= t - e["start"] < 0]
        a["_timing_ep"] = min(tc, key=lambda e: e["start"] - t) if tc else None

    # ------------------------------------------------------------------ packets (VAL only)
    sessions = sorted({e["session"] for e in eps} | {a["_near_same"]["session"] for a in off if a["_near_same"]})
    watch = defaultdict(list)                      # dst mac -> [lo, hi) bin windows (alert panels)
    for a in off:
        t = a["decision_time"]
        watch[a["device"]].append((math.floor(t - PANEL_S - a["streak"] - 1), math.ceil(t + PANEL_S + 1)))
    bins = Counter()                               # (dev, sec, family, src cat) -> packets
    first_att, n_att, plans, pk_counts = {}, Counter(), {}, {}
    for s in sessions:
        plan = PK.session_plan(cfg, s, "val")
        plans[s] = {"pcap": str(plan["pcap"]), "mode": plan["mode"], "val_start": plan["start"], "stop": plan["stop"]}
        look = defaultdict(list)
        for e in eps:
            if e["session"] == s:
                look[e["device"]].append((e["start"] - LOOKBACK_S, e["start"], e["episode_id"]))
        cnt = Counter()
        log(f"reading VAL packets of {s} (val start {plan['start']}, stop {plan['stop']}) ...")
        for ts, _sip, _dip, proto, smac, dmac in PK.session_packets(cfg, s, "val", cnt):
            w = watch.get(dmac)
            if w:
                for lo, hi in w:
                    if lo <= ts < hi:
                        bins[(dmac, math.floor(ts), fam(proto), hosts.cat(smac))] += 1
                        break
            lk = look.get(dmac)
            if lk and hosts.is_attacker(smac):
                for lo, hi, eid in lk:
                    if lo <= ts < hi:
                        n_att[eid] += 1
                        if eid not in first_att or ts < first_att[eid]:
                            first_att[eid] = ts
        pk_counts[s] = dict(cnt)
        log(f"  {s}: {dict(cnt)}")
    check("no packet of a test window read (every scanned session's reader stopped at / before its cut or ended)",
          all(p["mode"] not in ("test", "test_only") for p in plans.values()), str({s: p["mode"] for s, p in plans.items()}))

    # ------------------------------------------------------------------ A1: evidence + verdicts
    rows, panels = [], []
    for a in off:
        t, st, thr, dev, af = a["decision_time"], int(a["streak"]), int(a["threshold"]), a["device"], a["family"]
        wins = [int(round(t - st + k)) for k in range(st)]                 # triggering window starts
        per_win = [sum(bins[(dev, w, af, c)] for c in K.SRC_CATS) for w in wins]
        check(f"{a['alert_id']}: recounted packets of its last window == the runtime's count",
              per_win[-1] == a["count"], f"{per_win[-1]} vs {a['count']}", hard=False)
        share = {c: sum(bins[(dev, w, af, c)] for w in wins) for c in K.SRC_CATS}
        tot = sum(share.values())
        share_all = {c: sum(bins[(dev, w, f, c)] for w in wins for f in ("TCP", "UDP", "other")) for c in K.SRC_CATS}
        tot_all = sum(share_all.values())
        att = (share["attacker"] + share["testbed"]) / tot if tot else float("nan")
        att_all = (share_all["attacker"] + share_all["testbed"]) / tot_all if tot_all else float("nan")
        src_ok = bool(tot) and att >= SOURCE_MIN
        te = a["_timing_ep"]
        tim_ok = te is not None
        pe = te if te is not None else a["_near_same"]               # episode for the protocol check
        maj, famshare = None, {}
        if pe is not None:
            m = K.episode_flow_mask(gt, pe)
            fc = Counter(fam(p) for p in F["Protocol"].to_numpy()[m])
            famshare = {k: v / sum(fc.values()) for k, v in fc.items()}
            maj = fc.most_common(1)[0][0] if fc else None
            if m.sum() != pe["n_flows"]:
                check(f"{a['alert_id']}: episode flow mask == step 29 n_flows", False, f"{m.sum()} vs {pe['n_flows']}")
        pro_ok = maj is not None and af == maj
        failed = [n for n, ok in (("source", src_ok), ("timing", tim_ok), ("protocol", pro_ok)) if not ok]
        verdict = "PRECURSOR" if not failed else "FALSE_ALARM"
        ns, na = a["_near_same"], a["_near_any"]
        rows.append({
            "alert_id": a["alert_id"], "decision_time": t, "window_start": a["window_start"], "device": dev,
            "device_name": a.get("device_name"), "group": a["group"], "family": af, "rule": a["rule"],
            "threshold": thr, "streak_at_alert": st, "n_windows_above_threshold": sum(c > thr for c in per_win),
            "triggering_windows": "; ".join(f"[{w},{w + 1}) {c} pkts {'>' if c > thr else '<='} {thr}"
                                           for w, c in zip(wins, per_win)),
            "trigger_packets_family": tot, **{f"share_{c}": (share[c] / tot if tot else None) for c in K.SRC_CATS},
            "share_attacker_identity_D74": att, "share_attacker_identity_all_families": att_all,
            "share_attacker_exact_only": share["attacker"] / tot if tot else None,
            "near_same_episode": ns and ns["episode_id"], "near_same_class": ns and names[ns["class"]],
            "near_same_labelled_start": ns and ns["start"], "near_same_gap_s": ns and t - ns["start"],
            "near_any_episode": na and na["episode_id"], "near_any_device": na and na["device"],
            "near_any_class": na and names[na["class"]], "near_any_labelled_start": na and na["start"],
            "near_any_gap_s": na and t - na["start"],
            "timing_episode": te["episode_id"] if te else "", "timing_gap_s": (t - te["start"]) if te else None,
            "protocol_check_episode": pe and pe["episode_id"],
            "episode_majority_family": maj, "episode_family_shares": str({k: round(v, 4) for k, v in famshare.items()}),
            "source_check": src_ok, "timing_check": tim_ok, "protocol_check": pro_ok,
            "failed_checks": ",".join(failed), "verdict": verdict})
        panels.append({"a": a, "wins": wins, "ep": pe,
                       "val_start": plans[ns["session"]]["val_start"] if ns is not None else None})
    import pandas as pd
    A = pd.DataFrame(rows)
    A.to_csv(out.path("A_alerts.csv"), index=False)
    n_fa = int((A["verdict"] == "FALSE_ALARM").sum()) if len(A) else 0
    n_pre = int((A["verdict"] == "PRECURSOR").sum()) if len(A) else 0
    lo_hi = E.garwood_rate(n_fa, H, cfg["eval"]["ci_level"])
    log(f"verdicts: PRECURSOR {n_pre}, FALSE_ALARM {n_fa} -> {n_fa / H:.3f} / h (prereg {len(off) / H:.3f} / h)")

    # ------------------------------------------------------------------ A2: episode-start what-if
    shift_rows, eps2 = [], []
    for e in eps:
        s = e["session"]
        vs = plans[s]["val_start"]
        lo = e["start"] - LOOKBACK_S
        f = first_att.get(e["episode_id"])
        new = f if f is not None else e["start"]
        shift_rows.append({"episode_id": e["episode_id"], "class": names[e["class"]], "device": e["device"],
                           "session": s, "labelled_start": e["start"], "attacker_first_packet": f,
                           "attacker_packets_in_lookback": n_att.get(e["episode_id"], 0),
                           "shift_s": e["start"] - new, "found": f is not None,
                           "at_lookback_edge": f is not None and f - lo < 1.0,
                           "lookback_clipped_by_val_start": vs is not None and lo < vs})
        eps2.append({**copy.deepcopy(e), "start": float(new)})
    # mechanism context for shifted episodes (report-only): where the session's val flows and the device's flows start
    for r in shift_rows:
        ms = gt["session"] == r["session"]
        md = ms & (gt["dev"] == r["device"])
        r["session_val_window_start"] = plans[r["session"]]["val_start"]
        r["session_first_val_flow_start"] = float(gt["start"][ms].min())
        r["device_first_val_flow_start"] = float(gt["start"][md].min())
        r["device_val_flows_before_labelled_start"] = int((md & (gt["start"] < r["labelled_start"])).sum())
    S_ = pd.DataFrame(shift_rows)
    S_.to_csv(out.path("A_episode_start_shift.csv"), index=False)

    def evaluate(eps_x: list) -> dict:
        modes = sorted({t.split("_s")[0] for t in runs})
        rgA = {m: runs[f"{m}_s0"]["rg"] for m in modes}
        per = {t: E.run_metrics(R, gt, eps_x, rgA[t.split("_s")[0]], cfg, names, hours) for t, R in runs.items()}
        rgm = E.rg_metrics(rgA[modes[0]], runs[f"{modes[0]}_s0"]["incidents"], eps_x, cfg, names, hours, {})
        res = {"rate_guard": {"alerts_on_no_episode": rgm["alerts_on_no_episode"],
                              "alerts_on_no_episode_per_h": rgm["alerts_on_no_episode"] / H,
                              "incidents": rgm["incidents"], "false_incidents": rgm["false_incidents"],
                              "false_incidents_per_h": rgm["false_incidents"] / H}, "modes": {}, "per_run": {}}
        for t, p in per.items():
            res["per_run"][t] = p["flow_incidents"]
        for m in modes:
            tags = sorted(t for t in runs if t.startswith(m + "_"))
            r = {"false_incidents_per_h": E.ci_seeds([per[t]["flow_incidents"]["false"] / H for t in tags], 0.95),
                 "misclassified_incidents_per_h": E.ci_seeds([per[t]["flow_incidents"]["misclassified"] / H for t in tags], 0.95),
                 "seed0_false": per[f"{m}_s0"]["flow_incidents"]["false"],
                 "seed0_misclassified": per[f"{m}_s0"]["flow_incidents"]["misclassified"], "classes": {}}
            for c in sorted({e["class"] for e in eps_x}):
                ix = [k for k, e in enumerate(eps_x) if e["class"] == c]
                cc = {}
                for p, key in (("flow", "ttd_flow"), ("rate_guard", "ttd_rate_guard"), ("either", "ttd_either"),
                               ("flow_own", "ttd_flow_own")):
                    d0 = per[f"{m}_s0"]["detection"]
                    v = np.array([d0[k][key] for k in ix if d0[k][key] is not None], float)
                    rate_s0 = float(np.mean([bool(d0[k][p]) for k in ix]))
                    rate_seeds = [float(np.mean([bool(per[t]["detection"][k][p]) for k in ix])) for t in tags]
                    cc[p] = {"n": len(ix), "detected_s0": int(len(v)), "detection_rate_s0": rate_s0,
                             "detection_rate_mean_seeds": float(np.mean(rate_seeds)) if p != "rate_guard" else rate_s0,
                             "median_ttd_s0": float(np.median(v)) if len(v) else None,
                             "p95_ttd_s0": float(np.quantile(v, 0.95)) if len(v) else None}
                r["classes"][names[c]] = cc
            res["modes"][m] = r
        return res

    base, what = evaluate(eps), evaluate(eps2)
    for t, v in base["per_run"].items():
        check(f"prereg reproduction {t}: flow incidents == step 29", v == m29["per_run"][t]["flow_incidents"], str(v))
    check("prereg reproduction: rate-guard off-episode alerts and false incidents == step 29",
          base["rate_guard"]["alerts_on_no_episode"] == m29["rate_guard"]["alerts_on_no_episode"]
          and base["rate_guard"]["false_incidents"] == m29["rate_guard"]["false_incidents"], str(base["rate_guard"]))
    for c, d in m29["aggregate"]["GLOBAL"]["ttd"].items():
        for p in ("flow", "rate_guard", "either"):
            a_, b_ = base["modes"]["GLOBAL"]["classes"][c][p]["median_ttd_s0"], d[p]["median"]
            same = (a_ is None and not np.isfinite(b_ if b_ is not None else np.nan)) or (a_ is not None and abs(a_ - b_) < 1e-9)
            check(f"prereg reproduction: GLOBAL s0 median TTD {c} / {p} == step 29", same, f"{a_} vs {b_}")
    out.write_json("A_whatif.json", {"note": "what-if, not pre-registered: episodes start at the attacker-first-packet "
                                             "start; every other prereg rule unchanged; both paths",
                                     "prereg": base, "what_if": what})

    # ------------------------------------------------------------------ figures
    fig_panels(out.fig / "A_alert_panels.png", panels, bins, names)
    fig_shift(out.fig / "A_episode_start_shift.png", S_, names)

    # ------------------------------------------------------------------ A3
    if n_pre:
        a3 = out.write_text("amendment_3_proposal_DRAFT.md", amendment_text(A, S_, base, what, H, len(off), n_fa))
    else:
        a3 = out.write_text("A3_prereg_definition_stands.md", stands_text(A, S_, base, what, H, len(off)))

    lock1 = K.lock("end", log)
    check("config.py / class_map.json sha256 unchanged start -> end", lock0 == lock1, str(lock1))
    out.write_json("A_run.json", {"script": "diagnostics/diag_03_part_a.py", "run28": K.RUN28_ID, "run28_tag": K.RUN28_TAG,
                                  "run29_tag": K.RUN29_TAG, "hours": H, "lock": {"start": lock0, "end": lock1},
                                  "val_sha256": ctx["val_sha256"], "hosts": hosts.describe(), "sessions_read": plans,
                                  "packet_reader_counts": pk_counts, "rate_guard_per_run": off_by_run,
                                  "checks": checks, "log": logs})
    with open(summ, "a", encoding="utf-8") as fh:
        fh.write(summary_text(A, S_, base, what, H, off, off_by_run, n_fa, n_pre, lo_hi, a3, checks, hosts, lock0, lock1))
    print(f"wrote {len(out.written)} files under {out.root}")
    return 0


# ---------------------------------------------------------------------- text
def _r(x, d=3):
    return "-" if x is None or (isinstance(x, float) and not np.isfinite(x)) else f"{x:.{d}f}"


def _ci(a, d=3):
    return f"{a['mean']:.{d}f} [{a['lo']:.{d}f}, {a['hi']:.{d}f}]" if np.isfinite(a.get("lo", np.nan)) else f"{a['mean']:.{d}f}"


def whatif_table(base, what, H) -> list[str]:
    L = ["| measure (val, per benign hour = 1.953 h) | prereg (as reported) | what-if, not pre-registered |", "|---|---|---|",
         f"| rate guard: alerts on no episode / h | {base['rate_guard']['alerts_on_no_episode_per_h']:.3f} "
         f"({base['rate_guard']['alerts_on_no_episode']}) | {what['rate_guard']['alerts_on_no_episode_per_h']:.3f} "
         f"({what['rate_guard']['alerts_on_no_episode']}) |",
         f"| rate guard: false incidents / h | {base['rate_guard']['false_incidents_per_h']:.3f} "
         f"({base['rate_guard']['false_incidents']}) | {what['rate_guard']['false_incidents_per_h']:.3f} "
         f"({what['rate_guard']['false_incidents']}) |"]
    for m in base["modes"]:
        b, w = base["modes"][m], what["modes"][m]
        L += [f"| {m} flow path: false incidents / h (5 seeds) | {_ci(b['false_incidents_per_h'])} | "
              f"{_ci(w['false_incidents_per_h'])} |",
              f"| {m} flow path: misclassified incidents / h (5 seeds) | {_ci(b['misclassified_incidents_per_h'])} | "
              f"{_ci(w['misclassified_incidents_per_h'])} |",
              f"| {m} seed 0: false / misclassified incidents (counts) | {b['seed0_false']} / {b['seed0_misclassified']} | "
              f"{w['seed0_false']} / {w['seed0_misclassified']} |"]
    L += ["", "Time to detect (seed 0; s) and detection rate, per class x path. Cell = median / p95 (detected / episodes); "
          "prereg -> what-if.", "",
          "| mode | class | path | prereg median / p95 (det.) | what-if median / p95 (det.) |", "|---|---|---|---|---|"]
    for m in base["modes"]:
        for c, cc in base["modes"][m]["classes"].items():
            for p in ("flow", "rate_guard", "either", "flow_own"):
                b, w = cc[p], what["modes"][m]["classes"][c][p]
                L.append(f"| {m} | {c} | {p} | {_r(b['median_ttd_s0'], 1)} / {_r(b['p95_ttd_s0'], 1)} ({b['detected_s0']}/{b['n']}) | "
                         f"{_r(w['median_ttd_s0'], 1)} / {_r(w['p95_ttd_s0'], 1)} ({w['detected_s0']}/{w['n']}) |")
    return L


def shift_table(S_) -> list[str]:
    L = ["| episode | class | device | labelled start | attacker-first-packet | shift s | attacker pkts in lookback | notes |",
         "|---|---|---|---|---|---|---|---|"]
    for r in S_.itertuples():
        note = []
        if not r.found:
            note.append("no attacker packet in the 60 s lookback (start unchanged)")
        if r.at_lookback_edge:
            note.append("first packet at the lookback edge: shift capped at 60 s")
        if r.lookback_clipped_by_val_start:
            note.append("lookback clipped by the val window start")
        L.append(f"| {r.episode_id} | {r._2} | {r.device} | {r.labelled_start:.0f} | "
                 f"{'-' if not r.found else f'{r.attacker_first_packet:.3f}'} | {r.shift_s:.3f} | "
                 f"{r.attacker_packets_in_lookback:,} | {'; '.join(note)} |")
    return L


def summary_text(A, S_, base, what, H, off, off_by_run, n_fa, n_pre, g, a3, checks, hosts, lock0, lock1) -> str:
    L = ["## Results (computed after the rule above was written)", "",
         f"Inputs: step 28 run `{K.RUN28_ID}` ({K.RUN28_TAG}), step 29 `{K.RUN29_TAG}`; benign val hours {H:.4f}. "
         f"Attacker host = V1 step 13 / D74 identity ({hosts.describe()['rule']}). Rate guard alerts on no episode "
         f"(prereg rule): **{len(off)}**.", "",
         "### A1. Per-alert verdicts (`A_alerts.csv`)", "",
         "| alert | decision time | device | family | triggering windows (pkts vs threshold) | attacker-identity share | "
         "timing episode (alert - start) | episode majority family | failed | verdict |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in A.itertuples():
        gap = f"{r.timing_episode} ({r.timing_gap_s:+.1f} s)" if r.timing_episode else \
            f"none (nearest same-device {r.near_same_episode}: {r.near_same_gap_s:+.1f} s)"
        L.append(f"| {r.alert_id} | {r.decision_time:.0f} | {r.device_name} `{r.device}` ({r.group}) | {r.family} | "
                 f"{r.triggering_windows} | {r.share_attacker_identity_D74:.4f} | {gap} | {r.episode_majority_family} | "
                 f"{r.failed_checks or '-'} | **{r.verdict}** |")
    L += ["", f"- PRECURSOR **{n_pre}**, FALSE_ALARM **{n_fa}**.",
          f"- **Rate-guard benign alerts / h: prereg (primary) {len(off) / H:.3f} ({len(off)} / {H:.3f} h)  |  "
          f"FALSE_ALARM only {g['rate']:.3f} [{g['lo']:.3f}, {g['hi']:.3f}] ({n_fa} / {H:.3f} h, Garwood 95 %)**.",
          "- Packet share by source host in the triggering windows (alert family): "
          + "; ".join(f"{r.alert_id}: attacker {r.share_attacker:.3f}, testbed {r.share_testbed:.3f}, other device "
                      f"{r.share_other_device:.3f}, unknown {r.share_unknown:.3f}" for r in A.itertuples()), "",
          "Across runs (D77: seeds 1-4 ran without the packet path, so they carry no rate-guard alerts by design):", "",
          "| run | packet path ran | rate-guard alerts | on no episode | same 6 as GLOBAL_s0 |", "|---|---|---|---|---|"]
    for t, v in sorted(off_by_run.items()):
        L.append(f"| {t} | {v['packet_path_ran']} | {v['rg_alerts']} | {v['off_episode_alerts']} | {v['same_6_as_GLOBAL_s0']} |")
    L += ["", "### A2. Episode-start what-if (REPORT-ONLY; replaces nothing)", "",
          "Attacker-first-packet start = the first packet from the attacker identity into the episode's device in "
          "[labelled start - 60 s, labelled start); shift = labelled start - that time (`A_episode_start_shift.csv`).", ""]
    L += shift_table(S_)
    L += ["", "#### what-if, not pre-registered", ""] + whatif_table(base, what, H)
    L += ["", f"### A3. `{Path(a3).name}` written.", "",
          "### Figures", "", "- `figures/A_alert_panels.png` -- one panel per alert, packet rate into the device "
          "(1 s bins, stacked by source host), threshold, triggering windows, labelled episode start",
          "- `figures/A_episode_start_shift.png` -- per-episode start shift by class", "",
          "### Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                               f"{c['detail']}" for c in checks]
    L += ["", f"verify_v2_lock OK at start and end; config/config.py {lock1['config/config.py']}, "
              f"config/class_map.json {lock1['config/class_map.json']} (unchanged: {lock0 == lock1}).", ""]
    return "\n".join(L)


def amendment_text(A, S_, base, what, H, n_off, n_fa) -> str:
    L = ["# DRAFT -- proposed Phase 3 Amendment 3: episode start = attacker-first-packet start", "",
         "**Status: DRAFT ONLY. Not pinned, not referenced by any code, not adopted.** Proposed by diag_03 **after the "
         "Phase 3 results were seen** (the 6 rate-guard alerts on no episode, `docs/V2_DECISIONS.md` D87). Any adoption "
         "would have to be pinned before it is applied to a split it has not yet been evaluated on (test); on val it can "
         "only ever be a post-hoc re-description.", "",
         "## Proposed change (applies to BOTH paths: flow model and rate guard)", "",
         "Prereg section 3 (ground-truth episodes): episodes are still grouped as now (attack flows per (class, protected "
         "device), new episode after a > 60 s gap; episode end = latest end). The **episode start** becomes the earlier "
         "of (a) the first labelled flow's start and (b) the first packet from the attacker / testbed identity (V1 "
         "step 13's rule, evaluation-only ground truth) into the episode's device within the 60 s before (a). "
         "Every other rule (detection window end + 120 s, incident outcome, time-to-detect = first alert - episode "
         "start, hours) is unchanged.", "",
         "## Why (diag_03 part A)", "",
         f"- {n_off - n_fa} of {n_off} rate-guard alerts on no episode pass all three pre-fixed checks (source >= 90 % "
         "attacker identity, alert within 10 s before a same-device episode's labelled start, family == the episode's "
         f"majority family); {n_fa} fail at least one.",
         f"- Val episodes with any attacker packet into their device in the 60 s before the labelled start: "
         f"{int((S_['shift_s'] > 0).sum())} of {len(S_)}; the change moves only: "
         + "; ".join(f"{r.episode_id} ({r._2}, shift {r.shift_s:.1f} s"
                     + (", lookback clipped by the val window start" if r.lookback_clipped_by_val_start else "") + ")"
                     for r in S_.itertuples() if r.shift_s > 0) + ".",
         "- Mechanism seen in the data (report-only): "
         + "; ".join(f"{r.episode_id}: the capture's val window opens at {r.session_val_window_start:.1f}, the "
                     f"capture's first val flow starts at {r.session_first_val_flow_start:.0f}, the device's first "
                     f"val flow at {r.device_first_val_flow_start:.0f}, its first attacker packet in val at "
                     f"{r.attacker_first_packet:.1f}" for r in S_.itertuples() if r.shift_s > 0)
         + ". Packets are split by packet time and flows by flow start time (08's rule), so packets of flows that "
         "started in gap@train|val still reach the device inside the val window, while those flows are not val "
         "flows. The labelled episode then starts at the first flow that STARTED in val. This explanation is "
         "inferred: diag_03 did not read gap-window flows.", "",
         "## Alternatives (not evaluated here)", "",
         "- Leave the episode start as pre-registered and report the boundary alerts as 'attack packets of flows "
         "outside the val split' (sender-based, as D87 / V1 13c do).",
         "- Make the packet path and the flow path use the same cut: e.g. drop val packets of 5-tuples whose flow "
         "started before the val cut. This changes the data the runtime sees, so it would need its own pre-registration.",
         "", "## Effect on every Phase 3 headline number (val; from diag_03 A2)", ""]
    L += whatif_table(base, what, H)
    L += ["", "Per-episode start shift:", ""] + shift_table(S_)
    L += ["", "## Risks / reasons against", "",
          "- It is chosen after seeing the result it removes, so on val it cannot count as a pre-registered result; the "
          "prereg numbers stay primary and both are reported.",
          "- An earlier start lengthens every time-to-detect that is measured from it (see the table), so it is not a "
          "free improvement.",
          "- The attacker identity is evaluation-only ground truth; the runtime never knows it, so the change affects "
          "only how episodes are scored, never what the runtime does.", ""]
    return "\n".join(L)


def stands_text(A, S_, base, what, H, n_off) -> str:
    L = ["# diag_03 A3 -- why the prereg episode-start definition stands", "",
         f"All {n_off} rate-guard alerts on no episode are FALSE_ALARM under the rule fixed before the numbers "
         "(A_summary.md, A0). Failed checks per alert:", ""]
    L += [f"- {r.alert_id}: {r.failed_checks}" for r in A.itertuples()]
    L += ["", "No amendment is proposed: the alerts are not explained as precursors of a labelled episode by the pre-fixed "
          "rule, so changing the episode start would only move numbers without a pre-fixed justification. The what-if "
          "below (report-only) shows what such a change would have done.", ""] + whatif_table(base, what, H)
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------- figures
def fig_panels(path, panels, bins, names):
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    PS.apply()
    n = len(panels)
    if not n:
        return None
    nc = min(3, n)
    nr = int(math.ceil(n / nc))
    fig, axes = plt.subplots(nr, nc, figsize=(4.2 * nc, 3.1 * nr), squeeze=False, sharey=True)
    for ax in axes.flat[n:]:
        ax.set_visible(False)
    for ax, P in zip(axes.flat, panels):
        a, wins, ep = P["a"], P["wins"], P["ep"]
        t, dev, af, thr = a["decision_time"], a["device"], a["family"], a["threshold"]
        x0, x1 = math.floor(t - PANEL_S), math.ceil(t + PANEL_S)
        secs = np.arange(x0, x1)
        bottom = np.zeros(len(secs))
        for c in K.SRC_CATS:
            v = np.array([bins[(dev, int(s), af, c)] for s in secs], float)
            if v.any():
                ax.bar(secs - t, v, width=0.9, bottom=bottom, align="edge", color=CAT_COLOR[c], linewidth=0)
            bottom += v
        for w in wins:
            ax.axvspan(w - t, w + 1 - t, color=PS.CATEGORICAL[0], alpha=0.12, linewidth=0)
        ax.axhline(thr, color=PS.TEXT1, lw=0.9, ls="--")
        ax.axvline(0, color=PS.CATEGORICAL[4], lw=1.0)
        top = max(bottom.max(), thr) * 1.32
        ax.set_ylim(0, top)
        ax.text(-PANEL_S + 1, thr, f"threshold {thr:,}", va="bottom", ha="left", fontsize=6.5, color=PS.TEXT1)
        ax.text(-0.6, top * 0.97, "alert", va="top", ha="right", fontsize=6.5, color=PS.CATEGORICAL[4])
        vs = P.get("val_start")
        if vs is not None and -PANEL_S < vs - t < PANEL_S:
            ax.axvline(vs - t, color=PS.TEXT2, lw=0.9, ls="-.")
            ax.text(vs - t - 0.8, top * 0.6, "val window\nstarts", va="center", ha="right", fontsize=6.5,
                    color=PS.TEXT2)
        if ep is not None:
            xs = ep["start"] - t
            ax.axvline(xs, color=PS.class_color(ep["class"]), lw=1.2, ls=":")
            ax.text(xs + 0.6, top * 0.86, f"{ep['episode_id']} labelled start\n({names[ep['class']]}, {xs:+.0f} s)",
                    va="top", ha="left", fontsize=6.5, color=PS.TEXT1)
        ax.set_xlim(-PANEL_S, PANEL_S)
        ax.set_title(f"{a['alert_id']}  {a.get('device_name', '')} ({a['group']}), {af}, streak {a['streak']}",
                     loc="left", fontsize=8)
        ax.set_xlabel("seconds from the alert's decision time", fontsize=8)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
    for r in range(nr):
        axes[r][0].set_ylabel("packets / 1 s into the device")
    hand = [Patch(color=CAT_COLOR[c], label=CAT_LABEL[c]) for c in K.SRC_CATS] + \
           [Patch(color=PS.CATEGORICAL[0], alpha=0.12, label="triggering windows"),
            Line2D([], [], color=PS.TEXT1, ls="--", label="threshold (group, family)"),
            Line2D([], [], color=PS.CATEGORICAL[4], label="alert decision time"),
            Line2D([], [], color=PS.TEXT2, ls="-.", label="val window start (no val packet read before it)")]
    fig.legend(handles=hand, loc="lower center", ncol=4, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.06))
    fig.suptitle("diag_03 A: rate-guard alerts on no episode -- packets into the protected device (alert's family), "
                 "stacked by source host (val)", x=0.01, ha="left", fontsize=9)
    fig.tight_layout(rect=(0, 0.03, 1, 0.96))
    return PS.save(fig, path)


def fig_shift(path, S_, names):
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    PS.apply()
    classes = [c for c in names[1:] if c in set(S_["class"])]
    fig, ax = plt.subplots(figsize=(7.4, 0.9 + 0.75 * len(classes)))
    cid = {c: names.index(c) for c in classes}
    for k, c in enumerate(classes):
        sub = S_[S_["class"] == c].sort_values(["shift_s", "episode_id"]).reset_index(drop=True)
        offs = np.linspace(-0.22, 0.22, len(sub)) if len(sub) > 1 else [0.0]
        groups = defaultdict(list)                     # points at (nearly) the same shift share one label
        for j, r in sub.iterrows():
            y = k + offs[j]
            mk = "o" if r["found"] else "x"
            ax.plot(r["shift_s"], y, mk, ms=6, color=PS.class_color(cid[c]),
                    mfc=PS.class_color(cid[c]) if not r["at_lookback_edge"] else PS.SURFACE, mew=1.2)
            groups[round(float(r["shift_s"]) / 2.0)].append((r["shift_s"], y, r["episode_id"]))
        for g in groups.values():
            ids = [x[2] for x in g]
            lab = "\n".join(", ".join(ids[i:i + 4]) for i in range(0, len(ids), 4))
            if len(ids) > 1:
                lab = f"{len(ids)} episodes: " + ("\n" if len(ids) > 2 else "") + lab
            ax.annotate(lab, (max(x[0] for x in g), float(np.mean([x[1] for x in g]))), textcoords="offset points",
                        xytext=(8, 0), va="center", fontsize=6.5, color=PS.TEXT2)
    ax.set_yticks(range(len(classes)), classes)
    ax.set_ylim(len(classes) - 0.5, -0.5)
    ax.set_xlim(-3, LOOKBACK_S + 8)
    ax.axvline(LOOKBACK_S, color=PS.NEUTRAL_LIGHT, lw=0.8, ls="--")
    ax.text(LOOKBACK_S - 0.5, len(classes) - 0.55, "lookback limit 60 s", ha="right", va="bottom", fontsize=6.5, color=PS.TEXT2)
    ax.set_xlabel("labelled start - attacker-first-packet start (s)")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    hand = [Line2D([], [], marker="o", ls="none", color=PS.TEXT2, label="attacker packet found"),
            Line2D([], [], marker="o", ls="none", color=PS.TEXT2, mfc=PS.SURFACE, label="found at the 60 s edge (capped)"),
            Line2D([], [], marker="x", ls="none", color=PS.TEXT2, label="none in lookback (shift 0)")]
    ax.legend(handles=hand, frameon=False, fontsize=7, loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=3)
    ax.set_title("diag_03 A2: episode start shift, per val episode (what-if, not pre-registered)", loc="left", fontsize=9,
                 pad=18)
    fig.tight_layout()
    return PS.save(fig, path)


if __name__ == "__main__":
    sys.exit(main())
