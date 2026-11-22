#!/usr/bin/env python
"""diagnostics/diag_03_part_b.py -- READ-ONLY diag_03 part B: misclassified flow incidents (val).

B0  the rules (fixed before any number; written verbatim at the top of B_summary.md before anything is computed)
B1  every misclassified incident of the 10 step 28 rerun_full runs (GLOBAL / ROUTED x seeds 0-4), found with step
    29's OWN incident_outcomes (29_eval_stream.py imported read-only); every flow that contributed an alert to one
    (policy decision opened / extended for that incident) assigned to the first hypothesis it matches (H1..H4);
    B_incidents.csv, B_flows.csv; stability across seeds; GLOBAL vs ROUTED
Figures: figures/B_hypothesis_share.png, figures/B_confusion.png, figures/B_h1_profile.png (only if H1 flows exist).
Changes nothing; every output is a new file under --out (default results/diag_03).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diagnostics import diag_03_common as K  # noqa: E402
from common import plot_style as PS  # noqa: E402

RULE_B0 = """### B0. Rules, fixed before any numbers. Write them verbatim at the top of results/diag_03/B_summary.md first.
A misclassified incident = an incident overlapping an episode of a different attack class on the same device (prereg Phase 3 definition).
Each flow that contributed an alert to such an incident is assigned to the FIRST hypothesis it matches, in this order:
- **H1 unfixed reversal:** a TCP flow whose source endpoint (after normalisation) is the protected device and whose destination is
  the attacker host, with orientation_flipped = False. A reversal R3 didn't catch, e.g. SYN/ACK-first.
- **H2 label boundary:** the flow's start lies within 10 s of its episode's labelled start or end.
- **H3 collateral traffic:** the flow's true label is benign, or it is not attacker↔device traffic, but it lies inside an attack episode on
  that device (the device's own traffic disturbed by the attack).
- **H4 genuine confusion:** everything else.
Verdict: a hypothesis "explains" the misclassified incidents iff it covers ≥ 80% of their alert flows, pooled over all 10 runs (GLOBAL + ROUTED × 5 seeds).
If none reaches 80%, say so and give the split.
"""

HYP = ("H1", "H2", "H3", "H4")
HYP_LABEL = {"H1": "H1 unfixed reversal", "H2": "H2 label boundary", "H3": "H3 collateral traffic",
             "H4": "H4 genuine confusion"}
HYP_COLOR = {"H1": PS.CATEGORICAL[0], "H2": PS.CATEGORICAL[1], "H3": PS.CATEGORICAL[2], "H4": PS.BENIGN_GRAY}
BOUNDARY_S, EXPLAIN_MIN = 10.0, 0.80
CONTRIB = ("opened", "extended")
PROFILE = ["SYN Flag Count", "ACK Flag Count", "RST Flag Count", "FIN Flag Count", "FWD Init Win Bytes",
           "Bwd Init Win Bytes", "Total Fwd Packet", "Total Bwd packets"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(K.REPO / "results" / "diag_03"))
    args = ap.parse_args()
    out = K.Out(Path(args.out))
    summ = out.write_text("B_summary.md", "# diag_03 part B -- misclassified incidents (READ-ONLY, val)\n\n"
                          + RULE_B0 + "\n---\n\n")
    logs, checks = [], []

    def log(m: str) -> None:
        print(m, flush=True)
        logs.append(m)

    def check(name: str, ok: bool, detail: str = "", hard: bool = True) -> None:
        checks.append({"check": name, "pass": bool(ok), "level": "hard" if hard else "warn", "detail": detail})
        log(f"  {'PASS' if ok else ('FAIL' if hard else 'WARN')}  {name}  {detail}")
        if hard and not ok:
            raise RuntimeError(f"hard check failed: {name}: {detail}")

    lock0 = K.lock("start", log)
    ctx = K.load_context(log, need_flows=True)
    cfg, E, gt, eps, runs, names, m29 = (ctx[k] for k in ("cfg", "E", "gt", "eps", "runs", "names", "m29"))
    F, F0, hosts = ctx["flows"], ctx["flows_v20"], ctx["hosts"]
    slack, rgc = cfg["episodes"]["detect_slack_s"], cfg["policy"]["rate_guard_class"]
    by_dev = defaultdict(list)
    for e in eps:
        by_dev[e["device"]].append(e)
    col = {c: F[c].to_numpy() for c in K.FLOW_COLS}
    ori_ds = F["orientation_flipped"].to_numpy(bool)

    # ------------------------------------------------------------------ incidents
    inc_rows, flow_rows, sel = [], [], {}
    for tag in sorted(runs, key=lambda t: (t.split("_s")[0], int(t.split("_s")[1]))):
        R = runs[tag]
        flow_inc = [i for i in R["incidents"] if i["class"] != rgc]
        outc = E.incident_outcomes(flow_inc, eps, slack, names, rgc)
        cnt = {"n": len(flow_inc), **{k: outc.count(k) for k in ("correct", "misclassified", "false")}}
        check(f"{tag}: incident outcomes == step 29 ({cnt})", cnt == m29["per_run"][tag]["flow_incidents"])
        sel[tag] = [i for i, o in zip(flow_inc, outc) if o == "misclassified"]
    # top-3 SHAP of the contributing flows (alerts.jsonl), per run
    shap = {}
    for tag, mis in sel.items():
        P = runs[tag]["P"]
        m = P["incident_id"].isin([i["incident_id"] for i in mis]).to_numpy() & P["policy_decision"].isin(CONTRIB).to_numpy()
        _, shap[tag] = K.parse_alerts(runs[tag]["dir"] / "alerts.jsonl", set(P["flow_uid"].to_numpy()[m]))
    for tag, mis in sel.items():
        R = runs[tag]
        P, gi = R["P"], R["gi"]
        mode, seed = tag.split("_s")[0], int(tag.split("_s")[1])
        inc_id = P["incident_id"].to_numpy()
        pdec = P["policy_decision"].to_numpy()
        for i in mis:
            dev = i["device"]
            ov = [e for e in by_dev.get(dev, []) if i["first"] <= e["end"] + slack and i["last"] >= e["start"]]
            rows = np.flatnonzero((inc_id == i["incident_id"]) & np.isin(pdec, CONTRIB))
            check(f"{tag} {i['incident_id']}: contributing flows == incident n_alerts", len(rows) == i["n_alerts"],
                  f"{len(rows)} vs {i['n_alerts']}", hard=False)
            hc = Counter()
            for r in rows:
                k = int(gi[r])
                uid = gt["uid"][k]
                st = float(gt["start"][k])
                ep = min(ov, key=lambda e: (K.interval_distance(st, e["start"], e["end"] + slack), abs(st - e["start"])))
                smac, dmac = str(col["src_mac"][k]).lower(), str(col["dst_mac"][k]).lower()
                flip = bool(P["orientation_flipped"].iat[r])
                if flip != bool(ori_ds[k]):
                    check(f"{tag} {uid}: runtime orientation_flipped == dataset", False, "", hard=False)
                y = int(gt["y"][k])
                proto = int(col["Protocol"][k])
                h1 = proto == 6 and smac == dev and hosts.is_attacker(dmac) and not flip
                h2 = abs(st - ep["start"]) <= BOUNDARY_S or abs(st - ep["end"]) <= BOUNDARY_S
                attdev = (smac == dev and hosts.is_attacker(dmac)) or (dmac == dev and hosts.is_attacker(smac))
                inside = any(e["start"] <= st <= e["end"] for e in by_dev[dev])
                inside_slack = any(e["start"] <= st <= e["end"] + slack for e in by_dev[dev])
                h3 = (y == 0 or not attdev) and inside
                h = "H1" if h1 else "H2" if h2 else "H3" if h3 else "H4"
                hc[h] += 1
                z = F0.loc[uid]
                same = str(z["src_mac"]).lower() == smac and str(z["Src IP"]) == str(col["Src IP"][k])
                sh = shap[tag].get(uid, {}).get("top3") or []
                fr = {"run": tag, "mode": mode, "seed": seed, "incident_id": i["incident_id"], "flow_uid": uid,
                      "true_label": names[y], "pred": names[int(P["pred"].iat[r])], "pmax": float(P["pmax"].iat[r]),
                      **{f"p_{names[c]}": float(P[f"p_{c}"].iat[r]) for c in range(len(names))},
                      "model_id": P["model_id"].iat[r], "orientation_flipped": flip,
                      "v2_0_orientation": "same as v2_1" if same else "swapped vs v2_1",
                      "v2_0_src": f"{z['Src IP']}:{z['Src Port']} {z['src_mac']}",
                      "v2_0_dst": f"{z['Dst IP']}:{z['Dst Port']} {z['dst_mac']}",
                      "v2_1_src": f"{col['Src IP'][k]}:{col['Src Port'][k]} {smac}",
                      "v2_1_dst": f"{col['Dst IP'][k]}:{col['Dst Port'][k]} {dmac}",
                      "src_host": "protected device" if smac == dev else hosts.cat(smac),
                      "dst_host": "protected device" if dmac == dev else hosts.cat(dmac),
                      "protocol": proto, **{c: float(col[c][k]) for c in PROFILE + ["PSH Flag Count"]},
                      "flow_start": st, "flow_duration_s": float(gt["end"][k] - st), "episode_id": ep["episode_id"],
                      "episode_class": names[ep["class"]], "start_minus_episode_start_s": st - ep["start"],
                      "start_minus_episode_end_s": st - ep["end"], "decision_time": float(P["decision_time"].iat[r]),
                      "attacker_device_traffic": attdev, "inside_episode": inside, "inside_episode_or_slack": inside_slack,
                      "match_H1": h1, "match_H2": h2, "match_H3": h3, "hypothesis": h}
                for j in range(3):
                    f_ = sh[j] if j < len(sh) else (None, None, None)
                    fr[f"shap{j + 1}_feature"], fr[f"shap{j + 1}_value"], fr[f"shap{j + 1}_shap"] = f_[0], f_[1], f_[2]
                fr["shap_present"] = len(sh) == 3
                flow_rows.append(fr)
            e0 = min(ov, key=lambda e: e["start"])
            inc_rows.append({"run": tag, "mode": mode, "seed": seed, "incident_id": i["incident_id"],
                             "pred_class": i["class"], "device": dev, "device_name": runs[tag]["P"]["device"].iat[rows[0]]
                             if len(rows) else "", "group": i["group"],
                             "episodes": ",".join(e["episode_id"] for e in ov),
                             "episode_true_class": ",".join(sorted({names[e['class']] for e in ov})),
                             "first_minus_episode_start_s": i["first"] - e0["start"],
                             "last_minus_episode_end_s": i["last"] - max(e["end"] for e in ov),
                             "n_alerts_recorded": i["n_alerts"], "n_alert_flows": len(rows),
                             **{h: hc[h] for h in HYP},
                             "signature": f"{i['class']}@{dev}@{','.join(e['episode_id'] for e in ov)}"})
    import pandas as pd
    I = pd.DataFrame(inc_rows)
    Fl = pd.DataFrame(flow_rows)
    I.to_csv(out.path("B_incidents.csv"), index=False)
    Fl.to_csv(out.path("B_flows.csv"), index=False)
    check("every contributing alert flow has the runtime's top-3 SHAP in alerts.jsonl", bool(Fl["shap_present"].all()),
          f"{int(Fl['shap_present'].sum())} / {len(Fl)}")
    check("misclassified incidents pooled == sum of step 29 per-run counts", len(I) == sum(
        m29["per_run"][t]["flow_incidents"]["misclassified"] for t in runs), f"{len(I)}")

    # ------------------------------------------------------------------ verdict, stability
    tot = len(Fl)
    pooled = {h: int((Fl["hypothesis"] == h).sum()) for h in HYP}
    share = {h: (pooled[h] / tot if tot else float("nan")) for h in HYP}
    explains = [h for h in HYP if tot and share[h] >= EXPLAIN_MIN]
    per_run = {t: {h: int(((Fl["run"] == t) & (Fl["hypothesis"] == h)).sum()) for h in HYP} for t in sel}
    inc_major = Counter(I[list(HYP)].idxmax(axis=1)) if len(I) else Counter()
    stab = {}
    for mode in ("GLOBAL", "ROUTED"):
        sub = I[I["mode"] == mode]
        stab[mode] = {s: sorted(sub.loc[sub["signature"] == s, "seed"].tolist()) for s in sorted(set(sub["signature"]))}
    sigs = {m: set(v) for m, v in stab.items()}
    only = {"GLOBAL_only": sorted(sigs["GLOBAL"] - sigs["ROUTED"]), "ROUTED_only": sorted(sigs["ROUTED"] - sigs["GLOBAL"]),
            "both": sorted(sigs["GLOBAL"] & sigs["ROUTED"])}
    sens_h3 = int(((Fl["hypothesis"] == "H4") & Fl["inside_episode_or_slack"]
                   & ((Fl["true_label"] == names[0]) | ~Fl["attacker_device_traffic"])).sum()) if tot else 0
    conf = Counter()
    for r in I.itertuples():
        for c in r.episode_true_class.split(","):
            conf[(c, r.pred_class)] += 1
    log(f"pooled alert flows {tot}: {pooled}; explains: {explains or 'none'}")
    # report-only context: how common the H1 predicate is among ALL labelled flows of the overlapped episodes, and how
    # the model classifies flows that match it vs flows that do not (s0 of both modes)
    base_rate = []
    epi = {e["episode_id"]: e for e in eps}
    att_v = np.vectorize(hosts.is_attacker, otypes=[bool])
    for eid in sorted({x for s in I["episodes"] for x in s.split(",")}) if len(I) else []:
        e = epi[eid]
        m = K.episode_flow_mask(gt, e)
        sm = np.char.lower(col["src_mac"][m].astype(str))
        dm = np.char.lower(col["dst_mac"][m].astype(str))
        pred_h1 = (col["Protocol"][m].astype(int) == 6) & (sm == e["device"]) & att_v(dm) & ~ori_ds[m]
        row = {"episode_id": eid, "class": names[e["class"]], "device": e["device"], "labelled_flows": int(m.sum()),
               "h1_predicate_flows": int(pred_h1.sum()), "h1_predicate_share": float(pred_h1.mean()) if m.any() else None}
        for tag in ("GLOBAL_s0", "ROUTED_s0"):
            P, gi = runs[tag]["P"], runs[tag]["gi"]
            pos = np.full(len(gt["y"]), -1)
            pos[gi] = np.arange(len(gi))
            pr = P["pred"].to_numpy()[pos[np.flatnonzero(m)]]
            for lab, mk in (("h1", pred_h1), ("not_h1", ~pred_h1)):
                row[f"{tag}_{lab}_n"] = int(mk.sum())
                row[f"{tag}_{lab}_pred_own_class"] = float((pr[mk] == e["class"]).mean()) if mk.any() else None
                row[f"{tag}_{lab}_pred_counts"] = str(dict(Counter(names[int(c)] for c in pr[mk])))
        base_rate.append(row)
    pd.DataFrame(base_rate).to_csv(out.path("B_h1_base_rate.csv"), index=False)

    # ------------------------------------------------------------------ figures
    fig_share(out.fig / "B_hypothesis_share.png", pooled, per_run)
    fig_conf(out.fig / "B_confusion.png", conf, names)
    h1_fig = None
    if pooled["H1"]:
        h1_fig = fig_h1(out.fig / "B_h1_profile.png", Fl, runs, gt, F, names)

    lock1 = K.lock("end", log)
    check("config.py / class_map.json sha256 unchanged start -> end", lock0 == lock1, str(lock1))
    out.write_json("B_run.json", {"script": "diagnostics/diag_03_part_b.py", "run28": K.RUN28_ID, "lock": {"start": lock0, "end": lock1},
                                  "val_sha256": ctx["val_sha256"], "hosts": hosts.describe(), "pooled": pooled,
                                  "share": share, "explains": explains, "per_run": per_run, "stability": stab,
                                  "global_vs_routed": only, "incident_majority_hypothesis": dict(inc_major),
                                  "sensitivity_H4_to_H3_with_slack": sens_h3, "h1_base_rate": base_rate,
                                  "confusion": {f"{a}->{b}": v for (a, b), v in conf.items()}, "checks": checks, "log": logs})
    L = ["## Results (computed after the rules above were written)", "",
         f"Inputs: step 28 run `{K.RUN28_ID}` ({K.RUN28_TAG}); incidents classified with step 29's own "
         "`incident_outcomes`; contributing flow = an alert with policy decision opened / extended for that incident. "
         f"Attacker host = V1 step 13 / D74 identity. 'Its episode' = the overlapped episode whose [start, end + 120 s] "
         "holds the flow's start (else the nearest); see choices.md.", "",
         "### Counts per run", "", "| run | misclassified incidents | alert flows | H1 | H2 | H3 | H4 |", "|---|---|---|---|---|---|---|"]
    for t in sel:
        L.append(f"| {t} | {len(sel[t])} | {sum(per_run[t].values())} | " + " | ".join(str(per_run[t][h]) for h in HYP) + " |")
    L += [f"| **pooled** | **{len(I)}** | **{tot}** | " + " | ".join(f"**{pooled[h]}** ({share[h]:.1%})" for h in HYP) + " |",
          "", "### Verdict", "",
          (f"- **{', '.join(HYP_LABEL[h] for h in explains)}** covers >= 80 % of the pooled alert flows and explains the "
           "misclassified incidents." if explains else
           "- **No hypothesis reaches 80 %** of the pooled alert flows. Split: " +
           ", ".join(f"{HYP_LABEL[h]} {share[h]:.1%} ({pooled[h]})" for h in HYP) + "."),
          "- Per incident (report-only, the hypothesis holding most of its flows): " +
          ", ".join(f"{h} {inc_major.get(h, 0)}" for h in HYP) + f" of {len(I)} incidents.",
          f"- Sensitivity (report-only): {sens_h3} H4 flows would be H3 if 'inside an episode' included the 120 s "
          "detection slack.", "",
          "### Incidents (`B_incidents.csv`)", "",
          "| run | incident | predicted | device (group) | episode(s), true class | first - ep start s | last - ep end s | alert flows | H1/H2/H3/H4 |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in I.itertuples():
        L.append(f"| {r.run} | {r.incident_id} | {r.pred_class} | {r.device_name} `{r.device}` ({r.group}) | {r.episodes}, "
                 f"{r.episode_true_class} | {r.first_minus_episode_start_s:+.1f} | {r.last_minus_episode_end_s:+.1f} | "
                 f"{r.n_alert_flows} | {r.H1}/{r.H2}/{r.H3}/{r.H4} |")
    L += ["", "### Stability across seeds", ""]
    for mode, v in stab.items():
        L += [f"**{mode}**", "", "| incident signature (predicted@device@episodes) | seeds | stable (all 5) |", "|---|---|---|"]
        L += [f"| {s} | {sd} | {len(set(sd)) == 5} |" for s, sd in v.items()] + [""]
    L += ["### Context for H1 (report-only, not part of the verdict): the H1 predicate on ALL labelled flows of the "
          "overlapped episodes (`B_h1_base_rate.csv`)", "",
          "| episode | class | labelled flows | match H1 predicate | GLOBAL s0: own class among matching / non-matching | "
          "ROUTED s0: own class among matching / non-matching |", "|---|---|---|---|---|---|"]
    for r in base_rate:
        L.append(f"| {r['episode_id']} | {r['class']} | {r['labelled_flows']:,} | {r['h1_predicate_flows']:,} "
                 f"({r['h1_predicate_share']:.1%}) | {_p(r['GLOBAL_s0_h1_pred_own_class'])} / "
                 f"{_p(r['GLOBAL_s0_not_h1_pred_own_class'])} | {_p(r['ROUTED_s0_h1_pred_own_class'])} / "
                 f"{_p(r['ROUTED_s0_not_h1_pred_own_class'])} |")
    L += ["", "Predicted classes of the matching flows: " + "; ".join(
        f"{r['episode_id']} GLOBAL s0 {r['GLOBAL_s0_h1_pred_counts']}" for r in base_rate), ""]
    L += ["### GLOBAL vs ROUTED", "", f"- in both: {only['both']}", f"- GLOBAL only: {only['GLOBAL_only'] or 'none'}",
          f"- ROUTED only: {only['ROUTED_only'] or 'none'}", "",
          "### Confusion (episode true class -> incident predicted class), incidents pooled over 10 runs", "",
          "| true \\ predicted | " + " | ".join(names[1:]) + " |", "|---|" + "---|" * (len(names) - 1)]
    for a in names[1:]:
        L.append(f"| {a} | " + " | ".join(str(conf.get((a, b), 0)) for b in names[1:]) + " |")
    L += ["", "### Figures", "", "- `figures/B_hypothesis_share.png`", "- `figures/B_confusion.png`",
          f"- `figures/B_h1_profile.png`" if h1_fig else "- no H1 flow, so no H1 profile figure", "",
          "### Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                               f"{c['detail']}" for c in checks if c["level"] == "warn" or not c["check"].startswith(("GLOBAL_s", "ROUTED_s"))]
    n_hidden = sum(1 for c in checks if c["level"] == "hard" and c["check"].startswith(("GLOBAL_s", "ROUTED_s")))
    L += [f"- PASS  {n_hidden} per-run hard checks (incident outcomes == step 29), listed in B_run.json", "",
          f"verify_v2_lock OK at start and end; config/config.py {lock1['config/config.py']}, "
          f"config/class_map.json {lock1['config/class_map.json']} (unchanged: {lock0 == lock1}).", ""]
    with open(summ, "a", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    print(f"wrote {len(out.written)} files under {out.root}")
    return 0


def _p(x):
    return "-" if x is None else f"{x:.1%}"


# ---------------------------------------------------------------------- figures
def fig_share(path, pooled, per_run):
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    PS.apply()
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 3.6), gridspec_kw={"width_ratios": [1, 3.2]})
    rows = [("pooled (10 runs)", pooled)]
    tags = list(per_run)
    for ax, data, horiz in ((axes[0], rows, False), (axes[1], [(t, per_run[t]) for t in tags], False)):
        x = np.arange(len(data))
        for j, (lab, d) in enumerate(data):
            tot = sum(d.values())
            b = 0.0
            for h in HYP:
                v = d[h] / tot if tot else 0
                if v > 0:
                    ax.bar(j, v, 0.62, bottom=b, color=HYP_COLOR[h], edgecolor=PS.SURFACE, linewidth=1)
                    if v >= 0.07:
                        ax.text(j, b + v / 2, f"{v:.0%}\n({d[h]})" if len(data) == 1 else f"{v:.0%}", ha="center",
                                va="center", fontsize=6.5, color=PS.SURFACE if h != "H3" else PS.TEXT1)
                b += v
            ax.text(j, 1.02, f"n={tot}", ha="center", va="bottom", fontsize=6.5, color=PS.TEXT2)
        ax.set_xticks(x, [lab for lab, _ in data], rotation=0 if len(data) == 1 else 35,
                      ha="center" if len(data) == 1 else "right", fontsize=7.5)
        ax.set_ylim(0, 1.1)
        ax.axhline(EXPLAIN_MIN, color=PS.TEXT1, lw=0.8, ls="--")
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("share of alert flows")
    axes[1].text(1.0, EXPLAIN_MIN + 0.012, "80 % rule", transform=axes[1].get_yaxis_transform(), fontsize=6.5,
                 va="bottom", ha="right", color=PS.TEXT1,
                 bbox={"boxstyle": "round,pad=0.15", "fc": PS.SURFACE, "ec": "none"})
    axes[0].set_title("pooled", loc="left", fontsize=9)
    axes[1].set_title("per run (labels for shares >= 7 %)", loc="left", fontsize=9)
    fig.legend(handles=[Patch(color=HYP_COLOR[h], label=HYP_LABEL[h]) for h in HYP], loc="lower center", ncol=4,
               frameon=False, fontsize=7.5, bbox_to_anchor=(0.5, -0.07))
    fig.suptitle("diag_03 B: hypothesis share of the alert flows in misclassified incidents (val)", x=0.01, ha="left",
                 fontsize=9)
    fig.tight_layout(rect=(0, 0.04, 1, 0.95))
    return PS.save(fig, path)


def fig_conf(path, conf, names):
    import matplotlib.pyplot as plt
    PS.apply()
    att = names[1:]
    M = np.array([[conf.get((a, b), 0) for b in att] for a in att], float)
    fig, ax = plt.subplots(figsize=(4.6, 3.6))
    im = ax.imshow(M, cmap=PS.SEQUENTIAL_CMAP, vmin=0, vmax=max(M.max(), 1))
    for i in range(len(att)):
        for j in range(len(att)):
            ax.text(j, i, f"{int(M[i, j])}", ha="center", va="center", fontsize=9,
                    color=PS.SURFACE if M[i, j] > 0.6 * M.max() else PS.TEXT1)
    ax.set_xticks(range(len(att)), att)
    ax.set_yticks(range(len(att)), att)
    ax.set_xlabel("incident predicted class")
    ax.set_ylabel("overlapped episode true class")
    from matplotlib.ticker import MaxNLocator
    cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="misclassified incidents")
    cb.locator = MaxNLocator(integer=True)
    cb.update_ticks()
    ax.set_title("Misclassified incidents, pooled over 10 runs\n(diagonal is 0 by definition)", loc="left", fontsize=9)
    fig.tight_layout()
    return PS.save(fig, path)


def fig_h1(path, Fl, runs, gt, F, names):
    """H1 flows (deduplicated over runs) vs correctly classified flows of both classes involved (GLOBAL_s0)."""
    import matplotlib.pyplot as plt
    PS.apply()
    h1 = Fl[Fl["hypothesis"] == "H1"].drop_duplicates("flow_uid")
    pairs = sorted(set(zip(h1["episode_class"], h1["pred"])))
    P, gi = runs["GLOBAL_s0"]["P"], runs["GLOBAL_s0"]["gi"]
    y, pred = gt["y"][gi], P["pred"].to_numpy()
    neutrals = (PS.TEXT1, PS.TEXT2, PS.BENIGN_GRAY)
    groups = []                      # H1 groups in neutral ink; correct-class groups in their fixed class colours
    for k, (ec, pc) in enumerate(pairs):
        sub = h1[(h1["episode_class"] == ec) & (h1["pred"] == pc)]
        groups.append((f"H1: {ec} ep.\n-> pred {pc}", f"H1 flows in {ec} episodes predicted {pc} (n={len(sub)})",
                       sub[PROFILE].to_numpy(float), neutrals[k % len(neutrals)]))
    rng = np.random.default_rng(0)
    for c in sorted({names.index(a) for p in pairs for a in p}):
        ix = np.flatnonzero((y == c) & (pred == c))
        n_all = len(ix)
        if len(ix) > 3000:
            ix = np.sort(rng.choice(ix, 3000, replace=False))
        groups.append((f"correct\n{names[c]}", f"correctly classified {names[c]} flows (GLOBAL s0, {len(ix)} of {n_all:,})",
                       F[PROFILE].to_numpy(float)[gi[ix]], PS.class_color(c)))
    fig, axes = plt.subplots(2, 4, figsize=(12, 5.6))
    for ax, j in zip(axes.flat, range(len(PROFILE))):
        for g, (_, _, X, colr) in enumerate(groups):
            v = X[:, j]
            jit = rng.uniform(-0.18, 0.18, len(v))
            ax.scatter(g + jit, v, s=5, color=colr, alpha=0.5, linewidths=0)
            ax.plot([g - 0.3, g + 0.3], [np.median(v)] * 2, color=PS.TEXT1, lw=1.2)
        allv = np.concatenate([X[:, j] for _, _, X, _ in groups])
        if np.nanmax(allv) == np.nanmin(allv):                       # constant feature: one plain tick
            ax.set_yticks([allv[0]], [f"{allv[0]:g}"])
            ax.set_ylim(allv[0] - 1, allv[0] + 1)
        else:
            ax.set_yscale("symlog", linthresh=1)
        ax.set_xticks(range(len(groups)), [chr(65 + g) for g in range(len(groups))], fontsize=7.5)
        ax.set_title(PROFILE[j], loc="left", fontsize=8)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
    fig.text(0.01, 0.005, "\n".join(f"{chr(65 + k)} = {g[1]}" for k, g in enumerate(groups))
             + "\nbar = median; y symlog (a constant feature shows one tick)", fontsize=7, color=PS.TEXT2, va="bottom")
    fig.suptitle(f"diag_03 B: H1 flows ({len(h1)} unique over 10 runs) vs correctly classified flows -- flag counts, "
                 "Init Win, packet counts (v2_1, after normalisation)", x=0.01, ha="left", fontsize=9)
    fig.tight_layout(rect=(0, 0.04 + 0.022 * (len(groups) + 1), 1, 0.95))
    return PS.save(fig, path)


if __name__ == "__main__":
    sys.exit(main())
