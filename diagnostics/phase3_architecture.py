#!/usr/bin/env python
"""diagnostics/phase3_architecture.py -- Phase 3 step H: the runtime architecture figure (matplotlib boxes and arrows,
both paths, DFD ids where they apply) -> results/phase3/figures/runtime_architecture.png (never overwritten).
Reads nothing but the config; no data.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import RESULTS_DIR  # noqa: E402
from common import phase3_config as C  # noqa: E402
from common import plot_style as PS  # noqa: E402

NL = "\n"


def main() -> int:
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    cfg = C.load_phase3_config()
    PS.apply()
    fig, ax = plt.subplots(figsize=(14.5, 6.8))
    ax.set_xlim(0, 30)
    ax.set_ylim(-0.2, 12.6)
    ax.axis("off")
    FLOW, PKT, STORE, CTRL = PS.CATEGORICAL[0], PS.CATEGORICAL[4], PS.NEUTRAL_LIGHT, PS.CATEGORICAL[2]

    def box(x, y, w, h, title, sub=(), col=FLOW, dfd=None):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.05,rounding_size=0.18", fc=PS.SURFACE, ec=col, lw=1.6))
        ax.text(x + w / 2, y + h - 0.28, title, ha="center", va="top", fontsize=8.3, weight="bold", color=PS.TEXT1)
        if sub:
            ax.text(x + w / 2, y + h - 0.72, NL.join(sub), ha="center", va="top", fontsize=6.4, color=PS.TEXT2,
                    linespacing=1.25)
        if dfd:
            ax.text(x + w - 0.1, y + 0.08, dfd, ha="right", va="bottom", fontsize=7.5, color=col, weight="bold")
        return (x, y, w, h)

    def arrow(a, b, col=PS.TEXT2, side=("r", "l"), rad=0.0):
        def pt(r, s):
            x, y, w, h = r
            return {"r": (x + w, y + h / 2), "l": (x, y + h / 2), "t": (x + w / 2, y + h), "b": (x + w / 2, y)}[s]
        ax.add_patch(FancyArrowPatch(pt(a, side[0]), pt(b, side[1]), arrowstyle="-|>", mutation_scale=11, color=col,
                                     lw=1.2, connectionstyle=f"arc3,rad={rad}"))

    rg, po, ba = cfg["rate_guard"], cfg["policy"], cfg["batch"]
    src = box(0.2, 8.3, 3.3, 2.4, "Flow source", ("CICFlowMeter (locked jar):", "row per ended flow", "or CSV replay (val)"))
    rou = box(4.0, 8.3, 3.2, 2.4, "Route", ("MAC -> device -> group", "ingest rule, extractor", "orientation; unknown",
                                            "-> fallback group"))
    nor = box(7.7, 8.3, 3.0, 2.4, "Normalise", ("orientation rule R3", "map sha256 pinned"))
    fea = box(11.2, 8.3, 3.2, 2.4, "Features", ("70, features_v1 order,", "float32, NaN / inf -> 0;",
                                                f"batch <= {ba['max_flows']} or {ba['max_event_s'] * 1000:.0f} ms"))
    pre = box(14.9, 8.3, 3.5, 2.4, "Predict + calibrate", ("XGBoost margins", "(GLOBAL, promoted)", "softmax(z / T)"))
    shp = box(14.9, 11.1, 3.5, 1.3, "SHAP on alert", ("top-3 TreeSHAP",))
    pol = box(19.0, 8.3, 3.7, 2.4, "Policy", (f"alert: attack and p >= {po['confidence_threshold']}",
                                              f"incidents ({po['aggregation_window_s']:g} s), cooldown",
                                              f"{po['cooldown_s']:g} s, severity map;", "config sha256 pinned"), CTRL, "P5")
    log = box(23.2, 8.3, 3.1, 2.4, "Log", ("append-only JSONL,", "hash-chained, Ed25519", "(runtime key)"), CTRL, "P6")
    s3 = box(26.9, 9.4, 2.9, 1.7, "S3 alert store", ("alerts + health", "logs"), STORE)
    prq = box(26.9, 7.4, 2.9, 1.6, "Predictions", ("every flow (Phase 4", "review queue)"), STORE)
    out = box(21.0, 11.1, 5.6, 1.3, "Outbox -> Networking", ("incident.opened / .closed (P7 notify, P8 mitigate)",), STORE)
    reg = box(10.9, 4.4, 3.4, 2.0, "Model registry", ("signed entries,", "signed state log"), STORE)
    ldr = box(14.9, 4.4, 3.5, 2.0, "Model loader", ("Ed25519 signature, file +", "pin hashes, promoted only"), CTRL, "P4")
    pk = box(0.2, 0.8, 3.3, 2.6, "Packet source", ("capture / pcap,", "Ethernet + IPv4 header,", "split-confined (val)"), PKT)
    thr = box(5.6, 4.4, 3.6, 1.8, "Thresholds", ("fitted on train benign", "(step 27), sha256 checked"), STORE)
    rg2 = box(4.4, 2.0, 5.6, 1.8, "Rate guard v2", (f"{rg['window_s']:g} s windows into each protected device,",
                                                    f"TCP / UDP / other; > {rg['multiplier']} x train-benign max",
                                                    f"for {rg['consecutive']} windows in a row"), PKT)
    rg1 = box(4.4, -0.1, 5.6, 1.7, "V1 rule (unchanged)", ("non-TCP/UDP, 10 s, stream + victim",
                                                           "config/rate_guard_v1.json"), PKT)
    rga = box(19.0, 1.0, 3.7, 2.0, "Rate-guard alerts", ("decision time = window end",), PKT)
    for a, b, c in ((src, rou, FLOW), (rou, nor, FLOW), (nor, fea, FLOW), (fea, pre, FLOW), (pre, pol, FLOW), (pol, log, CTRL),
                    (reg, ldr, STORE), (pk, rg2, PKT), (pk, rg1, PKT), (rg2, rga, PKT), (rg1, rga, PKT), (log, s3, CTRL),
                    (log, prq, CTRL)):
        arrow(a, b, c)
    arrow(pre, shp, FLOW, side=("t", "b"))
    arrow(shp, pol, FLOW, side=("r", "t"), rad=-0.2)
    arrow(ldr, pre, CTRL, side=("t", "b"))
    arrow(thr, rg2, STORE, side=("b", "t"))
    arrow(rga, pol, PKT, side=("t", "b"))
    arrow(log, out, CTRL, side=("t", "b"))
    ax.text(0.2, 12.2, "one event clock for both paths", fontsize=7.5, color=PS.TEXT2, style="italic")
    ax.plot([0.2, 26.5], [7.0, 7.0], color=PS.GRID, lw=0.8, ls="--", zorder=0)
    ax.text(0.2, 7.2, "flow path (ML)", fontsize=8, color=FLOW, weight="bold")
    ax.text(0.2, 6.6, "packet path (rate guard)", fontsize=8, color=PKT, weight="bold", va="top")
    ax.set_title("LG-IDS V2 Phase 3 streaming runtime (DFD ids P4 model loading, P5 policy, P6 logging, S3 alert store)",
                 loc="left", fontsize=10)
    out_p = RESULTS_DIR / "phase3" / "figures" / "runtime_architecture.png"
    PS.save(fig, out_p)
    print(out_p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
