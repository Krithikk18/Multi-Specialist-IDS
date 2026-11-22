#!/usr/bin/env python
"""diagnostics/phase3_shap_alert_batches.py -- READ-ONLY correction to step 30's "SHAP (batches with alerts)" numbers.

30 filtered batches by SHAP-stage time > 0, but that stage also times the per-row alert decision, so it is > 0 for every
batch. Here the batches are split exactly: predictions.parquet rows are written in batch order and latency.npz keeps the
batch sizes, so each batch's alert count is known. Reports, per benchmark run, the SHAP-stage time for batches with >= 1
alert (per batch and per alert) and for batches without alerts (= the alert-decision overhead).
Inputs: results/phase3/30 (manifest sha256 checked) and its run folders. Output: results/phase3/bench_shap_diag/
summary.md + shap_alert_batches.json (refused if they exist).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import RESULTS_DIR  # noqa: E402
from common import phase3_run as R3  # noqa: E402


def main() -> int:
    import pyarrow.parquet as pq
    out = RESULTS_DIR / "phase3" / "bench_shap_diag"
    if (out / "summary.md").exists():
        print(f"{out} exists (never overwritten)")
        return 1
    up = R3.resolve("30")
    rows, J = [], {"step30_run": up["meta"]["run_id"], "runs": {}}
    for r in up["manifest"]["runs"]:
        d = Path(r["dir"])
        L = np.load(d / "latency.npz")
        bs, sh = L["batch_sizes"], L["batch_shap"] / 1e3
        alert = pq.read_table(d / "predictions.parquet", columns=["alert"]).column("alert").to_numpy()
        edges = np.concatenate([[0], np.cumsum(bs)])
        na = np.add.reduceat(alert.astype(np.int64), edges[:-1]) if len(bs) else np.zeros(0, np.int64)
        w, wo = na > 0, na == 0
        q = lambda a: [float(np.quantile(a, x)) for x in (.5, .95, .99)] if len(a) else [float("nan")] * 3  # noqa: E731
        J["runs"][r["tag"]] = {"batches": int(len(bs)), "with_alerts": int(w.sum()),
                               "shap_us_per_batch_with_alerts": q(sh[w]), "shap_us_per_alert": q(sh[w] / na[w]),
                               "no_alert_batches_us": q(sh[wo])}
        j = J["runs"][r["tag"]]
        rows.append(f"| {r['tag']} | {j['batches']:,} | {j['with_alerts']:,} | "
                    + " / ".join(f"{x:,.0f}" for x in j["shap_us_per_batch_with_alerts"]) + " | "
                    + " / ".join(f"{x:,.0f}" for x in j["shap_us_per_alert"]) + " | "
                    + " / ".join(f"{x:.1f}" for x in j["no_alert_batches_us"]) + " |")
    out.mkdir(parents=True, exist_ok=True)
    R3.write_json(out / "shap_alert_batches.json", J)
    L = ["# Step 30 correction -- SHAP-on-alert latency split by batches with / without alerts (read-only)", "",
         f"- step 30 run `{up['meta']['run_id']}`; microseconds, p50 / p95 / p99", "",
         "| run | batches | with alerts | SHAP per batch with alerts | SHAP per alert | batches without alerts |",
         "|---|---|---|---|---|---|", *rows]
    (out / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
