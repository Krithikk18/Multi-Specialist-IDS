"""common/amendment.py -- Phase 2 pre-registration Amendment 1, section 2 (docs/V2_PREREG_PHASE2_AMENDMENT_1.md):
choose the primary class-weight configuration jointly for all specialists + GLOBAL, from step 23's results.

Active only when the config carries "primary_selection" (config/v2_phase2_v2_1.json); with config/v2_phase2.json
every Phase 2 script behaves exactly as before.

    if A.active(cfg): sel = A.select_primary(E, cfg)                 # step 23 (E = its per-entity results)
    ch = A.chosen(cfg, M22, up23)                                    # steps 24-26: chosen config label, routing

Rule: per mode c (config class_weights.primary + ablation_modes), ROUTED(c) non-rare macro-F1 mean over seeds and
false-alarm count mean over seeds on the full val split; keep modes within `tolerance` of the best macro-F1; pick
the fewest mean false alarms; ties -> the first of `tie_order` among the tied.
"""

from __future__ import annotations

import numpy as np


def active(cfg: dict) -> bool:
    return bool(cfg.get("primary_selection"))


def modes(cfg: dict) -> list[str]:
    return [cfg["class_weights"]["primary"], *cfg["class_weights"]["ablation_modes"]]


def routed_name(cfg: dict, mode: str) -> str:
    return "ROUTED" if mode == cfg["class_weights"]["primary"] else f"ROUTED_A1_{mode}"


def flat_name(cfg: dict, mode: str) -> str:
    return "FLAT_GLOBAL" if mode == cfg["class_weights"]["primary"] else f"FLAT_GLOBAL_A1_{mode}"


def config_label(cfg: dict, mode: str) -> str:
    """The `config` label step 22 gives the specs of this weighting ("primary" or "A1_<mode>")."""
    return "primary" if mode == cfg["class_weights"]["primary"] else f"A1_{mode}"


def swap_weights(model_id: str, mode: str) -> str:
    """SPEC_G1__sqrt -> SPEC_G1__<mode> (step 22's / 23's model id convention)."""
    return model_id.rsplit("__", 1)[0] + f"__{mode}"


def decide(rows: list[dict], tolerance: float, tie_order: list[str]) -> dict:
    """rows: [{"mode", "macro_f1_nonrare_mean", "fa_count_mean"}] -> the decision (pure function, unit-tested)."""
    best = max(r["macro_f1_nonrare_mean"] for r in rows)
    keep = [r for r in rows if r["macro_f1_nonrare_mean"] >= best - tolerance]
    fewest = min(r["fa_count_mean"] for r in keep)
    tied = [r["mode"] for r in keep if r["fa_count_mean"] == fewest]
    order = [m for m in tie_order if m in tied] + [m for m in tied if m not in tie_order]
    return {"chosen": order[0], "best_macro_f1_nonrare_mean": best, "within_tolerance": [r["mode"] for r in keep],
            "fewest_fa_count_mean": fewest, "tied_on_fa": tied, "tie_break_used": len(tied) > 1}


def select_primary(E: dict, cfg: dict) -> dict:
    """Apply the rule to step 23's entity results E[system]["all"]["aggregate"]; returns the table + decision."""
    ps = cfg["primary_selection"]
    rows = []
    for m in modes(cfg):
        a = E[routed_name(cfg, m)]["all"]["aggregate"]
        f = E[flat_name(cfg, m)]["all"]["aggregate"] if flat_name(cfg, m) in E else None
        rows.append({"mode": m, "routed_system": routed_name(cfg, m), "flat_system": flat_name(cfg, m),
                     "macro_f1_nonrare_mean": float(a["macro_f1_nonrare"]["mean"]),
                     "macro_f1_nonrare_ci": [a["macro_f1_nonrare"]["lo"], a["macro_f1_nonrare"]["hi"]],
                     "macro_f1_all_mean": float(a["macro_f1_all"]["mean"]),
                     "fa_count_mean": float(np.mean(a["fa_counts_per_seed"])), "fa_counts_per_seed": a["fa_counts_per_seed"],
                     "fa_per_hour_mean": float(a["fa_per_hour"]["mean"]),
                     "flat_macro_f1_nonrare_mean": float(f["macro_f1_nonrare"]["mean"]) if f else None})
    d = decide(rows, float(ps["tolerance"]), list(ps["tie_order"]))
    m = d["chosen"]
    return {"rule": ps["rule"], "amendment": ps.get("amendment"), "tolerance": ps["tolerance"],
            "tie_order": ps["tie_order"], "table": rows, **d, "chosen_config_label": config_label(cfg, m),
            "chosen_routed_system": routed_name(cfg, m), "chosen_flat_system": flat_name(cfg, m)}


def chosen(cfg: dict, M22: dict, up23: dict | None) -> dict:
    """The primary configuration steps 24-26 report: the amendment's choice (from step 23's manifest) if active,
    else the pre-registered primary. Returns weights, config label, routing {group: model_id}, default model id."""
    prim, default = M22["routing"]["primary"], M22["routing"]["default"]
    if not active(cfg):
        return {"weights": cfg["class_weights"]["primary"], "config_label": "primary", "routing": dict(prim),
                "default": default, "source": "pre-registered primary"}
    if up23 is None or "primary_selection" not in up23["manifest"]:
        raise RuntimeError("amendment active but the step 23 run carries no primary_selection")
    sel = up23["manifest"]["primary_selection"]
    m = sel["chosen"]
    return {"weights": m, "config_label": config_label(cfg, m), "routing": {g: swap_weights(v, m) for g, v in prim.items()},
            "default": swap_weights(default, m), "source": f"amendment selection in step 23 run {up23['meta']['run_id']}",
            "selection": sel}
