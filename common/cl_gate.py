"""common/cl_gate.py -- Phase 4 metrics, regression gate, Amendment 2 section 4 verdict and the poisoning verdict
(docs/V2_PREREG_PHASE4.md sections 6-8). Pure functions over arrays.

    E = eval_set(y, pred, K, nonrare, session, start_ts, idle_gap)   # recall / F1 per class, macro-F1, FA/h
    G = gate(E_candidate, E_deployed, nonrare, gate_cfg)             # (i) recall, (ii) macro-F1, (iii) FA/h -> PASS
    V = verdict_a2s4(...)                                            # Amendment 2 section 4, the pinned rule
    poisoning_verdict(quarantined, gate_pass_seed0)                  # CAUGHT_BY_VALIDATOR / CAUGHT_BY_GATE / NOT_CAUGHT

Definitions (Phase 2's): prediction = argmax; per-class recall / F1 with support > 0 (else NaN, never 0); precision of a
class with support but no predictions = 0; macro-F1 all = classes with support; macro-F1 non-rare = the given non-rare
classes (support >= min_val_flows in the evaluation set); flow-level false alarms = benign flows predicted as any attack
class; benign hours = per-session active segments of the evaluated flows' starts (pause > idle_gap ends one) holding
>= 1 benign flow (common/phase2_metrics.benign_hours).
"""

from __future__ import annotations

import numpy as np

from common import phase2_metrics as PM

PASS, FAIL = "PASS", "FAIL"


def nonrare_classes(y, K: int, min_flows: int) -> list[int]:
    sup = np.bincount(np.asarray(y, np.int64), minlength=K)[:K]
    return [int(c) for c in np.flatnonzero(sup >= min_flows)]


def eval_set(y, pred, K: int, nonrare: list[int], session, start_ts, idle_gap: float) -> dict:
    y, pred = np.asarray(y, np.int64), np.asarray(pred, np.int64)
    cm = PM.confusion(y, pred, K)
    pc = PM.per_class_prf(cm)
    sup = pc["support"]
    present = sup > 0
    nr = np.zeros(K, bool)
    nr[list(nonrare)] = True
    nr &= present
    fa = int(((y == 0) & (pred != 0)).sum())
    hours = PM.benign_hours(np.asarray(session).astype(str), np.asarray(start_ts, np.int64), y == 0, idle_gap) \
        if (y == 0).any() else 0.0
    return {"n": int(len(y)), "support": sup.tolist(), "recall": pc["recall"].tolist(), "precision": pc["precision"].tolist(),
            "f1": pc["f1"].tolist(), "confusion": cm.tolist(),
            "macro_f1_all": float(np.nanmean(pc["f1"][present])) if present.any() else float("nan"),
            "macro_f1_nonrare": float(np.nanmean(pc["f1"][nr])) if nr.any() else float("nan"),
            "nonrare": [int(c) for c in np.flatnonzero(nr)], "fa_count": fa, "benign_hours": float(hours),
            "fa_per_hour": fa / hours if hours > 0 else float("nan")}


def gate(cand: dict, ref: dict, nonrare: list[int], gcfg: dict) -> dict:
    """Candidate vs the deployed model on the same rows. PASS iff (i) no non-rare class's recall drops by more than
    max_recall_drop, (ii) non-rare macro-F1 drops by no more than max_macro_f1_drop, (iii) FA/h rises by no more than
    max_fa_per_h_rise. Rare classes are reported, never gated."""
    drops = {int(c): float(ref["recall"][c] - cand["recall"][c]) for c in nonrare}
    bad_i = {c: d for c, d in drops.items() if d > gcfg["max_recall_drop"]}
    d_f1 = float(ref["macro_f1_nonrare"] - cand["macro_f1_nonrare"])
    d_fa = float(cand["fa_per_hour"] - ref["fa_per_hour"])
    C = {"i_recall": {"pass": not bad_i, "drops": drops, "failing": bad_i, "max": gcfg["max_recall_drop"]},
         "ii_macro_f1_nonrare": {"pass": d_f1 <= gcfg["max_macro_f1_drop"], "drop": d_f1, "max": gcfg["max_macro_f1_drop"]},
         "iii_fa_per_hour": {"pass": d_fa <= gcfg["max_fa_per_h_rise"], "rise": d_fa, "max": gcfg["max_fa_per_h_rise"],
                             "cand": cand["fa_per_hour"], "ref": ref["fa_per_hour"]}}
    ok = all(v["pass"] for v in C.values())
    reasons = []
    if bad_i:
        reasons.append("(i) recall drop > %g on class(es) %s" % (gcfg["max_recall_drop"],
                                                                 {c: round(d, 5) for c, d in bad_i.items()}))
    if not C["ii_macro_f1_nonrare"]["pass"]:
        reasons.append(f"(ii) non-rare macro-F1 drop {d_f1:.5f} > {gcfg['max_macro_f1_drop']}")
    if not C["iii_fa_per_hour"]["pass"]:
        reasons.append(f"(iii) FA/h rise {d_fa:.3f} > {gcfg['max_fa_per_h_rise']}")
    rare = [c for c in range(len(cand["support"])) if cand["support"][c] > 0 and c not in nonrare]
    return {"status": PASS if ok else FAIL, "pass": ok, "conditions": C, "reason": "; ".join(reasons) or "all three hold",
            "rare_not_gated": rare}


def paired(arm: list, ref: list, level: float = 0.95) -> dict:
    """Mean and t-CI over seeds of (arm - ref), paired by seed."""
    d = np.asarray(arm, float) - np.asarray(ref, float)
    out = PM.t_ci(d.tolist(), level)
    out["diffs"] = d.tolist()
    return out


def forgetting(before: list, after: list, level: float = 0.95) -> dict:
    """Forgetting = before - after (positive = the update lost performance), per seed, with a t-CI."""
    return paired(before, after, level)


def verdict_a2s4(forget_pg: list, forget_gl: list, aff_pg: list, aff_gl: list, time_pg: list, time_gl: list,
                 vcfg: dict, level: float = 0.95) -> dict:
    """Amendment 2 section 4: per-group WINS iff [forgetting lower (paired CI of per-group - global over the seeds
    entirely below 0) OR (|mean difference| <= forgetting_equal_tol AND mean global time / mean per-group time >=
    time_ratio)] AND mean(affected-group macro-F1 per-group - global) >= -affected_group_tol."""
    d = paired(forget_pg, forget_gl, level)
    lower = bool(np.isfinite(d["hi"]) and d["hi"] < 0)
    equal = bool(abs(d["mean"]) <= vcfg["forgetting_equal_tol"])
    tp, tg = float(np.mean(time_pg)), float(np.mean(time_gl))
    ratio = tg / tp if tp > 0 else float("inf")
    cheaper = bool(ratio >= vcfg["time_ratio"])
    a = paired(aff_pg, aff_gl, level)
    aff_ok = bool(a["mean"] >= -vcfg["affected_group_tol"])
    wins = (lower or (equal and cheaper)) and aff_ok
    return {"verdict": "WINS" if wins else "DOES_NOT_WIN", "wins": wins,
            "forgetting_diff_pg_minus_global": d, "forgetting_lower": lower, "forgetting_equal_within_tol": equal,
            "time_mean_s": {"per_group": tp, "global": tg}, "time_ratio_global_over_per_group": ratio,
            "time_cheaper": cheaper, "affected_group_diff_pg_minus_global": a, "affected_group_ok": aff_ok,
            "rule": "WINS iff [forgetting lower (CI excludes 0) OR (equal within %g AND >= %gx lower retrain time)] AND "
                    "affected-group macro-F1 not worse by more than %g" % (vcfg["forgetting_equal_tol"], vcfg["time_ratio"],
                                                                           vcfg["affected_group_tol"])}


def poisoning_verdict(quarantined: bool, gate_pass_seed0: bool) -> str:
    if quarantined:
        return "CAUGHT_BY_VALIDATOR"
    return "NOT_CAUGHT" if gate_pass_seed0 else "CAUGHT_BY_GATE"


def flip_labels(label_id, target_class: int, to_class: int, frac: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Poisoning: round(frac x n_target) seeded-random labels of target_class -> to_class. Returns (new labels, flipped)."""
    lid = np.asarray(label_id, np.int64).copy()
    ix = np.flatnonzero(lid == target_class)
    k = int(round(frac * len(ix)))
    rng = np.random.default_rng(seed)
    sel = np.sort(rng.permutation(ix)[:k]) if k < len(ix) else ix
    lid[sel] = to_class
    flipped = np.zeros(len(lid), bool)
    flipped[sel] = True
    return lid, flipped


def poison_targets(label_id, K: int, nonrare: list[int], benign_id: int = 0) -> dict:
    """P1 target = the most frequent attack class in the batch; P2 target = the least frequent NON-RARE attack class in
    the batch (non-rare = the gate's val-B rule). Ties -> the lower class id."""
    cnt = np.bincount(np.asarray(label_id, np.int64), minlength=K)[:K]
    att = [c for c in range(K) if c != benign_id and cnt[c] > 0]
    p1 = max(att, key=lambda c: (cnt[c], -c)) if att else None
    nr = [c for c in att if c in nonrare]
    p2 = min(nr, key=lambda c: (cnt[c], c)) if nr else None
    return {"p1": p1, "p2": p2, "counts": cnt.tolist()}
