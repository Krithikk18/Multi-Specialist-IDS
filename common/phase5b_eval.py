"""common/phase5b_eval.py -- Phase 5B metrics and pre-registered verdict rules (docs/V2_PREREG_PHASE5B.md sections 3-5).
Pure functions over arrays / per-seed lists.

    eval_arm(y, pred, K, nonrare, session, start_ts, gap)   per-class recall / F1, macro-F1 non-rare, FA count + FA/h
    paired_ci(a, b, ev)                                    mean of (b - a) by seed + 95 % percentile bootstrap CI
    noninferiority(f1_ctx, f1_glob, fa_ctx, fa_glob, ni, ev)   PASS / FAIL
    flip_agreement(pred, pred_flip, mask)                  share of flows whose predicted class is unchanged
    h_c1(agree_ctx, agree_glob, agree_ctx_b, agree_glob_b, ev) HOLDS iff CI lo > 0 on all flows AND on benign flows
    h_c2(rec, ev)                                          HOLDS iff CI lo of (Δ_ctx - Δ_flow) > 0 (per class)
    h_c3(pairs, fa_by_seed, fa_ref, zd, ev)                HOLDS iff CI lo of mean miss-recall >= recall_lo_min AND
                                                           FA/h CI hi <= fa_ref
Bootstrap = common/zeroday_metrics.bootstrap_mean_ci (resample the units with replacement, numpy default_rng(seed)).
"""

from __future__ import annotations

import numpy as np

from common import cl_gate as CG
from common import zeroday_metrics as ZM

HOLDS, NOT_HOLDS, PASS, FAIL = "HOLDS", "DOES_NOT_HOLD", "PASS", "FAIL"


def eval_arm(y, pred, K: int, nonrare: list[int], session, start_ts, gap: float) -> dict:
    return CG.eval_set(y, pred, K, nonrare, session, start_ts, gap)


def boot(values, ev: dict) -> dict:
    return ZM.bootstrap_mean_ci(values, ev["bootstrap_resamples"], ev["bootstrap_seed"], ev["ci_level"])


def paired_ci(a, b, ev: dict) -> dict:
    """b - a paired by position (seed)."""
    d = np.asarray(b, float) - np.asarray(a, float)
    out = boot(d, ev)
    out["diffs"] = d.tolist()
    return out


def noninferiority(f1_ctx, f1_glob, fa_ctx, fa_glob, ni: dict, ev: dict) -> dict:
    f1 = paired_ci(f1_glob, f1_ctx, ev)
    dfa = np.asarray(fa_ctx, float) - np.asarray(fa_glob, float)
    med = float(np.median(dfa))
    a = bool(f1["n"] > 0 and f1["lo"] > -ni["macro_f1_margin"])
    b = bool(med <= ni["fa_count_margin"])
    return {"status": PASS if (a and b) else FAIL, "macro_f1_diff": f1, "macro_f1_ok": a, "fa_count_diffs": dfa.tolist(),
            "fa_count_diff_median": med, "fa_ok": b, "macro_f1_margin": ni["macro_f1_margin"],
            "fa_count_margin": ni["fa_count_margin"]}


def flip_agreement(pred, pred_flip, mask=None) -> float:
    pred, pred_flip = np.asarray(pred), np.asarray(pred_flip)
    m = np.ones(len(pred), bool) if mask is None else np.asarray(mask, bool)
    return float((pred[m] == pred_flip[m]).mean()) if m.any() else float("nan")


def h_c1(agree_ctx, agree_glob, agree_ctx_benign, agree_glob_benign, ev: dict) -> dict:
    A = paired_ci(agree_glob, agree_ctx, ev)
    B = paired_ci(agree_glob_benign, agree_ctx_benign, ev)
    ok_a, ok_b = bool(A["n"] > 0 and A["lo"] > 0), bool(B["n"] > 0 and B["lo"] > 0)
    return {"verdict": HOLDS if (ok_a and ok_b) else NOT_HOLDS, "all": A, "benign": B, "all_ok": ok_a, "benign_ok": ok_b}


def h_c2(rec: dict, ev: dict) -> dict:
    """rec = {arm: [recall per seed]} for one class; arms GLOBAL, GLOBAL_NOFP, GLOBAL_CTX, GLOBAL_CTX_NOFP."""
    d_flow = np.asarray(rec["GLOBAL_NOFP"], float) - np.asarray(rec["GLOBAL"], float)
    d_ctx = np.asarray(rec["GLOBAL_CTX_NOFP"], float) - np.asarray(rec["GLOBAL_CTX"], float)
    C = paired_ci(d_flow, d_ctx, ev)
    return {"verdict": HOLDS if (C["n"] > 0 and C["lo"] > 0) else NOT_HOLDS, "delta_flow": d_flow.tolist(),
            "delta_ctx": d_ctx.tolist(), "diff": C}


def h_c3(pairs: list[dict], fa_by_seed: list[float], fa_ref: float, zd: dict, ev: dict, classes: list[int]) -> dict:
    """pairs = [{"k", "s", "n_miss", "recall"}]; eligible = k in classes and n_miss >= min_misses."""
    el = [p for p in pairs if p["k"] in classes and p["n_miss"] >= zd["min_misses"] and np.isfinite(p["recall"])]
    R = boot([p["recall"] for p in el], ev)
    F = boot(fa_by_seed, ev)
    a = bool(R["n"] > 0 and R["lo"] >= zd["recall_lo_min"])
    b = bool(F["n"] > 0 and F["hi"] <= fa_ref)
    why = []
    if R["n"] == 0:
        why.append("no eligible pair")
    elif not a:
        why.append(f"miss-recall CI lower bound {R['lo']:.4f} < {zd['recall_lo_min']}")
    if not b:
        why.append(f"FA/h CI upper bound {F['hi']:.3f} > reference {fa_ref:.3f}")
    return {"verdict": HOLDS if (a and b) else NOT_HOLDS, "recall": R, "fa": F, "fa_ref": float(fa_ref),
            "recall_ok": a, "fa_ok": b, "eligible_pairs": [{"k": p["k"], "s": p["s"], "n_miss": p["n_miss"],
                                                            "recall": p["recall"]} for p in el],
            "reason": "; ".join(why) or "both conditions hold"}
