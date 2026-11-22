"""common/zeroday_metrics.py -- Phase 5A metrics, CIs and the Amendment 2 section 3 verdict + section 5 kill-rule line
(docs/V2_PREREG_PHASE5.md sections 5-6). Pure functions over arrays / lists.

    miss_recall(flag, miss)                        -> {"flagged", "n", "recall"} (recall NaN when n == 0)
    bootstrap_mean_ci(values, B, seed, level)      percentile CI of the mean, resampling the values (pairs) with replacement
    fa_rate(flag, is_benign, hours)                -> {"fa_count", "benign_hours", "fa_per_hour"}
    paired_test(pairs, fa_a, fa_b, ev, ...)        (a) recall CI lo > 0, (b) FA/h difference CI hi <= margin, for any arm
                                                   pair (b vs a: d = b - a)
    verdict(pairs, fa, ev, verdict_classes, all_classes)
        prereg reading: verdict classes, pairs with n_miss >= min_misses, support >= min_support_classes classes
        Amendment 2 literal reading: every attack class, every pair with >= 1 miss, no support condition
        same verdict -> it is the verdict; different -> status CONFLICT (no verdict; human decision)
    kill_line(s3_verdict, s4_verdict)              the exact section 5 line
A pair = {"k": class id, "s": seed, "n_miss": int, "recall": {arm: float}}; fa = {arm: {seed: fa_per_hour}}.
"""

from __future__ import annotations

import numpy as np

from common import phase2_metrics as PM

WIN, NO_WIN, CONFLICT = "PER_GROUP_WINS", "DOES_NOT_WIN", "CONFLICT"
A_GLOBAL, A_PER_GROUP, A_RANDOM = "GLOBAL_NORMAL", "PER_GROUP_NORMAL", "RANDOM_GROUP_NORMAL"
KILL_FIRES = "Kill rule §5 FIRES: routing is operational only; no novelty claim."
KILL_NOT = "Kill rule §5 does not fire: the routing novelty claim rests on the zero-day result (§3) alone."
KILL_CONFLICT = "Kill rule §5: not evaluated (the §3 verdict is CONFLICT; a human decision is needed)."


def miss_recall(flag: np.ndarray, miss: np.ndarray) -> dict:
    flag, miss = np.asarray(flag, bool), np.asarray(miss, bool)
    n = int(miss.sum())
    f = int((flag & miss).sum())
    return {"flagged": f, "n": n, "recall": f / n if n else float("nan")}


def bootstrap_mean_ci(values, n_resamples: int, seed: int, level: float = 0.95) -> dict:
    """Percentile bootstrap CI of the mean (equal weights), numpy default_rng(seed), linear percentiles."""
    v = np.asarray(values, dtype=np.float64)
    n = len(v)
    if n == 0:
        return {"mean": float("nan"), "lo": float("nan"), "hi": float("nan"), "n": 0, "resamples": int(n_resamples),
                "seed": int(seed)}
    rng = np.random.default_rng(int(seed))
    idx = rng.integers(0, n, size=(int(n_resamples), n))
    means = v[idx].mean(1)
    a = (1 - level) / 2
    lo, hi = np.percentile(means, [100 * a, 100 * (1 - a)], method="linear")
    return {"mean": float(v.mean()), "lo": float(lo), "hi": float(hi), "n": int(n), "resamples": int(n_resamples),
            "seed": int(seed)}


def t_interval(values, level: float = 0.95) -> dict:
    return PM.t_ci(list(np.asarray(values, dtype=np.float64)), level)


def fa_rate(flag: np.ndarray, is_benign: np.ndarray, hours: float) -> dict:
    flag, b = np.asarray(flag, bool), np.asarray(is_benign, bool)
    c = int((flag & b).sum())
    return {"fa_count": c, "n_benign": int(b.sum()), "benign_hours": float(hours),
            "fa_per_hour": c / hours if hours > 0 else float("nan"),
            "flag_rate": c / int(b.sum()) if b.any() else float("nan")}


def paired_test(pairs: list[dict], fa: dict, ev: dict, arm_a: str, arm_b: str, classes: list[int],
                min_misses: int) -> dict:
    """d = arm_b - arm_a over the pairs of `classes` with n_miss >= min_misses; FA difference over the seeds."""
    use = [p for p in pairs if p["k"] in classes and p["n_miss"] >= min_misses
           and np.isfinite(p["recall"][arm_a]) and np.isfinite(p["recall"][arm_b])]
    d = [p["recall"][arm_b] - p["recall"][arm_a] for p in use]
    B, sd, lvl = ev["bootstrap_resamples"], ev["bootstrap_seed"], ev["ci_level"]
    ci_d = bootstrap_mean_ci(d, B, sd, lvl)
    seeds = sorted(set(fa[arm_a]) & set(fa[arm_b]))
    dfa = [fa[arm_b][s] - fa[arm_a][s] for s in seeds]
    ci_fa = bootstrap_mean_ci(dfa, B, sd, lvl)
    support = sorted({p["k"] for p in use})
    a = bool(ci_d["n"] > 0 and ci_d["lo"] > 0)
    b = bool(ci_fa["n"] > 0 and ci_fa["hi"] <= ev["fa_margin_per_h"])
    return {"arm_a": arm_a, "arm_b": arm_b, "pairs_used": [{"k": p["k"], "s": p["s"], "n_miss": p["n_miss"],
                                                            "d": p["recall"][arm_b] - p["recall"][arm_a]} for p in use],
            "d": d, "ci_d": ci_d, "t_d": t_interval(d, lvl), "fa_seeds": seeds, "fa_diff": dfa, "ci_fa": ci_fa,
            "t_fa": t_interval(dfa, lvl), "a_recall_ci_above_0": a, "b_fa_ci_within_margin": b,
            "support_classes": support, "n_pairs": len(use)}


def _decide(T: dict, min_support: int | None) -> tuple[str, str]:
    if T["n_pairs"] == 0:
        return NO_WIN, "insufficient support: no eligible pair, so the recall CI does not exist and (a) cannot hold"
    if min_support is not None and len(T["support_classes"]) < min_support:
        return NO_WIN, (f"insufficient support: {len(T['support_classes'])} held-out class(es) with an eligible pair "
                        f"< {min_support}")
    a, b = T["a_recall_ci_above_0"], T["b_fa_ci_within_margin"]
    if a and b:
        return WIN, "(a) and (b) hold"
    why = []
    if not a:
        why.append(f"(a) fails: recall-difference CI lower bound {T['ci_d']['lo']:+.4f} <= 0")
    if not b:
        why.append(f"(b) fails: FA/h-difference CI upper bound {T['ci_fa']['hi']:+.3f} > margin")
    return NO_WIN, "; ".join(why)


def verdict(pairs: list[dict], fa: dict, ev: dict, verdict_classes: list[int], all_classes: list[int],
            arm_a: str = A_GLOBAL, arm_b: str = A_PER_GROUP) -> dict:
    """Amendment 2 section 3 under the prereg reading and the literal reading; CONFLICT if they disagree."""
    P = paired_test(pairs, fa, ev, arm_a, arm_b, verdict_classes, ev["min_misses"])
    vP, whyP = _decide(P, ev["min_support_classes"])
    L = paired_test(pairs, fa, ev, arm_a, arm_b, all_classes, 1)
    vL, whyL = _decide(L, None)
    status = vP if vP == vL else CONFLICT
    return {"verdict": status, "prereg": {"verdict": vP, "reason": whyP, **P},
            "literal": {"verdict": vL, "reason": whyL, **L}, "agree": vP == vL,
            "min_misses": ev["min_misses"], "min_support_classes": ev["min_support_classes"],
            "fa_margin_per_h": ev["fa_margin_per_h"]}


def kill_line(s3: str, s4: str) -> str:
    """Amendment 2 section 5 with section 4 = s4 (pinned) and section 3 = s3."""
    if s3 == CONFLICT:
        return KILL_CONFLICT
    if s3 == WIN:
        return KILL_NOT
    if s3 == NO_WIN and s4 == NO_WIN:
        return KILL_FIRES
    if s3 == NO_WIN and s4 == WIN:
        return "Kill rule §5 does not fire: the routing claim is limited to continual learning (§4)."
    raise ValueError(f"unknown verdicts s3={s3!r} s4={s4!r}")


def eligibility_table(pairs: list[dict], classes: list[int], min_misses: int) -> dict:
    return {int(k): {"pairs": sum(p["k"] == k for p in pairs),
                     "eligible": sum(p["k"] == k and p["n_miss"] >= min_misses for p in pairs)} for k in classes}
