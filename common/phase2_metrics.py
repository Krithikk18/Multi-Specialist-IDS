"""common/phase2_metrics.py -- pre-registered Phase 2 metrics (docs/V2_PREREG_PHASE2.md section 4), pure functions.

  per_class_prf / classification_metrics   P / R / F1, macro-F1 (all classes with support, non-rare), weighted F1,
                                           MCC, balanced accuracy, confusion matrix, OvR ROC- / PR-AUC
  t_ci, clopper_pearson, garwood           mean +- t-CI over seeds; exact binomial / Poisson CIs
  benign_hours, fp_threshold               false-alarm denominator (08's active-segment rule); V1's <= k FP rule
  softmax, fit_temperature, ece_*, brier   Stage 2 calibration
Classes with 0 support in an evaluation set are N/A (NaN), never 0.
"""

from __future__ import annotations

import numpy as np
from scipy import optimize, stats


# --------------------------------------------------------------------------- confidence intervals
def t_ci(values, level: float = 0.95) -> dict:
    v = np.asarray([x for x in values if x is not None and np.isfinite(x)], dtype=float)
    n = len(v)
    if n == 0:
        return {"mean": float("nan"), "lo": float("nan"), "hi": float("nan"), "n": 0}
    m = float(v.mean())
    if n == 1:
        return {"mean": m, "lo": float("nan"), "hi": float("nan"), "n": 1}
    h = float(stats.t.ppf(0.5 + level / 2, n - 1) * v.std(ddof=1) / np.sqrt(n))
    return {"mean": m, "lo": m - h, "hi": m + h, "n": n}


def clopper_pearson(k: int, n: int, level: float = 0.95) -> tuple[float, float]:
    if n <= 0:
        return float("nan"), float("nan")
    a = 1 - level
    lo = 0.0 if k == 0 else float(stats.beta.ppf(a / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(stats.beta.ppf(1 - a / 2, k + 1, n - k))
    return lo, hi


def garwood(k: int, level: float = 0.95) -> tuple[float, float]:
    """Exact Poisson CI for a count k (V1 step 10's formula)."""
    a = 1 - level
    lo = 0.0 if k == 0 else float(stats.chi2.ppf(a / 2, 2 * k) / 2)
    return lo, float(stats.chi2.ppf(1 - a / 2, 2 * k + 2) / 2)


# --------------------------------------------------------------------------- classification
def confusion(y: np.ndarray, pred: np.ndarray, K: int) -> np.ndarray:
    return np.bincount(np.asarray(y) * K + np.asarray(pred), minlength=K * K).reshape(K, K)


def per_class_prf(cm: np.ndarray) -> dict:
    tp = np.diag(cm).astype(float)
    support = cm.sum(1).astype(float)
    predicted = cm.sum(0).astype(float)
    with np.errstate(invalid="ignore", divide="ignore"):
        prec = np.where(predicted > 0, tp / predicted, np.where(support > 0, 0.0, np.nan))
        rec = np.where(support > 0, tp / support, np.nan)
        f1 = np.where(support > 0, np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0.0), np.nan)
    return {"support": support.astype(int), "tp": tp.astype(int), "predicted": predicted.astype(int),
            "precision": prec, "recall": rec, "f1": f1}


def mcc_multiclass(cm: np.ndarray) -> float:
    """Gorodkin's multiclass MCC (= sklearn matthews_corrcoef)."""
    cm = cm.astype(float)
    t, p, c, s = cm.sum(1), cm.sum(0), np.trace(cm), cm.sum()
    den = np.sqrt((s * s - (p * p).sum()) * (s * s - (t * t).sum()))
    return float((c * s - (t * p).sum()) / den) if den > 0 else 0.0


def ovr_auc(y: np.ndarray, P: np.ndarray, K: int) -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score
    roc, pr = np.full(K, np.nan), np.full(K, np.nan)
    for c in range(K):
        pos = np.asarray(y) == c
        if 0 < pos.sum() < len(pos):
            roc[c] = roc_auc_score(pos, P[:, c])
            pr[c] = average_precision_score(pos, P[:, c])
    return {"roc_auc": roc, "pr_auc": pr}


def classification_metrics(y: np.ndarray, P: np.ndarray, K: int, min_val_flows: int, level: float = 0.95,
                           with_auc: bool = True) -> dict:
    """All per-seed classification metrics of one evaluation set (prediction = argmax)."""
    y = np.asarray(y)
    pred = np.asarray(P).argmax(1)
    cm = confusion(y, pred, K)
    pc = per_class_prf(cm)
    sup = pc["support"]
    present, nonrare = sup > 0, sup >= min_val_flows
    rare = present & ~nonrare
    out = {"n": int(len(y)), "confusion": cm.tolist(), "support": sup.tolist(),
           "precision": pc["precision"].tolist(), "recall": pc["recall"].tolist(), "f1": pc["f1"].tolist(),
           "macro_f1_all": float(np.nanmean(pc["f1"][present])) if present.any() else float("nan"),
           "macro_f1_nonrare": float(np.nanmean(pc["f1"][nonrare])) if nonrare.any() else float("nan"),
           "weighted_f1": float((pc["f1"][present] * sup[present]).sum() / sup[present].sum()) if present.any() else float("nan"),
           "mcc": mcc_multiclass(cm),
           "balanced_accuracy": float(np.nanmean(pc["recall"][present])) if present.any() else float("nan"),
           "rare_classes": np.flatnonzero(rare).tolist(),
           "recall_cp": [list(clopper_pearson(int(pc["tp"][c]), int(sup[c]), level)) if sup[c] > 0 else [None, None]
                         for c in range(K)]}
    if with_auc:
        a = ovr_auc(y, P, K)
        out["roc_auc"], out["pr_auc"] = a["roc_auc"].tolist(), a["pr_auc"].tolist()
    return out


# --------------------------------------------------------------------------- false alarms
def active_segments(secs: np.ndarray, idle_gap: float) -> np.ndarray:
    """[start, end) segments of whole-second flow starts: a pause > idle_gap ends one; end = last start + 1 (08)."""
    s = np.unique(np.asarray(secs, dtype=np.int64))
    if len(s) == 0:
        return np.zeros((0, 2))
    brk = np.flatnonzero(np.diff(s) > idle_gap)
    return np.c_[np.r_[s[0], s[brk + 1]], np.r_[s[brk], s[-1]] + 1].astype(float)


def benign_hours(session: np.ndarray, start_ts: np.ndarray, benign_eval: np.ndarray, idle_gap: float) -> float:
    """Hours of the per-session active segments (from ALL given flow starts) holding >= 1 flow of benign_eval."""
    session, start_ts, benign_eval = np.asarray(session), np.asarray(start_ts, np.int64), np.asarray(benign_eval, bool)
    total = 0.0
    for s in np.unique(session[benign_eval]):
        m = session == s
        seg = active_segments(start_ts[m], idle_gap)
        bt = np.unique(start_ts[m & benign_eval])
        k = np.unique(np.searchsorted(seg[:, 0], bt, side="right") - 1)
        total += float((seg[k, 1] - seg[k, 0]).sum())
    return total / 3600.0


def fp_threshold(scores: np.ndarray, is_benign: np.ndarray, max_fp: int) -> float:
    """V1's rule: the lowest observed score t with #(benign scores >= t) <= max_fp (inf if none)."""
    scores, is_benign = np.asarray(scores, float), np.asarray(is_benign, bool)
    cand = np.unique(scores)
    b = np.sort(scores[is_benign])
    fp = len(b) - np.searchsorted(b, cand, side="left")               # benign >= t
    ok = cand[fp <= max_fp]
    return float(ok.min()) if len(ok) else float("inf")


# --------------------------------------------------------------------------- calibration
def softmax(z: np.ndarray, T: float = 1.0) -> np.ndarray:
    z = np.asarray(z, dtype=np.float64) / T
    z = z - z.max(1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(1, keepdims=True)


def nll(z: np.ndarray, y: np.ndarray, T: float) -> float:
    """Mean -log softmax(z / T)[y], computed relative to the true-class logit so that very confident correct rows
    keep their tiny (non-zero) loss: with d = z / T - z_y / T and m = max(d) >= 0,
    nll = log1p(sum_{j != y} e^{d_j}) if m == 0, else m + log(e^{-m} + sum_{j != y} e^{d_j - m}).
    (The naive log-sum-exp rounds 1 + 1e-60 to 1, flattening the loss and breaking the temperature fit.)"""
    z = np.asarray(z, dtype=np.float64) / T
    y = np.asarray(y)
    n = np.arange(len(y))
    d = z - z[n, y][:, None]
    m = d.max(1)
    e = np.exp(d - m[:, None])
    e[n, y] = 0.0
    other = e.sum(1)
    out = np.where(m == 0, np.log1p(other), m + np.log(np.exp(-m) + other))
    return float(out.mean())


def fit_temperature(z: np.ndarray, y: np.ndarray, bounds=(0.05, 20.0)) -> float:
    """One-parameter temperature minimising the val NLL (bounded search on log T)."""
    r = optimize.minimize_scalar(lambda lt: nll(z, y, float(np.exp(lt))), bounds=(np.log(bounds[0]), np.log(bounds[1])),
                                 method="bounded", options={"xatol": 1e-5})
    return float(np.exp(r.x))


def _ece(conf: np.ndarray, correct: np.ndarray, bins: int) -> float:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(conf, edges[1:-1], right=True), 0, bins - 1)
    e = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            e += m.mean() * abs(correct[m].mean() - conf[m].mean())
    return float(e)


def ece_top(P: np.ndarray, y: np.ndarray, bins: int = 15) -> float:
    return _ece(P.max(1), (P.argmax(1) == y).astype(float), bins)


def ece_classwise(P: np.ndarray, y: np.ndarray, bins: int = 15) -> list:
    """One-vs-rest ECE per class (NaN for a class absent from y)."""
    return [(_ece(P[:, c], (y == c).astype(float), bins) if (y == c).any() else float("nan")) for c in range(P.shape[1])]


def brier(P: np.ndarray, y: np.ndarray) -> float:
    Y = np.zeros_like(P, dtype=float)
    Y[np.arange(len(y)), y] = 1.0
    return float(((P - Y) ** 2).sum(1).mean())


def reliability(conf: np.ndarray, correct: np.ndarray, bins: int = 15) -> dict:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(conf, edges[1:-1], right=True), 0, bins - 1)
    out = {"bin_mid": [], "conf": [], "acc": [], "n": []}
    for b in range(bins):
        m = idx == b
        if m.any():
            out["bin_mid"].append(float((edges[b] + edges[b + 1]) / 2))
            out["conf"].append(float(conf[m].mean()))
            out["acc"].append(float(correct[m].mean()))
            out["n"].append(int(m.sum()))
    return out
