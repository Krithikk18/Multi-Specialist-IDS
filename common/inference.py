"""common/inference.py -- row -> feature vector -> margins -> temperature-calibrated probabilities -> top-k TreeSHAP.

    inf = Inference(runtime_model, cfg)
    x = inf.vector(row)                                  # float32 (70,), features_v1 order, NaN / +-inf -> 0 (V1 policy)
    z, p = inf.score(X, model_ids)                       # margins (n, K) float64 and P = softmax(z / T_model)
    top = inf.explain(X, model_ids, classes)             # per row: [(feature, value, contribution), ...] top-k |SHAP|

Hot path: plain lists / numpy only (no pandas). Prediction = XGBoost inplace_predict(predict_type="margin") on the
float32 matrix (training fed float32: common/phase2_data.feature_matrix); calibration = common/phase2_metrics.softmax,
the function step 24 fitted the temperatures with. Explanations = XGBoost pred_contribs (exact TreeSHAP, D01), run
only for the rows that became alerts; contributions are for the predicted class's margin. Boosters run single-threaded
(nthread 1: deterministic, and the Pi target is one core per stage).
"""

from __future__ import annotations

import math

import numpy as np

from common import schemas as S
from common.phase2_metrics import softmax


class Inference:
    def __init__(self, rm, cfg: dict):
        self.rm = rm
        self.feats = S.feature_columns()
        self.fill = float(cfg["features"]["nan_inf_to"])
        self.top_k = int(cfg["explain"]["top_k"])
        self.K = len(rm.class_names)
        for m in rm.models.values():
            m.booster.set_param({"nthread": 1})

    def vector(self, row: dict) -> np.ndarray:
        fill = self.fill
        v = [row[f] for f in self.feats]
        v = [x if (isinstance(x, float) and math.isfinite(x)) else _clean(x, fill) for x in v]
        return np.asarray(v, dtype=np.float32)

    def margins(self, X: np.ndarray, model_ids) -> np.ndarray:
        X = np.ascontiguousarray(X, dtype=np.float32)
        z = np.empty((len(X), self.K), dtype=np.float64)
        mids = np.asarray(model_ids, dtype=object)
        for mid in dict.fromkeys(mids.tolist()):
            ix = np.flatnonzero(mids == mid)
            b = self.rm.models[mid].booster
            z[ix] = np.asarray(b.inplace_predict(X[ix], predict_type="margin"), dtype=np.float64).reshape(len(ix), self.K)
        return z

    def calibrate(self, z: np.ndarray, model_ids) -> np.ndarray:
        p = np.empty_like(z)
        mids = np.asarray(model_ids, dtype=object)
        for mid in dict.fromkeys(mids.tolist()):
            ix = np.flatnonzero(mids == mid)
            p[ix] = softmax(z[ix], self.rm.models[mid].temperature)
        return p

    def score(self, X: np.ndarray, model_ids) -> tuple[np.ndarray, np.ndarray]:
        z = self.margins(X, model_ids)
        return z, self.calibrate(z, model_ids)

    def explain(self, X: np.ndarray, model_ids, classes) -> list[list[tuple[str, float, float]]]:
        import xgboost as xgb
        out: list = [None] * len(X)
        mids = np.asarray(model_ids, dtype=object)
        classes = np.asarray(classes, dtype=np.int64)
        for mid in dict.fromkeys(mids.tolist()):
            ix = np.flatnonzero(mids == mid)
            c = np.asarray(self.rm.models[mid].booster.predict(xgb.DMatrix(X[ix]), pred_contribs=True))
            c = c.reshape(len(ix), self.K, len(self.feats) + 1)
            for j, i in enumerate(ix):
                v = c[j, classes[i], :-1]
                top = np.argsort(-np.abs(v), kind="stable")[: self.top_k]
                out[i] = [(self.feats[t], float(X[i, t]), float(v[t])) for t in top]
        return out


def _clean(x, fill: float) -> float:
    try:
        f = float(x)
    except (TypeError, ValueError):
        raise ValueError(f"non-numeric feature value {x!r}") from None
    return f if math.isfinite(f) else fill
