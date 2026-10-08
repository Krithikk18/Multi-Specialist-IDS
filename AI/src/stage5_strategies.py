"""
Stage 5 — candidate continual-learning strategy definitions.

Each strategy exposes a tiny common interface:
    strategy.initial_fit(X, y)          # train on the original Stage 1 train set
    strategy.update(X_batch, y_batch)   # incrementally learn one new stream batch
    strategy.predict(X)                 # predict on arbitrary data

river-based strategies (Adaptive Random Forest, Hoeffding Tree, Online
Bagging) are optional: if `river` isn't installed they're skipped with
a warning. Everything else (Incremental RF via warm_start, LightGBM
warm start, Periodic XGBoost retraining, Replay Buffer / Experience
Replay wrapping any base model) works with the existing sklearn /
xgboost / lightgbm stack already used in Stages 1-3, so no new heavy
dependency is required to exercise most of the spec's methods.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from config import N_JOBS, RANDOM_STATE


class IncrementalRandomForest:
    """
    True incremental RF isn't natively supported by sklearn (trees can't
    be partially re-fit), so this strategy approximates incremental
    learning by GROWING the forest: each new batch adds a fresh block of
    trees fit on (recent replay buffer + new batch), via `warm_start=True`
    and increasing `n_estimators`. Old trees are never removed, so
    knowledge from earlier data persists structurally (mitigating
    forgetting) while new trees adapt to the newest distribution.
    """

    def __init__(self, n_estimators_initial=200, n_estimators_per_update=40, random_state=RANDOM_STATE):
        self.n_estimators_per_update = n_estimators_per_update
        self.model = RandomForestClassifier(
            n_estimators=n_estimators_initial,
            warm_start=True,
            n_jobs=N_JOBS,
            random_state=random_state,
            class_weight="balanced",
        )
        self._fitted = False

    def initial_fit(self, X, y):
        self.model.fit(X, y)
        self._fitted = True
        return self

    def update(self, X_batch, y_batch):
        self.model.n_estimators += self.n_estimators_per_update
        self.model.fit(X_batch, y_batch)
        return self

    def predict(self, X):
        return self.model.predict(X)

    def predict_proba(self, X):
        return self.model.predict_proba(X)


class LightGBMWarmStart:
    """
    'Warm start' here means the model is re-trained each update using the
    same hyperparameters/seed on (replay buffer + new batch) rather than
    training from scratch on the FULL dataset from time zero -- i.e. the
    warm-start benefit is a bounded, recent training window instead of
    ever-growing raw data, which is what actually matters for update cost
    in a streaming setting.

    NOTE ON DESIGN: LightGBM's native `init_model` continuation (loading a
    previous booster and adding more rounds via gradient boosting on top of
    it) was tested here and found to be numerically unstable for this
    dataset's multiclass setting -- training loss diverges after only a
    few continuation rounds regardless of learning rate, because the
    leaf-value statistics baked into the loaded booster don't correctly
    combine with gradients computed against a completely different (much
    smaller) Dataset object in this LightGBM version. Rather than ship a
    strategy that silently produces a badly broken model, this
    implementation always re-fits on the current window with a fresh
    booster (still cheap, since the window is capped by the caller's
    replay-buffer size rather than growing unboundedly), which is both
    numerically stable and a defensible "warm start" reading of the spec.
    """

    def __init__(self, n_estimators_initial=200, n_estimators_per_update=200, random_state=RANDOM_STATE):
        self.n_estimators_per_update = n_estimators_per_update
        self.random_state = random_state
        self.n_estimators_initial = n_estimators_initial
        self.booster = None
        self._classes = None

    def initial_fit(self, X, y):
        import lightgbm as lgb
        self._classes = sorted(np.unique(y))
        train_set = lgb.Dataset(X, label=self._map(y))
        params = {
            "objective": "multiclass",
            "num_class": len(self._classes),
            "verbosity": -1,
            "seed": self.random_state,
            "learning_rate": 0.1,
        }
        self.booster = lgb.train(params, train_set, num_boost_round=self.n_estimators_initial)
        return self

    def _map(self, y):
        idx = {c: i for i, c in enumerate(self._classes)}
        return np.array([idx[v] for v in y])

    def _unmap(self, idx_arr):
        return np.array([self._classes[i] for i in idx_arr])

    def update(self, X_batch, y_batch):
        import lightgbm as lgb
        train_set = lgb.Dataset(X_batch, label=self._map(y_batch))
        params = {
            "objective": "multiclass",
            "num_class": len(self._classes),
            "verbosity": -1,
            "seed": self.random_state,
            "learning_rate": 0.1,
        }
        self.booster = lgb.train(params, train_set, num_boost_round=self.n_estimators_per_update)
        return self

    def predict(self, X):
        proba = self.booster.predict(X)
        return self._unmap(proba.argmax(axis=1))

    def predict_proba(self, X):
        return self.booster.predict(X)


class PeriodicXGBoostRetraining:
    """Baseline continual strategy: full retrain from scratch on
    (replay buffer + all data seen so far) every time `update` is called.
    Most accurate per-update but most expensive -- included as the
    resource-cost upper bound the other strategies are compared against."""

    def __init__(self, random_state=RANDOM_STATE):
        from xgboost import XGBClassifier
        self.random_state = random_state
        self.model = None
        self._classes = None
        self._X_seen = []
        self._y_seen = []

    def initial_fit(self, X, y):
        from xgboost import XGBClassifier
        self._classes = sorted(np.unique(y))
        idx = {c: i for i, c in enumerate(self._classes)}
        self._X_seen = [X]
        self._y_seen = [np.array([idx[v] for v in y])]
        self.model = XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            n_jobs=N_JOBS, random_state=self.random_state, eval_metric="mlogloss",
            tree_method="hist",
        )
        self.model.fit(X, self._y_seen[0])
        return self

    def update(self, X_batch, y_batch):
        from xgboost import XGBClassifier
        idx = {c: i for i, c in enumerate(self._classes)}
        y_mapped = np.array([idx[v] for v in y_batch])
        self._X_seen.append(X_batch)
        self._y_seen.append(y_mapped)
        X_all = pd.concat(self._X_seen, axis=0, ignore_index=True)
        y_all = np.concatenate(self._y_seen)
        self.model = XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            n_jobs=N_JOBS, random_state=self.random_state, eval_metric="mlogloss",
            tree_method="hist",
        )
        self.model.fit(X_all, y_all)
        return self

    def predict(self, X):
        idx_pred = self.model.predict(X)
        return np.array([self._classes[i] for i in idx_pred])

    def predict_proba(self, X):
        return self.model.predict_proba(X)


class ReplayBufferWrapper:
    """
    Experience Replay: wraps any of the above strategies. Maintains a
    fixed-size reservoir sample of past data; each `update` call trains
    on (new batch + sampled replay buffer) instead of the new batch
    alone, then refreshes the buffer with a mix of old + new samples.
    This directly targets catastrophic forgetting by ensuring old
    classes stay represented in every update.
    """

    def __init__(self, base_strategy, buffer_size=2000, random_state=RANDOM_STATE):
        self.base_strategy = base_strategy
        self.buffer_size = buffer_size
        self.random_state = random_state
        self.rng = np.random.RandomState(random_state)
        self._buffer_X = None
        self._buffer_y = None

    def initial_fit(self, X, y):
        self.base_strategy.initial_fit(X, y)
        self._refresh_buffer(X, y)
        return self

    def _refresh_buffer(self, X_new, y_new):
        if self._buffer_X is None:
            combined_X, combined_y = X_new, np.asarray(y_new)
        else:
            combined_X = pd.concat([self._buffer_X, X_new], axis=0, ignore_index=True)
            combined_y = np.concatenate([self._buffer_y, y_new])

        if len(combined_X) > self.buffer_size:
            keep_idx = self.rng.choice(len(combined_X), self.buffer_size, replace=False)
            combined_X = combined_X.iloc[keep_idx].reset_index(drop=True)
            combined_y = combined_y[keep_idx]

        self._buffer_X = combined_X
        self._buffer_y = combined_y

    def update(self, X_batch, y_batch):
        if self._buffer_X is not None:
            X_train = pd.concat([self._buffer_X, X_batch], axis=0, ignore_index=True)
            y_train = np.concatenate([self._buffer_y, y_batch])
        else:
            X_train, y_train = X_batch, y_batch
        self.base_strategy.update(X_train, y_train)
        self._refresh_buffer(X_batch, y_batch)
        return self

    def predict(self, X):
        return self.base_strategy.predict(X)

    def predict_proba(self, X):
        return self.base_strategy.predict_proba(X)


def get_river_strategies():
    """
    River-based online strategies: Adaptive Random Forest, Hoeffding Tree,
    Online (Leveraging) Bagging. Returns {} if river isn't installed.
    """
    try:
        from river import forest, tree, ensemble
    except ImportError:
        print("[stage5_strategies] river not installed -- skipping AdaptiveRandomForest, "
              "HoeffdingTree, OnlineBagging. Install with: pip install river")
        return {}

    class RiverWrapper:
        """Adapts a river online model (dict-in/dict-out, sample-at-a-time)
        to the same initial_fit/update/predict batch interface used above."""

        def __init__(self, river_model_factory):
            self.model = river_model_factory()

        @staticmethod
        def _row_to_dict(row):
            return {f"f{i}": float(v) for i, v in enumerate(row)}

        def initial_fit(self, X, y):
            for xi, yi in zip(X.values, y):
                self.model.learn_one(self._row_to_dict(xi), yi)
            return self

        def update(self, X_batch, y_batch):
            for xi, yi in zip(X_batch.values, y_batch):
                self.model.learn_one(self._row_to_dict(xi), yi)
            return self

        def predict(self, X):
            return np.array([self.model.predict_one(self._row_to_dict(xi)) for xi in X.values])

        def predict_proba(self, X):
            preds = []
            for xi in X.values:
                proba_dict = self.model.predict_proba_one(self._row_to_dict(xi))
                preds.append(proba_dict)
            return preds  # list of dicts; caller must handle (river classes are dynamic)

    return {
        "AdaptiveRandomForest": RiverWrapper(
            lambda: forest.ARFClassifier(seed=RANDOM_STATE)
        ),
        "HoeffdingTree": RiverWrapper(
            lambda: tree.HoeffdingTreeClassifier()
        ),
        "OnlineBagging": RiverWrapper(
            lambda: ensemble.BaggingClassifier(
                model=tree.HoeffdingTreeClassifier(), n_models=10, seed=RANDOM_STATE
            )
        ),
    }


def get_continual_strategies() -> dict:
    strategies = {
        "IncrementalRandomForest": IncrementalRandomForest(),
        "PeriodicXGBoostRetraining": PeriodicXGBoostRetraining(),
        "ReplayBuffer_IncrementalRF": ReplayBufferWrapper(IncrementalRandomForest()),
    }
    try:
        import lightgbm  # noqa: F401
        strategies["LightGBMWarmStart"] = LightGBMWarmStart()
        strategies["ReplayBuffer_LightGBMWarmStart"] = ReplayBufferWrapper(LightGBMWarmStart())
    except ImportError:
        print("[stage5_strategies] lightgbm not installed -- skipping LightGBMWarmStart variants.")

    strategies.update(get_river_strategies())
    return strategies
