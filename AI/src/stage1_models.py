"""
Stage 1 — candidate model definitions.

SVM and KNN are intentionally excluded (per project decision: too slow on
~90k rows x 47 features for a CPU-only WSL environment). All other
classical models from the spec are included.

XGBoost / LightGBM / CatBoost are optional at import time: if a library
isn't installed, that model is skipped with a clear warning rather than
crashing the whole run, since the user may run this before installing
every optional dependency in requirements.txt.
"""

from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from config import N_JOBS, RANDOM_STATE


def get_model_zoo() -> dict:
    """Returns {model_name: sklearn-API estimator} for every available model."""
    zoo = {
        "RandomForest": RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            n_jobs=N_JOBS,
            random_state=RANDOM_STATE,
            class_weight="balanced",
        ),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=300,
            max_depth=None,
            n_jobs=N_JOBS,
            random_state=RANDOM_STATE,
            class_weight="balanced",
        ),
        "DecisionTree": DecisionTreeClassifier(
            max_depth=None,
            random_state=RANDOM_STATE,
            class_weight="balanced",
        ),
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            random_state=RANDOM_STATE,
            class_weight="balanced",
        ),
    }

    try:
        from xgboost import XGBClassifier
        zoo["XGBoost"] = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.1,
            n_jobs=N_JOBS,
            random_state=RANDOM_STATE,
            eval_metric="mlogloss",
            tree_method="hist",
        )
    except ImportError:
        print("[stage1_models] xgboost not installed -- skipping XGBoost. "
              "Install with: pip install xgboost")

    try:
        from lightgbm import LGBMClassifier
        zoo["LightGBM"] = LGBMClassifier(
            n_estimators=300,
            max_depth=-1,
            learning_rate=0.1,
            n_jobs=N_JOBS,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            verbosity=-1,
        )
    except ImportError:
        print("[stage1_models] lightgbm not installed -- skipping LightGBM. "
              "Install with: pip install lightgbm")

    try:
        from catboost import CatBoostClassifier
        zoo["CatBoost"] = CatBoostClassifier(
            iterations=300,
            depth=8,
            learning_rate=0.1,
            random_seed=RANDOM_STATE,
            verbose=False,
            auto_class_weights="Balanced",
            thread_count=N_JOBS,
        )
    except ImportError:
        print("[stage1_models] catboost not installed -- skipping CatBoost. "
              "Install with: pip install catboost")

    return zoo


# Models whose predict_proba is well-calibratable natively via tree
# structure (used to decide which models Stage 2 will calibrate).
TREE_ENSEMBLE_MODELS = {"RandomForest", "ExtraTrees", "XGBoost", "LightGBM", "CatBoost"}
