"""
Stage 3 — candidate anomaly-detector definitions.

Deep SVDD and the (V)Autoencoder are torch-based and optional: if torch
isn't installed, they're skipped with a warning rather than crashing
the run.
"""

from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

from config import N_JOBS, RANDOM_STATE


def get_anomaly_zoo() -> dict:
    """
    Returns {name: estimator}. All are fit on KNOWN-class training data
    only (one-class setup); at inference time they output an anomaly
    score / label where "outlier" = candidate zero-day.

    Note: LocalOutlierFactor in its default sklearn form only supports
    `fit_predict` on the same data it was fit on (transductive). For a
    detector usable on new/unseen inference data we use it with
    `novelty=True`, which enables `.predict()` on new samples.
    """
    zoo = {
        "IsolationForest": IsolationForest(
            n_estimators=300,
            contamination="auto",
            n_jobs=N_JOBS,
            random_state=RANDOM_STATE,
        ),
        "LocalOutlierFactor": LocalOutlierFactor(
            n_neighbors=35,
            novelty=True,
            n_jobs=N_JOBS,
        ),
        "OneClassSVM": OneClassSVM(
            kernel="rbf",
            nu=0.05,
            gamma="scale",
        ),
        "EllipticEnvelope": EllipticEnvelope(
            contamination=0.05,
            random_state=RANDOM_STATE,
        ),
    }

    try:
        import torch  # noqa: F401
        from stage3_deep_models import AutoencoderDetector, VAEDetector, DeepSVDDDetector
        zoo["Autoencoder"] = AutoencoderDetector(random_state=RANDOM_STATE)
        zoo["VariationalAutoencoder"] = VAEDetector(random_state=RANDOM_STATE)
        zoo["DeepSVDD"] = DeepSVDDDetector(random_state=RANDOM_STATE)
    except ImportError:
        print("[stage3_models] torch not installed -- skipping Autoencoder, "
              "VariationalAutoencoder, DeepSVDD. Install with: pip install torch")

    return zoo


# Models whose native output is {-1, 1} (outlier/inlier) via .predict()
SKLEARN_STYLE_LABEL_MODELS = {"IsolationForest", "LocalOutlierFactor", "OneClassSVM", "EllipticEnvelope"}
