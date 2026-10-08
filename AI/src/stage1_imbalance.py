"""
Imbalance-handling strategies.

The workflow spec asks to "evaluate SMOTE, ADASYN, Random Oversampling,
Class Weights, choose whichever improves validation performance." This
is wired into Stage 1: for the single best base model architecture
(chosen by default un-resampled performance), we re-fit with each
resampling strategy and compare on the validation set. Class weights
are handled separately (baked into the estimator itself via
`class_weight="balanced"` / `auto_class_weights`, already set in
stage1_models.py) so here we only need the data-level resamplers.
"""

from imblearn.over_sampling import ADASYN, RandomOverSampler, SMOTE

from config import N_JOBS, RANDOM_STATE


def get_resamplers() -> dict:
    """
    Returns {name: imblearn-API sampler}. 'ClassWeightOnly' is a no-op
    marker meaning "don't resample, rely on the estimator's built-in
    class_weight" -- included so it shows up side-by-side in the
    comparison table.
    """
    return {
        "ClassWeightOnly": None,
        "RandomOverSampler": RandomOverSampler(random_state=RANDOM_STATE),
        "SMOTE": SMOTE(random_state=RANDOM_STATE),
        "ADASYN": ADASYN(random_state=RANDOM_STATE),
    }
