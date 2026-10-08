"""
Stage 0 — Dataset Preprocessing
================================
Loads the raw Edge-IIoTset CSV, cleans it, encodes it, holds out two
attack classes entirely (MITM, Fingerprinting) to act as genuine
zero-day / unknown attacks for Stage 3, then produces a stratified
70/15/15 train/val/test split over the remaining 13 known classes.

Outputs
-------
data/processed/X_train.csv, X_val.csv, X_test.csv
data/processed/y_train.csv, y_val.csv, y_test.csv
data/processed/scaler.pkl
data/processed/target_encoder.pkl
data/processed/feature_encoders.pkl
data/processed/feature_columns.json

data/zero_day_holdout/X_zero_day.csv   (MITM + Fingerprinting, scaled with the
                                        SAME scaler/encoders fit on known data)
data/zero_day_holdout/y_zero_day.csv   (original string labels, kept OUT of
                                        target_encoder's known classes)

data/stream/X_stream_batch_{0..N-1}.csv, y_stream_batch_{0..N-1}.csv
    A slice carved out of the training data (before scaling is refit)
    to be replayed later, in Stage 5, as sequential "incoming" batches.

Run
---
    python src/stage0_preprocessing.py
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (
    DROP_COLS,
    N_STREAM_BATCHES,
    PROCESSED_DIR,
    RANDOM_STATE,
    RAW_DATA_PATH,
    STREAM_DIR,
    STREAM_FRAC_OF_TRAIN,
    TARGET_COL,
    TEST_FRAC,
    TRAIN_FRAC,
    VAL_FRAC,
    ZERO_DAY_CLASSES,
    ZERO_DAY_DIR,
)


def log(msg: str) -> None:
    print(msg, flush=True)


def main() -> None:
    assert abs(TRAIN_FRAC + VAL_FRAC + TEST_FRAC - 1.0) < 1e-9

    # ----------------------------------------------------------------
    # 1. LOAD
    # ----------------------------------------------------------------
    log("\nLoading dataset...")
    sample = pd.read_csv(RAW_DATA_PATH, nrows=5)
    use_cols = [c for c in sample.columns if c not in DROP_COLS]
    df = pd.read_csv(RAW_DATA_PATH, usecols=use_cols, low_memory=False)
    log(f"Loaded shape: {df.shape}")

    # ----------------------------------------------------------------
    # 2. DEDUPLICATE
    # ----------------------------------------------------------------
    log("\nRemoving duplicates...")
    before = len(df)
    df = df.drop_duplicates()
    log(f"Removed {before - len(df)} duplicate rows -> {df.shape}")

    # ----------------------------------------------------------------
    # 3. SPLIT OFF ZERO-DAY CLASSES ENTIRELY
    # ----------------------------------------------------------------
    log(f"\nHolding out zero-day classes: {ZERO_DAY_CLASSES}")
    zero_day_mask = df[TARGET_COL].isin(ZERO_DAY_CLASSES)
    df_zero_day = df[zero_day_mask].copy()
    df_known = df[~zero_day_mask].copy()
    log(f"Known-class rows: {df_known.shape[0]}  |  Zero-day rows: {df_zero_day.shape[0]}")
    log("Zero-day class counts:")
    log(str(df_zero_day[TARGET_COL].value_counts()))

    # ----------------------------------------------------------------
    # 4. FEATURES / TARGET SPLIT (known data only, from here on)
    # ----------------------------------------------------------------
    X = df_known.drop(columns=[TARGET_COL])
    y = df_known[TARGET_COL]
    X_zd = df_zero_day.drop(columns=[TARGET_COL])
    y_zd_raw = df_zero_day[TARGET_COL]

    # ----------------------------------------------------------------
    # 5. INFINITE -> NaN
    # ----------------------------------------------------------------
    log("\nHandling infinite values...")
    X = X.replace([np.inf, -np.inf], np.nan)
    X_zd = X_zd.replace([np.inf, -np.inf], np.nan)

    # ----------------------------------------------------------------
    # 6. MISSING VALUES
    #    Numeric protocol fields: NaN -> -1 (per workflow spec: absence of a
    #    protocol field is itself informative, so we do NOT impute with the
    #    median, which would blur "field not present" with a real value).
    #    Categorical: NaN -> "Unknown" string bucket.
    # ----------------------------------------------------------------
    log("\nHandling missing values (NaN -> -1 for numeric, 'Unknown' for categorical)...")
    numeric_cols = X.select_dtypes(include=[np.number]).columns
    categorical_cols = X.columns.difference(numeric_cols)

    X[numeric_cols] = X[numeric_cols].fillna(-1)
    X_zd[numeric_cols] = X_zd[numeric_cols].fillna(-1)
    for col in categorical_cols:
        X[col] = X[col].fillna("Unknown")
        X_zd[col] = X_zd[col].fillna("Unknown")

    # ----------------------------------------------------------------
    # 7. ENCODE CATEGORICAL FEATURES
    #    One-hot would be truer to the written spec, but several of these
    #    columns (ip.src_host, ip.dst_host, arp.*proto_ipv4, tcp.srcport)
    #    are high-cardinality quasi-identifiers -> one-hot would blow the
    #    dimensionality up and re-introduce leakage-like host fingerprints.
    #    We keep the existing project's LabelEncoder approach for the
    #    feature columns (consistent with the already-generated .pkl
    #    artifacts) and fit it on known+zero-day jointly per column so
    #    unseen zero-day categories don't crash the transform.
    # ----------------------------------------------------------------
    log("\nEncoding categorical features (LabelEncoder, fit on known+zero-day union)...")
    feature_encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        combined = pd.concat([X[col], X_zd[col]], axis=0).astype(str)
        le.fit(combined)
        X[col] = le.transform(X[col].astype(str))
        X_zd[col] = le.transform(X_zd[col].astype(str))
        feature_encoders[col] = le
    log(f"Encoded {len(categorical_cols)} categorical columns")

    feature_columns = list(X.columns)

    # ----------------------------------------------------------------
    # 8. ENCODE TARGET (known classes only -- zero-day labels are kept
    #    as raw strings and deliberately NOT part of this encoder, since
    #    the whole point is that Stage 1 has never seen them)
    # ----------------------------------------------------------------
    log("\nEncoding target column (known classes only)...")
    target_encoder = LabelEncoder()
    y_encoded = target_encoder.fit_transform(y)
    mapping = {cls: int(idx) for idx, cls in enumerate(target_encoder.classes_)}
    log("Class mapping:")
    for k, v in mapping.items():
        log(f"  {k:<25} -> {v}")

    # ----------------------------------------------------------------
    # 9. TRAIN / VAL / TEST SPLIT (70/15/15, stratified)
    # ----------------------------------------------------------------
    log("\nCreating stratified 70/15/15 train/val/test split...")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y_encoded,
        test_size=(VAL_FRAC + TEST_FRAC),
        stratify=y_encoded,
        random_state=RANDOM_STATE,
    )
    relative_test_frac = TEST_FRAC / (VAL_FRAC + TEST_FRAC)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=relative_test_frac,
        stratify=y_temp,
        random_state=RANDOM_STATE,
    )
    log(f"X_train: {X_train.shape}  X_val: {X_val.shape}  X_test: {X_test.shape}")

    # ----------------------------------------------------------------
    # 10. CARVE OUT A STREAM SLICE FROM TRAIN (for Stage 5)
    #     Done BEFORE scaling is fit, on a further split of X_train, so
    #     the "true" training set used for Stage 1 is what remains.
    # ----------------------------------------------------------------
    log(f"\nCarving {STREAM_FRAC_OF_TRAIN:.0%} of training data for Stage 5 stream simulation...")
    X_train_core, X_stream, y_train_core, y_stream = train_test_split(
        X_train, y_train,
        test_size=STREAM_FRAC_OF_TRAIN,
        stratify=y_train,
        random_state=RANDOM_STATE,
    )
    log(f"X_train_core (used by Stage 1): {X_train_core.shape}")
    log(f"X_stream (held for Stage 5):    {X_stream.shape}")

    # ----------------------------------------------------------------
    # 11. SCALING
    #     Fit ONLY on X_train_core to avoid any leakage from val/test/
    #     stream/zero-day into the scaler statistics.
    # ----------------------------------------------------------------
    log("\nFitting StandardScaler on X_train_core only...")
    scaler = StandardScaler()
    X_train_core_scaled = scaler.fit_transform(X_train_core)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    X_stream_scaled = scaler.transform(X_stream)
    X_zd_scaled = scaler.transform(X_zd)

    # ----------------------------------------------------------------
    # 12. SAVE PROCESSED (KNOWN) DATA
    # ----------------------------------------------------------------
    log("\nSaving processed known-class data...")

    def save_xy(X_arr, y_arr, x_name, y_name):
        pd.DataFrame(X_arr, columns=feature_columns).to_csv(PROCESSED_DIR / x_name, index=False)
        pd.DataFrame(y_arr, columns=[TARGET_COL]).to_csv(PROCESSED_DIR / y_name, index=False)

    save_xy(X_train_core_scaled, y_train_core, "X_train.csv", "y_train.csv")
    save_xy(X_val_scaled, y_val, "X_val.csv", "y_val.csv")
    save_xy(X_test_scaled, y_test, "X_test.csv", "y_test.csv")

    joblib.dump(scaler, PROCESSED_DIR / "scaler.pkl")
    joblib.dump(target_encoder, PROCESSED_DIR / "target_encoder.pkl")
    joblib.dump(feature_encoders, PROCESSED_DIR / "feature_encoders.pkl")
    with open(PROCESSED_DIR / "feature_columns.json", "w") as f:
        json.dump(feature_columns, f, indent=2)
    with open(PROCESSED_DIR / "class_mapping.json", "w") as f:
        json.dump(mapping, f, indent=2)

    # ----------------------------------------------------------------
    # 13. SAVE ZERO-DAY HOLDOUT
    # ----------------------------------------------------------------
    log("\nSaving zero-day holdout data...")
    pd.DataFrame(X_zd_scaled, columns=feature_columns).to_csv(
        ZERO_DAY_DIR / "X_zero_day.csv", index=False
    )
    pd.DataFrame({TARGET_COL: y_zd_raw.values}).to_csv(
        ZERO_DAY_DIR / "y_zero_day.csv", index=False
    )

    # ----------------------------------------------------------------
    # 14. SAVE STREAM BATCHES (for Stage 5), split into N sequential chunks
    # ----------------------------------------------------------------
    log(f"\nSaving {N_STREAM_BATCHES} stream batches for Stage 5...")
    stream_idx = np.arange(len(X_stream_scaled))
    rng = np.random.RandomState(RANDOM_STATE)
    rng.shuffle(stream_idx)
    batches = np.array_split(stream_idx, N_STREAM_BATCHES)
    for i, idx in enumerate(batches):
        pd.DataFrame(X_stream_scaled[idx], columns=feature_columns).to_csv(
            STREAM_DIR / f"X_stream_batch_{i}.csv", index=False
        )
        pd.DataFrame({TARGET_COL: np.array(y_stream)[idx]}).to_csv(
            STREAM_DIR / f"y_stream_batch_{i}.csv", index=False
        )
        log(f"  batch {i}: {len(idx)} rows")

    # ----------------------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------------------
    log("\n" + "=" * 70)
    log("STAGE 0 PREPROCESSING COMPLETE")
    log("=" * 70)
    log(f"Known classes           : {len(target_encoder.classes_)}")
    log(f"Zero-day classes        : {ZERO_DAY_CLASSES}")
    log(f"Train (core, Stage 1)   : {X_train_core.shape}")
    log(f"Validation              : {X_val.shape}")
    log(f"Test                    : {X_test.shape}")
    log(f"Stream (Stage 5, total) : {X_stream.shape} across {N_STREAM_BATCHES} batches")
    log(f"Zero-day holdout        : {X_zd.shape}")
    log("Done.")


if __name__ == "__main__":
    main()
