import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "ML-EdgeIIoT-dataset.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# COLUMNS TO DROP
# ============================================================

DROP_COLS = [
    "http.file_data",
    "http.request.uri.query",
    "http.request.method",
    "http.referer",
    "http.request.full_uri",
    "http.request.version",
    "dns.qry.name",
    "mqtt.msg_decoded_as",
    "mqtt.msg",
    "mqtt.protoname",
    "mqtt.topic",

    # additional columns
    "frame.time",
    "tcp.options",
    "tcp.payload",

    # binary label not needed
    "Attack_label"
]

TARGET_COL = "Attack_type"

RANDOM_STATE = 42

# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading dataset...")

sample = pd.read_csv(DATASET_PATH, nrows=5)

use_cols = [
    col for col in sample.columns
    if col not in DROP_COLS
]

df = pd.read_csv(
    DATASET_PATH,
    usecols=use_cols
)

print(f"Dataset loaded successfully")
print(f"Shape: {df.shape}")

# ============================================================
# REMOVE DUPLICATES
# ============================================================

print("\nRemoving duplicates...")

before = len(df)

df.drop_duplicates(inplace=True)

after = len(df)

print(f"Removed {before - after} duplicate rows")

# ============================================================
# SEPARATE FEATURES & TARGET
# ============================================================

X = df.drop(columns=[TARGET_COL])
y = df[TARGET_COL]

print(f"\nFeatures shape: {X.shape}")
print(f"Target shape: {y.shape}")

# ============================================================
# HANDLE INFINITE VALUES
# ============================================================

print("\nHandling infinite values...")

X.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)

# ============================================================
# HANDLE MISSING VALUES
# ============================================================

print("\nHandling missing values...")

numeric_cols = X.select_dtypes(
    include=[np.number]
).columns

X[numeric_cols] = X[numeric_cols].fillna(
    X[numeric_cols].median()
)

categorical_cols = X.select_dtypes(
    include=["object"]
).columns

for col in categorical_cols:
    X[col] = X[col].fillna("Unknown")

print("Missing values handled")

# ============================================================
# ENCODE CATEGORICAL FEATURES
# ============================================================

print("\nEncoding categorical features...")

feature_encoders = {}

categorical_cols = X.select_dtypes(
    include=["object"]
).columns

print(f"Found {len(categorical_cols)} categorical columns")

for col in categorical_cols:

    le = LabelEncoder()

    X[col] = le.fit_transform(
        X[col].astype(str)
    )

    feature_encoders[col] = le

print("Categorical encoding completed")

# ============================================================
# ENCODE TARGET
# ============================================================

print("\nEncoding target column...")

target_encoder = LabelEncoder()

y_encoded = target_encoder.fit_transform(y)

mapping = {
    cls: int(idx)
    for idx, cls in enumerate(
        target_encoder.classes_
    )
}

print("\nClass Mapping")

for k, v in mapping.items():
    print(f"{k:<25} -> {v}")

# ============================================================
# TRAIN TEST SPLIT
# ============================================================

print("\nCreating train/test split...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    stratify=y_encoded,
    random_state=RANDOM_STATE
)

print(f"X_train: {X_train.shape}")
print(f"X_test : {X_test.shape}")

# ============================================================
# FEATURE SCALING
# ============================================================

print("\nApplying StandardScaler...")

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)

X_test_scaled = scaler.transform(X_test)

print("Scaling completed")

# ============================================================
# SAVE DATA
# ============================================================

print("\nSaving processed files...")

pd.DataFrame(
    X_train_scaled,
    columns=X.columns
).to_csv(
    OUTPUT_DIR / "X_train.csv",
    index=False
)

pd.DataFrame(
    X_test_scaled,
    columns=X.columns
).to_csv(
    OUTPUT_DIR / "X_test.csv",
    index=False
)

pd.DataFrame(
    y_train,
    columns=["Attack_type"]
).to_csv(
    OUTPUT_DIR / "y_train.csv",
    index=False
)

pd.DataFrame(
    y_test,
    columns=["Attack_type"]
).to_csv(
    OUTPUT_DIR / "y_test.csv",
    index=False
)

# ============================================================
# SAVE ENCODERS
# ============================================================

joblib.dump(
    scaler,
    OUTPUT_DIR / "scaler.pkl"
)

joblib.dump(
    target_encoder,
    OUTPUT_DIR / "target_encoder.pkl"
)

joblib.dump(
    feature_encoders,
    OUTPUT_DIR / "feature_encoders.pkl"
)

print("\nSaved:")
print("X_train.csv")
print("X_test.csv")
print("y_train.csv")
print("y_test.csv")
print("scaler.pkl")
print("target_encoder.pkl")
print("feature_encoders.pkl")

# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("PREPROCESSING COMPLETED")
print("=" * 70)

print(f"Training Samples : {len(X_train)}")
print(f"Testing Samples  : {len(X_test)}")
print(f"Features         : {X.shape[1]}")
print(f"Classes          : {len(target_encoder.classes_)}")

print("\nDone!")
