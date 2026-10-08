import pandas as pd
import numpy as np
from pathlib import Path

DATASET_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "raw"
    / "ML-EdgeIIoT-dataset.csv"
)

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
    "mqtt.topic"
]

sample = pd.read_csv(DATASET_PATH, nrows=5)

use_cols = [c for c in sample.columns if c not in DROP_COLS]

df = pd.read_csv(
    DATASET_PATH,
    usecols=use_cols
)

print("\n" + "="*70)
print("DATASET SHAPE")
print("="*70)

print(df.shape)

print("\n" + "="*70)
print("CLASS DISTRIBUTION")
print("="*70)

print(df["Attack_type"].value_counts())

print("\n" + "="*70)
print("ATTACK LABEL DISTRIBUTION")
print("="*70)

print(df["Attack_label"].value_counts())

print("\n" + "="*70)
print("MISSING VALUES")
print("="*70)

missing = df.isnull().sum()
missing = missing[missing > 0]

print(missing)

print("\n" + "="*70)
print("DATA TYPES")
print("="*70)

print(df.dtypes.value_counts())

print("\n" + "="*70)
print("OBJECT COLUMNS")
print("="*70)

for col in df.select_dtypes(include="object").columns:
    print(col)

print("\n" + "="*70)
print("NUMERIC SUMMARY")
print("="*70)

print(df.describe().T)
