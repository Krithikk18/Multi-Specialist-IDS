"""common/label_store.py -- append-only, Ed25519-signed operator label batches (docs/V2_PREREG_PHASE4.md section 3).

Layout (store root outside the repo, e.g. ~/lgids_cache/v2/cl/labels/):
  <root>/<batch_id>/labels.parquet   one row per label: flow_uid, flow_id, start_ts, run_id (the flow key), label
                                     (class name), label_id, reason, operator_id, labelled_utc
                   /manifest.json    canonical JSON: counts per class / reason, file sha256, rows sha256 (content hash
                                     independent of parquet encoding), class map sha256, operator key, provenance
                   /manifest.sig     Ed25519 signature (hex) over the manifest bytes, operator key
  <root>/index.jsonl                 append-only, hash-chained, signed: one record per batch (batch id, manifest sha256)
Keys: <keys_dir>/operator_ed25519.key (32-byte seed, hex, file 600, dir 700) + .pub; created if absent; a keys dir inside
the repository is refused; the secret is never printed.

    secret, public = ensure_operator_keys(keys_dir, repo_root)
    write_batch(root, batch_id, rows, secret, provenance)      # refused if the batch exists (append-only)
    df, M = load_batch(root, batch_id, public)                 # LabelStoreRefused on any signature / hash problem
Training reads labels only through load_batch: an unsigned, re-signed-by-another-key, edited or un-indexed batch is
refused, never repaired.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path

import numpy as np

from common import registry as REG

KEY_NAME = "operator_ed25519"
SCHEMA = "lgids.labels.v1"
COLUMNS = ["flow_uid", "flow_id", "start_ts", "run_id", "label", "label_id", "reason", "operator_id", "labelled_utc"]
INDEX = "index.jsonl"


class LabelStoreRefused(RuntimeError):
    pass


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ensure_operator_keys(keys_dir: Path, repo_root: Path | None = None) -> tuple[bytes, bytes]:
    keys_dir = Path(keys_dir).expanduser().resolve()
    if repo_root is not None:
        rr = Path(repo_root).resolve()
        if keys_dir == rr or rr in keys_dir.parents:
            raise LabelStoreRefused(f"operator keys dir {keys_dir} is inside the repository {rr}")
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    sk_p, pk_p = keys_dir / f"{KEY_NAME}.key", keys_dir / f"{KEY_NAME}.pub"
    if not sk_p.exists():
        secret = os.urandom(32)
        fd = os.open(sk_p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secret.hex() + "\n")
        pk_p.write_text(REG.public_key(secret).hex() + "\n", encoding="ascii")
    secret = bytes.fromhex(sk_p.read_text(encoding="ascii").strip())
    public = bytes.fromhex(pk_p.read_text(encoding="ascii").strip())
    if REG.public_key(secret) != public:
        raise LabelStoreRefused(f"{pk_p} does not match {sk_p}")
    return secret, public


def operator_public_key(keys_dir: Path) -> bytes:
    p = Path(keys_dir).expanduser() / f"{KEY_NAME}.pub"
    if not p.is_file():
        raise LabelStoreRefused(f"operator public key {p} not found")
    return bytes.fromhex(p.read_text(encoding="ascii").strip())


def rows_sha256(df) -> str:
    """Content hash of the label rows, independent of the parquet encoding: sha256 over canonical JSON lines."""
    h = hashlib.sha256()
    cols = [df[c].tolist() for c in COLUMNS]
    for vals in zip(*cols):
        h.update(canon([v.item() if hasattr(v, "item") else v for v in vals]) + b"\n")
    return h.hexdigest()


def _check_rows(df, class_names: list[str]) -> None:
    miss = [c for c in COLUMNS if c not in df.columns]
    if miss:
        raise LabelStoreRefused(f"label rows lack columns {miss}")
    if df["flow_uid"].duplicated().any():
        raise LabelStoreRefused("duplicate flow_uid in one batch")


def write_batch(root: Path, batch_id: str, df, secret: bytes, provenance: dict, class_names: list[str],
                class_map_sha256: str) -> dict:
    """Write <root>/<batch_id>/ (refused if it exists), sign the manifest, append the signed index record."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    root = Path(root)
    d = root / batch_id
    if d.exists():
        raise LabelStoreRefused(f"label batch {d} already exists (the store is append-only)")
    _check_rows(df, class_names)
    df = df[COLUMNS].reset_index(drop=True)
    root.mkdir(parents=True, exist_ok=True)
    tmp = root / f".{batch_id}.partial"
    tmp.mkdir(parents=False, exist_ok=False)
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), tmp / "labels.parquet")
    pub = REG.public_key(secret)
    lab = df["label"].astype(str)
    M = {"schema": SCHEMA, "batch_id": batch_id, "created_utc": _now(), "n": int(len(df)),
         "counts_per_class": {n: int((lab == n).sum()) for n in class_names},
         "counts_per_reason": {str(k): int(v) for k, v in df["reason"].value_counts().sort_index().items()},
         "class_names": list(class_names), "class_map_sha256": class_map_sha256,
         "operator_ids": sorted(set(df["operator_id"].astype(str))),
         "files": {"labels.parquet": REG.sha256_file(tmp / "labels.parquet")}, "rows_sha256": rows_sha256(df),
         "provenance": provenance,
         "signature": {"algorithm": "Ed25519", "over": "canonical JSON of manifest.json (sort_keys, no spaces)",
                       "public_key": pub.hex(), "fingerprint": REG.fingerprint(pub), "backend": REG.BACKEND}}
    raw = canon(M)
    (tmp / "manifest.json").write_bytes(raw)
    (tmp / "manifest.sig").write_text(REG.sign(secret, raw).hex() + "\n", encoding="ascii")
    tmp.rename(d)
    rec = _append_index(root, batch_id, hashlib.sha256(raw).hexdigest(), secret)
    return {"dir": str(d), "manifest": M, "manifest_sha256": hashlib.sha256(raw).hexdigest(), "index_record": rec}


def _append_index(root: Path, batch_id: str, manifest_sha: str, secret: bytes) -> dict:
    p = Path(root) / INDEX
    prev = REG.sha256_file(p) if p.exists() else None
    rec = {"batch_id": batch_id, "manifest_sha256": manifest_sha, "utc": _now(), "prev_index_sha256": prev}
    rec["sig"] = REG.sign(secret, canon(rec)).hex()
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def read_index(root: Path, public: bytes) -> dict:
    """{batch_id: manifest_sha256} of a fully valid, chained, signed index (LabelStoreRefused otherwise)."""
    p = Path(root) / INDEX
    if not p.is_file():
        raise LabelStoreRefused(f"{p}: no index")
    out, prev_bytes = {}, b""
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        rec = json.loads(line)
        sig = bytes.fromhex(rec.pop("sig", "") or "")
        if not REG.verify(public, canon(rec), sig):
            raise LabelStoreRefused(f"{p}: record {i} has a bad signature")
        want = hashlib.sha256(prev_bytes).hexdigest() if i else None
        if rec["prev_index_sha256"] != want:
            raise LabelStoreRefused(f"{p}: record {i} breaks the chain (an earlier record was edited or removed)")
        if rec["batch_id"] in out:
            raise LabelStoreRefused(f"{p}: batch {rec['batch_id']} indexed twice")
        out[rec["batch_id"]] = rec["manifest_sha256"]
        prev_bytes += (line + "\n").encode("utf-8")
    return out


def load_batch(root: Path, batch_id: str, public: bytes, class_names: list[str] | None = None):
    """(DataFrame, manifest) of a verified batch: signed index lists it with this manifest sha256, manifest signature
    valid for `public`, labels.parquet sha256 and the rows' content hash == manifest, counts == manifest."""
    import pyarrow.parquet as pq
    d = Path(root) / batch_id
    for f in ("manifest.json", "manifest.sig", "labels.parquet"):
        if not (d / f).is_file():
            raise LabelStoreRefused(f"{d}: {f} missing (unsigned or incomplete batch)")
    raw = (d / "manifest.json").read_bytes()
    M = json.loads(raw)
    if canon(M) != raw:
        raise LabelStoreRefused(f"{d}: manifest.json is not canonical (edited)")
    try:
        sig = bytes.fromhex((d / "manifest.sig").read_text(encoding="ascii").strip())
    except ValueError:
        raise LabelStoreRefused(f"{d}: manifest.sig unreadable") from None
    if not REG.verify(public, raw, sig):
        raise LabelStoreRefused(f"{d}: bad manifest signature (not signed by the operator key)")
    idx = read_index(root, public)
    if idx.get(batch_id) != hashlib.sha256(raw).hexdigest():
        raise LabelStoreRefused(f"{d}: not in the signed index with this manifest sha256")
    if REG.sha256_file(d / "labels.parquet") != M["files"]["labels.parquet"]:
        raise LabelStoreRefused(f"{d}: labels.parquet sha256 differs from the signed manifest (tampered)")
    df = pq.read_table(d / "labels.parquet").to_pandas()
    if list(df.columns) != COLUMNS or rows_sha256(df) != M["rows_sha256"] or len(df) != M["n"]:
        raise LabelStoreRefused(f"{d}: label rows differ from the signed manifest")
    names = class_names if class_names is not None else M["class_names"]
    lab = df["label"].astype(str)
    if {n: int((lab == n).sum()) for n in names} != {n: M["counts_per_class"].get(n, 0) for n in names}:
        raise LabelStoreRefused(f"{d}: counts per class differ from the signed manifest")
    return df, M


def manifest_sha256(root: Path, batch_id: str) -> str:
    return hashlib.sha256((Path(root) / batch_id / "manifest.json").read_bytes()).hexdigest()


def make_rows(flow_uid, flow_id, start_ts, run_id: str, label_id, reason, operator_id: str, class_names: list[str],
              labelled_utc: str | None = None):
    """Label rows in the store's column layout (label names from the class map by id)."""
    import pandas as pd
    lid = np.asarray(label_id, dtype=np.int64)
    names = np.array(class_names, dtype=object)
    lab = np.array([("<id %d>" % i) if not 0 <= i < len(names) else names[i] for i in lid.tolist()], dtype=object)
    n = len(lid)
    return pd.DataFrame({"flow_uid": np.asarray(flow_uid, dtype=object).astype(str),
                         "flow_id": np.asarray(flow_id, dtype=object).astype(str),
                         "start_ts": np.asarray(start_ts, dtype=np.int64), "run_id": [str(run_id)] * n,
                         "label": lab.astype(str), "label_id": lid, "reason": np.asarray(reason, dtype=object).astype(str),
                         "operator_id": [str(operator_id)] * n, "labelled_utc": [labelled_utc or _now()] * n})
