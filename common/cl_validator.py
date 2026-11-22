"""common/cl_validator.py -- the pre-registered label-batch validator (docs/V2_PREREG_PHASE4.md section 3).

A batch is QUARANTINED (not used for training; needs human review) if ANY of:
  (a) signature / hash: common/label_store.load_batch refuses it (bad or missing signature, file or content hash
      differs from the signed manifest, not in the signed index, counts differ)
  (b) a label not in the class map (label name not a class, or label_id != the class map id of that name)
  (c) among the batch items the DEPLOYED model scored with calibrated max-probability >= confident_pmax, the share whose
      label differs from the deployed model's predicted class is > max_confident_disagreement (0 such items -> passes)
Every check is evaluated (on the raw parquet when (a) fails, for the report) and every check that fired is listed.

    R = validate_batch(root, batch_id, public, class_names, deployed, cfg_validator)
    deployed = {"flow_uid": [...], "pred": [...], "pmax": [...]}   # the runtime's predictions for the queued flows
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from common import label_store as LS

VALID, QUARANTINED = "VALID", "QUARANTINED"


def check_class_map(labels, label_ids, class_names: list[str]) -> dict:
    lab = np.asarray(labels, dtype=object).astype(str)
    lid = np.asarray(label_ids, dtype=np.int64)
    name_to_id = {n: i for i, n in enumerate(class_names)}
    unknown = ~np.isin(lab, list(class_names))
    mism = np.array([(not u) and name_to_id[n] != i for n, i, u in zip(lab.tolist(), lid.tolist(), unknown.tolist())],
                    dtype=bool)
    bad = unknown | mism
    vals, cnt = np.unique(lab[bad], return_counts=True) if bad.any() else ([], [])
    return {"fired": bool(bad.any()), "n_bad": int(bad.sum()), "unknown_names": int(unknown.sum()),
            "id_mismatch": int(mism.sum()), "bad_values": {str(v): int(c) for v, c in zip(vals, cnt)}}


def check_confident_disagreement(label_ids, pred, pmax, confident_pmax: float, max_rate: float) -> dict:
    lid = np.asarray(label_ids, dtype=np.int64)
    pred = np.asarray(pred, dtype=np.int64)
    pmax = np.asarray(pmax, dtype=np.float64)
    conf = pmax >= confident_pmax
    n = int(conf.sum())
    dis = int((conf & (lid != pred)).sum())
    rate = dis / n if n else 0.0
    return {"fired": bool(n > 0 and rate > max_rate), "n_confident": n, "n_disagree": dis, "rate": float(rate),
            "threshold_pmax": float(confident_pmax), "max_rate": float(max_rate)}


def _raw_rows(root: Path, batch_id: str):
    import pyarrow.parquet as pq
    p = Path(root) / batch_id / "labels.parquet"
    return pq.read_table(p).to_pandas() if p.is_file() else None


def validate_batch(root: Path, batch_id: str, public: bytes, class_names: list[str], deployed: dict, vcfg: dict) -> dict:
    R = {"batch_id": batch_id, "root": str(root), "checks": {}}
    df, M = None, None
    try:
        df, M = LS.load_batch(root, batch_id, public, class_names)
        R["checks"]["a_signature_hash"] = {"fired": False, "detail": "signature, index, file and content hashes OK"}
    except LS.LabelStoreRefused as e:
        R["checks"]["a_signature_hash"] = {"fired": True, "detail": str(e)}
        df = _raw_rows(root, batch_id)
    if df is None:
        R["checks"]["b_label_in_class_map"] = {"fired": True, "detail": "no readable label rows"}
        R["checks"]["c_confident_disagreement"] = {"fired": True, "detail": "no readable label rows"}
    else:
        R["checks"]["b_label_in_class_map"] = check_class_map(df["label"], df["label_id"], class_names)
        pos = {u: i for i, u in enumerate(deployed["flow_uid"])}
        ix = np.array([pos.get(u, -1) for u in df["flow_uid"].astype(str)], dtype=np.int64)
        found = ix >= 0
        pred = np.asarray(deployed["pred"], np.int64)[ix[found]]
        pmax = np.asarray(deployed["pmax"], np.float64)[ix[found]]
        c = check_confident_disagreement(df["label_id"].to_numpy(np.int64)[found], pred, pmax,
                                         vcfg["confident_pmax"], vcfg["max_confident_disagreement"])
        c["n_labels_not_in_queue"] = int((~found).sum())
        R["checks"]["c_confident_disagreement"] = c
        R["n"] = int(len(df))
    R["fired"] = [k for k, v in R["checks"].items() if v.get("fired")]
    R["status"] = QUARANTINED if R["fired"] else VALID
    R["manifest_sha256"] = LS.manifest_sha256(root, batch_id) if (Path(root) / batch_id / "manifest.json").is_file() else None
    return R
