#!/usr/bin/env python
"""39_build_context_dataset.py -- Phase 5B step B (docs/V2_PREREG_PHASE5B.md section 2): build dataset v2_2_context.
OFFLINE: v2_1_oriented train + val only (the test split is never built or read); nothing registered.

Per split, per (session, split) segment (state reset), the streaming context features (common/context_features.py) are
computed and appended to every v2_1 column, with ctx_warmup. Checks: the pinned feature list equals the config's
generated names; a seeded contiguous val slice (reference_check.slice_rows flows, processing order) computed by the
streaming code equals the naive O(n^2) reference exactly (mismatch -> FAIL, the phase stops); row order and every v2_1
column unchanged. Reports: rows per split x class x group, evictions, warm-up share, val us/flow and peak state, the
per-feature summary (train benign vs each attack class) and histograms of the most separating context features.
Outputs: full -> <datasets_root>/<dataset_version>/ (train.parquet, val.parquet, split_definition.json copied byte for
byte, dataset_manifest.json); dry run -> <cache>_dry_run/dataset/<run>/ (5 % stratified samples). results/phase5b/39/.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

from config.config import REPO_ROOT
from common import context_config as CC
from common import context_features as CF
from common import phase2_data as D
from common import phase5b_run as PR
from common import schemas as S
from common.phase2_config import load_phase2_config

SCRIPT = "39_build_context_dataset.py"


def reference_check(df: pd.DataFrame, cfg: dict, log=print) -> dict:
    """Seeded contiguous slice (in processing order) of one segment with enough flows; streaming == naive, exactly."""
    rc = cfg["reference_check"]
    keys = [cfg["columns"][k] for k in cfg["context"]["segment_keys"]]
    segs = sorted(((k, ix) for k, ix in df.groupby(keys, sort=True).indices.items()), key=lambda kv: str(kv[0]))
    want = int(rc["slice_rows"])
    big = [s for s in segs if len(s[1]) >= want] or [max(segs, key=lambda s: len(s[1]))]
    rng = np.random.default_rng(int(rc["seed"]))
    key, ix = big[int(rng.integers(0, len(big)))]
    sub = df.iloc[ix].reset_index(drop=True)
    o = CF.order(CF.prepare(sub, cfg))
    n = min(want, len(sub))
    a = int(rng.integers(0, len(sub) - n + 1))
    sl = sub.iloc[np.sort(o[a:a + n])].reset_index(drop=True)
    inp = CF.prepare(sl, cfg)
    t0 = time.perf_counter()
    Fs, info = CF.compute(inp, cfg)
    Fn = CF.naive(inp, cfg)
    eq = bool(np.array_equal(Fs, Fn))
    bad = np.argwhere(Fs != Fn)
    log(f"  reference check: segment {key}, slice [{a}, {a + n}) of {len(sub):,} flows: streaming == naive {eq} "
        f"({time.perf_counter() - t0:.1f} s; evictions {info['evictions']})")
    return {"segment": [str(k) for k in (key if isinstance(key, tuple) else (key,))], "start": a, "rows": n,
            "segment_rows": int(len(sub)), "equal": eq, "mismatches": int(len(bad)), "evictions": info["evictions"],
            "first_mismatches": bad[:5].tolist()}


def class_group_counts(df: pd.DataFrame, lab: str, grp: str, names: list[str]) -> dict:
    return {f"{names[int(c)]}|{g}": int(n) for (c, g), n in df.groupby([lab, grp]).size().items()}


def feature_summary(df: pd.DataFrame, ctx: list[str], names: list[str], lab: str, seed: int = 0, top: int = 6,
                    bins: int = 40) -> dict:
    """Per context feature: median / p90 / mean for train benign and each attack class; AUC of each attack class vs
    benign (<= 20,000 rows per class, seeded); log10(1 + x) histograms of the `top` most separating features."""
    from sklearn.metrics import roc_auc_score
    rng = np.random.default_rng(seed)
    y = df[lab].to_numpy(np.int64)
    cls = [c for c in range(len(names)) if (y == c).any()]
    sub = {c: (lambda ix: rng.choice(ix, min(20000, len(ix)), replace=False))(np.flatnonzero(y == c)) for c in cls}
    out, sep = {}, {}
    for f in ctx:
        v = df[f].to_numpy(np.float64)
        rec = {names[c]: {"median": float(np.median(v[y == c])), "p90": float(np.quantile(v[y == c], 0.9)),
                          "mean": float(v[y == c].mean())} for c in cls}
        aucs = {}
        for c in cls:
            if c == 0 or 0 not in sub:
                continue
            yy = np.r_[np.zeros(len(sub[0])), np.ones(len(sub[c]))]
            aucs[names[c]] = float(roc_auc_score(yy, np.r_[v[sub[0]], v[sub[c]]]))
        rec["auc_vs_benign"] = aucs
        sep[f] = max((abs(a - 0.5) for a in aucs.values()), default=0.0)
        out[f] = rec
    best = sorted(ctx, key=lambda f: -sep[f])[:top]
    hist = {}
    for f in best:
        lv = np.log10(1.0 + np.maximum(df[f].to_numpy(np.float64), 0))
        edges = np.linspace(0, max(1e-9, float(lv.max())) * 1.02, bins + 1)
        hist[f] = {"edges_log10_1p": edges.tolist(),
                   "counts": {names[c]: np.histogram(lv[y == c], edges)[0].tolist() for c in cls}}
    return {"per_feature": out, "separation": sep, "top": best, "hist": hist}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--rerun-tag", default=None)
    args = ap.parse_args()
    cfg = CC.load_phase5b_config()
    run = PR.P5BRun("39", SCRIPT, cfg, args.dry_run, args.run_id, args.rerun_tag)
    M = run.base_manifest(["common/phase2_config.py"])
    PR.lock_banner(run, M, "start")
    ok = False
    try:
        free = shutil.disk_usage(run.cache).free / 1e9
        need = float(cfg["paths"]["min_free_gb"])
        run.check(M, f"free space on the cache filesystem >= {need:.0f} GB", free >= need, f"{free:,.1f} GB")
        if free < need:
            raise RuntimeError("not enough free space")
        cm = S.load_class_map()
        names = list(cm.names)
        FL = CC.load_feature_list()
        gen = CC.build_feature_list(cfg)
        run.check(M, "pinned feature list == names generated from the config", FL["features"] == gen["features"],
                  f"{FL['n_features']} = {FL['n_flow']} flow + {FL['n_context']} context")
        ctx = FL["context_features"]
        cfg2 = load_phase2_config(REPO_ROOT / cfg["phase2_config"])
        run.check(M, "phase2 config dataset == source_dataset", cfg2["dataset_version"] == cfg["source_dataset"],
                  cfg2["dataset_version"])
        src_dir = D.dataset_dir(cfg2)
        srcM = D.load_dataset_manifest(cfg2)
        if args.dry_run:
            out_dir = run.cache_dir("dataset")
        else:
            out_dir = CC.expand(cfg["paths"]["datasets_root"]) / cfg["dataset_version"]
            if out_dir.exists():
                raise PR.RunRefused(f"{out_dir} exists (datasets are written once)")
            out_dir.mkdir(parents=True)
        wc = cfg["context"]["warmup_column"]
        lab, grp = cfg["columns"]["label_id"], cfg["columns"]["group"]
        files, counts, segs, ref, summ, cost = {}, {}, {}, None, None, {}
        for split in ("train", "val"):
            t0 = time.monotonic()
            df = D.load_split(cfg2, split, sample=args.dry_run)
            clash = [c for c in ctx + [wc] if c in df.columns]
            if clash:
                raise RuntimeError(f"{split}: context column names already present {clash}")
            run.log(f"  {split}: {len(df):,} rows x {df.shape[1]} columns (v2_1{' 5 % sample' if args.dry_run else ''})")
            F, warm, info = CF.compute_segments(df, cfg, run.log)
            segs[split] = info["segments"]
            if split == "val":
                ref = reference_check(df, cfg, run.log)
                run.check(M, "real-data reference check: streaming == naive on the val slice (exact, all 44)", ref["equal"],
                          f"{ref['rows']:,} flows of segment {ref['segment']}, mismatches {ref['mismatches']}")
                if not ref["equal"]:
                    raise RuntimeError("STOP: streaming context code disagrees with the naive reference on real data")
                n = sum(s["n"] for s in info["segments"])
                cost = {"us_per_flow": sum(s["seconds"] for s in info["segments"]) * 1e6 / max(1, n),
                        "peak_hosts": max(s["peak_hosts"] for s in info["segments"]),
                        "peak_pairs": max(s["peak_pairs"] for s in info["segments"]),
                        "peak_events": max(s["peak_events"] for s in info["segments"]),
                        "state_note": "peak tracked keys and window events within one segment (2 windows per key)"}
            out = df.copy()
            for j, f in enumerate(ctx):
                out[f] = F[:, j]
            out[wc] = warm
            same = all(out[c].equals(df[c]) for c in df.columns)
            run.check(M, f"{split}: every v2_1 column and the row order unchanged", same, f"{len(df.columns)} columns")
            if split == "train":
                summ = feature_summary(out, ctx, names, lab)
            p = out_dir / f"{split}.parquet"
            out.to_parquet(p, index=False)
            files[split] = {"path": str(p), "rows": int(len(out)), "bytes": p.stat().st_size,
                            "file_sha256": PR.sha256_path(p), "source_file_sha256": srcM["files"][split]["file_sha256"]}
            counts[split] = class_group_counts(out, lab, grp, names)
            ev = {k: sum(s["evictions"][k] for s in info["segments"]) for k in ("host", "pair")}
            run.log(f"  {split}: written {p.name} ({files[split]['bytes'] / 1e6:.1f} MB) in {time.monotonic() - t0:.1f} s; "
                    f"evictions {ev}; warm-up {int(warm.sum()):,} ({warm.mean():.4f})")
            files[split]["evictions"] = ev
            files[split]["warmup"] = int(warm.sum())
            files[split]["warmup_share"] = float(warm.mean())
            del df, out, F
        shutil.copyfile(src_dir / "split_definition.json", out_dir / "split_definition.json")
        manifest = {"manifest_version": 1, "dataset_version": cfg["dataset_version"], "created_utc": PR.now_utc(),
                    "status": "PASS", "dry_run": args.dry_run, "script": SCRIPT, "run_id": run.run_id,
                    "derived_from": {"dataset_version": cfg["source_dataset"], "manifest_sha256": srcM["_sha256"],
                                     "files": {s: srcM["files"][s]["file_sha256"] for s in ("train", "val")}},
                    "test_policy": "test split NOT built in v2_2_context (Phase 5B reads train / val only)",
                    "class_map": {"sha256": S.CLASS_MAP_SHA256},
                    "features": {"file_sha256": S.FEATURES_V1_SHA256, "list_sha256": S.FEATURES_V1_LIST_SHA256, "n": 70,
                                 "context_file": cfg["feature_list"], "context_file_sha256": S.FEATURES_V2_2_CONTEXT_SHA256,
                                 "context_n": len(ctx), "warmup_column": wc,
                                 "note": "ctx_warmup is metadata, never a model feature"},
                    "context_config_sha256": cfg["_sha256"], "split_definition": {
                        "file_sha256": PR.sha256_path(out_dir / "split_definition.json"), "copied_from": str(src_dir)},
                    "counts": counts, "segments": segs, "files": files, "reference_check": ref, "val_cost": cost}
        man_sha = PR.write_json(out_dir / "dataset_manifest.json", manifest)
        M["dataset"] = {"dir": str(out_dir), "manifest_sha256": man_sha, "files": files, "dry_run": args.dry_run,
                        "dataset_version": cfg["dataset_version"]}
        M["counts"], M["segments"], M["reference_check"], M["val_cost"] = counts, segs, ref, cost
        PR.write_json(run.res / "feature_summary.json", summ)
        M["feature_summary_top"] = summ["top"]
        PR.lock_banner(run, M, "end")
        ok = all(c["pass"] for c in M["checks"] if c["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        run.log(f"ERROR: {e!r}")
    write_summary(run, M, args.dry_run)
    run.finish(ok, M)
    return 0 if ok else 1


def write_summary(run, M: dict, dry: bool) -> None:
    st = "PASS" if all(c["pass"] for c in M.get("checks", []) if c["level"] == "hard") and not M.get("error") else "FAIL"
    L = [f"# Step 39 -- context dataset v2_2_context -- {st}" + (" (DRY RUN)" if dry else ""), ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    if M.get("dataset"):
        d = M["dataset"]
        L += [f"- dataset dir `{d['dir']}`, manifest sha256 `{d['manifest_sha256'][:16]}...`", ""]
        L += ["| split | rows | MB | evictions (host / pair) | warm-up flows (share) |", "|---|---|---|---|---|"]
        for s, f in d["files"].items():
            L.append(f"| {s} | {f['rows']:,} | {f['bytes'] / 1e6:.1f} | {f['evictions']['host']} / {f['evictions']['pair']} | "
                     f"{f['warmup']:,} ({f['warmup_share']:.4f}) |")
        L += ["", "| split | class x group | rows |", "|---|---|---|"]
        for s, c in M["counts"].items():
            L += [f"| {s} | {k} | {v:,} |" for k, v in c.items()]
        L.append("")
    if M.get("reference_check"):
        L += [f"- real-data reference check (val slice): {M['reference_check']}", ""]
    if M.get("val_cost"):
        L += [f"- val compute cost: {M['val_cost']}", ""]
    if M.get("segments"):
        L += ["| split | segment | flows | us/flow | evictions | peak hosts / pairs / events | warm-up |", "|---|---|---|---|---|---|---|"]
        for s, segs in M["segments"].items():
            for g in segs:
                L.append(f"| {s} | {' / '.join(g['segment'])} | {g['n']:,} | {g['us_per_flow']:.1f} | {g['evictions']} | "
                         f"{g['peak_hosts']} / {g['peak_pairs']} / {g['peak_events']:,} | {g['warmup']:,} |")
        L.append("")
    if M.get("feature_summary_top"):
        L += [f"- most separating context features (max |AUC - 0.5| vs train benign): {M['feature_summary_top']} "
              "(full table: feature_summary.json)", ""]
    L += ["## Checks", ""] + [f"- {'PASS' if c['pass'] else ('WARN' if c['level'] == 'warn' else 'FAIL')}  {c['check']}  "
                              f"{c['detail']}" for c in M.get("checks", [])]
    (run.res / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
