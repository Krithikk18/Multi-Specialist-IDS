#!/usr/bin/env python
"""21b_normalise_orientation.py -- Phase 2 closeout step C: dataset v2_1_oriented = v2_0_v1equiv TRAIN + VAL with the
orientation normaliser applied (common/orientation.py, rule R3, config/orientation_map.json pinned in common/schemas.py).

  python 21b_normalise_orientation.py [--dry-run] [--run-id ID]

Reads the source dataset (config/v2_phase2.json's dataset_version) through common/phase2_data.load_split -- train and
val only, sha256-checked against the source manifest. Writes ~/lgids_cache/v2/datasets/v2_1_oriented/ (same layout as
v2_0: train.parquet, val.parquet, split_definition.json copied byte-for-byte, dataset_manifest.json) atomically
(.partial dir renamed; refused if the target exists). The TEST split is NOT built here: it is normalised once, with
this same pinned code and map, at the single final test run (manifest test_policy; docs/V2_PREREG_PHASE2_AMENDMENT_1.md).

Hard checks: rows / order / columns unchanged (+ the bool flag column appended); unflipped rows bit-identical to the
source; every flipped row is TCP and no longer satisfies R3; flip counts per split x group x class == the R3 gate run
(results/orient_gate/rerun_pct_fix, full run only); common/schemas.validate_frame gives the same check results on the
source and the normalised rows (the dataset layout is not the raw-CSV contract, so some checks fail identically on both;
listed in the summary).
Outputs: results/21b/ (summary.md, run_manifest.json, run_meta.json, run.log, figures/*.png); run dir
~/lgids_cache/v2/dataset_runs/<run_id>/. --dry-run: the 5 % sample -> ~/lgids_cache/v2/datasets_dry_run/
v2_1_oriented__<run_id>/, results/21b/dry_run/<run_id>/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import orientation as O  # noqa: E402
from common import phase2_data as D  # noqa: E402
from common import phase2_run as R  # noqa: E402
from common import plot_style as PS  # noqa: E402
from common import schemas as S  # noqa: E402
from common.phase2_config import expand, load_phase2_config  # noqa: E402
from config.config import RESULTS_DIR  # noqa: E402

SCRIPT = "21b_normalise_orientation.py"
STEP = "21b"
OUT_VERSION = "v2_1_oriented"
SPLITS = ("train", "val")
GATE_RESULTS = RESULTS_DIR / "orient_gate" / "rerun_pct_fix"
EXTRA_CODE = ["common/orientation.py", "config/orientation_map.json", "diagnostics/orient_gate_r3.py"]
TEST_POLICY = ("test split NOT built in v2_1_oriented: it is normalised once, with this same pinned code "
               "(common/orientation.py) and map (config/orientation_map.json, sha256 in the manifest), at the single "
               "final test run; Phase 2 never reads it (docs/V2_PREREG_PHASE2_AMENDMENT_1.md)")


def content_sha256(df: pd.DataFrame) -> str:
    """sha256 over per-column digests (numbers: raw float64 / int64 bytes; others: NUL-joined strings), in column order."""
    h = hashlib.sha256()
    for c in df.columns:
        s = df[c]
        if pd.api.types.is_bool_dtype(s.dtype):
            b = s.to_numpy(np.uint8).tobytes()
        elif pd.api.types.is_integer_dtype(s.dtype):
            b = s.to_numpy(np.int64).tobytes()
        elif pd.api.types.is_numeric_dtype(s.dtype):
            b = s.to_numpy(np.float64).tobytes()
        else:
            b = "\x00".join(s.astype(str).tolist()).encode("utf-8")
        h.update(c.encode("utf-8") + b"\x01" + hashlib.sha256(b).digest())
    return h.hexdigest()


def flip_table(df: pd.DataFrame, flag: np.ndarray, gcol: str, ycol: str, names: list[str]) -> list[dict]:
    rows = []
    g, y = df[gcol].astype(str).to_numpy(), df[ycol].to_numpy(np.int64)
    for gg in sorted(set(g)):
        for k, n in enumerate(names):
            m = (g == gg) & (y == k)
            if m.any():
                rows.append({"group": gg, "class": n, "class_id": k, "n": int(m.sum()), "flipped": int(flag[m].sum()),
                             "pct": 100 * float(flag[m].mean())})
    return rows


def check_list(rep: dict) -> list[tuple]:
    return [(c["check"], bool(c["pass"])) for c in rep["checks"]]


# --------------------------------------------------------------------------- figures
def fig_flips(path, flips: dict, names, title):
    import matplotlib.pyplot as plt
    PS.apply()
    fig, axes = plt.subplots(1, len(flips), figsize=(4.6 * len(flips), 0.32 * max(len(v) for v in flips.values()) + 1.6),
                             sharex=True, squeeze=False)
    for ax, (s, rows) in zip(axes[0], flips.items()):
        lab = [f"{r['group']} {r['class']}" for r in rows]
        v = [r["flipped"] for r in rows]
        y = np.arange(len(rows))
        ax.barh(y, np.maximum(v, 0), color=[PS.class_color(r["class_id"]) for r in rows], height=0.6)
        for yi, r in enumerate(rows):
            ax.text(max(r["flipped"], 0.8) * 1.15, yi, f"{r['flipped']:,} / {r['n']:,} ({r['pct']:.3f} %)", va="center",
                    fontsize=6.8, color=PS.TEXT1)
        ax.set_xscale("symlog", linthresh=1)
        ax.set_yticks(y, lab, fontsize=7.5)
        ax.invert_yaxis()
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_title(s, loc="left", fontsize=9)
        ax.set_xlabel("rows flipped (symlog)")
        ax.set_xlim(0, max(10, max(v)) * 40)
    fig.subplots_adjust(top=0.84, wspace=0.75)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


def fig_initwin(path, shares: dict, cls_id: int, title):
    """shares: {"v2_0" | "v2_1": {"train": {value: share}, "val": {...}}, "n": {...}}."""
    import matplotlib.pyplot as plt
    PS.apply()
    cats = list(shares["v2_0"]["train"])
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 0.5 * len(cats) + 1.7), sharey=True)
    y = np.arange(len(cats))
    for ax, ver in zip(axes, ("v2_0", "v2_1")):
        tr = [100 * shares[ver]["train"][c] for c in cats]
        va = [100 * shares[ver]["val"][c] for c in cats]
        ax.barh(y - 0.2, tr, 0.38, color=PS.NEUTRAL_LIGHT, label=f"train (n={shares['n']['train']:,})")
        ax.barh(y + 0.2, va, 0.38, color=PS.class_color(cls_id), label=f"val (n={shares['n']['val']:,})")
        for yi, (a, b) in enumerate(zip(tr, va)):
            if a > 0:
                ax.text(a + 1, yi - 0.2, f"{a:.1f} %", va="center", fontsize=7, color=PS.TEXT2)
            if b > 0:
                ax.text(b + 1, yi + 0.2, f"{b:.1f} %", va="center", fontsize=7, color=PS.TEXT1)
        ax.set_xlim(0, 118)
        ax.set_yticks(y, cats)
        ax.invert_yaxis()
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_xlabel("% of flows")
        ax.set_title("v2_0_v1equiv (as extracted)" if ver == "v2_0" else f"{OUT_VERSION} (R3 normalised)", loc="left",
                     fontsize=8.5)
    axes[0].set_ylabel("FWD Init Win Bytes")
    axes[1].legend(frameon=False, loc="lower right", fontsize=7.5)
    fig.subplots_adjust(top=0.8, wspace=0.08)
    fig.suptitle(title, x=0.01, ha="left", y=0.99)
    PS.save(fig, path)


# --------------------------------------------------------------------------- main
def main() -> int:
    import pyarrow as pa
    import pyarrow.parquet as pq
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--class-a", default="port_scan", help="class for the FWD Init Win figure")
    ap.add_argument("--focus-group", default="G1", help="group for the FWD Init Win figure")
    args = ap.parse_args()
    cfg = load_phase2_config()                                          # the SOURCE dataset's config (v2_0)
    S.verify_v2_lock(strict=True)
    pins_before = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                     ("config/class_map.json", S.CLASS_MAP_PATH))}
    omap = O.load_map(S.ORIENTATION_MAP_PATH, S.ORIENTATION_MAP_SHA256)
    cm = S.load_class_map()
    names = list(cm.names)
    feats = S.feature_columns()
    if O.feature_order(omap) != feats:
        raise SystemExit("orientation map features != features_v1.json")
    ctx = R.start_run(STEP, "dataset_runs", SCRIPT, cfg, args.dry_run, args.run_id)
    M = R.base_manifest(ctx, SCRIPT, EXTRA_CODE)
    root = expand(cfg["paths"]["datasets_root"])
    out_dir = (root.with_name(root.name + "_dry_run") / f"{OUT_VERSION}__{ctx.run_id}") if args.dry_run else root / OUT_VERSION
    part = out_dir.with_name("." + out_dir.name + ".partial")
    M.update({"output_dataset": OUT_VERSION, "output_dir": str(out_dir), "test_policy": TEST_POLICY,
              "orientation": {"map": "config/orientation_map.json", "map_sha256": omap["_sha256"], "rule": "R3",
                              "rule_text": omap["rule"]["R3"], "flag_column": omap["machine"]["flag_column"],
                              "code_sha256": R.sha256_path(Path(O.__file__))}})
    ok, out, figs = False, {"flips": {}, "validate": {}}, []
    try:
        if out_dir.exists() or part.exists():
            raise R.RunRefused(f"target exists: {out_dir if out_dir.exists() else part} (never overwritten)")
        c = cfg["columns"]
        dm = D.load_dataset_manifest(cfg)
        src_dir = D.dataset_dir(cfg)
        M["source"] = {"dataset_version": cfg["dataset_version"], "dir": str(src_dir), "manifest_sha256": dm["_sha256"],
                       "files": {s: D.verify_split_file(cfg, s) for s in SPLITS}, "test_read": False}
        part.mkdir(parents=True)
        files, frames = {}, {}
        fc = omap["machine"]["flag_column"]
        for s in SPLITS:
            src = D.load_split(cfg, s, None, sample=args.dry_run)
            if fc in src.columns:
                raise RuntimeError(f"source {s} already has {fc}")
            n = O.normalise(src, omap)
            flag = n[fc].to_numpy(bool)
            # ---- hard checks per split
            R.add_check(ctx, M, f"{s}: rows, order, columns unchanged (+ {fc} appended)",
                        len(n) == len(src) and list(n.columns) == list(src.columns) + [fc]
                        and n.dtypes.drop(fc).equals(src.dtypes), f"{len(n):,} rows, {len(n.columns)} columns")
            same = n.drop(columns=[fc]).loc[~flag].reset_index(drop=True).equals(src.loc[~flag].reset_index(drop=True))
            R.add_check(ctx, M, f"{s}: unflipped rows bit-identical to the source", bool(same), f"{int((~flag).sum()):,} rows")
            g = omap["machine"]["protocol_guard"]
            tcp = pd.to_numeric(src[g["column"]]).to_numpy() == g["value"]
            R.add_check(ctx, M, f"{s}: every flipped row is TCP and no longer satisfies R3",
                        bool(tcp[flag].all() and not O.is_reversed(n.loc[flag], omap).any()), f"{int(flag.sum()):,} flipped")
            out["flips"][s] = flip_table(src, flag, c["group"], c["label_id"], names)
            # ---- validate_frame on source vs normalised (identical check results)
            rs = S.validate_frame(src)
            rn = S.validate_frame(n.drop(columns=[fc]))
            out["validate"][s] = {"source": check_list(rs), "normalised": check_list(rn),
                                  "failing_on_both": [k for k, v in check_list(rn) if not v],
                                  "extra_columns": rn["columns"]["extra_columns"], "missing_meta": rn["columns"]["missing_meta"],
                                  "nan_inf_total": {"source": int(sum(v["nan"] + v["inf"] for v in rs["nan_inf"].values())),
                                                    "normalised": int(sum(v["nan"] + v["inf"] for v in rn["nan_inf"].values()))},
                                  "blank_mac_bad": {k: {r: rn["blank_mac"][k][r] for r in S.BLANK_MAC_BAD} for k in rn["blank_mac"]}}
            R.add_check(ctx, M, f"{s}: validate_frame check results identical on source and normalised rows",
                        check_list(rs) == check_list(rn),
                        f"{sum(v for _, v in check_list(rn))}/{len(check_list(rn))} pass on both")
            R.add_check(ctx, M, f"{s}: validate_frame content checks pass (features present / ordered / numeric, "
                        "timestamps, NaN-inf policy, blank-MAC rule)",
                        rn["columns"]["features_in_order"] and not rn["columns"]["missing_features"] and not rn["non_numeric"]
                        and all(rn["blank_mac"][k][r] == 0 for k in rn["blank_mac"] for r in S.BLANK_MAC_BAD),
                        "layout checks (V1 raw-CSV meta / label columns) are expected to differ; see summary")
            p = part / f"{s}.parquet"
            pq.write_table(pa.Table.from_pandas(n, preserve_index=False), p)
            files[s] = {"path": str(out_dir / f"{s}.parquet"), "rows": int(len(n)), "bytes": p.stat().st_size,
                        "file_sha256": R.sha256_path(p), "content_sha256": content_sha256(n),
                        "flipped": int(flag.sum())}
            frames[s] = (src[[c["group"], c["label_id"], "FWD Init Win Bytes"]], n[["FWD Init Win Bytes"]])
            ctx.log(f"  {s}: {len(n):,} rows, {int(flag.sum()):,} flipped -> {p.name} {files[s]['file_sha256'][:16]}..")
            del src, n
        # ---- cross-check with the gate (full run only)
        if not args.dry_run:
            gm = json.loads((GATE_RESULTS / "run_meta.json").read_text(encoding="utf-8"))
            gate = json.loads((Path(gm["cache_dir"]) / "gate.json").read_text(encoding="utf-8"))
            want = {(r["split"], r["group"], r["class"]): r["flag_R3"] for r in gate["rows"]}
            got = {(s, r["group"], r["class"]): r["flipped"] for s in SPLITS for r in out["flips"][s]}
            R.add_check(ctx, M, "flip counts per split x group x class == the R3 gate run", want == got,
                        f"gate run {gm['run_id']}: {sum(want.values()):,} rows")
            M["gate_run"] = {"run_id": gm["run_id"], "run_manifest_sha256": gm["run_manifest_sha256"]}
        shutil.copyfile(src_dir / "split_definition.json", part / "split_definition.json")
        man = {"manifest_version": 1, "dataset_version": OUT_VERSION, "created_utc": M["created_utc"], "status": "PASS",
               "dry_run": bool(args.dry_run), "script": SCRIPT, "run_id": ctx.run_id, "derived_from": M["source"],
               "orientation": M["orientation"], "test_policy": TEST_POLICY,
               "class_map": {"sha256": S.CLASS_MAP_SHA256, "classes": names},
               "features": {"file_sha256": S.FEATURES_V1_SHA256, "list_sha256": S.FEATURES_V1_LIST_SHA256, "n": len(feats),
                            "note": f"feature set and order unchanged; '{fc}' is metadata, never a model feature"},
               "split_definition": {"path": "split_definition.json", "sha256": R.sha256_path(part / "split_definition.json"),
                                    "copied_from": str(src_dir / "split_definition.json")},
               "counts": {s: dm["counts"][s] for s in SPLITS}, "caps": {k: v for k, v in dm["caps"].items()
                                                                        if k.split("|")[1] in SPLITS},
               "flips": out["flips"], "files": files, "code_sha256": M["code_sha256"],
               "content_sha256_of": "21b content_sha256: sha256 over per-column digests (column name + sha256 of the "
                                    "column's raw float64 / int64 bytes or NUL-joined strings)"}
        R.write_json(part / "dataset_manifest.json", man)
        part.rename(out_dir)
        M["files"] = files
        M["dataset_manifest_sha256"] = R.sha256_path(out_dir / "dataset_manifest.json")
        # ---- figures
        fig_flips(ctx.fig / "flips_per_split_group_class.png", out["flips"], names,
                  f"Rows flipped by the R3 orientation normaliser ({OUT_VERSION}), per split x group x class")
        A = cm.id_of(args.class_a)
        shares, ns = {"v2_0": {}, "v2_1": {}}, {}
        tops = set()
        for s, (sf, nf_) in frames.items():
            m = ((sf[c["group"]].astype(str) == args.focus_group) & (sf[c["label_id"]] == A)).to_numpy()
            ns[s] = int(m.sum())
            tops |= set(pd.Series(sf.loc[m, "FWD Init Win Bytes"]).value_counts().head(3).index)
        tops = sorted(float(t) for t in tops)
        for s, (sf, nf_) in frames.items():
            m = ((sf[c["group"]].astype(str) == args.focus_group) & (sf[c["label_id"]] == A)).to_numpy()
            for ver, v in (("v2_0", sf.loc[m, "FWD Init Win Bytes"]), ("v2_1", nf_.loc[m, "FWD Init Win Bytes"])):
                v = pd.to_numeric(v).to_numpy(float)
                d = {f"{t:g}": float((v == t).mean()) if len(v) else 0.0 for t in tops}
                d["other"] = float((~np.isin(v, tops)).mean()) if len(v) else 0.0
                shares[ver][s] = d
        shares["n"] = ns
        out["initwin_shares"] = shares
        fig_initwin(ctx.fig / "fwd_init_win_focus_A_v2_0_vs_v2_1.png", shares, A,
                    f"FWD Init Win Bytes of {args.focus_group} {args.class_a}, train vs val: v2_0 vs {OUT_VERSION}")
        R.write_json(ctx.partial / "21b.json", out)
        M["figures"] = sorted(str(p.relative_to(ctx.res)) for p in ctx.fig.glob("*.png"))
        ok = all(ch["pass"] for ch in M["checks"] if ch["level"] == "hard")
    except Exception as e:                                             # noqa: BLE001
        M["error"] = "".join(traceback.format_exception(e))
        ctx.log(f"ERROR: {e!r}")
        if part.exists():
            failed = part.with_name(part.name.replace(".partial", ".FAILED"))
            part.rename(failed)
            M["failed_output_kept"] = str(failed)
    M["pins_after"] = {p: R.sha256_path(q) for p, q in (("config/config.py", S.CONFIG_PY_PATH),
                                                         ("config/class_map.json", S.CLASS_MAP_PATH))}
    R.add_check(ctx, M, "config.py / class_map.json unchanged", M["pins_after"] == pins_before, "")
    ok = ok and M["pins_after"] == pins_before
    M["status"] = "PASS" if ok else "FAIL"
    write_summary(ctx.res / "summary.md", M, out, ctx)
    R.finish_run(ctx, ok, M)
    return 0 if ok else 1


def write_summary(path, M, out, ctx) -> None:
    L = [f"# Step 21b -- orientation-normalised dataset {OUT_VERSION} -- {M['status']}" + (" (DRY RUN)" if M["dry_run"] else ""),
         "", f"- run `{ctx.run_id}`; source `{(M.get('source') or {}).get('dataset_version')}` (train + val, sha256-checked; "
         f"test not read); output `{M['output_dir']}`",
         f"- rule R3 = `{M['orientation']['rule_text']}`; map sha256 `{M['orientation']['map_sha256']}`; "
         f"common/orientation.py sha256 `{M['orientation']['code_sha256']}`",
         f"- **test policy**: {M['test_policy']}", ""]
    if M.get("error"):
        L += ["## !!! FAILURE", "", "```", M["error"], "```", ""]
    L += ["## Checks", ""] + [f"- {'PASS' if ch['pass'] else 'FAIL'}  {ch['check']}  {ch['detail']}" for ch in M["checks"]] + [""]
    if out.get("flips"):
        L += ["## Flips per split x group x class", "", "| split | group | class | n | flipped | % |", "|---|---|---|---|---|---|"]
        for s, rows in out["flips"].items():
            L += [f"| {s} | {r['group']} | {r['class']} | {r['n']:,} | {r['flipped']:,} | {r['pct']:.4f} |" for r in rows]
        L += [""]
    if M.get("files"):
        L += ["## Files", "", "| split | rows | flipped | file sha256 | content sha256 |", "|---|---|---|---|---|"]
        L += [f"| {s} | {f['rows']:,} | {f['flipped']:,} | `{f['file_sha256']}` | `{f['content_sha256']}` |"
              for s, f in M["files"].items()]
        L += ["", f"- dataset_manifest.json sha256 `{M.get('dataset_manifest_sha256')}`", ""]
    if out.get("validate"):
        L += ["## validate_frame (common/schemas.py) on the source vs the normalised rows", ""]
        for s, v in out["validate"].items():
            L.append(f"- {s}: identical check results: {v['source'] == v['normalised']}; checks failing on BOTH (dataset "
                     f"layout != V1 raw-CSV contract): {v['failing_on_both']}; extra columns {v['extra_columns']}; missing "
                     f"meta {v['missing_meta']}; NaN/inf counts {v['nan_inf_total']}; blank-MAC violations {v['blank_mac_bad']}")
        L += [""]
    if out.get("initwin_shares"):
        sh = out["initwin_shares"]
        L += ["## FWD Init Win Bytes, focus-group class-A flows (share)", "", "| value | train v2_0 | train v2_1 | val v2_0 | val v2_1 |",
              "|---|---|---|---|---|"]
        for k in sh["v2_0"]["train"]:
            L.append(f"| {k} | {100 * sh['v2_0']['train'][k]:.1f} % | {100 * sh['v2_1']['train'][k]:.1f} % | "
                     f"{100 * sh['v2_0']['val'][k]:.1f} % | {100 * sh['v2_1']['val'][k]:.1f} % |")
        L += [""]
    L += ["## Figures", "", "- `figures/flips_per_split_group_class.png` -- rows flipped per split x group x class (symlog; "
          "flipped / n and %).",
          "- `figures/fwd_init_win_focus_A_v2_0_vs_v2_1.png` -- FWD Init Win Bytes value shares of the focus group's class-A "
          "flows, train vs val, v2_0 (left) vs v2_1 (right)."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
