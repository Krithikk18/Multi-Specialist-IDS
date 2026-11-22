#!/usr/bin/env python
"""diagnostics/phase3_2_test_counts.py -- Phase 3.2 PART C: test-count reconciliation (data for
results/phase3_2/tests/reconciliation.md).

1. Per phase commit (Phase 3 e9c845b, Phase 3.1 eabd7c9, Phase 4 14029ad; plus Phase 2 1383701 and orientation R4
   f7b1d4d for context): the test functions (`def test_*` at module level) of every tests/test_*.py, read READ-ONLY
   from the repository's loose object files with zlib (no git command is run; the object store is never written).
2. Now: every tests/test_*.py run in its own process: the V2 files with their own plain runner (python tests/<file>,
   "N/M passed"); V1 tests/test_rate_guard.py (no __main__; its usage line says pytest, which is not installed in any
   environment here) with an import-and-call driver that applies the plain runners' collection rule (module-level
   callables named test_* defined in that file, in definition order). sha256 of the V1 file and rate_guard.py before
   and after (V1 files are never edited).
3. Additions / removals per file between consecutive snapshots (a removal stops the reconciliation: reported FAIL).
Output: results/phase3_2/tests/counts.json (refused if it exists).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import time
import traceback
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config.config import REPO_ROOT, RESULTS_DIR  # noqa: E402
from common import schemas as S  # noqa: E402

COMMITS = {"phase2": "1383701bcb35cb860d597c75953a688fe07ea145", "phase3": "e9c845beade9d28c952b293e0ffa2460f40469ca",
           "orient_r4": "f7b1d4ded99b228a9d4a52afeb2003e0e6f00c26", "phase3_1": "eabd7c90e52c861738be6231c7b2bd12f027549d",
           "phase4": "14029adbfd05debfe671da4dc922d32dc5135e93"}
V1_FILE = "test_rate_guard.py"
PAT = re.compile(r"^def (test_\w+)\(", re.M)


def sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def git_obj(sha_: str) -> tuple[str, bytes]:
    raw = zlib.decompress((REPO_ROOT / ".git" / "objects" / sha_[:2] / sha_[2:]).read_bytes())
    hdr, _, body = raw.partition(b"\0")
    return hdr.split()[0].decode(), body


def git_tree(sha_: str) -> dict:
    t, b = git_obj(sha_)
    if t != "tree":
        raise ValueError(f"{sha_} is a {t}")
    out, i = {}, 0
    while i < len(b):
        sp = b.index(b" ", i)
        nul = b.index(b"\0", sp)
        out[b[sp + 1:nul].decode()] = b[nul + 1:nul + 21].hex()
        i = nul + 21
    return out


def snapshot(commit: str) -> dict:
    t, b = git_obj(commit)
    root = git_tree(re.search(rb"^tree ([0-9a-f]{40})", b, re.M).group(1).decode())
    tt = git_tree(root["tests"])
    files = {n: sorted(PAT.findall(git_obj(s)[1].decode("utf-8"))) for n, s in sorted(tt.items())
             if n.startswith("test_") and n.endswith(".py")}
    return {"commit": commit, "subject": b.split(b"\n\n", 1)[1].decode(errors="replace").splitlines()[0][:160],
            "files": files, "total": sum(map(len, files.values())),
            "total_excl_v1": sum(len(v) for k, v in files.items() if k != V1_FILE)}


V1_DRIVER = r'''
import importlib.util, sys, traceback
from pathlib import Path
p = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("test_rate_guard", p)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
tests = sorted([(n, f) for n, f in vars(m).items() if n.startswith("test_") and callable(f)
                and getattr(f, "__module__", "") == "test_rate_guard"], key=lambda kv: kv[1].__code__.co_firstlineno)
failed = 0
for n, f in tests:
    try:
        f(); print(f"  PASS  {n}")
    except Exception:
        failed += 1; print(f"  FAIL  {n}\n{traceback.format_exc()}")
print(f"\n{len(tests) - failed}/{len(tests)} passed")
sys.exit(1 if failed else 0)
'''


def run_now() -> dict:
    out = {}
    for f in sorted((REPO_ROOT / "tests").glob("test_*.py")):
        src = f.read_text(encoding="utf-8")
        if "__main__" in src:
            cmd, method = [sys.executable, str(f)], "plain runner: python tests/<file>"
        else:
            cmd, method = [sys.executable, "-c", V1_DRIVER, str(f)], "import-and-call driver (pytest not installed)"
        t0 = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        txt = r.stdout + r.stderr
        m = re.findall(r"(\d+)/(\d+) passed", txt)
        passed, total = (map(int, m[-1]) if m else (None, None))
        out[f.name] = {"method": method, "static_defs": len(PAT.findall(src)), "ran": total, "passed": passed,
                       "exit": r.returncode, "seconds": round(time.time() - t0, 1),
                       "failed": re.findall(r"FAIL\s+(test_\w+)", txt)}
        print(f"  {f.name:32s} static {out[f.name]['static_defs']:3d}  ran {total}  passed {passed}  exit {r.returncode}",
              flush=True)
    return out


def main() -> int:
    S.verify_v2_lock(strict=True)
    p0 = {"config/config.py": sha(S.CONFIG_PY_PATH), "config/class_map.json": sha(S.CLASS_MAP_PATH)}
    print(f"[start] verify_v2_lock OK; config.py {p0['config/config.py']}; class_map.json {p0['config/class_map.json']}")
    out_p = RESULTS_DIR / "phase3_2" / "tests" / "counts.json"
    if out_p.exists():
        raise SystemExit(f"{out_p} exists (never overwritten)")
    out_p.parent.mkdir(parents=True, exist_ok=True)
    v1 = {p: sha(REPO_ROOT / p) for p in ("tests/" + V1_FILE, "rate_guard.py")}
    res = {"script": "diagnostics/phase3_2_test_counts.py", "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "git": "commit snapshots read read-only from .git/objects (loose objects, zlib); no git command run",
           "snapshots": {}, "v1_sha256_before": v1}
    for k, c in COMMITS.items():
        try:
            res["snapshots"][k] = snapshot(c)
        except Exception as e:                                         # noqa: BLE001
            res["snapshots"][k] = {"commit": c, "error": repr(e)}
        s = res["snapshots"][k]
        print(f"  {k} {c[:7]}: {s.get('total')} test functions ({s.get('total_excl_v1')} excluding V1 {V1_FILE})")
    res["now"] = run_now()
    res["now_total_ran"] = sum(v["ran"] or 0 for v in res["now"].values())
    res["now_total_passed"] = sum(v["passed"] or 0 for v in res["now"].values())
    res["now_total_ran_excl_v1"] = sum(v["ran"] or 0 for k, v in res["now"].items() if k != V1_FILE)
    res["static_equals_ran"] = all(v["static_defs"] == v["ran"] for v in res["now"].values())
    order = ["phase3", "phase3_1", "phase4"]
    snaps = [res["snapshots"][k]["files"] for k in order] + [{k: sorted(PAT.findall((REPO_ROOT / "tests" / k).read_text(encoding="utf-8")))
                                                               for k in res["now"]}]
    labels = order + ["now"]
    res["changes"] = {}
    removed = []
    for (a, A), (b, B) in zip(zip(labels, snaps), list(zip(labels, snaps))[1:]):
        ch = {}
        for n in sorted(set(A) | set(B)):
            x, y = set(A.get(n, [])), set(B.get(n, []))
            if x != y:
                ch[n] = {"added": sorted(y - x), "removed": sorted(x - y), "new_file": n not in A, "file_gone": n not in B}
                removed += [(a, b, n, t) for t in sorted(x - y)]
        res["changes"][f"{a}->{b}"] = ch
    res["removed_tests"] = removed
    res["v1_sha256_after"] = {p: sha(REPO_ROOT / p) for p in v1}
    S.verify_v2_lock(strict=True)
    p1 = {"config/config.py": sha(S.CONFIG_PY_PATH), "config/class_map.json": sha(S.CLASS_MAP_PATH)}
    res["lock"] = {"start": p0, "end": p1}
    out_p.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    ok = (not removed and res["now_total_ran"] == res["now_total_passed"] and res["v1_sha256_after"] == v1 and p0 == p1)
    print(f"now: {res['now_total_passed']}/{res['now_total_ran']} passed ({res['now_total_ran_excl_v1']} V2 + "
          f"{res['now'].get(V1_FILE, {}).get('ran')} V1); removed tests: {removed or 'none'}; static == ran: "
          f"{res['static_equals_ran']}")
    print(f"[end] verify_v2_lock OK; config.py {p1['config/config.py']}; class_map.json {p1['config/class_map.json']} -> {out_p}")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:                                                  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
