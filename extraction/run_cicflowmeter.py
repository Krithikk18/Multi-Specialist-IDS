"""
run_cicflowmeter.py — Offline flow extraction via Java CICFlowMeter.

Wraps the `cfm` CLI (cic.cs.unb.ca.ifm.Cmd) from a built CICFlowMeter
distribution: pcap file in, per-flow CSV out.

Two things about `cfm` that this wrapper exists to handle:

1. Its start script sets `-Djava.library.path=../lib/native`, which is
   RELATIVE.  Run it from anywhere but the distribution's own bin/ and the
   native jnetpcap load fails with UnsatisfiedLinkError.  We always launch
   with cwd=<dist>/bin.

2. The output filename is derived from the input filename by a convention
   we deliberately do NOT hardcode.  We snapshot the output directory
   before and after the run and pick up whatever actually appeared.

Note on flow counts: CICFlowMeter discards every flow with <= 1 packet
(`if(flow.packetCount()>1)` guards every emit path in FlowGenerator.java).
Captures dominated by unanswered scan attempts therefore yield far fewer
flows than Zeek reports connections.  That is by design, not a fault here.

Paper_Implemetation copy (from Implemetation_Demo/extraction/run_cicflowmeter.py):
  - jar / build / timeouts come from config.config.EXTRACTOR; verify_lock() runs
    before extraction and any mismatch (e.g. jar SHA256) aborts with exit 1.
  - Java always runs with TZ=UTC; -Duser.timezone flags in the caller's JAVA_OPTS /
    CFM_OPTS / JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS are stripped so they cannot override it.
  - flow/activity timeouts are compiled into Cmd.java (cfm takes no timeout args); they
    are checked against the build's Cmd.java source when it is present, and recorded.
  - a sidecar <csv>.meta.json records the provenance of each output CSV.
  - the summary prints the output path for any --out-dir (the old relative_to crash).
  - the JVM heap cap is locked: EXTRACTOR.java_heap_max is appended last to CFM_OPTS (caller
    -Xmx flags are stripped) and recorded in the sidecar.
  - idle sweeper (extractor/idle_sweeper.patch): its end-of-run stats go into the sidecar; a run
    with any packet beyond the sweeper's slack, or without the stats line, fails (exit 1) and
    gets no sidecar, so it is never reused.
  - one extraction per out-dir: an exclusive flock on <out-dir>/.cfm.lock is held for the
    whole run; a second run on the same out-dir exits 1 instead of deleting the CSV the first
    is writing (that race made the first cfm crash with an NPE in InsertCsvRow.insert).

Usage (from the repo root):
    python extraction/run_cicflowmeter.py                     # benign pcap (config DATASET)
    python extraction/run_cicflowmeter.py --pcap path/to.pcap --out-dir DIR --suffix singlepkt

Author: LG-IDS Project
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ── Repo-root-relative configuration ──────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:  # `from config.config import ...` from any cwd
    sys.path.insert(0, str(REPO_ROOT))
from config.config import DATASET, EXTRACTOR, FLOWS_DIR, LockError, verify_lock  # noqa: E402

_TZ_FLAG_RE = re.compile(r"(?:^|\s)-Duser\.timezone=\S*")
_XMX_RE = re.compile(r"(?:^|\s)-Xmx\S*")
_JVM_OPT_VARS = ("JAVA_OPTS", "CFM_OPTS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS")

# cfm prints one progress line per flow; the useful summary is only at the end.
_TOTAL_RE = re.compile(r"is done\.\s*total\s+(\d+)\s+flows")
_PKT_RE = re.compile(r"Packet stats:\s*Total=(\d+),Valid=(\d+),Discarded=(\d+)")
# end-of-run line of the idle sweeper (extractor/idle_sweeper.patch), printed on stderr
_SWEEP_RE = re.compile(r"idle sweeper: sweeps=(\d+) swept_flows=(\d+) tombstones_left=(\d+) "
                       r"successors_from_tombstone=(\d+) late_packets_beyond_slack=(\d+) \(slack (\d+) s")


class ExtractionError(RuntimeError):
    """Raised when extraction fails or produces nothing usable."""


# ── Config ────────────────────────────────────────────────────────────────────

def resolve_cicflowmeter_home(build: str | None = None) -> Path:
    """
    Locate the built CICFlowMeter distribution from config.config.EXTRACTOR:
    the jar is <home>/lib/<jar>, so home = jar_path.parent.parent (LGIDS_JAR overrides).
    Only the locked build (EXTRACTOR.build) is accepted.
    """
    if build and build != EXTRACTOR.build:
        raise ExtractionError(
            f"--build {build!r} does not match the locked build {EXTRACTOR.build!r} "
            f"(config/config.py EXTRACTOR.build)")
    home = EXTRACTOR.jar_path.parent.parent
    source = f"config.config EXTRACTOR.jar_path ({EXTRACTOR.jar_path})"

    cfm = home / "bin" / "cfm"
    if not home.is_dir():
        raise ExtractionError(
            f"CICFlowMeter home does not exist: {home}\n"
            f"  (from {source})\n"
            f"  Build it with:  cd <repo> && ./gradlew installDist"
        )
    if not cfm.is_file():
        raise ExtractionError(
            f"cfm launcher not found: {cfm}\n"
            f"  (CICFlowMeter home from {source})\n"
            f"  Expected the unpacked output of `gradlew installDist`."
        )
    if not os.access(cfm, os.X_OK):
        raise ExtractionError(f"cfm is not executable: {cfm}")

    natives = list((home / "lib" / "native").glob("libjnetpcap*.so"))
    if not natives:
        raise ExtractionError(
            f"No libjnetpcap*.so under {home / 'lib' / 'native'} — "
            f"cfm will fail with UnsatisfiedLinkError."
        )
    return home


def resolve_pcap(pcap_arg: str | None) -> Path:
    """Resolve the input pcap: explicit path, else the benign pcap (config DATASET)."""
    if pcap_arg:
        pcap = Path(pcap_arg)
        if not pcap.is_absolute():
            pcap = REPO_ROOT / pcap
    else:
        pcap = DATASET.benign_pcap_path

    if not pcap.is_file():
        raise ExtractionError(f"pcap not found: {pcap}")
    return pcap


def check_compiled_timeouts(cfm_home: Path) -> str:
    """cfm takes no timeout args: they are constants in Cmd.java. If the build's source
    tree is next to the distribution, check them against EXTRACTOR; else say unchecked."""
    src = cfm_home.parents[2] / "src/main/java/cic/cs/unb/ca/ifm/Cmd.java"
    if not src.is_file():
        return f"unchecked (no source at {src})"
    text = src.read_text(encoding="utf-8", errors="replace")
    got = {}
    for name in ("flowTimeout", "activityTimeout"):
        m = re.search(rf"long\s+{name}\s*=\s*(\d+)L", text)
        got[name] = int(m.group(1)) if m else None
    want = {"flowTimeout": EXTRACTOR.flow_timeout_s * 1_000_000,
            "activityTimeout": EXTRACTOR.activity_timeout_s * 1_000_000}
    if got != want:
        raise ExtractionError(f"Cmd.java timeouts {got} (µs) != config {want} (µs): {src}")
    return f"verified against {src}"


def utc_env() -> dict:
    """Caller's environment with TZ=UTC forced, any -Duser.timezone / -Xmx JVM flag removed, and
    the locked heap cap (EXTRACTOR.java_heap_max) appended last to CFM_OPTS (cfm puts CFM_OPTS
    after JAVA_OPTS on the java command line, and the last -Xmx wins)."""
    env = dict(verify_lock(strict=False)["env"], TZ="UTC")
    for k in _JVM_OPT_VARS:
        if k in env:
            env[k] = _XMX_RE.sub(" ", _TZ_FLAG_RE.sub(" ", env[k])).strip()
    env["CFM_OPTS"] = f"{env.get('CFM_OPTS', '')} {EXTRACTOR.java_heap_max}".strip()
    return env


def parse_sweeper(combined: str) -> dict:
    """The idle sweeper's end-of-run statistics. Raises unless present with 0 late packets: a
    packet older than (max time seen - slack) can make a swept flow differ from the flow the
    unswept code would have produced, so such a CSV is not accepted."""
    m = _SWEEP_RE.search(combined)
    if not m:
        raise ExtractionError("cfm did not print the idle-sweeper statistics line; the jar is "
                              "not the locked sweeper build")
    keys = ("sweeps", "swept_flows", "tombstones_left", "successors_from_tombstone",
            "late_packets_beyond_slack", "slack_s")
    st = dict(zip(keys, (int(g) for g in m.groups())))
    if st["late_packets_beyond_slack"] > 0:
        raise ExtractionError(
            f"idle sweeper: {st['late_packets_beyond_slack']:,} packets older than (max time seen - "
            f"{st['slack_s']} s slack); the output may differ from the unswept extractor, so it is "
            f"rejected (no meta sidecar written). Sweeper stats: {st}")
    return st


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def wrapper_git_commit() -> str | None:
    """HEAD of this repo, with '-dirty' if this wrapper differs from HEAD / is untracked."""
    def git(*a):
        return subprocess.run(["git", "-C", str(REPO_ROOT), *a], capture_output=True,
                              text=True, timeout=30)
    try:
        head = git("rev-parse", "HEAD")
        if head.returncode != 0:
            return None
        rel = Path(__file__).resolve().relative_to(REPO_ROOT).as_posix()
        st = git("status", "--porcelain", "--", rel).stdout.strip()
        return head.stdout.strip() + ("-dirty" if st else "")
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


# ── Extraction ────────────────────────────────────────────────────────────────

def _count_csv_rows(path: Path) -> int:
    """Count data rows (total lines minus the header)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        n = sum(1 for _ in fh)
    return max(n - 1, 0)


LOCK_NAME = ".cfm.lock"


def acquire_dir_lock(out_dir: Path, pcap: Path):
    """Exclusive, non-blocking flock on <out_dir>/.cfm.lock; returns the open handle (keep it
    alive for the whole run). Two cfm runs on one out-dir race: each start deletes the CSV the
    other is appending to, and InsertCsvRow.insert then hits a null stream (NPE at line 71).
    flock is released by the kernel when the process exits, so a crash leaves no stale lock."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / LOCK_NAME
    fh = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip() or "unknown"
        fh.close()
        raise ExtractionError(f"another extraction is writing to {out_dir} (lock {path} held by: "
                              f"{holder}); refusing to start a second one")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid {os.getpid()} pcap {pcap} since "
             f"{dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}\n")
    fh.flush()
    return fh


def run_cicflowmeter(
    pcap: Path,
    out_dir: Path,
    cfm_home: Path,
    timeout: float = 3600.0,
    overwrite: bool = True,
) -> dict:
    """
    Run cfm offline on a single pcap and return a result summary.

    Parameters
    ----------
    pcap : Path
        Input capture file.
    out_dir : Path
        Directory cfm writes its CSV into (created if absent).
    cfm_home : Path
        Root of the built CICFlowMeter distribution.
    timeout : float
        Hard limit in seconds for the subprocess.
    overwrite : bool
        Remove pre-existing output for this pcap first, so repeat runs are
        idempotent rather than ambiguous.

    Returns
    -------
    dict with keys: csv_path, flow_count, reported_flows, packets_total,
    packets_valid, packets_discarded, elapsed_s
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = cfm_home / "bin"
    cfm = bin_dir / "cfm"

    # Snapshot BEFORE, so we can identify whatever cfm creates without
    # assuming its naming convention.
    before = {p: p.stat().st_mtime for p in out_dir.iterdir() if p.is_file()}

    # Idempotency: clear only the exact file cfm is about to write.
    #
    # This used to match any name starting with the pcap's, which silently
    # deleted tagged outputs from earlier runs — extracting with the stock
    # build and then the patched one destroyed the stock result, which is the
    # comparison the two builds exist for.
    for p in list(before):
        if overwrite and p.name == f"{pcap.name}_Flow.csv":
            print(f"  [overwrite] removing existing {p.name}")
            p.unlink()
            before.pop(p, None)

    print(f"  cfm      : {cfm}")
    print(f"  cwd      : {bin_dir}   (required: java.library.path is relative)")
    print(f"  input    : {pcap}")
    print(f"  output   : {out_dir}")

    # CICFlowMeter formats its Timestamp column with the JVM's DEFAULT
    # timezone.  On a machine set to, say, IST every timestamp would be
    # shifted +5:30 against Zeek's UTC epoch and the label join would break
    # silently.  Pin TZ=UTC so extraction is reproducible on any machine
    # (and strip caller -Duser.timezone flags, which would override TZ).
    env = utc_env()
    assert env["TZ"] == "UTC"

    started_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    start = time.time()
    proc = subprocess.run(
        [str(cfm), str(pcap), str(out_dir)],
        cwd=str(bin_dir),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    elapsed = time.time() - start
    ended_utc = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    combined = (proc.stdout or "") + (proc.stderr or "")

    if proc.returncode != 0:
        tail = "\n".join(combined.strip().splitlines()[-25:])
        raise ExtractionError(
            f"cfm exited {proc.returncode} after {elapsed:.1f}s.\n"
            f"--- last output ---\n{tail}"
        )

    # cfm's own reported totals (one progress line per flow; summary at end).
    m_total = _TOTAL_RE.search(combined)
    m_pkt = _PKT_RE.search(combined)
    reported_flows = int(m_total.group(1)) if m_total else None
    pkts = (
        tuple(int(g) for g in m_pkt.groups()) if m_pkt else (None, None, None)
    )
    sweeper = parse_sweeper(combined)

    # Identify new/modified output files.
    after = {p: p.stat().st_mtime for p in out_dir.iterdir() if p.is_file()}
    produced = [p for p, mt in after.items() if p not in before or mt > before[p]]

    if not produced:
        raise ExtractionError(
            f"cfm exited 0 but produced no file in {out_dir}.\n"
            f"  This usually means the pcap had no flows with >1 packet, or\n"
            f"  the native library failed to load silently.\n"
            f"--- last output ---\n"
            + "\n".join(combined.strip().splitlines()[-15:])
        )
    if len(produced) > 1:
        print(f"  [warn] cfm produced {len(produced)} files: "
              f"{[p.name for p in produced]}")

    csv_path = max(produced, key=lambda p: p.stat().st_mtime)
    flow_count = _count_csv_rows(csv_path)

    # Fail loudly on empty output.
    if csv_path.stat().st_size == 0:
        raise ExtractionError(f"Output file is zero bytes: {csv_path}")
    if flow_count == 0:
        raise ExtractionError(
            f"Output has a header but ZERO flow rows: {csv_path}\n"
            f"  Extraction produced nothing usable — refusing to continue."
        )

    return {
        "csv_path": csv_path,
        "flow_count": flow_count,
        "reported_flows": reported_flows,
        "packets_total": pkts[0],
        "packets_valid": pkts[1],
        "packets_discarded": pkts[2],
        "elapsed_s": elapsed,
        "started_utc": started_utc,
        "ended_utc": ended_utc,
        "tz": env["TZ"],
        "cfm_opts": env["CFM_OPTS"],
        "sweeper": sweeper,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract CICFlowMeter flow features from a pcap (offline mode)."
    )
    ap.add_argument("--pcap", default=None,
                    help="explicit pcap path (repo-relative or absolute); "
                         "default: config DATASET benign pcap")
    ap.add_argument("--out-dir", default=None,
                    help="output dir (default: config FLOWS_DIR)")
    ap.add_argument("--build", default=None,
                    help=f"CICFlowMeter build; must equal the locked build "
                         f"(config EXTRACTOR.build = {EXTRACTOR.build!r}), which is "
                         f"also the default.")
    ap.add_argument("--suffix", default=None,
                    help="tag appended to the output filename, so runs from "
                         "different builds do not overwrite each other")
    ap.add_argument("--timeout", type=float, default=3600.0,
                    help="subprocess timeout in seconds (default 3600)")
    args = ap.parse_args()

    print("=" * 70)
    print("CICFlowMeter — offline extraction")
    print("=" * 70)

    try:
        # Lock check first: jar SHA256, config files, groups lock. Any mismatch aborts.
        try:
            verify_lock(strict=True)
        except LockError as exc:
            raise ExtractionError(str(exc)) from exc
        print(f"  lock     : OK (jar sha256 {EXTRACTOR.jar_sha256[:16]}..., "
              f"commit {EXTRACTOR.commit})")
        cfm_home = resolve_cicflowmeter_home(args.build)
        build_name = EXTRACTOR.build
        print(f"  build    : {build_name}")
        timeouts_check = check_compiled_timeouts(cfm_home)
        print(f"  timeouts : flow {EXTRACTOR.flow_timeout_s}s, activity "
              f"{EXTRACTOR.activity_timeout_s}s ({timeouts_check})")
        pcap = resolve_pcap(args.pcap)
        out_dir = Path(args.out_dir) if args.out_dir else FLOWS_DIR
        if not out_dir.is_absolute():
            out_dir = REPO_ROOT / out_dir
        # Held until the CSV is renamed and its sidecar written (released by the OS on exit).
        lock_fh = acquire_dir_lock(out_dir, pcap)

        result = run_cicflowmeter(pcap, out_dir, cfm_home, timeout=args.timeout)

        # Tag the output so stock and patched runs coexist for comparison.
        if args.suffix:
            tagged = result["csv_path"].with_name(
                f"{result['csv_path'].stem}__{args.suffix}"
                f"{result['csv_path'].suffix}")
            result["csv_path"].replace(tagged)
            result["csv_path"] = tagged

        # Provenance sidecar next to the CSV.
        meta_path = result["csv_path"].with_name(result["csv_path"].name + ".meta.json")
        meta = {
            "csv": str(result["csv_path"]),
            "input_pcap": str(pcap),
            "input_pcap_sha256": sha256_file(pcap),
            "jar_path": str(EXTRACTOR.jar_path),
            "jar_sha256": sha256_file(EXTRACTOR.jar_path),
            "jar_sha256_expected": EXTRACTOR.jar_sha256,
            "upstream": EXTRACTOR.upstream,
            "commit": EXTRACTOR.commit,
            "patch": EXTRACTOR.patch,
            "patch_sweeper": EXTRACTOR.patch_sweeper,
            "java_heap_max": EXTRACTOR.java_heap_max,
            "cfm_opts": result["cfm_opts"],
            "idle_sweeper": result["sweeper"],
            "build": build_name,
            "flow_timeout_s": EXTRACTOR.flow_timeout_s,
            "activity_timeout_s": EXTRACTOR.activity_timeout_s,
            "timeouts_check": timeouts_check,
            "tz": result["tz"],
            "started_utc": result["started_utc"],
            "ended_utc": result["ended_utc"],
            "elapsed_s": round(result["elapsed_s"], 3),
            "row_count": result["flow_count"],
            "cfm_reported_flows": result["reported_flows"],
            "packets": {"total": result["packets_total"], "valid": result["packets_valid"],
                        "discarded": result["packets_discarded"]},
            "wrapper": str(Path(__file__).resolve()),
            "wrapper_git_commit": wrapper_git_commit(),
        }
        if meta["jar_sha256"] != EXTRACTOR.jar_sha256:  # jar changed during the run
            raise ExtractionError(f"jar SHA256 changed during extraction: {meta['jar_sha256']}")
        meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    except ExtractionError as exc:
        print(f"\nFAILED: {exc}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print(f"\nFAILED: cfm exceeded the {args.timeout}s timeout.",
              file=sys.stderr)
        return 1

    # Repo-relative when the CSV is inside the repo, absolute otherwise (was a
    # bare relative_to(REPO_ROOT), which raised ValueError for any outside out-dir).
    try:
        shown = result["csv_path"].relative_to(REPO_ROOT)
    except ValueError:
        shown = result["csv_path"]
    print()
    print("-" * 70)
    print(f"  output file      : {shown}")
    print(f"  metadata         : {meta_path.name}")
    print(f"  filename pattern : <input pcap filename> + '_Flow.csv'")
    print(f"  flow rows in CSV : {result['flow_count']}")
    if result["reported_flows"] is not None:
        print(f"  cfm reported     : {result['reported_flows']} flows")
        if result["reported_flows"] != result["flow_count"]:
            print("  [warn] cfm's reported count differs from CSV row count")
    if result["packets_total"] is not None:
        print(f"  packets          : total={result['packets_total']} "
              f"valid={result['packets_valid']} "
              f"discarded={result['packets_discarded']}")
    print(f"  elapsed          : {result['elapsed_s']:.1f}s")
    print("-" * 70)
    print("Extraction complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
