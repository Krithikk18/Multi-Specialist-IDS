#!/usr/bin/env python
"""config/config.py -- single source of truth for paths and locked pipeline settings.

Stdlib only. Import from scripts run at the repo root:
    from config.config import DEVICE_TABLE, EXTRACTOR, apply_training_filter, verify_lock

`python -m config.config` prints a summary and runs verify_lock(); exit 1 on failure.

Environment overrides
  LGIDS_CACHE   cache directory for heavy pcaps (default ~/lgids_cache, WSL native fs)
  LGIDS_JAR     CICFlowMeter jar (default: the patched singlepkt build, see EXTRACTOR)

Time zone
  CICFlowMeter writes flow Timestamps in the JVM's local time zone, which Java reads from
  TZ when the JVM starts. Setting TZ inside this Python process does not change the
  timestamps; the subprocess must be started with TZ=UTC. verify_lock() returns that env:
      subprocess.run([...], env=verify_lock()["env"])
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- paths
REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"
DATA_DIR = REPO_ROOT / "data"
DATA_RAW = DATA_DIR / "raw"
DATA_INTERIM = DATA_DIR / "interim"
FLOWS_DIR = DATA_INTERIM / "flows"
RESULTS_DIR = REPO_ROOT / "results"
DEVICE_TABLE = CONFIG_DIR / "device_table.csv"
IP_MAC_MAP = CONFIG_DIR / "ip_mac_map.csv"
BEHAVIOUR_GROUPS = CONFIG_DIR / "behaviour_groups.json"
CACHE_DIR = Path(os.environ.get("LGIDS_CACHE") or Path.home() / "lgids_cache").expanduser()
# Attack flow CSVs (tens of millions of rows for the SYN parts) live on the fast cache fs, not /mnt/d.
ATTACK_FLOWS_DIR = CACHE_DIR / "flows" / "attack"

# Patched singlepkt build + idle sweeper (~/tools/CICFlowMeter-sweep = the singlepkt tree with
# extractor/idle_sweeper.patch applied; run_cicflowmeter.py --build singlepkt). The previous
# singlepkt-only jar (sha256 a96e7255...) is kept unchanged in ~/tools/CICFlowMeter-singlepkt.
_DEFAULT_JAR = ("/home/krithikk/tools/CICFlowMeter-sweep/build/install/CICFlowMeter/"
                "lib/CICFlowMeter-4.0.jar")


# --------------------------------------------------------------------------- lock records
@dataclass(frozen=True)
class Extractor:
    upstream: str = "ahlashkari/CICFlowMeter"
    commit: str = "98a5eba"
    patch: str = "extractor/guard_gt0.patch"   # relative to REPO_ROOT
    patch_sweeper: str = "extractor/idle_sweeper.patch"   # applied after patch
    note: str = ("idle sweeper: every 10 s of capture time, flows past flow timeout + 60 s slack are "
                 "emitted and removed (tombstones rebuild the identical successor flow); rows are "
                 "identical to the singlepkt-only jar a96e7255... after sorting, only the row order "
                 "changes (regression: BenignTraffic.pcap and the 3M-packet SYN cut)")
    build: str = "singlepkt"
    # JVM heap cap the wrapper passes to cfm (appended last to CFM_OPTS, so it wins over any
    # caller -Xmx). The default (1/4 of RAM, 2.45 GB here) runs out on the SYN-flood parts even
    # with the sweeper: DDoS-SYN_Flood.pcap peaked at 4.22 GB RSS with -Xmx4g; 6g is the margin.
    java_heap_max: str = "-Xmx6g"
    flow_timeout_s: int = 120
    activity_timeout_s: int = 5
    tz: str = "UTC"
    jar_path: Path = field(default_factory=lambda: Path(os.environ.get("LGIDS_JAR") or _DEFAULT_JAR))
    jar_sha256: str = "01acf9411e7ab6a06c6b1c352ac7485f155b053077b58880622049cbfd708995"

    @property
    def patch_path(self) -> Path:
        return REPO_ROOT / self.patch

    @property
    def patch_sweeper_path(self) -> Path:
        return REPO_ROOT / self.patch_sweeper


@dataclass(frozen=True)
class Dataset:
    name: str = "CICIoT2023"
    source: str = "raw_pcaps_only"
    benign_pcap: str = "BenignTraffic.pcap"
    # From results/step5/ip_mac_map_report.md (pcap_cache, verified) and the cache sidecar
    # ~/lgids_cache/BenignTraffic.pcap.sha256.json; both agree.
    benign_pcap_sha256: str = "549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8"

    @property
    def benign_pcap_path(self) -> Path:
        return DATA_RAW / "ciciot2023" / "benign" / self.benign_pcap

    @property
    def benign_pcap_cached(self) -> Path:
        return CACHE_DIR / self.benign_pcap


@dataclass(frozen=True)
class Network:
    subnets: tuple[str, ...] = ("192.168.137.0/24", "10.22.22.0/24")
    gateway_ip: str = "192.168.137.1"


@dataclass(frozen=True)
class Groups:
    version: str = "v1.0"
    path: Path = BEHAVIOUR_GROUPS
    labels: tuple[str, ...] = ("G1", "G2", "GEN")


@dataclass(frozen=True)
class AttackerMacs:
    exact: tuple[str, ...] = ("e4:5f:01:55:90:c4",)
    prefixes: tuple[str, ...] = ("dc:a6:32",)   # testbed Raspberry Pis

    def matches(self, mac: str) -> bool:
        m = mac.strip().lower()
        return m in self.exact or any(m.startswith(p) for p in self.prefixes)


EXTRACTOR = Extractor()
DATASET = Dataset()
NETWORK = Network()
GROUPS = Groups()
ATTACKER_MACS = AttackerMacs()


# --------------------------------------------------------------------------- training filter
TRAINING_FILTER_RULE = 'owner_status == "owned" and exclude_reason == ""'


def apply_training_filter(df):
    """Rows usable for training: owner_status == "owned" and exclude_reason blank.
    A missing exclude_reason (NaN, if the CSV was read without keep_default_na=False)
    counts as blank."""
    reason = df["exclude_reason"].fillna("").astype(str)
    return df[(df["owner_status"] == "owned") & (reason == "")]


# --------------------------------------------------------------------------- verification
class LockError(RuntimeError):
    pass


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def verify_lock(strict: bool = True) -> dict:
    """Check the jar (exists, SHA256 matches), the config files and the groups lock.

    Returns {"ok": bool, "checks": [(name, ok, detail), ...], "env": {**os.environ, "TZ": "UTC"}}.
    Pass "env" to every CICFlowMeter subprocess (see module docstring). Raises LockError on
    any failed check when strict.
    """
    checks = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    jar = EXTRACTOR.jar_path
    if jar.is_file():
        got = sha256_file(jar)
        check("extractor jar sha256", got == EXTRACTOR.jar_sha256,
              f"{jar} ({got[:16]}...)" if got == EXTRACTOR.jar_sha256
              else f"{jar}: expected {EXTRACTOR.jar_sha256}, got {got}")
    else:
        check("extractor jar exists", False, f"not found: {jar} (set LGIDS_JAR)")
    check("extractor patch exists", EXTRACTOR.patch_path.is_file(), str(EXTRACTOR.patch_path))
    check("extractor sweeper patch exists", EXTRACTOR.patch_sweeper_path.is_file(),
          str(EXTRACTOR.patch_sweeper_path))
    for p in (DEVICE_TABLE, IP_MAC_MAP, BEHAVIOUR_GROUPS):
        check(f"config file {p.name}", p.is_file(), str(p))
    if BEHAVIOUR_GROUPS.is_file():
        lock = json.loads(BEHAVIOUR_GROUPS.read_text(encoding="utf-8"))
        v = str(lock.get("version", ""))
        check("groups version", v.lstrip("v") == GROUPS.version.lstrip("v"),
              f"behaviour_groups.json version {v!r} vs GROUPS.version {GROUPS.version!r}")
        labels = set(lock.get("labels", {}))
        check("groups labels", labels == set(GROUPS.labels),
              f"{sorted(labels)} vs {list(GROUPS.labels)}")
        check("groups lock verified", lock.get("verification", {}).get("pass") is True,
              "behaviour_groups.json verification.pass")
    env = {**os.environ, "TZ": EXTRACTOR.tz}
    cur = os.environ.get("TZ")
    check("extractor TZ", env["TZ"] == "UTC",
          f"subprocess env TZ=UTC (this shell: TZ={cur!r}; not used by the JVM unless passed)")
    ok = all(c[1] for c in checks)
    if strict and not ok:
        raise LockError("lock verification failed: "
                        + "; ".join(f"{n}: {d}" for n, o, d in checks if not o))
    return {"ok": ok, "checks": checks, "env": env}


def summary() -> str:
    def block(title: str, d: dict) -> list[str]:
        w = max(map(len, d))
        return [title] + [f"  {k:<{w}} : {v}" for k, v in d.items()]

    L = [f"LG-IDS AIML config  ({Path(__file__).relative_to(REPO_ROOT)})", ""]
    L += block("PATHS", {"REPO_ROOT": REPO_ROOT, "DATA_RAW": DATA_RAW,
                         "DATA_INTERIM": DATA_INTERIM, "FLOWS_DIR": FLOWS_DIR,
                         "RESULTS_DIR": RESULTS_DIR, "CONFIG_DIR": CONFIG_DIR,
                         "DEVICE_TABLE": DEVICE_TABLE, "IP_MAC_MAP": IP_MAC_MAP,
                         "BEHAVIOUR_GROUPS": BEHAVIOUR_GROUPS,
                         "CACHE_DIR": f"{CACHE_DIR}"
                                      + ("  (LGIDS_CACHE)" if os.environ.get("LGIDS_CACHE") else ""),
                         "ATTACK_FLOWS_DIR": ATTACK_FLOWS_DIR})
    L += [""] + block("EXTRACTOR", {**asdict(EXTRACTOR),
                                    "jar_path": f"{EXTRACTOR.jar_path}"
                                                + ("  (LGIDS_JAR)" if os.environ.get("LGIDS_JAR") else "")})
    L += [""] + block("DATASET", {**asdict(DATASET), "benign_pcap_path": DATASET.benign_pcap_path,
                                  "benign_pcap_cached": DATASET.benign_pcap_cached})
    L += [""] + block("NETWORK", asdict(NETWORK))
    L += [""] + block("GROUPS", asdict(GROUPS))
    L += [""] + block("ATTACKER_MACS", asdict(ATTACKER_MACS))
    L += ["", "TRAINING_FILTER", f"  {TRAINING_FILTER_RULE}"]
    return "\n".join(L)


def main() -> int:
    print(summary())
    res = verify_lock(strict=False)
    print("\nVERIFY_LOCK")
    for name, ok, detail in res["checks"]:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<34} {detail}")
    print(f"\n{'LOCK OK' if res['ok'] else 'LOCK FAILED'}")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
