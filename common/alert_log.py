"""common/alert_log.py -- append-only, hash-chained, Ed25519-signed JSONL logs (DFD P6 -> S3): alerts, health, outbox.

    secret, public = ensure_runtime_keys(cfg)                 # ~/lgids_cache/keys/runtime/ (never inside the repo)
    log = ChainLog(run_dir / "alerts.jsonl", secret, stream="alerts")
    log.append({...})                                         # adds seq, stream, prev_sha256, sig
    log.close()                                               # -> {"n", "head_sha256"} (recorded in the run manifest)
    verify_chain(path, public, expect_n=..., expect_head=...) # {"ok", "n", "head_sha256", "error", "line"}

Record = canonical JSON (sort_keys, no spaces) of {seq, stream, prev_sha256, ...fields, sig}; prev_sha256 = sha256 of the
previous line's bytes (without its newline; the first record carries 64 zeros); sig = Ed25519 over the canonical JSON
of the record without "sig". An edited line fails its signature, a deleted / reordered / inserted line breaks seq or
the chain, a cut tail is caught by the expected count / head kept outside the file (run manifest). The runtime key
is a different key from the registry signing key (common/registry.py), stored in its own directory, mode 600.
The log refuses to open an existing file (append-only per run, never overwritten).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from common import registry as REG

KEY_NAME = "runtime_ed25519"
GENESIS = "0" * 64


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_default).encode("utf-8")


def _default(o):
    if hasattr(o, "item"):
        return o.item()
    if isinstance(o, (set, tuple)):
        return list(o)
    return str(o)


def ensure_runtime_keys(keys_dir: Path, repo_root: Path | None = None) -> tuple[bytes, bytes]:
    """(secret, public) of the runtime alert key; created (os.urandom, file 600, dir 700) if absent. Never printed."""
    keys_dir = Path(keys_dir).expanduser().resolve()
    if repo_root is not None:
        rr = Path(repo_root).resolve()
        if keys_dir == rr or rr in keys_dir.parents:
            raise PermissionError(f"runtime keys dir {keys_dir} is inside the repository {rr}")
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
        raise PermissionError(f"{pk_p} does not match {sk_p}")
    return secret, public


def runtime_public_key(keys_dir: Path) -> bytes:
    return bytes.fromhex((Path(keys_dir).expanduser() / f"{KEY_NAME}.pub").read_text(encoding="ascii").strip())


class ChainLog:
    def __init__(self, path: Path, secret: bytes, stream: str, flush_every: int = 256):
        self.path = Path(path)
        self.fh = open(self.path, "xb")                                  # refuses an existing file
        self.secret, self.stream = secret, stream
        self.prev, self.seq = GENESIS, 0
        self.flush_every = flush_every

    def append(self, fields: dict) -> dict:
        rec = {**fields, "seq": self.seq, "stream": self.stream, "prev_sha256": self.prev}
        rec["sig"] = REG.sign(self.secret, canon(rec)).hex()
        line = canon(rec)
        self.fh.write(line + b"\n")
        self.prev = hashlib.sha256(line).hexdigest()
        self.seq += 1
        if self.seq % self.flush_every == 0:
            self.fh.flush()
        return rec

    def close(self) -> dict:
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.fh.close()
        return {"n": self.seq, "head_sha256": self.prev, "file_sha256": REG.sha256_file(self.path)}


def verify_chain(path: Path, public: bytes, expect_n: int | None = None, expect_head: str | None = None) -> dict:
    prev, n = GENESIS, 0
    try:
        with open(path, "rb") as fh:
            for i, raw in enumerate(fh):
                if not raw.endswith(b"\n"):
                    return {"ok": False, "n": n, "head_sha256": prev, "line": i, "error": "unterminated last line"}
                line = raw[:-1]
                rec = json.loads(line)
                if canon(rec) != line:
                    return {"ok": False, "n": n, "head_sha256": prev, "line": i, "error": "not canonical JSON"}
                sig = bytes.fromhex(rec.pop("sig", ""))
                if rec.get("seq") != i:
                    return {"ok": False, "n": n, "head_sha256": prev, "line": i, "error": f"seq {rec.get('seq')} != {i}"}
                if rec.get("prev_sha256") != prev:
                    return {"ok": False, "n": n, "head_sha256": prev, "line": i, "error": "chain broken (prev_sha256)"}
                if not REG.verify(public, canon(rec), sig):
                    return {"ok": False, "n": n, "head_sha256": prev, "line": i, "error": "bad signature"}
                prev = hashlib.sha256(line).hexdigest()
                n += 1
    except (OSError, ValueError) as e:
        return {"ok": False, "n": n, "head_sha256": prev, "line": n, "error": repr(e)}
    if expect_n is not None and n != expect_n:
        return {"ok": False, "n": n, "head_sha256": prev, "line": n, "error": f"{n} records, expected {expect_n} (cut?)"}
    if expect_head is not None and prev != expect_head:
        return {"ok": False, "n": n, "head_sha256": prev, "line": n, "error": "head sha256 != expected"}
    return {"ok": True, "n": n, "head_sha256": prev, "line": None, "error": None}
