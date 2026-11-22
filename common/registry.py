"""common/registry.py -- signed model registry (Phase 2 step 6).

Layout (registry root from config/v2_phase2.json, outside the repo):
  <root>/<entry_id>/model.ubj          the XGBoost booster (copied from a step 22 run)
                   /calibrator.json    its step 24 temperature calibrator
                   /manifest.json      class_map / features / dataset / prereg / config hashes, seed, file sha256s,
                                       val metrics summary, signer public key
                   /manifest.sig       Ed25519 signature (hex) over the canonical manifest bytes (covers file hashes)
                   /state.log          append-only JSON lines, each signed: candidate -> approved -> promoted
Keys: <keys_dir>/registry_ed25519.key (32-byte seed, hex, mode 600) + .pub; created if absent; never printed.

Ed25519: the `cryptography` library when importable, else the RFC 8032 section 6 reference algorithm below
(deterministic: both give identical signatures; tested on RFC 8032 test vectors; docs/V2_DECISIONS.md D02).

load_model(entry_dir, ...) refuses (RegistryRefused) on: a bad / missing manifest signature, a file whose sha256
differs from the manifest, the runtime class_map.json or features_v1.json hash differing from the manifest, a bad
state-log signature, or a state outside allow_states (default: promoted only; offline evaluation may allow more).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
from pathlib import Path

STATES = ("candidate", "approved", "promoted")
TRANSITIONS = {"candidate": "approved", "approved": "promoted"}
KEY_NAME = "registry_ed25519"


class RegistryRefused(RuntimeError):
    pass


# --------------------------------------------------------------------------- Ed25519 (RFC 8032 section 6 reference)
_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _sha512_modq(b: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b).digest(), "little") % _q


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _eq(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _recover_x(y: int, sign: int):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P) -> bytes:
    zi = _inv(P[2])
    x, y = P[0] * zi % _p, P[1] * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _expand(secret: bytes):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _pure_public(secret: bytes) -> bytes:
    return _compress(_mul(_expand(secret)[0], _G))


def _pure_sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_mul(a, _G))
    r = _sha512_modq(prefix + msg)
    Rs = _compress(_mul(r, _G))
    h = _sha512_modq(Rs + A + msg)
    return Rs + int.to_bytes((r + h * a) % _q, 32, "little")


def _pure_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _decompress(public), _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _q:
        return False
    h = _sha512_modq(sig[:32] + public + msg)                          # H(R || A || M), RFC 8032 5.1.7
    return _eq(_mul(s, _G), _add(R, _mul(h, A)))


try:                                                                   # the library when available (D02)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    BACKEND = "cryptography"

    def public_key(secret: bytes) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(secret: bytes, msg: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(secret).sign(msg)

    def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False
except ImportError:
    BACKEND = "pure-python RFC 8032 (cryptography not installed)"
    public_key, sign, verify = _pure_public, _pure_sign, _pure_verify


# --------------------------------------------------------------------------- keys
def ensure_keys(keys_dir: Path, repo_root: Path | None = None) -> tuple[bytes, bytes]:
    """(secret, public) from keys_dir, created (os.urandom, mode 600) if absent. Refuses a dir inside the repo."""
    keys_dir = Path(keys_dir).expanduser().resolve()
    if repo_root is not None:
        rr = Path(repo_root).resolve()
        if keys_dir == rr or rr in keys_dir.parents:
            raise RegistryRefused(f"keys dir {keys_dir} is inside the repository {rr}")
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    sk_p, pk_p = keys_dir / f"{KEY_NAME}.key", keys_dir / f"{KEY_NAME}.pub"
    if not sk_p.exists():
        secret = os.urandom(32)
        fd = os.open(sk_p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secret.hex() + "\n")
        pk_p.write_text(public_key(secret).hex() + "\n", encoding="ascii")
    secret = bytes.fromhex(sk_p.read_text(encoding="ascii").strip())
    public = bytes.fromhex(pk_p.read_text(encoding="ascii").strip())
    if public_key(secret) != public:
        raise RegistryRefused(f"{pk_p} does not match {sk_p}")
    return secret, public


def fingerprint(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


# --------------------------------------------------------------------------- entries
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def register(root: Path, entry_id: str, model_file: Path, calibrator_file: Path, manifest_fields: dict,
             secret: bytes, by: str = "26_model_registry.py (automatic registration)") -> Path:
    """Create <root>/<entry_id>/ (refused if it exists): copy the files, write + sign the manifest, state candidate.
    `by` (optional, Phase 4) names the registering script in the signed candidate record; the default is step 26's."""
    d = Path(root) / entry_id
    if d.exists():
        raise RegistryRefused(f"registry entry {d} already exists (entries are immutable)")
    d.mkdir(parents=True)
    shutil.copyfile(model_file, d / "model.ubj")
    shutil.copyfile(calibrator_file, d / "calibrator.json")
    pub = public_key(secret)
    M = {**manifest_fields, "registry_version": 1, "entry_id": entry_id, "created_utc": _now(),
         "files": {"model.ubj": sha256_file(d / "model.ubj"), "calibrator.json": sha256_file(d / "calibrator.json")},
         "signature": {"algorithm": "Ed25519", "over": "canonical JSON of manifest.json (sort_keys, no spaces)",
                       "public_key": pub.hex(), "fingerprint": fingerprint(pub), "backend": BACKEND}}
    (d / "manifest.json").write_bytes(canon(M))
    (d / "manifest.sig").write_text(sign(secret, canon(M)).hex() + "\n", encoding="ascii")
    _append_state(d, "candidate", secret, by=by)
    return d


def _append_state(d: Path, state: str, secret: bytes, by: str) -> dict:
    log = d / "state.log"
    prev = sha256_file(log) if log.exists() else None
    rec = {"state": state, "utc": _now(), "by": by, "prev_log_sha256": prev,
           "manifest_sha256": hashlib.sha256((d / "manifest.json").read_bytes()).hexdigest()}
    rec["sig"] = sign(secret, canon(rec)).hex()
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def read_state(d: Path, public: bytes) -> str:
    """Current state = last record of a fully valid, chained, signed state log."""
    log = Path(d) / "state.log"
    if not log.is_file():
        raise RegistryRefused(f"{d}: no state.log")
    man_sha = hashlib.sha256((Path(d) / "manifest.json").read_bytes()).hexdigest()
    lines = log.read_text(encoding="utf-8").splitlines()
    state, prev_bytes = None, b""
    for i, line in enumerate(lines):
        rec = json.loads(line)
        sig = bytes.fromhex(rec.pop("sig", ""))
        if not verify(public, canon(rec), sig):
            raise RegistryRefused(f"{d}: state.log record {i} has a bad signature")
        if rec["manifest_sha256"] != man_sha:
            raise RegistryRefused(f"{d}: state.log record {i} is for another manifest")
        want_prev = hashlib.sha256(prev_bytes).hexdigest() if i else None
        if rec["prev_log_sha256"] != want_prev:
            raise RegistryRefused(f"{d}: state.log record {i} breaks the chain")
        if rec["state"] not in STATES or (state is None and rec["state"] != "candidate") or \
                (state is not None and TRANSITIONS.get(state) != rec["state"]):
            raise RegistryRefused(f"{d}: state.log record {i}: illegal transition {state} -> {rec['state']}")
        state = rec["state"]
        prev_bytes += (line + "\n").encode("utf-8")
    if state is None:
        raise RegistryRefused(f"{d}: empty state.log")
    return state


def transition(d: Path, to_state: str, secret: bytes, by: str) -> dict:
    """Manual step (approve / promote): appends a signed record; only candidate -> approved -> promoted."""
    cur = read_state(d, public_key(secret))
    if TRANSITIONS.get(cur) != to_state:
        raise RegistryRefused(f"{d}: cannot go {cur} -> {to_state}")
    return _append_state(Path(d), to_state, secret, by)


def verify_entry(d: Path, public: bytes) -> dict:
    """Manifest signature + file hashes; returns the manifest."""
    d = Path(d)
    raw = (d / "manifest.json").read_bytes() if (d / "manifest.json").is_file() else None
    if raw is None or not (d / "manifest.sig").is_file():
        raise RegistryRefused(f"{d}: manifest or signature missing")
    sig = bytes.fromhex((d / "manifest.sig").read_text(encoding="ascii").strip())
    M = json.loads(raw)
    if canon(M) != raw or not verify(public, raw, sig):
        raise RegistryRefused(f"{d}: bad manifest signature")
    if M["signature"]["public_key"] != public.hex():
        raise RegistryRefused(f"{d}: signed by another key ({M['signature']['fingerprint']})")
    for name, want in M["files"].items():
        if not (d / name).is_file() or sha256_file(d / name) != want:
            raise RegistryRefused(f"{d}: {name} sha256 differs from the signed manifest")
    return M


def load_model(d: Path, public: bytes, class_map_path: Path, features_path: Path,
               allow_states: tuple = ("promoted",)) -> dict:
    """Verified booster + temperature, or RegistryRefused. Checks: signature + file hashes, runtime class_map.json
    and features_v1.json file hashes == manifest, state in allow_states."""
    import xgboost as xgb
    M = verify_entry(d, public)
    if sha256_file(class_map_path) != M["class_map_sha256"]:
        raise RegistryRefused(f"{d}: runtime class map {class_map_path} sha256 != manifest class_map_sha256")
    if sha256_file(features_path) != M["features_file_sha256"]:
        raise RegistryRefused(f"{d}: runtime features {features_path} sha256 != manifest features_file_sha256")
    state = read_state(d, public)
    if state not in allow_states:
        raise RegistryRefused(f"{d}: state {state!r} not in {allow_states} (only promoted models load at runtime)")
    b = xgb.Booster()
    b.load_model(str(Path(d) / "model.ubj"))
    cal = json.loads((Path(d) / "calibrator.json").read_text(encoding="utf-8"))
    return {"booster": b, "temperature": float(cal["temperature"]), "manifest": M, "state": state}
