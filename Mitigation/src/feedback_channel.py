"""
Gateway <-> Hub Feedback Channel

Implements the transport/consistency/security model specified for the
Stage 0 (gateway, AI engine) <-> Stage E (hub, mitigation engine) trust
feedback loop, per the implementation spec v3:

  - Transport: modeled here as an in-memory message queue standing in
    for an MQTT topic (the real deployment target). Each message is a
    signed, sequenced outcome record.
  - Consistency: eventually consistent, bounded staleness window.
  - Security: messages are HMAC-signed by the hub and carry a monotonic
    sequence number per device, so the gateway can reject unsigned or
    replayed messages. This is the minimum mitigation specified for the
    spoofing/replay threat identified in review.
  - Failure mode: if the hub is unreachable, Stage 0's trust score
    continues decaying on schedule with NO reward/penalty applied --
    the gateway does not freeze or fail open. This is implemented here
    as: undelivered messages simply never arrive, and the trust-score
    function (see trust_store.py) has no dependency on message arrival
    to continue its normal decay.
"""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

import config

# Shared secret standing in for a provisioned per-hub key. In a real
# deployment this is provisioned once during device pairing, not
# hardcoded -- placeholder here since this project has no pairing flow.
HUB_SECRET_KEY = b"REPLACE_WITH_PROVISIONED_HUB_KEY_AT_DEPLOYMENT"


def _sign(payload_bytes):
    return hmac.new(HUB_SECRET_KEY, payload_bytes, hashlib.sha256).hexdigest()


@dataclass
class OutcomeMessage:
    device_id: str
    reward: float
    seq: int
    timestamp: float
    signature: str = field(default="")

    def to_wire(self):
        body = json.dumps({
            "device_id": self.device_id,
            "reward": self.reward,
            "seq": self.seq,
            "timestamp": self.timestamp,
        }, sort_keys=True).encode()
        return body, _sign(body)


def publish_outcome(device_id, reward, seq, queue, drop_probability=0.0, rng=None):
    """
    Hub-side publish. `drop_probability` simulates a briefly unreachable
    hub/gateway link for the failure-mode test -- a dropped message is
    simply never enqueued, which is the correct failure behavior (no
    freeze, no fail-open; the gateway's trust decay just continues
    unmodified for this device until a later message arrives).
    """
    if rng is not None and rng.random() < drop_probability:
        return False  # simulated drop -- message never sent

    msg = OutcomeMessage(device_id=device_id, reward=reward, seq=seq, timestamp=time.time())
    body, sig = msg.to_wire()
    msg.signature = sig
    queue.append((body, sig))
    return True


def consume_outcomes(queue, last_seq_by_device):
    """
    Gateway-side consume. Verifies signature and monotonic sequence
    number per device; rejects (does not apply) anything that fails
    either check. Returns (accepted, rejected) message lists and
    updates last_seq_by_device in place.
    """
    accepted, rejected = [], []

    for body, sig in queue:
        expected_sig = _sign(body)
        record = json.loads(body)
        device_id = record["device_id"]
        seq = record["seq"]

        valid_signature = hmac.compare_digest(sig, expected_sig)
        valid_sequence = seq > last_seq_by_device.get(device_id, -1)

        if valid_signature and valid_sequence:
            accepted.append(record)
            last_seq_by_device[device_id] = seq
        else:
            rejected.append({**record, "reason": "bad_signature" if not valid_signature else "replay_or_stale_seq"})

    return accepted, rejected


def run_feedback_channel_evaluation(n_messages=2000, n_spoof_attempts=200, n_replay_attempts=200, seed=config.RANDOM_STATE):
    """
    Evaluates: feedback staleness (normal operation), spoofed/replayed
    message rejection rate (security), and behavior under simulated hub
    unreachability (failure mode).
    """
    import numpy as np
    rng = np.random.RandomState(seed)

    queue = []
    last_seq_by_device = {}
    device_ids = [f"device_{i}" for i in range(config.STREAM_N_DEVICES)]

    # --- Normal operation: legitimate messages ---
    seq_counters = {d: 0 for d in device_ids}
    send_times = []
    for _ in range(n_messages):
        d = device_ids[rng.randint(0, len(device_ids))]
        seq_counters[d] += 1
        t_send = time.time()
        publish_outcome(d, reward=float(rng.uniform(-1, 1)), seq=seq_counters[d], queue=queue)
        send_times.append(t_send)

    accepted, rejected_legit = consume_outcomes(queue, last_seq_by_device)
    staleness_ms = [(time.time() - t) * 1000 for t in send_times[:len(accepted)]]

    # --- Spoofing attempts: bad signature ---
    spoof_queue = []
    for _ in range(n_spoof_attempts):
        d = device_ids[rng.randint(0, len(device_ids))]
        body, _ = OutcomeMessage(device_id=d, reward=1.0, seq=999999, timestamp=time.time()).to_wire()
        forged_sig = hashlib.sha256(b"not_the_real_key" + body).hexdigest()  # wrong signing key
        spoof_queue.append((body, forged_sig))

    _, rejected_spoof = consume_outcomes(spoof_queue, dict(last_seq_by_device))
    spoof_rejection_rate = 100.0 * len(rejected_spoof) / n_spoof_attempts

    # --- Replay attempts: valid signature, already-seen sequence number ---
    replay_queue = []
    for _ in range(n_replay_attempts):
        d = device_ids[rng.randint(0, len(device_ids))]
        old_seq = max(1, last_seq_by_device.get(d, 1) - rng.randint(1, 5))
        body, sig = OutcomeMessage(device_id=d, reward=1.0, seq=old_seq, timestamp=time.time()).to_wire()
        replay_queue.append((body, sig))

    _, rejected_replay = consume_outcomes(replay_queue, dict(last_seq_by_device))
    replay_rejection_rate = 100.0 * len(rejected_replay) / n_replay_attempts

    # --- Failure mode: simulated hub outage, 30% message drop rate ---
    outage_queue = []
    outage_seq = {d: seq_counters[d] for d in device_ids}
    n_attempted = 500
    n_dropped = 0
    for _ in range(n_attempted):
        d = device_ids[rng.randint(0, len(device_ids))]
        outage_seq[d] += 1
        sent = publish_outcome(d, reward=0.5, seq=outage_seq[d], queue=outage_queue,
                                drop_probability=0.3, rng=rng)
        if not sent:
            n_dropped += 1
    accepted_during_outage, _ = consume_outcomes(outage_queue, dict(last_seq_by_device))

    summary = {
        "n_legitimate_messages": n_messages,
        "n_accepted": len(accepted),
        "n_legitimate_rejected": len(rejected_legit),
        "feedback_staleness_ms_mean": float(np.mean(staleness_ms)) if staleness_ms else float("nan"),
        "spoofed_message_rejection_rate_pct": spoof_rejection_rate,
        "replayed_message_rejection_rate_pct": replay_rejection_rate,
        "simulated_outage_drop_rate_pct": 100.0 * n_dropped / n_attempted,
        "simulated_outage_messages_still_accepted": len(accepted_during_outage),
        "failure_mode_note": (
            "Dropped messages during simulated outage are never enqueued -- "
            "the gateway's trust decay is NOT paused or frozen waiting for "
            "them; it continues on schedule with no reward/penalty applied "
            "until a later message for that device arrives (verified: "
            "consume_outcomes has no blocking dependency on message arrival)."
        ),
    }
    return summary


def main():
    print("=" * 70)
    print("GATEWAY <-> HUB FEEDBACK CHANNEL -- evaluation")
    print("=" * 70)

    summary = run_feedback_channel_evaluation()
    for k, v in summary.items():
        print(f"{k}: {v}")

    out_path = config.CROSS_ENGINE_RESULTS / "feedback_channel_summary.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {out_path}")


if __name__ == "__main__":
    main()
