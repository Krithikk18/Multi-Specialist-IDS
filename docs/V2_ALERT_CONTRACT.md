# LG-IDS -- alert contract: AIML runtime -> Networking (notification P7 / mitigation P8)

**Status: PROPOSED** -- for agreement with the Networking team. Nothing in it is frozen until both sides sign off;
the AIML side implements this draft in `common/runtime.py` (outbox) and `common/alert_log.py` (chain + signature).

## 1. What is handed over

One message per **incident** event, not per flow: the runtime aggregates alerts into incidents keyed by (class,
protected device) (`docs/V2_PREREG_PHASE3.md` section 4), so a flood of 100,000 attack flows is one incident.

| type | when |
|---|---|
| `incident.opened` | the first alert of a new incident (after the cooldown of its key) |
| `incident.closed` | `aggregation_window_s` after its last alert (final counts) |

Per-flow alerts stay in the AIML side's own log (`alerts.jsonl`, same chain and signature) for audit and review.

## 2. Message fields (one JSON object per line)

| field | type | meaning |
|---|---|---|
| `schema` | string | `lgids.alert.v1` |
| `type` | string | `incident.opened` or `incident.closed` |
| `event_time` | number | capture-clock time of the event (UTC epoch s): open = first alert's decision time, close = close time |
| `wall_time` | number | runtime wall clock when written (UTC epoch s) |
| `incident.incident_id` | string | unique within a runtime run (`inc000001` ...) |
| `incident.class` | string | predicted class name from `config/class_map.json`, or `rate_guard` for the packet path |
| `incident.device` | string | protected device: its MAC (lower-case), or `ip:<addr>` when only an IP is known |
| `incident.group` | string | device group (inventory) |
| `incident.severity` | string | `High` / `Medium` / `Low` (config `policy.severity`; unknown class -> `Medium`) |
| `incident.first`, `incident.last` | number | first / last alert time (event clock) |
| `incident.closed_at` | number or null | close time (closed messages) |
| `incident.n_alerts`, `incident.n_suppressed_after` | int | alerts absorbed; alerts suppressed by the cooldown after it |
| `incident.paths` | list | `flow` (ML model), `rate_guard` (packet path) |
| `producer`, `contract` | string | `LG-IDS AIML runtime`, `docs/V2_ALERT_CONTRACT.md` |
| `seq`, `stream`, `prev_sha256`, `sig` | | chain and signature fields (section 3) |

## 3. Integrity: how to verify a message

- Each line is canonical JSON (`sort_keys`, separators `,` / `:`, UTF-8).
- `prev_sha256` = sha256 of the previous line's bytes (no newline); the first line carries 64 zeros; `seq` counts
  from 0. A deleted, inserted or reordered line breaks `seq` / the chain.
- `sig` = Ed25519 signature (hex) over the canonical JSON of the object **without** `sig`, by the runtime alert key.
  The public key is `~/lgids_cache/keys/runtime/runtime_ed25519.pub` (32 bytes, hex) -- to be handed to Networking
  out of band; it is NOT the model-registry key.
- Reference verifier: `common/alert_log.verify_chain(path, public_key)`. The run manifest also records the final
  count and head hash, so a cut tail is detectable.

## 4. Delivery (for now)

A local append-only file `alerts_outbox.jsonl` in the runtime run folder (`~/lgids_cache/v2/runtime/<run_id>/`),
flushed every 256 records and at close. Networking tails it. A socket / MQTT transport replaces the file on the Pi;
the message format stays the same.

## 5. Open questions for the Networking team

1. Does mitigation need the attacker side (source IPs / MACs seen in the incident)? Not in v1 of the message.
2. Should `incident.updated` messages be sent while an incident is open (e.g. every N alerts or every 60 s)?
3. Acknowledgement / back-channel (mitigation applied, false positive marked) -- would feed Phase 4's review queue.
4. Key distribution and rotation for the runtime public key.
