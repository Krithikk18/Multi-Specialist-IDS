# Mitigation Engine (P10, home hub)

Implementation of Stages A-E (Device Criticality -> Adaptive Risk Score
-> Context Check -> Immediate Containment -> Recovery Loop) plus the
gateway<->hub feedback channel and the Part-C cross-engine ablations,
per the implementation spec (v3).

## Quick start (WSL / conda)

```bash
conda activate ids   # same environment as the AI engine
cd Mitigation
pip install -r requirements.txt   # numpy, pandas, scikit-learn, joblib

# Full pipeline
python src/run_pipeline.py

# Or run stages individually:
python src/stage0_preprocessing.py       # unchanged from your original script
python src/stage_a_criticality.py
python src/stage_b_risk_score.py
python src/stage_c_context_check.py
python src/stage_d_containment.py
python src/stage_e_recovery.py
python src/feedback_channel.py
python src/stage_c_synthetic_streams.py
python src/cross_engine_ablations.py
```

## What's REAL vs. SYNTHETIC in this project -- read this first

This is the single most important thing to understand before citing any
number from this project. Unlike the AI engine (where every input is
real Edge-IIoTset traffic), the mitigation engine's stages mostly don't
consume raw network flow data at all -- per the architecture spec, they
consume outputs from the AI engine (severity, confidence, trust) plus
device/context metadata that Edge-IIoTset simply does not contain
(device identity, criticality tier, occupancy state, longitudinal
per-device behavior). There is no way to "complete" these stages the
way the AI engine's Stage 1 was completed (train a classifier, get
metrics) -- most of them were never meant to be classifiers.

| Component | Status | Source |
|---|---|---|
| Stage 0 preprocessing | REAL | Your original `preprocessing.py`, unchanged. Real Edge-IIoTset. |
| Stage B severity input | REAL (derived) | Deterministic mapping from `Attack_type` (config.SEVERITY_MAP) -- not fabricated, but a judgment call on tier assignment, stated and justified in config.py. |
| Stage B confidence/trust/frequency inputs | SYNTHETIC, grounded | Simulated distributions, but their parameters (91.67%/8.33% high/low-confidence split, 3.90% label-noise rate) are taken directly from the AI engine's ACTUAL measured results, not picked arbitrarily -- see stage_b_risk_score.py docstrings for the exact source numbers. |
| Stage A device catalog + criticality tiers | SYNTHETIC, stated as config | A plausible smart-home device list built from Edge-IIoTset's actual protocol mix (MQTT/Modbus/HTTP/DNS). Per the spec, Stage A is "configuration lookup, not a trained model" -- this is meant to be config data, not learned or extracted. |
| Stage C digital twin state | SYNTHETIC | No twin data exists anywhere; a simple occupancy/time-of-day generator stands in for P16/P17. |
| Stage D containment | Deterministic logic | No data dependency -- it's a rule engine, evaluated on synthetic events for volume. |
| Stage E recovery outcomes | SYNTHETIC, stated model | Post-containment behavior is a stated distributional model (genuine threats mostly re-offend, false escalations mostly settle), not observed behavior -- Edge-IIoTset has no per-device timeline to observe. |
| Part C event streams | SYNTHETIC, explicit method | Built via the exact sampling/timeline/noise-injection method specified in the implementation spec, using REAL Edge-IIoTset flow samples as the content of each synthetic event. Explicitly labeled a controlled synthetic simulation study. |

**If you're writing this up for the thesis/paper:** state plainly that
Stages A/C/D/E and the Part-C streams are a controlled synthetic
simulation study, and that Stage B's severity is real while its other
three inputs are grounded synthetic proxies. This is not a weakness to
hide -- it's the correct and honestly-labeled way to evaluate a
closed-loop/online-learning mitigation system when no real longitudinal
smart-home dataset exists (which is true of essentially all research in
this space; Edge-IIoTset itself is a static capture).

## Folder structure

```
Mitigation/
  data/
    raw/ML-EdgeIIoT-dataset.csv        <- your original file, untouched
    processed/                          <- Stage 0 output (same as before)
    synthetic/                          <- device tier lookup (Stage A config output)
    streams/                            <- Part-C synthetic event streams
  models/
    stage_b_risk/                       <- static + online-adapted risk weights
  results/
    stage_a/ ... stage_e/               <- per-stage metrics
    cross_engine/                       <- Part-C ablation results
  src/
  logs/
  requirements.txt
  README.md
```

## What each stage does, and where results land

### Stage 0 -- `stage0_preprocessing.py`
Unchanged from your original script. Loads the raw CSV, drops
leakage/free-text columns, handles missing/infinite values, encodes
categoricals and target, 80/20 train/test split, StandardScaler.
Outputs unchanged: `data/processed/{X,y}_{train,test}.csv` + encoders.

### Stage A -- `stage_a_criticality.py`
Device criticality classifier (config lookup) + Stage A2 structural
safety fallback. Evaluates tier-assignment coverage, unknown-device
fallback correctness (must always resolve to `safety_critical`, never
silently to `convenience`), and the Stage A2 structural proof (verified
by exhaustive check over the catalog -- a design proof, not a sampled
statistic, per the spec's treatment of the zero-auto-action guarantee).
-> `results/stage_a/stage_a_summary.json`

### Stage B -- `stage_b_risk_score.py`
The one genuinely learned component. Risk(d,e) = w1*severity +
w2*confidence + w3*(1-trust) + w4*frequency. Evaluates both a
static-weight baseline and an online multiplicative-weights-adapted
version, reporting AUROC, escalation precision/recall, and cumulative
regret for both -> `results/stage_b/`.

**Known issue found and fixed (online weight collapse):** the first
implementation of the multiplicative-weights update used each term's
raw contribution (weight x value) to decide which weight to reinforce.
Since severity's contribution naturally has a larger scale than
confidence/trust/frequency's, this caused the weights to collapse to
~99.97% severity / ~0.01% everything else within a few hundred updates
-- a real bug (comparing feature-value scale, not weight usefulness),
not a legitimate result. Root-caused by inspecting `final_online_weights`
after a full run and noticing the degenerate split. Fixed by
un-weighting each contribution back to its raw input value before
comparing shares, centering the comparison around an equal-informativeness
baseline (1/n_terms), and enforcing a hard minimum weight floor
(`min_weight_floor=0.05`) so no signal can be driven to irrelevance. Also
added independent label noise to the genuine-threat ground truth
(grounded in the AI engine's actual 3.90% Stage 1 test error rate) since
the original label was `severity > 0`, a near-deterministic function of
severity itself, which gave any update rule a trivial shortcut regardless
of how the update math worked. After both fixes: online weights settle at
severity=0.79 / confidence=0.11 / distrust=0.05 / frequency=0.05 -- still
severity-dominant (correctly, since severity genuinely is the most
informative signal), but a real, non-degenerate distribution, with online
AUROC (0.908) meaningfully beating static (0.876) and 16.9% cumulative
regret reduction. See `multiplicative_weights_update`'s docstring in
`stage_b_risk_score.py` for the full technical explanation.

### Stage C -- `stage_c_context_check.py`
Rule engine querying `twin_state_simulator.py`'s synthetic digital-twin
timeline (state lookup only, never a what-if simulation run). Reports
context-adjusted decision agreement (measured against an oracle drawn
from the same synthetic generator -- this evaluates rule-logic internal
consistency, not twin-vs-reality drift, since no independent ground
truth exists outside the simulator; stated explicitly in the result),
twin query latency, and stale-state rate -> `results/stage_c/`.

### Stage D -- `stage_d_containment.py`
Deterministic action trigger. Calls
`stage_a_criticality.is_auto_isolation_eligible` as the single choke
point before any auto-isolate action, with a hard runtime assertion (not
just a policy check) that safety-critical devices never reach an
auto-action branch. -> `results/stage_d/`.

### Stage E -- `stage_e_recovery.py`
Sequential post-containment monitor. Simulates rolling anomaly-score
behavior over a monitoring window (genuine threats mostly re-offend,
false escalations mostly settle -- a stated distributional model, not
observed data) and decides restore vs. escalate. Its output is exactly
the reward/penalty signal consumed by the feedback channel and Stage B's
weight update. -> `results/stage_e/stage_e_outcomes.csv` +
`stage_e_summary.json`.

### Feedback channel -- `feedback_channel.py`
Implements the gateway<->hub trust feedback transport specified in the
implementation spec: HMAC-signed, sequence-numbered messages (closes the
spoofing/replay attack surface identified in review), eventually
consistent, with an explicit non-blocking failure mode (a dropped
message during a simulated hub outage is simply never enqueued -- trust
decay is NOT paused or frozen waiting for it). Evaluates staleness under
normal operation, spoofed/replayed message rejection rate, and behavior
under a simulated 30% message-drop outage.
-> `results/cross_engine/feedback_channel_summary.json`.

### Part C -- `stage_c_synthetic_streams.py` + `cross_engine_ablations.py`
Builds the two synthetic event streams per the spec's explicit
construction method (sampling real Edge-IIoTset flow instances per
attack class, stitching into per-device timelines with exponential
inter-arrival, injecting false-escalation noise at a rate grounded in
the AI engine's ACTUAL measured Stage-3 false-positive rate of 1.262%,
not an arbitrary value -- see `config.FALSE_ESCALATION_NOISE_FRACTION`'s
derivation comment). Runs the two mitigation-side cross-engine ablations:

- **Closed-loop vs. open-loop trust adaptation** (the core novelty
  claim): replays the repeated-offense stream through `trust_store.py`
  with feedback enabled vs. disabled. **Headline result: 0% of repeat
  offenders remain trusted at the end of their timeline under the
  closed loop (caught within ~1 event on average), vs. 100% still fully
  trusted under the open loop (feedback disabled) -- the mechanism the
  entire pairing claim rests on demonstrably works in this simulation.**
- **Static vs. adaptive mitigation weighting**: replays the
  false-escalation-noise stream through Stage B's static vs. online
  weights. Modest, honestly-reported result: 1.28% cumulative regret
  reduction, escalation recall improves from 18.3% to 21.4% under noise.
  This is a smaller effect than the closed-loop result and is reported
  as such rather than inflated.

-> `results/cross_engine/part_c_mitigation_side_ablations.json`

**Known issue found and fixed (trust model decaying to zero for benign
devices):** the first implementation of `TrustStore` decayed a device's
trust exponentially from its current value with no floor or positive
reinforcement mechanism -- so even a perfectly benign device with zero
negative feedback ever applied saw its trust collapse toward 0 purely
from the passage of time (e.g. lambda=0.05 over 25 ticks: trust
0.5 -> 0.151). This is backwards (a well-behaved device should build
trust, or at minimum hold steady, not decay to zero from inactivity)
and it also broke the closed-loop-vs-open-loop ablation: with decay
alone already crushing trust regardless of feedback, both conditions
converged to identical "0% still trusted" results, showing no
differentiation at all. Root-caused by testing a synthetic all-benign
device in isolation and observing its trust dropping despite no negative
events. Fixed by changing the decay target from 0 to a neutral prior
(0.5) and adding a small passive per-tick reward for unremarkable
observation (light-path sampling finding nothing wrong) -- so a benign
device's trust now correctly rises over time (0.5 -> 0.725 over 25
ticks with zero negative feedback), while an actively-penalized offender
under the closed loop still correctly collapses (down to ~0.11 over the
same span). A second, related issue: the original repeated-offense
stream had every single event for an "offending" device be malicious
(100% offense rate), which made the ablation meaningless for a different
reason -- trust collapsed from the very first event in both closed- and
open-loop conditions, leaving no room for the loop to matter. Fixed by
giving repeat-offender devices a mixed traffic pattern (35% malicious,
65% ordinary benign events from the same device), which is also more
realistic. See `trust_store.py`'s class docstring and
`stage_c_synthetic_streams.py`'s `build_timeline_for_device` docstring
for the full explanation of both fixes.

## Design decisions and deviations from the spec (and why)

| Spec item | What was done | Why |
|---|---|---|
| Stage A device inventory | Synthetic catalog, stated as config data | Spec explicitly says Stage A is "configuration lookup, not a trained model" -- no dataset can supply this |
| Stage B confidence/trust/frequency | Simulated, but grounded in the AI engine's actual measured numbers, not arbitrary | No live AI-engine process to source these from in this project; grounding in real measured statistics (91.67/8.33 routing split, 3.90% error rate, 1.262% FPR) keeps the simulation honest rather than fabricated wholesale |
| Stage C digital twin | Synthetic occupancy/time-of-day generator | No twin data exists anywhere in this project or Edge-IIoTset |
| Stage E outcomes | Stated distributional model, not observed | Edge-IIoTset is a static capture with no per-device longitudinal trace |
| Part C event streams | Built via the spec's explicit sampling/timeline/noise method | Same reason as Stage E -- explicitly labeled a controlled synthetic simulation study throughout results and this README |
| Feedback channel transport | In-memory queue standing in for MQTT | No live gateway process in this project; the message format (HMAC-signed, sequence-numbered) and consumption logic (signature + replay checks) are the real deliverable, transport mechanism is a stand-in |

## Re-running after changing something

Same pattern as the AI engine: each stage reads from disk and writes to
disk. If you tweak, say, `stage_b_risk_score.py`'s update rule, you only
need to re-run that script and `cross_engine_ablations.py` (which
depends on it) -- no need to redo Stage A/C/D first.
