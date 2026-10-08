"""
Trust Store -- implements Stage 0's (AI engine, gateway-side) trust
formula so the Part-C closed-loop-vs-open-loop ablation can be run from
the mitigation-engine side without needing a live gateway process.

tau(d, t) = tau0 * exp(-lambda * (t - t_last)) + beta * outcome_reward,
clipped to [0, 1]. Hard reset to 0 on identity/firmware change (not
modeled here -- no such events in the synthetic stream) or, per this
module's use in the closed-loop ablation, simply decays if no feedback
arrives (open-loop) or is nudged by Stage E rewards (closed-loop).
"""

import math

import config


class TrustStore:
    """
    tau(d,t) = tau0 * exp(-lambda*(t-t_last)) + beta*outcome_reward,
    per the architecture spec. Corrected model (see README "known issue
    found and fixed"): decay must relax an ABSENT signal back toward a
    neutral prior, not compound a fixed prior downward every tick with
    no reward ever offsetting it -- otherwise even a perfectly benign
    device's trust collapses to 0 from pure time-decay, which is
    obviously wrong and would make the closed-loop-vs-open-loop
    ablation meaningless (everything decays to the scrutiny threshold
    regardless of feedback, leaving no room for closed-loop to show an
    effect). Decay here relaxes trust toward NEUTRAL (0.5), and every
    tick without negative feedback is treated as an implicit small
    positive event (the device was observed behaving, i.e. Stage 0's
    light-path sampling didn't find anything wrong) -- reflecting a
    reputation system that rewards a track record of unremarkable
    behavior, not one that assumes guilt by default and requires
    active reward just to tread water.
    """

    def __init__(self, decay_lambda=0.08, feedback_beta=0.35, closed_loop=True,
                 neutral_prior=0.5, passive_tick_reward=0.02):
        self.decay_lambda = decay_lambda
        self.feedback_beta = feedback_beta
        self.closed_loop = closed_loop
        self.neutral_prior = neutral_prior
        self.passive_tick_reward = passive_tick_reward
        self.tau = {}          # device_id -> current trust
        self.last_update = {}  # device_id -> last tick index

    def get(self, device_id, t):
        return self.tau.get(device_id, self.neutral_prior)

    def _relax_toward_neutral(self, device_id, t):
        current = self.tau.get(device_id, self.neutral_prior)
        t_last = self.last_update.get(device_id, t)
        dt = max(0, t - t_last)
        # exponential relaxation toward neutral_prior, not toward 0
        relaxed = self.neutral_prior + (current - self.neutral_prior) * math.exp(-self.decay_lambda * dt)
        return relaxed

    def tick_decay(self, device_id, t):
        """
        Advance trust with no explicit feedback this tick: relax toward
        neutral, plus a small passive reward for an unremarkable
        observation (light-path sampling found nothing wrong). This is
        what lets a benign device's trust GROW toward 1.0 over time
        rather than decaying to 0 from inactivity.
        """
        relaxed = self._relax_toward_neutral(device_id, t)
        updated = relaxed + self.passive_tick_reward
        self.tau[device_id] = max(0.0, min(1.0, updated))
        self.last_update[device_id] = t

    def apply_feedback(self, device_id, reward, t):
        """
        Applies a Stage E outcome reward, IF closed_loop is enabled.
        In open-loop mode this degrades to tick_decay's passive
        behavior only -- used as the ablation baseline (trust evolves
        from passive observation alone, no explicit Stage E feedback
        ever incorporated, matching a system with no gateway<->hub
        channel at all).
        """
        relaxed = self._relax_toward_neutral(device_id, t)
        if self.closed_loop:
            updated = relaxed + self.feedback_beta * reward
        else:
            updated = relaxed + self.passive_tick_reward
        self.tau[device_id] = max(0.0, min(1.0, updated))
        self.last_update[device_id] = t
