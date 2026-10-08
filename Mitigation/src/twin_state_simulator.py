"""
Synthetic digital-twin state generator (stands in for P16/P17 in the DFD).

Edge-IIoTset has no occupancy/time-of-day/device-mode information, so
this module generates a plausible household state timeline. Stated
explicitly as synthetic, seeded for reproducibility. This is queried
for STATE ONLY by Stage C -- never run as a what-if simulator, per the
architecture spec.

Model: simple day/night occupancy cycle with random "away" periods,
independent per simulated day. Not intended as a contribution in itself
-- it exists only to give Stage C something real to query.
"""

import random
from datetime import datetime, timedelta

import config


def generate_twin_timeline(days=config.TWIN_SIM_DAYS, seed=config.TWIN_SIM_RANDOM_STATE):
    """
    Returns a list of hourly state records:
      {"timestamp": iso str, "hour": int, "occupied": bool, "mode": str}

    mode is one of "home_active", "home_asleep", "away".
    """
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, 0, 0, 0)
    timeline = []

    for day in range(days):
        # Each day, small chance the household is fully away (e.g. work
        # trip) -- otherwise follows a normal daily cycle.
        away_all_day = rng.random() < 0.08

        for hour in range(24):
            ts = start + timedelta(days=day, hours=hour)
            if away_all_day:
                occupied, mode = False, "away"
            elif 0 <= hour < 7:
                occupied, mode = True, "home_asleep"
            elif 7 <= hour < 9:
                # morning departure window -- occupied with declining
                # probability as the window progresses
                occupied = rng.random() < (9 - hour) / 2
                mode = "home_active" if occupied else "away"
            elif 9 <= hour < 17:
                occupied = rng.random() < 0.15  # most people out at work
                mode = "home_active" if occupied else "away"
            elif 17 <= hour < 23:
                occupied, mode = True, "home_active"
            else:  # 23:00
                occupied, mode = True, "home_asleep"

            timeline.append({
                "timestamp": ts.isoformat(),
                "hour": hour,
                "occupied": occupied,
                "mode": mode,
            })

    return timeline


def query_state_at(timeline, index):
    """State lookup -- O(1) by index, simulating a twin state read."""
    return timeline[index % len(timeline)]


if __name__ == "__main__":
    tl = generate_twin_timeline()
    print(f"Generated {len(tl)} hourly twin-state records over {config.TWIN_SIM_DAYS} days")
    print("Sample:", tl[8])   # 08:00 on day 0
    print("Sample:", tl[14])  # 14:00 on day 0
