"""
Generate synthetic login events for impossible-travel detection.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

CITIES = [
    ("New York", "US", 40.7128, -74.0060),
    ("London", "GB", 51.5074, -0.1278),
    ("Dubai", "AE", 25.2048, 55.2708),
    ("Singapore", "SG", 1.3521, 103.8198),
    ("Mumbai", "IN", 19.0760, 72.8777),
    ("Tokyo", "JP", 35.6762, 139.6503),
    ("Sao Paulo", "BR", -23.5505, -46.6333),
    ("Johannesburg", "ZA", -26.2041, 28.0473),
    ("Frankfurt", "DE", 50.1109, 8.6821),
    ("Sydney", "AU", -33.8688, 151.2093),
]


def generate_synthetic(rows: int, seed: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    user_ids = rng.integers(1000, 1400, size=rows)
    base_ts = np.datetime64("2026-02-01T00:00:00")
    offsets = rng.integers(0, 3600 * 24 * 30, size=rows)  # 30 days
    login_ts = base_ts + offsets.astype("timedelta64[s]")

    city_idx = rng.integers(0, len(CITIES), size=rows)
    cities = [CITIES[i][0] for i in city_idx]
    countries = [CITIES[i][1] for i in city_idx]
    lats = np.array([CITIES[i][2] for i in city_idx], dtype=float)
    lons = np.array([CITIES[i][3] for i in city_idx], dtype=float)

    # Inject some impossible jumps by shuffling location for a subset
    jump_mask = rng.random(size=rows) < 0.08
    jump_idx = rng.integers(0, len(CITIES), size=rows)
    lats = np.where(jump_mask, np.array([CITIES[i][2] for i in jump_idx]), lats)
    lons = np.where(jump_mask, np.array([CITIES[i][3] for i in jump_idx]), lons)
    cities = [CITIES[i][0] if not jump_mask[j] else CITIES[jump_idx[j]][0] for j, i in enumerate(city_idx)]
    countries = [CITIES[i][1] if not jump_mask[j] else CITIES[jump_idx[j]][1] for j, i in enumerate(city_idx)]

    device_ids = [f"dev-{d}" for d in rng.integers(10000, 20000, size=rows)]
    ips = [f"192.0.{rng.integers(0,255)}.{rng.integers(1,255)}" for _ in range(rows)]

    df = pd.DataFrame(
        {
            "user_id": user_ids,
            "login_ts": login_ts.astype("datetime64[s]").astype(str),
            "lat": lats,
            "lon": lons,
            "city": cities,
            "country": countries,
            "device_id": device_ids,
            "ip": ips,
        }
    )

    # Shuffle for realism
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic login events")
    parser.add_argument("--out", type=Path, required=True, help="Output CSV path")
    parser.add_argument("--rows", type=int, default=50000)
    parser.add_argument("--seed", type=int, default=7)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    df = generate_synthetic(args.rows, seed=args.seed)
    df.to_csv(args.out, index=False)


if __name__ == "__main__":
    main()
