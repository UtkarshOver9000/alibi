"""
Detect impossible travel based on geo-distance and time deltas.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from .geo import haversine_km
from .schema import LOGIN_COLUMNS


def detect_impossible_travel(
    df: pd.DataFrame,
    speed_threshold_kmph: float = 900.0,
    min_time_hours: float = 0.25,
) -> pd.DataFrame:
    df = df.copy()
    df["login_ts"] = pd.to_datetime(df["login_ts"], utc=True, errors="coerce")
    df = df.sort_values(["user_id", "login_ts"])

    df["prev_login_ts"] = df.groupby("user_id")["login_ts"].shift(1)
    df["prev_lat"] = df.groupby("user_id")["lat"].shift(1)
    df["prev_lon"] = df.groupby("user_id")["lon"].shift(1)

    time_delta = (df["login_ts"] - df["prev_login_ts"]).dt.total_seconds() / 3600.0
    df["time_delta_hours"] = time_delta

    distance_km = haversine_km(
        df["prev_lat"].to_numpy(dtype=float),
        df["prev_lon"].to_numpy(dtype=float),
        df["lat"].to_numpy(dtype=float),
        df["lon"].to_numpy(dtype=float),
    )
    df["distance_km"] = distance_km

    with np.errstate(divide="ignore", invalid="ignore"):
        required_speed = df["distance_km"] / df["time_delta_hours"]
    df["required_speed_kmph"] = required_speed.replace([np.inf, -np.inf], np.nan)

    impossible = (df["time_delta_hours"] >= min_time_hours) & (df["required_speed_kmph"] > speed_threshold_kmph)
    df["is_impossible_travel"] = impossible.fillna(False).astype(int)

    return df


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect impossible travel anomalies")
    parser.add_argument("--data", type=Path, required=True, help="Input CSV path")
    parser.add_argument("--out", type=Path, required=True, help="Output CSV path")
    parser.add_argument("--speed-threshold", type=float, default=900.0, help="Max realistic travel speed km/h")
    parser.add_argument("--min-time-hours", type=float, default=0.25, help="Ignore deltas smaller than this")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    df = pd.read_csv(args.data)

    missing = [c for c in LOGIN_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    out = detect_impossible_travel(
        df,
        speed_threshold_kmph=args.speed_threshold,
        min_time_hours=args.min_time_hours,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.out, index=False)
    print(f"Wrote anomalies to: {args.out}")


if __name__ == "__main__":
    main()
