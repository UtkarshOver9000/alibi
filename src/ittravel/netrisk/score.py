"""
Score every network with the trained network-risk model, from the latest weeks of ThreatFox data.

The snapshot builder calls this after each ThreatFox download. Each network gets its predicted rate of new
attack servers per address and an address-weighted percentile: 99.9 means its addresses look riskier than 99.9%
of all announced IPv4 addresses.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .panel import Networks, features, read_threatfox, week_index
from .panel import weekly as weekly_counts
from .train import ARTIFACT_DIR, PANEL_WEEKS, day

TOP_LISTED = 25  # riskiest networks named on the dashboard
MIN_LISTED_SIZE = 256  # a /24 at least: a lone address with one server says little about a network


def score(threatfox: Path, network: Path, model_path: Path = ARTIFACT_DIR / "netrisk_model.joblib") -> dict:
    """Percentile of every network for next week, plus the riskiest few with their recent attack servers."""
    df = read_threatfox(threatfox)
    nets = Networks(network)
    end = int(week_index(pd.Series([df["ts"].max()]))[0])  # same history as the test weeks had: complete weeks only
    history = PANEL_WEEKS - 1
    servers, families = weekly_counts(df, nets, end - history, history)
    bundle = joblib.load(model_path)
    rate = bundle["model"].predict(features(servers, families, nets, history).astype(np.float64)) * bundle["scale"]
    size = nets.table["size"].to_numpy().astype(np.float64)
    order = np.argsort(rate, kind="stable")
    below = np.empty_like(rate)
    below[order] = np.cumsum(size[order]) / size.sum()  # share of address space at or below each network's rate
    asns = nets.table.index.to_numpy()
    recent = servers[:, -4:].sum(axis=1)
    listed = [i for i in order[::-1] if recent[i] > 0 and size[i] >= MIN_LISTED_SIZE][:TOP_LISTED]
    return {
        "asn": asns.astype(np.uint32),
        "pct": (below * 100).astype(np.float32),
        "rate": rate.astype(np.float32),
        "weeks": [day(end - history), day(end)],
        "top": [
            {
                "asn": int(asns[i]),
                "percentile": round(float(below[i] * 100), 3),
                "servers_last_4_weeks": int(recent[i]),
                "addresses": int(size[i]),
                "hosting": bool(nets.table["hosting"].iat[i]),
            }
            for i in listed
        ],
    }
