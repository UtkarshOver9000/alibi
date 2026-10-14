"""
A weekly panel of networks (ASNs) and the attack servers abuse.ch ThreatFox saw on them.

Each row is one network in one week. Its features use only the weeks before; its target is how many new attack
servers (ip:port indicators) ThreatFox first saw on that network during the week. Models predict the rate per
address, because a sign-in comes from one address: a huge ISP with a few infected boxes is safer, address for
address, than a small host where every tenth server is malicious. IPs are mapped to networks with the snapshot's
IP-to-network table (iptoasn.com).
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

FEATURES = [
    "log_servers_per_million_last_week",
    "log_servers_per_million_last_4_weeks",
    "log_servers_per_million_before",
    "log_servers_last_4_weeks",
    "families_last_4_weeks",
    "weeks_since_last_server",
    "log10_network_size",
    "hosting",
]
# More past attack servers never lowers the risk; a longer quiet spell never raises it.
MONOTONIC = [1, 1, 1, 1, 1, -1, 0, 1]
HISTORY_WEEKS = 4  # the first weeks of a panel only serve as history
QUIET_CAP = 30  # weeks_since_last_server for a network never seen, or quiet for longer
DAY0 = pd.Timestamp("2026-01-05")  # a Monday: weeks run Monday to Sunday, UTC


def read_threatfox(path: Path) -> pd.DataFrame:
    """The IPv4 ip:port indicators of a ThreatFox JSON export (.zip as downloaded, .gz or plain .json)."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            raw = zf.read(zf.namelist()[0])
    else:
        raw = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    rows = [r for group in json.loads(raw).values() for r in group if r.get("ioc_type") == "ip:port"]
    ips, kept = [], []
    for r in rows:
        try:
            addr = ipaddress.ip_address(r["ioc_value"].rsplit(":", 1)[0])
        except ValueError:
            continue
        if addr.version == 4:
            ips.append(int(addr))
            kept.append(r)
    return pd.DataFrame(
        {
            "ts": pd.to_datetime([r["first_seen_utc"] for r in kept]),
            "ip": np.array(ips, dtype=np.int64),
            "malware": [r.get("malware") or "unknown" for r in kept],
        }
    )


class Networks:
    """Every announced network: its address ranges, total size and whether it is a hosting provider."""

    def __init__(self, network_npz: Path):
        z = np.load(network_npz)
        self.start, self.end, self.asn = z["start"], z["end"], z["asn"]
        sizes = pd.Series((self.end - self.start + 1).astype(np.int64)).groupby(self.asn).sum()
        hosting = pd.Series(z["hosting"]).groupby(self.asn).max()
        table = pd.DataFrame({"size": sizes, "hosting": hosting.astype(int)})
        self.table = table[table.index > 0]

    def asn_of(self, ips: np.ndarray) -> np.ndarray:
        i = np.searchsorted(self.start, ips, side="right") - 1
        inside = (i >= 0) & (ips <= self.end[np.maximum(i, 0)])
        return np.where(inside, self.asn[np.maximum(i, 0)], 0)


def week_index(ts: pd.Series) -> np.ndarray:
    return ((ts - DAY0).dt.days // 7).to_numpy()


def weekly(df: pd.DataFrame, nets: Networks, first: int, n_weeks: int) -> tuple[np.ndarray, np.ndarray]:
    """Distinct attack-server IPs and distinct malware families per network and week (weeks first..first+n-1)."""
    df = df.assign(asn=nets.asn_of(df["ip"].to_numpy()), week=week_index(df["ts"]) - first)
    df = df[(df["asn"] > 0) & (df["week"] >= 0) & (df["week"] < n_weeks)]
    grid = {"index": nets.table.index, "columns": range(n_weeks), "fill_value": 0}
    servers = df.groupby(["asn", "week"])["ip"].nunique().unstack(fill_value=0).reindex(**grid)
    families = df.groupby(["asn", "week"])["malware"].nunique().unstack(fill_value=0).reindex(**grid)
    return servers.to_numpy(), families.to_numpy()


def features(servers: np.ndarray, families: np.ndarray, nets: Networks, w: int) -> np.ndarray:
    """Features of every network for week w, from weeks before w only."""
    seen = servers[:, :w] > 0
    last = np.where(seen.any(axis=1), w - 1 - np.argmax(seen[:, ::-1], axis=1), w - QUIET_CAP)
    size = nets.table["size"].to_numpy().astype(np.float64)
    recent = servers[:, w - HISTORY_WEEKS : w].sum(axis=1)
    return np.column_stack(
        [
            np.log1p(servers[:, w - 1] * 1e6 / size),
            np.log1p(recent * 1e6 / size),
            np.log1p(servers[:, :w].sum(axis=1) * 1e6 / size),
            np.log1p(recent),
            families[:, w - HISTORY_WEEKS : w].sum(axis=1),
            np.minimum(w - last, QUIET_CAP),
            np.log10(size),
            nets.table["hosting"].to_numpy(),
        ]
    ).astype(np.float32)


def counts(servers: np.ndarray, w: int) -> np.ndarray:
    """New attack servers per network in week w: the target."""
    return servers[:, w].astype(np.float64)
