"""
Train and test the network-risk model on abuse.ch ThreatFox data.

    python -m ittravel.netrisk.train --threatfox data/intel/threatfox_full.json.zip

Question: how likely is an address in this network to become a new attack server next week? The panel covers
the last PANEL_WEEKS complete weeks before the export (ThreatFox's full export keeps about six months of
indicators, so older weeks would be thinned out). After HISTORY_WEEKS of history the weeks are split by time:
the earliest for training, the next VAL_WEEKS for validation and the last TEST_WEEKS for the test.

Three candidates predict each network's rate of new attack servers per address: gradient boosting and a
Poisson GLM (both weighted by network size, the standard exposure set-up) and the rule "attack servers per
address in the last 4 weeks". Validation picks the one that ranks address space best; the test weeks are
scored once. Every metric is address-weighted: a sign-in comes from one address, so a /8 counts as much as
65,536 /24s.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.linear_model import PoissonRegressor
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .panel import DAY0, FEATURES, HISTORY_WEEKS, MONOTONIC, Networks, counts, features, read_threatfox, week_index
from .panel import weekly as weekly_counts

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts"
NETWORK = Path(__file__).resolve().parents[1] / "intel_data" / "network.npz"
PANEL_WEEKS = 23
VAL_WEEKS = 4
TEST_WEEKS = 5
MAX_ROUNDS = 300  # boosting rounds tried; validation picks how many to keep
BOOTSTRAP = 100  # resamples of whole networks for the confidence intervals
SHARES = {"top_0.1pct_of_addresses": 0.001, "top_1pct_of_addresses": 0.01}
SEED = 7
RULE = "rule_servers_per_address_last_4_weeks"
LIVE_DIFFERENCES = [
    "Live scores are recomputed with every snapshot from the latest weeks of ThreatFox data, so they follow the "
    "attack servers reported most recently; the model itself was trained once, on the weeks named here.",
    "IPs are placed in networks with today's IP-to-network table, also for past weeks, so a range that changed "
    "owner since then is counted under its current network.",
]


def day(week: int) -> str:
    return str((DAY0 + pd.Timedelta(weeks=week)).date())


class Rule:
    """The baseline: attack servers per address in the last 4 weeks (ties broken by network size)."""

    def predict(self, x: np.ndarray) -> np.ndarray:
        col = FEATURES.index("log_servers_per_million_last_4_weeks")
        return np.expm1(x[:, col].astype(np.float64)) / 1e6 + 1e-15 * x[:, FEATURES.index("log10_network_size")]


def flagged(rate: np.ndarray, servers: np.ndarray, size: np.ndarray, share: float) -> dict:
    """What challenging sign-ins from the riskiest `share` of address space would have covered."""
    order = np.argsort(-rate, kind="stable")
    space = np.cumsum(size[order]) / size.sum()
    k = int(np.searchsorted(space, share)) + 1
    caught = servers[order[:k]].sum() / max(servers.sum(), 1)
    return {"networks": k, "recall": round(float(caught), 4), "lift": round(float(caught / space[k - 1]), 1)}


def evaluate(rate: np.ndarray, servers: np.ndarray, size: np.ndarray) -> dict:
    """Address-weighted: each new attack server is a positive, every other announced address a negative."""
    score = np.r_[rate, rate]
    truth = np.r_[np.ones_like(servers), np.zeros_like(servers)]
    weight = np.r_[servers, np.maximum(size - servers, 0)]
    keep = weight > 0
    out = {
        "network_weeks": int(len(rate)),
        "new_attack_servers": int(servers.sum()),
        "roc_auc": round(float(roc_auc_score(truth[keep], score[keep], sample_weight=weight[keep])), 4),
    }
    return out | {name: flagged(rate, servers, size, share) for name, share in SHARES.items()}


def bootstrap(rate: np.ndarray, servers: np.ndarray, size: np.ndarray, n_networks: int, weeks: int) -> dict:
    """95% intervals for the recall figures, resampling whole networks (their weeks move together)."""
    rng = np.random.default_rng(SEED)
    found: dict[str, list[float]] = {name: [] for name in SHARES}
    for _ in range(BOOTSTRAP):
        picked = rng.integers(0, n_networks, n_networks)
        rows = (picked[:, None] + n_networks * np.arange(weeks)).ravel()
        for name, share in SHARES.items():
            found[name].append(flagged(rate[rows], servers[rows], size[rows], share)["recall"])
    out: dict = {
        f"{name}_recall": [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]
        for name, v in found.items()
    }
    return out | {"resamples": BOOTSTRAP}


def fit_boosting(xt, yt, st, xv, yv, sv) -> tuple[HistGradientBoostingRegressor, int]:
    params: dict = dict(
        loss="poisson",
        learning_rate=0.05,
        max_leaf_nodes=31,
        min_samples_leaf=50,
        monotonic_cst=MONOTONIC,
        early_stopping=False,
        random_state=SEED,
    )
    full = HistGradientBoostingRegressor(max_iter=MAX_ROUNDS, **params).fit(xt, yt / st, sample_weight=st)
    # pick the round with the lowest Poisson deviance on the validation weeks
    curve = []
    for pred in full.staged_predict(xv):
        mu = np.maximum(pred * sv, 1e-12)
        curve.append(float(np.sum(2 * (np.where(yv > 0, yv * np.log(np.maximum(yv, 1e-12) / mu), 0) - (yv - mu)))))
    best = int(np.argmin(curve)) + 1
    return HistGradientBoostingRegressor(max_iter=best, **params).fit(xt, yt / st, sample_weight=st), best


def train(threatfox: Path, network: Path = NETWORK) -> tuple[dict, object]:
    df = read_threatfox(threatfox)
    nets = Networks(network)
    end = int(week_index(pd.Series([df["ts"].max()]))[0])  # the newest week is still running: stop before it
    first = end - PANEL_WEEKS
    servers, families = weekly_counts(df, nets, first, PANEL_WEEKS)
    n = len(nets.table)
    size = nets.table["size"].to_numpy().astype(np.float64)
    targets = list(range(HISTORY_WEEKS, PANEL_WEEKS))
    split = {
        "train": targets[: -VAL_WEEKS - TEST_WEEKS],
        "validation": targets[-VAL_WEEKS - TEST_WEEKS : -TEST_WEEKS],
        "test": targets[-TEST_WEEKS:],
    }

    def stack(weeks: list[int]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        return (
            np.vstack([features(servers, families, nets, w) for w in weeks]),
            np.concatenate([counts(servers, w) for w in weeks]),
            np.tile(size, len(weeks)),
        )

    (xt, yt, st), (xv, yv, sv), (xs, ys, ss) = (stack(split[k]) for k in ("train", "validation", "test"))
    boosting, rounds = fit_boosting(xt, yt, st, xv, yv, sv)
    # per million addresses, in float64 with mean-one weights: lbfgs on the raw scale returns NaN gradients
    glm = make_pipeline(StandardScaler(), PoissonRegressor(alpha=1e-6, max_iter=1000, solver="newton-cholesky"))
    glm.fit(xt.astype(np.float64), yt / st * 1e6, poissonregressor__sample_weight=st / st.mean())
    candidates = {"gradient_boosting": boosting, "poisson_glm": glm, RULE: Rule()}
    scale = {"gradient_boosting": 1.0, "poisson_glm": 1e-6, RULE: 1.0}

    def rate(name: str, x: np.ndarray) -> np.ndarray:
        return candidates[name].predict(x.astype(np.float64)) * scale[name]

    val_auc = {k: evaluate(rate(k, xv), yv, sv)["roc_auc"] for k in candidates}
    chosen = max(val_auc, key=val_auc.__getitem__)
    test = {k: evaluate(rate(k, xs), ys, ss) for k in candidates}
    weeks = week_index(df["ts"])
    in_panel = df[(weeks >= first) & (weeks < end)]
    card = {
        "name": "Network risk model",
        "question": "How likely is an address in this network to become a new attack server next week?",
        "data": {
            "source": "abuse.ch ThreatFox, full export (ip:port indicators)",
            "url": "https://threatfox.abuse.ch/export/json/full/",
            "licence": "CC0",
            "newest_indicator": str(df["ts"].max()),
            "attack_server_ips": int(in_panel["ip"].nunique()),
            "networks": n,
            "networks_with_a_server": int((servers.sum(axis=1) > 0).sum()),
        },
        "periods": {
            "history": [day(first), day(first + HISTORY_WEEKS)],
            **{k: [day(first + w[0]), day(first + w[-1] + 1)] for k, w in split.items()},
        },
        "features": FEATURES,
        "chosen": chosen,
        "validation_roc_auc": val_auc,
        "gradient_boosting_rounds": rounds,
        "test_metrics": {"model": test[chosen], **test},
        "confidence_intervals": bootstrap(rate(chosen, xs), ys, ss, n, len(split["test"])),
        "live_differences": LIVE_DIFFERENCES,
        "scikit_learn": sklearn.__version__,
    }
    return card, {"model": candidates[chosen], "scale": scale[chosen], "features": FEATURES}


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the network-risk model on ThreatFox data")
    parser.add_argument("--threatfox", type=Path, default=Path("data/intel/threatfox_full.json.zip"))
    parser.add_argument("--network", type=Path, default=NETWORK)
    args = parser.parse_args()
    card, bundle = train(args.threatfox, args.network)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, ARTIFACT_DIR / "netrisk_model.joblib", compress=3)
    (ARTIFACT_DIR / "netrisk_card.json").write_text(json.dumps(card, indent=2))
    print(json.dumps({k: card[k] for k in ("periods", "chosen", "validation_roc_auc")}, indent=1))
    print(json.dumps({k: v["roc_auc"] for k, v in card["test_metrics"].items()}, indent=1))
    print(json.dumps(card["test_metrics"]["model"] | {"ci": card["confidence_intervals"]}, indent=1))


if __name__ == "__main__":
    main()
