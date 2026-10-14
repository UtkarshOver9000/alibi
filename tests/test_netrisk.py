"""The network-risk model, trained and scored on a real excerpt of abuse.ch ThreatFox's 2026 export."""

import gzip
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from ittravel.netrisk import panel, score, train

SAMPLE = Path(__file__).parent / "fixtures" / "raw" / "threatfox_full_sample.json.gz"
HOME_ISPS = (3320, 2856, 9498)  # Deutsche Telekom, BT, Bharti Airtel: huge, with a few infected boxes each


@pytest.fixture(scope="module")
def export(tmp_path_factory):
    """The excerpt zipped the way ThreatFox serves its full export."""
    path = tmp_path_factory.mktemp("threatfox") / "threatfox_full.json.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("full.json", gzip.decompress(SAMPLE.read_bytes()))
    return path


@pytest.fixture(scope="module")
def nets():
    return panel.Networks(train.NETWORK)


def test_features_never_look_ahead(export, nets):
    df = panel.read_threatfox(export)
    end = int(panel.week_index(pd.Series([df["ts"].max()]))[0])
    servers, families = panel.weekly(df, nets, end - train.PANEL_WEEKS, train.PANEL_WEEKS)
    assert servers.sum() > 1000
    for w in (panel.HISTORY_WEEKS, 12, train.PANEL_WEEKS - 1):
        later_s, later_f = servers.copy(), families.copy()
        later_s[:, w:] += 50  # anything in week w or after must not move week w's features
        later_f[:, w:] += 5
        assert np.array_equal(panel.features(servers, families, nets, w), panel.features(later_s, later_f, nets, w))


def test_training_and_scoring_end_to_end(export, monkeypatch, tmp_path):
    monkeypatch.setattr(train, "MAX_ROUNDS", 30)
    monkeypatch.setattr(train, "BOOTSTRAP", 10)
    card, bundle = train.train(export)
    assert card["periods"]["train"][1] == card["periods"]["validation"][0]  # out of time, no gaps or overlap
    assert card["periods"]["validation"][1] == card["periods"]["test"][0]
    assert card["chosen"] in card["validation_roc_auc"] and train.RULE in card["test_metrics"]
    test = card["test_metrics"]["model"]
    assert test["new_attack_servers"] > 100 and 0.5 < test["roc_auc"] <= 1
    lo, hi = card["confidence_intervals"]["top_1pct_of_addresses_recall"]
    assert 0 <= lo <= test["top_1pct_of_addresses"]["recall"] <= hi <= 1

    joblib.dump(bundle, tmp_path / "netrisk_model.joblib")
    scored = score.score(export, train.NETWORK, tmp_path / "netrisk_model.joblib")
    pct = dict(zip(scored["asn"].tolist(), scored["pct"].tolist(), strict=True))
    assert len(pct) > 50_000 and scored["top"] and scored["top"][0]["percentile"] >= 99


def test_the_shipped_model_keeps_home_isps_out_of_the_riskiest_addresses(export):
    scored = score.score(export, train.NETWORK)
    pct = dict(zip(scored["asn"].tolist(), scored["pct"].tolist(), strict=True))
    assert all(pct[asn] < 99 for asn in HOME_ISPS)
    assert all(t["servers_last_4_weeks"] > 0 and t["addresses"] >= score.MIN_LISTED_SIZE for t in scored["top"])
