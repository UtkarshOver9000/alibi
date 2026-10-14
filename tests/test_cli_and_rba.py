import gzip
import json
import sys
import zipfile
from pathlib import Path

import duckdb
import pandas as pd
import pytest

from ittravel.cli import score_file
from ittravel.engine import RiskEngine
from ittravel.rba import load, train
from ittravel.rba.features import FEATURE_COLUMNS, build_features
from ittravel.rba.train import evaluate, score_quantiles, threshold_for_budget
from ittravel.schema import LoginEvent
from ittravel.state import StateStore

RBA_SAMPLE = Path(__file__).parent / "fixtures" / "rba-sample.csv.gz"


def test_cli_scores_events_in_order(tmp_path):
    events = [
        {"user_id": "c", "login_ts": "2026-08-01T09:00:00Z", "ip": "84.208.20.10", "device_id": "d1", "country": "NO"},
        {"user_id": "c", "login_ts": "2026-08-01T09:10:00Z", "ip": "185.220.101.7", "device_id": "d2", "country": "RU"},
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events))
    out = score_file(path)
    assert len(out) == 2
    assert out[1]["features"]["country_hop_1h"] == 1


def test_feature_sql_uses_only_earlier_logins():
    con = duckdb.connect()
    rows = pd.DataFrame(
        {
            "ts": pd.to_datetime(["2020-03-01 10:00", "2020-03-01 10:20", "2020-03-02 09:00", "2020-03-01 10:30"]),
            "user_id": [1, 1, 1, 2],
            "rtt_ms": [500.0, None, 600.0, 300.0],
            "ip": ["a", "b", "b", "b"],
            "country": ["NO", "SE", "SE", "NO"],
            "asn": [1, 2, 2, 2],
            "ua": ["x", "y", "y", "z"],
            "browser": ["c", "c", "c", "c"],
            "os": ["w", "w", "w", "w"],
            "device": ["desktop", "desktop", "desktop", "mobile"],
            "success": [True, False, True, True],
            "attack_ip": [False, False, False, False],
            "ato": [False, True, False, False],
        }
    )
    con.register("rows", rows)
    con.execute("CREATE TABLE logins AS SELECT * FROM rows")
    assert build_features(con) == 4
    f = con.execute("SELECT * FROM features ORDER BY user_id, ts").fetchdf()
    first, hop, later = f.iloc[0], f.iloc[1], f.iloc[2]
    assert first["new_country"] == 0 and first["log_prior_logins"] == 0
    assert hop["new_country"] == 1 and hop["country_hop_1h"] == 1 and hop["new_asn"] == 1 and hop["success"] == 0
    assert later["new_country"] == 0 and later["prev_failed"] == 1 and later["fails_prev10"] == 1
    other = f.iloc[3]
    assert other["ip_attempts_1h"] == 1 and other["ip_failures_1h"] == 1  # user 1's failed 10:20 attempt from IP "b"
    assert set(FEATURE_COLUMNS) <= set(f.columns)


def test_threshold_for_budget_and_quantiles():
    proba = pd.Series([0.9, 0.5, 0.1, 0.05, 0.01]).to_numpy()
    weights = pd.Series([1, 1, 1, 1, 1], dtype=float).to_numpy()
    assert threshold_for_budget(proba, weights, 0.2) == 0.9  # flags exactly the top 20%
    q = score_quantiles(proba, weights, levels=4)
    assert q["levels"][0] == 0 and q["levels"][-1] == 1
    assert q["values"] == sorted(q["values"])


def test_evaluate_reports_alert_metrics():
    y = pd.Series([1, 0, 0, 0, 1]).to_numpy()
    p = pd.Series([0.9, 0.8, 0.1, 0.1, 0.2]).to_numpy()
    m = evaluate(y, p, threshold=0.5)
    assert m["confusion_matrix"] == {"tn": 2, "fp": 1, "fn": 1, "tp": 1}
    assert m["alert_rate"] == 0.4 and m["alerts_per_10k_logins"] == 4000.0
    assert m["recall"] == 0.5 and m["precision"] == 0.5
    assert m["roc_auc"] == pytest.approx(5 / 6, abs=1e-4)


def test_training_runs_end_to_end_on_real_rba_rows(tmp_path, monkeypatch):
    """Zip like Zenodo's -> DuckDB -> features -> both models -> model card -> the live engine scores with them."""
    archive = tmp_path / "rba-dataset.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("rba-dataset.csv", gzip.decompress(RBA_SAMPLE.read_bytes()))
    db = tmp_path / "rba.duckdb"
    assert load.load(archive, db, chunk_rows=1000) == 2676  # three chunks, so appending is covered too

    artifacts = tmp_path / "artifacts"
    monkeypatch.setattr(train, "ARTIFACT_DIR", artifacts)
    monkeypatch.setattr(train, "MAX_ROUNDS", 40)  # enough to exercise round picking; the real run tries 500
    monkeypatch.setattr(sys, "argv", ["train", "--db", str(db), "--reports-dir", str(tmp_path / "reports")])
    train.main()

    card = json.loads((artifacts / "rba_model_card.json").read_text())
    assert card["features"] == FEATURE_COLUMNS and card["live_differences"]
    assert card["dataset"]["logins"] == 2676 and card["dataset"]["account_takeovers"] == 25
    for target in ("ato", "attack_ip"):
        test = card["test_metrics"][target]
        assert test["positives"] > 0 and 0 <= test["roc_auc"] <= 1
        assert card["score_quantiles"][target]["values"] == sorted(card["score_quantiles"][target]["values"])
    report = json.loads((tmp_path / "reports" / "rba_metrics.json").read_text())
    assert set(report["targets"]) == {"ato", "attack_ip"}
    assert (tmp_path / "reports" / "figures" / "rba_training_curves.png").stat().st_size > 0

    engine = RiskEngine(state_store=StateStore(), artifact_dir=artifacts)
    login = LoginEvent(user_id="u", login_ts="2026-08-03T09:00:00Z", ip="84.208.20.10", device_id="d", country="NO")
    result = engine.evaluate_event(login)
    assert 0 <= result.ato_probability <= 1 and result.risk_tier in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
