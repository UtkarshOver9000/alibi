"""
Sanity tests for the engine evaluation harness.
"""

from ittravel.evaluate import run_evaluation


def test_evaluation_metrics_are_well_formed():
    metrics = run_evaluation(rows=600, seed=3)
    assert metrics["rows"] == 600
    assert metrics["unique_users"] > 0
    for key in ("precision", "recall", "f1_score", "accuracy"):
        assert 0.0 <= metrics[key] <= 1.0
    cm = metrics["confusion_matrix"]
    assert cm["tp"] + cm["fp"] + cm["fn"] + cm["tn"] == 600


def test_evaluation_recall_is_reasonably_high():
    # The ensemble should catch the large majority of reference-labeled
    # impossible-travel events; this guards against a silent regression
    # in the velocity/device/subnet heuristics.
    metrics = run_evaluation(rows=3000, seed=11)
    assert metrics["recall"] >= 0.9
