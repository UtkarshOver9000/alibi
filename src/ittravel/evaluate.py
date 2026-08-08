"""
Evaluate the real-time AIAnomalyEngine against the offline geometric
reference detector (detect.py) on synthetic labeled login sequences.

detect_impossible_travel() is a simple, independently-implemented
vectorized physics check (pure velocity/distance threshold). We treat its
output as ground truth and measure how well the production ensemble
engine (IsolationForest + device/subnet heuristics + geo-velocity) agrees
with it, since the ensemble also folds in signals the reference detector
doesn't see (new devices, subnet jumps).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detect import detect_impossible_travel
from .ml_engine import AIAnomalyEngine
from .schema import LoginEvent
from .state import StateStore
from .synthetic_data import generate_synthetic


def run_evaluation(rows: int = 5000, seed: int = 11) -> dict:
    df = generate_synthetic(rows, seed=seed)
    labeled = detect_impossible_travel(df).sort_values(["user_id", "login_ts"])

    engine = AIAnomalyEngine(state_store=StateStore())

    tp = fp = fn = tn = 0
    for row in labeled.itertuples(index=False):
        event = LoginEvent(
            user_id=str(row.user_id),
            login_ts=row.login_ts.isoformat() if hasattr(row.login_ts, "isoformat") else str(row.login_ts),
            lat=float(row.lat),
            lon=float(row.lon),
            city=row.city,
            country=row.country,
            device_id=row.device_id,
            ip=row.ip,
        )
        result = engine.evaluate_event(event)
        y_true = bool(row.is_impossible_travel)
        y_pred = bool(result.is_anomaly)

        if y_true and y_pred:
            tp += 1
        elif y_pred and not y_true:
            fp += 1
        elif y_true and not y_pred:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0

    return {
        "rows": int(rows),
        "unique_users": int(labeled["user_id"].nunique()),
        "positive_rate": round((tp + fn) / len(labeled), 4) if len(labeled) else 0.0,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the anomaly engine against the reference detector")
    parser.add_argument("--rows", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--out", type=Path, default=None, help="Optional JSON output path")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    metrics = run_evaluation(rows=args.rows, seed=args.seed)
    print(json.dumps(metrics, indent=2))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)


if __name__ == "__main__":
    main()
