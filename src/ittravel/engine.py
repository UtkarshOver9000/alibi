"""
ALIBI 1.0 — Network-risk scoring engine.

Uses the network-risk model trained on real 2026 ThreatFox data (ROC-AUC 0.964)
to score any ASN's risk of hosting a new attack server in the coming week.
The model lives at artifacts/netrisk_model.joblib and is retrained on each
6-hour snapshot refresh via GitHub Actions.
"""

from __future__ import annotations

from .netrisk.score import score as netrisk_score  # noqa: F401 — re-exported for API layer

__all__ = ["netrisk_score"]
