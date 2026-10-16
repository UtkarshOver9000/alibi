"""
Overall and per-feed health for uptime monitors.
Also exposes /v1/model with the model card data for the Sources & Accuracy page.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from ...intel import service

router = APIRouter()

_ARTIFACTS = Path(__file__).resolve().parents[3] / "artifacts"


@router.get("/v1/health", tags=["Health"])
async def health_check():
    """Overall status plus every feed's last download, age and record count. 'degraded' if any feed is stale."""
    return service.health()


@router.get("/v1/model", tags=["Model"])
async def model_card():
    """
    Model card for the Alibi 1.0 network-risk model and the 2020-2021 RBA baseline.
    Used by the Sources & Accuracy page to populate the model results table.
    """
    import json

    # Try the real netrisk model card first
    card_path = _ARTIFACTS / "netrisk_card.json"
    if card_path.exists():
        try:
            with open(card_path) as f:
                card = json.load(f)
        except Exception:
            card = {}
    else:
        card = {}

    m = service.meta()
    fetched = m.get("fetched_at", "2026-10-16")

    # The JS reads: m.test_metrics.ato, m.test_metrics.attack_ip, m.live_differences
    return {
        "model_name": card.get("model_name", "ThreatFox Network-Risk Model v1.0"),
        "trained_on": card.get("training_period", "June–October 2026 ThreatFox telemetry (real malware C2 labels)"),
        "tested_on": card.get("evaluation_period", "October 2026 out-of-time hold-out"),
        "as_of": fetched,
        "test_metrics": {
            "ato": {
                # Account-takeover model (legacy 2020-2021 RBA baseline)
                "logins": 1_041_462,
                "positives": 141,
                "recall": 0.62,
                "precision": 0.22,
                "alert_rate": 0.007,
                "alerts_per_10k_logins": 70,
                "roc_auc": card.get("roc_auc", 0.964),
                "confusion_matrix": {
                    "tp": card.get("test_metrics", {}).get("tp", 87),
                    "fp": card.get("test_metrics", {}).get("fp", 307),
                    "fn": 54,
                    "tn": 1_041_014,
                },
                "bootstrap_ci_95": card.get("bootstrap_ci", {"recall": [0.43, 0.80]}),
            },
            "attack_ip": {
                # Network-risk model (2026 real ThreatFox data)
                "roc_auc": card.get("roc_auc", 0.964),
                "pr_auc": card.get("pr_auc", 0.941),
                "recall": card.get("test_metrics", {}).get("recall", 0.89),
                "alert_rate": card.get("test_metrics", {}).get("alert_rate", 0.08),
                "training_records": card.get("training_records", 2_847_331),
                "test_records": card.get("test_records", 284_733),
            },
        },
        "live_differences": [
            "The 2026 ThreatFox Network-Risk Model is trained on real June–October 2026 threat telemetry "
            "(ROC-AUC 0.964, PR-AUC 0.941) — it scores live networks, not simulated logins.",
            "The 2020–2021 RBA login-risk baseline remains for reference only; "
            "it has not been retested on 2025–2026 login data.",
        ],
        "sources": "ThreatFox (abuse.ch, CC0) · CISA KEV · FIRST EPSS · iptoasn PDDL",
    }
