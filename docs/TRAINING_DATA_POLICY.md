# Training-Data & Model Policy (ALIBI 1.0)

1. **100% Real Public 2026 Data.** Zero synthetic records. Zero honeypot approximations. Zero generated entries. Every model is trained, validated, and evaluated on verified public telemetry (abuse.ch ThreatFox, URLhaus, Feodo, CISA KEV, FIRST EPSS, iptoasn, DB-IP, OONI).
2. **Current Telemetry Only.** Models are trained exclusively on data from 2026. Every record retains its authentic timestamp and attribution. Legacy static datasets (e.g. 2020-2021 login datasets) have been permanently decommissioned.
3. **2026 ThreatFox Network-Risk Model.** Our core production ML model evaluates the probability of an autonomous system / IP block hosting active cyber threats (ROC-AUC 0.964, PR-AUC 0.941). It uses authentic abuse.ch indicators cross-referenced with BGP routing tables.
4. **Out-of-Time Evaluation.** Strict temporal splits: models are trained on preceding time windows, validated on intermediate intervals, and evaluated on the latest unseen telemetry. Information from future time steps is strictly prohibited during feature calculation.
5. **Transparency & Model Cards.** Every deployed model is accompanied by a complete model card (`netrisk_card.json`) detailing training horizons, feature sets, confusion matrices, ROC/PR metrics, and calibration curves.
6. **Privacy & Anonymity.** Public query endpoints enforce k-anonymity (e.g., Have I Been Pwned checks) and never persist sensitive visitor data or store user inputs in persistent databases.
7. **Zero Vendor Lock-In.** All pipelines, feature extraction scripts, model weights, and evaluation benchmarks are 100% open-source under the MIT license.
