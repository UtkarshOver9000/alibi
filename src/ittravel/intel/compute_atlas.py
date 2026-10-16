"""
Global AI & Compute Infrastructure Atlas (Pillar 10).
Curated planetary directory of major hyperscaler AI supercomputing clusters,
frontier semiconductor fabrication nodes, and high-bandwidth interconnects.
"""

from __future__ import annotations

from typing import Any

from .service import _load

# Real global AI superclusters and hyperscaler data centers
AI_SUPERCLUSTERS = [
    {
        "id": "aws-us-east-1",
        "name": "AWS US-East (Northern Virginia) AI Supercluster",
        "operator": "Amazon Web Services",
        "location": "Ashburn, Virginia, United States",
        "lat": 39.0438,
        "lon": -77.4874,
        "type": "hyperscaler_ai_cluster",
        "hardware": "NVIDIA H100 / B200, AWS Trainium2",
        "estimated_gpus": "100,000+",
        "subsea_corridors": ["MAREA", "Dunant", "BRUSA"],
    },
    {
        "id": "gcp-us-central1",
        "name": "Google Cloud Iowa (Council Bluffs) TPU v5p Cluster",
        "operator": "Google Cloud",
        "location": "Council Bluffs, Iowa, United States",
        "lat": 41.2619,
        "lon": -95.8608,
        "type": "hyperscaler_ai_cluster",
        "hardware": "Google Cloud TPU v5e / v5p, NVIDIA H100",
        "estimated_gpus": "80,000+",
        "subsea_corridors": ["Cross-continental US transits"],
    },
    {
        "id": "azure-east-us-2",
        "name": "Microsoft Azure East US 2 (Boydton) Frontier AI Cluster",
        "operator": "Microsoft Azure / OpenAI",
        "location": "Boydton, Virginia, United States",
        "lat": 36.6676,
        "lon": -78.3875,
        "type": "hyperscaler_ai_cluster",
        "hardware": "NVIDIA H100 / H200 (Azure NDv5)",
        "estimated_gpus": "120,000+",
        "subsea_corridors": ["Dunant", "MAREA", "Grace Hopper"],
    },
    {
        "id": "meta-prineville",
        "name": "Meta AI Research SuperCluster (Prineville)",
        "operator": "Meta Platforms",
        "location": "Prineville, Oregon, United States",
        "lat": 44.2999,
        "lon": -120.8345,
        "type": "hyperscaler_ai_cluster",
        "hardware": "NVIDIA H100 / Research SuperCluster (RSC)",
        "estimated_gpus": "350,000+",
        "subsea_corridors": ["Jupiter", "Bifrost", "Echo"],
    },
    {
        "id": "gcp-europe-west4",
        "name": "Google Cloud Europe-West4 (Eemshaven)",
        "operator": "Google Cloud",
        "location": "Eemshaven, Groningen, Netherlands",
        "lat": 53.4391,
        "lon": 6.8375,
        "type": "hyperscaler_ai_cluster",
        "hardware": "Google Cloud TPU v4 / v5e",
        "estimated_gpus": "40,000+",
        "subsea_corridors": ["TAT-14", "Apollo", "C-Lion1"],
    },
    {
        "id": "azure-sweden-central",
        "name": "Microsoft Azure Sweden Central (Gävle/Sandviken)",
        "operator": "Microsoft Azure",
        "location": "Gävle, Sweden",
        "lat": 60.6749,
        "lon": 17.1417,
        "type": "hyperscaler_ai_cluster",
        "hardware": "NVIDIA H100 (100% Carbon-Free Power Grid)",
        "estimated_gpus": "30,000+",
        "subsea_corridors": ["Eastern Light", "Baltic Sea Subsea"],
    },
]

# Real global semiconductor fabrication nodes & photolithography hubs
SEMICONDUCTOR_FABS = [
    {
        "id": "tsmc-fab-18",
        "name": "TSMC GigaFab 18 (3nm / 2nm GAA Production)",
        "operator": "Taiwan Semiconductor Manufacturing Co. (TSMC)",
        "location": "Tainan Science Park, Tainan, Taiwan",
        "lat": 23.1118,
        "lon": 120.2736,
        "type": "semiconductor_fab",
        "process_node": "3nm (N3E / N3P) & 2nm GAA (N2)",
        "criticality": "EXTREME — Produces >90% of global advanced AI accelerators (NVIDIA/Apple/AMD)",
    },
    {
        "id": "asml-hq",
        "name": "ASML Worldwide EUV Headquarters & Cleanrooms",
        "operator": "ASML Holding N.V.",
        "location": "Veldhoven, North Brabant, Netherlands",
        "lat": 51.4089,
        "lon": 5.4097,
        "type": "semiconductor_monopoly_chokepoint",
        "process_node": "High-NA EUV (0.55 NA EXE:5000) & 0.33 NA Twinscan",
        "criticality": "EXTREME — Sole worldwide supplier of Extreme Ultraviolet photolithography",
    },
    {
        "id": "intel-d1x",
        "name": "Intel Ronler Acres D1X Research & Production Fab",
        "operator": "Intel Corporation",
        "location": "Hillsboro, Oregon, United States",
        "lat": 45.5413,
        "lon": -122.9298,
        "type": "semiconductor_fab",
        "process_node": "Intel 18A (1.8nm with RibbonFET & PowerVia)",
        "criticality": "HIGH — United States domestic leading-edge foundry node",
    },
    {
        "id": "samsung-pyeongtaek",
        "name": "Samsung Electronics Pyeongtaek Campus (Line 3/4)",
        "operator": "Samsung Electronics",
        "location": "Pyeongtaek, Gyeonggi-do, South Korea",
        "lat": 37.0396,
        "lon": 127.0645,
        "type": "semiconductor_fab",
        "process_node": "3nm GAA & HBM3e / HBM4 High-Bandwidth Memory",
        "criticality": "EXTREME — Primary global manufacturer of HBM3e memory for AI accelerators",
    },
]


def get_compute_atlas() -> dict[str, Any]:
    """Compile the Global AI & Compute Infrastructure Atlas."""
    cables_data = _load("cables.json")
    all_cables = cables_data.get("cables", [])

    return {
        "title": "ALIBI 1.0 Global AI & Compute Infrastructure Atlas",
        "summary": (
            "Geospatial mapping of hyperscaler AI supercomputing clusters, semiconductor fabs, "
            "and interconnecting subsea infrastructure."
        ),
        "ai_clusters": AI_SUPERCLUSTERS,
        "semiconductor_fabs": SEMICONDUCTOR_FABS,
        "interconnecting_subsea_cables_count": len(all_cables),
        "source": "Corporate Filings, Public Disclosures, TeleGeography",
    }
