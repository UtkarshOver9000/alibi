"""ALIBI 1.0 — Open-Source Planetary Tech & Defense Terminal."""

__version__ = "1.0.0"

from .client import AlibiClient, AlibiClientError

__all__ = ["__version__", "AlibiClient", "AlibiClientError"]
