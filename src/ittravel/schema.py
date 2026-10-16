"""
Request and response models for Alibi 1.0.
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, Field, field_validator


class CompanyQuery(BaseModel):
    q: str = Field(..., min_length=2, max_length=120, description="Company name, domain, or ASN")


class FootprintQuery(BaseModel):
    ip: str = Field(..., description="IP address to audit")

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return str(ipaddress.ip_address(v.strip()))


class DomainQuery(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253, description="Domain to inspect for threats")
