"""
API Key Authorization dependency for FastAPI.
"""

from __future__ import annotations

from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from ..state import store


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key header 'X-API-Key'",
        )
    if not store.is_valid_api_key(api_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked API Key",
        )
    return api_key
