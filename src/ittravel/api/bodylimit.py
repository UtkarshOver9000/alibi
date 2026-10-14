"""
A cap on request bodies, whether the client sends Content-Length or streams the body in chunks without one.
"""

from __future__ import annotations

from fastapi import HTTPException
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY = 256 * 1024  # a 30-event demo story is about 12 KB
TOO_LARGE = "Request body too large"


class BodyLimitMiddleware:
    """413 for a body over the limit: up front when Content-Length says so, and while reading otherwise, so no
    client can make the server hold a huge body in memory.

    Add it before any other middleware so it sits innermost: FastAPI then reads the body through it directly and
    turns its HTTPException into the 413 response (a BaseHTTPMiddleware in between would wrap the error)."""

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY):
        self.app, self.limit = app, limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        length = Headers(scope=scope).get("content-length", "")
        if length.isdigit() and int(length) > self.limit:
            return await JSONResponse({"detail": TOO_LARGE}, status_code=413)(scope, receive, send)
        seen = 0

        async def capped() -> Message:
            nonlocal seen
            message = await receive()
            seen += len(message.get("body", b""))
            if seen > self.limit:
                raise HTTPException(413, TOO_LARGE)
            return message

        await self.app(scope, capped, send)
