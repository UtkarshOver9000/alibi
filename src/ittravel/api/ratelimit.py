"""
Per-IP token-bucket rate limits for the public, keyless endpoints.

Buckets live in process memory, so on a serverless platform each instance keeps its own
count. That stops one client hammering an instance; a gateway or CDN limit is still the
right place for a hard global cap.
"""

from __future__ import annotations

import math
import os
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# path prefix -> (bucket size, refill per second). First match wins.
LIMITS = (
    ("/v1/terminal/", (60, 1.0)),
    ("/v1/shield/", (60, 1.0)),
    ("/v1/", (120, 2.0)),  # read-only intel endpoints
)
EXEMPT = ("/v1/health",)


def trusted_proxy_hops() -> int:
    """How many proxies in front of the app append to X-Forwarded-For. With none (the default) the header is ignored,
    since anyone can write it. Vercel replaces the header with the caller's real address, so there the default is 1."""
    value = os.getenv("ALIBI_TRUSTED_PROXY_HOPS")
    if value:
        return max(int(value), 0)
    return 1 if os.getenv("VERCEL") else 0


def client_ip(request: Request) -> str:
    """The caller's address. X-Forwarded-For is read only behind trusted proxies, and then from the right: each proxy
    appends the address it saw, so the entry added by our outermost proxy is the first one a client can't forge."""
    direct = request.client.host if request.client else "unknown"
    hops = trusted_proxy_hops()
    forwarded = [part.strip() for part in request.headers.get("x-forwarded-for", "").split(",") if part.strip()]
    if hops and len(forwarded) >= hops:
        return forwarded[-hops]
    return direct


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limits=LIMITS):
        super().__init__(app)
        self.limits = limits
        self.buckets: dict[tuple[str, str], tuple[float, float]] = {}  # (ip, prefix) -> (tokens, last time)
        self.last_prune = time.monotonic()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        rule = next(((p, r) for p, r in self.limits if path.startswith(p)), None)
        if rule is None or path.startswith(EXEMPT):
            return await call_next(request)
        prefix, (size, refill) = rule
        now = time.monotonic()
        key = (client_ip(request), prefix)
        tokens, last = self.buckets.get(key, (float(size), now))
        tokens = min(size, tokens + (now - last) * refill)
        if tokens < 1:
            wait = math.ceil((1 - tokens) / refill)
            return JSONResponse(
                {"detail": f"Too many requests. Try again in {wait} s."},
                status_code=429,
                headers={"Retry-After": str(wait)},
            )
        self.buckets[key] = (tokens - 1, now)
        if now - self.last_prune > 600:  # forget idle clients
            self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < 600}
            self.last_prune = now
        return await call_next(request)
