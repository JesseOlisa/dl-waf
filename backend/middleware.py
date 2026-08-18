import re
import time
import logging
from datetime import datetime, timezone

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from backend import database, inference
from backend.config import settings

logger = logging.getLogger(__name__)

# The kill-switch lives in SQLite. Reading it on every proxied request would be
# wasteful, so cache it for a short TTL. invalidate_waf_cache() (called by the
# toggle route) forces an immediate refresh so the demo reacts instantly.
_WAF_CACHE_TTL = 1.0  # seconds
_waf_cache: dict = {"enabled": True, "at": 0.0}


def invalidate_waf_cache() -> None:
    _waf_cache["at"] = 0.0


def _waf_is_enabled() -> bool:
    now = time.monotonic()
    if now - _waf_cache["at"] > _WAF_CACHE_TTL:
        try:
            _waf_cache["enabled"] = database.get_waf_enabled()
        except Exception as exc:
            logger.error("Failed to read WAF state — assuming enabled: %s", exc)
            _waf_cache["enabled"] = True
        _waf_cache["at"] = now
    return _waf_cache["enabled"]

# Paths the WAF should never classify — its own API, docs, and demo routes.
# /demo handles its own WAF pipeline call internally.
_SKIP_PREFIXES = ("/api/", "/demo", "/docs", "/openapi", "/redoc")

# Localhost source IPs — dashboard frontend (port 3000) and other local
# services are trusted and bypass WAF classification entirely.
_TRUSTED_IPS = {"127.0.0.1", "::1"}

# Lightweight attack-type heuristics (regex on raw text)
_ATTACK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SQLi",               re.compile(r"select|union|insert|drop|--|;", re.IGNORECASE)),
    ("XSS",                re.compile(r"<script|onerror|javascript:", re.IGNORECASE)),
    ("Path Traversal",     re.compile(r"\.\./|\.\.\\", re.IGNORECASE)),
    ("Command Injection",  re.compile(r"\b(cmd|exec|system|bash|sh)\b|;\s*\$", re.IGNORECASE)),
]


def _guess_attack_type(text: str) -> str:
    for name, pattern in _ATTACK_PATTERNS:
        if pattern.search(text):
            return name
    return "Unknown"


class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Pass through WAF's own API/doc routes and trusted local traffic
        source_ip = request.client.host if request.client else ""
        if any(path.startswith(p) for p in _SKIP_PREFIXES) or source_ip in _TRUSTED_IPS:
            return await call_next(request)

        method = request.method
        url = str(request.url)
        headers = dict(request.headers)
        body_bytes = await request.body()
        body = body_bytes.decode("utf-8", errors="replace")

        waf_enabled = _waf_is_enabled()

        if waf_enabled:
            label, confidence = inference.classify(method, url, headers, body)
            attack_type = _guess_attack_type(url + "\n" + body) if label == 1 else None
            action_taken = "BLOCKED" if label == 1 else "ALLOWED"
        else:
            # Kill-switch off: fail open, do not classify. Malicious traffic passes
            # straight to the upstream — the "unprotected" state the demo simulates.
            label, confidence = 0, 0.0
            attack_type = None
            action_taken = "ALLOWED (WAF disabled)"

        payload_fragment = inference.get_payload_fragment(method, url, headers, body)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip or None,
            "http_method": method,
            "request_uri": str(request.url.path),
            "classification": label,
            "confidence_score": confidence,
            "attack_type": attack_type,
            "action_taken": action_taken,
            "payload_fragment": payload_fragment,
            "waf_enabled": 1 if waf_enabled else 0,
        }

        try:
            database.log_event(event)
        except Exception as exc:
            logger.error("Failed to log event: %s", exc)

        if label == 1:
            return JSONResponse(
                status_code=403,
                content={"detail": "Blocked by WAF", "confidence": confidence},
            )

        # Forward allowed request to upstream
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                target = settings.target_url.rstrip("/") + str(request.url.path)
                if request.url.query:
                    target += f"?{request.url.query}"

                fwd_headers = {
                    k: v for k, v in headers.items()
                    if k.lower() not in ("host", "content-length", "transfer-encoding")
                }

                resp = await client.request(
                    method=method,
                    url=target,
                    headers=fwd_headers,
                    content=body_bytes,
                )

            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers),
            )
        except httpx.ConnectError:
            return JSONResponse(status_code=502, content={"detail": "Upstream unavailable"})
        except Exception as exc:
            logger.error("Forward error: %s", exc)
            return JSONResponse(status_code=502, content={"detail": "Gateway error"})
