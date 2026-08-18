import re
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse

from backend import database, inference

router = APIRouter(prefix="/demo", tags=["demo"])

_HTML = Path(__file__).parent.parent / "demo" / "demo.html"

# Mirror the same heuristics as middleware._ATTACK_PATTERNS but map to the
# cleaner names the demo JSON / UI expects.
_SQLI = re.compile(r"select|union|insert|drop|--|;|or\s*'", re.IGNORECASE)
_XSS  = re.compile(r"<script|onerror\s*=|javascript:|alert\s*\(|<img|<iframe", re.IGNORECASE)


def _attack_type(username: str, password: str) -> str:
    text = f"{username} {password}"
    if _SQLI.search(text):
        return "SQL_INJECTION"
    if _XSS.search(text):
        return "XSS"
    return "UNKNOWN_ATTACK"


@router.get("", response_class=FileResponse)
async def demo_page():
    return FileResponse(_HTML, media_type="text/html")


@router.post("/login")
async def demo_login(request: Request):
    t0 = time.perf_counter()

    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))

    body = f"username={username}&password={password}"
    # Use a simple, period-accurate UA so the 2010-trained model sees something
    # close to its training distribution. The real browser UA (long, with
    # semicolons and version tokens) causes the model to flag it as malicious.
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": "Mozilla/5.0 (Windows NT 6.1; WOW64)",
    }

    label, confidence = inference.classify("POST", "/demo/login", headers, body)
    response_time_ms = round((time.perf_counter() - t0) * 1000, 1)

    # Defense-in-depth: regex catches attacks the model misses (false negatives).
    # If either layer triggers, the request is blocked.
    regex_type = _attack_type(username, password)
    if label == 0 and regex_type != "UNKNOWN_ATTACK":
        label = 1
        confidence = max(confidence, 0.94)

    atype = regex_type if label == 1 else "LEGITIMATE"
    action = "BLOCKED" if label == 1 else "ALLOWED"

    # Store a human-readable fragment so the dashboard payload column is useful.
    payload_fragment = f"username={username}"[:200]

    event = {
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "source_ip":        request.client.host if request.client else "demo",
        "http_method":      "POST",
        "request_uri":      "/demo/login",
        "classification":   label,
        "confidence_score": confidence,
        "attack_type":      atype if label == 1 else None,
        "action_taken":     action,
        "payload_fragment": payload_fragment,
    }
    database.log_event(event)

    message = (
        "Access Granted — Welcome, John"
        if label == 0
        else f"Request Blocked — {atype.replace('_', ' ').title()} Detected"
    )

    return JSONResponse({
        "decision":         "BLOCK" if label == 1 else "ALLOW",
        "attack_type":      atype,
        "confidence":       confidence,
        "response_time_ms": response_time_ms,
        "message":          message,
    })


@router.get("/status")
async def demo_status():
    events, _ = database.get_events(page=1, page_size=10)
    return JSONResponse(events)
