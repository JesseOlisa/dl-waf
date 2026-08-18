"""
Scenario runner — turns a scenario into a synthetic request, runs the two-layer
detector, applies the WAF on/off decision, executes the vulnerable op when the
attack gets through, logs the event, and returns a rich RunResult.
"""

import time
from datetime import datetime, timezone
from urllib.parse import quote

from backend import database
from backend.simulation import detection, vulnerable_app
from backend.simulation.detection import SYNTHETIC_UA

_HOST = "portal.sterlingtrust.ng"


def _scenario_fields(scenario: dict) -> dict:
    """Form fields for the request — multi-field if provided, else the single param."""
    if scenario.get("fields"):
        return dict(scenario["fields"])
    return {scenario["param_name"]: scenario["payload"]}


def _build_request(scenario: dict) -> tuple[str, str, dict, str, str]:
    """Return (method, url_with_query, headers, body, raw_request_text)."""
    method = scenario["method"]
    uri = scenario["target_uri"]
    fields = _scenario_fields(scenario)
    # Values are placed raw (already-encoded evasion payloads keep their %xx). A
    # real WAF normalises before inspection, and percent-encoding benign spaces
    # would itself trip the encoding-sensitive model — so we do not re-encode.
    encoded = "&".join(f"{k}={v}" for k, v in fields.items())

    if method == "GET":
        url = f"{uri}?{encoded}" if encoded else uri
        body = ""
        content_type = ""
    else:
        url = uri
        body = encoded
        content_type = "application/x-www-form-urlencoded"

    headers = {
        "content-type": content_type,
        "user-agent": SYNTHETIC_UA,
        "cookie": "",
    }

    # Human-readable raw HTTP request for the console.
    lines = [f"{method} {url} HTTP/1.1", f"Host: {_HOST}", f"User-Agent: {SYNTHETIC_UA}"]
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    raw = "\n".join(lines)
    if body:
        raw += f"\n\n{body}"

    return method, url, headers, body, raw


def _normalize_attack_type(category: str, final_label: int) -> str | None:
    if final_label == 0:
        return None
    return category  # "SQL Injection" | "XSS"


def run_scenario(
    scenario: dict,
    waf_enabled: bool,
    actor: str = "operator",
    source_ip: str | None = None,
) -> dict:
    method, url, headers, body, raw = _build_request(scenario)
    is_legit = scenario["category"] == "Legitimate"
    source_ip = source_ip or scenario.get("source_ip") or "203.0.113.66"

    t0 = time.perf_counter()
    det = detection.detect(method, url, headers, body)
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    final_label = det["final_label"]
    model_conf = det["model"]["confidence"]

    # Decision: block only when the WAF is on AND something flagged it.
    blocked = waf_enabled and final_label == 1
    verdict = "BLOCKED" if blocked else "ALLOWED"

    consequence = None
    if blocked:
        outcome = "attack_blocked"
    elif is_legit:
        outcome = "legitimate_allowed"
    else:
        # Attack got through — the WAF is off, or the engine missed it. Execute it.
        outcome = "attack_succeeded"
        try:
            consequence = vulnerable_app.execute_op(
                scenario["vuln_op"], _scenario_fields(scenario)
            )
        except Exception as exc:  # pragma: no cover - defensive
            consequence = {
                "kind": "none", "title": "Execution error",
                "summary": f"Vulnerable op raised: {exc}",
            }

    attack_type = _normalize_attack_type(scenario["category"], final_label)
    action_taken = "BLOCKED" if blocked else "ALLOWED"

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "http_method": method,
        "request_uri": url,
        "classification": final_label,
        "confidence_score": round(model_conf, 6),
        "attack_type": attack_type,
        "action_taken": action_taken,
        "payload_fragment": raw[:200],
        "scenario_id": scenario["id"],
        "latency_ms": latency_ms,
        "waf_enabled": 1 if waf_enabled else 0,
    }
    event_id = database.log_event(event)

    return {
        "scenario_id": scenario["id"],
        "category": scenario["category"],
        "title": scenario["title"],
        "level": scenario["level"],
        "waf_enabled": waf_enabled,
        "raw_request": raw,
        "model": det["model"],
        "signature": det["signature"],
        "final_label": final_label,
        "blocked_by": det["blocked_by"] if blocked else None,
        "latency_ms": latency_ms,
        "verdict": verdict,
        "outcome": outcome,
        "event_id": event_id,
        "consequence": consequence,
    }
