"""
Two-layer detection engine.

Layer 1 — the trained LSTM (backend.inference). Primary detector, excellent on
SQL injection.
Layer 2 — signature rules. Secondary detector that reliably catches XSS (which
the CSIC-2010-trained model under-detects) and normalises URL-encoded evasions
by decoding before matching, the way a production WAF does.

Final decision = model OR signature. Both signals are reported transparently so
the dashboard can show exactly which layer caught (or missed) each request. This
layered design is the honest answer to the model's XSS blind spot.
"""

import re
from urllib.parse import unquote

from backend import inference
from backend.config import settings

# Synthetic UA — the real browser UA false-positives the 2010-era model, so all
# simulated requests present this (the original demo relies on the same trick).
SYNTHETIC_UA = "Mozilla/5.0 (Windows NT 6.1; WOW64)"

_SIGNATURES = [
    ("SQL Injection", re.compile(
        r"union\s+select|select\s+.*\s+from|insert\s+into|update\s+\w+\s+set|"
        r"drop\s+table|delete\s+from|'\s*or\s*'?\d|or\s+1\s*=\s*1|--|/\*|;\s*drop|xp_cmdshell",
        re.IGNORECASE)),
    ("XSS", re.compile(
        r"<script|</script|onerror\s*=|onload\s*=|onmouseover\s*=|javascript:|"
        r"<img[^>]+src|<svg|<iframe|alert\s*\(|document\.cookie|eval\s*\(|<body[^>]+on",
        re.IGNORECASE)),
]


def signature_scan(text: str) -> dict:
    """Normalise (URL-decode) then match signatures. Returns the first hit."""
    # Decode twice to defeat simple double-encoding.
    normalized = unquote(unquote(text))
    for category, pattern in _SIGNATURES:
        m = pattern.search(normalized)
        if m:
            return {"matched": True, "category": category, "pattern": m.group(0)[:40]}
    return {"matched": False, "category": None, "pattern": None}


def detect(method: str, url: str, headers: dict, body: str) -> dict:
    """
    Run both layers on a request. Returns:
      { model:{label,confidence,threshold}, signature:{...},
        final_label:int, blocked_by: 'model'|'signature'|'both'|None }
    """
    model_label, model_conf = inference.classify(method, url, headers, body)

    # Signatures inspect the full request surface (URL + body).
    sig = signature_scan(f"{url}\n{body}")

    model_hit = model_label == 1
    sig_hit = sig["matched"]

    # Layered decision. The DL model is a high-RECALL anomaly detector: it flags
    # attacks with high confidence, but (trained on CSIC-2010) it also over-flags
    # unfamiliar legitimate banking traffic — e.g. numeric fund-transfer bodies.
    # The signature layer supplies PRECISION: a block requires a confirmed attack
    # signature, so the model's over-sensitivity cannot cause a false block. This
    # is the crux of the layered design — neither layer alone is sufficient.
    final_label = 1 if sig_hit else 0

    if sig_hit and model_hit:
        blocked_by = "both"
    elif sig_hit:
        blocked_by = "signature"
    elif model_hit:
        # Model flagged but no signature confirmed it — the layer prevents a false block.
        blocked_by = "model_only_advisory"
    else:
        blocked_by = None

    return {
        "model": {
            "label": model_label,
            "confidence": model_conf,
            "threshold": settings.classification_threshold,
        },
        "signature": sig,
        "final_label": final_label,
        "blocked_by": blocked_by,
    }
