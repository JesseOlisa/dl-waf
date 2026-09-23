"""
Phase 7 — Obfuscation / Evasion Robustness Evaluation

Measures how the DL-WAF behaves on obfuscated, encoded, and filter-evasion
payloads that the standard CSIC-2010 test split does not stress. This is the
quantitative counterpart to the qualitative scenarios in
backend/simulation/scenarios.py (sqli_obfuscated, xss_filter_evasion).

Three detection surfaces are reported per payload, so the paper can be precise
about which layer caught (or missed) what:

  Layer 1 — deployed reverse-proxy middleware decision (model-only, as in
            backend/middleware.py). No normalisation of encoded payloads.
  Layer 2 — signature scan on the double-URL-decoded request (as in
            backend/simulation/detection.py). Already normalises before matching.
  Layered — the two-layer simulation engine's final (detection.py:68): a block
            requires a confirmed signature, so the model is advisory only.

An optional ModSecurity CRS baseline can be attached via --mode (binding uses
python-modsecurity on Kaggle/Colab, http replays against a running
owasp/modsecurity-crs container) so obfuscated-attack block rates are directly
comparable between ModSecurity and the DL-WAF.

Usage:
    python -m evaluation.obfuscation_eval                      # local, DL-WAF layers
    python -m evaluation.obfuscation_eval --mode binding --crs /tmp/coreruleset
    python -m evaluation.obfuscation_eval --mode http --url http://localhost:8081

Output:
    model/results/obfuscation_results.json
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import quote, unquote

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR  = os.path.join(BASE_DIR, "model", "results")

SYNTHETIC_UA = "Mozilla/5.0 (Windows NT 6.1; WOW64)"


def _double(raw: str) -> str:
    return quote(quote(raw, safe=""), safe="")


# ── Payload registry ───────────────────────────────────────────────────────────
# expected: 1 = genuinely malicious, 0 = legitimate traffic. Fields are data, so
# each entry documents the evasion technique it targets rather than cluttering
# the code with comments.
PAYLOADS = [
    # SQL injection
    {"id": "sqli_auth_bypass", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "admin' OR '1'='1' --", "expected": 1,
     "technique": "plain auth bypass (control)"},
    {"id": "sqli_obfuscated_encoded", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "%27%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%3D%271%27--", "expected": 1,
     "technique": "URL-encoded inline-comment auth bypass (simulation console scenario)"},
    {"id": "sqli_comment_inline", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "admin'/**/OR/**/'1'='1'--", "expected": 1,
     "technique": "inline-comment whitespace obfuscation"},
    {"id": "sqli_double_encoded", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": _double("admin' OR '1'='1' --"), "expected": 1,
     "technique": "double percent-encoding"},
    {"id": "sqli_tab_separators", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "admin'\tOR\t'1'='1'--", "expected": 1,
     "technique": "tab/whitespace separator obfuscation"},
    {"id": "sqli_mixed_case", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "AdMiN' oR '1'='1' --", "expected": 1,
     "technique": "mixed-case keywords"},
    {"id": "sqli_no_whitespace", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "0'UNION/**/SELECT/**/password/**/FROM/**/users--", "expected": 1,
     "technique": "no whitespace between SQL keywords (hard evasion)"},

    # Cross-site scripting
    {"id": "xss_reflected", "category": "XSS", "method": "GET", "uri": "/api/bank/search", "param": "q",
     "payload": "<script>alert('XSS')</script>", "expected": 1,
     "technique": "plain reflected XSS (control)"},
    {"id": "xss_svg_onload", "category": "XSS", "method": "GET", "uri": "/api/bank/search", "param": "q",
     "payload": "<svg/onload=alert(document.cookie)>", "expected": 1,
     "technique": "SVG onload filter evasion (simulation console scenario)"},
    {"id": "xss_img_onerror", "category": "XSS", "method": "POST", "uri": "/api/bank/support", "param": "message",
     "payload": "<img src=x onerror=alert(document.cookie)>", "expected": 1,
     "technique": "img onerror handler evasion"},
    {"id": "xss_nested_script", "category": "XSS", "method": "GET", "uri": "/api/bank/search", "param": "q",
     "payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "expected": 1,
     "technique": "nested-tag filter break"},
    {"id": "xss_double_encoded", "category": "XSS", "method": "GET", "uri": "/api/bank/search", "param": "q",
     "payload": _double("<script>alert('XSS')</script>"), "expected": 1,
     "technique": "double percent-encoded script tag"},
    {"id": "xss_hex_entities", "category": "XSS", "method": "GET", "uri": "/api/bank/search", "param": "q",
     "payload": "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;", "expected": 1,
     "technique": "hex HTML-entity encoding (hard evasion, not URL-decoded)"},
    {"id": "xss_javascript_uri", "category": "XSS", "method": "GET", "uri": "/api/bank/search", "param": "q",
     "payload": "<a href=jav&#x61;script:alert(1)>click</a>", "expected": 1,
     "technique": "entity-obfuscated javascript: URI"},

    # Legitimate baselines — must NOT be blocked
    {"id": "legit_account_lookup", "category": "Legitimate", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "0123456701", "expected": 0,
     "technique": "normal account-number lookup"},
    {"id": "legit_balance_query", "category": "Legitimate", "method": "GET", "uri": "/api/bank/accounts", "param": "q",
     "payload": "balance=5000", "expected": 0,
     "technique": "normal balance query"},
    {"id": "legit_plain_search", "category": "Legitimate", "method": "GET", "uri": "/api/bank/search", "param": "q",
     "payload": "loan calculator status", "expected": 0,
     "technique": "normal text search"},
]


def build_request(p: dict) -> tuple[str, str, dict, str, str]:
    """Return (method, url_with_query, headers, body, raw_request_text)."""
    method = p["method"]
    uri = p["uri"]
    pair = f"{p['param']}={p['payload']}"

    if method == "GET":
        url = f"{uri}?{pair}"
        body = ""
        content_type = ""
    else:
        url = uri
        body = pair
        content_type = "application/x-www-form-urlencoded"

    headers = {"content-type": content_type, "user-agent": SYNTHETIC_UA, "cookie": ""}

    lines = [f"{method} {url} HTTP/1.1", f"Host: portal.sterlingtrust.ng", f"User-Agent: {SYNTHETIC_UA}"]
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    raw = "\n".join(lines)
    if body:
        raw += f"\n\n{body}"
    return method, url, headers, body, raw


# ── DL-WAF layers ───────────────────────────────────────────────────────────────

def eval_dlwaf(p: dict) -> dict:
    """Run Layer 1 (model), Layer 2 (normalised signatures), and their OR."""
    from backend import inference
    from backend.simulation.detection import signature_scan

    method, url, headers, body, raw = build_request(p)

    t0 = time.perf_counter()
    model_label, model_conf = inference.classify(method, url, headers, body)
    sig = signature_scan(f"{url}\n{body}")
    latency_ms = round((time.perf_counter() - t0) * 1000, 3)

    sig_hit = sig["matched"]
    final_label = 1 if sig_hit else 0

    if sig_hit and model_label == 1:
        blocked_by = "both"
    elif sig_hit:
        blocked_by = "signature"
    elif model_label == 1:
        blocked_by = "model_only_advisory"
    else:
        blocked_by = None

    return {
        "payload_id": p["id"],
        "category": p["category"],
        "method": method,
        "uri": url,
        "payload": p["payload"],
        "technique": p["technique"],
        "expected": p["expected"],
        "decoded_to": unquote(unquote(p["payload"])),
        "layer1_model": {"label": model_label, "confidence": model_conf},
        "layer2_signature": {"matched": sig_hit, "category": sig["category"], "pattern": sig["pattern"]},
        "final_label": final_label,
        "blocked_by": blocked_by,
        "latency_ms": latency_ms,
    }


# ── ModSecurity CRS baseline ───────────────────────────────────────────────────

def eval_modsec_binding(p: dict, crs_path: str) -> dict:
    import modsecurity  # type: ignore

    modsec = modsecurity.Modsecurity()
    modsec.setConnectorInformation("DL-WAF-Eval/1.0")
    rules = modsecurity.Rules()
    setup_conf = os.path.join(crs_path, "crs-setup.conf.example")
    if not os.path.exists(setup_conf):
        setup_conf = os.path.join(crs_path, "crs-setup.conf")
    if os.path.exists(setup_conf):
        rules.loadFromUri(setup_conf)
    rules.loadFromUri(os.path.join(crs_path, "rules", "*.conf"))

    method, url, headers, body, _ = build_request(p)
    from urllib.parse import urlparse

    t0 = time.perf_counter()
    txn = modsecurity.Transaction(modsec, rules)
    txn.processConnection("127.0.0.1", 12345, "127.0.0.1", 80)
    txn.processURI(urlparse(url).path or "/", method, "1.1")
    txn.addRequestHeader("Host", "localhost")
    txn.addRequestHeader("User-Agent", SYNTHETIC_UA)
    if headers.get("content-type"):
        txn.addRequestHeader("Content-Type", headers["content-type"])
    txn.processRequestHeaders()
    if body:
        txn.appendRequestBody(body.encode("utf-8", errors="replace"))
    txn.processRequestBody()
    blocked = txn.intervention(modsecurity.ModSecurityIntervention())
    latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    return {"blocked": bool(blocked), "latency_ms": latency_ms}


def eval_modsec_http(p: dict, base_url: str, timeout: float) -> dict:
    import httpx

    method, url, headers, body, _ = build_request(p)
    from urllib.parse import urlparse

    path = urlparse(url).path
    target = base_url.rstrip("/") + path
    if urlparse(url).query:
        target += f"?{urlparse(url).query}"

    hdrs = {"User-Agent": SYNTHETIC_UA}
    if headers.get("content-type"):
        hdrs["Content-Type"] = headers["content-type"]

    t0 = time.perf_counter()
    try:
        resp = httpx.Client(timeout=timeout).request(
            method=method, url=target, headers=hdrs,
            content=body.encode("utf-8", errors="replace") if body else None,
        )
        blocked = resp.status_code in (403, 406)
    except Exception:
        blocked = False
    latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    return {"blocked": blocked, "latency_ms": latency_ms}


# ── Summarise + save ───────────────────────────────────────────────────────────

def summarize(rows: list) -> dict:
    def layer_fields(rows, key):
        return {
            "n_attacks": sum(1 for r in rows if r["expected"] == 1),
            "attacks_caught": sum(
                1 for r in rows if r["expected"] == 1 and r[key] == 1
            ),
            "legit_flags": sum(
                1 for r in rows if r["expected"] == 0 and r[key] == 1
            ),
        }

    model = layer_fields(rows, "layer1_model__label")
    sig = layer_fields(rows, "layer2_signature__matched")
    final = layer_fields(rows, "final_label")

    for d in (model, sig, final):
        d["attack_rate"] = round(d["attacks_caught"] / d["n_attacks"], 4) if d["n_attacks"] else None

    return {"layer1_model": model, "layer2_signature": sig, "layered": final}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["dlwaf", "binding", "http"], default="dlwaf",
                        help="dlwaf=local two-layer engine; binding=python-modsecurity; http=replay against server")
    parser.add_argument("--crs", default="/tmp/coreruleset", help="CRS repo path (binding mode)")
    parser.add_argument("--url", default="http://localhost:8081", help="ModSecurity server URL (http mode)")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    print(f"[1/3] Loading payload registry ({len(PAYLOADS)} payloads) …")
    print(f"[2/3] Load {args.mode} detection surface(s) …")

    if args.mode in ("dlwaf", "binding", "http"):
        try:
            from backend import inference
            inference.load_model_and_vocab()
        except Exception as exc:
            print(f"      [WARN] model unavailable ({exc}) — Layer 1 will fail open")

    rows = []
    for p in PAYLOADS:
        r = eval_dlwaf(p)

        if args.mode == "binding":
            r["modsecurity"] = eval_modsec_binding(p, args.crs)
        elif args.mode == "http":
            r["modsecurity"] = eval_modsec_http(p, args.url, args.timeout)
        else:
            r["modsecurity"] = None
        rows.append(r)

    # Flatten helpers used by summarize.
    for r in rows:
        r["layer1_model__label"] = r["layer1_model"]["label"]
        r["layer2_signature__matched"] = 1 if r["layer2_signature"]["matched"] else 0

    summary = summarize(rows)

    for r in rows:
        for drop in ("layer1_model__label", "layer2_signature__matched"):
            r.pop(drop, None)

    os.makedirs(OUT_DIR, exist_ok=True)
    result = {
        "experiment": "obfuscation_evasion_robustness",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "payloads_total": len(rows),
        "summary": summary,
        "payloads": rows,
    }
    out_path = os.path.join(OUT_DIR, "obfuscation_results.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"      Saved → {out_path}")

    print("\n[3/3] Results ─────────────────────────────────────────────")
    print(f"{'Payload':<28}{'Cat':<14}{'Exp':>3}{'L1':>3}{'L2':>3}{'Fin':>4}{'via':<22}")
    for r in rows:
        l1 = r["layer1_model"]["label"]
        l2 = 1 if r["layer2_signature"]["matched"] else 0
        via = r["blocked_by"] or "-"
        print(f"{r['payload_id']:<28}{r['category']:<14}{r['expected']:>3}"
              f"{l1:>3}{l2:>3}{r['final_label']:>4}{via:<22}")

    s = summary
    print("\n── Obfuscated-attack detection rate / legit false flags ──")
    print(f"  Layer1 model (reverse-proxy middleware, model-only): "
          f"{s['layer1_model']['attacks_caught']}/{s['layer1_model']['n_attacks']} "
          f"({s['layer1_model']['attack_rate']:.1%})  legit-flags={s['layer1_model']['legit_flags']}")
    print(f"  Layer2 signature (double-decoded scan):                "
          f"{s['layer2_signature']['attacks_caught']}/{s['layer2_signature']['n_attacks']} "
          f"({s['layer2_signature']['attack_rate']:.1%})  legit-flags={s['layer2_signature']['legit_flags']}")
    print(f"  Simulation engine final (signature-confirmed gate):    "
          f"{s['layered']['attacks_caught']}/{s['layered']['n_attacks']} "
          f"({s['layered']['attack_rate']:.1%})  legit-flags={s['layered']['legit_flags']}")

    ms = [r["modsecurity"] for r in rows if r["modsecurity"]]
    if ms:
        ms_att = sum(1 for r, m in zip(rows, [r["modsecurity"] for r in rows]) if r["expected"] == 1 and m["blocked"])
        ms_leg = sum(1 for r, m in zip(rows, [r["modsecurity"] for r in rows]) if r["expected"] == 0 and not m["blocked"])
        ms_n = sum(1 for r in rows if r["expected"] == 1)
        print(f"  ModSecurity CRS:                           "
              f"{ms_att}/{ms_n} ({ms_att / ms_n:.1%})  legit-allowed={ms_leg}/{sum(1 for r in rows if r['expected'] == 0)}")


if __name__ == "__main__":
    main()