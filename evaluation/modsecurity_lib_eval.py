"""
Phase 7 — ModSecurity Real-Engine Evaluation (libmodsecurity binding)

Runs the ACTUAL ModSecurity v3 C engine (libmodsecurity) with OWASP CRS v3.3.9
over the exact same 9,160-row CSIC 2010 test split used for the LSTM/CNN metrics,
so the DL-WAF and ModSecurity numbers are directly comparable.

Unlike the pure-Python CRS rule emulation in kaggle_modsecurity_eval.ipynb, this
drives a real engine Transaction per request:
    process_connection -> process_uri -> headers -> body -> intervention

Blocking is enabled the way productions do it: after loading crs-setup.conf,
phase-2 SecDefaultAction is set to "deny,status:403" (CRS ships pass-only, i.e.
detection mode, by default). A request is "blocked" iff
transaction.intervention().disruptive is True.

Usage:
    python -m evaluation.modsecurity_lib_eval --crs /tmp/coreruleset
    python -m evaluation.modsecurity_lib_eval --crs /tmp/coreruleset --max-rows 500

Output:
    model/results/modsecurity_lib_metrics.json   (real engine numbers)
"""

import argparse
import glob
import json
import os
import time

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from evaluation.modsecurity_eval import build_test_split, RAW_CSV

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR  = os.path.join(BASE_DIR, "model", "results")

BASE_CONFIG = (
    "SecRuleEngine On\n"
    "SecRequestBodyAccess On\n"
    "SecRequestBodyLimit 13107200\n"
    "SecRequestBodyNoFilesLimit 131072\n"
    "SecResponseBodyAccess Off\n"
    "SecPcreMatchLimit 150000\n"
    "SecPcreMatchLimitRecursion 150000\n"
)

# CRS ships in detection-only mode (phase 1 & 2 default to "pass"). A production
# WAF enables blocking by flipping phase 2 to deny, which is what makes the
# anomaly-scoring threshold rule (REQUEST-949) actually return a 403.
BLOCKING_DEFAULTS = (
    'SecDefaultAction "phase:1,log,auditlog,pass"\n'
    'SecDefaultAction "phase:2,log,auditlog,deny,status:403"\n'
)


def _quiet():
    import libmodsecurity as ls

    modsec = ls.ModSecurity()
    try:
        modsec.set_log_callback(lambda *a: None)
    except Exception:
        pass
    return modsec


def build_rules(crs_path: str) -> tuple[object, int, int]:
    """Build a RulesSet once: base engine config + crs-setup + blocking defaults +
    all CRS rule files. Returns (rules, rules_parsed, files_with_fatal_errors)."""
    import libmodsecurity as ls

    rules = ls.RulesSet()
    base_rc = rules.load(BASE_CONFIG)
    if base_rc < 0:
        raise RuntimeError(f"base config failed: {rules.get_parser_error()}")

    setup = os.path.join(crs_path, "crs-setup.conf.example")
    if not os.path.exists(setup):
        setup = os.path.join(crs_path, "crs-setup.conf")
    setup_rc = rules.load_from_uri(setup) if os.path.exists(setup) else 0
    block_rc = rules.load(BLOCKING_DEFAULTS)

    files = sorted(glob.glob(os.path.join(crs_path, "rules", "*.conf")))
    loaded = 0
    failed = []
    for f in files:
        n = rules.load_from_uri(f)
        if n >= 0:
            loaded += n
        else:
            failed.append(os.path.basename(f))
    return rules, loaded, len(failed)


def _clean_path(url_field: str) -> str:
    """CSIC's URL column is the raw request line, e.g.
    'http://localhost:8080/tienda1/index.jsp HTTP/1.1'. Strip the trailing
    HTTP version (as preprocess.py does for the ML models) so ModSecurity
    receives a well-formed URI instead of one polluted by protocol dialect."""
    import re
    from urllib.parse import urlparse

    if not isinstance(url_field, str):
        return "/"
    url_field = re.sub(r"\s+HTTP/\S+$", "", url_field.strip())
    parsed = urlparse(url_field)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def classify_row(modsec, rules, row) -> tuple[int, float]:
    """Return (blocked, latency_ms) for one CSIC row through real ModSecurity."""
    import libmodsecurity as ls

    method   = str(row.get("Method", "GET") or "GET").strip().upper()
    url      = str(row.get("URL", "/") or "/").strip()
    target   = _clean_path(url)
    content_type = str(row.get("content-type", "") or "")
    ua       = str(row.get("User-Agent", "Mozilla/5.0") or "Mozilla/5.0")
    cookie   = str(row.get("cookie", "") or "")
    body     = str(row.get("content", "") or "")

    # Present a realistic HTTP transaction so the CRS 920-protocol rules do not
    # misfire on the *carriage* of the request (Content-Length on POST bodies,
    # Accept present, Content-Type only where a body actually exists). If these
    # are omitted, CRS rejects nearly every replay for non-attack reasons.
    t0 = time.perf_counter()
    txn = ls.Transaction(modsec, rules)
    txn.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
    txn.process_uri(target, method, "1.1")
    txn.add_request_header("Host", "localhost")
    txn.add_request_header("User-Agent", ua)
    txn.add_request_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    if body:
        content_type = content_type or "application/x-www-form-urlencoded"
        txn.add_request_header("Content-Type", content_type)
        txn.add_request_header("Content-Length", str(len(body.encode("utf-8", errors="replace"))))
    if cookie:
        txn.add_request_header("Cookie", cookie)
    txn.process_request_headers()
    if body:
        txn.append_request_body(body.encode("utf-8", errors="replace"))
    txn.process_request_body()
    inv = txn.intervention()
    latency_ms = (time.perf_counter() - t0) * 1000
    del txn
    return bool(inv and inv.disruptive), latency_ms

def compute_and_save(y_true, y_pred, latencies, info: dict) -> dict:
    acc  = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec  = float(recall_score(y_true, y_pred, zero_division=0))
    f1   = float(f1_score(y_true, y_pred, zero_division=0))
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel().tolist()
    fpr  = round(fp / (fp + tn), 6) if (fp + tn) > 0 else 0.0

    metrics = {
        "engine": "libmodsecurity (ModSecurity v3 C engine)",
        "crs_version": info["crs"],
        "rules_loaded": info["rules_loaded"],
        "config": "crs-setup + phase-2 deny (blocking enabled) | log-errors-home",
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1_score": round(f1, 6),
        "false_positive_rate": fpr,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "n_samples": len(y_true),
        "mean_latency_ms": round(float(np.mean(latencies)), 3),
        "p95_latency_ms": round(float(np.percentile(latencies, 95)), 3),
        "p99_latency_ms": round(float(np.percentile(latencies, 99)), 3),
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = os.path.join(OUT_DIR, "modsecurity_lib_metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"      Saved → {out_path}")
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--crs", default="/tmp/coreruleset",
                        help="Path to OWASP CRS repo (v3.3.x tested)")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Limit rows (for smoke testing)")
    args = parser.parse_args()

    print("[1/4] Loading dataset…")
    import pandas as pd
    df = pd.read_csv(RAW_CSV)
    df["content"] = df["content"].fillna("")
    df_test, y_true = build_test_split(df)
    if args.max_rows:
        df_test = df_test.head(args.max_rows)
        y_true = y_true[:args.max_rows]
    print(f"      {len(df_test):,} test rows (malicious={sum(y_true):,})")

    print(f"[2/4] Building real ModSecurity ruleset (CRS: {args.crs})…")
    rules, n_rules, n_failed = build_rules(args.crs)
    print(f"      rules parsed: {n_rules}  files with fatal errors: {n_failed}")

    modsec = _quiet()

    print(f"[3/4] Replaying {len(df_test):,} requests through libmodsecurity…")
    y_pred = []
    latencies = []
    t0_all = time.perf_counter()
    for i, (_, row) in enumerate(df_test.iterrows(), 1):
        blocked, lat = classify_row(modsec, rules, row)
        y_pred.append(1 if blocked else 0)
        latencies.append(lat)
        if i % 1000 == 0:
            print(f"      {i:,}/{len(df_test):,}  "
                  f"({time.perf_counter() - t0_all:.1f}s elapsed)")
    print(f"      done in {time.perf_counter() - t0_all:.1f}s")

    print("[4/4] Computing metrics…")
    metrics = compute_and_save(y_true, y_pred, latencies,
                               {"crs": "v3.3.9", "rules_loaded": n_rules})

    print("\n── Real ModSecurity (libmodsecurity + CRS 3.3.9) ──")
    for k, v in metrics.items():
        if k != "confusion_matrix":
            print(f"  {k:<22} {v}")
    cm = metrics["confusion_matrix"]
    print(f"  Confusion matrix:  TP={cm['tp']:,} FP={cm['fp']:,} "
          f"FN={cm['fn']:,} TN={cm['tn']:,}")


if __name__ == "__main__":
    main()