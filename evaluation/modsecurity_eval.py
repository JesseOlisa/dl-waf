"""
Phase 7 — ModSecurity Baseline Evaluation

Two modes — pick whichever environment you're in:

────────────────────────────────────────────────────────────────────
MODE A  (Kaggle / Google Colab — recommended)
────────────────────────────────────────────────────────────────────
Run these cells first in your notebook:

    !apt-get install -y libmodsecurity3 libmodsecurity-dev
    !pip install python-modsecurity
    !git clone https://github.com/coreruleset/coreruleset /tmp/crs

Then run:

    !python modsecurity_eval.py --mode binding --crs /tmp/coreruleset

────────────────────────────────────────────────────────────────────
MODE B  (local — requires a running ModSecurity HTTP server)
────────────────────────────────────────────────────────────────────
Start server:
    docker run -d -p 8081:80 -e BACKEND=http://httpbin.org \\
        owasp/modsecurity-crs:apache

Then run:
    python -m evaluation.modsecurity_eval --mode http --url http://localhost:8081

────────────────────────────────────────────────────────────────────
Output: model/results/modsecurity_metrics.json
"""

import argparse
import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score,
)
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_CSV  = os.path.join(BASE_DIR, "data", "raw", "csic_database.csv")
OUT_DIR  = os.path.join(BASE_DIR, "model", "results")


# ── Shared helpers ─────────────────────────────────────────────────────────────

def build_test_split(df: pd.DataFrame):
    """Reproduce the exact 70/15/15 stratified split from preprocess.py."""
    y = df["classification"].astype(int).values
    _, df_tmp, _, y_tmp = train_test_split(
        df, y, test_size=0.30, stratify=y, random_state=42
    )
    _, df_test, _, y_test = train_test_split(
        df_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=42
    )
    return df_test.reset_index(drop=True), y_test.tolist()


def extract_uri_path(url_field: str) -> str:
    # CSIC's URL column is the raw request line incl. trailing " HTTP/1.1";
    # strip it (as data/preprocess.py does) so the request line is well-formed.
    try:
        cleaned = re.sub(r"\s+HTTP/\S+$", "", str(url_field).strip())
        return urlparse(cleaned).path or "/"
    except Exception:
        return "/"


# ── MODE A: python-modsecurity binding ────────────────────────────────────────

def evaluate_binding(df_test: pd.DataFrame, crs_path: str) -> tuple[list, list[float]]:
    """
    Evaluate using the python-modsecurity C-library binding.
    Returns (y_pred, latencies_ms).
    """
    try:
        import modsecurity  # type: ignore
    except ImportError:
        raise ImportError(
            "python-modsecurity not installed.\n"
            "On Kaggle/Colab run:\n"
            "  !apt-get install -y libmodsecurity3 libmodsecurity-dev\n"
            "  !pip install python-modsecurity"
        )

    modsec = modsecurity.Modsecurity()
    modsec.setConnectorInformation("DL-WAF-Eval/1.0")

    rules = modsecurity.Rules()

    # Load CRS setup + rules
    setup_conf = os.path.join(crs_path, "crs-setup.conf.example")
    if not os.path.exists(setup_conf):
        setup_conf = os.path.join(crs_path, "crs-setup.conf")
    if os.path.exists(setup_conf):
        rules.loadFromUri(setup_conf)

    rules_glob = os.path.join(crs_path, "rules", "*.conf")
    rules.loadFromUri(rules_glob)

    y_pred: list[int] = []
    latencies: list[float] = []

    for _, row in df_test.iterrows():
        method       = str(row.get("Method", "GET") or "GET").strip().upper()
        url_field    = str(row.get("URL", "/") or "/").strip()
        uri_path     = extract_uri_path(url_field)
        content_type = str(row.get("content-type", "") or "")
        user_agent   = str(row.get("User-Agent", "Mozilla/5.0") or "Mozilla/5.0")
        cookie       = str(row.get("cookie", "") or "")
        body         = str(row.get("content", "") or "")

        t0 = time.perf_counter()
        txn = modsecurity.Transaction(modsec, rules)
        txn.processConnection("127.0.0.1", 12345, "127.0.0.1", 80)
        txn.processURI(uri_path, method, "1.1")
        txn.addRequestHeader("Host", "localhost")
        txn.addRequestHeader("User-Agent", user_agent)
        if content_type:
            txn.addRequestHeader("Content-Type", content_type)
        if cookie:
            txn.addRequestHeader("Cookie", cookie)
        txn.processRequestHeaders()
        if body:
            txn.appendRequestBody(body.encode("utf-8", errors="replace"))
        txn.processRequestBody()

        intervention = modsecurity.ModSecurityIntervention()
        blocked = txn.intervention(intervention)

        latencies.append((time.perf_counter() - t0) * 1000)
        y_pred.append(1 if blocked else 0)

    return y_pred, latencies


# ── MODE B: HTTP replay against a running server ───────────────────────────────

def evaluate_http(df_test: pd.DataFrame, base_url: str, timeout: float) -> tuple[list, list[float]]:
    """Replay requests via HTTP; 403/406 response = blocked = malicious."""
    import httpx

    y_pred: list[int] = []
    latencies: list[float] = []
    errors = 0

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        for i, (_, row) in enumerate(df_test.iterrows(), 1):
            method       = str(row.get("Method", "GET") or "GET").strip().upper()
            url_field    = str(row.get("URL", "/") or "/").strip()
            path         = url_field if url_field.startswith("/") else "/" + url_field
            target       = base_url.rstrip("/") + path
            content_type = str(row.get("content-type", "") or "")
            user_agent   = str(row.get("User-Agent", "Mozilla/5.0") or "Mozilla/5.0")
            cookie       = str(row.get("cookie", "") or "")
            body         = str(row.get("content", "") or "").encode("utf-8", errors="replace")

            headers = {"User-Agent": user_agent}
            if content_type:
                headers["Content-Type"] = content_type
            if cookie:
                headers["Cookie"] = cookie

            t0 = time.perf_counter()
            try:
                resp = client.request(method=method, url=target,
                                      headers=headers, content=body)
                prediction = 1 if resp.status_code in (403, 406) else 0
            except Exception as exc:
                prediction = 0
                errors += 1
                if errors == 1:
                    print(f"  WARNING connection error row {i}: {exc}")
            latencies.append((time.perf_counter() - t0) * 1000)
            y_pred.append(prediction)

            if i % 500 == 0:
                print(f"  {i:,}/{len(df_test):,} done")

    if errors:
        print(f"  Total errors: {errors} (treated as allowed)")
    return y_pred, latencies


# ── Metrics + save ─────────────────────────────────────────────────────────────

def compute_and_save(y_true: list, y_pred: list, latencies: list[float]) -> dict:
    acc  = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec  = float(recall_score(y_true, y_pred, zero_division=0))
    f1   = float(f1_score(y_true, y_pred, zero_division=0))
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel().tolist()
    fpr  = round(fp / (fp + tn), 6) if (fp + tn) > 0 else 0.0

    metrics = {
        "model":               "modsecurity",
        "accuracy":            round(acc,  6),
        "precision":           round(prec, 6),
        "recall":              round(rec,  6),
        "f1_score":            round(f1,   6),
        "false_positive_rate": fpr,
        "confusion_matrix":    {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "n_samples":           len(y_true),
        "mean_latency_ms":     round(float(np.mean(latencies)),           3),
        "p95_latency_ms":      round(float(np.percentile(latencies, 95)), 3),
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = os.path.join(OUT_DIR, "modsecurity_metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved → {out_path}")
    return metrics


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["binding", "http"], default="binding",
                        help="'binding' = python-modsecurity (Kaggle/Colab); "
                             "'http' = replay against running server")
    parser.add_argument("--crs",  default="/tmp/coreruleset",
                        help="Path to cloned OWASP CRS repo (binding mode)")
    parser.add_argument("--url",  default="http://localhost:8081",
                        help="ModSecurity server URL (http mode)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-rows", type=int, default=None)
    args = parser.parse_args()

    print(f"\n[1/3] Loading dataset: {RAW_CSV}")
    df = pd.read_csv(RAW_CSV)
    df["content"] = df["content"].fillna("")

    print("[2/3] Reconstructing test split …")
    df_test, y_true = build_test_split(df)
    if args.max_rows:
        df_test = df_test.head(args.max_rows)
        y_true  = y_true[:args.max_rows]
    print(f"      {len(df_test):,} test rows")

    print(f"[3/3] Evaluating via mode='{args.mode}' …")
    if args.mode == "binding":
        y_pred, latencies = evaluate_binding(df_test, args.crs)
    else:
        y_pred, latencies = evaluate_http(df_test, args.url, args.timeout)

    metrics = compute_and_save(y_true, y_pred, latencies)

    print("\n── Results ───────────────────────────────────────────")
    for k, v in metrics.items():
        if k != "confusion_matrix":
            print(f"  {k:<25} {v}")
    cm = metrics["confusion_matrix"]
    print(f"\n  Confusion matrix:  TP={cm['tp']:,}  FP={cm['fp']:,}  "
          f"FN={cm['fn']:,}  TN={cm['tn']:,}")


if __name__ == "__main__":
    main()
