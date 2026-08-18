"""
Phase 7 — DL-WAF vs ModSecurity Comparison

Loads metrics from model/results/ and prints a formatted side-by-side
comparison table for Chapter 5 of the thesis.

Usage:
    python -m evaluation.compare_results

Outputs:
    model/results/final_comparison.json   — machine-readable comparison
    Prints formatted table to stdout
"""

import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS  = os.path.join(BASE_DIR, "model", "results")


def load(filename: str) -> dict | None:
    path = os.path.join(RESULTS, filename)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


METRICS = ["accuracy", "precision", "recall", "f1_score", "false_positive_rate"]
LABELS  = {
    "accuracy":            "Accuracy",
    "precision":           "Precision",
    "recall":              "Recall (TPR)",
    "f1_score":            "F1-Score",
    "false_positive_rate": "False Positive Rate",
}


def pct(v: float) -> str:
    return f"{v * 100:.4f}%"


def winner(lstm: float, cnn: float, modsec: float | None, higher_is_better: bool) -> str:
    """Return arrow indicating which system leads on this metric."""
    candidates = {"LSTM": lstm, "CNN": cnn}
    if modsec is not None:
        candidates["ModSec"] = modsec
    best = max(candidates, key=lambda k: candidates[k] if higher_is_better else -candidates[k])
    return f"← {best}"


def print_table(lstm: dict, cnn: dict, modsec: dict | None) -> None:
    col_w   = 14
    has_ms  = modsec is not None

    header_cols = ["Metric", "LSTM", "CNN"]
    if has_ms:
        header_cols.append("ModSecurity")
    header_cols.append("Best")

    sep = "─" * (22 + col_w * (3 if has_ms else 2) + 10)
    print(f"\n{sep}")
    print(f"{'Metric':<22}" + "".join(f"{h:>{col_w}}" for h in header_cols[1:]))
    print(sep)

    for key in METRICS:
        higher_is_better = key != "false_positive_rate"
        label   = LABELS[key]
        v_lstm  = lstm.get(key, 0.0)
        v_cnn   = cnn.get(key, 0.0)
        v_ms    = modsec.get(key) if has_ms else None

        row = f"{label:<22}{pct(v_lstm):>{col_w}}{pct(v_cnn):>{col_w}}"
        if has_ms:
            row += f"{pct(v_ms):>{col_w}}"
        row += f"  {winner(v_lstm, v_cnn, v_ms, higher_is_better)}"
        print(row)

    print(sep)

    # Latency row
    lat = load("latency_results.json")
    if lat:
        print(f"\n{'Latency (mean ms)':<22}"
              f"{lat['lstm']['mean_ms']:>{col_w}.3f}"
              f"{lat['cnn']['mean_ms']:>{col_w}.3f}")
        if has_ms and modsec.get("mean_latency_ms"):
            print(f"{'ModSec latency (ms)':<22}"
                  f"{modsec['mean_latency_ms']:>{col_w}.3f}")

    print(sep)

    if not has_ms:
        print("\n  [!] modsecurity_metrics.json not found.")
        print("      Run: python -m evaluation.modsecurity_eval --url http://localhost:8081")


def main() -> None:
    lstm   = load("lstm_metrics.json")
    cnn    = load("cnn_metrics.json")
    modsec = load("modsecurity_metrics.json")

    if lstm is None:
        print("[ERROR] lstm_metrics.json not found in model/results/")
        return
    if cnn is None:
        print("[ERROR] cnn_metrics.json not found in model/results/")
        return

    print("\n══ DL-WAF vs ModSecurity — Chapter 5 Comparison ══")
    print_table(lstm, cnn, modsec)

    # Save machine-readable comparison
    comparison = {
        "lstm":        {k: lstm.get(k) for k in METRICS},
        "cnn":         {k: cnn.get(k)  for k in METRICS},
        "modsecurity": {k: modsec.get(k) for k in METRICS} if modsec else None,
    }

    lat = load("latency_results.json")
    if lat:
        comparison["latency"] = lat

    out = os.path.join(RESULTS, "final_comparison.json")
    with open(out, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"\n  Saved → {out}")


if __name__ == "__main__":
    main()
