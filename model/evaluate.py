"""
Phase 4 — Model Comparison and Selection

Loads both trained models, evaluates them on the held-out test set, measures
single-request inference latency, and records which model the WAF should deploy.

Usage:
    python -m model.evaluate

Outputs (all in model/results/):
    lstm_metrics.json       — test-set metrics for the LSTM
    cnn_metrics.json        — test-set metrics for the CNN
    comparison_table.json   — both models' metrics + latency + selection
    latency_results.json    — mean/median/p95/p99 latency per model
    selected_model.json     — { "selected": ..., "reason": ... }
"""

import os
import json
import time

import numpy as np

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import tensorflow as tf
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC_DIR    = os.path.join(BASE_DIR, "data", "processed")
SAVED_DIR   = os.path.join(BASE_DIR, "model", "saved")
RESULTS_DIR = os.path.join(BASE_DIR, "model", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

MODELS = {
    "lstm": os.path.join(SAVED_DIR, "lstm_best.keras"),
    "cnn":  os.path.join(SAVED_DIR, "cnn_best.keras"),
}

# ── Settings (fixed by thesis spec) ────────────────────────────────────────────
THRESHOLD    = 0.5
BATCH_SIZE   = 64
WARMUP_RUNS  = 100     # excluded from timing
TIMED_RUNS   = 1000    # sequential single-request predictions


def load_test_set():
    print("[1/5] Loading test set …")
    X_test = np.load(os.path.join(PROC_DIR, "X_test.npy")).astype(np.int32)
    y_test = np.load(os.path.join(PROC_DIR, "y_test.npy")).astype(np.float32)
    print(f"      X_test={X_test.shape}  y_test={y_test.shape}")
    print(f"      Class balance — legitimate={int((y_test == 0).sum()):,}  "
          f"malicious={int((y_test == 1).sum()):,}")
    return X_test, y_test


def compute_metrics(name: str, model, X_test, y_test) -> dict:
    print(f"\n[2/5] Evaluating {name.upper()} on test set …")
    y_prob = model.predict(X_test, batch_size=BATCH_SIZE, verbose=1).flatten()
    y_pred = (y_prob >= THRESHOLD).astype(int)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n  {name.upper()} Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["Legitimate", "Malicious"]))
    print(f"  Confusion Matrix:\n{cm}")

    metrics = {
        "model": name,
        "accuracy":            round(acc,  6),
        "precision":           round(prec, 6),
        "recall":              round(rec,  6),
        "f1_score":            round(f1,   6),
        "false_positive_rate": round(fpr,  6),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp),
        },
    }

    out = os.path.join(RESULTS_DIR, f"{name}_metrics.json")
    with open(out, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"      Saved → {os.path.basename(out)}")
    return metrics


def measure_latency(name: str, model, X_test) -> dict:
    """Time single-request inference — this is what the WAF middleware does."""
    print(f"\n[3/5] Measuring {name.upper()} inference latency "
          f"({WARMUP_RUNS} warm-up + {TIMED_RUNS} timed) …")

    # Sample with replacement if the test set is smaller than the run count.
    total = WARMUP_RUNS + TIMED_RUNS
    idx = np.arange(total) % len(X_test)

    # Warm-up — first calls include graph tracing and lazy kernel init.
    for i in idx[:WARMUP_RUNS]:
        model.predict(X_test[i:i + 1], verbose=0)

    timings = []
    for n, i in enumerate(idx[WARMUP_RUNS:], start=1):
        x = X_test[i:i + 1]
        t0 = time.perf_counter()
        model.predict(x, verbose=0)
        timings.append((time.perf_counter() - t0) * 1000.0)   # ms

        if n % 250 == 0:
            print(f"      {n}/{TIMED_RUNS} …")

    arr = np.array(timings)
    result = {
        "model":     name,
        "n_samples": int(len(arr)),
        "mean_ms":   round(float(arr.mean()), 3),
        "median_ms": round(float(np.median(arr)), 3),
        "p95_ms":    round(float(np.percentile(arr, 95)), 3),
        "p99_ms":    round(float(np.percentile(arr, 99)), 3),
        "min_ms":    round(float(arr.min()), 3),
        "max_ms":    round(float(arr.max()), 3),
    }
    print(f"      mean={result['mean_ms']}ms  p95={result['p95_ms']}ms  "
          f"p99={result['p99_ms']}ms")
    return result


def select_model(lstm: dict, cnn: dict) -> dict:
    """Selection criterion: F1-score penalised by false-positive rate.

    A WAF that blocks legitimate traffic is worse than useless in production,
    so FPR is subtracted directly rather than treated as a tiebreak.
    """
    score_lstm = lstm["f1_score"] - lstm["false_positive_rate"]
    score_cnn  = cnn["f1_score"]  - cnn["false_positive_rate"]

    if score_lstm >= score_cnn:
        winner, w_score, l_score = "lstm", score_lstm, score_cnn
    else:
        winner, w_score, l_score = "cnn", score_cnn, score_lstm

    loser = "CNN" if winner == "lstm" else "LSTM"
    reason = (f"{winner.upper()} selected: combined score (F1 - FPR) = "
              f"{w_score:.4f} vs {loser} = {l_score:.4f}")
    return {"selected": winner, "reason": reason}


def print_comparison(lstm: dict, cnn: dict, latency: dict) -> None:
    print("\n[4/5] Side-by-side comparison")

    rows = [
        ("Accuracy",            "accuracy",            True),
        ("Precision",           "precision",           True),
        ("Recall (TPR)",        "recall",              True),
        ("F1-Score",            "f1_score",            True),
        ("False Positive Rate", "false_positive_rate", False),
    ]

    sep = "─" * 64
    print(f"\n{sep}")
    print(f"{'Metric':<24}{'LSTM':>14}{'CNN':>14}{'Better':>12}")
    print(sep)

    for label, key, higher_is_better in rows:
        v_lstm, v_cnn = lstm[key], cnn[key]
        if v_lstm == v_cnn:
            better = "tie"
        elif (v_lstm > v_cnn) == higher_is_better:
            better = "LSTM"
        else:
            better = "CNN"
        print(f"{label:<24}{v_lstm * 100:>13.4f}%{v_cnn * 100:>13.4f}%{better:>12}")

    print(sep)
    for label, key in [("Latency mean (ms)", "mean_ms"),
                       ("Latency p95 (ms)",  "p95_ms"),
                       ("Latency p99 (ms)",  "p99_ms")]:
        v_lstm, v_cnn = latency["lstm"][key], latency["cnn"][key]
        better = "LSTM" if v_lstm < v_cnn else ("CNN" if v_cnn < v_lstm else "tie")
        print(f"{label:<24}{v_lstm:>14.3f}{v_cnn:>14.3f}{better:>12}")
    print(sep)


def main():
    print("=" * 64)
    print("DL-WAF — Model Comparison and Selection")
    print("=" * 64)

    for name, path in MODELS.items():
        if not os.path.exists(path):
            print(f"[ERROR] {name} checkpoint not found: {path}")
            print("        Run model/train_lstm.py and model/train_cnn.py first.")
            return

    X_test, y_test = load_test_set()

    metrics, latency = {}, {}
    for name, path in MODELS.items():
        print(f"\n  Loading {name.upper()} from {os.path.relpath(path, BASE_DIR)} …")
        model = tf.keras.models.load_model(path)
        metrics[name] = compute_metrics(name, model, X_test, y_test)
        latency[name] = measure_latency(name, model, X_test)

    print_comparison(metrics["lstm"], metrics["cnn"], latency)

    selection = select_model(metrics["lstm"], metrics["cnn"])

    comparison = {
        "lstm":    metrics["lstm"],
        "cnn":     metrics["cnn"],
        "latency": latency,
        "selected_model": {
            "name":   selection["selected"],
            "reason": selection["reason"],
        },
    }

    outputs = {
        "comparison_table.json": comparison,
        "latency_results.json":  latency,
        "selected_model.json":   selection,
    }
    print("\n[5/5] Saving results …")
    for filename, payload in outputs.items():
        with open(os.path.join(RESULTS_DIR, filename), "w") as f:
            json.dump(payload, f, indent=2)
        print(f"      Saved → model/results/{filename}")

    print(f"\n  {selection['reason']}")
    print(f"\n  Point the WAF at this model via MODEL_PATH in backend/.env:")
    print(f"      MODEL_PATH=model/saved/{selection['selected']}_best.keras")


if __name__ == "__main__":
    main()
