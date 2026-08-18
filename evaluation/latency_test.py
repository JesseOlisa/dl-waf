"""
Phase 7 — Inference Latency Measurement

Measures per-request inference latency for both LSTM and CNN models
on 1,000 randomly sampled test-set requests.

Usage:
    python -m evaluation.latency_test

Outputs:
    model/results/latency_results.json
"""

import json
import os
import time

import numpy as np
import tensorflow as tf

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC_DIR    = os.path.join(BASE_DIR, "data", "processed")
MODEL_DIR   = os.path.join(BASE_DIR, "model", "saved")
RESULTS_DIR = os.path.join(BASE_DIR, "model", "results")
N_SAMPLES   = 1_000
WARMUP      = 10


def measure_model(name: str, model_path: str, X: np.ndarray) -> dict:
    print(f"\n[{name.upper()}] Loading {model_path} …")
    model = tf.keras.models.load_model(model_path)

    # Warm up — avoid measuring cold-start JIT overhead
    print(f"  Warming up ({WARMUP} runs) …")
    for i in range(WARMUP):
        model.predict(X[:1], verbose=0)

    print(f"  Measuring {len(X)} single-sample inferences …")
    latencies_ms: list[float] = []
    for i in range(len(X)):
        t0 = time.perf_counter()
        model.predict(X[i : i + 1], verbose=0)
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    arr = np.array(latencies_ms)
    result = {
        "model":     name,
        "n_samples": len(latencies_ms),
        "mean_ms":   round(float(arr.mean()),             3),
        "median_ms": round(float(np.median(arr)),         3),
        "p95_ms":    round(float(np.percentile(arr, 95)), 3),
        "p99_ms":    round(float(np.percentile(arr, 99)), 3),
        "min_ms":    round(float(arr.min()),               3),
        "max_ms":    round(float(arr.max()),               3),
    }

    print(f"  mean={result['mean_ms']} ms  p95={result['p95_ms']} ms  p99={result['p99_ms']} ms")
    return result


def main() -> None:
    x_test_path = os.path.join(PROC_DIR, "X_test.npy")
    if not os.path.exists(x_test_path):
        print(f"[ERROR] {x_test_path} not found. Run data/preprocess.py first.")
        return

    print(f"Loading test set …")
    X_test = np.load(x_test_path)
    rng    = np.random.default_rng(42)
    idx    = rng.choice(len(X_test), size=min(N_SAMPLES, len(X_test)), replace=False)
    X_sample = X_test[idx]
    print(f"  Sampled {len(X_sample)} rows from {len(X_test):,}")

    results: dict[str, dict] = {}

    for model_name in ("lstm", "cnn"):
        path = os.path.join(MODEL_DIR, f"{model_name}_best.keras")
        if not os.path.exists(path):
            print(f"[SKIP] {path} not found")
            continue
        results[model_name] = measure_model(model_name, path, X_sample)

    if not results:
        print("[ERROR] No models found.")
        return

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "latency_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved → {out_path}")
    print("\n── Summary ──────────────────────────────────────────")
    for name, r in results.items():
        print(f"  {name.upper()}: mean={r['mean_ms']} ms  "
              f"p95={r['p95_ms']} ms  p99={r['p99_ms']} ms")


if __name__ == "__main__":
    main()
