"""
Phase 1 — Data Preprocessing
Reads data/raw/csic_database.csv and produces tokenised, padded numpy arrays
plus supporting JSON files in data/processed/.
"""

import os
import json
import re
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from urllib.parse import urlparse

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_CSV    = os.path.join(BASE_DIR, "data", "raw", "csic_database.csv")
OUT_DIR    = os.path.join(BASE_DIR, "data", "processed")
os.makedirs(OUT_DIR, exist_ok=True)

# ── Constants ──────────────────────────────────────────────────────────────────
MAX_LEN    = 1024
VOCAB_SIZE = 97          # index 0 = padding, 1-95 = ASCII 32-126, 96 = newline

# ── Vocabulary ─────────────────────────────────────────────────────────────────

def build_vocab():
    """
    Fixed vocabulary (does not depend on corpus content):
      index 0  → padding / unknown
      index 1  → ASCII 32 (space)
      ...
      index 95 → ASCII 126 (~)
      index 96 → newline (\n)
    """
    vocab = {"<PAD>": 0}
    for code in range(32, 127):          # ASCII 32–126 → indices 1–95
        vocab[chr(code)] = code - 31
    vocab["\n"] = 96
    return vocab


def tokenize(text: str, vocab: dict) -> list:
    return [vocab.get(ch, 0) for ch in text]


def pad_or_truncate(seq: list, max_len: int) -> list:
    if len(seq) >= max_len:
        return seq[:max_len]             # truncate from end
    return seq + [0] * (max_len - len(seq))   # post-pad with zeros

# ── Request serialisation ──────────────────────────────────────────────────────

def extract_uri_path(url_field: str) -> str:
    """
    URL column looks like:
      'http://localhost:8080/tienda1/index.jsp HTTP/1.1'
    Returns just the path+query part: '/tienda1/index.jsp'
    """
    if not isinstance(url_field, str):
        return ""
    # strip trailing protocol version
    url_field = re.sub(r"\s+HTTP/\S+$", "", url_field.strip())
    try:
        parsed = urlparse(url_field)
        path = parsed.path
        if parsed.query:
            path = path + "?" + parsed.query
        return path
    except Exception:
        return url_field


def serialize_row(row) -> str:
    """
    Serialise one CSV row into a single string that captures all
    payload-relevant HTTP fields.

    Format (newline-separated):
      {Method} {URL}
      {Method}
      {uri_path}
      {content-type}
      {User-Agent}
      {cookie}
      {body}
    """
    method       = str(row.get("Method", "") or "")
    url_field    = str(row.get("URL", "") or "")
    uri_path     = extract_uri_path(url_field)
    content_type = str(row.get("content-type", "") or "")
    user_agent   = str(row.get("User-Agent", "") or "")
    cookie       = str(row.get("cookie", "") or "")
    body         = str(row.get("content", "") or "")

    parts = [
        f"{method} {url_field}",
        method,
        uri_path,
        content_type,
        user_agent,
        cookie,
        body,
    ]
    return "\n".join(parts)

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("DL-WAF Preprocessing Pipeline")
    print("=" * 60)

    # 1. Load CSV
    print(f"\n[1/9] Loading CSV: {RAW_CSV}")
    df = pd.read_csv(RAW_CSV)
    df["content"] = df["content"].fillna("")
    print(f"      Loaded {len(df):,} rows | columns: {list(df.columns)}")

    # 2. Serialise requests
    print("\n[2/9] Serialising HTTP requests …")
    texts  = df.apply(serialize_row, axis=1).tolist()
    labels = df["classification"].astype(int).tolist()

    # 3. Build vocabulary (fixed; not corpus-dependent)
    print("\n[3/9] Building vocabulary (97 tokens) …")
    vocab = build_vocab()
    assert len(vocab) == VOCAB_SIZE, f"Expected 97 tokens, got {len(vocab)}"

    # 4. Tokenise
    print("\n[4/9] Tokenising sequences …")
    sequences = [tokenize(t, vocab) for t in texts]

    # 5. Sequence length statistics (before truncation)
    lengths = [len(s) for s in sequences]
    p95_len = int(np.percentile(lengths, 95))
    print(f"      Length stats  min={min(lengths):,}  "
          f"mean={int(np.mean(lengths)):,}  "
          f"p95={p95_len:,}  "
          f"max={max(lengths):,}")

    # 6. Pad / truncate to MAX_LEN
    print(f"\n[5/9] Padding / truncating to {MAX_LEN} …")
    X = np.array([pad_or_truncate(s, MAX_LEN) for s in sequences], dtype=np.int32)
    y = np.array(labels, dtype=np.float32)

    # 7. Stratified split  70 / 15 / 15
    print("\n[6/9] Stratified split 70 / 15 / 15 …")
    X_train, X_tmp, y_train, y_tmp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=42
    )

    print(f"      Train : {len(X_train):,} samples")
    print(f"      Val   : {len(X_val):,} samples")
    print(f"      Test  : {len(X_test):,} samples")

    # 8. Compute class weights from training set only
    print("\n[7/9] Computing class weights …")
    n_total  = len(y_train)
    n_neg    = int(np.sum(y_train == 0))
    n_pos    = int(np.sum(y_train == 1))
    w0 = n_total / (2.0 * n_neg)
    w1 = n_total / (2.0 * n_pos)
    class_weights = {"0": round(w0, 6), "1": round(w1, 6)}
    print(f"      class 0 weight = {w0:.4f}  |  class 1 weight = {w1:.4f}")

    # 9. Save outputs
    print("\n[8/9] Saving outputs to data/processed/ …")

    np.save(os.path.join(OUT_DIR, "X_train.npy"), X_train)
    np.save(os.path.join(OUT_DIR, "X_val.npy"),   X_val)
    np.save(os.path.join(OUT_DIR, "X_test.npy"),  X_test)
    np.save(os.path.join(OUT_DIR, "y_train.npy"), y_train)
    np.save(os.path.join(OUT_DIR, "y_val.npy"),   y_val)
    np.save(os.path.join(OUT_DIR, "y_test.npy"),  y_test)

    # vocab.json — strip <PAD> key; store char → index
    vocab_out = {k: v for k, v in vocab.items() if k != "<PAD>"}
    with open(os.path.join(OUT_DIR, "vocab.json"), "w") as f:
        json.dump(vocab_out, f)

    with open(os.path.join(OUT_DIR, "class_weights.json"), "w") as f:
        json.dump(class_weights, f, indent=2)

    # dataset_stats.json
    def class_dist(arr):
        return {"0": int(np.sum(arr == 0)), "1": int(np.sum(arr == 1))}

    stats = {
        "total_records": len(df),
        "splits": {
            "train": {"size": len(X_train), "class_dist": class_dist(y_train)},
            "val":   {"size": len(X_val),   "class_dist": class_dist(y_val)},
            "test":  {"size": len(X_test),  "class_dist": class_dist(y_test)},
        },
        "sequence_length": {
            "max_len":    MAX_LEN,
            "min_raw":    min(lengths),
            "mean_raw":   round(float(np.mean(lengths)), 1),
            "p95_raw":    p95_len,
            "max_raw":    max(lengths),
        },
        "vocab_size": VOCAB_SIZE,
        "class_weights": class_weights,
    }
    with open(os.path.join(OUT_DIR, "dataset_stats.json"), "w") as f:
        json.dump(stats, f, indent=2)

    # 10. Final summary
    print("\n[9/9] Summary")
    print("-" * 40)
    print(f"  Total records       : {len(df):,}")
    print(f"  Legitimate (0)      : {int(np.sum(y == 0)):,}")
    print(f"  Malicious  (1)      : {int(np.sum(y == 1)):,}")
    print(f"  Train / Val / Test  : {len(X_train):,} / {len(X_val):,} / {len(X_test):,}")
    print(f"  Sequence length     : min={min(lengths)} | mean={int(np.mean(lengths))} | p95={p95_len} | max={max(lengths)}")
    print(f"  Vocab size          : {VOCAB_SIZE}")
    print(f"  Class weights       : 0={w0:.4f}  1={w1:.4f}")
    print("-" * 40)
    print("\nAll outputs saved to data/processed/")
    print("  X_train.npy  X_val.npy  X_test.npy")
    print("  y_train.npy  y_val.npy  y_test.npy")
    print("  vocab.json   class_weights.json   dataset_stats.json")
    print("\nPreprocessing complete.")


if __name__ == "__main__":
    main()
