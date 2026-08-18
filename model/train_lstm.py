"""
Phase 2 — LSTM Model Training
Trains a character-level LSTM on the preprocessed CSIC 2010 dataset.
Outputs: model/saved/lstm_best.keras + model/results/lstm_*.json/png
"""

import os
import json
import time
import numpy as np
import matplotlib
matplotlib.use("Agg")           # headless — no display needed
import matplotlib.pyplot as plt

os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"   # suppress oneDNN noise

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dropout, Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import (
    EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
)
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC_DIR    = os.path.join(BASE_DIR, "data", "processed")
SAVED_DIR   = os.path.join(BASE_DIR, "model", "saved")
RESULTS_DIR = os.path.join(BASE_DIR, "model", "results")
os.makedirs(SAVED_DIR,   exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

MODEL_PATH  = os.path.join(SAVED_DIR,   "lstm_best.keras")

# ── Hyper-parameters (fixed by thesis spec) ────────────────────────────────────
VOCAB_SIZE  = 97
EMBED_DIM   = 64
MAX_LEN     = 1024
BATCH_SIZE  = 64
MAX_EPOCHS  = 50
THRESHOLD   = 0.5


def load_data():
    print("[1/6] Loading preprocessed arrays …")
    X_train = np.load(os.path.join(PROC_DIR, "X_train.npy")).astype(np.int32)
    X_val   = np.load(os.path.join(PROC_DIR, "X_val.npy")).astype(np.int32)
    X_test  = np.load(os.path.join(PROC_DIR, "X_test.npy")).astype(np.int32)
    y_train = np.load(os.path.join(PROC_DIR, "y_train.npy")).astype(np.float32)
    y_val   = np.load(os.path.join(PROC_DIR, "y_val.npy")).astype(np.float32)
    y_test  = np.load(os.path.join(PROC_DIR, "y_test.npy")).astype(np.float32)

    with open(os.path.join(PROC_DIR, "class_weights.json")) as f:
        cw = json.load(f)
    class_weights = {0: cw["0"], 1: cw["1"]}

    print(f"      Train={len(X_train):,}  Val={len(X_val):,}  Test={len(X_test):,}")
    return X_train, X_val, X_test, y_train, y_val, y_test, class_weights


def build_model():
    print("\n[2/6] Building LSTM model …")
    model = Sequential([
        Embedding(input_dim=VOCAB_SIZE, output_dim=EMBED_DIM,
                  input_length=MAX_LEN, mask_zero=True),
        LSTM(128, return_sequences=True),
        Dropout(0.3),
        LSTM(64, return_sequences=False),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dense(1,  activation="sigmoid"),
    ])
    model.compile(
        optimizer=Adam(learning_rate=0.001, clipnorm=1.0),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    model.summary()
    return model


def train(model, X_train, y_train, X_val, y_val, class_weights):
    print("\n[3/6] Training …")
    callbacks = [
        EarlyStopping(
            monitor="val_loss", patience=8,
            restore_best_weights=True, verbose=1
        ),
        ReduceLROnPlateau(
            monitor="val_loss", factor=0.5,
            patience=3, verbose=1
        ),
        ModelCheckpoint(
            MODEL_PATH, monitor="val_loss",
            save_best_only=True, verbose=1
        ),
    ]
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=MAX_EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weights,
        callbacks=callbacks,
        verbose=1,
    )
    return history


def save_training_artifacts(history):
    print("\n[4/6] Saving training history and plots …")

    hist_dict = {k: [float(v) for v in vals]
                 for k, vals in history.history.items()}
    with open(os.path.join(RESULTS_DIR, "lstm_training_history.json"), "w") as f:
        json.dump(hist_dict, f, indent=2)

    epochs = range(1, len(hist_dict["loss"]) + 1)
    plt.figure(figsize=(9, 5))
    plt.plot(epochs, hist_dict["loss"],     label="Train Loss",      color="steelblue")
    plt.plot(epochs, hist_dict["val_loss"], label="Validation Loss", color="tomato")
    plt.xlabel("Epoch")
    plt.ylabel("Loss")
    plt.title("LSTM — Training vs Validation Loss")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "lstm_train_curve.png"), dpi=150)
    plt.close()
    print("      Saved lstm_training_history.json  lstm_train_curve.png")


def evaluate(model, X_test, y_test):
    print("\n[5/6] Evaluating on test set …")
    y_prob = model.predict(X_test, batch_size=BATCH_SIZE, verbose=1).flatten()
    y_pred = (y_prob >= THRESHOLD).astype(int)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Malicious"]))
    print(f"  Confusion Matrix:\n{cm}")
    print(f"\n  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1-Score  : {f1:.4f}")
    print(f"  FPR       : {fpr:.4f}")

    # Confusion matrix plot
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.colorbar(im, ax=ax)
    classes = ["Legitimate", "Malicious"]
    tick_marks = [0, 1]
    ax.set_xticks(tick_marks); ax.set_xticklabels(classes)
    ax.set_yticks(tick_marks); ax.set_yticklabels(classes)
    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
    ax.set_ylabel("True label")
    ax.set_xlabel("Predicted label")
    ax.set_title("LSTM — Confusion Matrix")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "lstm_confusion_matrix.png"), dpi=150)
    plt.close()

    metrics = {
        "model": "lstm",
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
    with open(os.path.join(RESULTS_DIR, "lstm_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("\n      Saved lstm_metrics.json  lstm_confusion_matrix.png")
    return metrics


def main():
    print("=" * 60)
    print("DL-WAF — LSTM Training")
    print("=" * 60)

    X_train, X_val, X_test, y_train, y_val, y_test, class_weights = load_data()
    model   = build_model()
    history = train(model, X_train, y_train, X_val, y_val, class_weights)
    save_training_artifacts(history)
    metrics = evaluate(model, X_test, y_test)

    print("\n[6/6] Done.")
    print(f"      Best model saved to : {MODEL_PATH}")
    print(f"      F1-Score            : {metrics['f1_score']:.4f}")
    print(f"      False Positive Rate : {metrics['false_positive_rate']:.4f}")


if __name__ == "__main__":
    main()
