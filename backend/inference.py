import json
import logging
import os
from urllib.parse import urlparse
from typing import Optional

# Suppress TensorFlow C++ logs (oneDNN info, CPU feature notices, GPU warnings)
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

import numpy as np

from backend.config import settings

logger = logging.getLogger(__name__)

# Module-level singletons — populated once at startup
_model = None
_vocab: dict[str, int] = {}


def load_model_and_vocab() -> None:
    global _model, _vocab

    import tensorflow as tf

    logger.info("Loading model from %s …", settings.model_path)
    _model = tf.keras.models.load_model(settings.model_path)
    logger.info("Model loaded — input shape: %s", _model.input_shape)

    with open(settings.vocab_path, "r", encoding="utf-8") as f:
        _vocab = json.load(f)
    logger.info("Vocabulary loaded — %d tokens", len(_vocab))
    print(f"[Inference] Model and vocab ready ({len(_vocab)} tokens)")


def _extract_uri_path(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def _serialize(method: str, url: str, headers: dict, body: str) -> str:
    uri_path = _extract_uri_path(url)
    content_type = headers.get("content-type", "") or ""
    user_agent = headers.get("user-agent", "") or ""
    cookie = headers.get("cookie", "") or ""
    parts = [
        f"{method} {url}",
        method,
        uri_path,
        content_type,
        user_agent,
        cookie,
        body,
    ]
    return "\n".join(parts)


def _tokenize_and_pad(text: str) -> np.ndarray:
    tokens = [_vocab.get(ch, 0) for ch in text]
    max_len = settings.max_seq_len
    if len(tokens) >= max_len:
        tokens = tokens[:max_len]
    else:
        tokens = tokens + [0] * (max_len - len(tokens))
    return np.array([tokens], dtype=np.int32)


def classify(
    method: str,
    url: str,
    headers: dict,
    body: str,
) -> tuple[int, float]:
    """Return (label, confidence_score). Fail-open: returns (0, 0.0) on error."""
    if _model is None:
        logger.error("Model not loaded — failing open")
        return 0, 0.0

    try:
        text = _serialize(method, url, headers, body)
        x = _tokenize_and_pad(text)
        prob = float(_model.predict(x, verbose=0)[0][0])
        label = 1 if prob >= settings.classification_threshold else 0
        return label, round(prob, 6)
    except Exception as exc:
        logger.error("Inference error — failing open: %s", exc)
        return 0, 0.0


def get_payload_fragment(method: str, url: str, headers: dict, body: str) -> str:
    text = _serialize(method, url, headers, body)
    return text[:200]
