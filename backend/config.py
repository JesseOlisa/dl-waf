from pydantic_settings import BaseSettings
from pydantic import Field
import os

# Resolve .env against this file's location, not the current working directory.
# The WAF must be launched from the project root (model/vocab paths are relative
# to it), so a bare ".env" would never resolve to backend/.env.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_ENV_FILE = os.path.join(_BACKEND_DIR, ".env")


class Settings(BaseSettings):
    # Model
    model_path: str = Field(default="model/saved/lstm_best.keras")
    vocab_path: str = Field(default="data/processed/vocab.json")

    # Database
    db_path: str = Field(default="backend/waf.db")

    # Inference
    classification_threshold: float = Field(default=0.5)
    max_seq_len: int = Field(default=1024)

    # JWT
    jwt_secret: str = Field(default="change-me-in-production")
    jwt_algorithm: str = Field(default="HS256")
    token_expire_minutes: int = Field(default=60)

    # Admin credentials
    admin_username: str = Field(default="admin")
    admin_password_hash: str = Field(default="")

    # Upstream app to forward allowed requests to
    target_url: str = Field(default="http://localhost:8001")

    # WAF server
    waf_host: str = Field(default="0.0.0.0")
    waf_port: int = Field(default=8080)

    model_config = {
        "env_file": _ENV_FILE,
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "protected_namespaces": ("settings_",),
    }


settings = Settings()
