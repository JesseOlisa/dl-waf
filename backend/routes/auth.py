import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, status
from jose import jwt
from passlib.context import CryptContext
from passlib.exc import UnknownHashError

from backend.config import settings
from backend.schemas import LoginRequest, TokenResponse

logger = logging.getLogger(__name__)

router = APIRouter()
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.token_expire_minutes)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    if not settings.admin_password_hash:
        # No credential configured — refuse rather than fall back to a default.
        logger.error(
            "ADMIN_PASSWORD_HASH is not set — rejecting all logins. "
            "Generate a hash and add it to backend/.env."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured",
        )

    username_ok = body.username == settings.admin_username

    try:
        password_ok = _pwd_ctx.verify(body.password, settings.admin_password_hash)
    except (ValueError, UnknownHashError):
        # Malformed hash in config — treat as a failed login, not a 500.
        logger.error("ADMIN_PASSWORD_HASH is malformed — rejecting login.")
        password_ok = False

    if not username_ok or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    return TokenResponse(access_token=_create_token(body.username))
