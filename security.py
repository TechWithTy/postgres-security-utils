from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.db_utils.encryption import DataEncryptor
from app.core.redis.rate_limit import (
    get_remaining_limit,
    increment_rate_limit,
    service_rate_limit,
)

# Initialize encryptor - handles both encryption and password hashing
encryptor = DataEncryptor()

ALGORITHM = "HS256"  # Still needed for JWT signatures

# Rate limits (requests per minute)
TOKEN_CREATION_LIMIT = 30
PASSWORD_ATTEMPT_LIMIT = 10


def create_access_token(subject: str | Any, expires_delta: timedelta) -> str:
    """Rate limited token creation"""
    identifier = f"token_create:{subject}"
    if not service_rate_limit(identifier, TOKEN_CREATION_LIMIT, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Token creation rate limit exceeded",
        )

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    return jwt.encode(
        encryptor.encrypt(to_encode), settings.SECRET_KEY, algorithm=ALGORITHM
    )


def verify_password(plain_password: str, encrypted_hash: str, identifier: str) -> bool:
    """Rate limited password verification"""
    attempt_key = f"pwd_attempt:{identifier}"
    remaining = get_remaining_limit(attempt_key, "auth", PASSWORD_ATTEMPT_LIMIT)

    if remaining <= 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password attempts",
        )

    result = encryptor.verify_hash(plain_password, encrypted_hash)
    increment_rate_limit(attempt_key, "auth")
    return result


def get_password_hash(password: str) -> str:
    """Create password hash with encryption"""
    return encryptor.create_hash(password)
