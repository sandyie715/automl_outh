"""
security.py — Password hashing and JWT token utilities
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext

load_dotenv()

# ── Config ─────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
ALGORITHM = "HS256"
EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 10080))  # 7 days

# ── Password hashing ───────────────────────────────
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

BCRYPT_MAX_LENGTH = 72


def hash_password(password: str) -> str:
    """Hash password safely for bcrypt."""
    password = password[:BCRYPT_MAX_LENGTH]
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against stored hash."""
    password = password[:BCRYPT_MAX_LENGTH]
    return pwd_context.verify(password, hashed_password)


# ── JWT Token Utilities ────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()

    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=EXPIRE_MINUTES)
    )

    payload.update({"exp": expire})

    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """Return decoded token or None if invalid."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        return None