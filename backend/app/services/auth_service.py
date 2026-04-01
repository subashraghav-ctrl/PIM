import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.security import (
    verify_password,
    create_access_token,
    create_mfa_session_token,
    create_refresh_token,
    hash_refresh_token,
    verify_token,
)
from app.core.mfa import verify_totp
from app.models.user import User
from app.services import audit_service


# In-memory refresh token store (replace with DB table in production)
# Structure: { hashed_token: {"user_id": str, "expires_at": datetime} }
_refresh_tokens: dict = {}


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = db.query(User).filter(
        (User.username == username) | (User.email == username)
    ).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user


def create_tokens_for_user(user: User) -> dict:
    access_token = create_access_token({
        "sub": str(user.id),
        "username": user.username,
        "is_superuser": user.is_superuser,
        "mfa_verified": not user.mfa_enabled,
    })
    raw_refresh, hashed_refresh = create_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    _refresh_tokens[hashed_refresh] = {
        "user_id": str(user.id),
        "expires_at": expires_at,
    }
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "token_type": "bearer",
        "mfa_required": False,
    }


def create_mfa_challenge(user: User) -> dict:
    mfa_session_token = create_mfa_session_token(str(user.id))
    return {
        "access_token": None,
        "refresh_token": None,
        "token_type": "bearer",
        "mfa_required": True,
        "mfa_session_token": mfa_session_token,
    }


def complete_mfa_login(db: Session, mfa_session_token: str, totp_code: str) -> Optional[dict]:
    payload = verify_token(mfa_session_token)
    if not payload or not payload.get("mfa_pending"):
        return None
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_secret:
        return None
    if not verify_totp(user.mfa_secret, totp_code):
        return None
    return create_tokens_for_user(user)


def refresh_access_token(db: Session, raw_refresh_token: str) -> Optional[str]:
    hashed = hash_refresh_token(raw_refresh_token)
    entry = _refresh_tokens.get(hashed)
    if not entry:
        return None
    if entry["expires_at"] < datetime.now(timezone.utc):
        del _refresh_tokens[hashed]
        return None
    user = db.query(User).filter(User.id == entry["user_id"]).first()
    if not user or not user.is_active:
        return None
    return create_access_token({
        "sub": str(user.id),
        "username": user.username,
        "is_superuser": user.is_superuser,
        "mfa_verified": True,
    })


def revoke_refresh_token(raw_refresh_token: str) -> None:
    hashed = hash_refresh_token(raw_refresh_token)
    _refresh_tokens.pop(hashed, None)
