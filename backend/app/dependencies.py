from typing import Generator, Optional

from fastapi import Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.exceptions import UnauthorizedError, ForbiddenError
from app.core.security import verify_token
from app.db.session import get_db
from app.models.user import User

security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise UnauthorizedError("Missing authentication token")

    payload = verify_token(credentials.credentials)
    if not payload:
        raise UnauthorizedError("Invalid or expired token")
    if payload.get("type") != "access":
        raise UnauthorizedError("Invalid token type")
    if payload.get("mfa_pending"):
        raise UnauthorizedError("MFA verification required")

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise UnauthorizedError("User not found or inactive")
    return user


def require_superuser(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_superuser:
        raise ForbiddenError("Superuser privileges required")
    return current_user


def get_client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
