from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.exceptions import UnauthorizedError, BadRequestError
from app.db.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.auth import (
    LoginRequest, LoginResponse, MFASetupResponse, MFAVerifyRequest,
    TokenRefreshRequest, TokenRefreshResponse,
)
from app.schemas.user import UserResponse
from app.services import auth_service, user_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = auth_service.authenticate_user(db, data.username, data.password)
    if not user:
        raise UnauthorizedError("Invalid credentials")

    if user.mfa_enabled:
        return auth_service.create_mfa_challenge(user)
    return auth_service.create_tokens_for_user(user)


@router.post("/mfa/setup", response_model=MFASetupResponse)
def mfa_setup(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.mfa_enabled:
        raise BadRequestError("MFA is already enabled. Disable it first.")
    return user_service.setup_mfa(db, current_user)


@router.post("/mfa/verify")
def mfa_verify(
    data: MFAVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verify TOTP to complete MFA enrollment (when called with valid access token)."""
    success = user_service.enable_mfa(db, current_user, data.totp_code)
    if not success:
        raise BadRequestError("Invalid TOTP code")
    return {"message": "MFA enabled successfully"}


@router.post("/mfa/login-verify", response_model=LoginResponse)
def mfa_login_verify(data: MFAVerifyRequest, db: Session = Depends(get_db)):
    """Complete MFA-gated login using the mfa_session_token."""
    if not data.mfa_session_token:
        raise BadRequestError("mfa_session_token is required")
    result = auth_service.complete_mfa_login(db, data.mfa_session_token, data.totp_code)
    if not result:
        raise UnauthorizedError("Invalid or expired MFA session token or TOTP code")
    return result


@router.post("/mfa/disable")
def mfa_disable(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Admin-only: disable MFA for a user."""
    from uuid import UUID
    if not current_user.is_superuser:
        raise BadRequestError("Superuser privileges required")
    user_service.disable_mfa(db, UUID(user_id), actor=current_user)
    return {"message": "MFA disabled"}


@router.post("/refresh", response_model=TokenRefreshResponse)
def refresh_token(data: TokenRefreshRequest, db: Session = Depends(get_db)):
    access_token = auth_service.refresh_access_token(db, data.refresh_token)
    if not access_token:
        raise UnauthorizedError("Invalid or expired refresh token")
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout")
def logout(data: TokenRefreshRequest):
    auth_service.revoke_refresh_token(data.refresh_token)
    return {"message": "Logged out"}


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user
