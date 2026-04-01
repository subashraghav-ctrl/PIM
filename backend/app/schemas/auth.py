from typing import Optional
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_session_token: Optional[str] = None


class MFASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_base64: str


class MFAVerifyRequest(BaseModel):
    totp_code: str
    mfa_session_token: Optional[str] = None  # required during login MFA step


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
