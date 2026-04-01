from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Database
    DATABASE_URL: str

    # Security
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # MFA
    MFA_ISSUER_NAME: str = "PIM-System"

    # Admin UI
    ADMIN_SESSION_SECRET: str

    # Application
    DEBUG: bool = False
    ALLOWED_ORIGINS: List[str] = ["http://localhost:8000"]

    # Scheduler
    JIT_EXPIRY_CHECK_INTERVAL_MINUTES: int = 5
    AUDIT_LOG_RETENTION_DAYS: int = 365

    # Notifications
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    NOTIFICATION_FROM_EMAIL: str = "noreply@pim.internal"

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_be_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("ADMIN_SESSION_SECRET")
    @classmethod
    def admin_secret_must_be_strong(cls, v: str) -> str:
        if len(v) < 16:
            raise ValueError("ADMIN_SESSION_SECRET must be at least 16 characters")
        return v


settings = Settings()
