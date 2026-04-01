from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, EmailStr, field_validator


class UserBase(BaseModel):
    username: str
    email: EmailStr
    is_active: bool = True
    is_superuser: bool = False


class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    password: Optional[str] = None


class UserResponse(UserBase):
    id: UUID
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime
    roles: List["RoleResponse"] = []

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    id: UUID
    username: str
    email: str
    is_active: bool
    is_superuser: bool
    mfa_enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# Forward reference resolved below
from app.schemas.role import RoleResponse  # noqa: E402
UserResponse.model_rebuild()
