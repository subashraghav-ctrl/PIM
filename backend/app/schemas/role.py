from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel


class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None
    risk_level: str = "medium"


class RoleCreate(RoleBase):
    pass


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    risk_level: Optional[str] = None


class RoleResponse(RoleBase):
    id: UUID
    is_system: bool
    created_at: datetime
    permissions: List["PermissionResponse"] = []

    model_config = {"from_attributes": True}


class RoleListResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    risk_level: str
    is_system: bool
    created_at: datetime

    model_config = {"from_attributes": True}


from app.schemas.permission import PermissionResponse  # noqa: E402
RoleResponse.model_rebuild()
