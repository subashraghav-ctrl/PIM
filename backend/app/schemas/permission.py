from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class PermissionBase(BaseModel):
    name: str
    resource: str
    action: str
    description: Optional[str] = None


class PermissionCreate(PermissionBase):
    pass


class PermissionUpdate(BaseModel):
    description: Optional[str] = None


class PermissionResponse(PermissionBase):
    id: UUID
    created_at: datetime

    model_config = {"from_attributes": True}
