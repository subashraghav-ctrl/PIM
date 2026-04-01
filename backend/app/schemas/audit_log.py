from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: int
    actor_id: Optional[str] = None
    actor_username: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
