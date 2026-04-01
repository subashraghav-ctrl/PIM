from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, field_validator


class AccessRequestCreate(BaseModel):
    role_id: UUID
    justification: str
    duration_hours: int

    @field_validator("duration_hours")
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if not (1 <= v <= 72):
            raise ValueError("duration_hours must be between 1 and 72")
        return v

    @field_validator("justification")
    @classmethod
    def justification_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Justification is required")
        return v.strip()


class ApprovalStepResponse(BaseModel):
    id: UUID
    step_order: int
    approver_id: UUID
    approver_username: Optional[str] = None
    status: str
    decided_at: Optional[datetime]
    decision_note: Optional[str]
    mfa_verified: bool

    model_config = {"from_attributes": True}


class AccessRequestResponse(BaseModel):
    id: UUID
    requester_id: UUID
    requester_username: Optional[str] = None
    role_id: UUID
    role_name: Optional[str] = None
    justification: str
    status: str
    duration_hours: int
    risk_level: str
    requested_at: datetime
    expires_at: Optional[datetime]
    approved_at: Optional[datetime]
    activated_at: Optional[datetime]
    revoked_at: Optional[datetime]
    approval_steps: List[ApprovalStepResponse] = []

    model_config = {"from_attributes": True}


class RevokeRequest(BaseModel):
    reason: Optional[str] = None
