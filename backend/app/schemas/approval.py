from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class ApproveRequest(BaseModel):
    decision_note: Optional[str] = None
    totp_code: Optional[str] = None  # Required when risk_level is high or critical


class DenyRequest(BaseModel):
    decision_note: str


class PendingApprovalResponse(BaseModel):
    step_id: UUID
    step_order: int
    request_id: UUID
    requester_username: str
    role_name: str
    risk_level: str
    justification: str
    duration_hours: int
    requested_at: str

    model_config = {"from_attributes": True}
