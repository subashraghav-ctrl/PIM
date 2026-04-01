from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.approval import ApproveRequest, DenyRequest, PendingApprovalResponse
from app.services import approval_service

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.get("/pending", response_model=List[PendingApprovalResponse])
def pending_approvals(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    steps = approval_service.list_pending_for_approver(db, approver_id=current_user.id)
    result = []
    for step in steps:
        req = step.access_request
        result.append(PendingApprovalResponse(
            step_id=step.id,
            step_order=step.step_order,
            request_id=req.id,
            requester_username=req.requester.username,
            role_name=req.role.name,
            risk_level=req.risk_level,
            justification=req.justification,
            duration_hours=req.duration_hours,
            requested_at=req.requested_at.isoformat(),
        ))
    return result


@router.post("/{step_id}/approve")
def approve(
    step_id: UUID,
    data: ApproveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    step = approval_service.approve_step(
        db, step_id, approver=current_user,
        decision_note=data.decision_note,
        totp_code=data.totp_code,
    )
    return {"message": "Step approved", "status": step.status, "request_status": step.access_request.status}


@router.post("/{step_id}/deny")
def deny(
    step_id: UUID,
    data: DenyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    step = approval_service.deny_step(
        db, step_id, approver=current_user, decision_note=data.decision_note
    )
    return {"message": "Request denied", "status": step.status, "request_status": step.access_request.status}
