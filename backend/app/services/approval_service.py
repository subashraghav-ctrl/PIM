from datetime import datetime, timezone
from typing import List
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ForbiddenError, BadRequestError
from app.core.mfa import verify_totp
from app.models.approval_step import ApprovalStep
from app.models.access_request import AccessRequest
from app.models.user import User
from app.services import audit_service
from app.services.access_request_service import activate_request, MFA_REQUIRED_LEVELS


def get_step(db: Session, step_id: UUID) -> ApprovalStep:
    step = db.query(ApprovalStep).filter(ApprovalStep.id == step_id).first()
    if not step:
        raise NotFoundError(f"Approval step {step_id} not found")
    return step


def list_pending_for_approver(db: Session, approver_id: UUID) -> List[ApprovalStep]:
    return (
        db.query(ApprovalStep)
        .join(AccessRequest, ApprovalStep.request_id == AccessRequest.id)
        .filter(
            ApprovalStep.approver_id == approver_id,
            ApprovalStep.status == "pending",
            AccessRequest.status == "pending",
        )
        .all()
    )


def approve_step(
    db: Session,
    step_id: UUID,
    approver: User,
    decision_note: str = None,
    totp_code: str = None,
) -> ApprovalStep:
    step = get_step(db, step_id)

    if step.approver_id != approver.id:
        raise ForbiddenError("You are not the designated approver for this step")
    if step.status != "pending":
        raise BadRequestError(f"Step is already '{step.status}'")

    req = step.access_request
    if req.status != "pending":
        raise BadRequestError(f"Request is no longer pending (status: '{req.status}')")

    # Prevent self-approval
    if req.requester_id == approver.id:
        raise ForbiddenError("You cannot approve your own access request")

    # MFA requirement for high/critical risk
    if req.risk_level in MFA_REQUIRED_LEVELS:
        if not totp_code:
            raise BadRequestError(
                f"TOTP code required to approve {req.risk_level} risk requests"
            )
        if not approver.mfa_secret or not verify_totp(approver.mfa_secret, totp_code):
            raise BadRequestError("Invalid TOTP code")
        step.mfa_verified = True

    step.status = "approved"
    step.decided_at = datetime.now(timezone.utc)
    step.decision_note = decision_note
    db.flush()

    audit_service.log_event(
        db, action="approval_step.approved", actor=approver,
        resource_type="access_request", resource_id=str(req.id),
        new_value={"step_order": step.step_order, "mfa_verified": step.mfa_verified},
    )

    # Check if ALL steps are now approved
    all_steps = db.query(ApprovalStep).filter(ApprovalStep.request_id == req.id).all()
    if all(s.status == "approved" for s in all_steps):
        req.approved_at = datetime.now(timezone.utc)
        db.flush()
        activate_request(db, req)
    else:
        db.commit()

    db.refresh(step)
    return step


def deny_step(
    db: Session,
    step_id: UUID,
    approver: User,
    decision_note: str,
) -> ApprovalStep:
    step = get_step(db, step_id)

    if step.approver_id != approver.id:
        raise ForbiddenError("You are not the designated approver for this step")
    if step.status != "pending":
        raise BadRequestError(f"Step is already '{step.status}'")

    req = step.access_request
    if req.status != "pending":
        raise BadRequestError(f"Request is no longer pending (status: '{req.status}')")

    step.status = "denied"
    step.decided_at = datetime.now(timezone.utc)
    step.decision_note = decision_note

    # Short-circuit: deny the entire request
    req.status = "denied"
    db.flush()

    audit_service.log_event(
        db, action="approval_step.denied", actor=approver,
        resource_type="access_request", resource_id=str(req.id),
        new_value={"step_order": step.step_order, "reason": decision_note},
    )
    db.commit()
    db.refresh(step)
    return step
