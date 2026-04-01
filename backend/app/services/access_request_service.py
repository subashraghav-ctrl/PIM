from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, BadRequestError, ForbiddenError
from app.models.access_request import AccessRequest
from app.models.approval_step import ApprovalStep
from app.models.role import Role
from app.models.user import User, user_roles
from app.schemas.access_request import AccessRequestCreate
from app.services import audit_service

# Number of approvers required per risk level
APPROVERS_REQUIRED = {
    "low": 1,
    "medium": 1,
    "high": 2,
    "critical": 3,
}
MFA_REQUIRED_LEVELS = {"high", "critical"}


def _get_approvers_for_role(db: Session, role: Role, exclude_user_id: UUID) -> List[User]:
    """Return superusers who can approve this role, excluding the requester."""
    approvers = (
        db.query(User)
        .filter(User.is_superuser == True, User.is_active == True, User.id != exclude_user_id)
        .all()
    )
    return approvers


def create_request(
    db: Session,
    data: AccessRequestCreate,
    requester: User,
    ip_address: Optional[str] = None,
) -> AccessRequest:
    role = db.query(Role).filter(Role.id == data.role_id).first()
    if not role:
        raise NotFoundError(f"Role {data.role_id} not found")

    # Check for existing pending/active request for same role
    existing = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.requester_id == requester.id,
            AccessRequest.role_id == data.role_id,
            AccessRequest.status.in_(["pending", "active"]),
        )
        .first()
    )
    if existing:
        raise BadRequestError("You already have a pending or active request for this role")

    approvers = _get_approvers_for_role(db, role, exclude_user_id=requester.id)
    required_count = APPROVERS_REQUIRED.get(role.risk_level, 1)
    if len(approvers) < required_count:
        raise BadRequestError(
            f"Cannot create request: need {required_count} approver(s) for {role.risk_level} risk "
            f"but only {len(approvers)} eligible approver(s) exist"
        )

    req = AccessRequest(
        requester_id=requester.id,
        role_id=role.id,
        justification=data.justification,
        duration_hours=data.duration_hours,
        risk_level=role.risk_level,
        status="pending",
    )
    db.add(req)
    db.flush()

    # Create approval steps
    for i, approver in enumerate(approvers[:required_count], start=1):
        step = ApprovalStep(
            request_id=req.id,
            step_order=i,
            approver_id=approver.id,
            status="pending",
        )
        db.add(step)

    audit_service.log_event(
        db, action="access_request.created", actor=requester,
        resource_type="access_request", resource_id=str(req.id),
        new_value={"role": role.name, "duration_hours": data.duration_hours, "risk_level": role.risk_level},
        ip_address=ip_address,
    )
    db.commit()
    db.refresh(req)
    return req


def list_requests(
    db: Session,
    requester_id: Optional[UUID] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> List[AccessRequest]:
    q = db.query(AccessRequest)
    if requester_id:
        q = q.filter(AccessRequest.requester_id == requester_id)
    if status:
        q = q.filter(AccessRequest.status == status)
    return q.order_by(AccessRequest.requested_at.desc()).offset(skip).limit(limit).all()


def get_request(db: Session, request_id: UUID) -> AccessRequest:
    req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not req:
        raise NotFoundError(f"Access request {request_id} not found")
    return req


def cancel_request(db: Session, request_id: UUID, requester: User) -> AccessRequest:
    req = get_request(db, request_id)
    if req.requester_id != requester.id:
        raise ForbiddenError("You can only cancel your own requests")
    if req.status != "pending":
        raise BadRequestError(f"Cannot cancel a request with status '{req.status}'")

    req.status = "denied"
    db.flush()
    audit_service.log_event(
        db, action="access_request.cancelled", actor=requester,
        resource_type="access_request", resource_id=str(req.id),
    )
    db.commit()
    db.refresh(req)
    return req


def revoke_request(
    db: Session, request_id: UUID, revoker: User, reason: Optional[str] = None
) -> AccessRequest:
    req = get_request(db, request_id)
    if req.status != "active":
        raise BadRequestError(f"Can only revoke active access (current status: '{req.status}')")

    # Remove JIT role from user
    db.execute(
        user_roles.delete().where(
            (user_roles.c.user_id == req.requester_id) &
            (user_roles.c.role_id == req.role_id)
        )
    )
    req.status = "revoked"
    req.revoked_at = datetime.now(timezone.utc)
    req.revoked_by = revoker.id
    db.flush()
    audit_service.log_event(
        db, action="access_request.revoked", actor=revoker,
        resource_type="access_request", resource_id=str(req.id),
        new_value={"reason": reason},
    )
    db.commit()
    db.refresh(req)
    return req


def activate_request(db: Session, req: AccessRequest) -> AccessRequest:
    """Grant the role to the user and set expiry. Called after all steps are approved."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=req.duration_hours)

    # Assign JIT role
    db.execute(
        user_roles.insert().values(
            user_id=req.requester_id,
            role_id=req.role_id,
            assigned_by=None,
            assigned_at=now,
        )
    )
    req.status = "active"
    req.activated_at = now
    req.expires_at = expires_at
    db.flush()
    audit_service.log_event(
        db, action="access_request.activated", actor=None,
        resource_type="access_request", resource_id=str(req.id),
        new_value={"expires_at": expires_at.isoformat()},
    )
    db.commit()
    db.refresh(req)
    return req
