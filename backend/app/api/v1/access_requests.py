from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies import get_current_user, require_superuser, get_client_ip
from app.models.user import User
from app.schemas.access_request import AccessRequestCreate, AccessRequestResponse, RevokeRequest
from app.services import access_request_service

router = APIRouter(prefix="/access-requests", tags=["access-requests"])


@router.get("", response_model=List[AccessRequestResponse])
def list_requests(
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Admins see all; regular users see only their own
    requester_id = None if current_user.is_superuser else current_user.id
    items = access_request_service.list_requests(
        db, requester_id=requester_id, status=status, skip=skip, limit=limit
    )
    return _enrich(items)


@router.post("", response_model=AccessRequestResponse, status_code=201)
def create_request(
    data: AccessRequestCreate,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ip = get_client_ip(request) if request else None
    req = access_request_service.create_request(db, data, requester=current_user, ip_address=ip)
    return _enrich_one(req)


@router.get("/{request_id}", response_model=AccessRequestResponse)
def get_request(
    request_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    req = access_request_service.get_request(db, request_id)
    if not current_user.is_superuser and req.requester_id != current_user.id:
        from app.core.exceptions import ForbiddenError
        raise ForbiddenError()
    return _enrich_one(req)


@router.delete("/{request_id}", response_model=AccessRequestResponse)
def cancel_request(
    request_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    req = access_request_service.cancel_request(db, request_id, requester=current_user)
    return _enrich_one(req)


@router.post("/{request_id}/revoke", response_model=AccessRequestResponse)
def revoke_request(
    request_id: UUID,
    data: RevokeRequest = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    reason = data.reason if data else None
    req = access_request_service.revoke_request(db, request_id, revoker=current_user, reason=reason)
    return _enrich_one(req)


def _enrich_one(req) -> dict:
    data = AccessRequestResponse.model_validate(req).model_dump()
    data["requester_username"] = req.requester.username if req.requester else None
    data["role_name"] = req.role.name if req.role else None
    for step_data, step in zip(data["approval_steps"], req.approval_steps):
        step_data["approver_username"] = step.approver.username if step.approver else None
    return data


def _enrich(items) -> list:
    return [_enrich_one(r) for r in items]
