from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies import get_current_user, require_superuser
from app.models.user import User
from app.schemas.permission import PermissionCreate, PermissionResponse, PermissionUpdate
from app.services import permission_service

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.get("", response_model=List[PermissionResponse])
def list_permissions(
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return permission_service.list_permissions(db, skip=skip, limit=limit)


@router.post("", response_model=PermissionResponse, status_code=201)
def create_permission(
    data: PermissionCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return permission_service.create_permission(db, data, actor=actor)


@router.get("/{permission_id}", response_model=PermissionResponse)
def get_permission(
    permission_id: UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return permission_service.get_permission(db, permission_id)


@router.put("/{permission_id}", response_model=PermissionResponse)
def update_permission(
    permission_id: UUID,
    data: PermissionUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return permission_service.update_permission(db, permission_id, data, actor=actor)


@router.delete("/{permission_id}", status_code=204)
def delete_permission(
    permission_id: UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    permission_service.delete_permission(db, permission_id, actor=actor)
