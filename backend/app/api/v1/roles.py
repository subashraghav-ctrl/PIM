from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies import get_current_user, require_superuser
from app.models.user import User
from app.schemas.role import RoleCreate, RoleListResponse, RoleResponse, RoleUpdate
from app.services import role_service

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("", response_model=List[RoleListResponse])
def list_roles(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return role_service.list_roles(db, skip=skip, limit=limit)


@router.post("", response_model=RoleResponse, status_code=201)
def create_role(
    data: RoleCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return role_service.create_role(db, data, actor=actor)


@router.get("/{role_id}", response_model=RoleResponse)
def get_role(
    role_id: UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return role_service.get_role(db, role_id)


@router.put("/{role_id}", response_model=RoleResponse)
def update_role(
    role_id: UUID,
    data: RoleUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return role_service.update_role(db, role_id, data, actor=actor)


@router.delete("/{role_id}", status_code=204)
def delete_role(
    role_id: UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    role_service.delete_role(db, role_id, actor=actor)


@router.post("/{role_id}/permissions/{permission_id}", response_model=RoleResponse)
def add_permission(
    role_id: UUID,
    permission_id: UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return role_service.add_permission(db, role_id, permission_id, actor=actor)


@router.delete("/{role_id}/permissions/{permission_id}", response_model=RoleResponse)
def remove_permission(
    role_id: UUID,
    permission_id: UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return role_service.remove_permission(db, role_id, permission_id, actor=actor)
