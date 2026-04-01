from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.permissions import get_effective_permissions
from app.db.session import get_db
from app.dependencies import get_current_user, require_superuser
from app.models.user import User
from app.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.services import user_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=List[UserListResponse])
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(require_superuser),
):
    return user_service.list_users(db, skip=skip, limit=limit)


@router.post("", response_model=UserResponse, status_code=201)
def create_user(
    data: UserCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return user_service.create_user(db, data, actor=actor)


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Users can view themselves; admins can view anyone
    if not current_user.is_superuser and current_user.id != user_id:
        from app.core.exceptions import ForbiddenError
        raise ForbiddenError()
    return user_service.get_user(db, user_id)


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: UUID,
    data: UserUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return user_service.update_user(db, user_id, data, actor=actor)


@router.delete("/{user_id}", response_model=UserResponse)
def deactivate_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return user_service.deactivate_user(db, user_id, actor=actor)


@router.post("/{user_id}/roles/{role_id}", response_model=UserResponse)
def assign_role(
    user_id: UUID,
    role_id: UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return user_service.assign_role(db, user_id, role_id, actor=actor)


@router.delete("/{user_id}/roles/{role_id}", response_model=UserResponse)
def remove_role(
    user_id: UUID,
    role_id: UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superuser),
):
    return user_service.remove_role(db, user_id, role_id, actor=actor)


@router.get("/{user_id}/permissions")
def get_permissions(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.is_superuser and current_user.id != user_id:
        from app.core.exceptions import ForbiddenError
        raise ForbiddenError()
    user = user_service.get_user(db, user_id)
    return get_effective_permissions(user)
