from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ConflictError, BadRequestError
from app.models.permission import Permission
from app.models.role import role_permissions
from app.schemas.permission import PermissionCreate, PermissionUpdate
from app.services import audit_service


def get_permission(db: Session, permission_id: UUID) -> Permission:
    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm:
        raise NotFoundError(f"Permission {permission_id} not found")
    return perm


def list_permissions(db: Session, skip: int = 0, limit: int = 200) -> List[Permission]:
    return db.query(Permission).order_by(Permission.resource, Permission.action).offset(skip).limit(limit).all()


def create_permission(db: Session, data: PermissionCreate, actor=None) -> Permission:
    if db.query(Permission).filter(Permission.name == data.name).first():
        raise ConflictError(f"Permission '{data.name}' already exists")

    perm = Permission(
        name=data.name,
        resource=data.resource,
        action=data.action,
        description=data.description,
    )
    db.add(perm)
    db.flush()
    audit_service.log_event(
        db, action="permission.created", actor=actor,
        resource_type="permission", resource_id=str(perm.id),
        new_value={"name": perm.name, "resource": perm.resource, "action": perm.action},
    )
    db.commit()
    db.refresh(perm)
    return perm


def update_permission(db: Session, permission_id: UUID, data: PermissionUpdate, actor=None) -> Permission:
    perm = get_permission(db, permission_id)
    if data.description is not None:
        perm.description = data.description
    db.flush()
    audit_service.log_event(
        db, action="permission.updated", actor=actor,
        resource_type="permission", resource_id=str(perm.id),
    )
    db.commit()
    db.refresh(perm)
    return perm


def delete_permission(db: Session, permission_id: UUID, actor=None) -> None:
    perm = get_permission(db, permission_id)
    # Check if assigned to any role
    assigned = db.execute(
        role_permissions.select().where(role_permissions.c.permission_id == permission_id)
    ).first()
    if assigned:
        raise BadRequestError("Cannot delete permission that is assigned to one or more roles")

    audit_service.log_event(
        db, action="permission.deleted", actor=actor,
        resource_type="permission", resource_id=str(perm.id),
        old_value={"name": perm.name},
    )
    db.delete(perm)
    db.commit()
