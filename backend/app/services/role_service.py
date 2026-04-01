from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ConflictError, BadRequestError
from app.models.role import Role
from app.models.permission import Permission
from app.schemas.role import RoleCreate, RoleUpdate
from app.services import audit_service


VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}


def get_role(db: Session, role_id: UUID) -> Role:
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise NotFoundError(f"Role {role_id} not found")
    return role


def list_roles(db: Session, skip: int = 0, limit: int = 100) -> List[Role]:
    return db.query(Role).offset(skip).limit(limit).all()


def create_role(db: Session, data: RoleCreate, actor=None) -> Role:
    if data.risk_level not in VALID_RISK_LEVELS:
        raise BadRequestError(f"risk_level must be one of: {VALID_RISK_LEVELS}")
    if db.query(Role).filter(Role.name == data.name).first():
        raise ConflictError(f"Role '{data.name}' already exists")

    role = Role(name=data.name, description=data.description, risk_level=data.risk_level)
    db.add(role)
    db.flush()
    audit_service.log_event(
        db, action="role.created", actor=actor,
        resource_type="role", resource_id=str(role.id),
        new_value={"name": role.name, "risk_level": role.risk_level},
    )
    db.commit()
    db.refresh(role)
    return role


def update_role(db: Session, role_id: UUID, data: RoleUpdate, actor=None) -> Role:
    role = get_role(db, role_id)
    if role.is_system:
        raise BadRequestError("Cannot modify a system role")

    old = {"name": role.name, "description": role.description, "risk_level": role.risk_level}

    if data.name is not None:
        existing = db.query(Role).filter(Role.name == data.name, Role.id != role_id).first()
        if existing:
            raise ConflictError(f"Role '{data.name}' already exists")
        role.name = data.name
    if data.description is not None:
        role.description = data.description
    if data.risk_level is not None:
        if data.risk_level not in VALID_RISK_LEVELS:
            raise BadRequestError(f"risk_level must be one of: {VALID_RISK_LEVELS}")
        role.risk_level = data.risk_level

    db.flush()
    audit_service.log_event(
        db, action="role.updated", actor=actor,
        resource_type="role", resource_id=str(role.id),
        old_value=old, new_value={"name": role.name, "risk_level": role.risk_level},
    )
    db.commit()
    db.refresh(role)
    return role


def delete_role(db: Session, role_id: UUID, actor=None) -> None:
    role = get_role(db, role_id)
    if role.is_system:
        raise BadRequestError("Cannot delete a system role")
    audit_service.log_event(
        db, action="role.deleted", actor=actor,
        resource_type="role", resource_id=str(role.id),
        old_value={"name": role.name},
    )
    db.delete(role)
    db.commit()


def add_permission(db: Session, role_id: UUID, permission_id: UUID, actor=None) -> Role:
    role = get_role(db, role_id)
    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm:
        raise NotFoundError(f"Permission {permission_id} not found")
    if perm in role.permissions:
        raise ConflictError("Role already has this permission")

    role.permissions.append(perm)
    db.flush()
    audit_service.log_event(
        db, action="role.permission_added", actor=actor,
        resource_type="role", resource_id=str(role.id),
        new_value={"permission": perm.name},
    )
    db.commit()
    db.refresh(role)
    return role


def remove_permission(db: Session, role_id: UUID, permission_id: UUID, actor=None) -> Role:
    role = get_role(db, role_id)
    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm or perm not in role.permissions:
        raise BadRequestError("Role does not have this permission")

    role.permissions.remove(perm)
    db.flush()
    audit_service.log_event(
        db, action="role.permission_removed", actor=actor,
        resource_type="role", resource_id=str(role.id),
        old_value={"permission": perm.name},
    )
    db.commit()
    db.refresh(role)
    return role
