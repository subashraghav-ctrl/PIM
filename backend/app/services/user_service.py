from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.core.mfa import generate_totp_secret, verify_totp, get_totp_uri, get_qr_code_base64
from app.core.exceptions import NotFoundError, ConflictError, BadRequestError
from app.models.user import User, user_roles
from app.models.role import Role
from app.schemas.user import UserCreate, UserUpdate
from app.services import audit_service


def get_user(db: Session, user_id: UUID) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise NotFoundError(f"User {user_id} not found")
    return user


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def list_users(db: Session, skip: int = 0, limit: int = 50) -> List[User]:
    return db.query(User).offset(skip).limit(limit).all()


def create_user(db: Session, data: UserCreate, actor: Optional[User] = None) -> User:
    if db.query(User).filter(User.username == data.username).first():
        raise ConflictError(f"Username '{data.username}' already exists")
    if db.query(User).filter(User.email == data.email).first():
        raise ConflictError(f"Email '{data.email}' already registered")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        is_active=data.is_active,
        is_superuser=data.is_superuser,
    )
    db.add(user)
    db.flush()
    audit_service.log_event(
        db, action="user.created", actor=actor,
        resource_type="user", resource_id=str(user.id),
        new_value={"username": user.username, "email": user.email},
    )
    db.commit()
    db.refresh(user)
    return user


def update_user(db: Session, user_id: UUID, data: UserUpdate, actor: Optional[User] = None) -> User:
    user = get_user(db, user_id)
    old = {"is_active": user.is_active, "is_superuser": user.is_superuser, "email": user.email}

    if data.email is not None:
        existing = db.query(User).filter(User.email == data.email, User.id != user_id).first()
        if existing:
            raise ConflictError(f"Email '{data.email}' already registered")
        user.email = data.email
    if data.is_active is not None:
        user.is_active = data.is_active
    if data.is_superuser is not None:
        user.is_superuser = data.is_superuser
    if data.password is not None:
        user.hashed_password = hash_password(data.password)

    db.flush()
    audit_service.log_event(
        db, action="user.updated", actor=actor,
        resource_type="user", resource_id=str(user.id),
        old_value=old, new_value={"is_active": user.is_active, "email": user.email},
    )
    db.commit()
    db.refresh(user)
    return user


def deactivate_user(db: Session, user_id: UUID, actor: Optional[User] = None) -> User:
    user = get_user(db, user_id)
    user.is_active = False
    db.flush()
    audit_service.log_event(
        db, action="user.deactivated", actor=actor,
        resource_type="user", resource_id=str(user.id),
    )
    db.commit()
    db.refresh(user)
    return user


def assign_role(db: Session, user_id: UUID, role_id: UUID, actor: Optional[User] = None) -> User:
    user = get_user(db, user_id)
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise NotFoundError(f"Role {role_id} not found")

    if role in user.roles:
        raise ConflictError(f"User already has role '{role.name}'")

    user.roles.append(role)
    db.flush()
    audit_service.log_event(
        db, action="user.role_assigned", actor=actor,
        resource_type="user", resource_id=str(user.id),
        new_value={"role_id": str(role.id), "role_name": role.name},
    )
    db.commit()
    db.refresh(user)
    return user


def remove_role(db: Session, user_id: UUID, role_id: UUID, actor: Optional[User] = None) -> User:
    user = get_user(db, user_id)
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise NotFoundError(f"Role {role_id} not found")

    if role not in user.roles:
        raise BadRequestError(f"User does not have role '{role.name}'")

    user.roles.remove(role)
    db.flush()
    audit_service.log_event(
        db, action="user.role_removed", actor=actor,
        resource_type="user", resource_id=str(user.id),
        old_value={"role_id": str(role.id), "role_name": role.name},
    )
    db.commit()
    db.refresh(user)
    return user


def setup_mfa(db: Session, user: User) -> dict:
    secret = generate_totp_secret()
    user.mfa_secret = secret
    db.commit()
    uri = get_totp_uri(secret, user.username)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_code_base64": get_qr_code_base64(uri),
    }


def enable_mfa(db: Session, user: User, totp_code: str) -> bool:
    if not user.mfa_secret:
        raise BadRequestError("MFA setup not initiated. Call /auth/mfa/setup first.")
    if not verify_totp(user.mfa_secret, totp_code):
        return False
    user.mfa_enabled = True
    db.commit()
    return True


def disable_mfa(db: Session, user_id: UUID, actor: Optional[User] = None) -> User:
    user = get_user(db, user_id)
    user.mfa_enabled = False
    user.mfa_secret = None
    db.flush()
    audit_service.log_event(
        db, action="user.mfa_disabled", actor=actor,
        resource_type="user", resource_id=str(user.id),
    )
    db.commit()
    db.refresh(user)
    return user
