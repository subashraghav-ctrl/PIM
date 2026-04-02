import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, String, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base

# Association table for User <-> Role (many-to-many)
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("assigned_by", UUID(as_uuid=True), ForeignKey("users.id"), nullable=True),
    Column("assigned_at", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
)


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(150), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(128), nullable=True)  # encrypted via sqlalchemy-utils
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    roles = relationship(
        "Role",
        secondary=user_roles,
        primaryjoin=lambda: User.id == user_roles.c.user_id,
        secondaryjoin="Role.id == user_roles.c.role_id",
        back_populates="users",
        lazy="selectin",
    )
    access_requests = relationship("AccessRequest", foreign_keys="AccessRequest.requester_id", back_populates="requester")
    approval_steps = relationship("ApprovalStep", foreign_keys="ApprovalStep.approver_id", back_populates="approver")
