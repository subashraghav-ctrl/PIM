import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, String, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base
from app.models.user import user_roles

# Association table for Role <-> Permission (many-to-many)
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
    Column("granted_at", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
)


class Role(Base):
    __tablename__ = "roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(500), nullable=True)
    risk_level = Column(String(20), nullable=False, default="medium")  # low|medium|high|critical
    is_system = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    users = relationship("User", secondary=user_roles, back_populates="roles", lazy="selectin")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles", lazy="selectin")
    access_requests = relationship("AccessRequest", back_populates="role")
