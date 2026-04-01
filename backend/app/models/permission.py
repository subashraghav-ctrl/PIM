import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base
from app.models.role import role_permissions


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("resource", "action", name="uq_resource_action"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), unique=True, nullable=False, index=True)  # e.g. "database:write"
    resource = Column(String(100), nullable=False)  # e.g. "database"
    action = Column(String(100), nullable=False)    # e.g. "write"
    description = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    roles = relationship("Role", secondary=role_permissions, back_populates="permissions", lazy="selectin")
