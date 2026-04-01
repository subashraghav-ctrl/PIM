from datetime import datetime, timezone
from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_actor_created", "actor_id", "created_at"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_action_created", "action", "created_at"),
        Index("ix_audit_logs_created_desc", "created_at"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    actor_username = Column(String(150), nullable=True)  # denormalized for historical accuracy
    action = Column(String(100), nullable=False, index=True)  # e.g. "user.created", "request.approved"
    resource_type = Column(String(100), nullable=True)        # e.g. "user", "role", "access_request"
    resource_id = Column(Text, nullable=True)                 # ID of affected entity
    old_value = Column(JSONB, nullable=True)
    new_value = Column(JSONB, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    actor = relationship("User", foreign_keys=[actor_id])
