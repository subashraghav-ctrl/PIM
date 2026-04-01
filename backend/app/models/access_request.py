import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    requester_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False, index=True)
    justification = Column(Text, nullable=False)
    # pending | approved | denied | active | expired | revoked
    status = Column(String(50), nullable=False, default="pending", index=True)
    duration_hours = Column(Integer, nullable=False)  # 1-72
    risk_level = Column(String(20), nullable=False, default="medium")  # copied from role at request time
    requested_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    requester = relationship("User", foreign_keys=[requester_id], back_populates="access_requests")
    role = relationship("Role", back_populates="access_requests")
    approval_steps = relationship("ApprovalStep", back_populates="access_request", cascade="all, delete-orphan", order_by="ApprovalStep.step_order")
    revoker = relationship("User", foreign_keys=[revoked_by])
