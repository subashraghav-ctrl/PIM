import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class ApprovalStep(Base):
    __tablename__ = "approval_steps"
    __table_args__ = (UniqueConstraint("request_id", "step_order", name="uq_request_step_order"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(UUID(as_uuid=True), ForeignKey("access_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    step_order = Column(Integer, nullable=False)
    approver_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    # pending | approved | denied
    status = Column(String(50), nullable=False, default="pending")
    decided_at = Column(DateTime(timezone=True), nullable=True)
    decision_note = Column(Text, nullable=True)
    mfa_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    access_request = relationship("AccessRequest", back_populates="approval_steps")
    approver = relationship("User", foreign_keys=[approver_id], back_populates="approval_steps")
