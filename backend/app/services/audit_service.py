from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.user import User


def log_event(
    db: Session,
    action: str,
    actor: Optional[User] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    old_value: Optional[Dict[str, Any]] = None,
    new_value: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else "system",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        old_value=old_value,
        new_value=new_value,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(entry)
    # Flush (not commit) — caller controls transaction
    db.flush()
    return entry
