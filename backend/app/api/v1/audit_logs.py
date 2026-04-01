import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies import require_superuser
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit_log import AuditLogListResponse, AuditLogResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    actor_username: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(require_superuser),
):
    q = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)
    if actor_username:
        q = q.filter(AuditLog.actor_username.ilike(f"%{actor_username}%"))

    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/export")
def export_audit_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_superuser),
):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(10000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "actor_username", "action", "resource_type", "resource_id", "ip_address", "created_at"])
    for log in logs:
        writer.writerow([
            log.id, log.actor_username, log.action,
            log.resource_type, log.resource_id,
            log.ip_address, log.created_at.isoformat(),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


@router.get("/{log_id}", response_model=AuditLogResponse)
def get_audit_log(
    log_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_superuser),
):
    from app.core.exceptions import NotFoundError
    log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    if not log:
        raise NotFoundError(f"Audit log entry {log_id} not found")
    return log
