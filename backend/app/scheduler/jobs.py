import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from app.config import settings
from app.db.session import SessionLocal
from app.models.access_request import AccessRequest
from app.models.user import user_roles
from app.services import audit_service

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def expire_jit_access() -> None:
    """Find active JIT requests that have passed their expiry and remove the role grant."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        expired = (
            db.query(AccessRequest)
            .filter(AccessRequest.status == "active", AccessRequest.expires_at <= now)
            .all()
        )
        for req in expired:
            db.execute(
                user_roles.delete().where(
                    (user_roles.c.user_id == req.requester_id) &
                    (user_roles.c.role_id == req.role_id)
                )
            )
            req.status = "expired"
            db.flush()
            audit_service.log_event(
                db, action="access_request.expired", actor=None,
                resource_type="access_request", resource_id=str(req.id),
                new_value={"expired_at": now.isoformat()},
            )
        if expired:
            db.commit()
            logger.info("Expired %d JIT access request(s)", len(expired))
    except Exception:
        db.rollback()
        logger.exception("Error in expire_jit_access job")
    finally:
        db.close()


def start_scheduler() -> None:
    scheduler.add_job(
        expire_jit_access,
        trigger="interval",
        minutes=settings.JIT_EXPIRY_CHECK_INTERVAL_MINUTES,
        id="expire_jit_access",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler started (JIT expiry check every %dm)", settings.JIT_EXPIRY_CHECK_INTERVAL_MINUTES)


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
