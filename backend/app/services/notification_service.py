"""
Notification stubs. Wire up real SMTP or webhook logic here.
All functions are no-ops until configured.
"""
import logging
from app.config import settings

logger = logging.getLogger(__name__)


def notify_approver(approver_email: str, requester: str, role: str, request_id: str) -> None:
    if not settings.SMTP_HOST:
        logger.debug("SMTP not configured — skipping approval notification to %s", approver_email)
        return
    logger.info("TODO: send approval notification to %s for request %s", approver_email, request_id)


def notify_requester_approved(requester_email: str, role: str, expires_at: str) -> None:
    if not settings.SMTP_HOST:
        return
    logger.info("TODO: notify requester %s of approved access to %s", requester_email, role)


def notify_requester_denied(requester_email: str, role: str, reason: str) -> None:
    if not settings.SMTP_HOST:
        return
    logger.info("TODO: notify requester %s of denied access to %s", requester_email, role)


def notify_access_expired(user_email: str, role: str) -> None:
    if not settings.SMTP_HOST:
        return
    logger.info("TODO: notify %s that access to %s has expired", user_email, role)
