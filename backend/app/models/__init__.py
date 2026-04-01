# Import all models so Alembic can detect them for autogenerate
from app.models.user import User, user_roles
from app.models.role import Role, role_permissions
from app.models.permission import Permission
from app.models.access_request import AccessRequest
from app.models.approval_step import ApprovalStep
from app.models.audit_log import AuditLog

__all__ = [
    "User",
    "user_roles",
    "Role",
    "role_permissions",
    "Permission",
    "AccessRequest",
    "ApprovalStep",
    "AuditLog",
]
