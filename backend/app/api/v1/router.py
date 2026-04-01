from fastapi import APIRouter

from app.api.v1 import auth, users, roles, permissions, access_requests, approvals, audit_logs

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(roles.router)
api_router.include_router(permissions.router)
api_router.include_router(access_requests.router)
api_router.include_router(approvals.router)
api_router.include_router(audit_logs.router)
