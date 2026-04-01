from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy.orm import Session
from typing import Optional
import os

from app.config import settings
from app.db.session import get_db
from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.access_request import AccessRequest
from app.models.audit_log import AuditLog
from app.services import auth_service, user_service, access_request_service, approval_service
from app.services import audit_service as audit_svc
from app.schemas.approval import ApproveRequest, DenyRequest
from app.core.exceptions import BadRequestError

router = APIRouter(prefix="/admin", tags=["admin-ui"])

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

signer = URLSafeTimedSerializer(settings.ADMIN_SESSION_SECRET)
SESSION_COOKIE = "pim_admin_session"
CSRF_COOKIE = "pim_csrf"


def _set_session(response: Response, user_id: str) -> None:
    token = signer.dumps(user_id, salt="admin-session")
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=3600 * 8)


def _get_session_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        user_id = signer.loads(token, salt="admin-session", max_age=3600 * 8)
    except (BadSignature, SignatureExpired):
        return None
    return db.query(User).filter(User.id == user_id, User.is_active == True).first()


def _get_csrf_token(request: Request) -> str:
    token = request.cookies.get(CSRF_COOKIE)
    if token:
        try:
            signer.loads(token, salt="csrf", max_age=3600)
            return token
        except Exception:
            pass
    return signer.dumps("csrf", salt="csrf")


def _verify_csrf(request: Request, form_token: str) -> bool:
    try:
        signer.loads(form_token, salt="csrf", max_age=3600)
        return True
    except Exception:
        return False


def _require_admin(request: Request, db: Session) -> User:
    user = _get_session_user(request, db)
    if not user or not user.is_superuser:
        raise RedirectResponse("/admin/login", status_code=302)
    return user


# ── Login ──────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = auth_service.authenticate_user(db, username, password)
    if not user or not user.is_superuser:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid credentials or insufficient privileges"},
            status_code=401,
        )
    response = RedirectResponse("/admin/", status_code=302)
    _set_session(response, str(user.id))
    return response


@router.get("/logout")
def logout(response: Response):
    response = RedirectResponse("/admin/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    admin = _require_admin(request, db)
    stats = {
        "users": db.query(User).count(),
        "active_users": db.query(User).filter(User.is_active == True).count(),
        "roles": db.query(Role).count(),
        "permissions": db.query(Permission).count(),
        "pending_requests": db.query(AccessRequest).filter(AccessRequest.status == "pending").count(),
        "active_jit": db.query(AccessRequest).filter(AccessRequest.status == "active").count(),
        "audit_entries": db.query(AuditLog).count(),
    }
    return templates.TemplateResponse("dashboard.html", {"request": request, "admin": admin, "stats": stats})


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/users", response_class=HTMLResponse)
def users_list(request: Request, db: Session = Depends(get_db)):
    admin = _require_admin(request, db)
    users = db.query(User).order_by(User.created_at.desc()).limit(200).all()
    roles = db.query(Role).all()
    csrf = _get_csrf_token(request)
    resp = templates.TemplateResponse("users/list.html", {
        "request": request, "admin": admin, "users": users, "roles": roles, "csrf": csrf,
    })
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="lax")
    return resp


@router.post("/users")
def create_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    is_superuser: bool = Form(False),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    admin = _require_admin(request, db)
    if not _verify_csrf(request, csrf):
        return RedirectResponse("/admin/users?error=csrf", status_code=302)
    from app.schemas.user import UserCreate
    try:
        user_service.create_user(db, UserCreate(username=username, email=email, password=password, is_superuser=is_superuser), actor=admin)
    except Exception as e:
        return RedirectResponse(f"/admin/users?error={str(e)}", status_code=302)
    return RedirectResponse("/admin/users", status_code=302)


@router.post("/users/{user_id}/deactivate")
def deactivate_user(request: Request, user_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    admin = _require_admin(request, db)
    if not _verify_csrf(request, csrf):
        return RedirectResponse("/admin/users?error=csrf", status_code=302)
    from uuid import UUID
    user_service.deactivate_user(db, UUID(user_id), actor=admin)
    return RedirectResponse("/admin/users", status_code=302)


# ── Roles ─────────────────────────────────────────────────────────────────────

@router.get("/roles", response_class=HTMLResponse)
def roles_list(request: Request, db: Session = Depends(get_db)):
    admin = _require_admin(request, db)
    roles = db.query(Role).order_by(Role.name).all()
    permissions = db.query(Permission).order_by(Permission.resource, Permission.action).all()
    csrf = _get_csrf_token(request)
    resp = templates.TemplateResponse("roles/list.html", {
        "request": request, "admin": admin, "roles": roles, "permissions": permissions, "csrf": csrf,
    })
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="lax")
    return resp


@router.post("/roles")
def create_role(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    risk_level: str = Form("medium"),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    admin = _require_admin(request, db)
    if not _verify_csrf(request, csrf):
        return RedirectResponse("/admin/roles?error=csrf", status_code=302)
    from app.schemas.role import RoleCreate
    from app.services import role_service
    try:
        role_service.create_role(db, RoleCreate(name=name, description=description, risk_level=risk_level), actor=admin)
    except Exception as e:
        return RedirectResponse(f"/admin/roles?error={str(e)}", status_code=302)
    return RedirectResponse("/admin/roles", status_code=302)


# ── Access Requests ───────────────────────────────────────────────────────────

@router.get("/requests", response_class=HTMLResponse)
def requests_list(request: Request, status: str = None, db: Session = Depends(get_db)):
    admin = _require_admin(request, db)
    q = db.query(AccessRequest).order_by(AccessRequest.requested_at.desc())
    if status:
        q = q.filter(AccessRequest.status == status)
    reqs = q.limit(200).all()
    csrf = _get_csrf_token(request)
    resp = templates.TemplateResponse("requests/list.html", {
        "request": request, "admin": admin, "reqs": reqs, "csrf": csrf, "filter_status": status,
    })
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="lax")
    return resp


@router.post("/requests/{request_id}/approve-step/{step_id}")
def approve_step(
    request: Request,
    request_id: str,
    step_id: str,
    csrf: str = Form(...),
    totp_code: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _require_admin(request, db)
    if not _verify_csrf(request, csrf):
        return RedirectResponse("/admin/requests?error=csrf", status_code=302)
    from uuid import UUID
    try:
        approval_service.approve_step(
            db, UUID(step_id), approver=admin,
            totp_code=totp_code or None,
        )
    except Exception as e:
        return RedirectResponse(f"/admin/requests?error={str(e)}", status_code=302)
    return RedirectResponse("/admin/requests", status_code=302)


@router.post("/requests/{request_id}/deny-step/{step_id}")
def deny_step(
    request: Request,
    request_id: str,
    step_id: str,
    csrf: str = Form(...),
    decision_note: str = Form("Denied via admin UI"),
    db: Session = Depends(get_db),
):
    admin = _require_admin(request, db)
    if not _verify_csrf(request, csrf):
        return RedirectResponse("/admin/requests?error=csrf", status_code=302)
    from uuid import UUID
    try:
        approval_service.deny_step(db, UUID(step_id), approver=admin, decision_note=decision_note)
    except Exception as e:
        return RedirectResponse(f"/admin/requests?error={str(e)}", status_code=302)
    return RedirectResponse("/admin/requests", status_code=302)


# ── Audit Log ─────────────────────────────────────────────────────────────────

@router.get("/audit", response_class=HTMLResponse)
def audit_list(
    request: Request,
    action: str = None,
    resource_type: str = None,
    page: int = 1,
    db: Session = Depends(get_db),
):
    admin = _require_admin(request, db)
    PAGE_SIZE = 50
    q = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)
    total = q.count()
    logs = q.offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE).all()
    return templates.TemplateResponse("audit/list.html", {
        "request": request, "admin": admin, "logs": logs,
        "total": total, "page": page, "page_size": PAGE_SIZE,
        "filter_action": action, "filter_resource": resource_type,
    })
