#!/usr/bin/env python3
"""
Seed the database with an initial admin user and base system roles/permissions.

Usage (inside Docker):
  docker compose exec app python scripts/seed_db.py
"""
from app.db.session import SessionLocal
from app.db.base import Base
from app.db.session import engine
from app.models import User, Role, Permission  # registers all models

from app.core.security import hash_password


def seed():
    # Create all tables if they don't exist (for dev convenience)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # ── Admin user ────────────────────────────────────────────────────────
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@pim.internal",
                hashed_password=hash_password("AdminPass123!"),
                is_active=True,
                is_superuser=True,
            )
            db.add(admin)
            db.flush()
            print("Created admin user: admin / AdminPass123!")
        else:
            print("Admin user already exists, skipping.")

        # ── System roles ──────────────────────────────────────────────────────
        system_roles = [
            {"name": "db-reader", "description": "Read-only database access", "risk_level": "low"},
            {"name": "db-admin", "description": "Full database administration", "risk_level": "critical"},
            {"name": "server-ssh", "description": "SSH access to production servers", "risk_level": "high"},
            {"name": "k8s-view", "description": "Kubernetes read-only access", "risk_level": "low"},
            {"name": "k8s-admin", "description": "Kubernetes cluster administration", "risk_level": "critical"},
            {"name": "network-admin", "description": "Network device administration", "risk_level": "high"},
        ]
        for role_data in system_roles:
            if not db.query(Role).filter(Role.name == role_data["name"]).first():
                role = Role(**role_data, is_system=True)
                db.add(role)
                print(f"Created system role: {role_data['name']}")

        # ── Sample permissions ────────────────────────────────────────────────
        sample_permissions = [
            {"name": "database:read", "resource": "database", "action": "read", "description": "Read database records"},
            {"name": "database:write", "resource": "database", "action": "write", "description": "Write database records"},
            {"name": "database:admin", "resource": "database", "action": "admin", "description": "Full database admin"},
            {"name": "server:ssh", "resource": "server", "action": "ssh", "description": "SSH access"},
            {"name": "kubernetes:read", "resource": "kubernetes", "action": "read", "description": "Read k8s resources"},
            {"name": "kubernetes:admin", "resource": "kubernetes", "action": "admin", "description": "Full k8s access"},
            {"name": "network:read", "resource": "network", "action": "read", "description": "View network config"},
            {"name": "network:admin", "resource": "network", "action": "admin", "description": "Manage network devices"},
        ]
        for perm_data in sample_permissions:
            if not db.query(Permission).filter(Permission.name == perm_data["name"]).first():
                perm = Permission(**perm_data)
                db.add(perm)
                print(f"Created permission: {perm_data['name']}")

        db.commit()
        print("\nSeed complete.")
        print("Admin credentials: admin / AdminPass123!")
        print("Change the admin password immediately in production!")

    except Exception as e:
        db.rollback()
        print(f"Error during seeding: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
