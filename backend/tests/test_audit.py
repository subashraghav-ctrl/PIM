import pytest


def test_audit_log_populated_on_user_create(client, db, admin_token):
    client.post(
        "/api/v1/users",
        json={"username": "audituser", "email": "audit@pim.test", "password": "TestPass123!"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    resp = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    actions = [e["action"] for e in resp.json()["items"]]
    assert "user.created" in actions


def test_audit_log_requires_admin(client, user_token):
    resp = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403


def test_audit_log_filter_by_action(client, db, admin_token):
    resp = client.get(
        "/api/v1/audit?action=user.created",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    for entry in resp.json()["items"]:
        assert "user.created" in entry["action"]


def test_audit_log_pagination(client, db, admin_token):
    resp = client.get(
        "/api/v1/audit?page=1&page_size=5",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["page"] == 1
    assert data["page_size"] == 5
    assert "total" in data
