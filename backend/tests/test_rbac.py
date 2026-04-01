import pytest


def test_create_role(client, admin_token):
    resp = client.post(
        "/api/v1/roles",
        json={"name": "new-role", "description": "Test", "risk_level": "low"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "new-role"


def test_create_role_duplicate(client, admin_token, sample_role):
    resp = client.post(
        "/api/v1/roles",
        json={"name": "test-role", "description": "Dup"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409


def test_list_roles(client, admin_token, sample_role):
    resp = client.get("/api/v1/roles", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_create_permission(client, admin_token):
    resp = client.post(
        "/api/v1/permissions",
        json={"name": "db:write", "resource": "db", "action": "write"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "db:write"


def test_assign_permission_to_role(client, admin_token, sample_role, sample_permission):
    resp = client.post(
        f"/api/v1/roles/{sample_role.id}/permissions/{sample_permission.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    perm_names = [p["name"] for p in resp.json()["permissions"]]
    assert "test:read" in perm_names


def test_assign_role_to_user(client, db, admin_token, regular_user, sample_role):
    resp = client.post(
        f"/api/v1/users/{regular_user.id}/roles/{sample_role.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    role_names = [r["name"] for r in resp.json()["roles"]]
    assert "test-role" in role_names


def test_get_user_permissions(client, db, admin_token, regular_user, sample_role, sample_permission):
    # Assign permission to role, role to user
    client.post(
        f"/api/v1/roles/{sample_role.id}/permissions/{sample_permission.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(
        f"/api/v1/users/{regular_user.id}/roles/{sample_role.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    resp = client.get(
        f"/api/v1/users/{regular_user.id}/permissions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    perm_names = [p["name"] for p in resp.json()]
    assert "test:read" in perm_names


def test_regular_user_cannot_create_role(client, user_token):
    resp = client.post(
        "/api/v1/roles",
        json={"name": "hacker-role"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 403
