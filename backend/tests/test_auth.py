import pytest


def test_login_success(client, admin_user):
    resp = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "TestPass123!"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"] is not None
    assert data["mfa_required"] is False


def test_login_wrong_password(client, admin_user):
    resp = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "pass"})
    assert resp.status_code == 401


def test_me_authenticated(client, admin_token):
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "testadmin"


def test_me_unauthenticated(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_refresh_token(client, admin_user):
    login_resp = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "TestPass123!"})
    refresh_token = login_resp.json()["refresh_token"]
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert resp.json()["access_token"] is not None


def test_logout(client, admin_user):
    login_resp = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "TestPass123!"})
    refresh_token = login_resp.json()["refresh_token"]
    resp = client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
