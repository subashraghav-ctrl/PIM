import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.core.security import hash_password
from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission

SQLALCHEMY_TEST_URL = "sqlite:///./test_pim.db"

engine = create_engine(SQLALCHEMY_TEST_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def client(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_user(db):
    user = User(
        username="testadmin",
        email="testadmin@pim.test",
        hashed_password=hash_password("TestPass123!"),
        is_active=True,
        is_superuser=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def regular_user(db):
    user = User(
        username="testuser",
        email="testuser@pim.test",
        hashed_password=hash_password("TestPass123!"),
        is_active=True,
        is_superuser=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def admin_token(client, admin_user):
    resp = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "TestPass123!"})
    return resp.json()["access_token"]


@pytest.fixture()
def user_token(client, regular_user):
    resp = client.post("/api/v1/auth/login", json={"username": "testuser", "password": "TestPass123!"})
    return resp.json()["access_token"]


@pytest.fixture()
def sample_role(db):
    role = Role(name="test-role", description="Test role", risk_level="low")
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


@pytest.fixture()
def sample_permission(db):
    perm = Permission(name="test:read", resource="test", action="read", description="Test read")
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm
