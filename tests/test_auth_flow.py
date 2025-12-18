from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from jarvis_auth.app.main import app
from jarvis_auth.app.api.deps import get_db
from jarvis_auth.app.db.base import Base

SQLALCHEMY_DATABASE_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session() -> Session:
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db_session: Session) -> TestClient:
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def register_user(client: TestClient, email: str = "user@example.com", username: str = "user1", password: str = "password123"):
    return client.post(
        "/auth/register",
        json={"email": email, "username": username, "password": password},
    )


def login_user(client: TestClient, email: str = "user@example.com", password: str = "password123"):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_register_user(client: TestClient):
    resp = register_user(client)
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "user@example.com"
    assert data["username"] == "user1"
    assert "password" not in data


def test_login_returns_tokens(client: TestClient):
    register_user(client)
    resp = login_user(client)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data and data["access_token"]
    assert "refresh_token" in data and data["refresh_token"]
    assert data["token_type"] == "bearer"


def test_me_requires_token(client: TestClient):
    resp = client.get("/auth/me")
    assert resp.status_code == 401

    register_user(client)
    login_resp = login_user(client)
    token = login_resp.json()["access_token"]
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "user@example.com"


def test_refresh_flow(client: TestClient):
    register_user(client)
    login_resp = login_user(client)
    tokens = login_resp.json()
    refresh_token = tokens["refresh_token"]

    refresh_resp = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 200
    new_access = refresh_resp.json()["access_token"]
    assert new_access and new_access != tokens["access_token"]

