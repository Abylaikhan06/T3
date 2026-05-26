import importlib
import sys

from fastapi.testclient import TestClient


def load_app(tmp_path, monkeypatch):
    values = {
        "DATABASE_URL": f"sqlite:///{tmp_path / 'test.db'}",
        "JWT_SECRET": "test-secret-with-more-than-thirty-two-symbols",
        "JWT_ALGORITHM": "HS256",
        "TOKEN_EXPIRE_MINUTES": "30",
        "SEED_DATA": "true",
        "ADMIN_EMAIL": "admin@example.com",
        "ADMIN_PASSWORD": "Admin123!",
        "MANAGER_EMAIL": "manager@example.com",
        "MANAGER_PASSWORD": "Manager123!",
        "USER_EMAIL": "user@example.com",
        "USER_PASSWORD": "User123!",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    for name in tuple(sys.modules):
        if name == "main" or name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    return importlib.import_module("main")


def login(client, email, password):
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_register_login_update_and_soft_delete(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        created = client.post(
            "/auth/register",
            json={
                "full_name": "New User",
                "email": "NEW@example.com",
                "password": "Password123!",
                "password_repeat": "Password123!",
            },
        )
        assert created.status_code == 201
        assert created.json()["email"] == "new@example.com"
        headers = login(client, "new@example.com", "Password123!")
        updated = client.put(
            "/users/me",
            headers=headers,
            json={"full_name": "Updated User", "email": "updated@example.com"},
        )
        assert updated.status_code == 200
        assert updated.json()["email"] == "updated@example.com"
        assert client.delete("/users/me", headers=headers).status_code == 200
        assert client.post(
            "/auth/login",
            json={"email": "updated@example.com", "password": "Password123!"},
        ).status_code == 401


def test_user_sees_own_order_while_manager_sees_all(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        user_orders = client.get(
            "/resources/orders", headers=login(client, "user@example.com", "User123!")
        )
        manager_orders = client.get(
            "/resources/orders",
            headers=login(client, "manager@example.com", "Manager123!"),
        )
        assert [order["id"] for order in user_orders.json()] == [1]
        assert len(manager_orders.json()) == 2


def test_only_admin_can_manage_rules(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        manager_headers = login(client, "manager@example.com", "Manager123!")
        admin_headers = login(client, "admin@example.com", "Admin123!")
        assert client.get("/admin/rules", headers=manager_headers).status_code == 403
        rules = client.get("/admin/rules", headers=admin_headers)
        assert rules.status_code == 200
        assert len(rules.json()) == 6


def test_requires_token_for_resource(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        assert client.get("/resources/orders").status_code == 401


def test_serves_website_frontend(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        page = client.get("/")
        script = client.get("/static/app.js")
        assert page.status_code == 200
        assert "AccessHub" in page.text
        assert script.status_code == 200
        assert "renderRules" in script.text


def test_rejects_invalid_user_input(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        invalid_registration = client.post(
            "/auth/register",
            json={
                "full_name": "123",
                "email": "wrong-email",
                "password": "simple",
                "password_repeat": "different",
            },
        )
        invalid_order = client.post(
            "/resources/orders",
            headers=login(client, "user@example.com", "User123!"),
            json={"title": "!!!", "amount": -1},
        )
        assert invalid_registration.status_code == 422
        assert invalid_order.status_code == 422
