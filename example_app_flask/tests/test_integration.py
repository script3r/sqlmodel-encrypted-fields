from __future__ import annotations

import pytest
from sqlmodel import create_engine

from example_app_flask import database
from example_app_flask.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'flask.db'}")
    monkeypatch.setattr(database, "engine", engine)
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
    engine.dispose()


def test_customer_create_and_lookup(client):
    payload = {"email": "alice@example.com", "email_lookup": "alice@example.com"}
    response = client.post("/customers", json=payload)
    assert response.status_code == 200
    customer_id = response.json["id"]
    assert client.get(f"/customers/{customer_id}").json["email"] == payload["email"]
    assert client.get(f"/customers/by-email/{payload['email']}").json["id"] == customer_id
    assert client.get("/customers/99999").status_code == 404
    assert client.get("/customers/by-email/missing@example.com").status_code == 404


def test_invalid_customer_returns_validation_error(client):
    assert client.post("/customers", json={"email": 123}).status_code == 422
