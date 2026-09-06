from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from example_app_fastapi import database
from example_app_fastapi.database import get_session
from example_app_fastapi.main import app
from example_app_fastapi.models import Customer


def _test_engine(tmp_path: Path):
    return create_engine(f"sqlite:///{tmp_path / 'test.db'}", echo=False)


@pytest.fixture
def client_and_engine(tmp_path: Path, monkeypatch):
    engine = _test_engine(tmp_path)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(database, "engine", engine)

    def _session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session_override
    try:
        with TestClient(app) as client:
            yield client, engine
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_customer_create_and_lookup(client_and_engine) -> None:
    client, engine = client_and_engine

    payload = {"email": "alice@example.com", "email_lookup": "alice@example.com"}
    response = client.post("/customers", json=payload)
    assert response.status_code == 200
    customer_id = response.json()["id"]

    response = client.get(f"/customers/{customer_id}")
    assert response.status_code == 200
    assert response.json()["email"] == payload["email"]

    response = client.get(f"/customers/by-email/{payload['email']}")
    assert response.status_code == 200
    assert response.json()["id"] == customer_id

    with engine.connect() as connection:
        raw = connection.exec_driver_sql(
            "select email from customer where id = ?",
            (customer_id,),
        ).fetchone()[0]
        assert isinstance(raw, (bytes, memoryview))
        raw_bytes = raw.tobytes() if isinstance(raw, memoryview) else raw
        assert payload["email"].encode("utf-8") not in raw_bytes

    with Session(engine) as session:
        statement = select(Customer).where(Customer.email_lookup == payload["email"])
        customer = session.exec(statement).first()
        assert customer is not None

    assert client.get("/customers/99999").status_code == 404
    assert client.get("/customers/by-email/missing@example.com").status_code == 404


def test_session_dependency_closes_session(monkeypatch):
    from unittest.mock import MagicMock

    session_type = MagicMock()
    monkeypatch.setattr(database, "Session", session_type)
    generator = get_session()
    assert next(generator) is session_type.return_value.__enter__.return_value
    generator.close()
    session_type.return_value.__exit__.assert_called_once()
