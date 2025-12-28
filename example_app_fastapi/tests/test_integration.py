from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from example_app_fastapi.database import get_session
from example_app_fastapi.main import app
from example_app_fastapi.models import Customer


def _test_engine(tmp_path: Path):
    return create_engine(f"sqlite:///{tmp_path / 'test.db'}", echo=False)


def test_customer_create_and_lookup(tmp_path: Path) -> None:
    engine = _test_engine(tmp_path)
    SQLModel.metadata.create_all(engine)

    def _session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session_override
    client = TestClient(app)

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

    app.dependency_overrides.clear()
