from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from example_app.database import get_session
from example_app.main import app
from example_app.models import Customer
from sqlmodel_encrypted_fields import configure_keysets


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _configure_keysets() -> None:
    root = _project_root()
    configure_keysets(
        {
            "default": {"path": str(root / "tests" / "fixtures" / "aead_keyset.json"), "cleartext": True},
            "deterministic": {"path": str(root / "tests" / "fixtures" / "daead_keyset.json"), "cleartext": True},
        }
    )


def _test_engine(tmp_path: Path):
    return create_engine(f"sqlite:///{tmp_path / 'test.db'}", echo=False)


def test_customer_create_and_lookup(tmp_path: Path) -> None:
    _configure_keysets()

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
