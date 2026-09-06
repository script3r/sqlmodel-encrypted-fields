from __future__ import annotations

from sqlalchemy import Column, MetaData
from sqlmodel import Field, SQLModel

from example_app_flask.crypto import registry


class Customer(SQLModel, table=True):
    # Keep example schemas independent when both apps are imported by tests.
    metadata = MetaData()

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(sa_column=Column(registry.encrypted_string()))
    email_lookup: str = Field(
        sa_column=Column(registry.deterministic_encrypted_string(keyset="deterministic"))
    )
