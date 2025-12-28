from __future__ import annotations

from typing import Optional

from sqlalchemy import Column
from sqlmodel import Field, SQLModel

from example_app_fastapi.crypto import registry


class Customer(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(sa_column=Column(registry.encrypted_string()))
    email_lookup: str = Field(sa_column=Column(registry.deterministic_encrypted_string(keyset="deterministic")))
