from __future__ import annotations

from typing import Optional

from sqlalchemy import Column
from sqlmodel import Field, SQLModel

from sqlmodel_encrypted_fields import DeterministicEncryptedString, EncryptedString


class Customer(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(sa_column=Column(EncryptedString()))
    email_lookup: str = Field(sa_column=Column(DeterministicEncryptedString(keyset="deterministic")))
