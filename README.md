# SQLModel Encrypted Fields

Encrypt SQLModel fields with Tink AEAD in a few lines, and keep ciphertext out of sight.

## Install

```bash
pip install sqlmodel-encrypted-fields
```

## Quickstart

```python
from sqlalchemy import Column
from sqlmodel import Field, SQLModel

from sqlmodel_encrypted_fields import (
    configure_keysets,
    EncryptedString,
    DeterministicEncryptedString,
)

configure_keysets(
    {
        "default": {"path": "/path/to/aead_keyset.json", "cleartext": True},
        "searchable": {"path": "/path/to/daead_keyset.json", "cleartext": True},
    }
)


class Customer(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(sa_column=Column(EncryptedString()))
    email_lookup: str = Field(sa_column=Column(DeterministicEncryptedString(keyset="searchable")))
```

## Notes

Regular AEAD fields change ciphertext on every write. Use deterministic fields only when you need equality lookups.

## Supported Fields

- `EncryptedType` (custom serializer/deserializer)
- `EncryptedString`
- `EncryptedJSON`
- `EncryptedBytes`
- `DeterministicEncryptedType` (custom serializer/deserializer)
- `DeterministicEncryptedString`
- `DeterministicEncryptedJSON`
- `DeterministicEncryptedBytes`

## Custom Serialization

```python
from datetime import date

from sqlmodel_encrypted_fields import EncryptedType


def serialize_date(value: date) -> str:
    return value.isoformat()


def deserialize_date(value: str) -> date:
    return date.fromisoformat(value)


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    birthday: date = Field(sa_column=EncryptedType(serializer=serialize_date, deserializer=deserialize_date))
```
