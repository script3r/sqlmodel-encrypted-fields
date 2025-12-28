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

from sqlmodel_encrypted_fields import KeysetRegistry

registry = KeysetRegistry(
    {
        "default": {"path": "/path/to/aead_keyset.json", "cleartext": True},
        "searchable": {"path": "/path/to/daead_keyset.json", "cleartext": True},
    }
)


class Customer(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(sa_column=Column(registry.encrypted_string()))
    email_lookup: str = Field(sa_column=Column(registry.deterministic_encrypted_string(keyset="searchable")))
```

## Example Apps

- FastAPI example: `example_app_fastapi/`
- Flask example: `example_app_flask/`

### Flask Example Snippet

```python
from flask import Flask

from example_app_flask.database import init_db
from example_app_flask.models import Customer

app = Flask(__name__)

@app.before_first_request
def _init_db() -> None:
    init_db()
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

from sqlmodel_encrypted_fields import KeysetRegistry

registry = KeysetRegistry(
    {
        "default": {"path": "/path/to/aead_keyset.json", "cleartext": True},
    }
)


def serialize_date(value: date) -> str:
    return value.isoformat()


def deserialize_date(value: str) -> date:
    return date.fromisoformat(value)


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    birthday: date = Field(
        sa_column=registry.encrypted_type(serializer=serialize_date, deserializer=deserialize_date)
    )
```
