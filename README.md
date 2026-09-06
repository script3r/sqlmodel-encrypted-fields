# SQLModel Encrypted Fields

Encrypt SQLModel and SQLAlchemy columns with Google Tink AEAD. Python values are
serialized and encrypted before storage, then authenticated and decrypted on read.

Requires Python 3.10–3.14. Supports SQLModel 0.0.42+, SQLAlchemy 2.0, and Tink 1.16.1+.

## Install

```bash
pip install sqlmodel-encrypted-fields
```

## Quickstart

Provide your own Tink JSON keysets: AEAD (for example AES256_GCM) for regular
fields, and deterministic AEAD (AES256_SIV) for equality lookups.

```python
from sqlalchemy import Column
from sqlmodel import Field, Session, SQLModel, create_engine, select

from sqlmodel_encrypted_fields import KeysetRegistry

registry = KeysetRegistry(
    {
        "default": {"path": "/path/to/aead_keyset.json", "cleartext": True},
        "searchable": {"path": "/path/to/daead_keyset.json", "cleartext": True},
    }
)


class Customer(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(sa_column=Column(registry.encrypted_string(), nullable=False))
    email_lookup: str = Field(
        sa_column=Column(
            registry.deterministic_encrypted_string(keyset="searchable"),
            nullable=False,
            index=True,
        )
    )


engine = create_engine("sqlite://")
SQLModel.metadata.create_all(engine)
with Session(engine) as session:
    session.add(Customer(email="alice@example.com", email_lookup="alice@example.com"))
    session.commit()
    customer = session.exec(
        select(Customer).where(Customer.email_lookup == "alice@example.com")
    ).one()
    assert customer.email == "alice@example.com"
```

The database stores binary ciphertext. Python model attributes and API responses
contain plaintext; this package protects database storage, not API access or logs.

## Fields and serialization

| Regular AEAD | Deterministic AEAD | Python value |
| --- | --- | --- |
| `EncryptedString` | `DeterministicEncryptedString` | `str` |
| `EncryptedJSON` | `DeterministicEncryptedJSON` | JSON-compatible values |
| `EncryptedBytes` | `DeterministicEncryptedBytes` | `bytes` |
| `EncryptedType` | `DeterministicEncryptedType` | Custom serialization |

Every type is available directly with `registry=registry` or through the matching
registry factory, such as `registry.encrypted_json()`. `None` maps to SQL `NULL`;
empty strings and empty bytes are encrypted normally. JSON uses sorted keys and
compact separators. Assign a new JSON value to persist changes, or configure
SQLAlchemy's mutable extension for in-place edits.

Custom serializers must return `str` (encoded as UTF-8) or `bytes`. Deserializers
receive UTF-8 text by default. Use `deserializer_input="bytes"` for binary payloads.
Exceptions propagate without retrying user code.

```python
from datetime import date


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    birthday: date = Field(
        sa_column=Column(
            registry.encrypted_type(
                serializer=date.isoformat,
                deserializer=date.fromisoformat,
            )
        )
    )
```

## Keys, associated data, and rotation

Use a separate registry for each independent configuration. For encrypted keysets,
provide the AEAD that protects the keyset (typically obtained from your KMS):

```python
registry = KeysetRegistry(
    {"default": {"path": "/path/to/encrypted_keyset.json", "master_key_aead": kms_aead}}
)
```

`cleartext=True` explicitly permits an unencrypted keyset file. The committed
fixtures and example applications use public test keys; create private keys for
real data. Keep keys separate from the database and its backups.

Associated authenticated data (AAD) binds ciphertext to an application context:

```python
email_type = registry.encrypted_string(aad_callback=lambda: b"customer.email:v1")
```

Callbacks may accept no arguments or `(value, dialect, is_bind)`. On reads,
`value` is `None`; the callback must reproduce the same AAD without plaintext or
row access. It must return `bytes` or `str`. Explicitly return `b""` for empty AAD.
Authentication failures, including wrong keys, changed AAD, and tampering, raise
Tink errors (SQLAlchemy may wrap errors during database operations).

After updating a keyset file or its configuration, call
`registry.set_config(new_config)`. To reload the same paths, call
`registry.set_config(registry.config)`. Existing fields and their dialect copies
use the new handles on subsequent lookups. Registry configuration is copied;
mutating the original dictionary or the `config` property does not update it.
Loads and invalidation are synchronized, but an operation that already obtained
a primitive can finish with the old key. Coordinate rotations with active writes
when you require a strict cutover, and reload every worker process.

Keep old keys enabled while old ciphertext still exists. Rotation does not rewrite
stored values. Deterministic ciphertext changes when the primary key changes:
equality queries encrypt with the current primary key and will not find older
ciphertexts until those rows are migrated. Plan that migration before rotation.

Regular AEAD produces different ciphertext on each write and cannot support
plaintext equality queries. Deterministic fields support equality and `IN` with
identical keys, serialization, and AAD; they reveal repeated values. Neither form
supports meaningful plaintext ordering, ranges, `LIKE`, or JSON path queries.

## Example applications

From a repository checkout:

```bash
pip install -e '.[fastapi,flask]'
uvicorn example_app_fastapi.main:app
# Or:
flask --app example_app_flask.app:create_app run
```

Both examples implement customer creation, retrieval by ID, and deterministic
email lookup. FastAPI closes sessions after each request; Flask initializes its
schema in the app factory. The examples are included in the source distribution
and repository, not the installed library wheel.

## Development and release

```bash
uv venv --python 3.14
uv pip install -e '.[test,dev]'
uv run pytest --cov
uv run ruff check .
uv run ruff format --check .
uv run python -m build
uv run twine check --strict dist/*
```

CI tests Python 3.10–3.14 on Linux and Python 3.14 on macOS and Windows. It also
checks formatting, runtime dependencies, distribution metadata, and encryption
from an installed wheel outside the source checkout.

To release, update `pyproject.toml` and `CHANGELOG.md`, then push a matching `vX.Y.Z`
tag. The release workflow validates the tag, runs CI, builds distributions, and
publishes the same artifacts to GitHub and PyPI. Failed publication can be retried
with the Release workflow's `tag` input. PyPI uses trusted publishing; configure:

- PyPI project: `sqlmodel-encrypted-fields`
- GitHub owner: `script3r`
- Repository: `sqlmodel-encrypted-fields`
- Workflow: `release.yml`
- Environment: `pypi`

For the first publication, add a pending publisher in your
[PyPI publishing settings](https://pypi.org/manage/account/publishing/).

## Migrating from 0.1.0

- Python 3.10+, SQLModel 0.0.42+, and Tink 1.16.1+ are now required.
- Custom deserializers receive text by default. Set `deserializer_input="bytes"`
  if yours expects bytes. Built-in bytes fields already select binary mode.
- AAD callbacks returning `None` now raise `TypeError`; return `b""` explicitly.
  Exceptions inside callbacks and deserializers are no longer retried.
- Use `set_config()` to change registry configuration. Changes now affect existing
  fields, including fields already used by an engine.
- Create a new field type to change its serializer, callback, or keyset name;
  do not mutate those attributes after constructing a SQLAlchemy column.

The ciphertext format is unchanged. Existing data remains readable with the same
keys, AAD, and matching deserializer. See [CHANGELOG.md](CHANGELOG.md).
