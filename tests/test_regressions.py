from __future__ import annotations

import json
from pathlib import Path

import pytest
import tink
from sqlalchemy import Column, Integer, MetaData, Table, bindparam, create_engine, select
from tink import aead, cleartext_keyset_handle, daead

from sqlmodel_encrypted_fields import EncryptedString, EncryptedType, KeysetRegistry


def write_keyset(path, template):
    handle = tink.new_keyset_handle(template)
    with path.open("w") as stream:
        cleartext_keyset_handle.write(tink.JsonKeysetWriter(stream), handle)
    return handle


@pytest.fixture
def registry(tmp_path):
    path = tmp_path / "keyset.json"
    write_keyset(path, aead.aead_key_templates.AES256_GCM)
    return KeysetRegistry({"default": {"path": str(path), "cleartext": True}})


@pytest.mark.parametrize("deterministic", [False, True])
def test_existing_field_observes_reconfigured_keyset(tmp_path, deterministic):
    template = (
        daead.deterministic_aead_key_templates.AES256_SIV
        if deterministic
        else aead.aead_key_templates.AES256_GCM
    )
    path = tmp_path / "keyset.json"
    old_handle = write_keyset(path, template)
    config = {"default": {"path": str(path), "cleartext": True}}
    registry = KeysetRegistry(config)
    field = (
        registry.deterministic_encrypted_string() if deterministic else registry.encrypted_string()
    )
    field.process_bind_param("old", None)
    new_handle = write_keyset(path, template)
    registry.set_config(config)
    ciphertext = field.process_bind_param("new", None)
    if deterministic:
        assert (
            new_handle.primitive(daead.DeterministicAead).decrypt_deterministically(ciphertext, b"")
            == b"new"
        )
        with pytest.raises(tink.TinkError):
            old_handle.primitive(daead.DeterministicAead).decrypt_deterministically(ciphertext, b"")
    else:
        assert new_handle.primitive(aead.Aead).decrypt(ciphertext, b"") == b"new"
        with pytest.raises(tink.TinkError):
            old_handle.primitive(aead.Aead).decrypt(ciphertext, b"")


@pytest.mark.parametrize(
    "factory",
    [
        "encrypted_type",
        "encrypted_string",
        "encrypted_json",
        "encrypted_bytes",
        "deterministic_encrypted_type",
        "deterministic_encrypted_string",
        "deterministic_encrypted_json",
        "deterministic_encrypted_bytes",
    ],
)
def test_compiled_statements_do_not_reuse_another_fields_context(tmp_path, factory):
    deterministic = factory.startswith("deterministic")
    template = (
        daead.deterministic_aead_key_templates.AES256_SIV
        if deterministic
        else aead.aead_key_templates.AES256_GCM
    )
    path = tmp_path / "keyset.json"
    handle = write_keyset(path, template)
    registry = KeysetRegistry({"default": {"path": str(path), "cleartext": True}})
    first = getattr(registry, factory)(aad_callback=lambda: b"first")
    second = getattr(registry, factory)(aad_callback=lambda: b"second")
    value = b"secret" if factory.endswith("bytes") else "secret"
    engine = create_engine("sqlite://")
    try:
        with engine.connect() as connection:
            for field, context in [(first, b"first"), (second, b"second")]:
                stmt = select(bindparam("value", type_=field))
                ciphertext = connection.execute(stmt, {"value": value}).cursor.fetchone()[0]
                if deterministic:
                    handle.primitive(daead.DeterministicAead).decrypt_deterministically(
                        ciphertext, context
                    )
                else:
                    handle.primitive(aead.Aead).decrypt(ciphertext, context)
    finally:
        engine.dispose()


def test_aad_callback_typeerror_is_not_retried(registry):
    calls = []

    def callback(*args):
        calls.append(args)
        if args:
            raise TypeError("context unavailable")
        return b""

    field = EncryptedString(registry=registry, aad_callback=callback)
    with pytest.raises(TypeError, match="context unavailable"):
        field.process_bind_param("secret", None)
    assert len(calls) == 1


def test_deserializer_errors_are_not_retried(registry):
    calls = []

    def deserialize(value):
        calls.append(value)
        raise ValueError("invalid payload")

    field = EncryptedType(registry=registry, deserializer=deserialize)
    ciphertext = field.process_bind_param("secret", None)
    with pytest.raises(ValueError, match="invalid payload"):
        field.process_result_value(ciphertext, None)
    assert len(calls) == 1


def test_registry_configuration_is_defensively_copied(registry):
    config = registry.config
    replacement = {"default": dict(config["default"])}
    registry.set_config(replacement)
    replacement["default"]["path"] = "missing.json"
    config = registry.config
    config["default"]["path"] = "also-missing.json"
    assert Path(registry.config["default"]["path"]).is_file()


def test_rotation_with_retained_key_works_on_existing_engine(tmp_path):
    path = tmp_path / "keyset.json"
    write_keyset(path, aead.aead_key_templates.AES256_GCM)
    original_keyset = json.loads(path.read_text())
    registry = KeysetRegistry({"default": {"path": str(path), "cleartext": True}})
    metadata = MetaData()
    table = Table(
        "records",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("value", registry.encrypted_string()),
    )
    engine = create_engine("sqlite://")
    try:
        metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(table.insert(), {"id": 1, "value": "before"})
            assert connection.execute(select(table.c.value)).scalar_one() == "before"
            new_handle = write_keyset(path, aead.aead_key_templates.AES256_GCM)
            new_keyset = json.loads(path.read_text())
            new_keyset["key"].extend(original_keyset["key"])
            path.write_text(json.dumps(new_keyset))
            registry.set_config(registry.config)
            connection.execute(table.insert(), {"id": 2, "value": "after"})
            assert connection.execute(
                select(table.c.value).order_by(table.c.id)
            ).scalars().all() == ["before", "after"]
            raw = connection.exec_driver_sql("SELECT value FROM records WHERE id=2").scalar_one()
            assert new_handle.primitive(aead.Aead).decrypt(raw, b"") == b"after"
    finally:
        engine.dispose()
