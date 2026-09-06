from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import date
from unittest.mock import Mock

import pytest
import tink
from sqlalchemy import Column, Integer, MetaData, Table, create_engine, select
from tink import aead, cleartext_keyset_handle, daead

from sqlmodel_encrypted_fields import ConfigurationError, KeysetConfig, KeysetRegistry


@pytest.fixture
def registry(tmp_path):
    config = {}
    for name, template in [
        ("default", aead.aead_key_templates.AES256_GCM),
        ("deterministic", daead.deterministic_aead_key_templates.AES256_SIV),
    ]:
        path = tmp_path / f"{name}.json"
        with path.open("w") as stream:
            cleartext_keyset_handle.write(
                tink.JsonKeysetWriter(stream), tink.new_keyset_handle(template)
            )
        config[name] = {"path": str(path), "cleartext": True}
    return KeysetRegistry(config)


@pytest.fixture(params=[False, True])
def field(request, registry):
    if request.param:
        return registry.deterministic_encrypted_string(keyset="deterministic")
    return registry.encrypted_string()


def test_tampered_ciphertext_fails_authentication(field):
    ciphertext = field.process_bind_param("secret", None)
    corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    with pytest.raises(tink.TinkError):
        field.process_result_value(corrupted, None)


@pytest.mark.parametrize("ciphertext", [b"", b"plaintext", b"\x00"])
def test_invalid_ciphertext_fails_closed(field, ciphertext):
    with pytest.raises(tink.TinkError):
        field.process_result_value(ciphertext, None)


def test_null_and_empty_string(field):
    assert field.process_bind_param(None, None) is None
    assert field.process_result_value(None, None) is None
    ciphertext = field.process_bind_param("", None)
    assert ciphertext
    assert field.process_result_value(ciphertext, None) == ""


def test_wrong_aad_fails_authentication(registry):
    writer = registry.encrypted_string(aad_callback=lambda: b"customer.email")
    reader = registry.encrypted_string(aad_callback=lambda: b"customer.name")
    with pytest.raises(tink.TinkError):
        reader.process_result_value(writer.process_bind_param("secret", None), None)


def test_aad_context_arguments(registry):
    calls = []

    def callback(value, dialect, is_bind):
        calls.append((value, dialect, is_bind))
        return b"context"

    field = registry.encrypted_string(aad_callback=callback)
    ciphertext = field.process_bind_param("secret", "dialect")
    assert field.process_result_value(ciphertext, "dialect") == "secret"
    assert calls == [("secret", "dialect", True), (None, "dialect", False)]


@pytest.mark.parametrize("value", [None, 123, bytearray(b"context")])
def test_invalid_aad_return_is_rejected(registry, value):
    field = registry.encrypted_string(aad_callback=lambda: value)
    with pytest.raises(TypeError, match="AAD callback"):
        field.process_bind_param("secret", None)


@pytest.mark.parametrize("callback", [None, lambda x: b"", lambda x, y: b""])
def test_invalid_aad_signature_is_rejected(registry, callback):
    with pytest.raises(ConfigurationError, match="AAD callback"):
        registry.encrypted_string(aad_callback=callback)


def test_explicit_custom_deserialization(registry):
    birthday = date(2000, 1, 2)
    text_field = registry.encrypted_type(serializer=date.isoformat, deserializer=date.fromisoformat)
    assert (
        text_field.process_result_value(text_field.process_bind_param(birthday, None), None)
        == birthday
    )
    binary_field = registry.encrypted_type(
        serializer=lambda value: value,
        deserializer=lambda value: value,
        deserializer_input="bytes",
    )
    assert (
        binary_field.process_result_value(binary_field.process_bind_param(b"\xff\x00", None), None)
        == b"\xff\x00"
    )


@pytest.mark.parametrize(
    "options",
    [
        {"deserializer_input": "invalid"},
        {"serializer": None},
        {"deserializer": None},
    ],
)
def test_invalid_serializer_configuration(registry, options):
    with pytest.raises(ConfigurationError):
        registry.encrypted_type(**options)


def test_invalid_serializer_result(registry):
    field = registry.encrypted_type(serializer=lambda value: 123)
    with pytest.raises(TypeError, match="Serializer must return"):
        field.process_bind_param("secret", None)


def test_string_and_bytes_types_reject_wrong_input(registry):
    with pytest.raises(TypeError, match="string"):
        registry.encrypted_string().process_bind_param(b"bytes", None)
    with pytest.raises(TypeError, match="bytes"):
        registry.encrypted_bytes().process_bind_param("text", None)


def test_encrypted_keyset_roundtrip(tmp_path):
    master = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM).primitive(aead.Aead)
    handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    path = tmp_path / "encrypted.json"
    with path.open("w") as stream:
        handle.write(tink.JsonKeysetWriter(stream), master)
    field = KeysetRegistry(
        {"default": {"path": str(path), "master_key_aead": master}}
    ).encrypted_string()
    ciphertext = field.process_bind_param("secret", None)
    assert field.process_result_value(ciphertext, None) == "secret"
    wrong_master = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM).primitive(aead.Aead)
    wrong_field = KeysetRegistry(
        {"default": {"path": str(path), "master_key_aead": wrong_master}}
    ).encrypted_string()
    with pytest.raises(tink.TinkError):
        wrong_field.process_result_value(ciphertext, None)


def test_invalid_keyset_configuration(tmp_path):
    with pytest.raises(ConfigurationError, match="empty"):
        KeysetConfig(path="")
    with pytest.raises(ConfigurationError, match="not a file"):
        KeysetConfig(path=str(tmp_path), cleartext=True)
    path = tmp_path / "keyset.json"
    path.write_text("{}")
    with pytest.raises(ConfigurationError, match="boolean"):
        KeysetConfig(path=str(path), cleartext="false")
    with pytest.raises(ConfigurationError, match="cannot specify"):
        KeysetConfig(path=str(path), cleartext=True, master_key_aead=Mock())


def test_keyset_handle_is_shared_across_threads(registry):
    def load(_):
        return registry.encrypted_string()._keyset_manager._get_keyset_handle()

    with ThreadPoolExecutor(max_workers=8) as pool:
        handles = list(pool.map(load, range(32)))
    assert all(handle is handles[0] for handle in handles)


def test_randomized_encryption_changes_ciphertext(registry):
    field = registry.encrypted_string()
    assert field.process_bind_param("same", None) != field.process_bind_param("same", None)


def test_database_roundtrip_equality_in_null_and_update(registry):
    metadata = MetaData()
    table = Table(
        "records",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("secret", registry.encrypted_json()),
        Column("lookup", registry.deterministic_encrypted_string(keyset="deterministic")),
    )
    engine = create_engine("sqlite://")
    try:
        metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(
                table.insert(),
                [
                    {"id": 1, "secret": {"private": True}, "lookup": "alice"},
                    {"id": 2, "secret": None, "lookup": None},
                ],
            )
            assert connection.execute(
                select(table.c.secret).where(table.c.lookup == "alice")
            ).scalar_one() == {"private": True}
            assert connection.execute(
                select(table.c.id).where(table.c.lookup.in_(["alice", "bob"]))
            ).scalars().all() == [1]
            assert (
                connection.execute(select(table.c.id).where(table.c.lookup.is_(None))).scalar_one()
                == 2
            )
            connection.execute(
                table.update().where(table.c.id == 1).values(secret={"updated": True})
            )
            assert connection.execute(
                select(table.c.secret).where(table.c.id == 1)
            ).scalar_one() == {"updated": True}
            raw = connection.exec_driver_sql("SELECT secret FROM records WHERE id=1").scalar_one()
            assert isinstance(raw, bytes) and b"updated" not in raw
    finally:
        engine.dispose()
