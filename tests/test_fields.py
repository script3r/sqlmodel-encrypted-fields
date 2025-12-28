from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

try:
    from tink import daead

    DAEAD_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on Tink build
    DAEAD_AVAILABLE = False
    daead = None

from sqlmodel_encrypted_fields import (
    ConfigurationError,
    DeterministicEncryptedBytes,
    DeterministicEncryptedJSON,
    DeterministicEncryptedString,
    EncryptedBytes,
    EncryptedJSON,
    EncryptedString,
    EncryptedType,
    configure_keysets,
)


@pytest.fixture(scope="module")
def keysets(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    tmp_path = tmp_path_factory.mktemp("keysets")
    aead_path = tmp_path / "aead_keyset.json"
    aead_path.write_text(_fixture_path("aead_keyset.json").read_text(encoding="utf-8"), encoding="utf-8")

    config = {
        "default": {"path": str(aead_path), "cleartext": True},
    }

    if DAEAD_AVAILABLE:
        daead_path = tmp_path / "daead_keyset.json"
        daead_path.write_text(_fixture_path("daead_keyset.json").read_text(encoding="utf-8"), encoding="utf-8")
        config["deterministic"] = {"path": str(daead_path), "cleartext": True}

    return config


def _fixture_path(name: str) -> Path:
    return Path(__file__).parent / "fixtures" / name


def test_missing_configuration_raises() -> None:
    configure_keysets({})
    field = EncryptedString()
    with pytest.raises(ConfigurationError):
        _ = field._keyset_manager.aead_primitive


def test_encrypt_decrypt_string_roundtrip(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)
    field = EncryptedString()
    ciphertext = field.process_bind_param("hello", None)
    assert isinstance(ciphertext, bytes)
    decrypted = field.process_result_value(ciphertext, None)
    assert decrypted == "hello"


def test_encrypt_decrypt_json_roundtrip(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)
    field = EncryptedJSON()
    payload = {"a": 1, "b": [True, False], "c": "text"}
    ciphertext = field.process_bind_param(payload, None)
    decrypted = field.process_result_value(ciphertext, None)
    assert decrypted == payload


def test_encrypt_decrypt_bytes_roundtrip(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)
    field = EncryptedBytes()
    payload = b"\x00\xffbinary"
    ciphertext = field.process_bind_param(payload, None)
    decrypted = field.process_result_value(ciphertext, None)
    assert decrypted == payload


def test_custom_serializer_roundtrip(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)

    def serialize(value: int) -> str:
        return f"v:{value}"

    def deserialize(value: str) -> int:
        return int(value.split(":", 1)[1])

    field = EncryptedType(serializer=serialize, deserializer=deserialize)
    ciphertext = field.process_bind_param(42, None)
    decrypted = field.process_result_value(ciphertext, None)
    assert decrypted == 42


def test_aad_callback_supports_str(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)

    def aad_callback() -> str:
        return "context"

    field = EncryptedString(aad_callback=aad_callback)
    ciphertext = field.process_bind_param("data", None)
    decrypted = field.process_result_value(ciphertext, None)
    assert decrypted == "data"


def test_memoryview_result_roundtrip(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)
    field = EncryptedString()
    ciphertext = field.process_bind_param("value", None)
    decrypted = field.process_result_value(memoryview(ciphertext), None)
    assert decrypted == "value"


@pytest.mark.skipif(not DAEAD_AVAILABLE, reason="Deterministic AEAD not available")
def test_deterministic_ciphertext_is_stable(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)
    field = DeterministicEncryptedString(keyset="deterministic")
    first = field.process_bind_param("email@example.com", None)
    second = field.process_bind_param("email@example.com", None)
    assert first == second


@pytest.mark.skipif(not DAEAD_AVAILABLE, reason="Deterministic AEAD not available")
def test_deterministic_roundtrip_json_and_bytes(keysets: dict[str, dict[str, Any]]) -> None:
    configure_keysets(keysets)

    json_field = DeterministicEncryptedJSON(keyset="deterministic")
    json_payload = {"x": 1, "y": "z"}
    json_cipher = json_field.process_bind_param(json_payload, None)
    assert json_field.process_result_value(json_cipher, None) == json_payload

    bytes_field = DeterministicEncryptedBytes(keyset="deterministic")
    bytes_payload = b"blob"
    bytes_cipher = bytes_field.process_bind_param(bytes_payload, None)
    assert bytes_field.process_result_value(bytes_cipher, None) == bytes_payload
