"""Encrypted SQLModel field types using Google Tink AEAD."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Callable, Optional

from sqlalchemy.types import LargeBinary, TypeDecorator
from tink import JsonKeysetReader, aead, cleartext_keyset_handle, read_keyset_handle

try:
    from tink import daead

    DAEAD_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on Tink build
    DAEAD_AVAILABLE = False
    daead = None


def _register_tink_primitives() -> None:
    aead.register()
    if DAEAD_AVAILABLE:
        daead.register()


_register_tink_primitives()

DEFAULT_KEYSET = "default"


class ConfigurationError(RuntimeError):
    """Raised when keyset configuration is missing or invalid."""


def _default_aad_callback(*_args: Any, **_kwargs: Any) -> bytes:
    return b""


DEFAULT_AAD_CALLBACK = _default_aad_callback


def _ensure_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("AAD callback must return bytes or str.")


def _json_serialize(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _json_deserialize(value: str) -> Any:
    return json.loads(value)


@dataclass(frozen=True)
class KeysetConfig:
    path: str
    master_key_aead: Optional[aead.Aead] = None
    cleartext: bool = False

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not self.path:
            raise ConfigurationError("Keyset path cannot be empty.")
        if not Path(self.path).exists():
            raise ConfigurationError(f"Keyset {self.path} does not exist.")
        if not self.cleartext and self.master_key_aead is None:
            raise ConfigurationError("Encrypted keysets must specify `master_key_aead`.")


_CONFIG: dict[str, dict[str, Any]] | None = None


def configure_keysets(config: dict[str, dict[str, Any]]) -> None:
    """Provide global keyset configuration.

    Expected format:
    {
        "default": {
            "path": "/path/to/keyset.json",
            "cleartext": True,
            "master_key_aead": <tink.aead.Aead>,  # optional when cleartext=True
        }
    }
    """

    global _CONFIG
    _CONFIG = config


class KeysetManager:
    _handle_cache: dict[tuple[str, str, bool, int], Any] = {}

    def __init__(self, keyset_name: str, aad_callback: Callable[..., Any]) -> None:
        self.keyset_name = keyset_name
        self.aad_callback = aad_callback
        self._keyset_handle = None

    def _get_config(self) -> dict[str, dict[str, Any]]:
        if _CONFIG is None:
            raise ConfigurationError("Keysets are not configured. Call configure_keysets() first.")
        return _CONFIG

    def _get_keyset_handle(self) -> Any:
        if self._keyset_handle is not None:
            return self._keyset_handle

        config = self._get_config()
        if self.keyset_name not in config:
            raise ConfigurationError(f"Missing keyset configuration for '{self.keyset_name}'.")

        keyset_config = KeysetConfig(**config[self.keyset_name])
        cache_key = (
            self.keyset_name,
            keyset_config.path,
            keyset_config.cleartext,
            id(keyset_config.master_key_aead) if keyset_config.master_key_aead is not None else 0,
        )
        cached_handle = self._handle_cache.get(cache_key)
        if cached_handle is not None:
            self._keyset_handle = cached_handle
            return cached_handle

        with open(keyset_config.path, "r", encoding="utf-8") as handle:
            reader = JsonKeysetReader(handle.read())
            if keyset_config.cleartext:
                keyset_handle = cleartext_keyset_handle.read(reader)
            else:
                keyset_handle = read_keyset_handle(reader, keyset_config.master_key_aead)

        self._handle_cache[cache_key] = keyset_handle
        self._keyset_handle = keyset_handle
        return keyset_handle

    @property
    def aead_primitive(self) -> aead.Aead:
        return self._get_keyset_handle().primitive(aead.Aead)

    @property
    def daead_primitive(self) -> Any:
        if not DAEAD_AVAILABLE:
            raise ConfigurationError("Deterministic AEAD is not available in this Tink build.")
        return self._get_keyset_handle().primitive(daead.DeterministicAead)


class EncryptedType(TypeDecorator):
    """Encrypts values using Tink AEAD and stores ciphertext as binary."""

    impl = LargeBinary
    cache_ok = True

    def __init__(
        self,
        *,
        keyset: str = DEFAULT_KEYSET,
        aad_callback: Callable[..., Any] = DEFAULT_AAD_CALLBACK,
        serializer: Callable[[Any], Any] = _json_serialize,
        deserializer: Callable[[Any], Any] = _json_deserialize,
    ) -> None:
        super().__init__()
        self.keyset = keyset
        self.aad_callback = aad_callback
        self.serializer = serializer
        self.deserializer = deserializer
        self._keyset_manager = KeysetManager(self.keyset, self.aad_callback)

    def _call_aad(self, value: Any, dialect: Any, is_bind: bool) -> bytes:
        try:
            aad_value = self.aad_callback(value, dialect, is_bind)
        except TypeError:
            aad_value = self.aad_callback()
        return _ensure_bytes(aad_value)

    def _serialize(self, value: Any) -> bytes:
        serialized = self.serializer(value)
        if isinstance(serialized, bytes):
            return serialized
        if isinstance(serialized, str):
            return serialized.encode("utf-8")
        raise TypeError("Serializer must return bytes or str.")

    def _deserialize(self, value: bytes) -> Any:
        try:
            return self.deserializer(value)
        except Exception:
            return self.deserializer(value.decode("utf-8"))

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        aad = self._call_aad(value, dialect, True)
        serialized = self._serialize(value)
        return self._keyset_manager.aead_primitive.encrypt(serialized, aad)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        aad = self._call_aad(None, dialect, False)
        data = value.tobytes() if isinstance(value, memoryview) else bytes(value)
        decrypted = self._keyset_manager.aead_primitive.decrypt(data, aad)
        return self._deserialize(decrypted)


class DeterministicEncryptedType(EncryptedType):
    """Encrypts values using deterministic AEAD for equality lookups."""
    cache_ok = True

    def __init__(self, **kwargs: Any) -> None:
        if not DAEAD_AVAILABLE:
            raise ConfigurationError("Deterministic AEAD is not available in this Tink build.")
        super().__init__(**kwargs)

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        aad = self._call_aad(value, dialect, True)
        serialized = self._serialize(value)
        return self._keyset_manager.daead_primitive.encrypt_deterministically(serialized, aad)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        aad = self._call_aad(None, dialect, False)
        data = value.tobytes() if isinstance(value, memoryview) else bytes(value)
        decrypted = self._keyset_manager.daead_primitive.decrypt_deterministically(data, aad)
        return self._deserialize(decrypted)


def _serialize_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("Value must be a string.")
    return value


def _deserialize_text(value: str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, str):
        return value
    raise TypeError("Value must be str or bytes.")


def _serialize_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("Value must be bytes.")
    return value


def _deserialize_bytes(value: bytes) -> bytes:
    return value


class EncryptedString(EncryptedType):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(serializer=_serialize_text, deserializer=_deserialize_text, **kwargs)


class EncryptedJSON(EncryptedType):
    pass


class EncryptedBytes(EncryptedType):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(serializer=_serialize_bytes, deserializer=_deserialize_bytes, **kwargs)


class DeterministicEncryptedString(DeterministicEncryptedType):
    cache_ok = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(serializer=_serialize_text, deserializer=_deserialize_text, **kwargs)


class DeterministicEncryptedJSON(DeterministicEncryptedType):
    cache_ok = True
    pass


class DeterministicEncryptedBytes(DeterministicEncryptedType):
    cache_ok = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(serializer=_serialize_bytes, deserializer=_deserialize_bytes, **kwargs)
