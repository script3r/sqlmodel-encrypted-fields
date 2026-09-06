"""Encrypted SQLModel field types using Google Tink AEAD."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Literal

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
    master_key_aead: aead.Aead | None = None
    cleartext: bool = False

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not self.path:
            raise ConfigurationError("Keyset path cannot be empty.")
        if not Path(self.path).is_file():
            raise ConfigurationError(f"Keyset {self.path} is not a file.")
        if not isinstance(self.cleartext, bool):
            raise ConfigurationError("`cleartext` must be a boolean.")
        if self.cleartext and self.master_key_aead is not None:
            raise ConfigurationError("Cleartext keysets cannot specify `master_key_aead`.")
        if not self.cleartext and self.master_key_aead is None:
            raise ConfigurationError("Encrypted keysets must specify `master_key_aead`.")


class KeysetRegistry:
    """Registry that owns keyset configuration and keyset handle cache."""

    def __init__(self, config: dict[str, dict[str, Any]]) -> None:
        self._lock = RLock()
        self._handle_cache: dict[str, Any] = {}
        self.set_config(config)

    @property
    def config(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {name: dict(options) for name, options in self._config.items()}

    def set_config(self, config: dict[str, dict[str, Any]]) -> None:
        """Replace configuration and invalidate handles, including existing fields."""
        snapshot = {name: dict(options) for name, options in config.items()}
        with self._lock:
            self._config = snapshot
            self._handle_cache.clear()

    def keyset_manager(self, keyset_name: str, aad_callback: Callable[..., Any]) -> KeysetManager:
        return KeysetManager(self, keyset_name, aad_callback)

    def encrypted_type(self, **kwargs: Any) -> EncryptedType:
        return EncryptedType(registry=self, **kwargs)

    def encrypted_string(self, **kwargs: Any) -> EncryptedString:
        return EncryptedString(registry=self, **kwargs)

    def encrypted_json(self, **kwargs: Any) -> EncryptedJSON:
        return EncryptedJSON(registry=self, **kwargs)

    def encrypted_bytes(self, **kwargs: Any) -> EncryptedBytes:
        return EncryptedBytes(registry=self, **kwargs)

    def deterministic_encrypted_type(self, **kwargs: Any) -> DeterministicEncryptedType:
        return DeterministicEncryptedType(registry=self, **kwargs)

    def deterministic_encrypted_string(self, **kwargs: Any) -> DeterministicEncryptedString:
        return DeterministicEncryptedString(registry=self, **kwargs)

    def deterministic_encrypted_json(self, **kwargs: Any) -> DeterministicEncryptedJSON:
        return DeterministicEncryptedJSON(registry=self, **kwargs)

    def deterministic_encrypted_bytes(self, **kwargs: Any) -> DeterministicEncryptedBytes:
        return DeterministicEncryptedBytes(registry=self, **kwargs)


class KeysetManager:
    def __init__(
        self, registry: KeysetRegistry, keyset_name: str, aad_callback: Callable[..., Any]
    ) -> None:
        self._registry = registry
        self.keyset_name = keyset_name
        self.aad_callback = aad_callback

    def _get_config(self) -> dict[str, dict[str, Any]]:
        if not self._registry.config:
            raise ConfigurationError(
                "Keysets are not configured. Provide a KeysetRegistry with config."
            )
        return self._registry.config

    def _get_keyset_handle(self) -> Any:
        # Loading and invalidation share a lock: a concurrent load must never
        # repopulate the cache with a handle from an obsolete configuration.
        with self._registry._lock:
            return self._load_keyset_handle()

    def _load_keyset_handle(self) -> Any:
        cached_handle = self._registry._handle_cache.get(self.keyset_name)
        if cached_handle is not None:
            return cached_handle
        config = self._get_config()
        if self.keyset_name not in config:
            raise ConfigurationError(f"Missing keyset configuration for '{self.keyset_name}'.")

        keyset_config = KeysetConfig(**config[self.keyset_name])

        with open(keyset_config.path, encoding="utf-8") as handle:
            reader = JsonKeysetReader(handle.read())
            if keyset_config.cleartext:
                keyset_handle = cleartext_keyset_handle.read(reader)
            else:
                keyset_handle = read_keyset_handle(reader, keyset_config.master_key_aead)

        self._registry._handle_cache[self.keyset_name] = keyset_handle
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
        registry: KeysetRegistry,
        keyset: str = DEFAULT_KEYSET,
        aad_callback: Callable[..., Any] = DEFAULT_AAD_CALLBACK,
        serializer: Callable[[Any], Any] = _json_serialize,
        deserializer: Callable[[Any], Any] = _json_deserialize,
        deserializer_input: Literal["text", "bytes"] = "text",
    ) -> None:
        super().__init__()
        if registry is None:
            raise ConfigurationError("Keyset registry is required.")
        if deserializer_input not in ("text", "bytes"):
            raise ConfigurationError("`deserializer_input` must be 'text' or 'bytes'.")
        if not callable(serializer) or not callable(deserializer):
            raise ConfigurationError("Serializer and deserializer must be callable.")
        try:
            signature = inspect.signature(aad_callback)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("AAD callback must have an inspectable signature.") from exc
        try:
            signature.bind(None, None, True)
            self._aad_accepts_context = True
        except TypeError:
            try:
                signature.bind()
            except TypeError as exc:
                raise ConfigurationError(
                    "AAD callback must accept zero or three positional arguments."
                ) from exc
            self._aad_accepts_context = False
        self.registry = registry
        self.keyset = keyset
        self.aad_callback = aad_callback
        self.serializer = serializer
        self.deserializer = deserializer
        self.deserializer_input = deserializer_input
        self._cache_token = object()
        self._keyset_manager = self.registry.keyset_manager(self.keyset, self.aad_callback)

    @property
    def _static_cache_key(self) -> tuple[Any, ...]:
        # SQLAlchemy's automatic key omits keyword-only / **kwargs parameters.
        # Identity also supports unhashable callable objects and mutable registries.
        # Dialect copies share this token and the same processing configuration.
        return (type(self), self._cache_token)

    def _call_aad(self, value: Any, dialect: Any, is_bind: bool) -> bytes:
        if self._aad_accepts_context:
            aad_value = self.aad_callback(value, dialect, is_bind)
        else:
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
        data = value.decode("utf-8") if self.deserializer_input == "text" else value
        return self.deserializer(data)

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
    cache_ok = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(serializer=_serialize_text, deserializer=_deserialize_text, **kwargs)


class EncryptedJSON(EncryptedType):
    cache_ok = True


class EncryptedBytes(EncryptedType):
    cache_ok = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            serializer=_serialize_bytes,
            deserializer=_deserialize_bytes,
            deserializer_input="bytes",
            **kwargs,
        )


class DeterministicEncryptedString(DeterministicEncryptedType):
    cache_ok = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(serializer=_serialize_text, deserializer=_deserialize_text, **kwargs)


class DeterministicEncryptedJSON(DeterministicEncryptedType):
    cache_ok = True


class DeterministicEncryptedBytes(DeterministicEncryptedType):
    cache_ok = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            serializer=_serialize_bytes,
            deserializer=_deserialize_bytes,
            deserializer_input="bytes",
            **kwargs,
        )
