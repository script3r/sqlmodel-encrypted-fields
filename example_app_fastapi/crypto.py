from __future__ import annotations

from pathlib import Path

from sqlmodel_encrypted_fields import KeysetRegistry


def _default_config() -> dict[str, dict[str, object]]:
    root = Path(__file__).resolve().parents[1]
    return {
        "default": {"path": str(root / "tests" / "fixtures" / "aead_keyset.json"), "cleartext": True},
        "deterministic": {
            "path": str(root / "tests" / "fixtures" / "daead_keyset.json"),
            "cleartext": True,
        },
    }


registry = KeysetRegistry(_default_config())
