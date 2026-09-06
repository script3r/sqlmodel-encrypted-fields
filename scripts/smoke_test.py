"""Exercise an installed distribution without importing the source checkout."""

import sys
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory

import tink
from tink import aead, cleartext_keyset_handle, daead

import sqlmodel_encrypted_fields
from sqlmodel_encrypted_fields import KeysetRegistry


def main() -> None:
    assert version("sqlmodel-encrypted-fields") == sys.argv[1]
    assert (
        Path(__file__).resolve().parents[1] not in Path(sqlmodel_encrypted_fields.__file__).parents
    )
    aead.register()
    daead.register()
    with TemporaryDirectory() as directory:
        config = {}
        for name, template in [
            ("default", aead.aead_key_templates.AES256_GCM),
            ("deterministic", daead.deterministic_aead_key_templates.AES256_SIV),
        ]:
            path = Path(directory) / f"{name}.json"
            with path.open("w") as stream:
                cleartext_keyset_handle.write(
                    tink.JsonKeysetWriter(stream), tink.new_keyset_handle(template)
                )
            config[name] = {"path": str(path), "cleartext": True}
        registry = KeysetRegistry(config)
        for field in [
            registry.encrypted_string(),
            registry.deterministic_encrypted_string(keyset="deterministic"),
        ]:
            encrypted = field.process_bind_param("installed package works", None)
            assert field.process_result_value(encrypted, None) == "installed package works"
    print(f"Installed release {sys.argv[1]} passed encryption smoke tests")


if __name__ == "__main__":
    main()
