# Changelog

## 0.2.0 — 2026-09-06

### Security and correctness

- Isolate SQLAlchemy statement-cache entries by encrypted field identity so
  compiled statements cannot reuse another field's keys, AAD, or serializers.
- Invalidate handles for existing fields when registry configuration changes;
  synchronize cache loading with invalidation and defensively copy configuration.
- Resolve AAD callback signatures before invocation. Internal callback errors
  propagate instead of retrying with no context. Reject `None` AAD results.
- Replace exception-driven deserializer retries with explicit text/bytes input.
- Reject ambiguous cleartext/master-key settings and directory keyset paths.
- Close FastAPI sessions after each request; repair Flask 3 app initialization,
  validate Flask input, and isolate example metadata during combined tests.

### Maintenance and release

- Support Python 3.10–3.14 with current SQLModel, SQLAlchemy 2.0, and Tink.
- Include FastAPI and Flask integration tests in the default suite; add regression
  coverage for key rotation, cache isolation, tampering, AAD, and database queries.
- Add linting, formatting, coverage, dependency auditing, and installed-wheel checks.
- Replace broken release automation with tested tag-based builds, matching version
  validation, GitHub artifacts, and PyPI trusted publishing.
- Correct project metadata, include the MIT license, and document key management,
  deterministic lookup limits, serializer contracts, and migration.

### Compatibility

Python 3.9 is no longer supported. Custom deserializers now receive UTF-8 text by
default; binary deserializers must select `deserializer_input="bytes"`. AAD callbacks
must return bytes or text, not `None`. Update registries through `set_config()`.
The existing ciphertext format remains unchanged. Deterministic primary-key
rotation still requires migrating stored ciphertext before equality lookups can
match older rows.
