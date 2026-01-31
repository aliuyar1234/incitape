# Security Review (v1.0)

## Scope

Critical flows reviewed:
- record network exposure and auth/TLS enforcement
- tape parsing, bounds, and checksums
- redaction and leakage prevention
- AI report mode safety
- replay network emission

## Checklist (status and evidence)

- Network exposure policy enforced (loopback default; non-loopback requires TLS+auth).
  - Status: PASS (code + tests)
  - Evidence: `incitape/crates/incitape-core/src/config.rs`, `incitape/crates/incitape-cli/tests/record_security.rs`

- Redaction on ingest (regex + entropy) with stable replacement format.
  - Status: PASS (code + tests)
  - Evidence: `incitape/crates/incitape-redaction/src/redaction.rs`, `incitape/crates/incitape-redaction/src/otlp.rs`

- Leakage scanning and leakage=0 gate in eval/validate strict.
  - Status: PASS (code + CI wiring)
  - Evidence: `incitape/crates/incitape-eval/src/runner.rs`, `incitape/crates/incitape-cli/src/validate.rs`,
    `incitape/.github/workflows/ci.yml`

- Tape bounds and hostile input handling fail closed.
  - Status: PASS (code + tests)
  - Evidence: `incitape/crates/incitape-tape/src/reader.rs`, `incitape/crates/incitape-tape/tests/tape_reader.rs`

- AI report safety (optional, schema validated, no tools).
  - Status: PASS (code + tests)
  - Evidence: `incitape/crates/incitape-report/src/report.rs`, `incitape/crates/incitape-report/src/ai.rs`,
    `incitape/crates/incitape-report/schema/ai_report.schema.json`

- Replay uses explicit timeouts and no retries by default.
  - Status: PASS (code)
  - Evidence: `incitape/crates/incitape-replay/src/client.rs`, `incitape/crates/incitape-cli/src/main.rs`

## Review notes

- This review is based on code inspection and automated tests. Demo execution depends on Docker.
