# Release Checklist (v1.0)

This checklist defines the acceptance run required before marking DONE.

## Core gates (run from repo root)

- Toolchain and tests:
  - `cargo fmt --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test --locked`
- Boundary fitness:
  - `cargo run -p boundary-check`
- Eval gates:
  - `cargo run -p incitape-cli -- eval generate --suite eval/suites/synthetic-smoke.yaml --out eval_out/smoke --overwrite`
  - `cargo run -p incitape-cli -- eval run --suite eval/suites/synthetic-smoke.yaml --out eval_out/eval.json --overwrite`
  - `cargo run -p incitape-cli -- eval generate --suite eval/suites/secret-injection.yaml --out eval_out/secret --overwrite`
  - `cargo run -p incitape-cli -- eval run --suite eval/suites/secret-injection.yaml --out eval_out/secret_eval.json --overwrite`
- Validate strict:
  - `cargo run -p incitape-cli -- validate eval_out/smoke/error-chain --strict`
- Determinism spot checks:
  - Run analyze twice on a fixture and compare `analysis.json` bytes.
  - Run eval run twice on a suite and compare `eval.json` bytes.
- Demo:
  - `./demo/run_demo.sh`
- Perf harness:
  - `./scripts/perf_analyze.sh --fixture eval/fixtures/perf_medium --runs 5`
- Supply chain:
  - `cargo audit`
  - `cargo deny check licenses`

## Cross-platform smoke (manual)

- Windows:
  - `cargo build --locked`
  - `cargo test --locked`
  - `cargo run -p incitape-cli -- analyze eval/fixtures/perf_medium/tape --overwrite`
- macOS:
  - `cargo build --locked`
  - `cargo test --locked`
  - `cargo run -p incitape-cli -- analyze eval/fixtures/perf_medium/tape --overwrite`

## Acceptance run record (fill in on release)

- date:
- operator:
- git commit:
- notes:
