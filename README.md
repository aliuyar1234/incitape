# IncidentTape (incitape)

IncidentTape captures OTLP telemetry into deterministic tape artifacts and produces deterministic RCA outputs.

## Build

- Debug:
  - `cargo build --locked`
- Release:
  - `cargo build --locked --release`

## Test

- `cargo test --locked`

## Quickstart

- Show CLI help:
  - `cargo run -p incitape-cli -- --help`
- Generate a synthetic suite and run eval:
  - `cargo run -p incitape-cli -- eval generate --suite eval/suites/synthetic-smoke.yaml --out eval_out/smoke`
  - `cargo run -p incitape-cli -- eval run --suite eval/suites/synthetic-smoke.yaml --out eval_out/eval.json`

## CLI Examples

- record:
  - `cargo run -p incitape-cli -- record --out ./tapes/demo --duration 10`
- replay:
  - `cargo run -p incitape-cli -- replay ./tapes/demo --to http://127.0.0.1:4317 --speed 0`
- analyze:
  - `cargo run -p incitape-cli -- analyze ./tapes/demo --overwrite`
- report:
  - `cargo run -p incitape-cli -- report ./tapes/demo --overwrite`
  - Optional AI (requires config):
    - `cargo run -p incitape-cli -- --config ./config.yaml report ./tapes/demo --ai --overwrite`
    - Deterministic AI (best-effort): add `--ai-deterministic`
    - Strict AI (fail on AI errors): add `--ai-strict`
- eval:
  - `cargo run -p incitape-cli -- eval generate --suite eval/suites/synthetic-smoke.yaml --out eval_out/smoke`
  - `cargo run -p incitape-cli -- eval run --suite eval/suites/synthetic-smoke.yaml --out eval_out/eval.json`
- validate:
  - `cargo run -p incitape-cli -- validate ./tapes/demo --strict`
- minimize:
  - `cargo run -p incitape-cli -- minimize ./tapes/demo --out ./tapes/demo-min --overwrite`

## Demo

- One-command demo:
  - `./demo/run_demo.sh`

## Performance

- Run perf harness:
  - `./scripts/perf_analyze.sh --fixture eval/fixtures/perf_medium --runs 5`

## Docs

- Runbook: `../spec/12_RUNBOOK.md`
- Release checklist: `RELEASE_CHECKLIST.md`
- Security review: `SECURITY_REVIEW.md`
