# Architecture (detailed)

This document is the detailed architecture reference for IncidentTape (`incitape`).

If you only want a quick orientation, see `../README.md` (Architecture overview).

## Overview diagram

```mermaid
flowchart LR
  CLI["incitape CLI (incitape-cli)"]
  TAPE[(tape_dir/)]

  REC["record (incitape-recorder)\nOTLP gRPC + OTLP HTTP server"]
  REP["replay (incitape-replay)\nOTLP gRPC client"]

  ANA["analyze (incitape-analyzer)\ntraces-first deterministic RCA"]
  RPT["report (incitape-report)\ndeterministic markdown (+ optional AI)"]
  VAL["validate (incitape-cli + tape)\nlayout + checksums + bounds"]
  MIN["minimize (incitape-minimize)\nsubset + derived_from"]
  EVAL["eval (incitape-eval)\nsynthetic + scoring + gates"]

  CLI --> REC
  CLI --> REP
  CLI --> ANA
  CLI --> RPT
  CLI --> VAL
  CLI --> MIN
  CLI --> EVAL

  REC --> TAPE
  TAPE --> REP
  TAPE --> ANA
  ANA --> RPT
  TAPE --> VAL
  TAPE --> MIN
  TAPE --> EVAL
```

## Dependency layers

The intended dependency direction is "downwards" (high-level components depend on tape/core, never the other way around):

```mermaid
flowchart TB
  CLI["incitape-cli\n(binary: incitape)"]

  REC["incitape-recorder"]
  REP["incitape-replay"]
  ANA["incitape-analyzer"]
  MIN["incitape-minimize"]
  RPT["incitape-report"]
  EVAL["incitape-eval"]

  TAPE["incitape-tape"]
  REDACT["incitape-redaction"]
  CORE["incitape-core"]

  CLI --> REC
  CLI --> REP
  CLI --> ANA
  CLI --> MIN
  CLI --> RPT
  CLI --> EVAL

  REC --> REDACT
  REC --> TAPE
  REP --> TAPE
  ANA --> TAPE
  MIN --> ANA
  MIN --> TAPE
  RPT --> ANA
  RPT --> REDACT
  RPT --> TAPE
  EVAL --> ANA
  EVAL --> REDACT
  EVAL --> TAPE

  TAPE --> CORE
  REDACT --> CORE
```

## Pipelines

### Record pipeline (networked)

```mermaid
flowchart LR
  CLIENT["Telemetry sender"]
  AUTH["TLS + bearer auth (required for non-loopback)"]
  OTLP["OTLP decode (bounded)"]
  REDACT["Redaction-on-ingest"]
  WRITE["TapeWriter\n(tape.tape.zst in <out>.partial/)"]
  FINALIZE["Finalize\n(tape_id + manifest.yaml + checksums.sha256)"]
  COMMIT["Atomic rename\n<out>.partial -> <out>/"]

  CLIENT --> AUTH --> OTLP --> REDACT --> WRITE --> FINALIZE --> COMMIT
```

Fail-closed highlights:
- Non-loopback bind without TLS+auth -> refuse to start (exit code 4).
- Oversized inputs / bounds violations / decode errors -> reject (no partial writes).
- Redaction failure -> abort (exit code 5).

### Replay pipeline (networked)

```mermaid
flowchart LR
  TAPE["tape_dir/"]
  VALIDATE["Checksums + bounds + framing"]
  ORDER["Canonical record order\n(time, type, payload_sha256)"]
  FILTER["Optional filter"]
  SPEED["Speed control"]
  EXPORT["OTLP gRPC export\n(timeouts, no retries by default)"]

  TAPE --> VALIDATE --> ORDER --> FILTER --> SPEED --> EXPORT
```

### Analyze pipeline (offline-first)

```mermaid
flowchart LR
  TAPE["tape_dir/"]
  VALIDATE["Checksums + bounds + framing"]
  TRACES["Trace decode\n(traces-first)"]
  GRAPH["Service graph"]
  FEAT["Robust features\n(latency/error/throughput)"]
  RANK["Deterministic ranking\n(stable tie-break)"]
  OUT["analysis.json\n(canonical JSON + determinism_hash)"]

  TAPE --> VALIDATE --> TRACES --> GRAPH --> FEAT --> RANK --> OUT
```

### Report pipeline (offline-first, optional local AI)

```mermaid
flowchart LR
  INPUT["tape_dir/ + analysis.json"]
  RENDER["Deterministic renderer"]
  REPORT["report.md"]

  INPUT --> RENDER --> REPORT

  subgraph AI["Optional AI section (report-only)"]
    PACK["Build evidence pack\n(bounded + sanitized)"]
    CALL["Local Ollama HTTP\n(loopback-only)"]
    SCHEMA["Schema validate\n(fail -> fallback)"]
  end

  INPUT --> PACK --> CALL --> SCHEMA --> RENDER
```

### Validate pipeline (offline-first)

```mermaid
flowchart LR
  TAPE["tape_dir/"]
  LAYOUT["Layout check\n(required files present)"]
  CHECKSUMS["checksums.sha256 verify"]
  FORMAT["Tape framing + bounds"]
  MANIFEST["manifest.yaml schema + tape_id match"]
  STRICT["--strict:\nleakage scan + security refusals"]

  TAPE --> LAYOUT --> CHECKSUMS --> FORMAT --> MANIFEST --> STRICT
```

### Minimize pipeline (offline-first)

```mermaid
flowchart LR
  TAPE["tape_dir/"]
  LOAD["Load analysis.json\n(or analyze if missing)"]
  PICK["Pick evidence traces\n(top-k + keep-window)"]
  REWRITE["Rewrite minimized tape\n(optionally drop logs/metrics)"]
  DERIVED["Write derived manifest\n(derived_from set) + checksums"]

  TAPE --> LOAD --> PICK --> REWRITE --> DERIVED
```

### Eval pipeline (offline-first)

```mermaid
flowchart LR
  SUITE["Suite YAML"]
  GEN["eval generate\n(deterministic seeds)"]
  TAPES["Labeled tapes\n(ground_truth in manifest)"]
  RUN["eval run\n(analyzer + baselines)"]
  METRICS["Metrics + gates\n(leakage=0, thresholds, determinism)"]
  OUT["eval.json\n(canonical JSON)"]

  SUITE --> GEN --> TAPES --> RUN --> METRICS --> OUT
```

## Crate map

| Crate | Responsibility |
|---|---|
| `incitape-cli` | CLI entrypoint (binary is `incitape`) |
| `incitape-core` | Error model, config, canonical JSON helpers |
| `incitape-tape` | Tape format, bounds, checksums, tape_id |
| `incitape-redaction` | Redaction ruleset + entropy detector + OTLP redaction |
| `incitape-recorder` | OTLP servers (gRPC/HTTP), auth/TLS enforcement, redaction-on-ingest, atomic finalize |
| `incitape-replay` | Deterministic replay + exporter |
| `incitape-analyzer` | Traces-first deterministic RCA |
| `incitape-eval` | Suite generator + scorer + regression gates |
| `incitape-report` | Deterministic report + optional schema-validated local AI |
| `incitape-minimize` | Produce smaller derived tapes |

## Related docs

- Release checklist: `../RELEASE_CHECKLIST.md`
- Security review: `../SECURITY_REVIEW.md`
