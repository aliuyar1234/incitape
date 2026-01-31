#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 --fixture <tape_dir> --runs <n> [--baseline <path>]" >&2
  exit 1
}

FIXTURE=""
RUNS=""
BASELINE="perf/perf_baseline.json"
PYTHON_CMD=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture) FIXTURE="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --baseline) BASELINE="$2"; shift 2 ;;
    *) usage ;;
  esac
done

if [[ -z "$FIXTURE" || -z "$RUNS" ]]; then
  usage
fi

if command -v python >/dev/null 2>&1; then
  PYTHON_CMD=(python)
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD=(python3)
elif command -v py >/dev/null 2>&1; then
  PYTHON_CMD=(py -3)
else
  echo "python is required to run perf harness" >&2
  exit 1
fi

if [[ ! -d "$FIXTURE" ]]; then
  echo "Fixture directory not found: $FIXTURE" >&2
  exit 1
fi

mkdir -p perf

TAPE_DIR="$FIXTURE"
if [[ ! -f "$TAPE_DIR/manifest.yaml" ]]; then
  SUBDIR=$(find "$FIXTURE" -maxdepth 2 -type f -name manifest.yaml | head -n 1 | xargs -r dirname)
  if [[ -z "$SUBDIR" ]]; then
    echo "No tape_dir found under fixture: $FIXTURE" >&2
    exit 1
  fi
  TAPE_DIR="$SUBDIR"
fi

RESULTS=()
for i in $(seq 1 "$RUNS"); do
  start=$("${PYTHON_CMD[@]}" - <<'PY'
import time
print(int(time.time() * 1000))
PY
)
  cargo run -p incitape-cli -- analyze "$TAPE_DIR" --overwrite >/dev/null
  end=$("${PYTHON_CMD[@]}" - <<'PY'
import time
print(int(time.time() * 1000))
PY
)
  RESULTS+=("$((end - start))")
done

"${PYTHON_CMD[@]}" - <<PY
import json
import statistics
values = [int(v) for v in "${RESULTS[*]}".split() if v]
values.sort()
median = int(statistics.median(values))
p95 = values[int(len(values) * 0.95) - 1] if values else 0
out = {
    "fixture": "$FIXTURE",
    "runs": int("$RUNS"),
    "median_ms": median,
    "p95_ms": p95,
    "samples_ms": values,
}
print(json.dumps(out, indent=2))
with open("perf/perf_last_run.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
PY

if [[ -f "$BASELINE" ]]; then
  "${PYTHON_CMD[@]}" - <<PY
import json
import sys
with open("$BASELINE", "r", encoding="utf-8") as f:
    base = json.load(f)
with open("perf/perf_last_run.json", "r", encoding="utf-8") as f:
    cur = json.load(f)
ratio = base.get("tolerance_ratio", 2.0)
if cur["median_ms"] > base["median_ms"] * ratio:
    print("perf regression: median_ms exceeded tolerance")
    sys.exit(1)
if cur["p95_ms"] > base["p95_ms"] * ratio:
    print("perf regression: p95_ms exceeded tolerance")
    sys.exit(1)
print("perf ok")
PY
fi

