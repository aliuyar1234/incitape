#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$ROOT_DIR/demo"
OUT_DIR="$DEMO_DIR/out"

mkdir -p "$OUT_DIR"

TOKEN_FILE="$OUT_DIR/auth.token"
CERT_FILE="$OUT_DIR/tls.crt"
KEY_FILE="$OUT_DIR/tls.key"

if [ -d "$OUT_DIR/tape" ]; then
  rm -rf "$OUT_DIR/tape"
fi

if [ ! -f "$TOKEN_FILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16 > "$TOKEN_FILE"
  else
    echo "openssl is required to generate auth token" >&2
    exit 1
  fi
fi

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$KEY_FILE" -out "$CERT_FILE" \
      -subj "/CN=incitape-demo" -days 1
  else
    echo "openssl is required to generate demo TLS cert" >&2
    exit 1
  fi
fi

export INCITAPE_AUTH_TOKEN="$(cat "$TOKEN_FILE")"

pushd "$DEMO_DIR" >/dev/null

docker compose up -d --build collector jaeger incitape frontend checkout payments
sleep 5

docker compose run --rm loadgen

sleep 25

docker compose down

popd >/dev/null

pushd "$ROOT_DIR" >/dev/null

cargo run -p incitape-cli -- analyze demo/out/tape --overwrite
cargo run -p incitape-cli -- report demo/out/tape --overwrite
cargo run -p incitape-cli -- validate demo/out/tape --strict

echo "Demo complete: demo/out/tape, analysis.json, report.md"

popd >/dev/null

