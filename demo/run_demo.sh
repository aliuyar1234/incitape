#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$ROOT_DIR/demo"
OUT_DIR="$DEMO_DIR/out"

mkdir -p "$OUT_DIR"

TOKEN_FILE="$OUT_DIR/auth.token"
CERT_FILE="$OUT_DIR/tls.crt"
KEY_FILE="$OUT_DIR/tls.key"

rm -rf "$OUT_DIR/tape" "$OUT_DIR/tape.partial"

if [ ! -f "$TOKEN_FILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16 > "$TOKEN_FILE"
  else
    echo "openssl is required to generate auth token" >&2
    exit 1
  fi
fi

needs_cert=true
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    if openssl x509 -in "$CERT_FILE" -noout -text | grep -q "DNS:incitape-demo"; then
      needs_cert=false
    fi
  fi
fi

if [ "$needs_cert" = true ]; then
  if command -v openssl >/dev/null 2>&1; then
    OPENSSL_CNF="$OUT_DIR/openssl.cnf"
    cat > "$OPENSSL_CNF" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = incitape-demo

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = incitape
DNS.2 = incitape-demo
EOF
    rm -f "$CERT_FILE" "$KEY_FILE"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$KEY_FILE" -out "$CERT_FILE" \
      -days 1 -config "$OPENSSL_CNF"
  else
    echo "openssl is required to generate demo TLS cert" >&2
    exit 1
  fi
fi

export INCITAPE_AUTH_TOKEN="$(cat "$TOKEN_FILE")"
printf "INCITAPE_AUTH_TOKEN=%s\n" "$INCITAPE_AUTH_TOKEN" > "$OUT_DIR/collector.env"

pushd "$DEMO_DIR" >/dev/null

docker compose up -d --build incitape

INCITAPE_ID=""
for _ in {1..10}; do
  INCITAPE_ID="$(docker compose ps -q incitape)"
  if [ -n "$INCITAPE_ID" ]; then
    break
  fi
  sleep 1
done

if [ -z "$INCITAPE_ID" ]; then
  echo "incitape container not found; aborting demo" >&2
  docker compose down
  exit 1
fi

for _ in {1..10}; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$INCITAPE_ID")" = "true" ]; then
    break
  fi
  sleep 1
done

if [ "$(docker inspect -f '{{.State.Running}}' "$INCITAPE_ID")" != "true" ]; then
  echo "incitape container failed to start; aborting demo" >&2
  docker compose down
  exit 1
fi

docker compose up -d --build --no-deps collector jaeger frontend checkout payments

ready=false
for _ in {1..30}; do
  if docker compose run --rm --entrypoint /bin/sh loadgen -c "curl -sf http://frontend:8080/ > /dev/null"; then
    ready=true
    break
  fi
  sleep 1
done

if [ "$ready" != "true" ]; then
  echo "frontend did not become ready; aborting demo" >&2
  docker compose down
  exit 1
fi

docker compose run --rm loadgen

sleep 5

INCITAPE_ID="$(docker compose ps -q incitape)"
if [ -z "$INCITAPE_ID" ]; then
  echo "incitape container not found before shutdown; aborting demo" >&2
  docker compose down
  exit 1
fi

docker kill --signal=SIGINT "$INCITAPE_ID"
docker wait "$INCITAPE_ID" >/dev/null

docker compose down

popd >/dev/null

pushd "$ROOT_DIR" >/dev/null

cargo run -p incitape-cli -- analyze demo/out/tape --overwrite
cargo run -p incitape-cli -- report demo/out/tape --overwrite
cargo run -p incitape-cli -- validate demo/out/tape --strict

echo "Demo complete: demo/out/tape, analysis.json, report.md"

popd >/dev/null
