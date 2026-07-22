#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Building geth ==="
go build -o ./build/bin/geth ./cmd/geth

echo "=== Starting dev node (chainID=1337, Prague enabled) ==="
exec ./build/bin/geth \
  --dev \
  --dev.period 1 \
  --http \
  --http.port 18545 \
  --http.api eth,net,web3,txpool \
  --verbosity 3 \
  "$@"
