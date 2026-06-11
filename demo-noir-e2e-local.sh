#!/usr/bin/env bash
#
# demo-noir-e2e-local.sh — Run the Noir e2e demo against a fresh local anvil.
#
# Spins up a temporary `anvil` instance (chain id 31337) in the background,
# sets RPC_URL / PRIVATE_KEY / DEPLOY=1, and then defers to demo-noir-e2e.sh
# for the actual pipeline. Anvil is torn down on exit regardless of result.
#
# Usage:
#   ANTHROPIC_API_KEY=… ./demo-noir-e2e-local.sh "<natural-language task>"
#
# All environment overrides accepted by demo-noir-e2e.sh (PROVE_OUTPUT,
# CIRCUIT_DIR, DEMO_PRICE, DEMO_SOURCES, DEMO_TS) are respected.

set -euo pipefail

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command '$1' not found in PATH" >&2
        exit 1
    fi
}

require_cmd anvil

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Use a random high port to avoid clashing with an already-running anvil.
PORT=$(( ( RANDOM % 10000 ) + 30000 ))
ANVIL_LOG="${PROVE_OUTPUT:-/tmp/proveno-demo}/anvil.log"
mkdir -p "$(dirname "$ANVIL_LOG")"

# Default anvil account #0 — well-known dev key, never use on a live chain.
LOCAL_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

cleanup() {
    if [[ -n "${ANVIL_PID:-}" ]] && kill -0 "$ANVIL_PID" 2>/dev/null; then
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "── starting anvil on 127.0.0.1:$PORT ──"
# --code-size-limit raises EIP-170 above the default 24576 bytes; the generated
# HonkVerifier is ~33KB and otherwise fails to deploy on a stock anvil.
anvil --port "$PORT" --code-size-limit 65536 --silent > "$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!

# Wait for anvil to become responsive.
for _ in $(seq 1 50); do
    if cast block-number --rpc-url "http://127.0.0.1:$PORT" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! cast block-number --rpc-url "http://127.0.0.1:$PORT" >/dev/null 2>&1; then
    echo "error: anvil did not become responsive; see $ANVIL_LOG" >&2
    tail -n 40 "$ANVIL_LOG" >&2
    exit 1
fi

export RPC_URL="http://127.0.0.1:$PORT"
export PRIVATE_KEY="$LOCAL_KEY"
export DEPLOY=1

# Use a normal call (not exec) so the EXIT trap still tears down anvil.
"$REPO_ROOT/demo-noir-e2e.sh" "$@"
