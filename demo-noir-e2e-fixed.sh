#!/usr/bin/env bash
#
# demo-noir-e2e-fixed.sh — Full-chain Noir e2e demo from a FIXED Lua program.
#
# Identical pipeline to demo-noir-e2e.sh (compile → dry-run → Noir UltraHonk
# proof → deploy → on-chain ProvenoVerifier.verify → ProvenoConsumer.consumeResult),
# but step 1 compiles a fixed Lua file instead of asking the LLM to write one.
# No ANTHROPIC_API_KEY required.
#
# Usage:
#   ./demo-noir-e2e-fixed.sh [path/to/program.lua]
#
#   With no argument it uses the bundled sample examples/simple.lua.
#
# Chain selection:
#   - Default (no RPC_URL set): spins up a throwaway local anvil and deploys a
#     fresh stack, via demo-noir-e2e-local.sh. One command, nothing external.
#   - If RPC_URL is set: delegates to demo-noir-e2e.sh against that chain. You
#     control deploy/reuse with DEPLOY / PROVENO_VERIFIER_ADDR /
#     PROVENO_CONSUMER_ADDR / PRIVATE_KEY exactly as for demo-noir-e2e.sh.
#
# All other env overrides honoured by demo-noir-e2e.sh (PROVE_OUTPUT,
# CIRCUIT_DIR) are respected.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Fixed Lua program: $1 or the bundled sample. examples/simple.lua returns
# f(5)=120 — a pure integer, deterministic, no tool calls or network.
LUA_SOURCE="${1:-examples/simple.lua}"

if [[ ! -f "$LUA_SOURCE" ]]; then
    echo "error: Lua source '$LUA_SOURCE' not found" >&2
    exit 1
fi

export LUA_SOURCE

if [[ -n "${RPC_URL:-}" ]]; then
    echo "── fixed-Lua demo against RPC_URL=$RPC_URL ──"
    exec "$REPO_ROOT/demo-noir-e2e.sh"
else
    echo "── fixed-Lua demo against a fresh local anvil (DEPLOY=1) ──"
    exec "$REPO_ROOT/demo-noir-e2e-local.sh"
fi
