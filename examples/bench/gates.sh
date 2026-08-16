#!/usr/bin/env bash
# Report the gate count of the currently-compiled circuit.
#
# Gate count is a pure function of the circuit source (the MAX_* constants).
# It does NOT depend on any program, input, or witness. This is the
# input-independent cost truth.
#
# Usage: gates.sh
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

ACIR="noir/target/trace_verifier.json"
[ -f "$ACIR" ] || { echo "no compiled circuit at $ACIR; run nargo compile" >&2; exit 1; }

MAX_STEPS=$(grep -oE 'MAX_STEPS: u32 = [0-9]+' noir/src/main.nr | grep -oE '[0-9]+$')
OUT=$(cd noir && bb gates -b target/trace_verifier.json 2>/dev/null)
ACIR_OPS=$(echo "$OUT" | grep -o '"acir_opcodes": [0-9]*' | grep -o '[0-9]*')
GATES=$(echo "$OUT" | grep -o '"circuit_size": [0-9]*' | grep -o '[0-9]*')

printf 'MAX_STEPS=%-8s acir_opcodes=%-9s circuit_size(gates)=%s\n' \
    "$MAX_STEPS" "$ACIR_OPS" "$GATES"
