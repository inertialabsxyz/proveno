#!/usr/bin/env bash
# Measure a program's trace length (num_steps) and gas WITHOUT proving.
#
# num_steps is the input-dependent truth: it is the actual number of VM
# instructions executed, and it must be <= MAX_STEPS for a proof to exist.
# This script reports it even when the program overflows the current ceiling
# (the witness builder reports the exact length in its TraceTooLong error).
#
# Usage: steps.sh <program.lua>
set -euo pipefail

PROG="${1:?usage: steps.sh <program.lua>}"
PROG="$(cd "$(dirname "$PROG")" && pwd)/$(basename "$PROG")"   # absolutize before cd
cd "$(dirname "$0")/../.."   # repo root
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CJ="$TMP/compiled.json"
DJ="$TMP/dry.json"

# 1. compile (fails loudly if the Lua doesn't compile)
if ! cargo run -q -p proveno-compiler -- "$PROG" "$CJ" >/dev/null 2>"$TMP/cerr"; then
    echo "COMPILE_FAIL"; cat "$TMP/cerr" >&2; exit 1
fi

# 2. dry-run -> gas + empty oracle tape
cargo run -q -p proveno-witness -- "$CJ" "$DJ" >/dev/null 2>&1
GAS=$(grep -o '"gas_used":[0-9]*' "$DJ" | head -1 | cut -d: -f2)
MEM=$(grep -o '"memory_used":[0-9]*' "$DJ" | head -1 | cut -d: -f2)

# 3. build witness (no prove). Either writes Prover.toml (=> grep num_steps)
#    or errors "trace length N exceeds MAX_STEPS" (=> extract N).
set +e
OUT=$(cargo run -q -p proveno-noir -- "$CJ" "$DJ" --circuit-dir noir 2>&1)
RC=$?
set -e

if echo "$OUT" | grep -q "exceeds MAX_STEPS"; then
    STEPS=$(echo "$OUT" | grep -o 'trace length [0-9]*' | grep -o '[0-9]*')
    FITS="NO (exceeds current MAX_STEPS)"
elif [ $RC -eq 0 ]; then
    STEPS=$(grep -E '^num_steps' noir/Prover.toml | grep -o '[0-9]\+' | head -1)
    FITS="yes"
else
    echo "WITNESS_FAIL"; echo "$OUT" >&2; exit 1
fi

printf '%-40s steps=%-8s gas=%-9s mem=%-9s fits=%s\n' \
    "$(basename "$PROG")" "$STEPS" "${GAS:-?}" "${MEM:-?}" "$FITS"
