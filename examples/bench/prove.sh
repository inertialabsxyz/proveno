#!/usr/bin/env bash
# Full pipeline with timing for one program at the CURRENT circuit ceiling:
# compile -> dry-run -> witness -> nargo execute -> bb prove -> bb verify.
# Prints prove wall-time and the current circuit's gate count.
#
# The circuit must already be compiled at a ceiling >= the program's num_steps
# (use set_ceiling.sh first). Usage: prove.sh <program.lua>
set -euo pipefail
PROG="${1:?usage: prove.sh <program.lua>}"
PROG="$(cd "$(dirname "$PROG")" && pwd)/$(basename "$PROG")"
cd "$(dirname "$0")/../.."   # repo root

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CJ="$TMP/c.json"; DJ="$TMP/d.json"

cargo run -q -p proveno-compiler -- "$PROG" "$CJ" >/dev/null 2>&1
cargo run -q -p proveno-witness -- "$CJ" "$DJ" >/dev/null 2>&1

MAX_STEPS=$(grep -oE 'MAX_STEPS: u32 = [0-9]+' noir/src/main.nr | grep -oE '[0-9]+$')
GATES=$(cd noir && bb gates -b target/trace_verifier.json 2>/dev/null | grep -o '"circuit_size": [0-9]*' | grep -o '[0-9]*')

# Time the full prove+verify (proveno-noir prints "Proof generated in X.Xs").
START=$(python3 -c 'import time;print(time.time())')
OUT=$(cargo run -q -p proveno-noir -- "$CJ" "$DJ" --circuit-dir noir --prove 2>&1) || { echo "$OUT" >&2; exit 1; }
END=$(python3 -c 'import time;print(time.time())')
WALL=$(python3 -c "print(f'{$END-$START:.1f}')")

PROVE=$(echo "$OUT" | grep -o 'Proof generated in [0-9.]*s' | grep -o '[0-9.]*' | head -1)
VERIFIED=$(echo "$OUT" | grep -q 'verified' && echo yes || echo "?")

printf '%-22s ceiling=%-7s gates=%-9s prove=%ss e2e_wall=%ss verified=%s\n' \
  "$(basename "$PROG")" "$MAX_STEPS" "$GATES" "${PROVE:-?}" "$WALL" "$VERIFIED"
