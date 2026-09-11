#!/usr/bin/env bash
# Full OpenVM pipeline with timing for one program:
# compile -> dry-run -> guest input -> app STARK prove -> verify.
#
# The OpenVM counterpart to prove.sh. The cost metric differs: Noir's circuit is
# a padded ceiling, so its gate count depends only on MAX_STEPS and its prove
# time is the same for every program that fits. OpenVM has no such ceiling — it
# proves the instructions actually executed, so `instructions_executed` is the
# cost driver and prove time tracks it.
#
# Two proof levels, per OpenVM's own terminology:
#   app    the application STARK (default here)
#   stark  those app segments aggregated recursively into one root STARK
# (`evm` wraps the latter in a Halo2 SNARK for on-chain verification.)
#
# Requires cargo-openvm plus a one-off keygen:
#   app level:   cargo openvm keygen --app-only   (writes app.pk, app.vk)
#   stark level: cargo openvm keygen              (also writes agg_prefix.pk)
#
# Usage: prove_openvm.sh <program.lua> [--stark]
set -euo pipefail
PROG="${1:?usage: prove_openvm.sh <program.lua> [--stark]}"
PROG="$(cd "$(dirname "$PROG")" && pwd)/$(basename "$PROG")"
LEVEL=app
[ "${2:-}" = "--stark" ] && LEVEL=stark
cd "$(dirname "$0")/../.."   # repo root

if [ ! -f openvm/app.pk ]; then
    echo "missing openvm/app.pk — run: cargo openvm keygen --app-only" >&2
    exit 1
fi
if [ "$LEVEL" = stark ] && [ ! -f openvm/agg_prefix.pk ]; then
    echo "missing openvm/agg_prefix.pk — run: cargo openvm keygen (without --app-only)" >&2
    exit 1
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CJ="$TMP/c.json"; DJ="$TMP/d.json"; IN="$TMP/in.json"; PF="$TMP/p.proof"

now() { python3 -c 'import time;print(time.time())'; }
secs() { python3 -c "print(f'{$2-$1:.1f}')"; }

if ! cargo run -q -p proveno-compiler -- "$PROG" "$CJ" >/dev/null 2>"$TMP/err"; then
    printf '%-22s COMPILE_FAIL\n' "$(basename "$PROG")"; cat "$TMP/err" >&2; exit 1
fi
if ! cargo run -q -p proveno-witness -- "$CJ" "$DJ" >/dev/null 2>"$TMP/err"; then
    printf '%-22s DRYRUN_FAIL\n' "$(basename "$PROG")"; cat "$TMP/err" >&2; exit 1
fi
if ! cargo run -q -p proveno-openvm-host -- "$CJ" "$DJ" --out "$IN" >"$TMP/host" 2>&1; then
    printf '%-22s REPLAY_FAIL\n' "$(basename "$PROG")"; cat "$TMP/host" >&2; exit 1
fi
DIGEST=$(grep -o 'Expected journal digest: [0-9a-f]*' "$TMP/host" | awk '{print $4}')
GAS=$(grep -o '"gas_used":[0-9]*' "$DJ" | head -1 | cut -d: -f2)

# instructions_executed is only emitted at info level, and only by `run`.
INSTR=$(RUST_LOG=info cargo openvm run -p proveno-openvm --input "$IN" 2>&1 \
        | grep -o 'instructions_executed=[0-9]*' | grep -o '[0-9]*' | head -1)

S=$(now)
cargo openvm prove "$LEVEL" -p proveno-openvm --input "$IN" --proof "$PF" >"$TMP/prove" 2>&1 \
    || { printf '%-22s PROVE_FAIL\n' "$(basename "$PROG")"; tail -20 "$TMP/prove" >&2; exit 1; }
E=$(now); PROVE=$(secs "$S" "$E")

# `verify stark` derives the baseline path from the binary target name and
# guesses the root package, so point it at the real file.
VERIFY_ARGS=(--proof "$PF")
[ "$LEVEL" = stark ] && VERIFY_ARGS+=(--app-baseline openvm/release/proveno-openvm.baseline.json)

S=$(now)
VERIFIED=no
cargo openvm verify "$LEVEL" "${VERIFY_ARGS[@]}" >"$TMP/verify" 2>&1 && VERIFIED=yes
E=$(now); VERIFY=$(secs "$S" "$E")

SIZE=$(wc -c < "$PF" | tr -d ' ')

printf '%-22s level=%-6s instr=%-9s gas=%-9s prove=%ss verify=%ss proof=%sB verified=%s digest=%s\n' \
  "$(basename "$PROG")" "$LEVEL" "${INSTR:-?}" "${GAS:-?}" "$PROVE" "$VERIFY" "$SIZE" "$VERIFIED" "${DIGEST:0:16}"
