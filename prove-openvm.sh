#!/usr/bin/env bash
# Prove a Lua script with the OpenVM backend, end to end, in one command.
#
#   ./prove-openvm.sh myscript.lua                              # app STARK
#   ./prove-openvm.sh myscript.lua --stark                      # aggregated STARK
#   ./prove-openvm.sh myscript.lua --policy policies/test-policy.json
#
# --policy takes a built-in profile name or a JSON file. It is passed to BOTH
# the dry run (which enforces it) and the guest input (which commits its hash),
# so the two cannot drift.
#
# Runs: compile -> dry run -> guest input -> prove -> verify, and leaves every
# artifact under target/openvm/<name>.*
#
# Needs `cargo openvm` (cargo-openvm). Proving keys are generated on first use
# and cached in openvm/ (gitignored): app.pk/app.vk for the app level, plus
# agg_prefix.pk for --stark.
set -euo pipefail

PROG="${1:-}"
if [ -z "$PROG" ] || [ "$PROG" = "--help" ] || [ "$PROG" = "-h" ]; then
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
[ -f "$PROG" ] || { echo "no such file: $PROG" >&2; exit 1; }
PROG="$(cd "$(dirname "$PROG")" && pwd)/$(basename "$PROG")"

shift
LEVEL=app
POLICY=
while [ $# -gt 0 ]; do
    case "$1" in
        --stark)  LEVEL=stark ;;
        --policy) shift; POLICY="${1:?--policy requires a value}" ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

cd "$(dirname "$0")"
NAME="$(basename "$PROG" .lua)"
OUT=target/openvm
mkdir -p "$OUT"

if ! command -v cargo-openvm >/dev/null 2>&1; then
    echo "cargo-openvm not found on PATH. Install it, then re-run." >&2
    exit 1
fi

# Keys are a one-off per VM config, so generate on first use rather than making
# the caller remember. `--app-only` skips the aggregation key, which only the
# stark level needs.
if [ "$LEVEL" = stark ] && [ ! -f openvm/agg_prefix.pk ]; then
    echo "==> generating proving keys (app + aggregation, one-off)"
    cargo openvm keygen
elif [ ! -f openvm/app.pk ]; then
    echo "==> generating proving keys (app only, one-off)"
    cargo openvm keygen --app-only
fi

echo "==> compiling $(basename "$PROG")"
cargo run -q -p proveno-compiler -- "$PROG" "$OUT/$NAME.compiled.json"

echo "==> dry run (records the oracle tape)"
WITNESS_ARGS=("$OUT/$NAME.compiled.json" "$OUT/$NAME.dry.json")
[ -n "$POLICY" ] && WITNESS_ARGS+=(--policy "$POLICY")
cargo run -q -p proveno-witness -- "${WITNESS_ARGS[@]}"

echo "==> building guest input and proving ($LEVEL)"
ARGS=(--out "$OUT/$NAME.input.json" --proof "$OUT/$NAME.$LEVEL.proof" --prove)
[ "$LEVEL" = stark ] && ARGS+=(--stark)
[ -n "$POLICY" ] && ARGS+=(--policy "$POLICY")
cargo run -q -p proveno-openvm-host -- \
    "$OUT/$NAME.compiled.json" "$OUT/$NAME.dry.json" "${ARGS[@]}"

echo
echo "Artifacts in $OUT/:"
ls -la "$OUT/$NAME."* | awk '{printf "  %-10s %s\n", $5, $9}'
