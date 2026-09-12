#!/usr/bin/env bash
# Run every examples/*.lua through the full OpenVM pipeline and report where
# each one gets to: compile -> dry run -> replay -> prove -> verify.
#
#   ./prove-examples.sh            # app STARK
#   ./prove-examples.sh --stark    # aggregated STARK
#   ./prove-examples.sh --dir examples/bench
#
# Reports per-stage outcome rather than pass/fail, because the interesting
# information is *which* stage stops a program. Scripts that call live tools
# (http_get) need network; scripts calling tools ProverHost does not implement
# stop at the dry run by design, not because proving is broken.
set -uo pipefail

LEVEL=app
DIR=examples
while [ $# -gt 0 ]; do
    case "$1" in
        --stark) LEVEL=stark ;;
        --dir)   shift; DIR="${1:?--dir requires a value}" ;;
        -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

cd "$(dirname "$0")"
OUT=target/openvm-examples
mkdir -p "$OUT"

command -v cargo-openvm >/dev/null 2>&1 || { echo "cargo-openvm not on PATH" >&2; exit 1; }
if [ "$LEVEL" = stark ] && [ ! -f openvm/agg_prefix.pk ]; then
    cargo openvm keygen >/dev/null 2>&1
elif [ ! -f openvm/app.pk ]; then
    cargo openvm keygen --app-only >/dev/null 2>&1
fi

BASELINE=openvm/release/proveno-openvm.baseline.json
now() { python3 -c 'import time;print(time.time())'; }
secs() { python3 -c "print(f'{$2-$1:.1f}')"; }

printf '%-26s %-8s %-8s %-8s %-8s %-8s %10s %8s  %s\n' \
    PROGRAM COMPILE DRYRUN REPLAY PROVE VERIFY INSTR PROVE_S NOTE
printf '%.0s-' {1..118}; echo

PASS=0; STOPPED=0
for PROG in "$DIR"/*.lua; do
    NAME="$(basename "$PROG" .lua)"
    B="$OUT/$NAME"
    C=- ; D=- ; R=- ; P=- ; V=- ; INSTR=- ; PT=- ; NOTE=

    if cargo run -q -p proveno-compiler -- "$PROG" "$B.compiled.json" >"$B.log" 2>&1; then
        C=ok
    else
        C=FAIL; NOTE=$(grep -m1 -oE '[A-Za-z]+Error[^,}]*|error: .*' "$B.log" | head -1)
    fi

    if [ "$C" = ok ]; then
        if cargo run -q -p proveno-witness -- "$B.compiled.json" "$B.dry.json" >"$B.log" 2>&1; then
            D=ok
        else
            D=FAIL; NOTE=$(grep -m1 -oE 'Unknown tool[^"]*|[A-Za-z]+Error[^,}]*|error: .*' "$B.log" | head -1)
        fi
    fi

    if [ "$D" = ok ]; then
        ARGS=(--out "$B.input.json" --proof "$B.$LEVEL.proof" --prove)
        [ "$LEVEL" = stark ] && ARGS+=(--stark)
        S=$(now)
        if cargo run -q -p proveno-openvm-host -- "$B.compiled.json" "$B.dry.json" "${ARGS[@]}" >"$B.log" 2>&1; then
            R=ok; P=ok; V=ok
        else
            # The driver replays before proving, so distinguish the two.
            if grep -q "host replay failed\|replay diverged" "$B.log"; then
                R=FAIL
            else
                R=ok; P=FAIL
            fi
            NOTE=$(grep -m1 -oE 'error: .*' "$B.log" | head -1 | cut -c1-44)
        fi
        E=$(now); PT=$(secs "$S" "$E")
        INSTR=$(RUST_LOG=info cargo openvm run -p proveno-openvm --input "$B.input.json" 2>&1 \
                | grep -o 'instructions_executed=[0-9]*' | grep -o '[0-9]*' | head -1)
        INSTR="${INSTR:--}"
    fi

    [ "$V" = ok ] && PASS=$((PASS+1)) || STOPPED=$((STOPPED+1))
    printf '%-26s %-8s %-8s %-8s %-8s %-8s %10s %8s  %s\n' \
        "$(basename "$PROG")" "$C" "$D" "$R" "$P" "$V" "$INSTR" "$PT" "${NOTE:0:40}"
done

echo
echo "$PASS proved and verified, $STOPPED stopped earlier (level=$LEVEL)"
