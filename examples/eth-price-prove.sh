#!/usr/bin/env bash
#
# eth-price-prove.sh — drive the full prove/verify pipeline on examples/eth_price.lua.
#
#   compile (Lua → bytecode) → dry-run (live http_get, oracle tape + public
#   inputs) → Noir UltraHonk prove + verify.
#
# Deterministic and fast (~3-4s prove). Requires `nargo` and `bb` on PATH.
#
# Recording tip: run `cargo build -p proveno-compiler -p proveno_prover \
#   -p proveno-noir` once first, so `cargo run --quiet` does NOT recompile (and
#   therefore prints no warnings) during the take.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SRC="examples/eth_price.lua"
OUT="${OUT:-/tmp/proveno-eth}"
mkdir -p "$OUT"

echo "── 1/3 · compile ──────────────────────────────────────────"
cargo run --quiet -p proveno-compiler -- "$SRC" "$OUT/compiled.json"

echo "── 2/3 · dry-run (live http_get → oracle tape) ────────────"
cargo run --quiet -p proveno_prover --bin proveno-prover -- \
    "$OUT/compiled.json" "$OUT/dry_result.json"

echo "── 3/3 · prove + verify (Noir UltraHonk) ──────────────────"
cargo run --quiet -p proveno-noir -- \
    "$OUT/compiled.json" "$OUT/dry_result.json" --prove
