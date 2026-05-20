#!/usr/bin/env bash
# zkvm-prove.sh — full luai ZK proving pipeline (app + EVM/Groth16)
#
# Stages:
#   1. Compile Lua source to bytecode JSON
#   2. Dry-run with live HTTP + policy enforcement → dry_result.json
#   3. Encode inputs for OpenVM guest
#   4. Simulate guest circuit (openvm run)
#   5. Prove with AggStark (openvm prove app)
#   6. Keygen for EVM/Groth16 (once; skipped if pk exists)
#   7. Prove EVM/Groth16 → proof.json
#   8. Package into luai wire-format bundle (luai-proof.bin)
#
# Usage:
#   bash zkvm-prove.sh [LUA_SRC] [POLICY]
#
#   LUA_SRC  path to Lua source file   (default: examples/prover.lua)
#   POLICY   policy profile name        (default: template_price_feed_v1)
#
# Outputs:
#   luai-proof.bin  — wire-format proof bundle (in openvm/)
#   proof size and public inputs are printed to stdout for use with `cast`
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUA_SRC="${1:-${REPO_ROOT}/examples/prover.lua}"
POLICY="${2:-template_price_feed_v1}"

COMPILED=/tmp/luai-compiled.json
DRY_RESULT=/tmp/luai-dry-result.json
OPENVM_INPUT=/tmp/openvm-1.json
EVM_PROOF_JSON=${REPO_ROOT}/openvm/proof.json
BUNDLE=${REPO_ROOT}/openvm/luai-proof.bin

echo "=== luai ZK Proving Pipeline ==="
echo "Lua source : ${LUA_SRC}"
echo "Policy     : ${POLICY}"
echo ""

# ── 1. Compile ──────────────────────────────────────────────────────────────
echo "[1/8] Compiling Lua source..."
(cd "${REPO_ROOT}" && cargo run -p luai-compiler --quiet -- "${LUA_SRC}" "${COMPILED}")
echo "      compiled → ${COMPILED}"

# ── 2. Dry-run ───────────────────────────────────────────────────────────────
echo "[2/8] Dry-run with policy ${POLICY}..."
T0=$SECONDS
(cd "${REPO_ROOT}" && cargo run -p luai-prover --quiet -- \
    "${COMPILED}" "${DRY_RESULT}" --policy "${POLICY}")
echo "      dry-run → ${DRY_RESULT}  ($(( SECONDS - T0 ))s)"

# ── 3. Encode for OpenVM ─────────────────────────────────────────────────────
echo "[3/8] Encoding inputs for OpenVM guest..."
(cd "${REPO_ROOT}/openvm" && cargo run --bin luai-openvm-encoder --quiet -- \
    "${COMPILED}" "${DRY_RESULT}")
echo "      encoded → ${OPENVM_INPUT}"

# ── 4. Simulate circuit ───────────────────────────────────────────────────────
echo "[4/8] Simulating OpenVM circuit..."
(cd "${REPO_ROOT}/openvm" && cargo openvm run --bin luai-openvm --input "${OPENVM_INPUT}")
echo "      simulation OK"

# ── 5. Prove app (AggStark) ───────────────────────────────────────────────────
echo "[5/8] App proving (AggStark)..."
(cd "${REPO_ROOT}/openvm" && cargo openvm keygen)
T0=$SECONDS
(cd "${REPO_ROOT}/openvm" && cargo openvm prove app --bin luai-openvm --input "${OPENVM_INPUT}")
(cd "${REPO_ROOT}/openvm" && cargo openvm verify app --proof luai-openvm.app.proof)
echo "      app proof verified  ($(( SECONDS - T0 ))s)"

# ── 6. Keygen for EVM/Groth16 (skip if already generated) ────────────────────
EVM_PK="${REPO_ROOT}/openvm/luai-openvm.evm.pk"
if [ ! -f "${EVM_PK}" ]; then
    echo "[6/8] Generating EVM proving key (one-time, may take several minutes)..."
    T0=$SECONDS
    (cd "${REPO_ROOT}/openvm" && cargo openvm keygen --evm)
    echo "      EVM keygen done  ($(( SECONDS - T0 ))s)"
else
    echo "[6/8] EVM proving key exists — skipping keygen"
fi

# ── 7. Prove EVM (Groth16) ────────────────────────────────────────────────────
echo "[7/8] EVM/Groth16 proving..."
T0=$SECONDS
(cd "${REPO_ROOT}/openvm" && \
    cargo openvm prove evm --bin luai-openvm --input "${OPENVM_INPUT}" --output proof.json)
echo "      EVM proof written → ${EVM_PROOF_JSON}  ($(( SECONDS - T0 ))s)"

# ── 8. Package ────────────────────────────────────────────────────────────────
echo "[8/8] Packaging wire-format bundle..."
(cd "${REPO_ROOT}/openvm" && \
    cargo run --bin luai-openvm-packager --quiet -- \
        --evm-json proof.json "${DRY_RESULT}" luai-proof.bin)

PROOF_SIZE=$(wc -c < "${BUNDLE}")
echo ""
echo "=== Results ==="
echo "proof size:    ${PROOF_SIZE} bytes  (luai-proof.bin)"

# Re-print packager output for the cast tuple
(cd "${REPO_ROOT}/openvm" && \
    cargo run --bin luai-openvm-packager --quiet -- \
        --evm-json proof.json "${DRY_RESULT}" /dev/null) 2>/dev/null || true

echo ""
echo "Wire-format proof: ${PROOF_SIZE} bytes"
echo "Done. Submit luai-proof.bin on-chain with LuaiVerifier.verify()."
