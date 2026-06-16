#!/usr/bin/env bash
#
# demo-noir-e2e.sh — End-to-end Noir proving demo for proveno.
#
# Pipeline:
#   1. Generate a Lua program with the orchestrator, execute it, and produce a
#      Noir UltraHonk proof (one `cargo run -p proveno-orchestrator -- … --prove --json`).
#   2. Deploy the on-chain stack (HonkVerifier + ProvenoVerifier + ProvenoConsumer) or
#      reuse already-deployed addresses passed through environment variables.
#   3. Call `ProvenoVerifier.verify(proof, inputs)` (view) on chain and require it
#      to return `true` — this is the headline assertion of the demo.
#   4. Build the canonical `outputPayload = abi.encode(int256(return_value))`
#      from the proof's own return value and call
#      `ProvenoConsumer.consumeResult(proof, inputs, outputPayload)`. The circuit
#      binds `outputHash` in-circuit to `keccak256(outputPayload)`, so this
#      check passes by construction.
#   5. Read back `lastResult` and print a one-line summary.
#
# Environment:
#   ANTHROPIC_API_KEY    required (used by the orchestrator for LLM generation)
#   RPC_URL              default: http://127.0.0.1:8545
#   PRIVATE_KEY          required (used for deploy and for the consumer cast send)
#   DEPLOY               1 to deploy a fresh stack via forge script, otherwise reuse env addrs
#   PROVENO_VERIFIER_ADDR   required if DEPLOY != 1
#   PROVENO_CONSUMER_ADDR   required if DEPLOY != 1
#   PROVE_OUTPUT         default: /tmp/proveno-demo  (where compiled.json/dry_result.json land)
#   CIRCUIT_DIR          default: noir            (path to the Noir circuit)
#
# Usage:
#   ./demo-noir-e2e.sh "<natural-language task>"
#   DEPLOY=1 RPC_URL=… PRIVATE_KEY=… ./demo-noir-e2e.sh
#
# See also: demo-noir-e2e-local.sh — wraps this script around a fresh local anvil.

set -euo pipefail

# ─── defaults ────────────────────────────────────────────────────────────────
DEFAULT_TASK='return a small JSON object {price=100, sources=1, ts=1700000000}'
TASK="${1:-$DEFAULT_TASK}"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PROVE_OUTPUT="${PROVE_OUTPUT:-/tmp/proveno-demo}"
CIRCUIT_DIR="${CIRCUIT_DIR:-noir}"
DEPLOY="${DEPLOY:-0}"

# ─── .env autoload ───────────────────────────────────────────────────────────
# The orchestrator binary reads .env via dotenvy, but this shell script's own
# prereq checks (e.g. ANTHROPIC_API_KEY below) run before the orchestrator
# starts, so we have to source .env here too. Looks for .env next to this
# script. Matches dotenvy semantics: existing environment variables win, so
# `KEY=… ./demo-noir-e2e.sh …` overrides what's in .env.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip blank lines and comments.
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        # Tolerate `export KEY=VALUE` form.
        line="${line#export }"
        key="${line%%=*}"
        # Skip malformed lines (no `=`) and keys already in the env with a
        # non-empty value. An exported-but-empty var (common in some shell
        # rc setups) should NOT block .env from filling it in.
        [[ "$key" == "$line" || -n "${!key:-}" ]] && continue
        export "$line"
    done < "$SCRIPT_DIR/.env"
fi

# ─── prerequisite checks ─────────────────────────────────────────────────────
require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command '$1' not found in PATH" >&2
        exit 1
    fi
}

require_cmd jq
require_cmd cast
require_cmd forge
require_cmd cargo

# ANTHROPIC_API_KEY is only needed for the orchestrator (LLM) generation path.
# When LUA_SOURCE is set, step 1 compiles a fixed Lua file instead — no LLM.
if [[ -z "${LUA_SOURCE:-}" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "error: ANTHROPIC_API_KEY must be set (or set LUA_SOURCE to skip the LLM)" >&2
    exit 1
fi

if [[ -n "${LUA_SOURCE:-}" && ! -f "$LUA_SOURCE" ]]; then
    echo "error: LUA_SOURCE='$LUA_SOURCE' not found" >&2
    exit 1
fi

if [[ "$DEPLOY" != "1" ]]; then
    if [[ -z "${PROVENO_VERIFIER_ADDR:-}" || -z "${PROVENO_CONSUMER_ADDR:-}" ]]; then
        echo "error: when DEPLOY != 1, both PROVENO_VERIFIER_ADDR and PROVENO_CONSUMER_ADDR must be set" >&2
        exit 1
    fi
fi

if [[ -z "${PRIVATE_KEY:-}" ]]; then
    echo "error: PRIVATE_KEY must be set (used for deploy and/or the consumer cast send)" >&2
    exit 1
fi

# Resolve repo root so we can run cargo / forge regardless of $CWD.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ─── 1. generate proof artifacts ─────────────────────────────────────────────
# Two backends, both producing the same JSON shape ({proving:{proof_bytes_hex,
# public_inputs[8]}, return_value}) at $ORCH_JSON:
#   - LUA_SOURCE set : compile a fixed Lua file (no LLM) and prove it.
#   - otherwise      : the orchestrator generates a program from $TASK via LLM.
mkdir -p "$PROVE_OUTPUT"
ORCH_JSON="$PROVE_OUTPUT/orchestrator.json"

if [[ -n "${LUA_SOURCE:-}" ]]; then
    echo "── [1/5] Generating Noir proof from fixed Lua source ──"
    echo "  source       : $LUA_SOURCE"
    # compile → dry-run → prove; progress to stderr so stdout stays pure JSON.
    cargo run --quiet -p proveno-compiler -- \
        "$LUA_SOURCE" "$PROVE_OUTPUT/compiled.json" >&2
    cargo run --quiet -p proveno_prover --bin proveno-prover -- \
        "$PROVE_OUTPUT/compiled.json" "$PROVE_OUTPUT/dry_result.json" >&2
    cargo run --quiet -p proveno-noir -- \
        "$PROVE_OUTPUT/compiled.json" "$PROVE_OUTPUT/dry_result.json" \
        --circuit-dir "$CIRCUIT_DIR" \
        --json \
        > "$ORCH_JSON"
else
    echo "── [1/5] Generating Noir proof via orchestrator ──"
    cargo run --quiet -p proveno-orchestrator -- \
        "$TASK" \
        --prove \
        --json \
        --prove-output "$PROVE_OUTPUT" \
        --circuit-dir "$CIRCUIT_DIR" \
        > "$ORCH_JSON"
fi

if ! jq -e '.proving.proof_bytes_hex' "$ORCH_JSON" > /dev/null; then
    echo "error: proof generation output missing proving.proof_bytes_hex; check $ORCH_JSON" >&2
    exit 1
fi

PROOF_HEX=$(jq -r '.proving.proof_bytes_hex' "$ORCH_JSON")
PI_HEX_0=$(jq -r '.proving.public_inputs[0]' "$ORCH_JSON")  # numSteps
PI_HEX_1=$(jq -r '.proving.public_inputs[1]' "$ORCH_JSON")  # programHash
PI_HEX_2=$(jq -r '.proving.public_inputs[2]' "$ORCH_JSON")  # returnValue
PI_HEX_3=$(jq -r '.proving.public_inputs[3]' "$ORCH_JSON")  # toolResponsesHash
PI_HEX_4=$(jq -r '.proving.public_inputs[4]' "$ORCH_JSON")  # inputHash
PI_HEX_5=$(jq -r '.proving.public_inputs[5]' "$ORCH_JSON")  # outputHash
PI_HEX_6=$(jq -r '.proving.public_inputs[6]' "$ORCH_JSON")  # attestationHash
PI_HEX_7=$(jq -r '.proving.public_inputs[7]' "$ORCH_JSON")  # policyHash
LUA_RETURN=$(jq -r '.return_value' "$ORCH_JSON")

# Decode numSteps (u32 bytes32 -> decimal) and returnValue (i64 bytes32 -> signed decimal).
NUM_STEPS=$(cast to-dec "$PI_HEX_0")
RETURN_VALUE=$(python3 - <<PY
hex_str = "${PI_HEX_2}"
v = int(hex_str, 16) & ((1 << 64) - 1)   # take low 8 bytes (i64)
if v >= (1 << 63):
    v -= (1 << 64)
print(v)
PY
)

if [[ -n "${LUA_SOURCE:-}" ]]; then
    echo "  lua source   : $LUA_SOURCE"
else
    echo "  task         : $TASK"
fi
echo "  lua return   : $LUA_RETURN"
echo "  num_steps    : $NUM_STEPS"
echo "  policy hash  : $PI_HEX_7"
echo "  output_hash  : $PI_HEX_5"
echo "  proof bytes  : $(( (${#PROOF_HEX} - 2) / 2 ))"

# ─── 2. deploy or reuse contracts ────────────────────────────────────────────
if [[ "$DEPLOY" == "1" ]]; then
    echo "── [2/5] Deploying HonkVerifier + ProvenoVerifier + ProvenoConsumer ──"
    DEPLOY_LOG="$PROVE_OUTPUT/deploy.log"
    # --disable-code-size-limit is required because the generated HonkVerifier
    # is ~34 KB, well over EIP-170's 24576-byte ceiling. Deploying to mainnet
    # would also require a chain that relaxes (or proxies around) that limit;
    # on anvil the demo pairs this with `--code-size-limit` on the node.
    POLICY_HASH="$PI_HEX_7" forge script contracts/script/Deploy.s.sol \
        --root contracts \
        --rpc-url "$RPC_URL" \
        --private-key "$PRIVATE_KEY" \
        --broadcast \
        --disable-code-size-limit \
        > "$DEPLOY_LOG" 2>&1 || {
            echo "error: forge script Deploy.s.sol failed; see $DEPLOY_LOG" >&2
            tail -n 40 "$DEPLOY_LOG" >&2
            exit 1
        }

    PROVENO_VERIFIER_ADDR=$(grep -E '^\s*ProvenoVerifier:' "$DEPLOY_LOG" | tail -n1 | awk '{print $NF}')
    PROVENO_CONSUMER_ADDR=$(grep -E '^\s*ProvenoConsumer:' "$DEPLOY_LOG" | tail -n1 | awk '{print $NF}')

    if [[ -z "$PROVENO_VERIFIER_ADDR" || -z "$PROVENO_CONSUMER_ADDR" ]]; then
        echo "error: could not parse deployed addresses from $DEPLOY_LOG" >&2
        tail -n 40 "$DEPLOY_LOG" >&2
        exit 1
    fi
    echo "  ProvenoVerifier : $PROVENO_VERIFIER_ADDR"
    echo "  ProvenoConsumer : $PROVENO_CONSUMER_ADDR"
else
    echo "── [2/5] Reusing deployed addresses ──"
    echo "  ProvenoVerifier : $PROVENO_VERIFIER_ADDR"
    echo "  ProvenoConsumer : $PROVENO_CONSUMER_ADDR"
fi

# ─── 3. on-chain proof verification ──────────────────────────────────────────
echo "── [3/5] On-chain ProvenoVerifier.verify(proof, inputs) ──"

INPUTS_TUPLE="($NUM_STEPS,$PI_HEX_1,$RETURN_VALUE,$PI_HEX_3,$PI_HEX_4,$PI_HEX_5,$PI_HEX_6,$PI_HEX_7)"
VERIFY_SIG='verify(bytes,(uint32,bytes32,int64,bytes32,bytes32,bytes32,bytes32,bytes32))(bool)'

VERIFY_OK=$(cast call \
    --rpc-url "$RPC_URL" \
    "$PROVENO_VERIFIER_ADDR" \
    "$VERIFY_SIG" \
    "$PROOF_HEX" \
    "$INPUTS_TUPLE")

if [[ "$VERIFY_OK" != "true" ]]; then
    echo "error: ProvenoVerifier.verify returned $VERIFY_OK (expected true)" >&2
    exit 1
fi
echo "  ✓ proof verified on chain (ProvenoVerifier.verify -> true)"

# ─── 4. consumer flow ────────────────────────────────────────────────────────
echo "── [4/5] ProvenoConsumer.consumeResult(proof, inputs, outputPayload) ──"

# Canonical output payload: abi.encode(int256(return_value)). The circuit bound
# outputHash = keccak256(this) in-circuit, so the consumer's check passes.
OUTPUT_PAYLOAD=$(cast abi-encode 'f(int256)' "$RETURN_VALUE")
EXPECTED_KECCAK=$(cast keccak "$OUTPUT_PAYLOAD")

echo "  outputPayload : $OUTPUT_PAYLOAD"
echo "  keccak256     : $EXPECTED_KECCAK"
echo "  outputHash    : $PI_HEX_5"

CONSUMER_SIG='consumeResult(bytes,(uint32,bytes32,int64,bytes32,bytes32,bytes32,bytes32,bytes32),bytes)'

set +e
CONSUMER_OUT=$(cast send \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    "$PROVENO_CONSUMER_ADDR" \
    "$CONSUMER_SIG" \
    "$PROOF_HEX" \
    "$INPUTS_TUPLE" \
    "$OUTPUT_PAYLOAD" 2>&1)
CONSUMER_STATUS=$?
set -e

CONSUMER_SUCCEEDED=0
if [[ $CONSUMER_STATUS -eq 0 ]]; then
    echo "  ✓ consumeResult succeeded"
    CONSUMER_SUCCEEDED=1
else
    echo "  ⚠ consumeResult failed:" >&2
    echo "$CONSUMER_OUT" | tail -n 20 >&2
fi

# ─── 5. read back consumer state ─────────────────────────────────────────────
echo "── [5/5] Reading ProvenoConsumer state ──"

LAST_RESULT=$(cast call --rpc-url "$RPC_URL" "$PROVENO_CONSUMER_ADDR" 'lastResult()(int256)' || echo "")

echo "  lastResult : $LAST_RESULT"

# ─── summary ─────────────────────────────────────────────────────────────────
echo
if [[ $CONSUMER_SUCCEEDED -eq 1 ]]; then
    echo "✓ demo OK — proof verified on chain; consumer stored lastResult = $LAST_RESULT"
else
    echo "✗ demo FAILED — proof verified on chain but consumeResult reverted" >&2
    exit 1
fi
