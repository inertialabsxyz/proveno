#!/usr/bin/env bash
#
# demo-noir-e2e.sh — End-to-end Noir proving demo for luai.
#
# Pipeline:
#   1. Generate a Lua program with the orchestrator, execute it, and produce a
#      Noir UltraHonk proof (one `cargo run -p luai-orchestrator -- … --prove --json`).
#   2. Deploy the on-chain stack (HonkVerifier + LuaiVerifier + LuaiConsumer) or
#      reuse already-deployed addresses passed through environment variables.
#   3. Call `LuaiVerifier.verify(proof, inputs)` (view) on chain and require it
#      to return `true` — this is the headline assertion of the demo.
#   4. Build an `outputPayload = abi.encode(uint256 price, uint8 sourcesUsed,
#      uint64 blockTimestamp)` from the demo defaults (or user-provided env)
#      and call `LuaiConsumer.consumeResult(proof, inputs, outputPayload)`.
#   5. Read back `lastPrice`, `lastSourcesUsed`, `lastBlockTimestamp` and print
#      a one-line summary.
#
# Encoding-bridge note (read this before running for real):
#   `LuaiConsumer.consumeResult` enforces
#       keccak256(outputPayload) == inputs.outputHash
#   The luai circuit currently commits `outputHash` as
#       SHA-256(canonical_serialize(return_value) || logs || transcript)
#   Producing a Lua program whose `outputHash` matches `keccak256(outputPayload)`
#   requires an encoding bridge that is the Lua program author's responsibility
#   and is not yet supplied by the pipeline. Until that bridge exists, the
#   `consumeResult` step is expected to revert with `OutputPayloadMismatch`.
#   The script catches that revert, reports it explicitly, and still exits 0
#   if the on-chain `LuaiVerifier.verify` succeeded — verifying the proof on
#   chain is what this demo is here to prove.
#
# Environment:
#   ANTHROPIC_API_KEY    required (used by the orchestrator for LLM generation)
#   RPC_URL              default: http://127.0.0.1:8545
#   PRIVATE_KEY          required (used for deploy and for the consumer cast send)
#   DEPLOY               1 to deploy a fresh stack via forge script, otherwise reuse env addrs
#   LUAI_VERIFIER_ADDR   required if DEPLOY != 1
#   LUAI_CONSUMER_ADDR   required if DEPLOY != 1
#   PROVE_OUTPUT         default: /tmp/luai-demo  (where compiled.json/dry_result.json land)
#   CIRCUIT_DIR          default: noir            (path to the Noir circuit)
#   DEMO_PRICE           default: 100000000000000000000 (= 100e18 in wei-scaled price)
#   DEMO_SOURCES         default: 1
#   DEMO_TS              default: 1700000000
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
PROVE_OUTPUT="${PROVE_OUTPUT:-/tmp/luai-demo}"
CIRCUIT_DIR="${CIRCUIT_DIR:-noir}"
DEPLOY="${DEPLOY:-0}"

DEMO_PRICE="${DEMO_PRICE:-100000000000000000000}"
DEMO_SOURCES="${DEMO_SOURCES:-1}"
DEMO_TS="${DEMO_TS:-1700000000}"

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

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "error: ANTHROPIC_API_KEY must be set" >&2
    exit 1
fi

if [[ "$DEPLOY" != "1" ]]; then
    if [[ -z "${LUAI_VERIFIER_ADDR:-}" || -z "${LUAI_CONSUMER_ADDR:-}" ]]; then
        echo "error: when DEPLOY != 1, both LUAI_VERIFIER_ADDR and LUAI_CONSUMER_ADDR must be set" >&2
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
echo "── [1/5] Generating Noir proof via orchestrator ──"
mkdir -p "$PROVE_OUTPUT"
ORCH_JSON="$PROVE_OUTPUT/orchestrator.json"

cargo run --quiet -p luai-orchestrator -- \
    "$TASK" \
    --prove \
    --json \
    --prove-output "$PROVE_OUTPUT" \
    --circuit-dir "$CIRCUIT_DIR" \
    > "$ORCH_JSON"

if ! jq -e '.proving.proof_bytes_hex' "$ORCH_JSON" > /dev/null; then
    echo "error: orchestrator output missing proving.proof_bytes_hex; check $ORCH_JSON" >&2
    exit 1
fi

PROOF_HEX=$(jq -r '.proving.proof_bytes_hex' "$ORCH_JSON")
PI_HEX_0=$(jq -r '.proving.public_inputs[0]' "$ORCH_JSON")  # numSteps
PI_HEX_1=$(jq -r '.proving.public_inputs[1]' "$ORCH_JSON")  # programHash
PI_HEX_2=$(jq -r '.proving.public_inputs[2]' "$ORCH_JSON")  # returnValue
PI_HEX_3=$(jq -r '.proving.public_inputs[3]' "$ORCH_JSON")  # toolResponsesHash
PI_HEX_4=$(jq -r '.proving.public_inputs[4]' "$ORCH_JSON")  # inputHash
PI_HEX_5=$(jq -r '.proving.public_inputs[5]' "$ORCH_JSON")  # outputHash
PI_HEX_6=$(jq -r '.proving.public_inputs[6]' "$ORCH_JSON")  # tlsAttestationHash
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

echo "  task         : $TASK"
echo "  lua return   : $LUA_RETURN"
echo "  num_steps    : $NUM_STEPS"
echo "  policy hash  : $PI_HEX_7"
echo "  output_hash  : $PI_HEX_5"
echo "  proof bytes  : $(( (${#PROOF_HEX} - 2) / 2 ))"

# ─── 2. deploy or reuse contracts ────────────────────────────────────────────
if [[ "$DEPLOY" == "1" ]]; then
    echo "── [2/5] Deploying HonkVerifier + LuaiVerifier + LuaiConsumer ──"
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

    LUAI_VERIFIER_ADDR=$(grep -E '^\s*LuaiVerifier:' "$DEPLOY_LOG" | tail -n1 | awk '{print $NF}')
    LUAI_CONSUMER_ADDR=$(grep -E '^\s*LuaiConsumer:' "$DEPLOY_LOG" | tail -n1 | awk '{print $NF}')

    if [[ -z "$LUAI_VERIFIER_ADDR" || -z "$LUAI_CONSUMER_ADDR" ]]; then
        echo "error: could not parse deployed addresses from $DEPLOY_LOG" >&2
        tail -n 40 "$DEPLOY_LOG" >&2
        exit 1
    fi
    echo "  LuaiVerifier : $LUAI_VERIFIER_ADDR"
    echo "  LuaiConsumer : $LUAI_CONSUMER_ADDR"
else
    echo "── [2/5] Reusing deployed addresses ──"
    echo "  LuaiVerifier : $LUAI_VERIFIER_ADDR"
    echo "  LuaiConsumer : $LUAI_CONSUMER_ADDR"
fi

# ─── 3. on-chain proof verification ──────────────────────────────────────────
echo "── [3/5] On-chain LuaiVerifier.verify(proof, inputs) ──"

INPUTS_TUPLE="($NUM_STEPS,$PI_HEX_1,$RETURN_VALUE,$PI_HEX_3,$PI_HEX_4,$PI_HEX_5,$PI_HEX_6,$PI_HEX_7)"
VERIFY_SIG='verify(bytes,(uint32,bytes32,int64,bytes32,bytes32,bytes32,bytes32,bytes32))(bool)'

VERIFY_OK=$(cast call \
    --rpc-url "$RPC_URL" \
    "$LUAI_VERIFIER_ADDR" \
    "$VERIFY_SIG" \
    "$PROOF_HEX" \
    "$INPUTS_TUPLE")

if [[ "$VERIFY_OK" != "true" ]]; then
    echo "error: LuaiVerifier.verify returned $VERIFY_OK (expected true)" >&2
    exit 1
fi
echo "  ✓ proof verified on chain (LuaiVerifier.verify -> true)"

# ─── 4. consumer flow ────────────────────────────────────────────────────────
echo "── [4/5] LuaiConsumer.consumeResult(proof, inputs, outputPayload) ──"

OUTPUT_PAYLOAD=$(cast abi-encode 'f(uint256,uint8,uint64)' "$DEMO_PRICE" "$DEMO_SOURCES" "$DEMO_TS")
EXPECTED_KECCAK=$(cast keccak "$OUTPUT_PAYLOAD")

echo "  outputPayload : $OUTPUT_PAYLOAD"
echo "  keccak256     : $EXPECTED_KECCAK"
echo "  outputHash    : $PI_HEX_5"

CONSUMER_SIG='consumeResult(bytes,(uint32,bytes32,int64,bytes32,bytes32,bytes32,bytes32,bytes32),bytes)'

set +e
CONSUMER_OUT=$(cast send \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    "$LUAI_CONSUMER_ADDR" \
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
elif echo "$CONSUMER_OUT" | grep -qi 'OutputPayloadMismatch'; then
    echo "  ⚠ consumeResult reverted with OutputPayloadMismatch — expected when the"
    echo "    Lua program does not provide the keccak256-encoded outputHash bridge."
    echo "    The proof itself verified on chain above; this is a known consumer-side gap."
else
    echo "  ⚠ consumeResult failed:" >&2
    echo "$CONSUMER_OUT" | tail -n 20 >&2
fi

# ─── 5. read back consumer state ─────────────────────────────────────────────
echo "── [5/5] Reading LuaiConsumer state ──"

LAST_PRICE=$(cast call --rpc-url "$RPC_URL" "$LUAI_CONSUMER_ADDR" 'lastPrice()(uint256)' || echo "")
LAST_SRCS=$(cast call  --rpc-url "$RPC_URL" "$LUAI_CONSUMER_ADDR" 'lastSourcesUsed()(uint8)'  || echo "")
LAST_TS=$(cast call    --rpc-url "$RPC_URL" "$LUAI_CONSUMER_ADDR" 'lastBlockTimestamp()(uint64)' || echo "")

echo "  lastPrice          : $LAST_PRICE"
echo "  lastSourcesUsed    : $LAST_SRCS"
echo "  lastBlockTimestamp : $LAST_TS"

# ─── summary ─────────────────────────────────────────────────────────────────
echo
if [[ $CONSUMER_SUCCEEDED -eq 1 ]]; then
    echo "✓ demo OK — proof verified on chain; consumer updated to ($LAST_PRICE, $LAST_SRCS, $LAST_TS)"
else
    echo "✓ demo OK — proof verified on chain; consumer step pending encoding bridge"
fi
