#!/usr/bin/env bash
#
# demo-bounty.sh — End-to-end verifiable-task bounty demo for proveno.
#
# The hero artifact: a requester posts a bounty committing the exact program
# hash of a proveno task and escrows ETH; an agent runs that task, generates a
# Noir UltraHonk proof, claims the bounty with the proof, the on-chain Bounty
# contract verifies it, and the agent is paid — all on a local anvil.
#
# Pipeline:
#   1. Generate a Noir proof for $LUA_SOURCE (compile -> dry-run -> proveno-noir
#      --json). programHash is public input index 1.
#   2. Deploy the on-chain stack (HonkVerifier + ProvenoVerifier + ProvenoConsumer
#      + Bounty) or reuse an already-deployed Bounty address from the environment.
#   3. As the poster (PRIVATE_KEY), call Bounty.postBounty(programHash) escrowing
#      the reward; capture the bounty id.
#   4. As the solver (SOLVER_KEY, a different account), record its balance, call
#      Bounty.claim(id, proof, inputs), then read its balance again.
#   5. Assert: BountyClaimed emitted, the bounty is now claimed, and the solver
#      balance rose by exactly reward - gas. Print a one-line success summary.
#
# Environment:
#   ANTHROPIC_API_KEY    required UNLESS LUA_SOURCE is set (no LLM in LUA_SOURCE mode)
#   LUA_SOURCE           default: examples/usdc_depeg.lua  (fixed Lua, no LLM)
#   RPC_URL              default: http://127.0.0.1:8545
#   PRIVATE_KEY          required — the poster/deployer (anvil account 0)
#   SOLVER_KEY           default: anvil account 1 — the agent that claims the bounty
#   REWARD               default: 1000000000000000000 (1 ETH, in wei) escrowed by the poster
#   DEPLOY               1 to deploy a fresh stack via forge script, otherwise reuse env addr
#   BOUNTY_ADDR          required if DEPLOY != 1
#   PROVE_OUTPUT         default: /tmp/proveno-demo  (where artifacts land)
#   CIRCUIT_DIR          default: noir            (path to the Noir circuit)
#
# Usage:
#   LUA_SOURCE=examples/usdc_depeg.lua ./demo-bounty.sh
#   DEPLOY=1 RPC_URL=… PRIVATE_KEY=… ./demo-bounty.sh
#
# See also: demo-bounty-local.sh — wraps this script around a fresh local anvil.

set -euo pipefail

# ─── defaults ────────────────────────────────────────────────────────────────
DEFAULT_TASK='return a small JSON object {price=100, sources=1, ts=1700000000}'
TASK="${1:-$DEFAULT_TASK}"

# Default to the proven depeg task so the demo runs without an LLM out of the box.
LUA_SOURCE="${LUA_SOURCE:-examples/usdc_depeg.lua}"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PROVE_OUTPUT="${PROVE_OUTPUT:-/tmp/proveno-demo}"
CIRCUIT_DIR="${CIRCUIT_DIR:-noir}"
DEPLOY="${DEPLOY:-0}"
REWARD="${REWARD:-1000000000000000000}"  # 1 ETH in wei

# Default solver = anvil account 1 (distinct from the account-0 poster), so the
# payout is visible as a balance change on a different address.
SOLVER_KEY="${SOLVER_KEY:-0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d}"

# ─── .env autoload ───────────────────────────────────────────────────────────
# Mirror demo-noir-e2e.sh: source .env next to this script so the shell's own
# prereq checks see the same vars the binaries read via dotenvy. Existing
# environment variables win.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        line="${line#export }"
        key="${line%%=*}"
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
require_cmd python3

if [[ -n "${LUA_SOURCE:-}" && ! -f "$LUA_SOURCE" ]]; then
    echo "error: LUA_SOURCE='$LUA_SOURCE' not found" >&2
    exit 1
fi

# ANTHROPIC_API_KEY is only needed for the orchestrator (LLM) generation path.
# With LUA_SOURCE set (the default), step 1 compiles a fixed Lua file — no LLM.
if [[ -z "${LUA_SOURCE:-}" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "error: ANTHROPIC_API_KEY must be set (or set LUA_SOURCE to skip the LLM)" >&2
    exit 1
fi

if [[ -z "${PRIVATE_KEY:-}" ]]; then
    echo "error: PRIVATE_KEY must be set (the poster/deployer)" >&2
    exit 1
fi

if [[ "$DEPLOY" != "1" && -z "${BOUNTY_ADDR:-}" ]]; then
    echo "error: when DEPLOY != 1, BOUNTY_ADDR must be set" >&2
    exit 1
fi

# Resolve repo root so we can run cargo / forge regardless of $CWD.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

SOLVER_ADDR=$(cast wallet address --private-key "$SOLVER_KEY")
REWARD_ETH=$(cast to-unit "$REWARD" ether)

# ─── 1. generate proof artifacts ─────────────────────────────────────────────
mkdir -p "$PROVE_OUTPUT"
ORCH_JSON="$PROVE_OUTPUT/orchestrator.json"

if [[ -n "${LUA_SOURCE:-}" ]]; then
    echo "── [1/5] Generating Noir proof from fixed Lua source ──"
    echo "  source       : $LUA_SOURCE"
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

PROGRAM_HASH="$PI_HEX_1"
echo "  lua return   : $LUA_RETURN"
echo "  num_steps    : $NUM_STEPS"
echo "  program hash : $PROGRAM_HASH"
echo "  proof bytes  : $(( (${#PROOF_HEX} - 2) / 2 ))"

INPUTS_TUPLE="($NUM_STEPS,$PI_HEX_1,$RETURN_VALUE,$PI_HEX_3,$PI_HEX_4,$PI_HEX_5,$PI_HEX_6,$PI_HEX_7)"

# ─── 2. deploy or reuse contracts ────────────────────────────────────────────
if [[ "$DEPLOY" == "1" ]]; then
    echo "── [2/5] Deploying HonkVerifier + ProvenoVerifier + ProvenoConsumer + Bounty ──"
    DEPLOY_LOG="$PROVE_OUTPUT/deploy.log"
    # --disable-code-size-limit: the generated HonkVerifier is ~34 KB, over
    # EIP-170's 24576-byte ceiling; the local anvil pairs this with --code-size-limit.
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

    BOUNTY_ADDR=$(grep -E '^\s*Bounty:' "$DEPLOY_LOG" | tail -n1 | awk '{print $NF}')

    if [[ -z "$BOUNTY_ADDR" ]]; then
        echo "error: could not parse deployed Bounty address from $DEPLOY_LOG" >&2
        tail -n 40 "$DEPLOY_LOG" >&2
        exit 1
    fi
    echo "  Bounty : $BOUNTY_ADDR"
else
    echo "── [2/5] Reusing deployed Bounty ──"
    echo "  Bounty : $BOUNTY_ADDR"
fi

# ─── 3. post the bounty (poster) ─────────────────────────────────────────────
echo "── [3/5] Poster posts a bounty (reward $REWARD_ETH ETH) ──"

# id = nextId++ : the new bounty takes the current nextId value.
BOUNTY_ID=$(cast call --rpc-url "$RPC_URL" "$BOUNTY_ADDR" 'nextId()(uint256)')

cast send \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --value "$REWARD" \
    "$BOUNTY_ADDR" \
    'postBounty(bytes32)(uint256)' \
    "$PROGRAM_HASH" \
    > /dev/null

echo "  bounty id    : $BOUNTY_ID"
echo "  program hash : $PROGRAM_HASH"
echo "  reward       : $REWARD_ETH ETH (escrowed)"

# ─── 4. agent claims the bounty (solver) ─────────────────────────────────────
echo "── [4/5] Agent claims the bounty with the proof ──"
echo "  solver       : $SOLVER_ADDR"

SOLVER_BAL_BEFORE=$(cast balance --rpc-url "$RPC_URL" "$SOLVER_ADDR")

CLAIM_SIG='claim(uint256,bytes,(uint32,bytes32,int64,bytes32,bytes32,bytes32,bytes32,bytes32))'

CLAIM_RECEIPT=$(cast send \
    --json \
    --rpc-url "$RPC_URL" \
    --private-key "$SOLVER_KEY" \
    "$BOUNTY_ADDR" \
    "$CLAIM_SIG" \
    "$BOUNTY_ID" \
    "$PROOF_HEX" \
    "$INPUTS_TUPLE")

SOLVER_BAL_AFTER=$(cast balance --rpc-url "$RPC_URL" "$SOLVER_ADDR")

# Gas the solver paid for the claim tx, so we can assert the net balance change
# is exactly (reward - gas).
GAS_USED=$(echo "$CLAIM_RECEIPT" | jq -r '.gasUsed')
GAS_PRICE=$(echo "$CLAIM_RECEIPT" | jq -r '.effectiveGasPrice')

# BountyClaimed(uint256,address,uint256) topic — assert the event was emitted.
CLAIMED_TOPIC=$(cast keccak 'BountyClaimed(uint256,address,uint256)')
if ! echo "$CLAIM_RECEIPT" | jq -e --arg t "$CLAIMED_TOPIC" \
        '.logs[].topics[0] | select(. == $t)' > /dev/null; then
    echo "error: BountyClaimed event not found in claim receipt" >&2
    exit 1
fi
echo "  ✓ BountyClaimed emitted"

# ─── 5. read back state + assert payout ──────────────────────────────────────
echo "── [5/5] Verifying claim state and payout ──"

# bounties(id) -> (poster, reward, programHash, claimed, solver)
read -r B_CLAIMED B_SOLVER < <(cast call --rpc-url "$RPC_URL" "$BOUNTY_ADDR" \
    'bounties(uint256)(address,uint256,bytes32,bool,address)' "$BOUNTY_ID" \
    | sed -n '4p;5p' | paste -sd' ' -)

if [[ "$B_CLAIMED" != "true" ]]; then
    echo "error: bounty $BOUNTY_ID not marked claimed (got '$B_CLAIMED')" >&2
    exit 1
fi
echo "  ✓ bounty claimed = true, solver = $B_SOLVER"

# Net balance change must equal reward minus the gas the solver spent claiming.
ASSERT_OK=$(python3 - <<PY
before = int("$SOLVER_BAL_BEFORE")
after  = int("$SOLVER_BAL_AFTER")
reward = int("$REWARD")
gas    = int("$GAS_USED", 0) * int("$GAS_PRICE", 0)
delta  = after - before
expected = reward - gas
print("OK" if delta == expected and delta > 0 else f"FAIL delta={delta} expected={expected}")
PY
)

if [[ "$ASSERT_OK" != "OK" ]]; then
    echo "error: solver balance change mismatch: $ASSERT_OK" >&2
    echo "  before=$SOLVER_BAL_BEFORE after=$SOLVER_BAL_AFTER reward=$REWARD" >&2
    exit 1
fi
echo "  ✓ solver balance rose by reward - gas (net positive)"

# ─── summary ─────────────────────────────────────────────────────────────────
echo
echo "post bounty (reward $REWARD_ETH) -> agent runs task -> proof -> claim -> agent paid $REWARD_ETH"
echo "✓ bounty claimed: agent paid $REWARD_ETH"
