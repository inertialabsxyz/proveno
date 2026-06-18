#!/usr/bin/env bash
#
# demo-bounty.sh — End-to-end verifiable-task bounty demo for proveno.
#
# The hero artifact: a requester posts a bounty committing the exact program
# hash of a proveno task and escrows ETH; an agent runs that task, generates a
# Noir UltraHonk proof, claims the bounty with the proof, the on-chain Bounty
# contract verifies it, and the agent is paid.
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
#      ended up net positive (reward minus fees). Print a one-line summary.
#
# Environment (any of these may be set in a .env next to this script):
#   ANTHROPIC_API_KEY    required UNLESS LUA_SOURCE is set (no LLM in LUA_SOURCE mode)
#   LUA_SOURCE           default: examples/usdc_depeg.lua  (fixed Lua, no LLM)
#   RPC_URL              default: http://127.0.0.1:8545
#   PRIVATE_KEY          required — the poster/deployer
#   SOLVER_KEY           default: anvil account 1 — the agent that claims the bounty
#   REWARD               default: 10000000000000000 (0.01 ETH, in wei) escrowed by the poster
#   DEPLOY               1 to deploy a fresh stack via forge script, otherwise reuse env addr
#   BOUNTY_ADDR          required if DEPLOY != 1
#   PROVE_OUTPUT         default: /tmp/proveno-demo  (where artifacts land)
#   CIRCUIT_DIR          default: noir            (path to the Noir circuit)
#   NO_COLOR / FORCE_COLOR  disable / force ANSI color
#
# Usage:
#   LUA_SOURCE=examples/usdc_depeg.lua ./demo-bounty.sh
#   DEPLOY=1 RPC_URL=… PRIVATE_KEY=… ./demo-bounty.sh
#
# See also: demo-bounty-local.sh — wraps this script around a fresh local anvil.

set -euo pipefail

# ─── color ───────────────────────────────────────────────────────────────────
if [[ -n "${NO_COLOR:-}" ]]; then
    _C=0
elif [[ -n "${FORCE_COLOR:-}" || -t 1 ]]; then
    _C=1
else
    _C=0
fi
if [[ "$_C" == 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'
    YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    BOLD=; DIM=; GREEN=; CYAN=; YELLOW=; RED=; RESET=
fi

step() { echo; echo "${BOLD}${CYAN}━━ $1 ━━${RESET}"; }
ok()   { echo "  ${GREEN}✓${RESET} $1"; }
kv()   { printf "  ${DIM}%-13s${RESET} ${BOLD}%s${RESET}\n" "$1" "$2"; }
die()  { echo "${RED}error:${RESET} $1" >&2; exit 1; }

# Print a Lua file indented, with light syntax color. Prefers `bat` if present
# (full highlighting); otherwise a minimal fallback that dims comments and
# greens strings. With color off, prints plain.
print_lua() {
    local f="$1"
    if [[ "$_C" != 1 ]]; then
        sed 's/^/    /' "$f"
    elif command -v bat >/dev/null 2>&1; then
        bat --language=lua --style=plain --paging=never --color=always "$f" | sed 's/^/    /'
    else
        awk -v C="$DIM" -v S="$GREEN" -v R="$RESET" '
            /^[[:space:]]*--/ { printf "    %s%s%s\n", C, $0, R; next }
            { line=$0; gsub(/"[^"]*"/, S "&" R, line); printf "    %s\n", line }' "$f"
    fi
}

# ─── .env autoload (BEFORE defaults, so .env values win over the defaults) ─────
# Source .env next to this script so the shell's own checks see the same vars the
# binaries read via dotenvy. A value already exported in the shell still wins.
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

# ─── defaults ──────────────────────────────────────────────────────────────────
DEFAULT_TASK='return a small JSON object {price=100, sources=1, ts=1700000000}'
TASK="${1:-$DEFAULT_TASK}"

# Default to the proven depeg task so the demo runs without an LLM out of the box.
LUA_SOURCE="${LUA_SOURCE:-examples/usdc_depeg.lua}"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PROVE_OUTPUT="${PROVE_OUTPUT:-/tmp/proveno-demo}"
CIRCUIT_DIR="${CIRCUIT_DIR:-noir}"
DEPLOY="${DEPLOY:-0}"
REWARD="${REWARD:-10000000000000000}"  # 0.01 ETH in wei

# Default solver = anvil account 1 (distinct from the account-0 poster), so the
# payout is visible as a balance change on a different address.
SOLVER_KEY="${SOLVER_KEY:-0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d}"

# ─── prerequisite checks ───────────────────────────────────────────────────────
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found in PATH"; }
require_cmd jq
require_cmd cast
require_cmd forge
require_cmd cargo
require_cmd python3

[[ -n "${LUA_SOURCE:-}" && ! -f "$LUA_SOURCE" ]] && die "LUA_SOURCE='$LUA_SOURCE' not found"

# ANTHROPIC_API_KEY is only needed for the orchestrator (LLM) generation path.
# With LUA_SOURCE set (the default), step 1 compiles a fixed Lua file — no LLM.
[[ -z "${LUA_SOURCE:-}" && -z "${ANTHROPIC_API_KEY:-}" ]] && \
    die "ANTHROPIC_API_KEY must be set (or set LUA_SOURCE to skip the LLM)"

[[ -z "${PRIVATE_KEY:-}" ]] && die "PRIVATE_KEY must be set (the poster/deployer)"
[[ "$DEPLOY" != "1" && -z "${BOUNTY_ADDR:-}" ]] && die "when DEPLOY != 1, BOUNTY_ADDR must be set"

# Resolve repo root so we can run cargo / forge regardless of $CWD.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

SOLVER_ADDR=$(cast wallet address --private-key "$SOLVER_KEY")
POSTER_ADDR=$(cast wallet address --private-key "$PRIVATE_KEY")
REWARD_ETH=$(cast to-unit "$REWARD" ether | sed 's/0*$//; s/\.$//')
CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || echo "?")

# ─── banner ────────────────────────────────────────────────────────────────────
echo "${BOLD}proveno · verifiable-task bounty demo${RESET}"
kv "network"  "$RPC_URL  ${DIM}(chain $CHAIN_ID)${RESET}"
kv "task"     "$LUA_SOURCE"
kv "reward"   "$REWARD_ETH ETH"
kv "poster"   "$POSTER_ADDR"
kv "solver"   "$SOLVER_ADDR"

# ─── 1. generate proof artifacts ─────────────────────────────────────────────
mkdir -p "$PROVE_OUTPUT"
ORCH_JSON="$PROVE_OUTPUT/orchestrator.json"

if [[ -n "${LUA_SOURCE:-}" ]]; then
    step "[1/5] Generate the proof  (compile · run · prove)"
    kv "source" "$LUA_SOURCE"
    echo "  ${DIM}task program:${RESET}"
    print_lua "$LUA_SOURCE"
    echo
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
    step "[1/5] Generate the proof via the orchestrator (LLM)"
    cargo run --quiet -p proveno-orchestrator -- \
        "$TASK" \
        --prove \
        --json \
        --prove-output "$PROVE_OUTPUT" \
        --circuit-dir "$CIRCUIT_DIR" \
        > "$ORCH_JSON"
fi

jq -e '.proving.proof_bytes_hex' "$ORCH_JSON" > /dev/null \
    || die "proof generation output missing proving.proof_bytes_hex; check $ORCH_JSON"

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
kv "lua return"   "$LUA_RETURN"
kv "num_steps"    "$NUM_STEPS"
kv "program hash" "$PROGRAM_HASH"
kv "proof bytes"  "$(( (${#PROOF_HEX} - 2) / 2 ))"
ok "proof generated and self-verified"

INPUTS_TUPLE="($NUM_STEPS,$PI_HEX_1,$RETURN_VALUE,$PI_HEX_3,$PI_HEX_4,$PI_HEX_5,$PI_HEX_6,$PI_HEX_7)"

# ─── 2. deploy or reuse contracts ────────────────────────────────────────────
if [[ "$DEPLOY" == "1" ]]; then
    step "[2/5] Deploy the stack  (HonkVerifier · ProvenoVerifier · ProvenoConsumer · Bounty)"
    DEPLOY_LOG="$PROVE_OUTPUT/deploy.log"
    # The bb 5.0.0 HonkVerifier is ~24.0 KB (23,977 B), under EIP-170's 24576-byte
    # ceiling, so it deploys to a stock chain. --disable-code-size-limit is left on
    # as headroom in case other demo contracts grow; it is no longer required.
    POLICY_HASH="$PI_HEX_7" forge script contracts/script/Deploy.s.sol \
        --root contracts \
        --rpc-url "$RPC_URL" \
        --private-key "$PRIVATE_KEY" \
        --broadcast \
        --disable-code-size-limit \
        > "$DEPLOY_LOG" 2>&1 || {
            echo "${RED}error:${RESET} forge script Deploy.s.sol failed; see $DEPLOY_LOG" >&2
            tail -n 40 "$DEPLOY_LOG" >&2
            exit 1
        }

    BOUNTY_ADDR=$(grep -E '^\s*Bounty:' "$DEPLOY_LOG" | tail -n1 | awk '{print $NF}')
    [[ -z "$BOUNTY_ADDR" ]] && { tail -n 40 "$DEPLOY_LOG" >&2; die "could not parse deployed Bounty address from $DEPLOY_LOG"; }
    kv "Bounty" "$BOUNTY_ADDR"
    ok "deployed"
else
    step "[2/5] Reuse the deployed Bounty"
    kv "Bounty" "$BOUNTY_ADDR"
fi

# ─── 3. post the bounty (poster) ─────────────────────────────────────────────
step "[3/5] Poster posts a bounty  (escrow $REWARD_ETH ETH)"

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

kv "bounty id"    "$BOUNTY_ID"
kv "program hash" "$PROGRAM_HASH"
kv "reward"       "$REWARD_ETH ETH (escrowed)"
ok "bounty posted"

# ─── 4. agent claims the bounty (solver) ─────────────────────────────────────
step "[4/5] Agent claims the bounty with the proof"
kv "solver" "$SOLVER_ADDR"

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

# Note: we do not reconcile fees to the wei. Total fees are chain dependent
# (L2 execution gas plus, on OP-stack chains like Base, an L1 data fee), so the
# assertion below checks the net balance change is positive and within the reward.

# BountyClaimed(uint256,address,uint256) topic — assert the event was emitted.
CLAIMED_TOPIC=$(cast keccak 'BountyClaimed(uint256,address,uint256)')
echo "$CLAIM_RECEIPT" | jq -e --arg t "$CLAIMED_TOPIC" \
        '.logs[].topics[0] | select(. == $t)' > /dev/null \
    || die "BountyClaimed event not found in claim receipt"
ok "BountyClaimed emitted"

# ─── 5. read back state + assert payout ──────────────────────────────────────
step "[5/5] Verify claim state and payout"

# bounties(id) -> (poster, reward, programHash, claimed, solver)
read -r B_CLAIMED B_SOLVER < <(cast call --rpc-url "$RPC_URL" "$BOUNTY_ADDR" \
    'bounties(uint256)(address,uint256,bytes32,bool,address)' "$BOUNTY_ID" \
    | sed -n '4p;5p' | paste -sd' ' -)

[[ "$B_CLAIMED" != "true" ]] && die "bounty $BOUNTY_ID not marked claimed (got '$B_CLAIMED')"
ok "bounty claimed = true, solver = $B_SOLVER"

# The solver must end up net positive: it received the reward and paid fees to
# claim. Invariant: 0 < balance change <= reward (the shortfall is fees).
ASSERT_OK=$(python3 - <<PY
before = int("$SOLVER_BAL_BEFORE")
after  = int("$SOLVER_BAL_AFTER")
reward = int("$REWARD")
delta  = after - before
ok = (delta > 0) and (delta <= reward)
print("OK" if ok else f"FAIL delta={delta} reward={reward} fee={reward - delta}")
PY
)

if [[ "$ASSERT_OK" != "OK" ]]; then
    echo "${RED}error:${RESET} solver balance change mismatch: $ASSERT_OK" >&2
    echo "  before=$SOLVER_BAL_BEFORE after=$SOLVER_BAL_AFTER reward=$REWARD" >&2
    exit 1
fi
ok "solver net positive: received the reward minus claim fees"

# ─── summary ─────────────────────────────────────────────────────────────────
echo
echo "  ${DIM}post bounty${RESET} → ${DIM}agent runs task${RESET} → ${DIM}proof${RESET} → ${DIM}claim${RESET} → ${BOLD}agent paid${RESET}"
echo "${BOLD}${GREEN}✓ bounty claimed: agent paid $REWARD_ETH ETH on chain $CHAIN_ID${RESET}"
