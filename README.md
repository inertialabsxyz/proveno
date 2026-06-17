# Proveno

**Verifiable tasks: write a task in Lua and prove it ran exactly as written.**

You write straightforward logic in Lua. Proveno executes it deterministically
off-chain, produces a zero-knowledge proof that *this exact program ran over
these exact inputs and produced this exact output*, and a smart contract verifies
that proof on-chain before acting on the result.

Proveno runs **verifiable tasks**: small programs you write in plain Lua that hand
back two things — the result, and a proof of exactly what they did. **If you can
write a script, you can write a verifiable task** — no circuits, no cryptography.
Instead of trusting an operator to report a result, a consumer trusts a *proof* that
a known program ran correctly. The operator becomes interchangeable — anyone running
the same task over the same inputs produces the same proof.

The identity is **horizontal** — verifiable tasks are useful wherever a result must
be trusted. On-chain verification (a contract acting on a task's proof,
coprocessor-style) is its first high-value **application**, not its category. The
zkVM is the proving **mechanism**, not the identity; "programs are data, not
circuits," so a new task needs no new circuit.

Under the hood it is a from-scratch, deterministic, sandboxed Lua VM. Programs run
as single-shot computations: they receive an input object, may invoke host-provided
tools, and return a structured result. Given the same bytecode, inputs, and tool
responses, execution is always identical — that determinism is the precondition for
provability.

## Two guarantees, one proof

A verifiable task proves two things side by side, bound into a single proof:

- **Execution — always.** *"The agreed program ran correctly over the inputs it was
  given, and produced this output."* This is what proveno does on its own.
- **Provenance — when a provider is attached.** *"Those inputs are the real data from
  the real source."* The same proof attests it, once a provenance provider supplies the
  attestation.

Execution integrity is the floor, and is useful on its own — verifiable custom
aggregation over *signed* inputs already composes cleanly with first-party oracles.
Provenance completes the picture.

Provenance is **delegated, not deferred.** Proveno does not *produce* authenticity
attestations — it *binds* them. Every tool call can carry an opaque attestation
blob sourced by an external provider (a signed feed payload, a zkTLS / TLS-notary
proof); the `attestation_hash` public input commits, per call, to that blob welded
to the exact response bytes it covers (`OracleTape::attestation_commitment`). The
circuit does **not** verify the blob — production is the provider's job, and a
downstream consumer that trusts the provider checks it against the response it
covers. This means an attestation cannot be re-presented over different responses
than those actually executed. The boundary where a provider plugs in is
`HostInterface::take_attestation`. Concrete providers (Pyth signatures, a zkTLS
network) are follow-on work; the binding interface is shipped. The `src/tls`
P-256/zkTLS machinery remains as one such attestation *producer*, now decoupled
from the public input. See `docs/tls-attestation.md` for that producer.

Proveno is **not an oracle** and does not replace Chainlink/Pyth — "oracle" promises
data provenance, which is the provider's job, not proveno's. It is **complementary**:
a programmable, proven-computation layer between raw (ideally signed) data and
on-chain action.

## Key properties

- **Deterministic** — no floats, no hash randomization, canonical table iteration order
- **Sandboxed** — no filesystem, network, or OS access; tools are the only external interface
- **Bounded** — gas, memory, depth, and output limits guarantee termination
- **Integer-only arithmetic** — signed 64-bit; use fixed-point for fractional values
- **ZK-provable** — two-phase execution model proved via Noir (`proveno-noir` + `nargo`/`bb`)

## What it's good for

The shape that fits: **a bounded task that applies a rule to fetched inputs, whose
correct application matters to a third party who won't — or can't — re-run it.**
A good proveno task is bounded, has logic whose correctness matters downstream,
consumes external inputs, and is useful from execution integrity alone — *gaining*
provenance when a provider is attached (see "Two guarantees, one proof" above).

- **Parametric payouts / settlement** — fetch a condition, apply the payout rule, a
  contract pays out on the proof (generalizes prediction-market / parimutuel resolution).
- **Eligibility & policy gating** — evaluate a rule set over fetched attributes
  (airdrops, allowlists, underwriting, KYC); a contract gates a claim on the proof.
- **Verifiable agent actions** — an LLM-authored task with deterministic control flow;
  prove what the agent actually did, with every `llm_query` committed in the transcript.
- **Auditable process** — prove a refund, royalty split, or fee was computed per the
  documented rules; a proof-of-process for disputes and compliance, no chain required.

## Workspace

| Crate | Purpose |
|-------|---------|
| `proveno` | Core library — parser, compiler, bytecode verifier, VM, host, oracle tape |
| `compiler` | CLI: compile Lua source → verified bytecode JSON |
| `prover` | CLI: dry-run compiled programs, produce oracle tapes and public inputs |
| `proveno-noir` | Noir witness writer + `nargo`/`bb` driver — the canonical proving path |
| `orchestrator` | LLM-driven agentic pipeline — accepts a task, generates and executes Lua |

> Noir is the canonical proving path. The historical OpenVM implementation has been
> archived on the `archive/openvm` branch — see that branch for the previous guest,
> encoder, on-chain verifier, and `zkvm-prove.sh` pipeline.

## Architecture

```
Lua source
    │
    ▼
parser/          — lexer + recursive-descent parser → AST
    │
    ▼
compiler/        — AST → bytecode (prototypes + constants + program hash)
    │
    ▼
bytecode/        — instruction set; verifier checks stack depth & operands
    │
    ▼
vm/engine.rs     — register-based execution; gas + memory metering
    │             builtins: string, math, table, json, type, pcall, …
    │
    ▼
host/            — HostInterface for tool calls; transcript recording;
                   canonical JSON; OracleTape for deterministic replay
```

### Proving pipeline

```
1. Compile       proveno-compiler source.lua compiled.json
2. Dry run       proveno-prover compiled.json dry_result.json
                 → executes with live host, records oracle tape
                 → computes public inputs (SHA-256 commitments)
3. Prove         cargo run -p proveno-noir -- compiled.json dry_result.json --prove
                 → builds the Noir witness, drives `nargo execute` +
                   `bb prove`/`bb verify` against the trace circuit
4. Submit        cast send / consumeResult against ProvenoConsumer.sol
                 → on-chain UltraHonk verify via HonkVerifier.sol
                 → ProvenoVerifier enforces policyHash match
                 → ProvenoConsumer asserts keccak256(outputPayload) == outputHash
```

Public inputs commit to: program hash, input hash, tool responses hash, output
hash, attestation hash (bind-only per-call provenance), policy hash (plus
`num_steps` and `return_value`).

### Toolchain versions

The Noir proving path is pinned to a specific toolchain. The circuit, the
checked-in `contracts/src/HonkVerifier.sol`, and the proof fixtures under
`contracts/test/fixtures/` are all generated with:

| Tool | Version |
|------|---------|
| `nargo` | `1.0.0-beta.18` |
| `bb` (Barretenberg) | `3.0.0` |
| `poseidon` (Noir lib, `noir/Nargo.toml`) | `v0.2.6` |

Other `nargo`/`bb` versions are **not** supported — newer `nargo` changed the
`poseidon2_permutation` signature (breaking `poseidon v0.2.6`), and `bb` emits a
different verifier/proof format per version. If you upgrade, you must regenerate
the verifier contract and fixtures together (see
`contracts/test/fixtures/README.md`).

### Quick start: prove and verify a Lua program

End-to-end demo against a local anvil chain. Requires `nargo`, `bb`, `forge`,
`cast`, `anvil`, and `jq` on `PATH` (see pinned versions above), plus
`ANTHROPIC_API_KEY`.

```bash
# 1. (one terminal) build everything once so the demo doesn't time out on cargo
cargo build --release -p proveno-orchestrator -p proveno-noir

# 2. (second terminal) run the demo — spins up a temporary anvil, deploys the
#    HonkVerifier/ProvenoVerifier/ProvenoConsumer triple, generates a Noir proof for
#    a small Lua program, and submits it on chain.
ANTHROPIC_API_KEY=sk-... bash demo-noir-e2e-local.sh \
    "return a small JSON object {price=100, sources=1, ts=1700000000}"

# 3. Or against an existing chain:
ANTHROPIC_API_KEY=sk-... \
RPC_URL=https://... PRIVATE_KEY=0x... DEPLOY=1 \
    bash demo-noir-e2e.sh "<task>"

# 4. Or against an existing deployment:
ANTHROPIC_API_KEY=sk-... \
RPC_URL=https://... PRIVATE_KEY=0x... \
PROVENO_VERIFIER_ADDR=0x... PROVENO_CONSUMER_ADDR=0x... \
    bash demo-noir-e2e.sh "<task>"
```

The script prints the proof bytes, the 8-element `bytes32[]` public inputs,
the on-chain `ProvenoVerifier.verify` result, and the consumer state after the
`consumeResult` call. See the comment header in `demo-noir-e2e.sh` for the
encoding-bridge caveat between `outputHash` (SHA-256) and the consumer's
`keccak256(outputPayload)` check.

## Orchestrator

The orchestrator is one way to author and run a task: it connects an LLM (Claude) to the
Proveno VM so a natural-language task becomes a proven computation. The LLM authors
the program; Proveno makes the result verifiable.

1. User provides a natural-language task
2. The LLM generates a Lua program to accomplish it
3. The program is compiled, verified, and executed in the sandboxed VM
4. Tool calls reach real external services (HTTP, KV store, LLM sub-queries)
5. On error, the LLM retries with error context (up to N attempts)
6. A full execution report is produced with verification hashes

### Usage

```
export ANTHROPIC_API_KEY=sk-...
cargo run -p proveno-orchestrator -- "fetch the top hacker news story title"
```

### Options

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable JSON output with full transcript and verification hashes |
| `--verbose` / `-v` | Show system prompt and raw LLM responses |
| `--model <model>` | Claude model to use (default: `claude-sonnet-4-6`) |
| `--max-retries <n>` | Max retry attempts on errors (default: 3) |

### Available tools

Programs running in the VM can call these tools via `tool.call(name, args)`:

| Tool | Description |
|------|-------------|
| `http_get` | GET a URL, returns `{status, body}` |
| `http_post` | POST JSON to a URL, returns `{status, body}` |
| `kv_get` | Read from an in-memory key-value store |
| `kv_set` | Write to an in-memory key-value store |
| `llm_query` | Call the LLM for fuzzy reasoning sub-tasks |
| `time_now` | Current Unix timestamp |

### Execution report

Every run produces a report with:
- The generated Lua program
- Return value and logs
- Full tool call transcript (name, args, response, bytes)
- Resource usage (gas, memory, tool calls) with limits
- SHA-256 verification hashes (program, oracle tape, output)

The `--json` flag outputs all of this as structured JSON for machine consumption.

### ZK proof artifacts

With `--prove`, the orchestrator generates ZK proof artifacts after successful execution:

```
cargo run -p proveno-orchestrator -- --prove "score this wallet for onchain reputation"
```

This produces `proof-output/compiled.json` and `proof-output/dry_result.json` — the inputs needed to generate a cryptographic proof via the Noir circuit. The proof attests that:

- **This specific program** was executed (program hash)
- **These specific API responses** were consumed (tool responses hash)
- **This specific output** was produced (output hash)

A third party can verify the proof without trusting the executor. The execution is deterministic: given the same program and oracle tape, anyone can replay it and get the identical result.

**Current trust boundary:** The ZK proof guarantees computational integrity — that the program ran correctly and produced the claimed output from the claimed inputs. It does not by itself guarantee data provenance (that API responses came from the real servers). Provenance is **delegated**: each tool call can carry an external provider's attestation, which the proof *binds* to the response bytes via the `attestation_hash` public input (committed, not verified in-circuit). A consumer that trusts the provider verifies the attestation against the bound response. Wiring concrete providers (Pyth signatures, a zkTLS network) at the `HostInterface::take_attestation` boundary is follow-on work; the binding is shipped.

### Benchmarks: proveno vs LangChain ReAct

Proveno generates a complete program in a single LLM call, then executes it in the VM at zero token cost. Traditional agent frameworks like LangChain use a ReAct loop where each tool call is a round-trip through the LLM, with the full conversation history growing at each step.

**Task: Onchain wallet reputation scoring (2 API calls)**

| | proveno | LangChain |
|---|---|---|
| LLM calls | 1 | 2 |
| Input tokens | 1,568 | 1,951 |
| Output tokens | 1,273 | 777 |
| **Total tokens** | **2,841** | **2,728** |

**Task: Multi-chain wallet scoring (8 API calls across 4 chains)**

| | proveno | LangChain |
|---|---|---|
| LLM calls | 1 | 2 |
| Input tokens | — | 4,004 |
| Output tokens | — | 1,163 |
| **Total tokens** | **3,346** | **5,167** |

At 8 API calls, LangChain uses **1.55x** more tokens. The gap widens with task complexity: each additional tool call adds API response data to LangChain's conversation context, while proveno's execution cost remains zero tokens regardless of how many tool calls the program makes.

**Task: Cross-chain token portfolio analysis (12 API calls, ~69KB response data)**

| | proveno | LangChain |
|---|---|---|
| LLM calls | 1 | 2 |
| Input tokens | 1,628 | 26,715 |
| Output tokens | 1,197 | 1,841 |
| **Total tokens** | **2,825** | **28,556** |

At 12 API calls with larger payloads (ERC-20 token lists at ~5-25KB each), LangChain uses **10.1x** more tokens. The API response data accumulates in LangChain's conversation context — 69KB of JSON becomes ~26K input tokens on the second LLM call. Proveno processes all of it in the VM at zero token cost.

Beyond token efficiency, Proveno produces a cryptographic proof of correct execution. LangChain produces an answer — Proveno produces an answer anyone can verify.

Benchmark scripts are in `examples/`:
- `examples/score-wallet.sh` — single-chain scoring (proveno)
- `examples/multichain-score-wallet.sh` — multi-chain scoring (proveno)
- `examples/large-response-processing.sh` — cross-chain token portfolio (proveno)
- `examples/score-wallet-langchain.py` — single-chain scoring (LangChain)
- `examples/multichain-score-langchain.py` — multi-chain scoring (LangChain)
- `examples/large-response-langchain.py` — cross-chain token portfolio (LangChain)

## Standard library

| Module | Functions |
|--------|-----------|
| `string` | `len`, `sub`, `find`, `upper`, `lower`, `rep`, `byte`, `char`, `format` |
| `math` | `abs`, `min`, `max`, `scale_div` |
| `table` | `insert`, `remove`, `concat`, `move`, `sort` |
| `json` | `encode`, `decode` |
| top-level | `type`, `tostring`, `tonumber`, `select`, `unpack`, `pcall`, `error`, `log`, `print`, `pairs_sorted`, `ipairs` |

## Resource limits (defaults)

| Limit | Default |
|-------|---------|
| Gas | 10,000,000 |
| Memory | 64 MB |
| Call depth | 200 |
| Tool calls | 64 |
| Bytes in per call | 1 MB |
| Bytes out per call | 64 KB |
| JSON / string length | 64 KB |
| Table / call nesting depth | 32 |
