# luai

A deterministic, sandboxed Lua virtual machine for agentic workloads.

Scripts run as single-shot programs: they receive an input object, may invoke host-provided tools, and return a structured result. Given the same bytecode, inputs, and tool responses, execution is always identical — making transcripts verifiable and zk-provable.

## Key properties

- **Deterministic** — no floats, no hash randomization, canonical table iteration order
- **Sandboxed** — no filesystem, network, or OS access; tools are the only external interface
- **Bounded** — gas, memory, depth, and output limits guarantee termination
- **Integer-only arithmetic** — signed 64-bit; use fixed-point for fractional values
- **ZK-provable** — two-phase execution model proved via Noir (`luai-noir` + `nargo`/`bb`)

## Workspace

| Crate | Purpose |
|-------|---------|
| `luai` | Core library — parser, compiler, bytecode verifier, VM, host, oracle tape |
| `compiler` | CLI: compile Lua source → verified bytecode JSON |
| `prover` | CLI: dry-run compiled programs, produce oracle tapes and public inputs |
| `luai-noir` | Noir witness writer + `nargo`/`bb` driver — the canonical proving path |
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
1. Compile       luai-compiler source.lua compiled.json
2. Dry run       luai-prover compiled.json dry_result.json
                 → executes with live host, records oracle tape
                 → computes public inputs (SHA-256 commitments)
3. Prove         cargo run -p luai-noir -- compiled.json dry_result.json --prove
                 → builds the Noir witness, drives `nargo execute` +
                   `bb prove`/`bb verify` against the trace circuit
4. Submit        cast send / consumeResult against LuaiConsumer.sol
                 → on-chain UltraHonk verify via HonkVerifier.sol
                 → LuaiVerifier enforces policyHash match
                 → LuaiConsumer asserts keccak256(outputPayload) == outputHash
```

Public inputs commit to: program hash, input hash, tool responses hash, output
hash, TLS attestation hash, policy hash (plus `num_steps` and `return_value`).

### Quick start: prove and verify a Lua program

End-to-end demo against a local anvil chain. Requires `nargo`, `bb`, `forge`,
`cast`, `anvil`, and `jq` on `PATH`, plus `ANTHROPIC_API_KEY`.

```bash
# 1. (one terminal) build everything once so the demo doesn't time out on cargo
cargo build --release -p luai-orchestrator -p luai-noir

# 2. (second terminal) run the demo — spins up a temporary anvil, deploys the
#    HonkVerifier/LuaiVerifier/LuaiConsumer triple, generates a Noir proof for
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
LUAI_VERIFIER_ADDR=0x... LUAI_CONSUMER_ADDR=0x... \
    bash demo-noir-e2e.sh "<task>"
```

The script prints the proof bytes, the 8-element `bytes32[]` public inputs,
the on-chain `LuaiVerifier.verify` result, and the consumer state after the
`consumeResult` call. See the comment header in `demo-noir-e2e.sh` for the
encoding-bridge caveat between `outputHash` (SHA-256) and the consumer's
`keccak256(outputPayload)` check.

## Orchestrator

The orchestrator connects an LLM (Claude) to the luai VM, forming an agentic pipeline:

1. User provides a natural-language task
2. The LLM generates a Lua program to accomplish it
3. The program is compiled, verified, and executed in the sandboxed VM
4. Tool calls reach real external services (HTTP, KV store, LLM sub-queries)
5. On error, the LLM retries with error context (up to N attempts)
6. A full execution report is produced with verification hashes

### Usage

```
export ANTHROPIC_API_KEY=sk-...
cargo run -p luai-orchestrator -- "fetch the top hacker news story title"
```

### Options

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable JSON output with full transcript and verification hashes |
| `--verbose` / `-v` | Show system prompt and raw LLM responses |
| `--model <model>` | Claude model to use (default: `claude-sonnet-4-20250514`) |
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
cargo run -p luai-orchestrator -- --prove "score this wallet for onchain reputation"
```

This produces `proof-output/compiled.json` and `proof-output/dry_result.json` — the inputs needed to generate a cryptographic proof via the Noir circuit. The proof attests that:

- **This specific program** was executed (program hash)
- **These specific API responses** were consumed (tool responses hash)
- **This specific output** was produced (output hash)

A third party can verify the proof without trusting the executor. The execution is deterministic: given the same program and oracle tape, anyone can replay it and get the identical result.

**Current trust boundary:** The ZK proof guarantees computational integrity — that the program ran correctly and produced the claimed output from the claimed inputs. It does not yet guarantee data provenance (that API responses came from the real servers). TLS attestation (verifying server certificates inside the VM) is planned to close this gap.

### Benchmarks: luai vs LangChain ReAct

luai generates a complete program in a single LLM call, then executes it in the VM at zero token cost. Traditional agent frameworks like LangChain use a ReAct loop where each tool call is a round-trip through the LLM, with the full conversation history growing at each step.

**Task: Onchain wallet reputation scoring (2 API calls)**

| | luai | LangChain |
|---|---|---|
| LLM calls | 1 | 2 |
| Input tokens | 1,568 | 1,951 |
| Output tokens | 1,273 | 777 |
| **Total tokens** | **2,841** | **2,728** |

**Task: Multi-chain wallet scoring (8 API calls across 4 chains)**

| | luai | LangChain |
|---|---|---|
| LLM calls | 1 | 2 |
| Input tokens | — | 4,004 |
| Output tokens | — | 1,163 |
| **Total tokens** | **3,346** | **5,167** |

At 8 API calls, LangChain uses **1.55x** more tokens. The gap widens with task complexity: each additional tool call adds API response data to LangChain's conversation context, while luai's execution cost remains zero tokens regardless of how many tool calls the program makes.

**Task: Cross-chain token portfolio analysis (12 API calls, ~69KB response data)**

| | luai | LangChain |
|---|---|---|
| LLM calls | 1 | 2 |
| Input tokens | 1,628 | 26,715 |
| Output tokens | 1,197 | 1,841 |
| **Total tokens** | **2,825** | **28,556** |

At 12 API calls with larger payloads (ERC-20 token lists at ~5-25KB each), LangChain uses **10.1x** more tokens. The API response data accumulates in LangChain's conversation context — 69KB of JSON becomes ~26K input tokens on the second LLM call. luai processes all of it in the VM at zero token cost.

Beyond token efficiency, luai produces a cryptographic proof of correct execution. LangChain produces an answer — luai produces an answer anyone can verify.

Benchmark scripts are in `examples/`:
- `examples/score-wallet.sh` — single-chain scoring (luai)
- `examples/multichain-score-wallet.sh` — multi-chain scoring (luai)
- `examples/large-response-processing.sh` — cross-chain token portfolio (luai)
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
