# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quality Gate

```bash
cargo test
```

Must pass before every commit. Run across all workspace members by default.

### Pre-PR gate

Before opening a PR, also run:

```bash
make test-prove
```

This drives the full nargo+bb prove/verify pipeline via `proveno-noir/tests/prove.rs` (which is **not** picked up by plain `cargo test` from the root). It prints prove/verify wall-time per test so circuit-size / prove-time regressions are visible. Slow (~20 s) and requires `nargo` and `bb` on `PATH`.

## Common Commands

```bash
# Build
cargo build                          # debug, all workspace members
cargo build -p proveno                  # core library only

# Test
cargo test                           # all tests
cargo test --lib                     # unit tests only (fast)
cargo test --test integration        # one integration file (also: builtins, compiler, json, tools)
cargo test --lib engine              # filter by name within unit tests

# Feature-gated builds
cargo build --features zkvm          # enable zkvm module
cargo test --features "serde zkvm"   # test with serde + zkvm features

# Run CLI tools
cargo run -p proveno-compiler -- source.lua compiled.json
cargo run -p proveno-prover   -- compiled.json dry_result.json
cargo run -p proveno-orchestrator -- "natural language task"

# Noir prove/verify benchmark (drives the full nargo+bb pipeline; prints prove/verify wall time)
# Requires `nargo` and `bb` on PATH.
cargo test -p proveno-noir --test prove end_to_end_prove_and_verify -- --nocapture
```

There is no separate lint command; `cargo test` exercises the full suite including doc-tests. `cargo clippy` is not currently part of the gate.

## Workspace Layout

| Crate | Role |
|---|---|
| `proveno` (root) | Core library: parser, compiler, bytecode, VM, host |
| `proveno-compiler` | CLI: compiles Lua source → verified bytecode JSON |
| `proveno-prover` | CLI: dry-runs bytecode, produces oracle tape + public inputs |
| `proveno-orchestrator` | LLM-driven agent loop (Claude API + live tool execution; `--prove` runs the full Noir pipeline) |
| `proveno-noir` | Noir witness writer + `nargo`/`bb` prover driver (canonical proving path) |
| `proveno-verifier` | Small helper binaries (e.g. `policy-hash` prints the canonical policy commitment) |

Core library features: `default = ["std"]`, optional `serde`, optional `zkvm`. The `zkvm` feature exposes `PublicInputs` / commitment helpers used by the Noir proving path.

## Resource limits (defaults)

| Limit | Default |
|---|---|
| Gas | 10,000,000 |
| Memory | 64 MB |
| Call depth | 200 |
| Tool calls | 64 |
| Bytes in per call | 1 MB |
| Bytes out per call | 64 KB |
| JSON / string length | 64 KB |
| Table / call nesting depth | 32 |

## Available tools (orchestrator)

Programs invoke tools via `tool.call(name, args)`:

| Tool | Description |
|---|---|
| `http_get` | GET a URL → `{status, body}` |
| `http_post` | POST JSON to a URL → `{status, body}` |
| `kv_get` | Read from in-memory key-value store |
| `kv_set` | Write to in-memory key-value store |
| `llm_query` | Sub-query the LLM for fuzzy reasoning |
| `time_now` | Current Unix timestamp |

## Proving pipeline

Canonical Noir-only flow, end-to-end. Steps 1–3 are also driven in one shot by
the orchestrator's `--prove` flag; step 4 lives in `demo-noir-e2e.sh` (and its
local-anvil wrapper `demo-noir-e2e-local.sh`).

```bash
# 1. Compile Lua source -> verified bytecode JSON
cargo run -p proveno-compiler -- source.lua compiled.json

# 2. Dry-run with the live host -> oracle tape + public inputs
cargo run -p proveno-prover -- compiled.json dry_result.json

# 3. Generate the Noir UltraHonk proof
cargo run -p proveno-noir -- compiled.json dry_result.json --prove

# 1+2+3 in one shot: orchestrator --prove also invokes proveno-noir and prints the
# proof bytes + canonical bytes32[] public inputs ready for on-chain submission.
cargo run -p proveno-orchestrator -- "<task>" --prove

# 4. Submit on chain to ProvenoConsumer.consumeResult (or ProvenoVerifier.verify).
#    The demo script handles the full LLM -> proof -> chain flow locally.
ANTHROPIC_API_KEY=… bash demo-noir-e2e-local.sh "<task>"
```

Public inputs (8, in circuit-declaration order): `num_steps`, `program_hash`,
`return_value`, `tool_responses_hash`, `input_hash`, `output_hash`,
`attestation_hash`, `policy_hash`. The Solidity `PublicInputs` struct in
`contracts/src/Types.sol` mirrors this ordering exactly; reordering breaks
verification.

## Architecture

Proveno is a **programmable oracle**: it turns a simple program into a verifiable one. A program (often LLM-authored) is compiled to bytecode and executed inside a deterministic, sandboxed, bounded interpreter; a ZK proof attests that this exact program ran over these exact inputs and produced this exact output, and a smart contract verifies that proof on-chain before acting on the result. All tool calls are recorded in a cryptographic transcript that can be replayed for proof generation.

The proof guarantees **computation integrity** (the program ran correctly over the inputs it was given), not **data provenance** (that those inputs are authentic data from the real source). Provenance is **delegated, not built**: the `attestation_hash` public input *binds* (does not verify) a per-call provider attestation to the response bytes it covers, via `OracleTape::attestation_commitment`; a provider plugs in at `HostInterface::take_attestation`. Concrete providers (Pyth signatures, zkTLS networks) are follow-on work. Keep this boundary honest in docs and code comments — the circuit binds blobs, it does not authenticate them.

### Execution pipeline

```
Lua source
    → parser/          (lexer + recursive-descent → AST)
    → compiler/        (AST → register-based bytecode + constants + program hash)
    → bytecode/verifier.rs  (validates stack depth, branch targets)
    → vm/engine.rs     (instruction dispatch loop, gas + memory metering)
    → host/            (tool calls, transcript, oracle tape)
```

### Key modules in `src/`

- **`parser/`** — Lexer and recursive-descent parser. Disallows `require`, `os`, `io`, and other unsafe constructs at parse time. `tool.call()` is a first-class syntax node.
- **`compiler/`** — `codegen.rs` compiles AST to `Instruction` bytecode. `proto.rs` defines `FunctionProto`, `Instruction`, `Constant`. `mod.rs` exposes `compile()` and `canonical_hash()`.
- **`bytecode/`** — `Instruction` enum and `verifier.rs`. The verifier performs a single-pass stack-depth check across all control-flow paths before any instruction executes.
- **`vm/engine.rs`** — `Vm` struct and the main execution loop. Manages `CallFrame` stack, resolves builtins from sentinel strings, dispatches `ToolCall` through `ToolRegistry`.
- **`vm/builtins.rs`** — All standard library functions (`string.*`, `math.*`, `table.*`, `json.*`, `pcall`, `type`, `pairs_sorted`, `ipairs`, `log`, `print`).
- **`vm/gas.rs` + `vm/memory.rs`** — `GasMeter` and `MemoryMeter`; all allocations and instructions are charged. Exhaustion raises `VmError`.
- **`types/value.rs`** — `LuaValue` enum (`Nil | Boolean | Integer | LuaString | Table | Closure | Builtin`). No floats — integers only.
- **`types/table.rs`** — `LuaTable` with integer array section and string/integer hash section. `rawset_tracked()` returns `RawsetResult` for memory accounting.
- **`host/`** — `ToolRegistry<H>` wraps a `HostInterface`, enforces per-call quotas, records a `Transcript`. `OracleTape` / `TapeHost` enable deterministic replay. `canonical_serialize()` produces byte-for-byte reproducible JSON for hashing.
- **`zkvm/`** — `PublicInputs`, `GuestInput`, SHA-256 commitment helpers (feature-gated on `zkvm`).

### Calling convention (important for compiler + VM work)

- Parameters occupy local slots `0..param_count`. Register them with `register_param()`, not `declare_local()`.
- Non-parameter locals start at slot `param_count` via `declare_local()`.
- The verifier expects operand-stack depth = 0 at function entry (params are in slots, not on the operand stack).
- Jump offsets are relative to the instruction **after** the jump (`pc` has already incremented when `jump_by()` is called).

### Determinism invariants

No floats, no randomized hash iteration, no time-dependent calls. `pairs_sorted` / `IterInitSorted` iterate tables in canonical key order. `canonical_serialize()` is the single JSON encoding path used for hashing. These constraints are load-bearing for ZK proof soundness — do not introduce non-determinism.
