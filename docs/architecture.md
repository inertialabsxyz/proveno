# Architecture

## What proveno is

Proveno runs **verifiable tasks**: small programs, often LLM-authored, written
in plain Lua. A task is compiled to bytecode and executed inside a
deterministic, sandboxed, bounded interpreter; a ZK proof attests that this
exact program ran over these exact inputs and produced this exact output, and a
verifier — off-chain, or a smart contract on-chain — checks it before acting on
the result. All tool calls are recorded in a cryptographic transcript that can
be replayed for proof generation.

A verifiable task proves two things side by side, in one proof: **execution**
(always — the program ran exactly as written over exactly these inputs) and
**provenance** (when a provider is attached — the inputs were authentic;
proveno *binds* the attestation, the provider *produces* it).

## What proveno is not

The identity is horizontal. Verifiable tasks are useful wherever a result must
be trusted. On-chain verification — a contract acting on a task's proof,
coprocessor-style — is its first high-value **application**, not its category.

Proveno is **not an oracle**. It touches the oracle world by consuming attested
inputs, but "oracle" promises data provenance, which is the provider's job, not
proveno's. The zkVM is the proving **mechanism**, not the identity; the Noir
backend could retarget without changing what proveno is.

This distinction is load-bearing and has already been got wrong once: the
application repository was originally named `proveno-oracle`, which contradicted
this paragraph and misdescribed its own contents.

## The boundary that matters

The proof guarantees **computation integrity** — the program ran correctly over
the inputs it was given — not **data provenance**, that those inputs are
authentic data from the real source.

Provenance is **delegated, not built**. The `attestation_hash` public input
*binds* (does not verify) a per-call provider attestation to the response bytes
it covers, via `OracleTape::attestation_commitment`. A provider plugs in at
`HostInterface::take_attestation`, which yields opaque `Vec<u8>`; nothing in the
runtime or the circuit interprets those bytes. Concrete providers (Pyth
signatures, zkTLS networks) are follow-on work; the TLS provider in
proveno-agent is the only one that exists.

Keep this boundary honest in docs and code comments. **The circuit binds blobs,
it does not authenticate them.**

## Layering

```
proveno-agent ───> proveno-zk ───> proveno-core
                                        ^
proveno-gateway ────────────────────────┘
```

**proveno-core** is the runtime and nothing else: parser, compiler, bytecode
verifier, VM, host, the ISA, and the record/replay machinery. It is
`no_std`-capable and has no notion of policy, HTTP, X.509, Ethereum or LLMs. Its
dependency tree is 22 crates with no default features.

**proveno-zk** is everything about proving: the execution policy and its two
enforcing host wrappers, the public-input commitments, the Noir circuit and
witness writer, the OpenVM guest and host, and the Solidity verifier and
consumer.

**proveno-agent** is how a task becomes an execution: the LLM orchestrator, the
demo server, and the TLS provenance provider.

**proveno-gateway** is an application of the runtime, not a new identity for
proveno. It is an MCP server whose one tool runs an agent-written Lua program;
every tool call the program makes is schema- and policy-checked, has its
credential injected by the gateway, is dispatched to a downstream MCP server,
and is recorded in a signed trace that replays bit-for-bit. It never calls a
model: it receives programs, not tasks. It depends on proveno-core only. Its
trace is built on core's transcript and oracle tape, so it is already the
witness a proof would consume, but proving is not in its scope yet. The spec
is `planning/proveno-gateway-spec.md`.

## Two commitment schemes

`program_hash`, `tool_responses_hash` and `attestation_hash` are
**backend-specific**. `input_hash` (SHA-256) and `output_hash` (keccak256) are
not — they are fixed by their consumers.

| Backend | Scheme | Constructor |
|---|---|---|
| Noir / UltraHonk | Poseidon2 | `compute_public_inputs` |
| zkVM (OpenVM) | SHA-256 | `compute_public_inputs_sha256` |

Poseidon2 is right inside a circuit, where BN254 is native and SHA-256 costs
~25k constraints per block. In a RISC-V zkVM the cost model inverts: one
Poseidon2 permutation is 488 software 254-bit modmuls absorbing 3 bytes (rate 3,
byte-per-field), against one accelerated instruction per 64-byte block for
SHA-256.

The two are **not interchangeable**. A verifier must recompute with the scheme
the prover used.

## Determinism invariants

These are load-bearing for proof soundness, not style preferences. They live in
proveno-core and must not be weakened by anything above it.

- **No floats.** Integers only, throughout `LuaValue`.
- **No randomized iteration.** `pairs_sorted` and `IterInitSorted` walk tables
  in canonical key order.
- **One JSON encoding.** `canonical_serialize()` is the single path used for
  hashing, and the same one `json.encode` uses.
- **No ambient I/O.** `require`, `os` and `io` are rejected at parse time. The
  only side-effecting primitive is a tool call, and every one is recorded.
- **Everything metered.** Gas and memory are charged on every instruction and
  allocation; exhaustion is a `VmError`, not a panic.

Given the same program and the same sequence of host responses, execution is
byte-identical. Replay depends on this, and it is tested rather than assumed.

## Known gaps

**The Poseidon2 program hash does not cover constants.**
`compute_program_hash` hashes only the `(opcode, operand)` instruction stream.
`PushK`, `GetField` and `SetField` carry a constant-pool *index*, so `return 1`,
`return 2` and `return "omega"` compile to the same stream and hash
identically. A prover can swap every literal in a program and still match a
committed `program_hash`.

`compute_program_hash_sha256`, the zkVM path, does not have this gap: it covers
the constant pool, upvalue descriptors and prototype metadata. Closing it on the
Noir side means changing `assert_bytecode` in `noir/src/main.nr` in lockstep,
which invalidates existing verification keys. The gap is open and **not** pinned
by a test.

**`VmConfig` is not bound by any public input.** The prover chooses the gas and
memory limits, which determine whether an execution completes or aborts.

**JSON schema validation is host-side only.** `required_output_schema` and
`schema_versions` are committed in `policy_hash` but not enforced in-guest,
because validation needs `serde_json`. The same boundary as `attestation_hash`:
bound, not verified.
