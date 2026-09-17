# Architecture

## What proveno is

Proveno runs **verifiable tasks**: small programs, often LLM-authored, written
in plain Lua. A task is compiled to bytecode and executed inside a
deterministic, sandboxed, bounded interpreter. Every tool call the program makes
is recorded in a transcript, and the responses form an oracle tape whose hash is
committed, so a run can be replayed exactly without touching the network again.

A run can then be proved. On **OpenVM**, the canonical proving backend, the
proof shows that the interpreter re-executed this exact program over this input
and this tape and produced this output. A verifier checks that proof off-chain
today. No on-chain verifier for OpenVM proofs exists yet. What each backend
covers is set out in [Proving backends](#proving-backends).

A verifiable task carries two things side by side: **execution** (the program
ran exactly as written over exactly these inputs, which a proof establishes on
OpenVM) and **provenance** (the inputs were authentic, which proveno only
*binds*: a provider has to *produce* the attestation, and no provider is working
today).

## What proveno is not

The identity is horizontal. Verifiable tasks are useful wherever a result must
be trusted. The first application is agent teams: the gateway puts a policy
between an agent's program and the tools it calls, and records a signed trace
that replays exactly. On-chain consumption, a contract acting on a
task's proof, comes next, once OpenVM proofs verify on-chain. Neither is the
category.

Proveno is **not an oracle**. It touches the oracle world by consuming attested
inputs, but "oracle" promises data provenance, which is the provider's job, not
proveno's.

OpenVM is the canonical backend, but a zkVM is the proving **mechanism**, not
the identity. What proveno is lies in the runtime and its determinism
invariants. The OpenVM guest runs that same interpreter as ordinary Rust, so
another zkVM could host it without changing what a task means, and the Noir
circuit remains a second backend in development.

This distinction is load-bearing and has already been got wrong once: the
application repository was originally named `proveno-oracle`, which contradicted
this section and misdescribed its own contents.

## The boundary that matters

The proof guarantees **computation integrity** (the program ran correctly over
the inputs it was given), not **data provenance** (that those inputs are
authentic data from the real source). Even the first half holds only on OpenVM
today; see [Proving backends](#proving-backends).

Provenance is **delegated, not built**. The `attestation_hash` public input
*binds* (does not verify) a per-call provider attestation to the response bytes
it covers, via `OracleTape::attestation_commitment` (Poseidon2) or its twin
`attestation_commitment_sha256`. A provider plugs in at
`HostInterface::take_attestation`, which yields opaque `Vec<u8>`; nothing in the
runtime or the circuit interprets those bytes. The binding covers the response,
not the request that produced it.

No attestation provider is working today:

- **proveno-agent** has TLS code that captures a server's certificate chain. It
  does not bind the response body, so it cannot show what the server returned,
  and no host calls it.
- **proveno-gateway** is the only host that supplies attestations. It relays the
  provenance object a downstream MCP server reports about its own response
  (`unsigned`, `signed`, `onchain` or `notarized`), checks only its shape, and
  binds it. The claim is the downstream's, unverified.

Response-authenticating providers (signed feeds, zkTLS, notarisation networks)
are roadmap work.

Keep this boundary honest in docs and code comments. **The circuit binds blobs,
it does not authenticate them.**

## Layering

```
proveno-agent ───> proveno-zk ───> proveno-core
      │                                 ^  ^
      └─────────────────────────────────┘  │
proveno-gateway ───────────────────────────┘
```

Dependencies point strictly inward, by git tag. The pins are not aligned:
proveno-zk and proveno-agent build against an older core tag than
proveno-gateway, so builtins added to core since then run in the gateway but
cannot yet be proved.

**proveno-core** is the runtime and nothing else: parser, compiler, bytecode
verifier, VM, host, the ISA, and the record/replay machinery. It is
`no_std`-capable and has no notion of policy, HTTP, X.509, Ethereum or LLMs.
With no default features it pulls in 12 external crates.

**proveno-zk** is everything about proving: the execution policy and its two
enforcing host wrappers, the public-input commitments, the OpenVM guest and
host, the Noir circuit and witness writer, and the Solidity contracts (a
verifier, a consumer and a bounty), which target the Noir backend.

**proveno-agent** is how a task becomes an execution: the LLM orchestrator, the
demo server, and the TLS certificate-chain code described above.

**proveno-gateway** is an application of the runtime, not a new identity for
proveno. It is an MCP server whose `execute` tool runs an agent-written Lua
program, alongside a `check` tool that only lints one. Every tool call the
program makes is schema- and policy-checked, has its credential injected by the
gateway, is dispatched to a downstream MCP server, and is recorded in a trace
signed with the operator's key. Replay reproduces the output, the status kind,
gas and memory. It never calls a model: it receives programs, not tasks. It
depends on proveno-core only. Its trace is built on core's transcript and oracle
tape, commits the SHA-256 program hash (the OpenVM scheme) and records the
`VmConfig` in its signed header, so it is already the witness an OpenVM proof
would consume. No proof is generated on this path yet. The spec is
[planning/proveno-gateway-spec.md](../planning/proveno-gateway-spec.md).

## Proving backends

| | OpenVM (canonical) | Noir / UltraHonk (in development) |
|---|---|---|
| What the proof covers | The guest re-executes the interpreter over the program, input and tape, then commits the results | That a claimed trace follows the committed bytecode's opcodes and control flow |
| Computation | Constrained | Not constrained: stack values, builtins and tool responses are free witnesses |
| `input_hash`, `policy_hash` | Derived in the guest | Public inputs the circuit never constrains |
| Execution policy | Enforced in the guest for HTTP tools | Not enforced |
| Verifier | Off-chain, with OpenVM's own tooling; no on-chain verifier yet | Solidity contracts exist, but inherit the limits above |

On OpenVM the guest reveals one SHA-256 digest of the six commitments; the
verifier receives the six values out of band and recomputes it.

On Noir, a proof **does not attest to a result**: the return value is tied only
to a claimed stack top, so a valid proof can carry a value the program did not
produce. The circuit is also bounded at compile time (bytecode, steps, tool
calls and tape entry size), and its tape entry bound is smaller than typical API
responses. The Noir backend may be pursued later; until then nothing should act
on a Noir proof, on-chain or off.

`proveno-verifier` in proveno-zk checks an integrity envelope, not a proof. It
is not a cryptographic verifier for either backend.

## Two commitment schemes

`program_hash`, `tool_responses_hash` and `attestation_hash` are
**backend-specific**. `input_hash` (SHA-256) and `output_hash` (keccak256) are
not; they are fixed by their consumers. `output_hash` covers
`abi.encode(int256)` of an integer return value, and any other return type
proves as `0` on both backends.

| Backend | Scheme | Constructor |
|---|---|---|
| zkVM (OpenVM) | SHA-256 | `compute_public_inputs_sha256` |
| Noir / UltraHonk | Poseidon2 | `compute_public_inputs` |

Both constructors take `program_hash` as a parameter. Which scheme it uses is
chosen when core is compiled (its `poseidon` feature); the OpenVM guest
recomputes the SHA-256 program hash itself.

Poseidon2 is right inside a circuit, where BN254 is native and SHA-256 costs an
estimated 25k constraints per block. In a RISC-V zkVM the cost model inverts: one
Poseidon2 permutation is 488 software 254-bit modmuls absorbing 3 bytes (rate 3,
byte-per-field), while SHA-256 can be a single accelerated instruction per
64-byte block. That acceleration is not in use yet: OpenVM's SHA-256 extension
is enabled, but proveno still hashes in software, so the chip sits idle.

The two are **not interchangeable**, and nothing in the public inputs names the
scheme. A verifier must recompute with the scheme the prover used.

## Determinism invariants

These are load-bearing for proof soundness, not style preferences. They live in
proveno-core and must not be weakened by anything above it.

- **No floats.** Integers only, throughout `LuaValue`.
- **No randomized iteration.** `pairs`, `pairs_sorted` and `IterInitSorted` all
  walk tables in canonical key order.
- **One JSON encoding.** `canonical_serialize()` is the single path used for
  hashing, and the same one `json.encode` uses.
- **No ambient I/O.** `require`, `os` and `io` are rejected at parse time. The
  only side-effecting primitive is a tool call, and every one is recorded.
- **Everything metered.** Gas and memory are charged on every instruction and
  allocation; exhaustion is a `VmError`, not a panic.

Given the same program and the same sequence of host responses, execution is
identical: same output, gas and memory. Replay depends on this, and it is tested
in core, proveno-zk and proveno-gateway rather than assumed.

## Known gaps

**The Noir circuit constrains control flow, not computation.** Described under
[Proving backends](#proving-backends). Its `input_hash` and `policy_hash` are
unconstrained public inputs. Every gap below that mentions Noir is secondary to
this one.

**The Poseidon2 program hash does not cover constants.**
`compute_program_hash` hashes only the `(opcode, operand)` instruction stream.
`PushK`, `GetField` and `SetField` carry a constant-pool *index*, so `return 1`,
`return 2` and `return "omega"` compile to the same stream and hash
identically. Prototype boundaries, arity and upvalues are omitted too.

`compute_program_hash_sha256`, the OpenVM path, does not have this gap: it
covers the constant pool, upvalue descriptors and prototype metadata. Closing it
on the Noir side means changing `assert_bytecode` in the circuit in lockstep,
which invalidates existing verification keys. The gap is open and **not** pinned
by a test.

**`VmConfig` is not bound by any public input.** The prover chooses the gas and
memory limits, which determine whether an execution completes or aborts. Quota
errors can be caught by `pcall`, so the config can also steer a program into its
fallback branch. The gateway records the config in its signed trace header, which
binds it to the operator's signature, not to a proof. Tracked in [proveno-zk#3](https://github.com/inertialabsxyz/proveno-zk/issues/3).

**Schema checks are host-side or absent.** `required_output_schema` and
`schema_versions` are both committed in `policy_hash`. `schema_versions` is
checked host-side only, as a structural type match, so a proof does not enforce
it. `required_output_schema` is enforced nowhere. On Noir no policy field is
enforced at all. Tracked in [proveno-zk#7](https://github.com/inertialabsxyz/proveno-zk/issues/7).

**The output binds only an integer.** Tables, strings and booleans prove as `0`.
Tracked in [proveno-zk#2](https://github.com/inertialabsxyz/proveno-zk/issues/2).

**OpenVM verification is incomplete.** There is no on-chain verifier and no EVM
proof. Off-chain, comparing the revealed digest with the recomputed commitments
is not automated, and the guest's proving keys and executable commitment are not
pinned, so a verifier has no canonical guest identity to check against. Tracked in
[proveno-zk#8](https://github.com/inertialabsxyz/proveno-zk/issues/8) and [proveno-zk#14](https://github.com/inertialabsxyz/proveno-zk/issues/14).

**Core version skew.** The proving stack and the gateway pin different core
tags, so programs using newer builtins can run in the gateway but cannot yet be
proved. Tracked in [proveno-zk#1](https://github.com/inertialabsxyz/proveno-zk/pull/1).
