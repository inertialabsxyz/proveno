# Noir Proving Pipeline — Phased Implementation Plan

**Status:** Draft
**Created:** 2026-05-20
**Replaces:** OpenVM Month 3 work in `draft-roadmap.md`
**Motivation:** Benchmarks show 2.7x–8.7x proving speedup (growing with program size) using
Noir trace verification vs OpenVM re-execution. ARM-native proving is a secondary benefit.

---

## Context

The existing OpenVM pipeline proves execution by re-running the entire proveno VM inside a
RISC-V zkVM guest. The Noir pipeline instead proves execution by verifying a pre-recorded
execution trace in a bespoke circuit. Both produce the same 6-hash `PublicInputs`
commitment; the Noir approach is faster because there is no RISC-V interpreter overhead.

The starting point is `noir/src/main.nr` — a working circuit for a 16-opcode benchmark
ISA that verifies pc transitions, step continuity, program hash, and return value.

---

## Phases

### Phase 1 — Full ISA Encoding

**Goal:** Expand the circuit and add a Rust encoder so it can represent any compiled
proveno program — not just the 16-opcode benchmark subset.

**Why first:** Everything downstream (trace emission, witness generation, proof) depends
on a stable opcode mapping. Define it once here; all later phases reference it.

**Scope: single-function programs only.** `Call`, `Closure`, and `PCall` are out of
scope for this phase. Programs with nested function calls are deferred to Phase 3.

#### 1a. Opcode mapping

Define a canonical opcode ID for every proveno `Instruction` variant. The encoding is a
`u8` discriminant; the operand is a unified `i64` (zero for instructions with none).

| ID | Instruction       | Operand                      |
|----|-------------------|------------------------------|
| 0  | Nop               | 0                            |
| 1  | PushK             | constant index (u16 → i64)   |
| 2  | PushNil           | 0                            |
| 3  | PushTrue          | 0                            |
| 4  | PushFalse         | 0                            |
| 5  | Pop               | 0                            |
| 6  | Dup               | 0                            |
| 7  | LoadLocal         | slot (u8 → i64)              |
| 8  | StoreLocal        | slot (u8 → i64)              |
| 9  | LoadUp            | slot (u8 → i64)              |
| 10 | StoreUp           | slot (u8 → i64)              |
| 11 | NewTable          | 0                            |
| 12 | GetTable          | 0                            |
| 13 | SetTable          | 0                            |
| 14 | GetField          | constant index (u16 → i64)   |
| 15 | SetField          | constant index (u16 → i64)   |
| 16 | Add               | 0                            |
| 17 | Sub               | 0                            |
| 18 | Mul               | 0                            |
| 19 | IDiv              | 0                            |
| 20 | Mod               | 0                            |
| 21 | Neg               | 0                            |
| 22 | Eq                | 0                            |
| 23 | Ne                | 0                            |
| 24 | Lt                | 0                            |
| 25 | Le                | 0                            |
| 26 | Gt                | 0                            |
| 27 | Ge                | 0                            |
| 28 | Not               | 0                            |
| 29 | And               | jump offset (i16 → i64)      |
| 30 | Or                | jump offset (i16 → i64)      |
| 31 | Concat            | n values (u8 → i64)          |
| 32 | Len               | 0                            |
| 33 | Jmp               | jump offset (i16 → i64)      |
| 34 | JmpIf             | jump offset (i16 → i64)      |
| 35 | JmpIfNot          | jump offset (i16 → i64)      |
| 36 | Call              | argc (u8 → i64)  — Phase 3  |
| 37 | Ret               | n returns (u8 → i64)         |
| 38 | Closure           | proto index (u16 → i64) — Phase 3 |
| 39 | ToolCall          | 0                            |
| 40 | PCall             | argc (u8 → i64)  — Phase 3  |
| 41 | Log               | 0                            |
| 42 | Error             | 0                            |
| 43 | IterInitSorted    | jump offset (i16 → i64)      |
| 44 | IterInitArray     | jump offset (i16 → i64)      |
| 45 | IterNext          | jump offset (i16 → i64)      |

Define this mapping in `src/noir/opcodes.rs` in the root proveno crate.

#### 1b. Circuit changes (`noir/src/main.nr`)

- `MAX_BYTECODE`: increase from 64 to 512
- `assert(opcode <= 15)` → `assert(opcode <= 45)`
- Extend pc transition logic to cover all jump variants:
  - `Jmp (33)`: unconditional — `next_pc = pc + 1 + operand`
  - `JmpIf (34)`: jump when `stack_top != 0`
  - `JmpIfNot (35)`: jump when `stack_top == 0`
  - `And (29)`: short-circuit jump when `stack_top == 0` (falsy)
  - `Or (30)`: short-circuit jump when `stack_top != 0` (truthy)
  - `IterInitSorted (43)`, `IterInitArray (44)`: jump when `stack_top == 0` (empty sentinel)
  - `IterNext (45)`: jump when iterator exhausted (`stack_top == 0`)
  - `Ret (37)`: unconstrained next_pc (end of function)
  - All others: `next_pc = pc + 1`
- Update hash input buffer size: `MAX_BYTECODE * 9 = 4608` bytes

#### 1c. Rust bytecode encoder

New file: `src/noir/encoder.rs`

```rust
pub struct NoirBytecode {
    pub opcodes:  Vec<u8>,    // length = actual instruction count, padded to MAX_BYTECODE
    pub operands: Vec<i64>,
    pub program_hash: [u8; 32],
}

pub fn encode_program(program: &CompiledProgram) -> Result<NoirBytecode, EncodeError>;
```

- Flattens `program.prototypes[0].code` into opcode/operand pairs using the table above
- Returns `EncodeError::TooLong` if instruction count exceeds `MAX_BYTECODE`
- Returns `EncodeError::CallNotSupported` for Call/Closure/PCall (Phase 3)
- Computes `program_hash` via SHA-256 over (opcode || operand LE) for all MAX_BYTECODE
  slots including zero-padding — must match the circuit's hash computation exactly

#### 1d. Tests

- Unit tests in `src/noir/encoder.rs`: encode known programs, verify hash byte-for-byte
- Snapshot test: encode a compiled Lua program, assert hash is stable across runs

---

### Phase 2 — VM Trace Emission

**Goal:** The proveno VM records a full execution trace during every run, ready to be
passed to the Noir witness generator.

**Why second:** The trace format must match what the circuit expects. Lock it in before
building the witness serialiser.

#### 2a. TraceStep type

New file: `src/noir/trace.rs`

```rust
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceStep {
    pub pc:        u32,   // program counter of this instruction
    pub opcode:    u8,    // canonical opcode ID from Phase 1 mapping
    pub operand:   i64,   // unified operand (0 if none)
    pub stack_top: i64,   // value at top of stack BEFORE this instruction
                          // (used for conditional jump verification)
    pub next_pc:   u32,   // actual pc of the next step
}
```

#### 2b. VM engine changes (`src/vm/engine.rs`)

- Add `trace: Vec<TraceStep>` to `Vm` struct (empty when trace recording is disabled)
- Add `record_trace: bool` to `VmConfig` (default false — zero overhead for non-proving runs)
- Before each instruction dispatch: if `record_trace`, capture `(pc, opcode_id, operand, stack_top)`
- After each instruction dispatch: record `next_pc` = updated `frame.pc`
- Add `trace: Vec<TraceStep>` to `VmOutput`
- Single-frame only for this phase (no cross-frame trace continuity yet — deferred to Phase 3)

#### 2c. Tests

- Integration test: run a program with `record_trace: true`, assert trace length == expected
- Correctness test: for each opcode class, assert `next_pc` in trace matches expected transition
- Determinism test: same program produces byte-identical trace on two runs

---

### Phase 3 — Witness Pipeline and `proveno-noir` Crate

**Goal:** A new `proveno-noir` crate that takes a `CompiledProgram + VmOutput` and
produces a verified Noir proof, mirroring the role of `proveno-openvm`.

**Also in this phase:** multi-function program support (Call, Closure, Ret across frames).

#### 3a. Multi-function trace continuity

When `Call` executes, the next step's pc is 0 in the callee's frame. When `Ret`
executes, the next pc is the return address in the caller's frame. The simple
`next_pc = pc + 1` rule breaks across frame boundaries.

The circuit treats this as: `Call` and `Ret` have unconstrained `next_pc` (same as
`Ret` is treated today). Frame correctness is instead guaranteed by the native VM
execution — the trace is generated by the honest prover running the real VM.

This is a pragmatic choice: it does not prove call/return correctness inside the
circuit, but does prove that the sequence of instructions executed (and their pc
transitions within each frame) matches the bytecode. Full call-frame verification is
deferred to a later phase if required.

Update the circuit to add Call (36), PCall (40), and Closure (38) to the
unconstrained-next_pc set alongside Ret (37).

#### 3b. `proveno-noir` crate structure

```
proveno-noir/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── witness.rs      # serialises bytecode + trace → Prover.toml
    └── prover.rs       # calls nargo, returns proof bytes + public inputs
```

Not added to the proveno workspace as a default member — enable via `--features noir` or
include conditionally. Mirror the `proveno-openvm` crate structure.

#### 3c. Witness serialiser (`witness.rs`)

```rust
pub struct NoirWitness {
    pub bytecode_opcodes:  [u8; MAX_BYTECODE],
    pub bytecode_operands: [i64; MAX_BYTECODE],
    pub trace_pcs:         Vec<u32>,   // padded to MAX_STEPS
    pub trace_opcodes:     Vec<u8>,
    pub trace_operands:    Vec<i64>,
    pub trace_stack_tops:  Vec<i64>,
    pub trace_next_pcs:    Vec<u32>,
    pub num_steps:         u32,        // public
    pub program_hash:      [u8; 32],   // public
    pub return_value:      i64,        // public
}

pub fn build_witness(
    bytecode: &NoirBytecode,
    trace: &[TraceStep],
    return_value: i64,
) -> Result<NoirWitness, WitnessError>;

pub fn write_prover_toml(witness: &NoirWitness, path: &Path) -> Result<(), io::Error>;
```

`write_prover_toml` produces `Prover.toml` in the format nargo expects. Arrays are
written as TOML inline arrays of integers.

#### 3d. Prover (`prover.rs`)

```rust
pub struct NoirProver {
    pub circuit_dir: PathBuf,   // path to the noir/ directory with Nargo.toml
}

pub struct NoirProof {
    pub proof_bytes:    Vec<u8>,
    pub public_inputs:  NoirPublicInputs,
    pub prove_duration: Duration,
}

impl NoirProver {
    pub fn prove(&self, witness: &NoirWitness) -> Result<NoirProof, ProveError>;
    pub fn verify(&self, proof: &NoirProof) -> Result<bool, ProveError>;
}
```

Calls `nargo prove` and `nargo verify` via `std::process::Command`. Times each phase.
Returns `ProveError::NargoNotFound` with install instructions if nargo is missing.

#### 3e. Tests

- End-to-end: compile a Lua program, execute with trace, prove, verify — asserts `verified == true`
- Multi-function: a program with one function call proves correctly
- Negative: tampered `return_value` in witness fails verification

---

### Phase 4 — Oracle Tape Verification

**Goal:** The circuit verifies that tool call responses match a committed hash, closing
the trust gap on oracle data.

**Why this matters:** Without this, the prover could substitute different tool
responses in the witness and the circuit would not detect it. `program_hash` and
`return_value` alone do not prevent this.

#### 4a. Circuit changes

New public input: `tool_responses_hash: pub [u8; 32]`

New witnesses:
```noir
tape_entry_lengths: [u32; MAX_TOOL_CALLS],
tape_entry_data:    [[u8; MAX_TAPE_ENTRY_BYTES]; MAX_TOOL_CALLS],
tape_entry_tags:    [u8; MAX_TOOL_CALLS],   // 0x00 = Ok, 0x01 = Err
num_tool_calls:     u32,
```

Suggested constants: `MAX_TOOL_CALLS = 64`, `MAX_TAPE_ENTRY_BYTES = 1024`.

Circuit logic added to the step loop: when `opcode == 39` (ToolCall), consume the
next tape entry and update a running hash accumulator. After all steps, assert the
final accumulator equals `tool_responses_hash`.

The hash framing matches `OracleTape::commitment_hash()`:
for each entry: `tag (1 byte) || length (4 bytes LE) || payload`.

#### 4b. Witness changes (`witness.rs`)

Add tape entries to `NoirWitness` and `build_witness`. Extract tape entries from
`VmOutput.transcript` using `OracleTape::from_records()`.

#### 4c. `NoirPublicInputs`

```rust
pub struct NoirPublicInputs {
    pub program_hash:        [u8; 32],
    pub return_value:        i64,
    pub tool_responses_hash: [u8; 32],
    pub num_steps:           u32,
}
```

#### 4d. Tests

- Program with tool calls proves correctly end-to-end
- Tampered tape entry fails verification
- Empty tape (`tool_responses_hash = SHA256("")`) proves for programs with no tool calls

---

### Phase 5 — Full Public Inputs Parity

**Goal:** The Noir proof produces the same 6-hash `PublicInputs` as the OpenVM proof,
enabling a clean swap at the verifier layer.

```rust
pub struct PublicInputs {
    pub program_hash:        [u8; 32],
    pub input_hash:          [u8; 32],
    pub tool_responses_hash: [u8; 32],
    pub output_hash:         [u8; 32],
    pub tls_attestation_hash:[u8; 32],
    pub policy_hash:         [u8; 32],
}
```

#### 5a. `input_hash`

SHA-256 of `canonical_serialize(input_value)`. Computed by the host and added as a
public input. The circuit does not re-derive it — the host computes it and the
verifier checks it against the expected input.

Add `input_hash: pub [u8; 32]` to `main.nr`. No circuit logic needed beyond declaring it.

#### 5b. `output_hash`

SHA-256 over: `canonical_serialize(return_value) || logs || transcript records`.
This is the same formula as `hash_output()` in `src/zkvm/commitment.rs`.

Add `output_hash: pub [u8; 32]` to `main.nr`. Computed by the host from `VmOutput`
using the existing `hash_output()` function. No circuit recomputation needed — binding
`return_value` in the circuit (Phase 1) already anchors the output; `output_hash`
adds the log and transcript commitment on top.

#### 5c. `policy_hash`

SHA-256 of the canonical policy document. Computed by the host and passed as a public
input `policy_hash: pub [u8; 32]`. No circuit logic needed — the verifier checks
this against the expected policy off-chain or on-chain.

#### 5d. `tls_attestation_hash`

P-256 ECDSA certificate chain verification using Noir's native
`std::ecdsa_secp256r1::verify_signature` gadget.

New witnesses per certificate (up to `MAX_CERTS = 4`):
```noir
cert_public_key_x: [[u8; 32]; MAX_CERTS],
cert_public_key_y: [[u8; 32]; MAX_CERTS],
cert_signatures:   [[u8; 64]; MAX_CERTS],
cert_msg_hashes:   [[u8; 32]; MAX_CERTS],
num_certs:         u32,
```

Circuit: verify each certificate's P-256 signature, accumulate cert hashes into a
running SHA-256, assert the final accumulator equals `tls_attestation_hash`.

The host extracts these fields from `VmOutput`'s `TlsAttestationRecord` list and
packs them into the witness. For programs with no HTTPS tool calls, `num_certs = 0`
and `tls_attestation_hash = [0u8; 32]`.

#### 5e. Tests

- Full 6-hash `PublicInputs` from Noir matches those computed by the existing
  `compute_public_inputs()` for the same program + input + oracle tape
- Regression: changing any input changes the corresponding hash and fails verification

---

### Phase 6 — On-Chain Verifier

**Goal:** A smart contract on an EVM-compatible chain can verify a Noir proof against
a claimed `PublicInputs`, replacing the OpenVM Groth16 verifier.

#### 6a. Solidity verifier generation

Noir's toolchain generates a Solidity verifier from the compiled circuit:

```bash
nargo codegen-verifier
```

This produces `contract/plonk_vk.sol` (UltraHonk verification key + verifier logic).
Add this as a generated artifact committed to `noir/contract/`.

The verifier exposes:
```solidity
function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
```

#### 6b. Public inputs encoding

The 6 hashes must be encoded as a `bytes32[]` array in the order the circuit declares
them. Document the canonical ordering in `noir/README.md`. The on-chain consumer pins
this ordering via their contract.

#### 6c. Integration with existing contracts

The existing `ProvenoVerifier.sol` (or equivalent) is updated to call the Noir Solidity
verifier instead of the OpenVM Groth16 verifier. The `PublicInputs` struct and
`policy_hash` enforcement logic remain unchanged — only the proof verification call
changes.

#### 6d. Tests

- Deploy the Solidity verifier to a local Anvil/Hardhat instance
- Pass a valid Noir proof → assert `verify()` returns `true`
- Pass a tampered proof → assert `verify()` returns `false`
- Gas measurement: record `verify()` gas cost and compare to OpenVM Groth16 baseline

---

## Circuit size budget

| Constant         | Phase 1 | Target |
|------------------|---------|--------|
| MAX_BYTECODE     | 512     | 512    |
| MAX_STEPS        | 16,384  | 16,384 |
| MAX_TOOL_CALLS   | —       | 64     |
| MAX_TAPE_ENTRY_BYTES | —   | 1,024  |

`MAX_STEPS = 16,384` is the primary driver of circuit size and proving time. At the
benchmark rate of ~1 second per 1,024 steps (flat for Noir), a 16,384-step circuit
proves in approximately 16 seconds — acceptable for async/batch use cases. If proving
time needs to be lower, reduce `MAX_STEPS` and enforce a tighter gas limit on programs
submitted to the proving pipeline.

---

## Relationship to existing OpenVM pipeline

The two pipelines can coexist. `DryRunResult` and `PublicInputs` are shared types.
Phase 5 completes parity so the same `PublicInputs` is produced by both provers for
the same execution. Until Phase 6 is complete, OpenVM remains the on-chain verifier.

The Noir pipeline becomes the default prover once Phase 6 ships and the Solidity
verifier is deployed.

---

## Decisions

1. **Proving time threshold: 30 seconds.** This is the maximum acceptable wall-clock
   time for end-to-end proof generation. Extrapolating from benchmarks (1024 steps ≈
   1 second flat), the full proveno circuit at `MAX_STEPS = 16,384` with oracle tape
   SHA-256 and the richer ISA will likely be 2–3x heavier per step, putting the
   estimate at 32–48 seconds — potentially over budget. `MAX_STEPS` may need to be
   reduced to 8,192 to comfortably hit 30 seconds. Benchmark after Phase 3 completes
   and tune before Phase 4.

2. **Intermediate stack state verification: deferred.** The circuit verifies pc
   transitions and the final return value but not intermediate stack state. This is
   acceptable for the first pass. The prover is the oracle operator; the verifier cares
   about `program_hash + return_value + tool_responses_hash`. Full stack state
   verification can be added in a later phase if the trust model requires it.

3. **TLS attestation in-circuit: use `std::ecdsa_secp256r1`.** Noir has a native
   built-in for P-256 ECDSA:
   ```noir
   std::ecdsa_secp256r1::verify_signature(
       public_key_x: [u8; 32],
       public_key_y: [u8; 32],
       signature:    [u8; 64],
       message_hash: [u8; 32],
   ) -> bool
   ```
   This is a first-class gadget compiled to optimised constraints. Phase 5b (TLS
   attestation in-circuit) is therefore not deferred — it is included in Phase 5 using
   this built-in. Call it once per certificate in the chain. The witness carries the
   certificate public keys, signatures, and message hashes; the circuit verifies each
   and accumulates `tls_attestation_hash` via a running SHA-256.
