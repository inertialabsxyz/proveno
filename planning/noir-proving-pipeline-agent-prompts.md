# Agent Prompts — Noir Proving Pipeline

These prompts are designed to be handed directly to a Claude Code agent. Each is self-contained. Agents work on git branches and do not share state during execution. Read the sequencing notes before dispatching.

---

## Sequencing Overview

```
Step 1 (single agent):   Phase 1 — Full ISA Encoding
                              │
Step 2 (single agent):   Phase 2 — VM Trace Emission
                              │
Step 3 (single agent):   Phase 3 — Witness Pipeline + luai-noir Crate
                              │
Step 4 (single agent):   Phase 4 — Oracle Tape Verification
                              │
Step 5 (single agent):   Phase 5 — Full Public Inputs Parity
                              │
Step 6 (single agent):   Phase 6 — On-Chain Verifier
```

Do not start any step until the previous step is merged to master. All phases are sequential — each depends on types and modules introduced by the previous phase.

---

## Step 1 — Phase 1: Full ISA Encoding

**Branch:** `noir/1-isa-encoding`
**Depends on:** current master

**Prompt:**

You are implementing Phase 1 of the luai Noir proving pipeline. The full specification is in `planning/noir-proving-pipeline-plan.md` under "Phase 1 — Full ISA Encoding". Read that section carefully before writing any code.

### Context

luai is a deterministic sandboxed Lua VM. The full execution pipeline is complete:

- `src/compiler/proto.rs` — `Instruction` enum with 46 variants (`Nop`, `PushK`, `PushNil`, `PushTrue`, `PushFalse`, `Pop`, `Dup`, `LoadLocal`, `StoreLocal`, `LoadUp`, `StoreUp`, `NewTable`, `GetTable`, `SetTable`, `GetField`, `SetField`, `Add`, `Sub`, `Mul`, `IDiv`, `Mod`, `Neg`, `Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`, `Not`, `And`, `Or`, `Concat`, `Len`, `Jmp`, `JmpIf`, `JmpIfNot`, `Call`, `Ret`, `Closure`, `ToolCall`, `PCall`, `Log`, `Error`, `IterInitSorted`, `IterInitArray`, `IterNext`). Operands are typed: `u8`, `u16`, or `i16` depending on the variant.
- `src/vm/engine.rs` — `Vm` struct and execution loop. `VmConfig` controls gas limit, memory limit, call depth.
- `src/host/` — `ToolRegistry`, `Transcript`, `OracleTape`, `canonical_serialize`.
- `src/zkvm/commitment.rs` — `PublicInputs` with six `[u8; 32]` hashes.
- `openvm/` — existing OpenVM guest + encoder (do not modify).
- `noir/src/main.nr` — a working Noir circuit for a 16-opcode benchmark ISA. `MAX_BYTECODE = 64`, `MAX_STEPS = 16384`. Verifies program hash, pc transitions, step continuity, and return value.

`cargo test` passes and must continue to pass after your changes.

### Your Task

**Part A — Define the canonical opcode mapping** as specified in `planning/noir-proving-pipeline-plan.md` under "1a. Opcode mapping":

1. Create `src/noir/mod.rs` exposing `pub mod opcodes; pub mod encoder;`.
2. Create `src/noir/opcodes.rs`. Define `pub const` for every luai `Instruction` variant using the ID table in the spec (Nop=0 through IterNext=45). Define `pub fn instruction_to_opcode_id(i: &Instruction) -> u8` and `pub fn instruction_to_operand(i: &Instruction) -> i64` that convert any `Instruction` to its `(u8, i64)` pair. Add `pub mod noir;` to `src/lib.rs`.
3. Unit-test `instruction_to_opcode_id` and `instruction_to_operand` for every variant in a `#[cfg(test)]` block in `src/noir/opcodes.rs`.

**Part B — Rust bytecode encoder** as specified under "1c. Rust bytecode encoder":

4. Create `src/noir/encoder.rs`. Define:
   ```rust
   pub const MAX_BYTECODE: usize = 512;

   pub struct NoirBytecode {
       pub opcodes:      [u8; MAX_BYTECODE],
       pub operands:     [i64; MAX_BYTECODE],
       pub program_hash: [u8; 32],
       pub instr_count:  usize,
   }

   pub enum EncodeError {
       TooLong { count: usize },
       CallNotSupported,   // Call, Closure, PCall — Phase 3
   }

   pub fn encode_program(program: &CompiledProgram) -> Result<NoirBytecode, EncodeError>;
   ```
   `encode_program` flattens `program.prototypes[0].code`, converts each instruction using `instruction_to_opcode_id`/`instruction_to_operand`, zero-pads to `MAX_BYTECODE`, then computes `program_hash` as SHA-256 over `(opcode_byte || operand_le_bytes) * MAX_BYTECODE` — including padding. Uses the `sha2` crate already in the workspace.

5. Add snapshot tests: compile two known Lua programs (e.g. `"return 1 + 2"` and a loop), encode them, assert `program_hash` is stable across two calls with identical input.

**Part C — Circuit changes** as specified under "1b. Circuit changes":

6. Edit `noir/src/main.nr`:
   - Change `global MAX_BYTECODE: u32 = 64` to `512`.
   - Update the hash input buffer size constant comment from `MAX_BYTECODE * 9 = 576` to `4608`.
   - Change `assert(opcode <= 15)` to `assert(opcode <= 45)`.
   - Extend the `expected_next_pc` computation to cover all jump variants: `Jmp(33)` unconditional; `JmpIf(34)` jump when `stack_top != 0`; `JmpIfNot(35)` jump when `stack_top == 0`; `And(29)` jump when `stack_top == 0`; `Or(30)` jump when `stack_top != 0`; `IterInitSorted(43)`, `IterInitArray(44)`, `IterNext(45)` jump when `stack_top == 0`.
   - Add `Call(36)`, `PCall(40)`, `Closure(38)`, `Ret(37)` to the unconstrained-next_pc set (same treatment as `Ret` today).

**Part D — Stubs for later phases** (prevents merge conflicts):

7. Create `src/noir/trace.rs` with the stub below. Phase 2 will replace the body:
   ```rust
   // Phase 2 stub — full implementation in noir/2-trace-emission
   #[derive(Debug, Clone)]
   #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
   pub struct TraceStep {
       pub pc:        u32,
       pub opcode:    u8,
       pub operand:   i64,
       pub stack_top: i64,
       pub next_pc:   u32,
   }
   ```
   Add `pub mod trace;` to `src/noir/mod.rs`.

### Do Not Touch

- `openvm/` — existing OpenVM pipeline; do not modify any file in this crate
- `prover/` — do not modify
- `src/vm/engine.rs` — Phase 2's domain
- `src/zkvm/` — do not modify

### Verification

```bash
cargo test
# → all tests pass

cargo test --lib noir
# → test opcodes::tests::all_variants_have_unique_ids ... ok
# → test encoder::tests::program_hash_is_stable ... ok

nargo check --program-dir noir
# → no errors (circuit compiles with new MAX_BYTECODE and opcode range)
```

Do not implement Phase 2 or later content beyond the stubs listed above.

---

## Step 2 — Phase 2: VM Trace Emission

**Branch:** `noir/2-trace-emission`
**Depends on:** Step 1 merged to master

**Prompt:**

You are implementing Phase 2 of the luai Noir proving pipeline. The full specification is in `planning/noir-proving-pipeline-plan.md` under "Phase 2 — VM Trace Emission". Read that section carefully before writing any code.

### Context

Phase 1 is complete. The following is now in place:

- `src/noir/opcodes.rs` — `instruction_to_opcode_id(i: &Instruction) -> u8` and `instruction_to_operand(i: &Instruction) -> i64` for all 46 variants.
- `src/noir/encoder.rs` — `encode_program(&CompiledProgram) -> Result<NoirBytecode, EncodeError>`. `NoirBytecode` holds `opcodes: [u8; 512]`, `operands: [i64; 512]`, `program_hash: [u8; 32]`.
- `src/noir/trace.rs` — `TraceStep` stub (five `pub` fields: `pc`, `opcode`, `operand`, `stack_top`, `next_pc`). Phase 1 stub — you will replace the body now.
- `noir/src/main.nr` — circuit updated to 46 opcodes, `MAX_BYTECODE = 512`.
- `src/vm/engine.rs` — `Vm` struct, `VmConfig`, `VmOutput`. `VmOutput` holds `return_value`, `logs`, `gas_used`, `memory_used`, `transcript`.

`cargo test` passes and must continue to pass.

### Your Task

Implement Phase 2 as specified in `planning/noir-proving-pipeline-plan.md` under "Phase 2 — VM Trace Emission":

1. **Replace the `TraceStep` stub** in `src/noir/trace.rs` with the full type (same five fields — the stub already has the right shape, just remove the stub comment).

2. **Add `record_trace: bool` to `VmConfig`** in `src/vm/engine.rs`. Default is `false`. Existing callers that construct `VmConfig` with struct literal syntax must continue to compile — add `record_trace: false` to the `Default` impl and any explicit constructions in tests.

3. **Add `trace: Vec<TraceStep>` to `VmOutput`** in `src/vm/engine.rs`. It is empty when `record_trace` is false.

4. **Instrument the execution loop** in `Vm::execute` (or the inner dispatch function): when `record_trace` is true, before each instruction dispatch capture `(pc, opcode_id, operand)` using `instruction_to_opcode_id` and `instruction_to_operand`; capture `stack_top` as the current top-of-stack integer value (0 if the stack is empty or the top is not an integer or boolean — coerce booleans to 1/0); after dispatch, capture `next_pc` as the updated `frame.pc`. Push a `TraceStep` for each dispatched instruction. Only record steps in the top-level frame (frame depth 0) for this phase — multi-frame tracing is Phase 3.

5. **Add tests** in `tests/integration.rs` (or a new `tests/noir_trace.rs`):
   - `trace_length_matches_instruction_count` — run a linear program with `record_trace: true`, assert `output.trace.len()` equals the number of bytecode instructions executed.
   - `trace_pc_sequential_for_linear_program` — assert `trace[i].pc == i as u32` for a straight-line program.
   - `trace_jump_produces_correct_next_pc` — run a program with a conditional branch, assert the `next_pc` at the branch step matches the actual taken branch target.
   - `trace_is_empty_without_flag` — run the same program with `record_trace: false`, assert `output.trace.is_empty()`.
   - `trace_is_deterministic` — run the same program twice, assert the two traces are byte-identical.

### Do Not Touch

- `src/noir/opcodes.rs` — Phase 1's domain; read it, do not modify
- `src/noir/encoder.rs` — Phase 1's domain; read it, do not modify
- `noir/src/main.nr` — Phase 1 updated this; do not modify
- `openvm/` — do not modify
- `prover/` — do not modify

### Verification

```bash
cargo test
# → all tests pass

cargo test --test noir_trace
# → test trace_length_matches_instruction_count ... ok
# → test trace_pc_sequential_for_linear_program ... ok
# → test trace_jump_produces_correct_next_pc ... ok
# → test trace_is_empty_without_flag ... ok
# → test trace_is_deterministic ... ok
```

---

## Step 3 — Phase 3: Witness Pipeline and `luai-noir` Crate

**Branch:** `noir/3-witness-pipeline`
**Depends on:** Step 2 merged to master

**Prompt:**

You are implementing Phase 3 of the luai Noir proving pipeline. The full specification is in `planning/noir-proving-pipeline-plan.md` under "Phase 3 — Witness Pipeline and `luai-noir` Crate". Read that section carefully before writing any code.

### Context

Phases 1 and 2 are complete:

- Phase 1: `src/noir/opcodes.rs` — opcode mapping for all 46 instructions. `src/noir/encoder.rs` — `encode_program` produces `NoirBytecode { opcodes: [u8; 512], operands: [i64; 512], program_hash: [u8; 32] }`. `noir/src/main.nr` — circuit covers all 46 opcodes, `MAX_BYTECODE = 512`, `MAX_STEPS = 16384`.
- Phase 2: `src/noir/trace.rs` — `TraceStep { pc, opcode, operand, stack_top, next_pc }`. `VmConfig.record_trace: bool`. `VmOutput.trace: Vec<TraceStep>`.

`cargo test` passes and must continue to pass. `nargo check --program-dir noir` passes and must continue to pass.

### Your Task

**Part A — Multi-function trace continuity**, as specified under "3a. Multi-function trace continuity":

1. Update `src/vm/engine.rs` trace recording to cover all call frames, not just frame 0. Each `Call`, `PCall`, and `Ret` instruction must still emit a `TraceStep` with its `next_pc` unconstrained (the actual post-instruction pc value). The trace must include every instruction dispatched across all frames, in execution order.

2. Remove the `EncodeError::CallNotSupported` variant from `src/noir/encoder.rs`. Update `encode_program` to encode `Call(36)`, `PCall(40)`, `Closure(38)` using the opcode IDs from the mapping. These were stubbed in Phase 1.

**Part B — `luai-noir` crate**, as specified under "3b–3d":

3. Create `luai-noir/` as a new workspace member. Add it to the root `Cargo.toml` `[workspace] members` array. Structure:
   ```
   luai-noir/
   ├── Cargo.toml
   └── src/
       ├── lib.rs
       ├── witness.rs
       └── prover.rs
   ```

4. **`witness.rs`** — implement:
   ```rust
   pub const MAX_BYTECODE: usize = 512;
   pub const MAX_STEPS: usize = 16384;

   pub struct NoirWitness {
       pub bytecode_opcodes:  [u8;  MAX_BYTECODE],
       pub bytecode_operands: [i64; MAX_BYTECODE],
       pub trace_pcs:         [u32; MAX_STEPS],
       pub trace_opcodes:     [u8;  MAX_STEPS],
       pub trace_operands:    [i64; MAX_STEPS],
       pub trace_stack_tops:  [i64; MAX_STEPS],
       pub trace_next_pcs:    [u32; MAX_STEPS],
       pub num_steps:         u32,
       pub program_hash:      [u8; 32],
       pub return_value:      i64,
   }

   pub fn build_witness(
       bytecode: &NoirBytecode,
       trace: &[TraceStep],
       return_value: i64,
   ) -> Result<NoirWitness, WitnessError>;

   pub fn write_prover_toml(witness: &NoirWitness, path: &Path) -> io::Result<()>;
   ```
   `build_witness` returns `WitnessError::TraceTooLong` if `trace.len() > MAX_STEPS`. `write_prover_toml` writes a `Prover.toml` with each array as an inline TOML integer array. Public inputs (`num_steps`, `program_hash`, `return_value`) are written as top-level keys without the array-of-array nesting nargo uses for struct inputs — match the format nargo expects for the `main` function signature in `noir/src/main.nr`.

5. **`prover.rs`** — implement:
   ```rust
   pub struct NoirProver {
       pub circuit_dir: PathBuf,
   }

   pub struct NoirProof {
       pub proof_bytes:    Vec<u8>,
       pub public_inputs:  NoirPublicInputs,
       pub prove_duration: std::time::Duration,
   }

   pub struct NoirPublicInputs {
       pub program_hash: [u8; 32],
       pub return_value: i64,
       pub num_steps:    u32,
   }

   pub enum ProveError {
       NargoNotFound,
       ExecuteFailed(String),
       ProveFailed(String),
       VerifyFailed(String),
       Io(std::io::Error),
   }

   impl NoirProver {
       pub fn prove(&self, witness: &NoirWitness) -> Result<NoirProof, ProveError>;
       pub fn verify(&self, proof: &NoirProof) -> Result<bool, ProveError>;
   }
   ```
   `prove` writes `Prover.toml` to `circuit_dir`, times `nargo execute` then `nargo prove`, reads `circuit_dir/proofs/*.proof` as `proof_bytes`, and populates `NoirPublicInputs` from `witness`. `verify` calls `nargo verify`. Both use `std::process::Command`. Return `ProveError::NargoNotFound` with an install hint if the binary is missing.

**Part C — Tests**, as specified under "3e. Tests":

6. Integration test in `luai-noir/tests/prove.rs` (skipped if nargo is absent — gate with `#[cfg(feature = "nargo_integration")]` or check for the binary at test start and skip):
   - `end_to_end_prove_and_verify` — compile `"return 1 + 2"`, execute with `record_trace: true`, build witness, prove, verify. Assert `verified == true`.
   - `tampered_return_value_fails_verify` — same flow but overwrite `witness.return_value` with a wrong value before calling `prove`. Assert that nargo verify fails or returns `false`.
   - `multi_function_proves_correctly` — compile a Lua program that calls a local function, prove and verify.

### Do Not Touch

- `src/noir/opcodes.rs` — read-only
- `noir/src/main.nr` — do not modify the circuit in this phase
- `openvm/` — do not modify
- `prover/` — do not modify

### Verification

```bash
cargo test
# → all tests pass

cargo build -p luai-noir
# → compiles without warnings

# If nargo is installed:
cargo test -p luai-noir --features nargo_integration
# → test end_to_end_prove_and_verify ... ok
# → test tampered_return_value_fails_verify ... ok
# → test multi_function_proves_correctly ... ok
```

---

## Step 4 — Phase 4: Oracle Tape Verification

**Branch:** `noir/4-oracle-tape`
**Depends on:** Step 3 merged to master

**Prompt:**

You are implementing Phase 4 of the luai Noir proving pipeline. The full specification is in `planning/noir-proving-pipeline-plan.md` under "Phase 4 — Oracle Tape Verification". Read that section carefully before writing any code.

### Context

Phases 1–3 are complete:

- Phase 1: `src/noir/opcodes.rs` — opcode IDs. `src/noir/encoder.rs` — `encode_program`. `noir/src/main.nr` — circuit for 46 opcodes.
- Phase 2: `src/noir/trace.rs` — `TraceStep`. `VmOutput.trace: Vec<TraceStep>`.
- Phase 3: `luai-noir/` crate — `NoirWitness`, `build_witness`, `write_prover_toml`, `NoirProver { prove, verify }`, `NoirPublicInputs { program_hash, return_value, num_steps }`.

Relevant existing types:
- `src/host/tape.rs` — `OracleTape { entries: Vec<TapeEntry> }`, `TapeEntry::Ok(Vec<u8>)` / `TapeEntry::Err(String)`, `OracleTape::from_records(&[ToolCallRecord]) -> OracleTape`, `OracleTape::commitment_hash() -> [u8; 32]`. The commitment framing is: for each entry, `tag (1 byte: 0x00=Ok, 0x01=Err) || length (4 bytes LE) || payload`.
- `src/host/transcript.rs` — `ToolCallRecord { response_canonical: Vec<u8>, error_message: String, status: ToolCallStatus, ... }`.

`cargo test` and `nargo check --program-dir noir` pass and must continue to pass.

### Your Task

**Part A — Circuit changes**, as specified under "4a. Circuit changes":

1. Add the following to `noir/src/main.nr` as new constants and witness parameters:
   ```noir
   global MAX_TOOL_CALLS: u32 = 64;
   global MAX_TAPE_ENTRY_BYTES: u32 = 1024;
   ```
   Add to `main` function signature:
   ```noir
   tape_entry_tags:    [u8;  MAX_TOOL_CALLS],
   tape_entry_lengths: [u32; MAX_TOOL_CALLS],
   tape_entry_data:    [[u8; MAX_TAPE_ENTRY_BYTES]; MAX_TOOL_CALLS],
   num_tool_calls:     u32,
   tool_responses_hash: pub [u8; 32],
   ```

2. In the step loop (`for i in 0..MAX_STEPS`): when `opcode == 39` (ToolCall), consume the next tape entry. Track a `tape_cursor: u32` counter starting at 0. For each ToolCall step, build the hash frame `[tag, len_le[0], len_le[1], len_le[2], len_le[3], payload[0..len]]` and feed it into a running SHA-256 accumulator. After all steps, assert `sha256_accumulator == tool_responses_hash`. For programs with no tool calls (`num_tool_calls == 0`), assert `tool_responses_hash == sha256([])` (the SHA-256 of an empty byte sequence).

   Use Noir's `std::hash::sha256` for all SHA-256 operations. Because Noir requires fixed-size arrays, build the full hash input as a flat `[u8; MAX_TOOL_CALLS * (5 + MAX_TAPE_ENTRY_BYTES)]` array (length-padded entries), hash once, and assert equality. Alternatively, use an iterative accumulator pattern if Noir's stdlib supports it — prefer the approach that produces fewer constraints.

**Part B — Witness changes**, as specified under "4b–4c":

3. Add to `NoirWitness` in `luai-noir/src/witness.rs`:
   ```rust
   pub tape_entry_tags:    [u8;  MAX_TOOL_CALLS],
   pub tape_entry_lengths: [u32; MAX_TOOL_CALLS],
   pub tape_entry_data:    [[u8; MAX_TAPE_ENTRY_BYTES]; MAX_TOOL_CALLS],
   pub num_tool_calls:     u32,
   pub tool_responses_hash: [u8; 32],
   ```

4. Update `build_witness` to accept `oracle_tape: &OracleTape`. Extract each `TapeEntry`, populate the new arrays (truncate payload to `MAX_TAPE_ENTRY_BYTES`, zero-pad if shorter), set `num_tool_calls`, and populate `tool_responses_hash` using `oracle_tape.commitment_hash()`.

5. Add `tool_responses_hash: [u8; 32]` to `NoirPublicInputs` in `luai-noir/src/prover.rs`.

6. Update `write_prover_toml` to serialise the new fields. `tape_entry_data` is a 2D array — write it as a TOML array of inline arrays.

**Part C — Tests**, as specified under "4d. Tests":

7. Add to `luai-noir/tests/prove.rs` (same nargo-gating as Step 3):
   - `prove_with_tool_calls` — compile and execute a Lua program that calls `tool.call("kv_get", {})` at least once. Build witness from the resulting oracle tape. Prove and verify. Assert `tool_responses_hash != [0u8; 32]`.
   - `tampered_tape_entry_fails_verify` — same flow, then overwrite one byte in `witness.tape_entry_data[0]`. Assert verify fails.
   - `no_tool_calls_zero_hash` — a program with no tool calls produces `tool_responses_hash == sha256_of_empty`.

### Do Not Touch

- `src/noir/opcodes.rs` — read-only
- `src/noir/encoder.rs` — read-only
- `src/noir/trace.rs` — read-only
- `openvm/` — do not modify
- `prover/` — do not modify

### Verification

```bash
cargo test
# → all tests pass

nargo check --program-dir noir
# → no errors

# If nargo is installed:
cargo test -p luai-noir --features nargo_integration
# → test prove_with_tool_calls ... ok
# → test tampered_tape_entry_fails_verify ... ok
# → test no_tool_calls_zero_hash ... ok
```

---

## Step 5 — Phase 5: Full Public Inputs Parity

**Branch:** `noir/5-public-inputs-parity`
**Depends on:** Step 4 merged to master

**Prompt:**

You are implementing Phase 5 of the luai Noir proving pipeline. The full specification is in `planning/noir-proving-pipeline-plan.md` under "Phase 5 — Full Public Inputs Parity". Read that section carefully before writing any code.

### Context

Phases 1–4 are complete. The Noir proof currently commits to: `program_hash`, `return_value`, `num_steps`, `tool_responses_hash`. The existing OpenVM proof commits to six `[u8; 32]` hashes in `PublicInputs` (`src/zkvm/commitment.rs`): `program_hash`, `input_hash`, `tool_responses_hash`, `output_hash`, `tls_attestation_hash`, `policy_hash`.

Relevant existing code:
- `src/zkvm/commitment.rs` — `compute_public_inputs(program_hash, input_value, oracle_tape, output, tls_attestations) -> PublicInputs`. `hash_output(output: &VmOutput) -> [u8; 32]` — SHA-256 over `canonical_serialize(return_value) || logs || transcript records`.
- `src/tls/mod.rs` — `TlsAttestationRecord { cert_chain_der, p256_verified, hostname, cert_not_after }`. `compute_tls_attestation_hash(&[TlsAttestationRecord]) -> [u8; 32]`.
- `src/tls/verify.rs` — `verify_p256_chain` extracts public key x/y coordinates and signature bytes from DER-encoded certs.
- `src/host/canonicalize.rs` — `canonical_serialize(v: &LuaValue) -> Vec<u8>`.

`cargo test` and `nargo check --program-dir noir` pass and must continue to pass.

### Your Task

**Part A — Add remaining public inputs to the circuit** (`noir/src/main.nr`):

1. Add four new public inputs to `main`:
   ```noir
   input_hash:           pub [u8; 32],
   output_hash:          pub [u8; 32],
   tls_attestation_hash: pub [u8; 32],
   policy_hash:          pub [u8; 32],
   ```
   These are declared as public inputs only — the circuit does not recompute them. The host computes them and the verifier checks them against expected values.

2. Add TLS attestation witnesses and verification as specified under "5d. `tls_attestation_hash`":
   ```noir
   global MAX_CERTS: u32 = 4;

   cert_public_key_x: [[u8; 32]; MAX_CERTS],
   cert_public_key_y: [[u8; 32]; MAX_CERTS],
   cert_signatures:   [[u8; 64]; MAX_CERTS],
   cert_msg_hashes:   [[u8; 32]; MAX_CERTS],
   num_certs:         u32,
   ```
   In the circuit: for each cert `i < num_certs`, call `std::ecdsa_secp256r1::verify_signature(cert_public_key_x[i], cert_public_key_y[i], cert_signatures[i], cert_msg_hashes[i])` and assert it returns `true`. Accumulate a SHA-256 over the cert public keys in order and assert the result equals `tls_attestation_hash`. When `num_certs == 0`, assert `tls_attestation_hash == [0u8; 32]`.

**Part B — Expand `NoirPublicInputs` and witness** (`luai-noir/`):

3. Replace `NoirPublicInputs` in `luai-noir/src/prover.rs` with the full six-hash struct matching `src/zkvm/commitment.rs`:
   ```rust
   pub struct NoirPublicInputs {
       pub program_hash:         [u8; 32],
       pub input_hash:           [u8; 32],
       pub tool_responses_hash:  [u8; 32],
       pub output_hash:          [u8; 32],
       pub tls_attestation_hash: [u8; 32],
       pub policy_hash:          [u8; 32],
   }
   ```

4. Add TLS witness fields to `NoirWitness` in `luai-noir/src/witness.rs`:
   ```rust
   pub cert_public_key_x: [[u8; 32]; MAX_CERTS],
   pub cert_public_key_y: [[u8; 32]; MAX_CERTS],
   pub cert_signatures:   [[u8; 64]; MAX_CERTS],
   pub cert_msg_hashes:   [[u8; 32]; MAX_CERTS],
   pub num_certs:         u32,
   ```

5. Update `build_witness` to accept `input_value: &LuaValue`, `output: &VmOutput`, `tls_attestations: &[TlsAttestationRecord]`, `policy_hash: [u8; 32]`. Compute each hash using the existing functions: `canonical_serialize` + `sha2` for `input_hash`; `hash_output` from `src/zkvm/commitment.rs` for `output_hash`; `compute_tls_attestation_hash` from `src/tls/mod.rs` for `tls_attestation_hash`. Extract P-256 cert fields using `verify_p256_chain` from `src/tls/verify.rs`.

6. Update `write_prover_toml` to include all new fields.

**Part C — Parity test**, as specified under "5e. Tests":

7. Add a test in `tests/integration.rs` or `luai-noir/tests/parity.rs`:
   - `noir_and_openvm_produce_identical_public_inputs` — run the same Lua program through both the existing `compute_public_inputs` (OpenVM path) and `build_witness` + `NoirPublicInputs` (Noir path). Assert all six hashes are identical.

### Do Not Touch

- `src/zkvm/commitment.rs` — read-only; use its functions but do not modify
- `src/tls/` — read-only
- `openvm/` — do not modify
- `prover/` — do not modify

### Verification

```bash
cargo test
# → all tests pass

nargo check --program-dir noir
# → no errors

cargo test --test parity
# → test noir_and_openvm_produce_identical_public_inputs ... ok

# If nargo is installed:
cargo test -p luai-noir --features nargo_integration
# → all prior tests still pass
```

---

## Step 6 — Phase 6: On-Chain Verifier

**Branch:** `noir/6-onchain-verifier`
**Depends on:** Step 5 merged to master

**Prompt:**

You are implementing Phase 6 of the luai Noir proving pipeline. The full specification is in `planning/noir-proving-pipeline-plan.md` under "Phase 6 — On-Chain Verifier". Read that section carefully before writing any code.

### Context

Phases 1–5 are complete. The Noir proof now produces the same six-hash `NoirPublicInputs` as the OpenVM proof. The circuit is in `noir/` with a working `Nargo.toml`. The existing Solidity contracts are in `contracts/` (contains the OpenVM Groth16 verifier integration).

`cargo test` and `nargo check --program-dir noir` pass and must continue to pass.

### Your Task

**Part A — Generate the Solidity verifier**, as specified under "6a. Solidity verifier generation":

1. From the `noir/` directory, run:
   ```bash
   nargo codegen-verifier
   ```
   This produces `noir/contract/plonk_vk.sol`. Commit this generated file to the repo. Document in `noir/README.md` that this file is generated and must be regenerated whenever the circuit changes.

2. Add a `noir/README.md` if one doesn't exist, documenting: how to regenerate the verifier, the public inputs encoding order, and the `nargo prove` / `nargo verify` workflow.

**Part B — Public inputs encoding**, as specified under "6b. Public inputs encoding":

3. The Solidity verifier's `verify` function takes `bytes32[] calldata publicInputs`. Document and implement the canonical ordering in `luai-noir/src/prover.rs` as:
   ```rust
   pub fn public_inputs_to_bytes32_array(pi: &NoirPublicInputs) -> Vec<[u8; 32]> {
       vec![
           pi.program_hash,
           pi.input_hash,
           pi.tool_responses_hash,
           pi.output_hash,
           pi.tls_attestation_hash,
           pi.policy_hash,
       ]
   }
   ```
   This ordering must match the order the public inputs are declared in `noir/src/main.nr`.

**Part C — Wire into existing contracts**, as specified under "6c. Integration with existing contracts":

4. In `contracts/`, add or update a Solidity contract `LuaiNoirVerifier.sol` that wraps `plonk_vk.sol`. It must expose:
   ```solidity
   function verifyExecution(
       bytes calldata proof,
       bytes32 programHash,
       bytes32 inputHash,
       bytes32 toolResponsesHash,
       bytes32 outputHash,
       bytes32 tlsAttestationHash,
       bytes32 policyHash
   ) external view returns (bool);
   ```
   This assembles the `bytes32[]` array in canonical order and delegates to the generated verifier's `verify` function.

5. Add `contracts/README.md` documenting: how to deploy, the public inputs ordering, and how to upgrade when the circuit changes (regenerate verifier, redeploy).

**Part D — Tests**, as specified under "6d. Tests":

6. Add a Foundry or Hardhat test in `contracts/test/` (use whichever framework is already in the repo, or Foundry if none exists):
   - `testVerifyValidProof` — generate a real Noir proof via `luai-noir`, pass it to `LuaiNoirVerifier.verifyExecution`, assert it returns `true`.
   - `testVerifyTamperedProofFails` — flip a byte in the proof, assert returns `false`.
   - `testVerifyWrongPolicyHashFails` — pass the correct proof with a wrong `policyHash`, assert returns `false`.
   - Record gas used by `verifyExecution` in the test output.

### Do Not Touch

- `openvm/` — do not modify; the OpenVM pipeline continues to coexist
- `prover/` — do not modify
- `src/` — do not modify Rust source in this phase
- Existing contracts that are not the new `LuaiNoirVerifier.sol`

### Verification

```bash
cargo test
# → all tests pass

nargo check --program-dir noir
# → no errors

ls noir/contract/plonk_vk.sol
# → file exists

# If Foundry is available:
forge test --match-path contracts/test/LuaiNoirVerifier.t.sol -v
# → testVerifyValidProof ... [PASS]
# → testVerifyTamperedProofFails ... [PASS]
# → testVerifyWrongPolicyHashFails ... [PASS]
# → Gas used by verifyExecution: <N> (record this number)
```
