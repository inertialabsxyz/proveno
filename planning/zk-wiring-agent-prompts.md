# Agent Prompts — ZK Proving Pipeline Wiring

These prompts are designed to be handed directly to a Claude Code agent. Each is self-contained. Agents work on git branches and do not share state during execution. Read the sequencing notes before dispatching.

---

## Sequencing Overview

```
Step 1 (single agent):   Policy hash wiring
                              │
              ┌───────────────┴───────────────┐
Step 2 (parallel):  2a — Proof packaging    2b — EVM proof path
              └───────────────┬───────────────┘
                         merge to master
                              │
Step 3 (single agent):   End-to-end re-benchmark
```

Do not start Step 2 until Step 1 is merged to master. Steps 2a and 2b touch different files and can run in parallel. Do not start Step 3 until both 2a and 2b are merged.

---

## Step 1 — Policy hash in the proving pipeline

**Branch:** `zk/1-policy-hash`
**Depends on:** `phase/3c-testnet` merged to master

**Prompt:**

You are wiring the policy hash through the proveno ZK proving pipeline. The full context is in `planning/programmable-oracle-mvp-plan.md`. Read the "Phase 3" section before proceeding.

### Context

The proving pipeline currently has a correctness gap: `policy_hash` is always `[0u8; 32]` in the proof output, regardless of which policy governed the execution.

The pipeline runs as follows:

```
Lua source
  → proveno-compiler  → compiled.json
  → proveno-prover    → dry_result.json   (DryRunResult, public_inputs.policy_hash = [0;32] today)
  → proveno-openvm-encoder → /tmp/openvm-1.json  (OpenVMInput = {compiled_program, dry_run_result})
  → cargo openvm prove app → proveno-openvm.app.proof
```

The OpenVM guest (`openvm/src/main.rs`) executes:

```rust
let public_inputs = compute_public_inputs(...);   // policy_hash = [0;32]
assert!(public_inputs == dry_run_result.public_inputs);
openvm::io::reveal_bytes32(public_inputs.policy_hash);  // reveals zero
```

And `prover/src/prover.rs::dry_run` calls:

```rust
let public_inputs = compute_public_inputs(...);   // policy_hash = [0;32]
```

So `dry_run_result.public_inputs.policy_hash` is also zero, and the assertion passes — but the revealed policy hash is always zero, which means `ProvenoVerifier.sol` can only ever be deployed with `expectedPolicyHash = 0x000...000`.

The relevant functions are in `src/zkvm/commitment.rs`:
- `compute_public_inputs(...)` — always zeroes `policy_hash`
- `compute_public_inputs_with_policy(...)` — takes an `&OraclePolicy`, computes real hash

### Your Task

1. **Update `prover/src/prover.rs`** — add a `dry_run_with_policy` method that accepts an `&OraclePolicy` and calls `compute_public_inputs_with_policy` instead of `compute_public_inputs`. The existing `dry_run` method must remain unchanged (zero policy hash, used by callers that don't supply a policy).

2. **Update `prover/src/main.rs`** — add an optional `--policy` CLI flag that accepts one of `"constrained_http_v1"` or `"template_price_feed_v1"`. When provided, call `dry_run_with_policy` with the named profile. When omitted, call `dry_run` as today (zero policy hash). Update usage help.

3. **Update `openvm/src/main.rs`** — after computing `public_inputs` via `compute_public_inputs`, override the policy hash from the dry-run result before asserting:

   ```rust
   let mut public_inputs = compute_public_inputs(
       program.program_hash, &input_value, &dry_run_result.oracle_tape,
       &output, &verified_attestations,
   );
   // Policy hash is an external commitment declared by the orchestrator,
   // not derived from the guest's own execution. Copy it from the dry run.
   public_inputs.policy_hash = dry_run_result.public_inputs.policy_hash;
   assert!(public_inputs == dry_run_result.public_inputs);
   openvm::io::reveal_bytes32(public_inputs.policy_hash);
   ```

   This preserves the assertion (which still verifies all six fields must match) while threading the policy hash through correctly.

4. **Update `orchestrator/src/bin/bench.rs`** — switch from calling `compute_public_inputs_with_policy` post-hoc to calling `prover::Prover::dry_run_with_policy` so the bench binary exercises the same code path the prover binary will use. The bench binary already imports `proveno_prover`; use `dry_run_with_policy` passing `template_price_feed_v1()`.

5. **Add a test** in `prover/src/prover.rs` that:
   - Runs a simple Lua program through `dry_run_with_policy` with `constrained_http_v1()`
   - Asserts `dry_run_result.public_inputs.policy_hash == constrained_http_v1().policy_hash()`
   - Asserts `dry_run_result.public_inputs.policy_hash != [0u8; 32]`

6. **Add a regression test** in `openvm/src/main.rs` is not feasible (the guest runs inside the zkVM). Instead, add a comment above the policy_hash override explaining the invariant: "the prover commits to the policy hash; the guest copies it and reveals it. The on-chain ProvenoVerifier checks it. The guest does not re-derive it from a policy document because the policy is not part of the guest's input."

### Do Not Touch

- `src/policy/mod.rs` and `src/policy/profiles.rs` — do not modify the policy definitions
- `contracts/` — do not modify Solidity contracts
- `verifier/` — do not modify the proveno wire-format verifier
- `openvm/src/encoder.rs` — the `OpenVMInput` struct; do not modify its shape (2a owns the packager)

### Verification

```bash
cargo test
# → all tests pass including the new dry_run_with_policy test

cargo run -p proveno_prover -- examples/prover.lua /tmp/dry_result_no_policy.json
# → writes dry_result_no_policy.json with policy_hash = "0000...0000"

cargo run -p proveno_prover -- examples/prover.lua /tmp/dry_result_with_policy.json \
  --policy constrained_http_v1
# → writes dry_result_with_policy.json; python3 -c "import json; d=json.load(open('/tmp/dry_result_with_policy.json')); print(d['public_inputs']['policy_hash'])" shows non-zero hex

cargo run -p proveno-orchestrator --bin bench 2>/dev/null | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['policy_hash'] != '0x' + '0'*64, 'policy_hash is zero'
print('policy_hash OK:', d['policy_hash'])
"
```

---

## Step 2a — Proof packaging binary

**Branch:** `zk/2a-packager`
**Depends on:** Step 1 merged to master

**Prompt:**

You are writing the proof packaging binary for proveno. This is the missing link between `cargo openvm prove app` (which produces `proveno-openvm.app.proof`) and the proveno wire-format proof bundle that `proveno-verifier` can verify and that `ProvenoVerifier.sol` can consume.

### Context

After Step 1, the proving pipeline is:

```
proveno-compiler   → compiled.json
proveno-prover     → dry_result.json          (with real policy_hash)
proveno-openvm-encoder → /tmp/openvm-1.json
cargo openvm prove app → proveno-openvm.app.proof
                                ↑
              THIS IS WHERE WE STOP TODAY
```

The next step — packaging the app proof into a proveno wire-format bundle — does not exist.

The proveno wire-format proof (defined in `verifier/src/lib.rs`) is:

```
[magic: 4]              b"proveno"
[version: 1]            0x01
[program_hash: 32]
[input_hash: 32]
[tool_responses_hash: 32]
[output_hash: 32]
[tls_attestation_hash: 32]
[policy_hash: 32]
[proof_blob_len: 4 LE]
[proof_blob: N]         OpenVM ZK proof bytes
[integrity: 32]         SHA-256(all preceding bytes)
```

The `proof_blob` is currently a placeholder (`"openvm-proof-placeholder"`). After this step, it must contain the raw bytes of the OpenVM app proof.

The public inputs (the six 32-byte hashes) are revealed by the guest via six `openvm::io::reveal_bytes32(...)` calls in `openvm/src/main.rs`. OpenVM writes these to the proof's "public values" / journal, accessible after proving.

### Your Task

1. **Research the OpenVM app proof format.** The proof is produced by `cargo openvm prove app` and is located at `proveno-openvm.app.proof`. Run `cargo openvm run --bin proveno-openvm --input /tmp/openvm-1.json` first (this simulates execution without proving) to understand what public values look like. Read the OpenVM SDK to understand the `StdIn`/`StdOut`/journal serialization used by `openvm::io::reveal_bytes32`.

   Specifically: find out how to deserialize `proveno-openvm.app.proof` in Rust to extract:
   - The raw proof bytes (to use as `proof_blob`)
   - The six 32-byte public values in reveal order

2. **Create `openvm/src/bin/packager.rs`** — a binary `proveno-openvm-packager` with this signature:

   ```
   proveno-openvm-packager <proof-file> <output-bundle>
   ```

   It must:
   a. Read and deserialize `<proof-file>` (the OpenVM app proof)
   b. Extract the six public values in the order they were revealed:
      `[program_hash, input_hash, tool_responses_hash, output_hash, tls_attestation_hash, policy_hash]`
   c. Build a `PublicInputs` struct from those values
   d. Call `proveno_verifier::build_test_proof(&public_inputs, &proof_bytes)` where `proof_bytes`
      is the serialized proof blob (or the full raw file contents if format is opaque)
   e. Write the wire-format bundle to `<output-bundle>`
   f. Print proof size and the six hash fields

3. **Add `[[bin]]` to `openvm/Cargo.toml`** for `proveno-openvm-packager`.

4. **Update `openvm/proof-app.sh`** to include the packaging step after proving:

   ```bash
   cargo openvm keygen
   cargo openvm prove app --bin proveno-openvm --input /tmp/openvm-1.json
   cargo openvm verify app --proof proveno-openvm.app.proof
   cargo run --bin proveno-openvm-packager -- proveno-openvm.app.proof proveno-proof.bin
   echo "Wire-format proof: $(wc -c < proveno-proof.bin) bytes"
   ```

5. **Update `zkvm-prove.sh`** (root-level) to call the packager after proving, so the full pipeline produces `proveno-proof.bin` as its final output.

6. **Write one unit test** in `openvm/src/bin/packager.rs` that:
   - Constructs a mock proof file in the expected format
   - Calls the packaging logic (extracted into a library function)
   - Asserts the output bundle round-trips through `proveno_verifier::verify_proof`

### Do Not Touch

- `verifier/src/lib.rs` — wire format is defined here; do not modify it
- `openvm/src/main.rs` — the guest program; do not modify (Step 1's domain)
- `openvm/src/encoder.rs` — the encoder; only read it, do not modify
- `contracts/` — no Solidity changes in this step
- `prover/` — no prover changes in this step

### Verification

```bash
cargo test -p proveno-openvm
# → all tests pass including the packager round-trip test

# After a real proving run (requires cargo openvm):
# cargo openvm prove app --bin proveno-openvm --input /tmp/openvm-1.json
# cargo run --bin proveno-openvm-packager -- proveno-openvm.app.proof proveno-proof.bin
# proveno_verifier::verify_proof(&proof_bundle, &public_inputs, &policy_hash) == Ok(...)
```

---

## Step 2b — EVM proof path

**Branch:** `zk/2b-evm-proof`
**Depends on:** Step 1 merged to master

**Prompt:**

You are wiring the EVM proof path for proveno. OpenVM application proofs (`cargo openvm prove app`) cannot be verified on-chain. This step switches to `cargo openvm prove evm`, which produces a Groth16 proof verifiable by a Solidity contract, and deploys or documents the matching EVM verifier.

### Context

The current `ProvenoVerifier.sol` is constructed with an `IOpenVmVerifier` address:

```solidity
constructor(bytes32 _expectedPolicyHash, address _openVmVerifier) {
    expectedPolicyHash = _expectedPolicyHash;
    openVmVerifier = IOpenVmVerifier(_openVmVerifier);
}
```

The interface:
```solidity
interface IOpenVmVerifier {
    function verify(bytes calldata proof, bytes32 publicInputsHash) external view returns (bool);
}
```

Currently, `StubOpenVmVerifier` is used in its place. This step replaces the stub with a real on-chain verifier.

OpenVM (v1.4.1) provides two proof modes:
- `cargo openvm prove app` — fast but only verifiable in native Rust
- `cargo openvm prove evm` — wraps the app proof in Groth16; produces calldata for a Solidity verifier

The EVM verification works as follows:
1. `cargo openvm keygen --evm` generates an EVM-compatible proving key
2. `cargo openvm prove evm ...` produces `proof.json` with Groth16 calldata
3. OpenVM generates a matching `Groth16Verifier.sol` that the `proof.json` calldata targets
4. `publicInputsHash` is the keccak256 of the committed public values

Read the OpenVM documentation and source at the pinned tag `v1.4.1` to determine:
- The exact CLI for EVM proving and key generation
- What `Groth16Verifier.sol` looks like and how to deploy it
- How `publicInputsHash` is computed from the revealed bytes (to confirm it matches `ProvenoVerifier.sol`'s `keccak256(abi.encode(...))`)

### Your Task

1. **Research OpenVM v1.4.1 EVM verification.** Read the OpenVM CLI docs and source to establish:
   - The exact command for EVM keygen and proving
   - The format of `proof.json` (the Groth16 calldata)
   - The Solidity verifier contract interface and how to deploy it
   - How `publicInputsHash` is derived from the six revealed `bytes32` values

2. **Verify the `publicInputsHash` computation matches `ProvenoVerifier.sol`.** The contract computes:

   ```solidity
   bytes32 piHash = keccak256(abi.encode(
       inputs.programHash, inputs.inputHash, inputs.toolResponsesHash,
       inputs.outputHash, inputs.tlsAttestationHash, inputs.policyHash
   ));
   ```

   Confirm that OpenVM's EVM verifier uses the same hash as its `publicInputsHash`. If it differs, document the mismatch and what change is needed in `ProvenoVerifier.sol`.

3. **Add `contracts/src/OpenVmGroth16Verifier.sol`** — either:
   a. Copy the auto-generated verifier from OpenVM's output, or
   b. Write a minimal wrapper that implements `IOpenVmVerifier` and delegates to OpenVM's generated contract

   If the generated verifier's interface is not `IOpenVmVerifier`-compatible, write an adapter.

4. **Update `contracts/script/Deploy.s.sol`** — add a second deploy path that reads an optional `OPENVM_VERIFIER_ADDR` environment variable. If set, use that address as the `IOpenVmVerifier` instead of deploying `StubOpenVmVerifier`. If not set, fall back to deploying the stub (preserving the existing test path).

5. **Update `contracts/README.md`** — add a section "Real OpenVM Verifier" explaining:
   - How to run EVM keygen and proving
   - How to deploy the Groth16Verifier
   - How to set `OPENVM_VERIFIER_ADDR` for the deploy script
   - Known limitations (if publicInputsHash computation differs)

6. **Write one forge test** in `contracts/test/OpenVmGroth16Verifier.t.sol` that verifies the adapter compiles and implements `IOpenVmVerifier`. If a real Groth16 proof is not available for unit testing, use a mock to test the interface binding only.

### Do Not Touch

- `contracts/src/ProvenoVerifier.sol` — do not modify the verification logic; only the deploy script and adapter are in scope
- `contracts/src/StubOpenVmVerifier.sol` — keep it; it is used by existing tests
- `openvm/src/main.rs` — do not modify the guest
- `openvm/src/bin/packager.rs` — Step 2a's domain
- `prover/` — no prover changes

### Verification

```bash
cd contracts && forge test
# → all existing tests still pass (StubOpenVmVerifier path unchanged)
# → new OpenVmGroth16Verifier interface test passes

forge build
# → no compilation errors

cat contracts/README.md | grep -A 20 "Real OpenVM Verifier"
# → section exists with EVM proving instructions
```

---

## Step 3 — End-to-end re-benchmark

**Branch:** `zk/3-rebenchmark`
**Depends on:** Steps 2a and 2b merged to master

**Prompt:**

You are completing the ZK proving pipeline and re-running the Phase 3 benchmarks with real measurements. Steps 2a and 2b are complete.

### Context

After Steps 2a and 2b:

- **Step 1** wired policy hash through the prover and guest
- **Step 2a** added `proveno-openvm-packager` which reads an OpenVM app proof and produces a proveno wire-format bundle
- **Step 2b** added the EVM Groth16 verifier path and `OpenVmGroth16Verifier.sol`

The `planning/phase3-benchmarks.md` file currently records:
- Proof size: 257 bytes (placeholder inner blob)
- Gas: 29,919 (StubOpenVmVerifier)
- Latency: 492 ms (dry-run only, no ZK proving)

All three numbers need to be re-measured with the real proving pipeline.

The `zkvm-prove.sh` script at the repo root already orchestrates:
```
compile → prover → encoder → openvm run (simulation)
```
After Step 2a it also runs:
```
→ openvm prove app → packager → proveno-proof.bin
```

### Your Task

1. **Update `zkvm-prove.sh`** to run the full EVM pipeline (from Step 2b):
   - `cargo openvm keygen --evm` (if keys don't exist)
   - `cargo openvm prove evm ...` → `proof.json`
   - Extract proof calldata from `proof.json` as the `proof_blob` for the wire-format bundle
   - Run the packager to produce `proveno-proof.bin`
   - Print proof size, policy hash, and public inputs tuple for `cast`

2. **Run the full pipeline** with `template_price_feed_v1` policy and a live `http_get`:
   - Compile `examples/prover.lua` (or a simple http_get Lua script)
   - Dry-run with `--policy template_price_feed_v1`
   - Prove (EVM) and package
   - Capture proof size, total wall-clock time

3. **Deploy and re-measure on-chain**:
   - Deploy `ProvenoVerifier` pointing to `OpenVmGroth16Verifier` (or stub if EVM verifier not yet available; see Step 2b)
   - Submit the real proof via `cast send`
   - Capture gas from the receipt
   - Submit a proof with wrong policy hash; confirm `PolicyHashMismatch()` revert

4. **Update `planning/phase3-benchmarks.md`** with real numbers:
   - Update proof size, gas, and latency rows
   - Update PASS/FAIL verdicts (if any measurement now exceeds its threshold, record FAIL and stop)
   - Update the "What Is Not Yet Measured" section — remove items that are now measured
   - Add a "Re-benchmark date" and note which step introduced the real proving

5. **Add the policy hash to `verifier/Cargo.toml` docs** (or a comment in `verifier/src/lib.rs`) noting that the `template_price_feed_v1` policy hash is `0xe401364e...4687` and is stable.

### Do Not Touch

- `src/policy/` — do not modify policy definitions
- `contracts/src/ProvenoVerifier.sol` — do not modify the contract logic
- The `verifier/src/lib.rs` wire format — do not change the proof format

### Verification

```bash
cargo test && cd contracts && forge test
# → all tests pass

cat planning/phase3-benchmarks.md | grep -E 'PASS|FAIL'
# → each row has an explicit verdict

cat planning/phase3-benchmarks.md | grep "proof_blob is a placeholder"
# → should return nothing (placeholder language removed)

bash zkvm-prove.sh 2>&1 | grep -E 'proof size|Wire-format|proveno-proof.bin'
# → shows real proof size in bytes
```

**If any measurement exceeds its threshold, record FAIL and stop.** Do not proceed. The next phase must not begin until the numbers are within range.
