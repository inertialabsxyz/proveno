# Agent Prompts — luai MVP

These prompts are designed to be handed directly to a Claude Code agent. Each is self-contained. Agents work on git branches and do not share state during execution. Read the sequencing notes before dispatching.

---

## Sequencing Overview

```
Step 1 (single agent):   Phase 1 — Finish Proof Integrity
                              │
Step 2 (single agent):   Phase 2 — Admissibility and Reproducibility
                              │
              ┌───────────────┴───────────────┐
Step 3a                                    Step 3b
Phase 3 — Verifier Library     Phase 3 — Solidity Contracts
              └───────────────┬───────────────┘
                         merge to main
                              │
Step 4 (single agent):   Phase 3 — Testnet Deploy + Benchmark
                         *** GAS/PROOF-SIZE GATE ***
                              │
              ┌───────────────┴───────────────┐
Step 5a                                    Step 5b
Phase 4 — Lua Template + Sources   Phase 4 — Output Schema
              └───────────────┬───────────────┘
                         merge to main
                              │
Step 6 (single agent):   Phase 4 — Orchestrator + E2E Example
                              │
              ┌───────────────┴───────────────┐
Step 7a                                    Step 7b
Phase 5 — Security Testing       Phase 5 — Service Hardening
              └───────────────┬───────────────┘
                         merge to main
                              │
Step 8 (single agent):   Phase 5+6 — Threat Model + MVP Release
```

Do not start Step 2 until Step 1 is merged to main. Steps 3a/3b, 5a/5b, and 7a/7b are parallel pairs — run each pair on separate branches simultaneously, then merge both before proceeding. Do not start Step 4 until Steps 3a and 3b are both merged.

---

## Step 1 — Phase 1: Finish Proof Integrity

**Branch:** `phase/1-proof-integrity`

**Prompt:**

You are implementing Phase 1 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 1: Finish Proof Integrity". Read that section carefully before writing any code.

### Context

luai is a deterministic, sandboxed Lua VM designed for agentic workloads. The core pipeline is complete:

- `src/parser/` — Lua lexer and recursive-descent parser
- `src/compiler/` — AST → register-based bytecode (`codegen.rs`, `proto.rs`)
- `src/bytecode/` — `Instruction` enum and stack-depth verifier
- `src/vm/engine.rs` — execution loop with gas and memory metering
- `src/vm/builtins.rs` — `string`, `math`, `table`, `json`, `pcall`, etc.
- `src/host/` — `ToolRegistry`, `Transcript`, `OracleTape`, `canonical_serialize`
- `src/zkvm/commitment.rs` — `PublicInputs` (program_hash, input_hash, tool_responses_hash, output_hash, tls_attestation_hash)
- `src/zkvm/guest_input.rs` — `GuestInput` for OpenVM
- `luai-openvm/` — OpenVM guest + encoder for zk proof generation
- `luai-prover/` — CLI: dry-runs compiled programs, records oracle tape and public inputs

TLS attestation is structurally present but incomplete: P-256 ECDSA signature verification and Mozilla root CA pinning are not yet implemented. The `tls_attestation_hash` in `PublicInputs` is currently zero for all executions.

`cargo test` passes across all workspace members and must continue to pass after your changes.

### Your Task

**Part A — Close the TLS attestation gaps** as specified in `planning/programmable-oracle-mvp-plan.md` under "Phase 1: Finish Proof Integrity":

1. Locate the TLS verification code in `luai-openvm/` and `luai-prover/`. Understand exactly where P-256 ECDSA verification is called and where it falls short.
2. Implement full P-256 ECDSA signature verification in the zkVM verification path. The signature check must run inside the guest (i.e. be part of the proof) not just in the prover host.
3. Implement Mozilla root CA pinning. Embed the Mozilla root set as a static constant — do not fetch it at runtime. Reject certificate chains that do not terminate in the pinned set.
4. Add graceful handling for non-P256 servers: execution must not panic or produce a malformed proof. Instead, `tls_attestation_hash` must be zero and the host must surface a clear degradation signal.
5. Add an end-to-end integration test in `tests/` that:
   - Makes a real HTTPS request to a public P256-supporting endpoint
   - Runs the full prove pipeline (compile → prover dry-run)
   - Asserts `tls_attestation_hash != [0u8; 32]` in the resulting `PublicInputs`
   - Asserts that a non-P256 server completes without panic and yields `tls_attestation_hash == [0u8; 32]`
6. Write `docs/tls-attestation.md` documenting: what the attestation hash proves, what it does not prove (no wall-clock time, no response freshness), which TLS configurations are supported, and what happens when attestation is unavailable.

**Part B — Add stubs for later phases** (prevents merge conflicts when parallel agents start)

Create `src/policy/mod.rs` with the following placeholder. Phase 2 will replace the stub body with a full implementation:

```rust
// Phase 2 stub — will be fully implemented in phase/2-admissibility
pub struct OraclePolicy;

impl OraclePolicy {
    pub fn policy_hash(&self) -> [u8; 32] {
        [0u8; 32] // Phase 2 stub
    }
}
```

Add `pub mod policy;` to `src/lib.rs`.

Also add a `policy_hash: [u8; 32]` field (defaulting to `[0u8; 32]`) to `PublicInputs` in `src/zkvm/commitment.rs`. Mark it with a `// Phase 2 stub` comment. Update `compute_public_inputs` to populate it as zeros for now.

### Verification

```bash
cargo test
# → all tests pass

cargo test --test integration -- tls
# → test tls_attestation_nonzero_for_p256 ... ok
# → test tls_degrades_cleanly_for_non_p256 ... ok

cargo build --workspace
# → compiles without errors or warnings
```

Do not implement Phase 2 or later content beyond the stubs listed above.

---

## Step 2 — Phase 2: Admissibility and Reproducibility

**Branch:** `phase/2-admissibility`
**Depends on:** Step 1 merged to main

**Prompt:**

You are implementing Phase 2 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 2: Define Admissibility and Reproducibility". Read that section carefully before writing any code.

### Context

Phase 1 is complete. The proof pipeline now produces a non-zero `tls_attestation_hash` for P256-supporting servers. The following is in place:

- `src/policy/mod.rs` exists with a `OraclePolicy` stub (zero `policy_hash`). You will replace this stub with a full implementation.
- `src/zkvm/commitment.rs` — `PublicInputs` has a `policy_hash: [u8; 32]` field currently populated as zeros. You will wire it up.
- `src/host/tool_registry.rs` — `ToolRegistry<H>` wraps a `HostInterface`, enforces per-call quotas, records a `Transcript`. You will add policy enforcement here.
- `src/host/canonicalize.rs` — `canonical_serialize(v: &LuaValue) -> Vec<u8>` is the single JSON encoding path.
- `docs/tls-attestation.md` documents the TLS trust model.

`cargo test` passes and must continue to pass after your changes.

### Your Task

Implement all of Phase 2 as specified in `planning/programmable-oracle-mvp-plan.md` under "Phase 2: Define Admissibility and Reproducibility":

1. **Replace the `OraclePolicy` stub** in `src/policy/mod.rs` with a full struct containing: `allowed_domains: Vec<String>`, `allowed_http_methods: Vec<String>`, `max_tool_calls: usize`, `max_payload_bytes_per_call: usize`, `tls_requirement: TlsRequirement` (an enum: `RequiredAttested | PreferredAttested | UnattestedPermitted`), `required_output_schema: Option<serde_json::Value>`, `schema_versions: HashMap<String, serde_json::Value>` (per-domain response schemas).
2. **Implement `canonical_serialize` for `OraclePolicy`** and `policy_hash(&self) -> [u8; 32]` as SHA-256 over the canonical bytes. The hash must be stable: same policy struct = same hash on any machine.
3. **Wire `policy_hash` into `PublicInputs`**: update `compute_public_inputs` in `src/zkvm/commitment.rs` to accept an `&OraclePolicy` and store `policy.policy_hash()`.
4. **Add domain allowlist enforcement** in `src/host/tool_registry.rs`: `http_get` and `http_post` must reject calls to domains not in `policy.allowed_domains`. Rejections must return `VmError`, not panic.
5. **Add HTTP method restriction**: `http_post` must be rejected when not in `policy.allowed_http_methods`. `template_price_feed_v1` uses `http_get` only.
6. **Add response schema validation** at the host boundary: after receiving a tool response, validate its JSON shape against `policy.schema_versions[domain]` if a schema is registered. Mismatch returns `VmError`.
7. **Define two named profiles** in `src/policy/profiles.rs`:
   - `constrained_http_v1()` — `http_get` only, no domain restriction, no schema constraint, `UnattestedPermitted`
   - `template_price_feed_v1()` — `http_get` only, approved domains TBD (leave as an empty `Vec` with a `// Phase 4 stub` comment), fixed response schema per source TBD (empty map with `// Phase 4 stub`), max 5 tool calls, `RequiredAttested`
8. **Write `docs/canonical-serialization.md`** describing the byte format of `OraclePolicy` canonical serialization precisely enough for an independent implementation to reproduce the same hash.
9. **Add tests**:
   - A domain-allowlist rejection test in `tests/tools.rs` (or a new `tests/policy.rs`)
   - A hash-stability test: construct `template_price_feed_v1()`, call `policy_hash()` twice, assert equal
   - A schema-mismatch rejection test

### Do Not Touch

- `luai-openvm/` — Phase 1's domain; read it, do not modify it
- `docs/tls-attestation.md` — Phase 1's doc; do not overwrite
- The OpenVM guest or prover pipeline — your changes are in `src/` only

### Verification

```bash
cargo test
# → all tests pass

cargo test --test policy
# → test domain_allowlist_rejects_unapproved_domain ... ok
# → test policy_hash_is_stable ... ok
# → test schema_mismatch_returns_vm_error ... ok

cargo test --lib policy
# → all policy unit tests pass
```

---

## Step 3a — Phase 3: Standalone Verifier Library

**Branch:** `phase/3a-verifier-lib`
**Depends on:** Step 2 merged to main

**Prompt:**

You are implementing the standalone verifier library portion of Phase 3 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 3: Validate On-Chain Viability". Read that section carefully before writing any code.

### Context

Phases 1 and 2 are complete:

- Phase 1: TLS attestation is cryptographically sound. P-256 ECDSA verification and Mozilla root CA pinning are implemented. `tls_attestation_hash` is non-zero for supported servers.
- Phase 2: `OraclePolicy` is a first-class type with a stable `policy_hash`. `PublicInputs` includes `policy_hash`. Domain allowlisting and response schema validation are enforced at the host boundary. Two profiles exist: `constrained_http_v1` and `template_price_feed_v1`.

`PublicInputs` in `src/zkvm/commitment.rs` has these fields, all `[u8; 32]`: `program_hash`, `input_hash`, `tool_responses_hash`, `output_hash`, `tls_attestation_hash`, `policy_hash`.

`cargo test` passes and must continue to pass.

### Your Task

Build a standalone Rust verifier library as specified in `planning/programmable-oracle-mvp-plan.md` under "Phase 3: Validate On-Chain Viability":

1. Create a new workspace crate `luai-verifier/` in `Cargo.toml`. It must not depend on the full luai VM runtime — only on `luai`'s `zkvm` module (for `PublicInputs`) and the OpenVM verification library.
2. Implement the public API in `luai-verifier/src/lib.rs`:
   ```rust
   pub struct VerificationResult {
       pub verified: bool,
       pub public_inputs: PublicInputs,
       pub output_bytes: Vec<u8>,
   }
   pub fn verify_proof(
       proof: &[u8],
       public_inputs: &PublicInputs,
       expected_policy_hash: &[u8; 32],
   ) -> Result<VerificationResult, VerifyError>;
   ```
   `verify_proof` must: (a) verify the OpenVM proof, (b) check `public_inputs.policy_hash == expected_policy_hash`, (c) return `Err` with a descriptive variant if either check fails.
3. Define `VerifyError` as an enum with at least: `ProofInvalid`, `PolicyHashMismatch { got: [u8; 32], expected: [u8; 32] }`, `MalformedInput(String)`.
4. Add tests in `luai-verifier/tests/`:
   - `verify_valid_proof_succeeds` — use a fixture proof generated from the test suite
   - `verify_wrong_policy_hash_fails` — assert `Err(VerifyError::PolicyHashMismatch { .. })`
   - `verify_tampered_proof_fails` — flip a byte in the proof, assert `Err(VerifyError::ProofInvalid)`

### Do Not Touch

- `contracts/` — does not exist yet; that is Step 3b's domain
- `src/policy/` — Phase 2's domain; read `PublicInputs` and `OraclePolicy`, do not modify them
- `luai-openvm/` — Phase 1's domain; link against it, do not modify it

### Verification

```bash
cargo build -p luai-verifier
# → compiles without errors

cargo test -p luai-verifier
# → test verify_valid_proof_succeeds ... ok
# → test verify_wrong_policy_hash_fails ... ok
# → test verify_tampered_proof_fails ... ok

cargo test
# → all workspace tests still pass
```

---

## Step 3b — Phase 3: Solidity Contracts

**Branch:** `phase/3b-contracts`
**Depends on:** Step 2 merged to main

**Prompt:**

You are implementing the Solidity contracts portion of Phase 3 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 3: Validate On-Chain Viability". Read that section carefully before writing any code.

### Context

Phases 1 and 2 are complete:

- Phase 1: TLS attestation is cryptographically sound with P-256 ECDSA and Mozilla root CA pinning.
- Phase 2: `OraclePolicy` has a stable `policy_hash`. `PublicInputs` (in `src/zkvm/commitment.rs`) has these fields, all `[u8; 32]`: `program_hash`, `input_hash`, `tool_responses_hash`, `output_hash`, `tls_attestation_hash`, `policy_hash`.

There are no Solidity contracts in the repository yet. You will create the `contracts/` directory and set up the toolchain.

`cargo test` passes and must continue to pass (your changes are Solidity only and do not affect it).

### Your Task

Build the Solidity verifier and consumer contracts as specified in `planning/programmable-oracle-mvp-plan.md` under "Phase 3: Validate On-Chain Viability":

1. Create `contracts/` and initialize a Hardhat or Foundry project (prefer Foundry if no prior toolchain is present).
2. Implement `contracts/src/LuaiVerifier.sol`:
   - Constructor accepts `bytes32 expectedPolicyHash`
   - `function verify(bytes calldata proof, PublicInputs calldata inputs) external returns (bool)`
   - Calls the OpenVM on-chain verifier (use a stub/interface if the verifier contract address is not yet known)
   - Reverts with `PolicyHashMismatch()` if `inputs.policyHash != expectedPolicyHash`
   - Reverts with `ProofInvalid()` if the OpenVM proof check fails
3. Define `struct PublicInputs` in `contracts/src/Types.sol` matching the Rust layout: six `bytes32` fields in the order: `programHash`, `inputHash`, `toolResponsesHash`, `outputHash`, `tlsAttestationHash`, `policyHash`.
4. Implement `contracts/src/LuaiConsumer.sol`:
   - Stores the last verified `uint256 price` and `uint64 timestamp`
   - `function consumeResult(bytes calldata proof, PublicInputs calldata inputs, bytes calldata outputPayload) external`
   - Calls `LuaiVerifier.verify(proof, inputs)`, then ABI-decodes `outputPayload` as `(uint256 price, uint8 sourcesUsed, uint64 blockTimestamp)` and stores them
5. Write Foundry tests in `contracts/test/`:
   - `LuaiVerifier.t.sol`: assert valid proof + correct policy hash passes; assert wrong policy hash reverts with `PolicyHashMismatch()`
   - `LuaiConsumer.t.sol`: assert `consumeResult` updates stored price on valid proof; assert it reverts on invalid proof
6. Add `contracts/README.md` describing the ABI encoding of `PublicInputs` and the output payload schema.

### Do Not Touch

- `luai-verifier/` — does not exist yet; that is Step 3a's domain
- `src/` — Phase 2's domain; do not modify any Rust source files
- `Cargo.toml` — do not modify; Step 3a owns workspace membership changes

### Verification

```bash
cd contracts && forge build
# → compiles without errors

cd contracts && forge test
# → test LuaiVerifier_valid_proof_passes ... ok
# → test LuaiVerifier_wrong_policy_hash_reverts ... ok
# → test LuaiConsumer_stores_price_on_valid_proof ... ok

cargo test
# → all Rust workspace tests still pass
```

---

## Step 4 — Phase 3: Testnet Deploy and Benchmark

**Branch:** `phase/3c-testnet`
**Depends on:** Steps 3a and 3b merged to main

**Prompt:**

You are completing Phase 3 of the luai MVP by deploying to testnet and measuring on-chain viability. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 3: Validate On-Chain Viability". Read that section before proceeding.

### Context

Phases 1, 2, and 3 (library + contracts) are complete:

- Phase 1: Proof pipeline is cryptographically sound with TLS attestation.
- Phase 2: `OraclePolicy` with stable `policy_hash`; domain allowlisting and schema validation enforced.
- Phase 3a: `luai-verifier` crate with `verify_proof(proof, public_inputs, expected_policy_hash)`.
- Phase 3b: `contracts/src/LuaiVerifier.sol` and `contracts/src/LuaiConsumer.sol` with Foundry tests.

`PublicInputs` ABI layout is documented in `contracts/README.md`.

`cargo test` and `forge test` both pass.

### Your Task

Deploy to testnet and record benchmark numbers as specified in `planning/programmable-oracle-mvp-plan.md` under "Phase 3: Validate On-Chain Viability":

1. Deploy `LuaiVerifier.sol` to Sepolia testnet with a known policy hash (use `template_price_feed_v1().policy_hash()` from `src/policy/profiles.rs`).
2. Generate a real proof using `luai-prover` with a live HTTPS task (a simple `http_get` to an approved endpoint is sufficient).
3. Submit the proof to the deployed contract and confirm the transaction succeeds.
4. Submit a proof with a different policy hash and confirm the transaction reverts with `PolicyHashMismatch()`.
5. Measure and record:
   - Proof size in bytes
   - Gas used for `LuaiVerifier.verify`
   - End-to-end latency: time from `luai-prover` invocation to proof available
6. Record everything in `planning/phase3-benchmarks.md`:
   - Deployed contract addresses (Sepolia)
   - Transaction hashes for the passing and rejecting submissions
   - The three measurements above
   - Explicit pass/fail thresholds (define: max acceptable gas, max acceptable proof size, max acceptable latency)
   - A clear PASS or FAIL verdict against each threshold

**If any measurement exceeds its threshold, do not proceed.** Record the failure in `planning/phase3-benchmarks.md` and stop. The next phase must not begin until the numbers are within range.

### Do Not Touch

- `src/policy/profiles.rs` — read `template_price_feed_v1()`, do not modify
- `contracts/src/` — do not modify the contracts; deploy them as-is
- `luai-verifier/` — do not modify; use it as a tool

### Verification

```bash
cat planning/phase3-benchmarks.md
# → contains deployed contract addresses
# → contains gas measurement
# → contains proof size measurement
# → contains latency measurement
# → contains explicit PASS/FAIL verdict for each threshold

cargo test && cd contracts && forge test
# → all tests still pass
```

---

## Step 5a — Phase 4: Lua Template and Approved Sources

**Branch:** `phase/4a-template`
**Depends on:** Step 4 merged to main (gas/proof-size gate must have passed)

**Prompt:**

You are implementing the Lua template and approved sources portion of Phase 4 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 4: Ship One Template-Backed Oracle". Read that section carefully before writing any code.

### Context

Phases 1–3 are complete:

- Phase 1: TLS attestation cryptographically sound.
- Phase 2: `OraclePolicy` with `policy_hash`. `template_price_feed_v1()` profile exists in `src/policy/profiles.rs` but has placeholder empty fields for `allowed_domains` and `schema_versions` (marked `// Phase 4 stub`).
- Phase 3: `luai-verifier` and Solidity contracts deployed to Sepolia testnet. Gas and proof size pass thresholds (see `planning/phase3-benchmarks.md`).

The VM accepts Lua programs via `luai-compiler` → `luai-prover` pipeline. `tool.call(name, args)` invokes registered tools. `http_get(url)` returns `{status, body}` where `body` is a JSON string. `json.decode(body)` parses it into a Lua table.

`cargo test` passes and must continue to pass.

### Your Task

1. **Create `src/templates/price_feed_v1.lua`** — the parameterized Lua template for `template_price_feed_v1`. The template takes a Lua table `params` as its input with fields:
   - `params.sources` — array of `{url, field_path}` tables
   - `params.deviation_threshold_pct` — integer (e.g. 5 = 5%)
   - `params.scale` — integer scale factor for fixed-point output (e.g. 1000000 = 6 decimal places)

   The template must: fetch each URL via `tool.call("http_get", {url=src.url})`, extract `field_path` from the decoded JSON response, normalize to fixed-point integer using `params.scale`, assert all values are within `params.deviation_threshold_pct` of each other (returning an error string if not), compute the average, return `{price=avg, sources_used=#params.sources, timestamp=tool.call("time_now", {})}`.

2. **Define approved sources** in `src/policy/sources.rs`. For each of these 3 sources define: the approved domain, the JSON field path for BTC/USD price, and the normalization factor:
   - CoinGecko: `api.coingecko.com`
   - CryptoCompare: `min-api.cryptocompare.com`
   - Binance: `api.binance.com`

   Add a `pub fn btc_usd_sources() -> Vec<ApprovedSource>` function returning all three.

3. **Update `template_price_feed_v1()` in `src/policy/profiles.rs`** to replace the Phase 4 stubs: populate `allowed_domains` from `btc_usd_sources()` and `schema_versions` from each source's declared response schema.

4. **Add tests** in `tests/integration.rs` (or a new `tests/template.rs`):
   - Load `src/templates/price_feed_v1.lua`, compile it, and run it through the VM with mock tool responses matching the approved source schemas. Assert the output has the correct shape `{price, sources_used, timestamp}`.
   - Assert that a mock response with a price deviation exceeding the threshold produces an error return value.

### Do Not Touch

- `contracts/` — Step 5b's domain (output schema update to consumer contract)
- `docs/output-schema.md` — does not exist yet; Step 5b's domain
- `luai-orchestrator/` — Step 6's domain; do not touch orchestrator code

### Verification

```bash
cargo test
# → all tests pass

cargo test --test template
# → test price_feed_v1_returns_correct_shape ... ok
# → test price_feed_v1_rejects_high_deviation ... ok

cargo build -p luai-compiler
# → compiles without errors
```

---

## Step 5b — Phase 4: Output Schema

**Branch:** `phase/4b-output-schema`
**Depends on:** Step 4 merged to main (gas/proof-size gate must have passed)

**Prompt:**

You are implementing the output schema definition portion of Phase 4 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 4: Ship One Template-Backed Oracle". Read that section carefully before writing any code.

### Context

Phases 1–3 are complete:

- Phase 2: `OraclePolicy` and `policy_hash` defined. `template_price_feed_v1()` profile exists in `src/policy/profiles.rs`.
- Phase 3b: `contracts/src/LuaiConsumer.sol` currently ABI-decodes the output payload as `(uint256 price, uint8 sourcesUsed, uint64 blockTimestamp)`. This is a placeholder — you will confirm and document this as the canonical schema.
- Phase 3: Contracts deployed to Sepolia; addresses in `planning/phase3-benchmarks.md`.

`cargo test` and `forge test` pass and must continue to pass.

### Your Task

1. **Write `docs/output-schema.md`** defining the canonical output schema for `template_price_feed_v1`:
   - Lua return value: `{price: integer, sources_used: integer, timestamp: integer}`
   - `price` — fixed-point integer; scale factor defined in `params.scale`
   - `sources_used` — number of sources that contributed
   - `timestamp` — Unix timestamp from `time_now` tool
   - On-chain ABI encoding: `abi.encode(uint256 price, uint8 sourcesUsed, uint64 blockTimestamp)`
   - Include an example encoding with sample values

2. **Verify and update `contracts/src/LuaiConsumer.sol`** to match the schema in `docs/output-schema.md` exactly. If the ABI decode matches already, add a comment referencing the doc. If it differs, fix it.

3. **Update the Foundry test** in `contracts/test/LuaiConsumer.t.sol` to encode a sample payload matching the documented schema and assert the consumer stores it correctly.

4. **Add a schema hash constant** to `src/policy/profiles.rs` for use in `template_price_feed_v1()`: a `const PRICE_FEED_V1_OUTPUT_SCHEMA_HASH: [u8; 32]` computed as the SHA-256 of the canonical schema description bytes. This lets policies commit to a specific output schema version.

### Do Not Touch

- `src/templates/price_feed_v1.lua` — does not exist yet; Step 5a's domain
- `src/policy/sources.rs` — does not exist yet; Step 5a's domain
- `src/policy/profiles.rs` approved_domains and schema_versions fields — Step 5a's domain

### Verification

```bash
cd contracts && forge build && forge test
# → test LuaiConsumer_stores_price_on_valid_proof ... ok
# → all other tests still pass

cargo test
# → all Rust tests still pass

cat docs/output-schema.md
# → contains ABI encoding section
# → contains example encoding
```

---

## Step 6 — Phase 4: Orchestrator and End-to-End Example

**Branch:** `phase/4c-orchestrator`
**Depends on:** Steps 5a and 5b merged to main

**Prompt:**

You are completing Phase 4 of the luai MVP by wiring up the orchestrator and publishing an end-to-end example. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 4: Ship One Template-Backed Oracle". Read that section carefully before writing any code.

### Context

Phase 4 (parts a and b) is complete:

- Phase 4a: `src/templates/price_feed_v1.lua` Lua template exists. `src/policy/sources.rs` defines `btc_usd_sources()` with 3 approved sources (CoinGecko, CryptoCompare, Binance). `template_price_feed_v1()` profile is fully populated.
- Phase 4b: `docs/output-schema.md` documents the canonical output schema. `contracts/src/LuaiConsumer.sol` decodes `(uint256, uint8, uint64)`.
- Phase 3: `luai-verifier` and Solidity contracts are deployed on Sepolia (addresses in `planning/phase3-benchmarks.md`).

The `luai-orchestrator` crate currently: accepts a natural-language task, sends it to the Claude API with a system prompt asking for a Lua program, compiles and executes the returned program, and retries on error. It is the entry point for `cargo run -p luai-orchestrator`.

`cargo test` passes and must continue to pass.

### Your Task

1. **Add a `--template` flag** to `luai-orchestrator`. When `--template price_feed_v1` is passed, use the template path instead of free-form generation.

2. **Implement parameter extraction** for `template_price_feed_v1` in `luai-orchestrator/src/template.rs` (create this file):
   - Send the user's task to the Claude API with a system prompt that asks it to extract ONLY: `{sources: [{url, field_path}], deviation_threshold_pct: integer, scale: integer}` as JSON
   - Validate the returned JSON: every `url`'s domain must appear in `btc_usd_sources()` domains; reject with a clear error if not
   - Assemble the final Lua by loading `src/templates/price_feed_v1.lua` and prepending a `local params = <json>` assignment
   - The LLM never writes Lua; it only fills parameter slots

3. **Update `luai-orchestrator/src/main.rs`** to branch on `--template`: if present, call `template::run(task, template_name)` instead of the free-form synthesis path.

4. **Publish an end-to-end example** in `examples/price-feed-e2e/`:
   - `README.md` — step-by-step walkthrough: submit task → parameter extraction → assembled Lua → VM execution → proof generation → on-chain verification → decoded result
   - `run.sh` — a shell script that runs the full pipeline with a sample task (`"get the average BTC/USD price from coingecko and cryptocompare"`) and prints each stage's output
   - Include sample outputs (redact any API keys)

### Do Not Touch

- `src/templates/price_feed_v1.lua` — read it, do not modify it
- `src/policy/sources.rs` — read it, do not modify it
- `contracts/` — read the deployed addresses, do not modify contracts

### Verification

```bash
cargo build -p luai-orchestrator
# → compiles without errors

cargo test
# → all tests pass

cargo run -p luai-orchestrator -- --template price_feed_v1 "get BTC/USD from coingecko and cryptocompare"
# → prints extracted params JSON
# → prints assembled Lua
# → (if ANTHROPIC_API_KEY is set) executes and returns a price result

cargo run -p luai-orchestrator -- --template price_feed_v1 "get price from unapproved.com"
# → prints a clear rejection message, exits non-zero
```

---

## Step 7a — Phase 5: Security Testing

**Branch:** `phase/5a-security`
**Depends on:** Step 6 merged to main

**Prompt:**

You are implementing the security testing portion of Phase 5 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 5: Harden for External Use". Read that section carefully before writing any code.

### Context

All of Phases 1–4 are complete:

- Phase 1: TLS attestation with P-256 and CA pinning.
- Phase 2: `OraclePolicy`, `policy_hash`, domain allowlisting, response schema validation.
- Phase 3: `luai-verifier`, Solidity contracts on Sepolia testnet.
- Phase 4: `template_price_feed_v1` Lua template, parameter extraction in orchestrator, end-to-end example.

The core VM pipeline is: source → `src/parser/` → `src/compiler/` → `src/bytecode/verifier.rs` → `src/vm/engine.rs` → `src/host/tool_registry.rs`. All five are in scope for fuzzing.

`cargo test` passes and must continue to pass.

### Your Task

1. **Set up cargo-fuzz** in `fuzz/` (add it to workspace if not present). Create fuzz targets for:
   - `fuzz/fuzz_targets/parser.rs` — arbitrary `&[u8]` as Lua source; assert `parse()` never panics (errors are fine, panics are not)
   - `fuzz/fuzz_targets/compiler.rs` — parse valid Lua first, then fuzz the resulting AST mutations through the compiler
   - `fuzz/fuzz_targets/verifier.rs` — arbitrary byte sequences as `Vec<Instruction>` through the bytecode verifier
   - `fuzz/fuzz_targets/host_boundary.rs` — arbitrary JSON bytes as mock tool responses through `ToolRegistry`; assert no panic

2. **Run each fuzzer** for at minimum 60 seconds per target (`cargo fuzz run <target> -- -max_total_time=60`). Fix any panics or assertion failures found. Commit fuzz targets and fixes separately.

3. **Add adversarial integration tests** in `tests/hardening.rs`:
   - `policy_bypass_rejected` — compile and run a Lua program that calls `tool.call("http_get", {url="http://evil.com"})` against a policy with only `coingecko.com` allowed; assert `VmError` with a domain-rejection message
   - `gas_exhaustion_terminates` — run a tight loop until gas is exhausted; assert `VmError::GasExhausted`, not a hang or panic
   - `memory_limit_terminates` — allocate large tables until memory limit is hit; assert `VmError::MemoryExhausted`
   - `tool_call_limit_terminates` — call a tool more times than the policy allows; assert `VmError` with a quota message
   - `determinism_check` — run the same program with the same mock tool responses twice; assert `output_hash` and `gas_used` are identical both times
   - `malformed_json_response` — inject `b"not json"` as a tool response; assert `VmError`, not a panic
   - `schema_mismatch_response` — inject a JSON response that does not match the declared schema; assert `VmError`

### Do Not Touch

- `luai-orchestrator/` — Step 7b's domain
- `Dockerfile` — does not exist yet; Step 7b's domain
- `contracts/` — do not modify

### Verification

```bash
cargo fuzz build
# → all fuzz targets compile

cargo fuzz run parser -- -max_total_time=60
cargo fuzz run compiler -- -max_total_time=60
cargo fuzz run verifier -- -max_total_time=60
cargo fuzz run host_boundary -- -max_total_time=60
# → each runs without finding panics

cargo test --test hardening
# → test policy_bypass_rejected ... ok
# → test gas_exhaustion_terminates ... ok
# → test memory_limit_terminates ... ok
# → test tool_call_limit_terminates ... ok
# → test determinism_check ... ok
# → test malformed_json_response ... ok
# → test schema_mismatch_response ... ok

cargo test
# → all tests pass
```

---

## Step 7b — Phase 5: Service Hardening

**Branch:** `phase/5b-hardening`
**Depends on:** Step 6 merged to main

**Prompt:**

You are implementing the service hardening portion of Phase 5 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 5: Harden for External Use". Read that section carefully before writing any code.

### Context

All of Phases 1–4 are complete:

- Phase 4: `luai-orchestrator` accepts `--template price_feed_v1` and runs parameter extraction + VM execution.
- The orchestrator's main entry point is in `luai-orchestrator/src/main.rs`.

`cargo test` passes and must continue to pass.

### Your Task

1. **Add structured logging** using the `tracing` crate to `luai-orchestrator/src/`:
   - Instrument task submission, policy check, template assembly, VM execution, and proof generation
   - Each log event must include: `task_id` (UUID), `policy_hash` (hex), `gas_used`, `memory_used`, `outcome` (`ok` or `err`), `latency_ms`
   - Use `tracing_subscriber` with JSON format output (machine-parseable)
   - Add `RUST_LOG=info` to the example in the README

2. **Add API key authentication** to a new minimal HTTP service in `luai-orchestrator/src/server.rs`:
   - `POST /jobs` — accepts `{task: string, template: string}` + `Authorization: Bearer <key>` header; returns `{job_id: string}`
   - `GET /jobs/{id}` — returns `{status: "pending"|"running"|"done"|"failed", result?: {...}, error?: string}`
   - Reject unauthenticated requests with HTTP 401
   - API keys are loaded from an env var `LUAI_API_KEYS` (comma-separated list)

3. **Add per-key rate limiting**: max 10 requests/minute per API key. Return HTTP 429 on excess. Use an in-memory token-bucket (no external dependency required).

4. **Add a `Dockerfile`** at the repo root for the hosted service:
   - Multi-stage build: builder stage compiles `luai-orchestrator`, final stage is `debian:slim`
   - Exposes port 8080
   - Health check: `GET /healthz` returns 200

5. **Add a `docker-compose.yml`** at the repo root for local development.

6. **Write `docs/deployment.md`** covering: env vars required (`ANTHROPIC_API_KEY`, `LUAI_API_KEYS`), how to build and run with Docker, how to submit a job via curl.

### Do Not Touch

- `fuzz/` — does not exist yet; Step 7a's domain
- `tests/hardening.rs` — does not exist yet; Step 7a's domain
- `src/` (core library) — do not modify VM, policy, or template code
- `contracts/` — do not modify

### Verification

```bash
cargo build -p luai-orchestrator
# → compiles without errors

cargo test
# → all tests pass

docker build -t luai-orchestrator .
# → image builds successfully

docker run -e ANTHROPIC_API_KEY=test -e LUAI_API_KEYS=testkey -p 8080:8080 luai-orchestrator &
curl -s http://localhost:8080/healthz
# → HTTP 200

curl -s -X POST http://localhost:8080/jobs \
  -H "Authorization: Bearer testkey" \
  -H "Content-Type: application/json" \
  -d '{"task":"test","template":"price_feed_v1"}'
# → {"job_id":"..."}

curl -s -X POST http://localhost:8080/jobs \
  -H "Content-Type: application/json" \
  -d '{"task":"test"}'
# → HTTP 401
```

---

## Step 8 — Phase 5+6: Threat Model and MVP Release

**Branch:** `phase/5c-release`
**Depends on:** Steps 7a and 7b merged to main

**Prompt:**

You are completing Phase 5 and implementing Phase 6 of the luai MVP. The full specification is in `planning/programmable-oracle-mvp-plan.md` under "Phase 5: Harden for External Use" and "Phase 6: MVP Release". Read both sections carefully before writing any code.

### Context

All of Phases 1–5 (security testing and service hardening) are complete:

- Phase 1: Cryptographically sound TLS attestation.
- Phase 2: `OraclePolicy`, `policy_hash`, domain allowlisting, schema validation.
- Phase 3: `luai-verifier` Rust crate and Solidity contracts on Sepolia. Gas/proof benchmarks in `planning/phase3-benchmarks.md`.
- Phase 4: `template_price_feed_v1` end-to-end. Orchestrator with `--template` flag. Example in `examples/price-feed-e2e/`.
- Phase 5a: Fuzz targets in `fuzz/`. Adversarial tests in `tests/hardening.rs`.
- Phase 5b: Structured logging, HTTP service with auth and rate limiting in `luai-orchestrator`. `Dockerfile` and `docs/deployment.md`.

`cargo test` passes. `forge test` passes. Docker image builds. API key auth works.

### Your Task

**Part A — Threat Model (Phase 5 completion)**

1. Write `docs/threat-model.md` as specified in `planning/programmable-oracle-mvp-plan.md` under "Phase 5":
   - Trust assumptions at MVP: executor liveness, TLS CA honesty, Claude API availability
   - What the proof DOES guarantee: computational integrity, policy compliance, data provenance for `RequiredAttested` sources
   - What the proof DOES NOT guarantee: response freshness beyond nonce window, unattested sources, executor liveness
   - Each failure mode from the spec's "Where the Trust Model Can Break" section — its mitigation and residual risk
   - How a protocol should self-select: suitable use cases (settlement, periodic rebalancing, bounded scoring) vs. unsuitable (real-time liquidation pricing, sub-minute freshness)

**Part B — MVP Release (Phase 6)**

2. **Launch the public testnet deployment**:
   - Deploy a fresh `LuaiVerifier.sol` to Sepolia with `template_price_feed_v1().policy_hash()`
   - Deploy the hosted service (use `docs/deployment.md`)
   - Run a live smoke test: submit a real price-feed task end-to-end, confirm the proof verifies on-chain
   - Record final deployed addresses in `docs/deployments.md`

3. **Write `docs/user-guide.md`** covering: how to submit a task (curl + SDK), available policies and their constraints, how to verify a proof independently using `luai-verifier`, how to consume a result in a Solidity contract, known limitations (latency, TLS coverage, liveness).

4. **Ship the TypeScript SDK** in `sdk/`:
   - `sdk/src/index.ts` — exports `submitTask(task, template, apiKey, baseUrl)`, `pollJob(jobId, apiKey, baseUrl)`, `decodeResult(outputBytes)`
   - TypeScript types: `PublicInputs`, `OracleResult { price: bigint, sourcesUsed: number, timestamp: bigint }`
   - `sdk/README.md` with usage examples
   - `sdk/package.json` with build script

5. **Write `docs/benchmarks.md`** with: proof generation latency (from `planning/phase3-benchmarks.md`), on-chain verification gas cost, token efficiency vs. LangChain (data is in `README.md`), explicit "Out of scope for MVP" section listing real-time liquidation, non-attested sources, liveness guarantees, and mainnet.

### Do Not Touch

- `fuzz/` — Phase 5a's domain; do not modify fuzz targets
- `tests/hardening.rs` — Phase 5a's domain; do not modify
- `contracts/src/` — do not modify the contract source; you are deploying existing contracts

### Verification

```bash
cargo test && cd contracts && forge test
# → all tests pass

cat docs/threat-model.md
# → contains "Trust assumptions" section
# → contains "What the proof DOES guarantee" section
# → contains "Suitable use cases" section

cat docs/deployments.md
# → contains Sepolia contract address for LuaiVerifier
# → contains hosted service endpoint

cat docs/user-guide.md
# → contains curl example for POST /jobs

cd sdk && npm run build
# → TypeScript compiles without errors

cat docs/benchmarks.md
# → contains proof generation latency
# → contains gas cost
# → contains "Out of scope for MVP" section
```
