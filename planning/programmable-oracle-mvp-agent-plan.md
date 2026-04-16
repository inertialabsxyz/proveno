# luai MVP — Agent Execution Plan

**Source:** `programmable-oracle-mvp-plan.md`
**Purpose:** Translate the MVP roadmap into discrete, executable agent tasks with explicit parallelism.

---

## How to read this document

Each phase lists its tasks as either **sequential** or **parallel**. Sequential tasks must complete before the next starts. Parallel tasks can be launched in a single agent batch — spawn them simultaneously, then wait for all to finish before proceeding.

When spawning parallel agents, include in each prompt:
- the relevant source files and modules to read
- the exact acceptance criterion the agent is responsible for
- the quality gate command (`cargo test`) to run before committing

All agents must pass `cargo test` before committing any change.

---

## Phase 1 — Finish Proof Integrity

**Objective:** Make the proof pipeline cryptographically complete for real HTTPS-backed executions.

**Exit condition:** luai can prove one real HTTPS-backed execution with a non-zero `tls_attestation_hash`.

### Step 1.1 — Sequential: understand the current TLS state

One agent reads the existing TLS attestation implementation and writes a short report before any code is touched.

```
Agent({
  description: "Audit TLS attestation gaps",
  prompt: """
    Read the TLS attestation implementation in the luai codebase.
    Relevant areas: luai-openvm guest, luai-prover, any tls/ or attestation/ modules.
    Also read planning/programmable-oracle-mvp-plan.md Phase 1 section.

    Report:
    1. What TLS verification steps are currently implemented?
    2. Where exactly does P-256 ECDSA verification need to be added?
    3. Where exactly does Mozilla root CA pinning need to be added?
    4. What does the current graceful-degradation path look like for non-P256 servers?

    Do not write any code. Return a structured findings report.
  """
})
```

### Step 1.2 — Parallel: implement P-256 + CA pinning

After the audit report, spawn two agents concurrently:

```
Agent A: "Implement P-256 ECDSA verification"
  - Read the audit report from Step 1.1
  - Implement full P-256 ECDSA signature verification in the zkVM verification path
  - Files: wherever the audit identified the gap (luai-openvm or luai-prover)
  - Run cargo test before committing
  - Commit as: feat(tls): implement P-256 ECDSA verification in zkVM path

Agent B: "Implement Mozilla root CA pinning"
  - Read the audit report from Step 1.1
  - Implement root CA pinning against the Mozilla root set
  - Ensure the pinned roots are embedded as a static constant, not fetched at runtime
  - Run cargo test before committing
  - Commit as: feat(tls): add Mozilla root CA pinning
```

Wait for both agents to complete before proceeding.

### Step 1.3 — Parallel: test + document

Spawn two agents concurrently:

```
Agent A: "Add live HTTPS prove test"
  - Add an end-to-end integration test that:
    - makes a real HTTPS request to a public API with P-256 support
    - runs the full prove pipeline
    - asserts that tls_attestation_hash is non-zero in the output
    - asserts graceful failure (not panic) when the server uses a non-P256 cipher
  - Test lives in tests/ or alongside the prover
  - Run cargo test before committing
  - Commit as: test(tls): add live HTTPS prove test with attestation assertion

Agent B: "Document TLS attestation model"
  - Write a doc (docs/tls-attestation.md or similar) covering:
    - exactly what the TLS attestation hash proves
    - what it does NOT prove (wall-clock time, response freshness)
    - which TLS configurations are supported vs. unsupported
    - what happens to the proof when attestation is unavailable
  - This doc should be readable by a third party auditor
  - Commit as: docs(tls): document attestation model and trust boundaries
```

### Phase 1 acceptance checklist

Before advancing to Phase 2, verify all of the following:

- [ ] A real HTTPS task proves end-to-end successfully
- [ ] The proof contains a non-zero `tls_attestation_hash` for P-256 servers
- [ ] Non-P256 servers degrade cleanly without invalid claims
- [ ] `cargo test` passes across all workspace members
- [ ] Attestation trust model is documented

---

## Phase 2 — Define Admissibility and Reproducibility

**Objective:** Define what counts as an acceptable oracle execution and make commitments reproducible outside the codebase.

**Exit condition:** luai can distinguish between "correctly executed" and "policy-approved" executions. The same artifact yields the same hashes in an independent implementation.

### Step 2.1 — Sequential: design OraclePolicy structure

One agent designs the `OraclePolicy` data structure and gets it reviewed before implementation begins.

```
Agent({
  description: "Design OraclePolicy schema",
  prompt: """
    Read planning/programmable-oracle-mvp-plan.md, Phase 2 section.
    Read the current public input / commitment structures in src/zkvm/.
    Read host/ and how tool calls are currently validated.

    Design the OraclePolicy struct:
    - fields: allowed_domains (Vec<String>), allowed_opcodes, max_tool_calls,
              max_payload_bytes, required_output_schema, tls_attestation_tier
              (RequiredAttested | PreferredAttested | UnattestedPermitted per source),
              schema_versions per source
    - it must be serializable to a canonical byte representation for hashing
    - policy_hash = SHA-256(canonical_serialize(policy))

    Output: a Rust struct definition and a short explanation of each field.
    Do NOT write production code yet — just the design doc/struct sketch.
    Return the struct definition and rationale.
  """
})
```

### Step 2.2 — Parallel: implement policy artifact + canonical serialization

After design is approved:

```
Agent A: "Implement OraclePolicy type and policy_hash"
  - Add OraclePolicy to src/ (e.g. src/policy/mod.rs)
  - Implement canonical_serialize for OraclePolicy
  - Add policy_hash() -> [u8; 32] using SHA-256 over canonical form
  - Add policy_hash to PublicInputs in src/zkvm/commitment.rs
  - Run cargo test before committing
  - Commit as: feat(policy): add OraclePolicy type and policy_hash to public inputs

Agent B: "Specify canonical serialization for all commitment inputs"
  - Audit src/host/canonicalize.rs and src/zkvm/
  - Ensure canonical_serialize covers: policy docs, task inputs, tool responses, outputs
  - Write a spec doc (docs/canonical-serialization.md) describing the format
    precisely enough for an independent implementation to reproduce the same bytes
  - Add a test that encodes a known fixture and asserts the exact byte output
  - Run cargo test before committing
  - Commit as: docs(canon): specify canonical serialization format for all commitment inputs
```

### Step 2.3 — Parallel: domain allowlisting + host boundary validation

```
Agent A: "Implement domain allowlisting and HTTP restrictions"
  - Add domain allowlist enforcement to the ToolRegistry or host boundary
  - http_get and http_post must reject calls to domains not in policy.allowed_domains
  - http_post must be disallowable per-policy (template_price_feed_v1 uses http_get only)
  - Add tests covering allowed and rejected domain calls
  - Commit as: feat(policy): enforce domain allowlist and HTTP method restrictions

Agent B: "Validate tool args and return schemas at host boundary"
  - Add schema validation for tool call arguments (JSON shape check against policy schema_versions)
  - Add schema validation for tool responses (reject responses that don't match declared schema)
  - Validation errors should surface as VmError, not silent wrong results
  - Add tests with malformed args and schema-mismatched responses
  - Commit as: feat(policy): validate tool args and response schemas at host boundary
```

### Step 2.4 — Parallel: define profiles + publish docs

```
Agent A: "Define constrained_http_v1 and template_price_feed_v1 profiles"
  - Create src/policy/profiles.rs (or similar)
  - constrained_http_v1: http_get only, bounded payload, no schema constraint
  - template_price_feed_v1: http_get only, approved domains only, fixed response + output schema,
    max 5 tool calls, all sources required_attested
  - Add a test that constructs each profile, hashes it, and asserts the hash is stable
  - Commit as: feat(policy): define constrained_http_v1 and template_price_feed_v1 profiles

Agent B: "Publish verifier-facing hashing and replay docs"
  - Write docs/verification.md covering:
    - how to independently compute policy_hash, program_hash, oracle_tape hash, output_hash
    - the exact byte layout of PublicInputs
    - a worked example with inputs and expected hashes
  - Commit as: docs(verification): publish verifier-facing hashing and replay documentation
```

### Phase 2 acceptance checklist

- [ ] OraclePolicy is a first-class artifact with a stable, canonical hash
- [ ] policy_hash appears in PublicInputs
- [ ] Domain allowlisting is enforced at the host boundary
- [ ] Tool args and response schemas are validated at the host boundary
- [ ] Two named profiles exist: `constrained_http_v1` and `template_price_feed_v1`
- [ ] An independent implementation can reproduce the same hashes from the docs
- [ ] `cargo test` passes across all workspace members

---

## Phase 3 — Validate On-Chain Viability

**Objective:** Prove that luai results can be consumed by smart contracts under policy constraints.

**Exit condition:** A testnet contract verifies a luai proof. Gas and proof size are within operationally usable thresholds.

### Step 3.1 — Sequential: finalize public inputs

```
Agent({
  description: "Finalize PublicInputs with policy_hash",
  prompt: """
    Read src/zkvm/commitment.rs.
    Ensure PublicInputs contains: program_hash, input_hash, tool_responses_hash,
    output_hash, policy_hash, tls_attestation_hash.
    All fields must be [u8; 32].
    The canonical serialization of PublicInputs must be stable and documented.
    Update tests to assert each field is populated correctly for a known fixture.
    Run cargo test. Commit as: feat(zkvm): finalize PublicInputs structure with policy_hash
  """
})
```

### Step 3.2 — Parallel: verifier library + Solidity contract

```
Agent A: "Build standalone verifier library"
  - Build a standalone Rust library (or crate) that, given:
      - a proof
      - PublicInputs
      - expected policy_hash
    returns: verified (bool) + extracted output value
  - It must not depend on the full luai VM runtime
  - Add tests with valid and invalid proofs, and wrong-policy-hash rejection
  - Commit as: feat(verifier): add standalone proof verifier library

Agent B: "Implement Solidity verifier contract"
  - Write a Solidity contract that:
    - accepts a luai proof + PublicInputs
    - verifies the OpenVM proof
    - enforces that policy_hash matches a constructor-set expected value
    - exposes the verified output for consumption
  - Write a basic consumer contract that reads the verified output
  - Commit as: feat(contracts): add Solidity verifier and consumer contracts
```

### Step 3.3 — Sequential: deploy to testnet and benchmark

One agent runs the deployment and measurement (requires coordination):

```
Agent({
  description: "Deploy to testnet and measure gas/proof size",
  prompt: """
    Deploy the Solidity verifier contract to a testnet (Sepolia or equivalent).
    Submit a real luai execution proof via the contract.
    Measure and record:
    - proof size (bytes)
    - gas cost for verification
    - end-to-end latency (prove time + submission)
    Verify:
    - the contract accepts a valid proof with the correct policy_hash
    - the contract rejects a proof with a wrong policy_hash
    Document results in planning/phase3-benchmarks.md.
    Set explicit pass/fail thresholds in that document.
    Commit as: docs(phase3): record testnet benchmark results and acceptance thresholds
  """
})
```

### Phase 3 acceptance checklist

- [ ] Testnet contract verifies a luai proof successfully
- [ ] Contract rejects proofs with wrong policy_hash
- [ ] Gas and proof size are within documented acceptance thresholds
- [ ] Thresholds are recorded in `planning/phase3-benchmarks.md`
- [ ] `cargo test` passes

**If gas/proof size exceed thresholds:** do not proceed to Phase 4. Investigate recursive proof aggregation or alternative verification paths before continuing.

---

## Phase 4 — Ship One Template-Backed Oracle

**Objective:** Turn the infrastructure into one productized oracle workflow.

**Exit condition:** A supported plain-English price feed task consistently resolves into `template_price_feed_v1` and executes reliably across approved sources.

### Step 4.1 — Parallel: template implementation + approved sources + output schema

These three can be assigned to three concurrent agents:

```
Agent A: "Implement template_price_feed_v1 Lua template"
  - Implement the Lua template for template_price_feed_v1:
    - accepts: list of (url, field_path) pairs, deviation_threshold
    - fetches each URL via http_get
    - extracts the numeric field at field_path
    - normalizes to fixed-point integer (scale factor in policy)
    - computes average; asserts all values within deviation_threshold of each other
    - returns: {price: integer, sources: integer, timestamp: integer}
  - The template is parameterized — it must not be free-form LLM output
  - Add unit tests for the template logic
  - Commit as: feat(oracle): implement template_price_feed_v1 Lua template

Agent B: "Define approved domains and extraction schemas"
  - Choose 2-3 public price feed APIs (e.g. CoinGecko, CryptoCompare, Binance public endpoints)
  - For each source, define:
    - approved domain
    - response schema (JSON field paths, types)
    - normalization factor
  - Add these as named schema_versions in the template_price_feed_v1 policy profile
  - Add a test that fetches from each source in a mock environment and validates schema
  - Commit as: feat(oracle): define approved sources and extraction schemas for price feed

Agent C: "Define fixed output schema for downstream contracts"
  - Define the canonical output schema for template_price_feed_v1:
    {price: u64, sources_used: u8, block_timestamp: u64}
  - Ensure the Solidity consumer contract from Phase 3 can decode this schema
  - Document the ABI encoding in docs/output-schema.md
  - Commit as: feat(oracle): define and document template_price_feed_v1 output schema
```

### Step 4.2 — Sequential: prompt-to-template parameterization

```
Agent({
  description: "Implement prompt-to-template parameter extraction",
  prompt: """
    Read the orchestrator (luai-orchestrator) and how it currently calls the LLM.
    Read the template_price_feed_v1 Lua template implemented in Step 4.1.

    Change the orchestrator's code path for template_price_feed_v1:
    - instead of asking the LLM to write Lua, ask it to extract ONLY:
      {sources: [{url, field_path}], deviation_threshold_pct}
    - validate the extracted params against the approved sources list
    - reject any source not in the approved list
    - assemble the Lua by substituting params into the fixed template
    - the LLM never writes code; it only fills slots

    Add error handling so that unsupported task descriptions return a clear rejection
    rather than falling back to free-form synthesis.

    Run cargo test. Commit as: feat(orchestrator): parameter extraction for template_price_feed_v1
  """
})
```

### Step 4.3 — Sequential: end-to-end example

```
Agent({
  description: "Publish end-to-end example: natural language to verified on-chain result",
  prompt: """
    Write an end-to-end example script or documented walkthrough that:
    1. Starts with a plain-English task: "get the average BTC/USD price from [source A] and [source B]"
    2. Shows the parameter extraction output
    3. Shows the assembled Lua program
    4. Runs it through the VM (using mock or real sources)
    5. Generates the proof
    6. Verifies it against the testnet contract
    7. Shows the decoded output

    Place this in examples/price-feed-e2e/ with a README.
    Commit as: docs(examples): add end-to-end price feed oracle walkthrough
  """
})
```

### Phase 4 acceptance checklist

- [ ] Supported price feed tasks reliably resolve into `template_price_feed_v1` (not free-form)
- [ ] Unsupported tasks are rejected, not silently degraded
- [ ] Execution succeeds across the approved sources
- [ ] Output schema is stable and documented
- [ ] End-to-end example is published
- [ ] `cargo test` passes

---

## Phase 5 — Harden for External Use

**Objective:** Reduce the risk of exposing the MVP to real external users on testnet.

**Exit condition:** No obvious policy-bypass or determinism regressions in core testing. Hosted failures are observable. Operators understand the trust boundaries.

### Step 5.1 — Parallel: fuzzing + adversarial tests + gas calibration

```
Agent A: "Fuzz parser, compiler, verifier, VM, and host boundary"
  - Set up cargo-fuzz targets for:
    - parser (arbitrary Lua source)
    - compiler (arbitrary AST)
    - verifier (arbitrary bytecode)
    - host boundary (arbitrary JSON tool responses)
  - Run each fuzzer for a reasonable seed corpus; fix any panics or assertion failures
  - Commit fuzz targets as: test(fuzz): add fuzz targets for parser/compiler/verifier/host
  - Commit any fixes separately with descriptive messages

Agent B: "Run adversarial tests"
  - Write tests covering:
    - policy bypass: attempt to call a domain not in the allowlist
    - resource exhaustion: programs that hit gas limit, memory limit, tool call limit
    - nondeterminism: run the same program twice and assert identical output + hashes
    - malformed API responses: invalid JSON, wrong schema, missing fields
  - All tests must assert the correct error type, not just "it errored"
  - Commit as: test(hardening): add adversarial tests for policy, resources, determinism, malformed responses

Agent C: "Calibrate gas and resource costs for template_price_feed_v1"
  - Run the full template profile against the approved sources with instrumentation
  - Record: gas used, memory used, proving time, proof size for a 2-source and 5-source run
  - Compare against the VM's default resource limits; adjust if needed
  - Document in planning/resource-calibration.md
  - Commit as: docs(calibration): record gas and resource costs for template_price_feed_v1
```

### Step 5.2 — Parallel: observability + service hardening + packaging

```
Agent A: "Add metrics and structured logging"
  - Add structured logs to: task submission, policy check, VM execution, proof generation
  - Logs must include: task_id, policy_hash, gas_used, memory_used, outcome (ok/err), latency_ms
  - Use tracing or a similar crate; ensure log format is machine-parseable (JSON)
  - Commit as: feat(observability): add structured logging for execution pipeline

Agent B: "Add auth, rate limiting, and job status handling"
  - Add API key authentication to the hosted service endpoint (luai-orchestrator or a new service crate)
  - Add per-key rate limiting (max N requests/minute, configurable)
  - Add a job status endpoint: POST /jobs returns job_id; GET /jobs/{id} returns status + result
  - Commit as: feat(service): add auth, rate limiting, and async job status to hosted service

Agent C: "Package MVP for deployment"
  - Add a Dockerfile for the hosted service
  - Add a docker-compose.yml for local development with all dependencies
  - Document deployment steps in docs/deployment.md
  - Commit as: chore(deploy): add Dockerfile and deployment documentation
```

### Step 5.3 — Sequential: threat model doc

```
Agent({
  description: "Write threat model and trust-boundary documentation",
  prompt: """
    Read planning/programmable-oracle-mvp-plan.md, the "Where the Trust Model Can Break" section.
    Read the implementation across src/, luai-orchestrator, and luai-openvm.

    Write docs/threat-model.md covering:
    - trust assumptions at MVP (executor liveness, TLS CA honesty, etc.)
    - what the proof DOES guarantee (computation integrity, policy compliance, data provenance for attested sources)
    - what the proof DOES NOT guarantee (freshness beyond nonce window, non-attested sources, executor liveness)
    - each failure mode from the plan, its mitigation, and its residual risk
    - how a protocol should self-select (suitable vs. unsuitable use cases)

    Commit as: docs(security): add threat model and trust-boundary documentation
  """
})
```

### Phase 5 acceptance checklist

- [ ] Fuzz targets exist and produce no panics on seed corpus
- [ ] Adversarial tests pass (policy bypass rejected, resource exhaustion caught, determinism confirmed)
- [ ] Gas/resource calibration is documented
- [ ] Structured logging in place
- [ ] Auth and rate limiting in place
- [ ] Deployment packaging complete
- [ ] Threat model documented
- [ ] `cargo test` passes

---

## Phase 6 — MVP Release

**Objective:** Put the constrained oracle in front of early adopters.

**Exit condition:** External users can submit supported tasks without hand-holding. At least one external integration runs on testnet.

### Step 6.1 — Parallel: testnet deployment + documentation + TypeScript SDK

```
Agent A: "Launch public testnet deployment"
  - Deploy the hardened MVP to a public testnet endpoint
  - Configure the verifier contract on Sepolia (or equivalent)
  - Smoke test the deployed endpoint with a real price feed task end-to-end
  - Record the deployment addresses in docs/deployments.md
  - Commit as: chore(deploy): publish testnet deployment addresses and smoke test results

Agent B: "Write user-facing documentation"
  - Write docs/user-guide.md covering:
    - how to submit a supported task (curl examples + SDK)
    - what policies are available and what they constrain
    - how to verify a proof independently
    - how to consume the result in a Solidity contract
    - known limitations (latency, freshness, TLS coverage)
  - Commit as: docs(guide): add user-facing documentation for MVP release

Agent C: "Ship TypeScript SDK"
  - Create a TypeScript package (sdk/ or a separate repo reference)
  - Implements: submitTask(task, policy), pollJob(jobId), decodeResult(proof, publicInputs)
  - Includes type definitions for PublicInputs, OracleResult
  - Includes a README with usage examples
  - Commit as: feat(sdk): add TypeScript SDK for task submission, polling, and result decoding

Agent D: "Publish benchmark numbers and known limitations"
  - Compile the Phase 3 and Phase 5 benchmark data
  - Write docs/benchmarks.md with:
    - proof generation latency (2-source vs 5-source)
    - on-chain verification gas cost
    - token efficiency vs. LangChain (data already in README)
  - Include an explicit "out of scope for MVP" section listing: real-time use cases,
    non-attested sources, liveness guarantees, mainnet
  - Commit as: docs(benchmarks): publish MVP benchmark numbers and known limitations
```

### Step 6.2 — Sequential: partner onboarding

```
Agent({
  description: "Prepare partner onboarding materials",
  prompt: """
    Using the documentation and SDK from Step 6.1, prepare an onboarding package:
    - a short (1-page) technical brief for a DeFi protocol evaluating luai as an oracle
    - a step-by-step integration guide: from submitting a task to calling a verified result
      in their contract
    - a list of 3-5 questions to ask a prospective partner to determine fit
      (e.g. latency tolerance, data source requirements, on-chain budget)

    Place in docs/partner-onboarding/.
    Commit as: docs(partners): add partner onboarding materials for MVP launch
  """
})
```

### Phase 6 acceptance checklist

- [ ] Public testnet endpoint is live
- [ ] External user can submit a supported task and receive a verified result without hand-holding
- [ ] A consuming contract can verify and use the result
- [ ] TypeScript SDK is published
- [ ] Benchmark numbers and known limitations are public
- [ ] At least one external integration runs on testnet under the intended policy model
- [ ] `cargo test` passes

---

## Dependency graph summary

```
Phase 1 ─────────────────────────────────────────────────┐
  1.1 audit (sequential)                                  │
    └─ 1.2 P-256 + CA pinning (parallel A+B)              │
         └─ 1.3 test + docs (parallel A+B)                │
                                                          │
Phase 2 ─────────────────────────────────────────────────┤
  2.1 OraclePolicy design (sequential)                    │
    └─ 2.2 policy type + canon serialization (parallel)   │
         └─ 2.3 allowlisting + schema validation (parallel)│
              └─ 2.4 profiles + docs (parallel)           │
                                                          │
Phase 3 ─────────────────────────────────────────────────┤
  3.1 finalize PublicInputs (sequential)                  │
    └─ 3.2 verifier lib + Solidity contract (parallel)    │
         └─ 3.3 deploy + benchmark (sequential)           │
              ↓ GATE: gas/proof size must pass threshold  │
                                                          │
Phase 4 ─────────────────────────────────────────────────┤
  4.1 template + sources + schema (parallel A+B+C)        │
    └─ 4.2 prompt-to-template extraction (sequential)     │
         └─ 4.3 end-to-end example (sequential)           │
                                                          │
Phase 5 ─────────────────────────────────────────────────┤
  5.1 fuzzing + adversarial + calibration (parallel A+B+C)│
    └─ 5.2 observability + service + packaging (parallel) │
         └─ 5.3 threat model doc (sequential)             │
                                                          │
Phase 6 ─────────────────────────────────────────────────┘
  6.1 deploy + docs + SDK + benchmarks (parallel A+B+C+D)
    └─ 6.2 partner onboarding (sequential)
```

Each phase is a hard gate. Do not start the next phase until all acceptance criteria in the current phase are checked off.
