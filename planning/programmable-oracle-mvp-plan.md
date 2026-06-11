# proveno — MVP Roadmap

**Status:** Draft Revision
**Created:** 2026-03-26
**Revised:** 2026-04-01
**Based on:** `programmable-oracle-mvp-rev5.md`
**Purpose:** Define a clear path to MVP with explicit objectives, scope boundaries, and acceptance criteria.

---

## MVP Definition

The MVP is not "general-purpose verifiable agents."

The MVP is:

> A constrained programmable oracle that accepts a plain-English task within an approved policy, fetches real HTTPS data from approved sources, executes a deterministic computation, produces a proof with data provenance, and verifies that proof on-chain.

For MVP, proveno only needs to be good at one narrow but real category of jobs:

- multi-source HTTPS data fetch
- deterministic JSON extraction/transformation
- arithmetic aggregation and threshold checks
- fixed, contract-consumable outputs

Examples:

- average two or more price feeds if they agree within a bound
- aggregate gas metrics from approved APIs
- compute a bounded score from approved API fields

Everything in this roadmap should serve that outcome.

---

## Why This Is a Strong Product

The core claim is: **cryptographic proof that a specific computation ran on specific data from specific sources under a specific policy, with no trust required in the operator.**

### The Competitive Landscape

Every existing oracle approach requires trusting some party or mechanism:

- **Centralised oracles (Chainlink, etc.):** economic and reputational security — staking, multi-sig, committee honesty. The network can be bribed, coerced, or compromised. If a bad price settles a liquidation, the slash happens after the fact.
- **TEE-based oracles (Pyth, TLS Notary):** hardware-level trust. You are trusting that Intel or AMD manufactured the enclave correctly and that the firmware was not compromised. Attestation proves code ran in a TEE; it does not prove the TEE is trustworthy.
- **Optimistic oracles (UMA):** correct results are assumed unless challenged within a window. Fast, but requires the liveness of honest disputers and introduces settlement delay.
- **Custom multisig:** pure economic and reputational security over N-of-M signers.

### What proveno Offers That None of These Do

**1. The transformation logic is part of the commitment.**
Not just "what is the price" but "what is the output of this exact program on this exact data." The on-chain consumer can read the Lua source, audit it, and pin their contract to a `policy_hash` that commits to that logic. No other oracle product makes the computation itself a first-class, verifiable artifact.

**2. Policy enforcement is cryptographic, not reputational.**
A contract that enforces `policy_hash == 0xABC...` rejects any proof that does not match — including proofs from a compromised executor, a malicious proveno deployment, or a future version of the policy. The protocol does not have to trust proveno as an ongoing operator. They trust the math.

**3. Programmability without surrendering verifiability.**
Existing oracles offer either a fixed feed (Chainlink price feed) or a flexible but unverified computation. proveno's claim is: you get custom aggregation logic — average N sources, check deviation bounds, apply normalization — with the same proof-backed guarantees as a fixed feed.

**4. Data provenance alongside computation.**
TLS attestation — where supported — binds the data to its source at the transport level. You are not just proving the computation was correct on claimed data; you are proving the data came from the claimed server. No other programmable oracle does this.

### The Strongest Version of the Value Proposition

A DeFi protocol can encode "I will only accept results computed by this logic, from these sources, under this policy" directly in a smart contract. No party in the system — not the executor, not proveno, not a compromised API key holder — can produce a valid proof that passes the check without actually satisfying all of those conditions. That is a qualitatively different trust model from anything else in the space.

### Honest Constraints

The USP is strongest for use cases that can tolerate proving latency. For real-time liquidation pricing requiring sub-minute freshness, the current approach is weaker. For settlement, periodic rebalancing, and threshold checks with a tolerance window, it is potentially the strongest verifiable option available.

Proof generation speed and on-chain verification cost are the two gates that determine whether this USP translates into a shippable product. Both are treated as explicit MVP gates in this roadmap.

---

## Where the Trust Model Can Break

The product's guarantee rests on a chain of properties, each of which can fail independently. This section names each failure mode honestly, categorises how completely it can be addressed, and proposes a mitigation approach.

Failure modes fall into three categories:

- **Fully addressable** — solvable with engineering effort
- **Substantially mitigated but not eliminated** — meaningful residual risk remains after mitigation
- **Not fully addressable without architectural change** — hard limits that define the product's boundaries rather than problems to be solved at MVP

---

### Fully Addressable

---

#### 1. Task-to-Template Mapping Fails

**The failure:** The LLM generates Lua that looks correct and passes policy checks but does something subtly different from the intended task — uses one source instead of two, applies the wrong aggregation, omits a deviation check. The proof is valid but the computation is wrong.

**Why it matters:** This is the most operationally likely failure mode for the MVP. The entire product surface is built on the assumption that natural language reliably maps to the intended template profile. If that mapping is brittle, the product is brittle.

**Mitigation:** Invert the generation model for template-backed profiles. Instead of free-form LLM synthesis followed by policy validation, use the LLM only to extract bounded parameters from the task description (which sources, which fields, what deviation threshold), then assemble the Lua from a fixed template with those parameters substituted in. The generated program is structurally identical to the template — policy compliance is structural rather than semantic. Free-form synthesis remains off the template path entirely. This is solvable structurally; the LLM stops writing code and only fills slots.

---

#### 2. Weak Policy Model

**The failure:** The `policy_hash` commits to a policy document, but the policy is underspecified or over-permissive. A policy that says "approved domains only" but has a broad allowlist, or that permits fallback sources without constraint, gives on-chain consumers a false sense of what they are committing to.

**Why it matters:** The policy hash is the on-chain trust anchor. If two policies with different semantics can produce indistinguishable proofs — or if a policy can be satisfied by executions the protocol never intended to allow — the `policy_hash` enforcement is hollow.

**Mitigation:** Define policies as explicit, machine-checkable specifications rather than prose constraints. The policy checker is a deterministic function over the compiled bytecode: it verifies allowed opcodes, the specific set of permitted tool calls, the domain allowlist, maximum tool call count, and required output schema. A policy passes only if every structural constraint is satisfied — not if it passes a prompt-level filter. Policies are versioned documents with a canonical hash. This is a pure engineering problem with no fundamental limit.

---

#### 7. On-Chain Verification Cost

**The failure:** zkVM proofs for general computation tend to be large. If verifying a proof costs more gas than a protocol can absorb in a transaction, no one integrates regardless of the trust model's quality.

**Why it matters:** On-chain verification cost is the load-bearing bridge between the off-chain proof system and actual protocol adoption. A proof that cannot be economically verified on-chain does not produce a usable oracle.

**Mitigation:** Phase 3 is a hard gate on this. Define explicit gas budget targets before Phase 3 begins — a maximum acceptable verification cost per proof for the MVP profile. If the numbers exceed the threshold, investigate recursive proof aggregation (wrapping the zkVM proof in a cheaper outer proof), proof compression, or alternative verification paths before proceeding. Do not invest in Phase 4 template and SDK work until Phase 3 numbers are within range. The Ethereum ecosystem is actively investing in cheaper verification paths; this is solvable with effort and time.

---

#### 8. Approved Source Schema Drift

**The failure:** An approved data source changes its JSON response schema. The extraction logic embedded in the template breaks silently or errors at runtime. Because the source domain is still approved, the policy check passes; the computation is simply wrong.

**Why it matters:** The approved source list is not static. Sources evolve. A product that requires manual intervention every time an API changes its schema has a growing operational burden.

**Mitigation:** Version extraction schemas explicitly as part of the policy document. Each approved source is associated with a named schema version specifying the expected field paths and types. When a source changes its schema, a new schema version is published and a new policy version is cut. Consumer contracts that pinned `policy_hash_v1` continue accepting proofs under the old schema; new proofs require `policy_hash_v2`. Schema validation at the host boundary — verifying the response matches the declared schema before passing it to the VM — catches drift at execution time. This is pure operational engineering; nothing about it is fundamentally hard.

---

### Substantially Mitigated but Not Eliminated

---

#### 3. TLS Attestation Gaps

**The failure:** A data source does not support P-256 or its certificate chain does not terminate in the pinned Mozilla roots. Attestation silently degrades: the proof generates but `tls_attestation_hash` is zero. If the policy permits unattested responses without restriction, an executor can serve fabricated data for those sources.

**Why it matters:** Data provenance is a core differentiator. A proof that does not attest the data source is not materially different from an optimistic oracle.

**Mitigation:** Remove silent fallback. Attestation tiers are explicit in the policy document: each source is classified as `required_attested`, `preferred_attested`, or `unattested_permitted`. If a source is `required_attested` and cannot be attested, execution fails — it does not silently succeed with a zero hash. For MVP, `template_price_feed_v1` requires all sources to be `required_attested`. The supported TLS configuration set can be expanded over time (more cipher suites, more CA roots).

**Residual risk:** The web is heterogeneous. There will always be useful sources that cannot be attested under any realistic TLS support envelope. The mitigation makes the distinction explicit and policy-enforced; it does not make every source attestable. Protocols must accept that some sources are permanently out of reach for this trust model.

---

#### 4. Response Freshness and Replay

**The failure:** TLS attestation proves what a server returned but not when. An executor can capture a genuine TLS session, store the response, and replay it later to satisfy a new proof request. A stale price that passes all policy checks is a meaningful attack on any time-sensitive use case.

**Why it matters:** A protocol verifying a proof is trusting that the data was fresh at the time of execution. If replay is possible, freshness is an assumption rather than a guarantee.

**Mitigation:** Include a caller-supplied nonce or recent block hash in the VM input, committed to via `input_hash` in the public inputs. A consuming contract enforces that the input timestamp falls within an acceptable recency window before accepting the proof. This makes replaying an old oracle response detectable: the old proof commits to a stale `input_hash` that the contract rejects.

**Residual risk:** This approach proves the request was made *after* a known point; it does not prove the response was received immediately rather than hours later. TLS itself does not commit to wall-clock time in a zkVM-verifiable way. Proving tight freshness bounds — that the response arrived within seconds of the request — would require either trusting the executor's clock or a more complex protocol that captures the TLS connection timestamp inside the proof. That is a deep cryptographic challenge beyond the current design. For use cases where minutes of tolerance are acceptable, the nonce approach is sufficient. For use cases requiring sub-minute freshness guarantees, this residual risk is real and should be documented as a known limitation.

---

### Not Fully Addressable Without Architectural Change

---

#### 5. Executor Censorship and Liveness

**The failure:** The executor is a trusted party for liveness. It can refuse to process tasks, go offline, or selectively execute only favourable inputs. It cannot forge results, but it can deny service. For protocols with settlement or liquidation dependencies, executor downtime is a serious operational risk.

**Why it matters:** A cryptographically sound oracle that is unavailable when needed is not an oracle. Liveness is a separate property from correctness, and cryptography alone cannot guarantee it.

**Mitigation:** Because execution is deterministic, any honest executor running the same program on the same inputs under the same policy produces an identical result. Design the public input structure and proof format so that any party can run the execution and submit a valid proof — the consumer contract does not care which executor produced it, only that `policy_hash` matches. For MVP, expose the executor implementation so that protocols can run their own. Document the liveness trust assumption explicitly: at MVP, liveness depends on at least one honest executor being willing and able to process requests.

**Hard limit:** Full liveness guarantees require a decentralised executor network with economic incentives — staking and slashing for non-responsiveness. That is a meaningful product and infrastructure commitment that is post-MVP. Cryptography cannot substitute for it. This failure mode defines a boundary of the MVP rather than a problem that can be engineered away within it. Protocols should understand they are trusting executor availability, not just proof correctness.

---

#### 6. Proof Generation Latency

**The failure:** ZK proving over general VM execution takes minutes. For use cases that require near-real-time data — liquidation pricing, time-sensitive settlement — a proof that is five minutes stale may be economically useless or actively dangerous.

**Why it matters:** If the proving pipeline is too slow for the target use cases, the product has no addressable market regardless of how strong the trust model is.

**Mitigation:** Treat proving latency as a first-class measurement from Phase 1. Establish baseline numbers for the MVP template profile before optimising anything else. Use the data to explicitly define the latency class the MVP targets — settlement and periodic checks with tolerance windows measured in minutes, not seconds. Document this constraint so that protocols self-select. Post-MVP, investigate proof parallelisation and hardware acceleration, but do not let latency optimisation delay the MVP.

**Hard limit:** There is a floor here that cannot be engineered away in any realistic near-term horizon. Current zkVM proving over general computation takes minutes. Hardware acceleration, parallelisation, and better proof systems will improve this incrementally, but sub-second proving for general VM execution over HTTPS data is not achievable with current technology. This permanently excludes real-time use cases. This is not a problem to be solved later — it is a permanent boundary that defines which use cases proveno serves. The honest response is accurate positioning: proveno is the right choice for use cases tolerant of minutes-scale latency, and the wrong choice for anything requiring real-time freshness. Overpromising on latency and letting protocols discover this constraint after integration would be damaging.

---

## Who This MVP Is For

The best early users are applications that need external data plus transparent transformation logic, but do not want to trust a centralized operator or build custom oracle infrastructure themselves.

### Price Aggregation

Applications likely to care:

- lending protocols needing guarded asset prices
- stablecoin protocols needing collateral pricing
- perpetuals and derivatives protocols needing settlement inputs
- treasury and rebalancing systems needing trusted reference prices

### Gas and Network Metric Aggregation

Applications likely to care:

- bridge protocols deciding when to relay or batch
- cross-chain routers choosing execution paths
- keeper and automation networks deciding when to trigger jobs
- wallets and smart account systems optimizing transaction timing

### Bounded Scoring

Applications likely to care:

- lending protocols using reputation or risk inputs
- anti-sybil, identity, and rewards systems
- on-chain insurance or risk platforms
- DAO tooling that needs verifiable eligibility or reputation scoring

For MVP, the clearest initial market is DeFi protocols that need custom price or metric aggregation. That use case is easier to govern, easier to explain, and closer to existing oracle budgets than broader scoring or agent-like applications.

---

## What Counts as MVP Success

proveno reaches MVP when all of the following are true:

1. A user can submit a supported oracle task in plain English.
2. The task is mapped to an approved policy or template profile.
3. The generated Lua is accepted only if it satisfies that policy.
4. The VM executes deterministically on real HTTPS data.
5. When a source uses a TLS configuration supported by proveno's attestation verifier, the proof includes cryptographic provenance for that response; unsupported TLS configurations are only acceptable under policies that explicitly allow unattested responses.
6. A proof commits to policy, program, input, data, and output.
7. A smart contract on testnet verifies the proof and enforces the expected `policy_hash`.
8. Another contract can consume the verified result without trusting the executor.

If any of those are missing, the product is not yet MVP.

---

## Scope Boundaries

These are explicitly out of scope for MVP unless they directly unblock the path above:

- general-purpose verifiable AI agents
- persistent multi-turn workflows
- broad custom tool ecosystems
- arbitrary side-effectful automation
- production mainnet rollout
- broad hosted platform features beyond what is needed for a testnet service

This roadmap optimizes for shipping one trustworthy oracle product, not a full platform.

---

## Current State

From the existing planning docs:

- Deterministic Lua VM: complete
- Parser/compiler/verifier/VM/host/tape/json stack: complete
- Transcript capture and replay: complete
- Orchestrator with LLM generation and retry loop: working
- OpenVM proving pipeline: working
- TLS attestation: structurally complete, but missing:
  - full P-256 verification
  - root CA pinning

This means the remaining work is mostly about:

- closing proof integrity gaps
- defining admissibility rules
- making verification externally reproducible
- narrowing product scope to one protocol-safe oracle profile

---

## MVP Principles

The roadmap should follow these principles:

### 1. Constrain Before Expanding

Do not widen tooling or product surface area until one oracle profile is trustworthy end-to-end.

### 2. Policy Is Part of the Product

The proof alone is not enough. The product must define what executions are admissible.

### 3. On-Chain Verification Is a Gate, Not a Future Nice-To-Have

If proof verification is too expensive or awkward on-chain, the oracle thesis is weakened. This has to be validated early.

### 4. Security Work Starts Before Service Exposure

Fuzzing, threat modeling, and policy enforcement cannot wait until after a hosted API exists.

### 5. Measure the MVP

Each phase must end with concrete acceptance criteria, not just activity completion.

---

## Target MVP Profile

The first shippable profile should be:

### `template_price_feed_v1`

Capabilities:

- fetch JSON from 2-5 approved HTTPS endpoints
- extract approved numeric fields
- normalize to fixed-point integers
- compute average / median / bounded deviation checks
- return a fixed output schema

Constraints:

- `http_get` only
- approved domains only
- fixed response schema per source
- fixed output schema
- bounded payload size and tool count
- no unconstrained fallback sources

This profile is narrow enough to govern and broad enough to matter.

If `template_price_feed_v1` works end-to-end, you have an MVP candidate.

---

## Roadmap

### Phase 1: Finish Proof Integrity

**Objective:** Make the proof pipeline cryptographically complete for real HTTPS-backed executions.

**Required work:**

- Implement full P-256 ECDSA verification in the zkVM verification path
- Implement Mozilla-root-based root CA pinning
- Add a live end-to-end HTTPS prove test with non-zero `tls_attestation_hash`
- Verify graceful handling of non-P256 servers
- Document exactly what TLS attestation proves and does not prove
- Keep workspace CI green for the full proof pipeline

**Acceptance criteria:**

- A real HTTPS task proves successfully end-to-end
- The proof contains a non-zero `tls_attestation_hash` for supported servers
- Unsupported TLS configurations degrade cleanly without invalid claims
- Third-party readers can understand the provenance trust model from the docs

**Exit condition:**

proveno can prove one real HTTPS-backed execution with cryptographically sound provenance.

---

### Phase 2: Define Admissibility and Reproducibility

**Objective:** Define what counts as an acceptable oracle execution and make commitments reproducible outside the codebase.

**Required work:**

- Introduce `OraclePolicy` as a first-class artifact
- Add `policy_hash` to the commitment/public-input structure
- Specify canonical serialization for:
  - policy documents
  - task inputs
  - tool responses
  - outputs
- Define domain allowlisting and HTTP restrictions
- Validate tool args and return schemas at the host boundary
- Define at least two execution profiles:
  - `constrained_http_v1`
  - `template_price_feed_v1`
- Publish verifier-facing hashing and replay documentation

**Acceptance criteria:**

- The same execution artifact yields the same hashes in an independent implementation
- A protocol can point to one policy document and say exactly what it allows
- Admissibility is machine-checkable, not implied by prompt wording

**Exit condition:**

proveno can distinguish between "correctly executed" and "policy-approved" executions.

---

### Phase 3: Validate On-Chain Viability

**Objective:** Prove that proveno results can be consumed by smart contracts under policy constraints.

**Required work:**

- Finalize public inputs including `policy_hash`
- Build a standalone verifier library
- Implement a Solidity verifier contract
- Build an example consumer contract that only accepts a specific `policy_hash`
- Deploy to testnet
- Measure proof size, gas cost, and verification latency
- Set explicit acceptance thresholds

**Acceptance criteria:**

- A testnet contract verifies a proveno proof successfully
- The contract rejects proofs with the wrong policy hash
- Gas and proof size are within a range you consider operationally usable

**Exit condition:**

proveno has a policy-enforced, on-chain-verifiable oracle path on testnet.

---

### Phase 4: Ship One Template-Backed Oracle

**Objective:** Turn the infrastructure into one productized oracle workflow.

**Required work:**

- Implement `template_price_feed_v1`
- Add prompt-to-template parameterization
- Define approved domains and extraction schemas for the initial sources
- Define a fixed output schema for downstream contracts
- Improve prompt and error handling so tasks reliably land in the template
- Publish one end-to-end example from natural language task to verified on-chain result

**Acceptance criteria:**

- A supported plain-English price feed task consistently resolves into the template profile
- Execution succeeds reliably across the approved sources
- The output schema is stable enough for another contract to consume

**Exit condition:**

proveno has one repeatable, protocol-safe oracle product, not just a toolkit.

---

### Phase 5: Harden for External Use

**Objective:** Reduce the risk of exposing the MVP to real external users on testnet.

**Required work:**

- Fuzz parser, compiler, verifier, VM, and host boundary
- Run adversarial tests for:
  - policy bypass
  - resource exhaustion
  - nondeterminism
  - malformed API responses
- Calibrate gas/resource costs for the MVP template profile
- Add metrics and structured logging
- Add authentication, rate limiting, and job status handling for a minimal hosted service
- Package the MVP in a deployment-friendly form
- Write threat model and trust-boundary docs

**Acceptance criteria:**

- No obvious policy-bypass or determinism regressions remain in core testing
- Hosted execution failures and rejections are observable and attributable
- Operators can deploy the MVP and understand its trust boundaries

**Exit condition:**

The MVP is safe enough to expose publicly on testnet with known limitations.

---

### Phase 6: MVP Release

**Objective:** Put the constrained oracle in front of early adopters.

**Required work:**

- Launch a public testnet deployment for the MVP profile
- Release documentation for:
  - submitting supported tasks
  - understanding policies
  - verifying proofs
  - consuming outputs on-chain
- Ship a TypeScript SDK for submission, polling, and decoding
- Publish benchmark numbers and known limitations
- Onboard 1-2 early design partners to use the template-backed oracle

**Acceptance criteria:**

- External users can submit supported tasks without hand-holding
- A consuming contract can verify and use the result
- At least one external integration runs on testnet under the intended policy model

**Exit condition:**

proveno is an MVP: a usable constrained programmable oracle with proof-backed, policy-bound outputs on testnet.

---

## Critical Decisions to Make Early

These should be resolved as early as possible because they affect the whole roadmap:

### 1. What Is the MVP Product Surface?

Recommendation:

- one template-backed profile first
- one constrained HTTP profile second
- free-form mode remains non-MVP

### 2. What Is the Policy Artifact Format?

Recommendation:

- make it explicit, hashable, versioned, and verifier-facing
- do not leave policy implicit in prompt text

### 3. What Are the On-Chain Acceptance Thresholds?

Recommendation:

- define target gas and proof size before over-investing in UX and SDK work

### 4. What Counts as Supported Data Provenance?

Recommendation:

- explicitly define the TLS/server classes the MVP supports
- define whether partial-attestation outputs are allowed by policy

---

## Risks to Manage

| Risk | Why it matters | Response |
|------|----------------|----------|
| Proving is too slow | Oracle latency becomes impractical | Benchmark early; accept that real-time use cases are out of scope |
| On-chain verification is too expensive | Contracts will not consume outputs | Treat gas/proof size as an MVP gate in Phase 3 |
| Free-form generation is too unreliable | Product feels brittle | Bias hard toward template-backed profiles for MVP |
| Policy model is too weak | Protocols cannot trust the product | Make policy hash and admissibility central, not optional |
| TLS coverage is incomplete | Many useful APIs may not be attestable | Narrow source support; document the residual risk clearly |
| Freshness guarantees are weaker than expected | Protocols discover replay risk after integration | Document the nonce mitigation and its limits upfront |
| Executor liveness is a single point of failure | Oracle unavailable when needed | Permissionless proof production; document liveness as a trust assumption at MVP |
| Scope creep into platform features | MVP slips without a shippable product | Enforce the scope boundaries above |

---

## Recommended Cuts

If time becomes constrained, cut these before cutting the MVP path:

- broad custom tool SDK work
- persistence and multi-turn orchestration
- multiple template families
- polished hosted platform features beyond a minimal testnet service
- broad marketing/site work

Do not cut:

- proof integrity
- policy/admissibility
- on-chain verification
- one complete template-backed oracle profile
- hardening needed for public testnet exposure

---

## Short Version

The path to MVP is:

1. Finish the proof pipeline.
2. Define policy and reproducible commitments.
3. Prove on-chain viability.
4. Ship one constrained template-backed oracle.
5. Harden it enough for public testnet use.
6. Release it to early adopters.

That is the smallest roadmap that still produces a credible MVP.
