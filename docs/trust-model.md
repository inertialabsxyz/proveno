# Trust Model

Salvaged from the MVP roadmap that framed proveno as a programmable oracle.
That framing is superseded (see [architecture](architecture.md)), but these
failure modes are not: they are properties of the guarantee itself. Some
mitigations still speak of templates and profiles, which were an oracle-
specific idea; read those as one possible mitigation rather than the plan.


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

