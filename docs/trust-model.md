# Trust model

Where the guarantee can break. This document names each failure mode, says what
the code does about it today, how it could be mitigated, and what risk remains
after that. It is subordinate to the [architecture document](architecture.md):
where the two disagree, this one is wrong.

Status reflects the code as of 2026-09-17. References are repository-relative
paths into the four code repositories.

## 0. How to read this

### What is guaranteed, and what is not

A proof guarantees **execution integrity over the inputs it was given**: this
program, run by the proveno interpreter over this input and this tape of tool
responses, produced this output. It does not guarantee **provenance**, that the
tape holds authentic data from the real source. Proveno binds attestation blobs
into the proof; it does not authenticate them. See
[The boundary that matters](architecture.md#the-boundary-that-matters).

Even the execution guarantee holds only on OpenVM today. The Noir backend is in
development and its proofs do not attest to results.

### Who you are trusting

| Party | Trusted for |
|---|---|
| Executor (the prover) | Liveness, which responses it fetched, which calls it let fail, the VM limits it chose. On Noir, everything. |
| Attestation provider | Authenticity of each response. No provider is working today. |
| Gateway operator | Every gateway guarantee, because no gateway run is proved and the trace is signed with the operator's own key. |
| Downstream MCP servers | Their responses and the provenance they report about them. |
| The model | That the program it wrote does what the task asked. |
| Verifier deployer and integrator | That the consumer checks the right public inputs against the right scheme and verification key. |
| Proof system | Soundness of OpenVM, and for Noir, of UltraHonk and its BN254 universal setup. |

### Backend matrix

What each path binds today.

| | OpenVM proof (canonical) | Noir proof (in development) | Gateway signed trace (no proof) |
|---|---|---|---|
| Program | SHA-256 program hash, covers constants and metadata | Poseidon2 hash of opcodes and operands only, not constants | SHA-256 program hash, signed |
| Computation | Re-executed in the guest | **Not constrained** | Replayable, operator-signed |
| Input | `input_hash`, derived in the guest | `input_hash` unconstrained | Signed |
| Tool responses | `tool_responses_hash` over the tape | Hash checked in-circuit, but not linked to the computation | Signed transcript |
| Attestations | Bound, not authenticated | Only a 32-byte leaf per call is bound | Downstream reports bound, unverified |
| Output | Integer only (other types prove as `0`) | Integer, but not tied to the computation | Full output, signed |
| Execution policy | Enforced in the guest for HTTP tools | `policy_hash` unconstrained, nothing enforced | Gateway policy applied; decisions signed, not re-checked on replay |
| `VmConfig` | Not bound | Not bound | In the signed header |
| Verifier | Off-chain only; no on-chain verifier | Solidity contracts exist; do not rely on them | Replay with the operator's signing key |

### Categories

Each failure mode is tagged with one of three categories:

- **[F] Fully addressable.** Solvable with engineering effort.
- **[S] Substantially mitigated, not eliminated.** Meaningful risk remains after
  mitigation.
- **[A] Not addressable without architectural change.** A boundary of the
  product rather than a bug to fix.

Each entry gives the failure, its status in code, a mitigation, and the residual
risk. "Open" means no mitigation is implemented yet.

### Measurements

Every performance figure quotes its machine and date. Figures without them must
not be quoted.

## 1. Execution guarantee (ZK)

### 1.1 [F] The Noir circuit does not constrain computation

**Failure.** A Noir proof can carry a return value the program did not produce.

**Status.** Open, and demonstrated on 2026-09-17: a proof of a false return
value verified with the pinned verification key and was accepted by the
verifier and consumer contracts in a test environment. The circuit
(`proveno-zk/noir/src/main.nr`) checks that each trace step's opcode and operand
match the committed bytecode and that the program counter follows the jump
rules. Stack values are free witnesses: they drive branches and supply the
return value, and arithmetic, builtins and tool responses are never re-derived.
The return value is not required to come from a final `Ret`, and the program
counter is unconstrained after calls and returns. The existing tamper test
(`proveno-zk/proveno-noir/tests/prove.rs`) changes only the return value, so it
does not catch a consistent forgery.

**Mitigation.** OpenVM is the canonical backend. Noir is labelled in development,
and nothing should act on a Noir proof. A Noir circuit that re-executes the
interpreter is possible future work.

**Residual risk.** The Solidity verifier is immutable
(`proveno-zk/contracts/src/ProvenoVerifier.sol`), so any deployment made from
the current contracts keeps accepting such proofs until consumers move off it.

### 1.2 [F] Noir `input_hash` and `policy_hash` are unconstrained

**Failure.** A Noir proof can name any input and any policy.

**Status.** Open. Both are declared public inputs in
`proveno-zk/noir/src/main.nr` and never referenced in the circuit body. The Noir
driver copies `policy_hash` from the dry run's output and replays without a
policy host (`proveno-zk/proveno-noir/src/lib.rs`). "A run that violates the
policy cannot be proved" holds on OpenVM only.

**Mitigation.** Derive both in-circuit, or drop them from the Noir public inputs.

**Residual risk.** None once fixed, beyond 1.1.

### 1.3 [F] The Poseidon2 program hash omits constants

**Failure.** Two programs that differ only in literals (or prototype metadata and
upvalues) share a Poseidon2 `program_hash`.

**Status.** Open, Noir only. `compute_program_hash` in
`proveno-core/src/compiler/program_hash.rs` hashes the `(opcode, operand)` stream.
The SHA-256 hash used by OpenVM and the gateway covers the constant pool,
upvalue descriptors and prototype metadata. Not pinned by a test. Moot while 1.1
is open.

**Mitigation.** Extend the circuit's bytecode assertion to cover the constant
pool and regenerate the verification key.

**Residual risk.** Verification key migration (see 1.10).

### 1.4 [F] `VmConfig` is unbound, and quota errors are catchable

**Failure.** The prover chooses gas, memory, call depth and tool-call quotas.
Those decide whether a run completes, and because quota failures surface as
ordinary runtime errors (`proveno-core/src/host/tool_registry.rs`,
`proveno-core/src/vm/gas.rs`), `pcall` can catch them. A prover can make a chosen
call fail and steer the program into its fallback branch while still producing a
valid proof.

**Status.** Open. The OpenVM host passes the config into the guest
(`proveno-zk/src/zkvm/guest_input.rs`) without committing it. The gateway records
it in its signed trace header, which binds it to the operator's signature, not
to a proof.

**Mitigation.** Commit the config in the public inputs, or make quota errors
uncatchable.

**Residual risk.** None once fixed.

### 1.5 [S] Selective failure through fabricated error responses

**Failure.** An error is a legitimate tape entry and carries no attestation
(`proveno-core/src/host/tape.rs`). An executor can report any source as failed,
and the program's fallback path is then proved faithfully.

**Status.** Open. Provenance cannot cover the absence of a response.

**Mitigation.** A policy option to fail closed on tool errors, and consumers that
reject runs in which a required call errored.

**Residual risk.** An executor can always withhold a response; the best outcome is
that withholding yields no proof rather than a different result.

### 1.6 [F] Unconsumed tape entries are accepted; requests are unbound

**Failure.** On OpenVM, extra responses the program never read can be folded into
`tool_responses_hash` and `attestation_hash`. Tool-call requests (name and
arguments) are excluded from every commitment by design, so a response is not
tied to the request that produced it.

**Status.** Open. Replay in `proveno-zk/src/zkvm/guest_input.rs` does not check
that the tape was fully consumed; request exclusion is in
`proveno-core/src/host/tape.rs`.

**Mitigation.** Require tape exhaustion in the guest. Commit requests, or require
attestations that name the request.

**Residual risk.** None for exhaustion. Request binding depends on provider
formats.

### 1.7 [F] The output binds only an integer

**Failure.** Tables, strings and booleans prove as `0` on both backends
(`proveno-zk/src/zkvm/commitment.rs`). A consumer cannot tell a real `0` from a
non-integer result.

**Status.** Open.

**Mitigation.** Commit canonical output bytes.

**Residual risk.** Consumers must decode the output with the right schema.

### 1.8 [F] Noir circuit bounds and silent truncation

**Failure.** The Noir circuit has fixed ceilings on bytecode, steps, tool calls
and tape entry size (`proveno-zk/noir/src/main.nr`). Oversized bytecode or step
counts fail loudly, but the witness writer (`proveno-zk/proveno-noir/src/witness.rs`)
silently truncates tape entries and the call count while hashing the full tape,
so the proof simply cannot be produced. The entry ceiling is 1 KB; real API
responses measured for the benchmarks ranged from 1.4 KB to 57 KB.

**Status.** Open. A liveness failure, not a soundness one.

**Mitigation.** Fail loudly in the witness writer and publish per-profile bounds.
OpenVM has no padded ceiling: cost tracks the instructions executed.

**Residual risk.** Each Noir profile is its own circuit, verification key and
deployed verifier.

### 1.9 [F] OpenVM verification is incomplete

**Failure.** A verifier cannot yet check an OpenVM proof end to end against a
known guest.

**Status.** Open.

- The guest reveals one SHA-256 digest of the six commitments
  (`proveno-zk/proveno-openvm/src/main.rs`). The host driver
  (`proveno-zk/proveno-openvm-host/src/main.rs`) runs OpenVM's verifier but only
  prints the expected digest; nothing compares it.
- The app proving and verification keys and the executable commitment are not
  committed or pinned, so there is no canonical guest identity to check against.
- There is no EVM-level proof and no on-chain verifier.
- `proveno-verifier` (`proveno-zk/verifier/src/lib.rs`) checks an integrity
  envelope and a policy-hash match, not a proof, and can build a "valid" envelope
  for any public inputs. proveno-agent depends on it.

**Mitigation.** Compare the digest in the verification step, pin the app
verification key and executable commitment, replace or remove
`proveno-verifier`, and add an EVM wrapper with an on-chain verifier.

**Residual risk.** Trust in the OpenVM proof system and its release process.

### 1.10 [S] Setup and verification key lifecycle

**Failure.** A verifier is only as sound as its setup and its key, and a fix to
the circuit or guest does not reach consumers still pointing at the old one.

**Status.** Undocumented until now. UltraHonk relies on the BN254 universal
reference string that the Barretenberg tooling downloads. The Noir verification
key is embedded in `proveno-zk/contracts/src/HonkVerifier.sol` and must be
regenerated in lockstep with the circuit, and `ProvenoVerifier` is immutable.
OpenVM keys are not pinned (1.9).

**Mitigation.** Document the setup assumption, pin keys in source control, and
define a redeploy and migration procedure with a scheme or version identifier
consumers can check.

**Residual risk.** Soundness of the universal setup and of the upstream provers.

### 1.11 [F] Mixing the two commitment schemes

**Failure.** `program_hash`, `tool_responses_hash` and `attestation_hash` are
SHA-256 on OpenVM and in the gateway, Poseidon2 on Noir. Nothing in the public
inputs names the scheme (`proveno-zk/src/zkvm/commitment.rs`,
`proveno-zk/contracts/src/Types.sol`), and the OpenVM digest orders fields
differently from the Noir public inputs. For an empty tape,
`tool_responses_hash` equals `attestation_hash`.

**Status.** Open. Mismatches fail closed, but a consumer has to know which scheme
applies.

**Mitigation.** Add a scheme or version tag to the public inputs.

**Residual risk.** None once fixed.

### 1.12 [F] Determinism edge cases

**Failure.** Small gaps at the edges of canonical encoding.

**Status.** Open.

- `hash_input` falls back to the hash of `"null"` when an input cannot be
  serialised, which can collide with a genuine `nil` input
  (`proveno-zk/src/zkvm/commitment.rs`).
- A tool response that cannot be canonicalised leaves a known replay gap
  (`proveno-core/src/host/tool_registry.rs`).
- Canonical serialisation has a size cap; values beyond it fall back or error
  (`proveno-core/src/host/canonicalize.rs`).

**Mitigation.** Fail instead of falling back, and document the cap.

**Residual risk.** None once fixed.

## 2. Attestation and provenance

### 2.1 [A] Bind, not authenticate

**Failure.** A proof can bind a forged or irrelevant attestation blob as easily as
a genuine one.

**Status.** By design. A provider plugs in at `HostInterface::take_attestation`
and yields opaque bytes. The runtime hashes them into `attestation_hash` next to
the response bytes they cover (`proveno-core/src/host/tape.rs`), and nothing in
the runtime, the guest or the circuit interprets them. On Noir only a 32-byte
leaf per call is bound, not the blob. The binding covers the response, not the
request (1.6): a genuine blob for a different URL binds equally well unless the
blob names the request.

**Mitigation.** Provenance is delegated. Pluggable providers are roadmap work:
signed data feeds, zkTLS and notarisation networks, each verified off-chain by a
consumer that trusts that provider.

**Residual risk.** A result is only as trustworthy as the weakest provenance on
its tape, and some useful sources will never be attestable.

### 2.2 [S] No provider works today, and the TLS code does not authenticate responses

**Failure.** Readers may assume the TLS code in proveno-agent attests what a server
returned. It does not.

**Status.** Open.

- The blob holds the hostname, the DER certificate chain, a validity date and a
  self-asserted verification flag (`proveno-agent/src/tls/mod.rs`). The response
  body is not bound. Certificate chains are public, so any executor can attach a
  genuine chain to fabricated data.
- Chain verification (`proveno-agent/src/tls/verify.rs`) does not check
  basicConstraints, key usage or validity dates.
- The re-verification function has no caller, and no host calls the provider.
- `proveno-agent/docs/tls-attestation.md` describes in-guest re-verification
  that does not exist.

**Mitigation.** Treat the TLS code as certificate capture only. Replace it with a
response-authenticating provider, correct its documentation, and add the missing
certificate checks if it is kept.

**Residual risk.** Sources with no response-authenticating provider.

### 2.3 [F] Attestation tiers are not enforced

**Failure.** A policy can require attested responses, and an unattested response
is still accepted.

**Status.** Open. The execution policy's `tls_requirement`
(`RequiredAttested`, `PreferredAttested`, `UnattestedPermitted`) is parsed and
committed in `policy_hash` but never acted on
(`proveno-zk/src/policy/canonical.rs`, `proveno-zk/src/zkvm/guest_input.rs`).

**Mitigation.** Enforce "a blob must be present" in the guest. Verifying the blob
remains the consumer's job.

**Residual risk.** A present blob is not an authentic one (2.1).

### 2.4 [S] Response freshness and replay

**Failure.** Nothing shows when a response was fetched. An executor can reuse old
responses, and a consumer can be handed the same proof twice.

**Status.** Open. There is no nonce, block hash, recency window or timestamp
check anywhere. The drivers run programs with a `nil` input. No contract reads
`inputHash`, and `ProvenoConsumer.consumeResult` accepts the same proof
repeatedly. The `time_now` tool returns the executor's clock, unattested
(`proveno-agent/proveno-orchestrator/src/tools.rs`).

**Mitigation.** Carry a caller nonce or recent block hash in the input, check
`inputHash` and a recency window in the consumer, record consumed proofs, and use
provider timestamps where a provider offers them.

**Residual risk.** A nonce shows the run happened after a known point, not that
the response arrived promptly. Tight freshness needs timestamps from the
provider.

### 2.5 [F] Consumer obligations for attestations are unstated

**Failure.** `attestation_hash` is useless unless the consumer does the work
around it, and nothing says what that work is.

**Status.** Open, no tooling. To rely on it, a consumer needs the full tape and
blobs, must recompute the commitment with the prover's scheme, verify each blob
with provider-specific logic, and check that each blob covers the request the
program actually made. None of this can happen on-chain, because blobs never go
on-chain.

**Mitigation.** A specification and off-chain tooling for these checks.

**Residual risk.** Attestations cannot be checked on-chain in this design.

### 2.6 [S] Gateway provenance tags are self-reported

**Failure.** A downstream MCP server can claim a response is `signed`, `onchain`
or `notarized` when it is not.

**Status.** By design today. The gateway checks only the shape of the reported
object (`proveno-gateway/src/downstream.rs`) and binds it. A failed call is always
recorded as `unsigned` (`proveno-gateway/src/host.rs`).

**Mitigation.** Verify the tags, or label them as unverified wherever they are
reported.

**Residual risk.** Trust in the operator and each downstream.

## 3. Policy

Two separate policies exist. The **execution policy** (`OraclePolicy`,
`proveno-zk/src/policy/`) is hashed into `policy_hash` and constrains HTTP tool
calls. The **gateway policy** (`proveno-gateway/src/policy.rs`) decides which
tools a principal may call and caps integer arguments. Neither is a checker over
compiled bytecode.

### 3.1 [F] Execution policy scope differs by tool and by backend

**Failure.** A consumer checking `policy_hash` may believe more is enforced than
is.

**Status.** Partial.

- Enforced in the OpenVM guest: HTTP method, domain allowlist, `max_tool_calls`
  and per-call payload size (`proveno-zk/src/policy/guest.rs`,
  `proveno-zk/src/zkvm/guest_input.rs`).
- Only `http_get` and `http_post` are policy-checked. Other tools, such as
  `llm_query`, `time_now` and key-value tools, pass through, bounded only by
  `max_tool_calls`.
- On Noir, nothing is enforced (1.2).

**Mitigation.** Extend the policy beyond HTTP tools and enforce it on every
proving path.

**Residual risk.** The expressiveness of the policy language.

### 3.2 [F] Domain extraction and redirects

**Failure.** The allowlist checks a domain extracted from the requested URL, which
may not be the host the data came from.

**Status.** Open. `extract_domain` (`proveno-zk/src/policy/canonical.rs`) is a
string split rather than a URL parser, so it can disagree with the HTTP client
about the host for unusual URLs. The HTTP clients follow redirects, and the
allowlist never sees the final host.

**Mitigation.** A standards-compliant URL parser shared with the client, and
clients that do not follow redirects.

**Residual risk.** DNS-level indirection.

### 3.3 [F] Output schema and source schema drift

**Failure.** A source changes its response shape, or a program returns a shape the
policy did not allow, and the proof still verifies.

**Status.** `required_output_schema` and `schema_versions` are both committed in
`policy_hash` but neither is enforced in any proof. `schema_versions` is checked
host-side only by `OraclePolicyHost` (`proveno-zk/src/policy/host.rs`), as a shallow
match on key presence and JSON type, keyed by domain. `required_output_schema` is
enforced nowhere. The built-in profiles leave both empty
(`proveno-zk/src/policy/profiles.rs`). A malicious host skips the host-side check
and the proof still verifies.

**Mitigation.** Enforce bounded schema checks in the guest, or remove the fields
from the hash. Version schemas explicitly.

**Residual risk.** Operational churn when sources change.

### 3.4 [F] Sparse or mismatched policy inputs

**Failure.** An empty list means unrestricted, so a sparse policy is wider, not
narrower. The policy is passed to the dry run and to the prover separately, so a
mismatch produces a proof naming a policy the dry run did not use.

**Status.** Open (`proveno-zk/src/policy/mod.rs`,
`proveno-zk/proveno-openvm-host/src/main.rs`).

**Mitigation.** One source of truth for the policy across dry run and proof, and a
deny-by-default option.

**Residual risk.** None once fixed.

### 3.5 [S] Gateway policy is stateless and per call

**Failure.** Limits apply to single calls, not to a run.

**Status.** Open. The session state passed to the policy is empty. An
`<arg>_max` bound caps one call, so repeated small calls reach any total up to
the run's tool-call quota. Negative integers pass an upper bound. The rules file
is referenced by `gateway_policy_hash` in the trace
(`proveno-gateway/src/trace.rs`) but is not stored with it
(`proveno-gateway/src/store.rs`).

**Mitigation.** Session state and cumulative caps (the spec already reserves the
hook), lower bounds, and storing the rules file beside the trace.

**Residual risk.** The expressiveness of the policy language.

### 3.6 [S] Credential injection

**Failure.** A credential leaks through the program or the trace.

**Status.** Mitigated for the program. Configuration names an environment
variable, never the secret (`proveno-gateway/src/config.rs`). The gateway attaches
it as that variable for a stdio downstream, which otherwise inherits only `PATH`
and `HOME`, or as a bearer token for an HTTP downstream
(`proveno-gateway/src/downstream.rs`). The program never sees it. A downstream
that echoes the credential in its response would put it into the transcript and
the stored trace.

**Mitigation.** Redact known credentials from responses before they are recorded.

**Residual risk.** Downstream behaviour the gateway cannot observe.

## 4. Signed trace and replay (gateway)

### 4.1 [S] The signature is operator self-attestation

**Failure.** The operator can sign a trace containing fabricated responses.
Replay proves internal consistency, not truth.

**Status.** The trace is signed with Ed25519 over the SHA-256 of its JSON, using
the gateway's own key (`proveno-gateway/src/trace.rs`). Replay derives the
verifying key from the secret signing seed (`proveno-gateway/src/replay.rs`).
There is no public-key-only verification path, no key identifier and no
rotation. No proof is generated on the gateway path, so every gateway guarantee
rests on trusting the operator.

**Mitigation.** Publish the public key and verify with it alone; add key ids and
rotation. Prove gateway runs on OpenVM: the trace already commits the SHA-256
program hash and the tape an OpenVM proof would consume.

**Residual risk.** Until runs are proved, the operator is trusted. After, the
operator is still trusted for which responses it fetched (1.5, 2.1).

### 4.2 [F] Replay does not re-check policy decisions or the VM version

**Failure.** A trace that marks a denied call as allowed still replays as a match.

**Status.** Open. Replay compares output, status kind, gas, memory and divergence
(`proveno-gateway/src/replay.rs`). It does not re-evaluate policy decisions,
compare error messages or check `vm_version`.

**Mitigation.** Re-run the policy during replay against the stored rules file
(3.5), and check the VM version.

**Residual risk.** None once fixed.

### 4.3 [S] Traces can be omitted

**Failure.** An operator can drop traces, and a store failure after a run leaves
tool calls with no trace.

**Status.** Open. Traces are write-once files with no chaining
(`proveno-gateway/src/store.rs`, `proveno-gateway/src/engine.rs`).

**Mitigation.** Hash-chain the store or publish to a transparency log.

**Residual risk.** Runs withheld before they start leave nothing to detect.

## 5. Task and program

### 5.1 [A] The proof binds the program, not the intent

**Failure.** The model writes a program that looks right, passes policy and does
something other than the task asked: one source instead of two, the wrong
aggregation, a missing check. The proof is valid and the result is wrong.

**Status.** No proof commits to the natural-language task. In proveno-agent the
stored program is the only human-readable record
(`proveno-agent/proveno-orchestrator/src/prove.rs`). In the gateway, `request` is
optional free text from the caller, and `description_hash` binds what the model
was told about the tools, not the task (`proveno-gateway/src/engine.rs`). The
only structural binding is a requester committing a `programHash` in advance
(`proveno-zk/contracts/src/Bounty.sol`), which targets the Noir scheme.

**Mitigation.** Requesters commit to a reviewed program hash. Humans review the
stored program and request. The gateway's typed prelude narrows what a program
can call.

**Residual risk.** The model's semantic errors, whenever no one reviews the
program.

### 5.2 [S] Unattested model sub-queries

**Failure.** A program can call `llm_query`, whose output flows into the result
unattested (`proveno-agent/proveno-orchestrator/src/tools.rs`).

**Status.** Allowed, and not covered by the execution policy (3.1).

**Mitigation.** A policy option to forbid it.

**Residual risk.** Tasks that inherently need a model in the loop.

## 6. Consumer integration

### 6.1 [F] The contracts check too little

**Failure.** Even with a sound proof, the consumer contracts would accept results
they should not.

**Status.** Open. The contracts target Noir (1.1).

- `ProvenoVerifier` checks only `policyHash` before calling the proof verifier.
- `ProvenoConsumer` checks the output payload hash, but not `programHash`,
  `inputHash` or the step count, so any program meeting the policy can set its
  result.
- There is no nonce, chain id or nullifier, so a proof can be replayed.
- `Bounty.claim` does not bind the proof to the claimant, so a pending claim can
  be front-run with the same proof.
- One expected policy hash covers every bounty.

**Mitigation.** Check `programHash`, `inputHash` and a nonce; bind claims to the
sender; set policy per bounty. Carry these into the OpenVM on-chain verifier when
it exists.

**Residual risk.** Integrator mistakes.

### 6.2 [F] Stale documents mislead integrators

**Failure.** Documents in the code repositories still describe guarantees that do
not hold.

**Status.** Open.

- `proveno-zk/contracts/README.md` documents a multi-field output payload and a
  `tlsAttestationHash` field that no longer exist.
- `proveno-zk/docs/phase3-benchmarks.md` reports on-chain gas for a stub
  verifier and an estimate for a Groth16 path that no longer exists.
- `proveno-zk/README.md` states that a policy-violating run cannot be proved,
  which holds on OpenVM only; `proveno-zk/CLAUDE.md` says the output schema is
  checked host-side.
- `proveno-agent/docs/tls-attestation.md` describes in-guest re-verification.

**Mitigation.** Correct or remove them. See the appendix.

**Residual risk.** None once fixed.

## 7. Operational limits

### 7.1 [A] Executor liveness and censorship

**Failure.** The executor can refuse tasks, go offline, or run only favourable
inputs.

**Status.** The executor and gateway are open source and run as single operator
processes. There is no executor network, staking or slashing. On OpenVM an
executor cannot forge the computation, but it can deny service, choose the VM
limits (1.4) and fabricate failures (1.5). On Noir it can forge results (1.1).

**Mitigation.** Execution is deterministic, so anyone running the same program
over the same input and tape gets the same result and can prove it. A consumer
should accept a proof from any executor, checking public inputs rather than
identity.

**Residual risk.** Real liveness guarantees need a decentralised executor network
with economic incentives. Cryptography cannot substitute for it.

### 7.2 [S] Proving latency

**Failure.** A proof arrives too late for time-sensitive uses.

**Status.** Measured on CPU. OpenVM cost tracks instructions executed, with a
fixed floor of roughly 150,000 instructions (input deserialisation and software
SHA-256) that dominates small tasks.

| Path | Result | Machine and date |
|---|---|---|
| OpenVM, `examples/prover.lua`, end to end (compile, dry run, app proof, verify) | 9.8 s, proof about 552 KB | Apple M4 Pro, CPU only, 2026-09-17 |
| OpenVM app proofs across the proveno-zk examples | 7.1 s to 11.2 s | Apple M4 Pro, CPU only, September 2026 |
| OpenVM app proofs, synthetic loads up to about 5.7M instructions | 7.4 s to 75.9 s, about 81,000 instructions per second, verify 0.1 to 0.2 s | Apple M4 Pro, CPU only, September 2026 |
| OpenVM aggregated STARK proof, smallest example | 19.8 s, verify 0.2 s | Apple M4 Pro, CPU only, September 2026 |
| OpenVM, gateway demo trace (four calls) | about 10.6 s app, about 26.5 s aggregated | Apple M4 Pro, 14 cores, 24 GiB, CPU only, September 2026 |
| Noir prove and verify | 3.0 s and 9 ms, proof 10,304 bytes | maintainer's Mac, 2026-09-17 |

The Noir figure is for a proof that does not attest to results (1.1) and should
not be quoted as the headline. The OpenVM EVM-level proof and GPU proving have
not been measured.

**Mitigation.** Route SHA-256 through OpenVM's accelerator, which is enabled but
idle; GPU proving; proof aggregation. Target settlement and review workflows that
tolerate tens of seconds.

**Residual risk.** Sub-second proving of general execution is out of reach, which
excludes real-time uses.

### 7.3 [S] On-chain verification cost

**Failure.** Verification costs more gas than an integrator can absorb.

**Status.** No on-chain path exists for OpenVM. The only on-chain verifier is the
Noir UltraHonk one: `ProvenoVerifier.verify` used 5,858,919 gas in the contract
tests, with a 10,304-byte proof as calldata, and the generated verifier deploys
at 24,392 bytes, just under the 24,576-byte contract size limit (measured
2026-09-17).

**Mitigation.** An OpenVM EVM wrapper with a measured gas cost; proof aggregation
across tasks.

**Residual risk.** The gas market, and the size of the OpenVM EVM wrapper, which
is not yet known.

### 7.4 [F] Proving bounds as product profiles

**Failure.** A fixed circuit ceiling rejects real workloads, or a generous one
costs every proof.

**Status.** Applies to Noir, whose cost is a function of its padded ceilings, not
the program (`proveno-zk/docs/openvm-benchmarks.md`). OpenVM has no padded
ceiling.

**Mitigation.** Publish bounds as named profiles.

**Residual risk.** Each profile is a separate verification key and verifier to
deploy.

## Appendix

### Summary by category

| Category | Failure modes |
|---|---|
| [F] Fully addressable | 1.1, 1.2, 1.3, 1.4, 1.6, 1.7, 1.8, 1.9, 1.11, 1.12, 2.3, 2.5, 3.1, 3.2, 3.3, 3.4, 4.2, 6.1, 6.2, 7.4 |
| [S] Substantially mitigated | 1.5, 1.10, 2.2, 2.4, 2.6, 3.5, 3.6, 4.1, 4.3, 5.2, 7.2, 7.3 |
| [A] Architectural | 2.1, 5.1, 7.1 |

### Measurements

| Measurement | Value | Machine | Date | Source |
|---|---|---|---|---|
| OpenVM end to end, `examples/prover.lua` | 9.8 s, about 552 KB | Apple M4 Pro, CPU only | 2026-09-17 | `./prove-openvm.sh` in proveno-zk |
| OpenVM app and aggregated levels | see 7.2 | Apple M4 Pro, CPU only | September 2026 | `proveno-zk/docs/openvm-benchmarks.md` |
| Gateway demo trace | about 10.6 s app, 26.5 s aggregated | Apple M4 Pro, 14 cores, 24 GiB, cargo-openvm v2.0.2 | September 2026 | [gateway spec](../planning/proveno-gateway-spec.md) |
| Noir prove, verify, proof size | 3.0 s, 9 ms, 10,304 bytes | maintainer's Mac | 2026-09-17 | Barretenberg CLI |
| Noir on-chain verify | 5,858,919 gas | Foundry tests | 2026-09-17 | proveno-zk contract tests |

### Renamed identifiers

| Older name | Current name |
|---|---|
| `tls_attestation_hash` | `attestation_hash` |
| `required_attested`, `preferred_attested`, `unattested_permitted` | `RequiredAttested`, `PreferredAttested`, `UnattestedPermitted` |

### Historical documents not to cite

- `proveno-zk/docs/phase3-benchmarks.md`: its gas figures come from a stub
  verifier and a retired Groth16 estimate.
- The in-guest re-verification section of `proveno-agent/docs/tls-attestation.md`.
- Earlier versions of this document, which framed proveno as a programmable
  oracle and assumed an attestation that proves what a server returned.
