# proveno-gateway: Deterministic Agent Execution with Replay

**Status:** draft, September 2026
**Repository:** proveno-gateway (depends on proveno-core by git tag)
**Scope:** the standalone prototype used for pilots and demos. Proof generation
is designed for but not built in this scope.

This spec is subordinate to [the architecture document](../docs/architecture.md).
Where the two disagree, the architecture document wins and this spec is wrong.

## 1. What the gateway is

Proveno runs verifiable tasks. proveno-gateway is an **application** of that
runtime: it puts the deterministic Lua VM between an agent and the real tools,
so that an agent's program runs as a verifiable task.

An agent's only tool is the gateway. The gateway is the only thing that talks to
the real tools. Between them sits proveno-core's VM, and every interaction with
the outside world is policy-checked, credential-injected by the gateway rather
than the model, and recorded. Any run can be replayed bit-for-bit with the world
switched off, and the recording is exactly the witness a later proof consumes
(see section 6).

The prototype shows three things to a design partner in one sitting: an agent
can do real work this way; a run can be reproduced exactly from its record; and
a policy change is enforced at the call, with the refusal in the record.

## 2. Topology

```
 Agent (any model / framework)
   │  MCP client, one server configured
   ▼
 proveno-gateway ─────────────────────────────────────
   MCP server  : exposes  execute(program)
   Lua VM      : proveno-core; deterministic, metered, no ambient I/O
   Host layer  : schema → policy → credential inject → tools/call → trace
   MCP client  : one connection per downstream tool server
   Trace store : append-only, signed per run
 ─────────────────────────────────────────────────────
   │  MCP tools/call, credentials attached here
   ▼
 Downstream MCP servers (customer's tools, any language)
```

The gateway speaks MCP on both edges. Standalone, it is the whole runtime.
Behind an existing gateway product, that product is simply one more downstream
MCP server providing OAuth and RBAC; proveno-gateway doesn't need to know it's
there.

## 3. Components

### 3.1 Agent-facing MCP server

One tool:

```
execute(program: string, session?: string) → { result, trace_id, status }
```

The upstream agent writes the Lua program; the gateway never calls a model. The
tool description is the prompt: every MCP client feeds it to the model at the
point it decides to call the tool, so no special system prompt is needed on the
agent side. It is generated at startup and contains, in order:

1. **Dialect rules**, taken from what proveno-core enforces rather than restated
   by hand:
   - Rejected at parse time: `debug`, `io`, `os`, `package`, `require`, `load`,
     `dofile`, `loadfile`, `loadstring`, `collectgarbage`, `setmetatable`,
     `getmetatable`, `rawget`, `rawset`, `setfenv`, `getfenv`, `coroutine`.
   - No float literals, and no floats at all: integers only.
   - No user-defined globals; declare everything `local`.
   - Deterministic iteration via `pairs_sorted`; the available `string`,
     `math`, `table` and `json` subset.
   - Time and randomness exist only as downstream tools, and are therefore
     recorded.
2. **The typed tool API**, derived from the JSON schemas of every downstream
   tool the current principal is allowed to call. Tools are namespaced by
   downstream server. Format, per tool:

```lua
-- Place a limit order. Returns { order_id, status }.
market.place_order{ pair: string, size: integer, price: string } -> table
```

3. **Two or three short example programs** showing the calling convention,
   catching a denied call with `pcall(function() ... end)`, and the return
   value. Core's compiler rejects `pcall(tool.call, ...)`, so the examples must
   not use that form.

Denied tools are omitted from the description and rejected at runtime if called
anyway.

**Calling convention.** The only side-effecting primitive is proveno-core's
`tool.call(name, args)`. The per-tool functions (`wallet.transfer{...}`) are a
generated Lua prelude of `local` tables whose functions call
`tool.call("wallet.transfer", args)`. Because core rejects unknown globals, the
prelude is prepended to the submitted program and compiled with it. The prelude
is a pure function of the description, so `program_hash` (section 3.4) covers
both, and lint errors are reported against the agent's own line numbers.

The prelude must use the assignment form
`wallet.transfer = function(args) ... end`. In proveno-core v0.2.0,
`function wallet.transfer(args)` compiles but the call then fails with
"attempt to call a table value"; that is a core bug to fix separately.

Because the description is part of the record (its hash is in every trace), it
must be a pure function of (dialect text version, downstream schemas,
principal's allow-list): tools sorted by name, schemas rendered canonically, no
timestamps or free-hand edits. Two gateway instances with the same config and
the same downstream servers must produce the same `description_hash`; a
different hash must always mean the model was told something different.

Enforcement, not hope: the gateway parses and lints every program before
execution and rejects forbidden constructs with a precise, line-numbered error
returned as the tool result (`line 4: os is not available; call clock.now{}`),
so the model corrects and resubmits in one round trip. Two supporting endpoints:

- `check(program)`: lint without executing, for agents that validate before
  acting.
- MCP resource `proveno://lua-guide` (and an MCP prompt of the same content) so
  a team can pull the dialect guide into its own system prompt without copying a
  document that drifts.

A long agent task is several short `execute` calls sharing a `session` id, each
its own trace. This keeps each trace small enough to prove later. Orchestration
across those calls (timers, retries, waiting for human approval, multi-day
tasks) is not the gateway's job: a durable-execution engine (Temporal, Restate,
Inngest) drives the task and calls `execute` as an activity; the session id is
the seam.

### 3.2 Deterministic Lua VM

proveno-core's VM, unmodified. The determinism invariants in the architecture
document apply as written; the gateway relies on them and must not weaken them.
What the gateway adds:

- **Metering is configured per run** from `[vm]` config into `VmConfig` (gas,
  memory, call depth, tool-call count, bytes in and out, output size). Core's
  default of 16 tool calls is too low for programs with tens of calls, so the
  gateway sets its own. Exhaustion fails the run with a recorded reason.
- **Tool errors are raised, not returned.** A host error becomes a Lua error
  carrying the message, which the program catches with `pcall`. An uncaught one
  ends the run with that status.
- **Determinism is tested at the gateway boundary too:** the same program and the
  same sequence of host responses give an identical return value, `gas_used` and
  `memory_used`, across runs and across machines.

### 3.3 Host layer

The gateway's `HostInterface` implementation. Every `tool.call` passes through,
in order:

1. **Schema check.** Args validated against the downstream tool's JSON schema.
2. **Policy check.** A function
   `(principal, tool, args, session_state) → allow | deny(reason)`. Prototype
   implementation: a static rules file (allow-list of tools per principal,
   optional per-argument constraints such as `wallet.transfer.amount <= 50`).
3. **Credential injection.** The gateway attaches the credential for that
   downstream server from its own config or environment. The program and the
   model never see it.
4. **Dispatch.** `tools/call` to the downstream MCP server. The response is
   converted to the VM's integer-only value model at this boundary (section 8).
   Core's host interface returns a table, so the result is taken from
   `structuredContent` if present, else from a single text content item that
   parses as a JSON object, else wrapped as `{ text = ... }`. A non-object value
   is wrapped as `{ value = ... }`. `isError: true` becomes a host error carrying
   the text.
5. **Record.** Call, policy decision, response or error, and the provenance
   attestation for the response are appended to the trace.

A schema failure or a deny is returned to core as a host error, so it lands in
core's transcript as a failed call, and the program sees it as a catchable
error. The gateway trace additionally records which step refused it and why.

### 3.4 Trace

Append-only, one per `execute`. It wraps core's `Transcript` rather than
replacing it: each entry is a `ToolCallRecord` plus what the gateway knows and
core does not.

```
header   : trace_id, session, principal,
           program_hash      (SHA-256 of the compiled bytecode, prelude included),
           gateway_policy_hash (SHA-256 of the canonical policy file; not the
                              proof's `policy_hash`, see section 6),
           description_hash  (SHA-256 of the full tool description the model saw:
                              dialect rules + generated API + examples),
           vm_version, vm_config,
           request (optional: the natural-language task, if the agent supplies it)
entries  : [ { record: ToolCallRecord, decision, provenance } ]
footer   : output, status, gas_used, memory_used, signature
```

`program_hash` is proveno-core's `compute_program_hash_sha256`. That scheme
covers the constant pool, which the Poseidon2 scheme does not, and it is the
same value the OpenVM proof commits to.

`vm_config` is recorded because it decides whether a run completes or aborts.
Replay must use it. Binding it inside a proof is an open gap in proveno-zk (see
the architecture document), not something the trace can fix.

`provenance` carries the attestation for each response. Proveno binds
attestations and does not verify them; the provenance layer is pluggable. The
tag says which provider produced the blob, which is what a consumer needs in
order to choose a verifier:

- `unsigned`: no attestation.
- `signed(by, sig)`: a signature from a data provider.
- `onchain(chain, block, ref)`: a reference to on-chain state.
- `notarized(scheme, ref)`: a zkTLS or TLSNotary transcript.

The blob goes in the record's `attestation` field, which is bound into
`attestation_hash`.

**How a tag is populated, decided September 2026.** The downstream reports its
own provenance; the gateway never queries a chain and never learns what one is.
A tool result carries it in MCP result metadata under the reserved key
`proveno/provenance`, an object whose `type` is one of the four tags above and
whose remaining fields are that tag's. The gateway reads it, sets the entry's
typed tag, and binds the provider's payload **verbatim**, canonicalised, as the
attestation blob, so a later verifier gets exactly what the provider said, not
a gateway paraphrase of it. Metadata is used rather than the response body so
the provenance never reaches the program or the model, and never has to appear
in a tool's schema.

A result with no such metadata is `unsigned`, which is what the prototype emits
today. A malformed or unknown one fails the call at the boundary rather than
being silently downgraded: a server that means to attest and gets it wrong
should hear about it.

Restating the limit, because the tag invites the opposite reading: `onchain`
means the response claimed to come from that chain at that block, and the claim
is sealed into the record. It does not mean proveno checked it.

The trace is signed by the gateway's key at the footer. Prototype scheme:
Ed25519 over the SHA-256 of the trace's JSON serialization with the signature
field empty, the key given as a hex-encoded 32-byte seed. `trace_id` is a UUIDv7;
it identifies the run and plays no part in determinism. The program text and the
tool description text are stored alongside it, keyed by `program_hash` and
`description_hash`, so a dispute can answer "what was the model told" as
mechanically as "what did the program do". Whether the program was the right
interpretation of the request is the model's judgement and is outside what the
trace guarantees; storing `request` next to the program is what lets a human
check that part separately.

### 3.5 Replay

```
proveno-gateway replay <trace_id>
```

Loads the program and the trace, builds an `OracleTape` from the recorded
entries, and runs the VM with the recorded `vm_config` over a replay host. No
network access. Each `tool.call` is matched by sequence number against the
recorded entry; tool name and canonical args must match exactly or replay fails
with a divergence report naming the sequence number, the expected call and the
actual one. The return value, `gas_used` and `memory_used` must equal the
footer. Replay is the correctness test for determinism and the demo's
centrepiece.

Core's `TapeHost` already replays responses in order but ignores the tool name
and args. The divergence check belongs with the tape, so it is added to
proveno-core rather than reimplemented in the gateway.

Core also discards the transcript, gas and memory figures when `execute`
returns an error. Runs that fail (an uncaught denial, gas exhaustion) must still
produce a trace and replay to the same failure, so core gains accessors for
those after a failed run.

### 3.6 Configuration

```toml
[server]
listen = "127.0.0.1:7777"
signing_key = "env:PROVENO_SIGNING_KEY"

[vm]
gas_limit = 2_000_000
memory_limit_bytes = 16_777_216
max_tool_calls = 64

[[downstream]]
name = "wallet"
transport = "stdio"           # or http
command = "agentkit-mcp"
credential = "env:WALLET_API_KEY"

[[downstream]]
name = "market"
transport = "http"
url = "http://localhost:8080/mcp"
credential = "env:MARKET_KEY"

[policy]
file = "policy.toml"

[store]
dir = "traces"

# Section 8, identity of the principal: a static bearer token per agent.
[principals.demo-agent]
token = "env:DEMO_AGENT_TOKEN"
```

Every secret is `env:NAME`; any other form is a config error. For a `stdio`
downstream, the credential is passed to the child process as the named
environment variable, and the child's environment is otherwise cleared except
for `PATH` and `HOME`. For an `http` downstream, it is sent as
`Authorization: Bearer <credential>`.

```toml
# policy.toml
[principals.demo-agent]
allow = ["wallet.get_balance", "market.get_price", "wallet.transfer"]

[constraints."wallet.transfer"]
amount_max = 50
```

## 4. Execution flow, one request

1. Agent calls `execute` with a Lua program.
2. The gateway lints it, prepends the prelude, compiles, computes
   `program_hash`, and opens a trace.
3. The VM runs until the program calls, say, `wallet.transfer{to=..., amount=20}`,
   which invokes the host.
4. Host layer: schema ok → policy ok (20 ≤ 50) → credential attached →
   `tools/call` to the wallet server → response.
5. Trace entry appended; the response is returned to the VM.
6. Program returns; footer written and signed; `{ result, trace_id, status }`
   returned to the agent.

If step 4 denies, the entry records the denial, the program receives a
catchable error, and execution continues or ends as the program decides.

## 5. Demo script

Downstream: a wallet MCP server against a local Anvil chain or a testnet
(AgentKit, a Safe-backed server, or a thin custom one), plus a price server.
Audience-recognisable, real signed transactions.

1. Agent is asked to "rebalance to 60/40 if the price has moved more than 2%".
   It writes a Lua program that reads balances and price, computes, and
   transfers. Show the program, show the transaction on the explorer, show the
   trace.
2. Stop the wallet and price servers. `proveno-gateway replay <trace_id>`.
   Identical output, identical `gas_used`, zero network.
3. Edit `policy.toml`: `amount_max = 10`. Rerun the same program. Show the
   denial in the trace and the agent's response to it.
4. (Optional) Change the program to attempt a tool that isn't in the
   allow-list. Show it absent from the generated API and rejected at runtime.

## 6. Proof tier: designed for, spiked, not built

The trace is the witness. proveno-zk's existing OpenVM guest runs the VM over
the compiled program and the recorded tape, and produces a proof over the
existing SHA-256 public inputs. Milestone 6 did this for two real demo traces in
September 2026 (proveno-zk PR #1): both proved and verified at both levels.

| Public input | What it binds for a gateway trace |
|---|---|
| `program_hash` | The compiled program, prelude included. Same value as the trace header. |
| `input_hash` | The VM input. `execute` passes none today. |
| `tool_responses_hash` | The ordered tool responses and errors (the tape). |
| `attestation_hash` | The per-call provenance attestation blobs. |
| `policy_hash` | proveno-zk's `OraclePolicy`. For a gateway trace it carries the VM limits the run actually enforced, taken from `vm_config`. It is **not** the gateway's rules file. |
| `output_hash` | The return value, **but only if it is an integer**. Any other value proves as `0`. Gateway programs return tables, so today this binds nothing useful for a gateway run: the demo's successful rebalance and its refused transfer commit the same `output_hash`. Tracked in proveno-zk issue #2. |

Everything else stays private: response bodies, intermediate state, any secret
the program handled.

**Two policy documents, two commitments.** proveno-zk's `OraclePolicy` governs
HTTP domains and methods, tool-call and payload limits, a TLS requirement and an
output schema. The gateway's rules file governs which principal may call which
tool, and per-argument bounds such as `amount_max`. `OraclePolicy` cannot
express a principal or an argument bound, so the two are not merged and the
rules do not compile to an `OraclePolicy`. The trace header therefore carries
`gateway_policy_hash`, and a proof's `policy_hash` carries `OraclePolicy`'s.

The gateway refuses a call before it is dispatched, so a refusal already appears
in the tape as a failed call. The proof does not re-enforce the gateway's
policy; binding the hash is what lets a verifier check which rules produced
those refusals.

**Proposed additions:** `gateway_policy_hash` and `description_hash` as public
inputs, so a proof can state which rules were in force and what the model was
told. Until they are added, both live only in the signed trace header, and any
report over a gateway trace must say that the proof does not cover them.

What the proof states: this program, under this policy, over these recorded
responses, produced this output. Until proveno-zk issue #2 is resolved, "this
output" holds only for an integer return value, so for a gateway run the proof
binds the program and what it was told by its tools, not what it concluded.
The VM limits a run used are also not bound: the prover supplies them, and the
OpenVM host ignored them entirely until milestone 6, which would have made a
larger trace unprovable.

What it does not state: that the responses were what the outside world actually
returned. Proveno binds each response's
attestation into `attestation_hash` but does not authenticate it. The
circuit binds blobs, it does not authenticate them. Verifying a `signed`,
`onchain` or `notarized` attestation is the job of the provider that produced it
and of a consumer that trusts that provider. An `unsigned` response is stated as
such in any report. A result is only as trustworthy as the weakest provenance in
its trace, and the report must say so.

**Proving cost, measured September 2026** (proveno-zk PR #1). Apple M4 Pro,
14 cores, 24 GiB, CPU proving, cargo-openvm v2.0.2, three runs each, for the
demo's four-call rebalance trace:

| | Prove | Verify |
|---|---|---|
| App proof | about 10.6 s | 0.06 s |
| Aggregated STARK | about 26.5 s | 0.25 s |

A refused-transfer trace took about 10.3 s and 22.7 s. Proofs are about 550 KB.
Most of the time is fixed: a trivial program takes 7.7 s and 19.4 s, so a
gateway trace adds only a few seconds on top. The earlier expectation of
"seconds per trace" was wrong by an order of magnitude and must not be quoted.

Tens of seconds is still fast enough to prove during a demo, if the audience is
told to expect it, and verification is fast at either level. These are CPU
figures on one machine; GPU proving has not been measured. Quote them with the
machine and the date, or not at all.

## 7. Non-goals for the prototype

- No policy language beyond the static rules file. A Cedar-compatible engine is
  the likely next step; the prototype only needs the hook.
- No credential management beyond env/config lookup.
- No RBAC UI, multi-tenancy, OAuth flows, rate limiting, or observability
  integration. If a customer has these, they have a gateway product; proveno-gateway sits
  behind it.
- No Python or JavaScript execution in the VM.
- No model calls from the gateway. It receives programs, not tasks; it holds no
  model credentials and takes no position on which model or framework the agent
  uses. A "task in, prompt the model" convenience mode is a possible later
  addition, not a guarantee-bearing one; proveno-agent is where that lives today.
- No orchestration across `execute` calls (timers, retries, approvals): that is
  the durable-execution layer's job.
- No `search`/`describe` discovery for large tool sets; the full Lua API goes in
  the tool description. Needed before any customer with hundreds of tools.
- No proof generation.
- No verification of attestations, now or later. Provenance is bind-only.

## 8. Open decisions

- **Identity of the principal.** How the agent authenticates to the gateway and
  how that maps to a policy principal. Prototype: a static token per agent in
  config.
- **Response size in the trace.** Large tool responses inflate traces and later
  proofs, and core's `max_tool_bytes_out` caps them per run. Options: store the
  full response and commit to its hash; or store the hash only and keep the body
  in a side store. Prototype: full response, revisit before proving.
- **Session state.** Whether the policy hook can see prior calls in the session
  (cumulative limits such as "≤ 100 total per day"). Cheap to add, and the first
  thing a wallet customer will ask for.
- **Non-integer numbers.** The VM has no floats, and a price server will return
  them. Downstream JSON must be mapped to integers at the host boundary, and the
  generated API must describe the mapping. Prototype: non-integer numbers become
  decimal strings, and `number` in a schema renders as `integer` or `string`
  accordingly. Fixed-point scaling per tool is the alternative.
- ~~**Gateway policy and proveno-zk's policy.**~~ **Decided, September 2026:**
  two documents, two commitments. The trace header field is
  `gateway_policy_hash`; a proof's `policy_hash` stays `OraclePolicy`'s. See
  section 6.

## 9. Milestones

1. **MCP edges.** Gateway as MCP server (`execute`, `check`, the `lua-guide`
   resource) and MCP client (downstream discovery, `tools/call`). Generated tool
   description and prelude: dialect rules, typed API from schemas, examples.
   Pre-execution lint with line-numbered rejections.
2. **Host layer.** Schema check, static policy, credential injection, number
   mapping, trace with signing.
3. **Replay.** Trace-to-tape loading, divergence reporting and post-failure
   transcript access (both added to proveno-core), and the determinism suite: same program + same
   responses → identical output, `gas_used` and `memory_used`, across runs and
   across machines. Core's record/replay already exists; this milestone is what
   sits on top of it.
4. **Demo.** Wallet + price downstream servers, the four-step script above,
   recorded end to end.
5. **Provenance tag populated** for on-chain reads (cheapest to do, most
   convincing for the crypto beachhead). Bound, not verified.
6. **Proof spike.** One real gateway trace through proveno-zk's existing OpenVM
   guest; measure proving time; decide what to promise.
