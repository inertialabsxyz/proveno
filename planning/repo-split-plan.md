# Repository Split: Core Infrastructure vs Applications

**Status:** draft, September 2026

## Context

Proveno's infrastructure and its first application have grown together in one
repository. The deterministic VM, the compiler, the record/replay machinery and the
canonical serialization are general purpose. The programmable-oracle use case (HTTP
domain allowlists, TLS attestation, price-feed schemas, the Noir circuit, the Solidity
consumer, the LLM orchestrator) is one application built on top of them.

Today the two are interleaved *inside* `src/`. `src/policy/` hardcodes that tools are
HTTP (`is_http_tool` matches `"http_get" | "http_post"`; `extract_domain` is a URL
parser). `src/tls/` is an attestation producer for one provenance provider. `src/zkvm/`
bakes an Ethereum consumer ABI into `output_hash`. That coupling makes it costly to
explore a second use case, such as the MCP agent-execution prototype, without dragging
the oracle along.

The goal is a core repository that knows nothing about HTTP, X.509, Ethereum or LLMs,
plus separate repositories that each explore one use case on top of it.

**The strongest evidence this is viable is already in the Makefile.** The CI gate is
`check = lint + test + test-nostd`, and all three are entirely core. Every
application-specific target (`build-openvm`, `prove-openvm`, `prove-examples`,
`test-prove`) is already documented as opt-in and outside the gate. The line has been
informally drawn for a while; this makes it structural.

## Decisions taken

- **Three repositories:** core, zk, oracle. New use cases become new repositories.
- **Decontaminate in place first**, as separate commits in this monorepo, while
  `make check` still covers everything. The split then becomes a mechanical file move.
- **Applications depend on core by git tag**, matching how `openvm` is already
  depended on. No publishing process to set up before anything can move.

---

## Target topology

```
proveno            (core)    VM runtime, determinism, record/replay. no_std capable.
  ├── proveno-zk   (app)     Proving: Noir circuit + driver, OpenVM guest + host,
  │     └── proveno-oracle   commitments, execution policy, Solidity contracts.
  │                (app)     The oracle product: LLM orchestrator, demo server,
  │                          TLS attestation, examples, benchmarks.
  └── proveno-mcp  (app)     The agent-execution prototype. Depends on core only.
```

`proveno-mcp` needs none of the proving stack, which is the point of the exercise: it
is the first consumer that proves the boundary is real.

---

## Where the line falls

| Current location | Goes to | Why |
|---|---|---|
| `src/parser`, `src/compiler`, `src/bytecode`, `src/types`, `src/vm` | **core** | Generic VM infrastructure. |
| `src/host/{canonicalize,transcript,tape,poseidon2}.rs` | **core** | Canonical serialization, per-call records, record/replay determinism. `canonicalize.rs` is the most reusable file in the tree. |
| `src/host/tool_registry.rs` (quota, gas, byte accounting) | **core** | Generic. Its policy half moves out; see S0.3. |
| `src/noir/{opcodes,trace}.rs` | **core**, renamed `src/isa/` | The VM's own ISA numbering and step trace. Nothing to do with Noir, and the current name says otherwise. |
| `src/noir/encoder.rs` `compute_program_hash*` | **core**, as `src/compiler/program_hash.rs` | The canonical definition of "the program hash". `compiler::codegen` already calls it. |
| `src/noir/encoder.rs` `encode_program`, `NoirBytecode` | **zk** | `MAX_BYTECODE = 512` is a fixed circuit ABI matching `noir/src/main.nr`. |
| `src/policy/`, `src/host/policy_host.rs` | **zk** | Oracle-specific: HTTP domains, methods, TLS requirement, price-feed schemas. `PolicyView` is what the guest enforces, so it belongs with the guest. |
| `src/zkvm/` (`PublicInputs`, `GuestInput`, `DryRunResult`) | **zk** | `policy_hash`, `attestation_hash`, and a keccak256 Ethereum ABI in `output_hash`. Moved wholesale rather than genericized; see "What we deliberately do not do". |
| `src/tls/` | **oracle** | An attestation producer for one provenance provider. Core already has the right generic seam: `HostInterface::take_attestation() -> Option<Vec<u8>>`, which is opaque and bind-only. |
| `src/main.rs` (`DemoHost`) | **core**, as `examples/repl.rs` | A smoke-test REPL with four toy tools. It should not define the crate's binary target. |
| `proveno-compiler` | **core** | Only imports `parser`, `compiler`, `bytecode`. |
| `proveno-witness`, `proveno-noir`, `proveno-openvm`, `proveno-openvm-host`, `verifier` | **zk** | All produce or consume `DryRunResult` / `PublicInputs`. |
| `proveno-orchestrator`, `proveno-demo` | **oracle** | clap, axum, tokio, alloy, dotenvy, the LLM loop. |
| `noir/` circuit, `contracts/`, `openvm.toml` | **zk** | |
| `policies/`, `bench/`, `scripts/`, `demo-*.sh`, oracle `examples/*.lua` | **oracle** | |
| `tests/{compiler,builtins,integration,json,noir_trace,tools}.rs` | **core** | 6 of 8 root test files are pure core. |
| `tests/policy.rs` | **zk** | |
| `tests/tls.rs` | **oracle** | Whole file is `#![cfg(feature = "tls")]` and `tls_attestation_nonzero_for_p256` makes a live call to example.com. A core suite should never do that. |
| `planning/`, `docs/tls-attestation.md` | **oracle** | `docs/canonical-serialization.md` is a core spec and stays. |

---

## Stage 0: decontaminate in place — **done**

Landed on `refactor/core-app-separation`. `make check` is green at every commit
from `84dd1b2` onward, and `make test-prove` passes all 7 Noir prove/verify tests
at the tip, which is what confirms the program hash and ISA encoding are
unchanged end to end through the real circuit.

| Commit | Step |
|---|---|
| `349317f` | `fix(parser)`: prerequisite, see below |
| `84dd1b2` | `style(repo)`: prerequisite, see below |
| `4202a5c` | S0.1 workspace.dependencies |
| `037f741` | S0.2 + S0.3 policy enforcement into host wrappers |
| `fa0126e` | S0.4 program-hash out of the noir module |
| `11a78cb` | S0.5 opaque DryRunResult attestations |
| `7e3498a` | S0.6 src/noir -> src/isa |
| `2adcfa0` | S0.7 DemoHost binary -> examples |
| `3535b4c` | S0.8 drop tls from default features |

End state: `parser`, `compiler`, `bytecode`, `types`, `vm`, `host` and `isa`
contain **zero** references to `policy`, `tls` or `noir`. The app-bound modules
point only inward (`policy -> types`, `tls -> host`, `noir -> compiler, isa`,
`zkvm -> host, policy`).

### Deviations from the plan as written

- **S0.2 and S0.3 were one commit.** Removing `Vm::new_with_policy` without also
  removing `ToolRegistry::with_policy` leaves no way to construct a
  policy-carrying VM, so the intermediate state does not build.
- **`src/host/policy_host.rs` moved to `src/policy/guest.rs`.** Not in the plan,
  but without it `host/` still contained a file that was pure policy
  enforcement, so the edge was not really cut.
- **Two prerequisite commits.** `make check` was already failing on `main` with
  44 clippy lints under clippy 1.98, so nothing could be committed through the
  gate. One of those lints (`match_overlapping_arm`) turned out to be a real
  bug: `b'0' => Ok(0)` sat ahead of `b'0'..=b'9'` in the lexer's escape
  handling, so `"\012"` lexed as NUL followed by the literal bytes `1` and `2`
  instead of the single byte 12. Fixed with a regression test.
- **`make test-tls` added and wired into `make check`.** S0.8 would otherwise
  have silently dropped `tests/tls.rs` from the gate, which is exactly the
  coverage-shrinks-silently risk listed below.
- **`TlsAttestationRecord::to_attestation_bytes` added** as the encoder at the
  boundary S0.5 created.

### Notes for whoever picks this up

- `CLAUDE.md` cites a test `poseidon_program_hash_does_not_cover_constants_known_gap`
  in `src/noir/encoder.rs`. It does not exist anywhere in the repo. The known gap
  it describes is real and still open; the test is not.
- `make lint` runs plain `cargo clippy`, not `--all-targets`, so lints in
  `tests/*.rs` are still not gated.
- `CLAUDE.md` and the crate table need updating for `src/isa/`, the lib-only core
  package, and the narrowed default feature set.

### The steps as originally planned

Each of these is one commit in this repository, with `make check` green before it lands.
Nothing moves repositories yet, and every step is independently reversible. This is the
part that carries the real risk, so it happens while the full test suite still covers
every crate at once.

**S0.1 `chore(repo): add workspace.package and workspace.dependencies`**
There is no `[workspace.dependencies]`, no `[workspace.package]`, no `.cargo/config.toml`
and no `[patch]` anywhere. Every crate pins its own versions. Centralize `serde`,
`serde_json`, `sha2`, `sha3`, `reqwest` and the `openvm` git tag first, so that after the
split each repository re-pins from one obvious place instead of drifting.
Also declare `serde` explicitly in `[features]`; it is currently an implicit feature from
`serde = { optional = true }`, yet five crates request it by name.

**S0.2 `refactor(vm): remove Vm::new_with_policy`**
`src/vm/engine.rs:201` is the entire `vm -> policy` edge, and it only forwards to
`ToolRegistry::with_policy`. Callers wrap the host instead, a pattern already proven in
`src/zkvm/guest_input.rs:104`. Three call sites: `tests/policy.rs:77`,
`proveno-witness/src/prover.rs:67`, `proveno-orchestrator/src/pipeline.rs:294`.

**S0.3 `refactor(host): move policy enforcement out of ToolRegistry`**
Delete the `#[cfg(feature = "std")] policy: Option<OraclePolicy>` field and
`ToolRegistry::with_policy`. Domain and method checks already live in
`PolicyEnforcingHost`. The response-schema check needs `serde_json`, so it goes into a
new std-only `OraclePolicyHost` wrapper in the policy module rather than into the
`no_std` guest-side one. Four in-module tests move with it. After this, `host/` imports
nothing from `policy/`.

> This also fixes a real defect noted in the earlier MCP analysis: a host-side policy
> denial currently raises before `host.call_tool` and writes **no** transcript record,
> so the attempt is invisible in the artifact. Moving the check into a host wrapper
> routes it through `ToolRegistry`'s error arm, which records it.

**S0.4 `refactor(compiler): move program-hash out of the noir module`**
`compiler::codegen:90` calls `noir::encoder::compute_program_hash` while
`noir/encoder.rs` imports `compiler::proto::CompiledProgram`. That mutual dependency
forces both into the same repository. Move `compute_program_hash` and
`compute_program_hash_sha256` to `src/compiler/program_hash.rs`; leave `encode_program`
and `NoirBytecode` behind. Output must stay byte-identical. The known-gap test
`poseidon_program_hash_does_not_cover_constants_known_gap` moves with the functions.

**S0.5 `refactor(zkvm): make DryRunResult attestations opaque`**
`DryRunResult.tls_attestations: Vec<TlsAttestationRecord>` is the only `zkvm -> tls`
edge, and it would otherwise force the zk repository to depend on the oracle
repository, which is backwards. Change to `attestations: Vec<Vec<u8>>`; the TLS
producer encodes at the boundary. Consumers are `proveno-witness/src/prover.rs` and
`proveno-orchestrator/src/prove.rs`, which pass it through without reading fields.

**S0.6 `refactor(repo): rename src/noir to src/isa`**
`opcodes.rs` and `trace.rs` are the VM's instruction numbering, not a prover concern.
Mechanical rename plus `tests/noir_trace.rs` to `tests/isa_trace.rs`.

**S0.7 `refactor(repo): move the DemoHost binary into examples`**
`src/main.rs` to `examples/repl.rs`, so the core library stops auto-discovering a binary
target.

**S0.8 `chore(repo): narrow the default feature set to std + poseidon`**
Drop `tls` from `default`. `tls` also implies `poseidon`, so today every dependent that
asks only for `zkvm` or `serde` still pulls p256, p384, x509-cert, webpki-roots and rsa.

> **Do not drop `poseidon` from the default.** `compiler::codegen` selects Poseidon2 vs
> SHA-256 for `program_hash` on that feature, and `proveno-compiler` stays in the core
> repository. If its default silently flipped to SHA-256, every committed
> `program_hash` would change and the Noir path would break without a compile error.
> This is the single most dangerous edit in the whole split; pin it with a test
> asserting the hash of a fixture program under default features.

---

## Stage 1: the split

### Boundary validated by dry run

Before any history surgery, both boundaries were checked by assembling throwaway
trees and running the gate against them. Both pass.

**Core alone** (`parser`, `compiler`, `bytecode`, `types`, `vm`, `host`, `isa`,
plus `proveno-compiler`), with `policy`, `tls`, `noir` and `zkvm` deleted:

| Check | Result |
|---|---|
| `cargo fmt --check` | pass |
| `cargo clippy -- -D warnings` | pass |
| `cargo test` | pass, 667 tests |
| `--no-default-features` build | pass |
| `--no-default-features --features std` | pass |
| `program_hash` of `examples/simple.lua` | `2cad63a185…`, identical to the monorepo |

Dependency tree: **245 crates** default, **22** with no default features. The
22-entry figure is the one `CLAUDE.md` cites as the target for zkVM guest builds.

This dry run found one real defect, fixed in `6015f76`: `get_url_from_args` sat
in `host/tool_registry.rs` but only the policy wrappers called it, so it became
dead code the moment they were removed and failed `clippy -D warnings`. It now
lives in `policy::canonical`.

**The zk layer as a separate crate** (`policy`, `zkvm`, `noir`) depending on core:

| Check | Result |
|---|---|
| build with `std,serde,zkvm` | pass |
| `cargo clippy -D warnings` | pass |
| `cargo test` | pass, 92 tests |
| zkVM guest config (`--no-default-features --features zkvm,serde`) | pass, 34 crates |

The only mechanical work was rewriting `crate::{host,types,vm,compiler,isa}` to
`proveno::…`, including splitting grouped `use crate::{…}` statements that mix
core and local modules. Seven files.

### Feature mapping for the zk crate

```toml
[features]
default  = ["std", "poseidon"]
std      = ["dep:serde_json", "proveno/std"]
serde    = ["dep:serde", "proveno/serde"]
zkvm     = []
poseidon = ["proveno/poseidon"]

[dependencies]
proveno = { git = "…", tag = "v0.2.0", default-features = false }
```

`default-features = false` on the core dependency is load-bearing for the same
reason it is on `proveno-openvm` today.

### Mechanics


Preserve history with `git subtree split` (or `git filter-repo` for the
multi-directory sets), so blame survives in each repository.

1. **`proveno`** is this repository with the zk and oracle sets deleted. Tag `v0.2.0`.
   Gate stays `make check` (`lint + test + test-nostd`). `test-nostd` is the most
   valuable target in the split: it is the real guard on the `no_std` / no-poseidon
   guest configuration, and it must not be left behind.
2. **`proveno-zk`** takes `policy/`, `zkvm/`, the Noir encoder, `proveno-witness`,
   `proveno-noir`, `proveno-openvm`, `proveno-openvm-host`, `verifier`, `noir/`,
   `contracts/`, `openvm.toml`, `tests/policy.rs`. Gate is `cargo test` plus
   `make test-prove`.
3. **`proveno-oracle`** takes `tls/`, `proveno-orchestrator`, `proveno-demo`,
   `examples/*.lua` (oracle ones), `bench/`, `scripts/`, `policies/`, `demo-*.sh`,
   `planning/`, `tests/tls.rs`.

Cross-repo dependency form:

```toml
proveno = { git = "https://github.com/inertialabsxyz/proveno", tag = "v0.2.0" }
```

Bump by moving the tag deliberately, one repository at a time.

---

## What we deliberately do not do

**We do not genericize `PublicInputs`.** Its six-field byte layout is what the Noir
circuit and the existing verification keys commit to. Splitting it into a generic
execution commitment plus an app-supplied extension is the theoretically right shape,
but it would invalidate verification keys for a refactor with no user-visible benefit.
Moving the whole `zkvm` module into the zk repository achieves the separation without
touching a byte. Core keeps `Vm`, `Transcript`, `OracleTape` and `TapeHost`, which is
everything a non-proving consumer needs.

**We do not extract a generic `CallGuard` trait yet.** The clean seam is a policy trait
in core with an `HttpOraclePolicy` implementation in the app. That is worth doing once
there are two real policy implementations, not before. Until then, `PolicyEnforcingHost`
wrapping a `HostInterface` is the seam, and it already works.

---

## Verification

After each Stage 0 commit, in the monorepo:

```bash
make check                                    # lint + test + test-nostd
make test-prove                               # Noir path unchanged (needs nargo + bb)
cargo run -p proveno-compiler -- examples/simple.lua /tmp/c.json
# assert program_hash is unchanged against a recorded fixture, especially after S0.4 and S0.8
```

After the split, in each repository:

```bash
# proveno
make check                                    # must pass with zero network access

# proveno-zk
cargo test && make test-prove
./prove-openvm.sh examples/simple.lua

# proveno-oracle
cargo test
ANTHROPIC_API_KEY=... bash demo-noir-e2e-local.sh "<task>"
```

The strongest end-to-end check that the boundary is real: `proveno-mcp` builds and its
tests pass depending on `proveno` alone, with no policy, TLS, Noir or OpenVM crate
anywhere in its lockfile.

---

## Risks

1. **The `program_hash` feature flip (S0.8).** Silent, not a compile error, and it
   breaks proofs. Pin with a fixture-hash test before touching the feature set.
2. **`proveno-openvm` must keep `default-features = false`.** Documented in-file:
   `poseidon` pulls acir, then wasmer, then cranelift, whose build script hard-panics on
   custom RISC-V triples, and cargo runs that build script whether or not the code is
   linked. Without the flag the dependency tree goes from 22 entries to 523.
3. **Shell scripts that span the whole pipeline.** `prove-openvm.sh`,
   `prove-examples.sh` and the `demo-*.sh` family invoke crates by `-p` across what will
   become three repositories. Each script must land in the repository that owns its
   whole pipeline, and the cross-repo ones need rewriting against installed binaries.
   Note `demo-noir-e2e.sh:123` is *already* broken: it invokes
   `--bin proveno-prover`, which does not exist. Fix or drop it during the move.
4. **Coverage shrinks silently.** `make test` today is a bare `cargo test` over the
   workspace. After the split it covers only the remaining members, with no failure to
   signal the loss. Each repository needs its own CI workflow before the split lands,
   not after.
5. **Version drift across three repositories.** S0.1 mitigates it but does not remove
   it. The `openvm` git tag `v2.0.2` is the only non-crates.io source and appears in two
   crates that both end up in the zk repository, which is lucky.
6. **`verifier/` directory versus `proveno-verifier` package name.** Rename the
   directory during the move; only `proveno-orchestrator`'s `path = "../verifier"`
   refers to it.
7. **`proveno-demo`'s direct `proveno` dependency is nearly vestigial**, just
   `LuaValue` and `VmConfig`. Removing those two would let the demo depend on
   `proveno-orchestrator` alone, which simplifies the oracle repository's graph.
