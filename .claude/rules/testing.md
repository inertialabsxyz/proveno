# Testing & Quality

## Makefile targets

```bash
make check             # CI gate: lint then test (must pass before merging)
make lint              # cargo fmt --check + cargo clippy -D warnings
make test              # all tests: unit + integration
make test-unit         # cargo test --lib  (in-module unit tests)
make test-integration  # cargo test --tests  (tests/*.rs integration files)
make fix               # auto-format + apply safe clippy fixes
```

`make check` is the hard gate. Run it before every commit. If it fails, fix before continuing.

Plain `cargo test` (the gate documented in `CLAUDE.md`) runs the same suite as `make test` and is acceptable when you only need the test pass; use `make check` when committing.

## Test mandate

Every feature commit must include at least one test for the new behaviour. Every bug fix must include a regression test that would have caught the bug. These are not optional — a commit that adds behaviour without a test, or fixes a bug without a regression test, is incomplete.

Determinism invariants (no floats, canonical iteration, canonical JSON, deterministic replay) are load-bearing for ZK proof soundness. Any change that touches the VM, compiler, host serialization, or oracle tape **must** include a test that pins the determinism property it affects — e.g. identical hashes on replay, byte-identical canonical JSON, sorted iteration order.

If a behaviour genuinely cannot be exercised without infrastructure that is unavailable in tests, document why in the PR description. This should be rare.

## Two test patterns

**Unit tests** — live in `#[cfg(test)]` modules inside the source file, importing from `super::*`. Use for any logic that can be exercised without driving the full VM: lexer/parser fragments, table operations, gas/memory meters, canonical serialization, TLS verification helpers, commitment hashing.

```rust
// src/vm/memory.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_rejects_when_over_limit() {
        let mut m = MemoryMeter::new(100);
        assert!(m.charge(50).is_ok());
        assert!(m.charge(60).is_err());
    }
}
```

**Integration tests** — live in `tests/*.rs` at the root and exercise the public API end-to-end (parse → compile → verify → execute, or full host + oracle tape round-trips). Current files: `integration.rs`, `compiler.rs`, `builtins.rs`, `json.rs`, `tools.rs`.

```rust
// tests/integration.rs
use luai::{bytecode::verify, compiler::compile, parser::parse, vm::Vm};

#[test]
fn replay_produces_identical_output_hash() {
    let proto = compile(&parse("return 1 + 2").unwrap()).unwrap();
    verify(&proto).unwrap();
    // run, capture oracle tape, replay, assert hash equality
}
```

Workspace crates (`compiler`, `prover`, `orchestrator`, `openvm`) carry their own tests next to their sources; `cargo test` at the root runs everything.

## Feature-gated tests

Code behind `#[cfg(feature = "zkvm")]` or `#[cfg(feature = "serde")]` needs explicit feature flags to be exercised:

```bash
cargo test --features zkvm
cargo test --features "serde zkvm"
```

If you add or modify zkvm/serde-gated code, run the feature-flagged tests locally before committing — `make check` runs the default feature set only.

## Clippy

`make lint` runs `cargo clippy -- -D warnings`. Fix warnings rather than silencing them. If a targeted `#[allow(...)]` is genuinely required, attach a one-line comment explaining why. Never silence clippy globally at the crate or module level.

## What to test at each layer

| Layer | Pattern | Example |
|---|---|---|
| Pure helpers (parser fragments, meters, hashers) | Unit test in `#[cfg(test)]` next to the code | `MemoryMeter::charge`, `canonical_serialize` |
| Bytecode verifier | Unit or integration; assert malformed bytecodes are rejected | stack-depth, branch-target tests |
| VM execution semantics | Integration via `parse → compile → execute` | `tests/integration.rs` |
| Builtins (`string`, `math`, `table`, `json`, `pcall`) | Integration through compiled Lua programs | `tests/builtins.rs`, `tests/json.rs` |
| Host tool calls + transcript | Integration with `TapeHost` / `OracleTape` | `tests/tools.rs` |
| Determinism (replay → identical hashes) | Integration; record then replay, assert hash equality | `tests/integration.rs` |
| TLS attestation | Feature-gated integration | `tls_attestation_nonzero_for_p256`, `tls_degrades_cleanly_for_non_p256` |
| ZK commitment / public inputs | Unit + feature-gated integration | `src/zkvm/commitment.rs`, `--features zkvm` |
