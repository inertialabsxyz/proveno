# proveno-demo

A web demo crate, member of the **proveno** Cargo workspace. The user asks a question
in plain English; an axum server has an LLM generate a Lua program, compiles and runs it
on the proveno VM, produces a Noir ZK proof of the execution, and submits an on-chain
`ProvenoVerifier.verify` call — streaming every stage to the browser over SSE so an
audience can watch the pipeline run end-to-end.

This is a workspace member (`proveno-demo`), not a standalone repo. It path-deps the
in-repo core crates:

```toml
proveno = { path = "..", features = ["serde"] }
proveno-orchestrator = { path = "../orchestrator" }
```

`runner.rs` consumes those as a library. It also reaches the workspace root for two
runtime resources, resolved from `CARGO_MANIFEST_DIR/..`:
- `contracts/script/Deploy.s.sol` — deployed in managed-anvil mode (`chain.rs`).
- `noir/` — the circuit dir for proving (`runner.rs::locate_circuit_dir`).

## Layout

```
proveno-demo/
├── Cargo.toml          # workspace-member manifest; in-repo path deps
├── src/
│   ├── main.rs         # axum binary: bind 0.0.0.0:3001, call app()
│   ├── lib.rs          # Router (GET /health, GET /, POST /run); SSE wiring
│   ├── events.rs       # DemoEvent enum + ProofHashes — the SSE wire contract
│   ├── runner.rs       # run_pipeline(): LLM → compile → execute → prove → on-chain verify
│   ├── chain.rs        # on-chain ProvenoVerifier.verify; managed-anvil or external mode
│   └── public_inputs.rs# local mirror of the 8 public inputs (matches contracts/src/Types.sol)
├── static/             # frontend: index.html, style.css, app.js
└── tests/integration.rs# spawn_app() + HTTP/SSE integration tests (hermetic)
```

## The SSE wire contract

`POST /run` accepts `{ "task": string }` and streams `DemoEvent`s (`src/events.rs`). The
schema is a public contract with `static/app.js`; renaming a variant or field is a
breaking change and must update `tests/integration.rs`, which pins the wire behaviour.
Framing is `data: <json>\n\n`; the stream closes when the runner completes or errors.

## Running it

```bash
# Hermetic: integration tests need no ANTHROPIC_API_KEY (they assert the
# error path — no key → error event at generating_lua, stream closes cleanly).
cargo test -p proveno-demo

# Live: needs ANTHROPIC_API_KEY in env or a .env file (loaded via dotenvy).
# Optional ANTHROPIC_MODEL overrides the default.
cargo run -p proveno-demo            # listens on 0.0.0.0:3001
```

Chain modes (`chain.rs`): default **managed-anvil** spawns `anvil`, runs the deploy
script, and reuses the addresses (needs `anvil` + `forge` on PATH). Setting `RPC_URL`
selects **external** mode (`PROVENO_VERIFIER_ADDR` required; `CHAIN_ID`, `EXPLORER_BASE`
optional).

Demo VM limits are intentionally small (`GAS_LIMIT = 1_000_000`, `MAX_TOOL_CALLS = 10`)
to keep prove times sane and bound runaway LLM programs.

## Status / honest boundaries

- Execution → Noir proof → on-chain `verify` are wired and exercised.
- On-chain **settle** (`consumeResult`) is the flagship target, gated on the output
  encoding bridge (GH#46); not yet wired here.
- Provenance is **bind-only** — `attestation_hash` commits per call; a trusted provider
  is follow-on (the demo shows a Level-1 placeholder, not a real attestation).
- The UI attack-simulator is still a stub (GH-tracked); it is not a live `ProofInvalid`
  rejection yet.

## Conventions

Defer to the repo-root `CLAUDE.md` and `.claude/rules/` (commits, PRs, testing,
review-gate). Gate is `cargo test`. Every new SSE behaviour needs a test in
`tests/integration.rs`.
