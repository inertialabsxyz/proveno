# Commits

**Gate:** `cargo test` must pass before every commit. No exceptions.

**Auto-commit:** Commit each logical change as it is completed, without waiting to be asked. Use judgment to determine when a change is coherent and complete — do not commit mid-feature or bundle unrelated changes.

**Message format:** `type(scope): short description`

- `type` — `feat`, `fix`, `refactor`, `test`, `docs`, `chore`
- `scope` — the crate or module. Common scopes:
  - Crates: `compiler`, `prover`, `orchestrator`, `openvm`, `zkvm`
  - Core modules: `parser`, `bytecode`, `vm`, `host`, `tls`, `types`
  - Cross-cutting: `tests`, `docs`, `repo`, `planning`, `ci`
- Description — imperative, lowercase, no period. 72 characters total max.

```
feat(orchestrator): add Ollama backend and --generate-only flag
fix(zkvm): correct p256_verified call in commitment test
refactor(tls): move chain verification into root crate
test(integration): add tls_attestation_nonzero_for_p256
docs(repo): document resource limits and proving pipeline
```

**Scope:** One logical change per commit. Don't bundle unrelated fixes.
