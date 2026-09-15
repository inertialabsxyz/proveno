# CLAUDE.md

This repository holds **no code**. It is the proveno umbrella: the project
overview and the cross-cutting documents that belong to no single crate.

## Where the code is

| Repository | Scope | Gate |
|---|---|---|
| [proveno-core](https://github.com/inertialabsxyz/proveno-core) | Runtime: parser, compiler, bytecode, VM, host, ISA, record/replay | `make check` |
| [proveno-zk](https://github.com/inertialabsxyz/proveno-zk) | Proving: policy, commitments, Noir circuit, OpenVM guest, contracts | `make check`, then `make test-prove` before a PR |
| [proveno-agent](https://github.com/inertialabsxyz/proveno-agent) | Agent: LLM orchestrator, demo server, TLS provenance | `make check` |
| [proveno-gateway](https://github.com/inertialabsxyz/proveno-gateway) | Gateway: MCP server and client, host policy, signed trace, replay | `make check` |

Dependencies point strictly inward, by git tag:
`proveno-agent -> proveno-zk -> proveno-core` and
`proveno-gateway -> proveno-core`.

If a task involves code, it belongs in one of those four. Work there, not here.

## What changes here

- `docs/architecture.md` — what proveno is and is not, the execution/provenance
  boundary, the two commitment schemes, the determinism invariants, and the
  known gaps.
- `docs/trust-model.md` — where the guarantee can break.
- `README.md` — the map.
- `planning/proveno-gateway-spec.md` — the gateway prototype spec, held here
  until proveno-gateway has settled. Subordinate to the architecture document.

## Rules for editing these documents

**The architecture document is the tie-breaker.** When a planning doc, a README
or a code comment contradicts it, the other one is wrong. That has already
happened once: an application repository was named `proveno-oracle` while this
document said, in bold, that proveno is not an oracle.

**Do not restate crate-level detail here.** Resource limits, feature flags,
module layouts and command lines belong in the CLAUDE.md of the repository that
owns them. Anything duplicated here will drift.

**Keep the provenance boundary honest.** The circuit binds attestation blobs, it
does not authenticate them. If a change makes it sound otherwise, that is a bug
in the prose.
