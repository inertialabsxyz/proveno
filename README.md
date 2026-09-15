# proveno

Proveno runs **verifiable tasks**: small programs, often LLM-authored, written
in plain Lua. A task is compiled to bytecode and executed inside a
deterministic, sandboxed, bounded interpreter. A ZK proof attests that this
exact program ran over these exact inputs and produced this exact output, and a
verifier — off-chain, or a smart contract on-chain — checks it before acting on
the result. Every tool call is recorded in a transcript that can be replayed
bit-for-bit.

This repository is the **umbrella**: the project overview and the cross-cutting
documents that belong to no single crate. The code lives in three repositories.

## The repositories

| Repository | What it is | Depends on |
|---|---|---|
| [proveno-core](https://github.com/inertialabsxyz/proveno-core) | The runtime: parser, compiler, bytecode verifier, VM, host, record/replay. `no_std`-capable, no network, no proving. | — |
| [proveno-zk](https://github.com/inertialabsxyz/proveno-zk) | The proving layer: execution policy, public-input commitments, the Noir circuit and the OpenVM guest, the on-chain verifier and consumer contracts. | proveno-core |
| [proveno-agent](https://github.com/inertialabsxyz/proveno-agent) | The agent layer: an LLM orchestrator that writes Lua for a natural-language task, runs it, and can prove the result. Plus a demo server and a TLS provenance provider. | proveno-core, proveno-zk |

Dependencies point strictly inward, by git tag. Core knows nothing about
policy, proving or provenance.

```
proveno-agent ──> proveno-zk ──> proveno-core
```

## Where to start

- **Changing the VM, compiler, parser or the record/replay machinery** →
  proveno-core. `make check` is the gate.
- **Changing a circuit, a commitment, the execution policy or a contract** →
  proveno-zk. `make check`, then `make test-prove` before opening a PR.
- **Changing how tasks are authored, run or demonstrated** → proveno-agent.

## Documents here

- [Architecture](docs/architecture.md) — what proveno is and, just as
  importantly, what it is not. Read this before arguing about scope.
- [Trust model](docs/trust-model.md) — where the guarantee can break, named
  honestly, each with a category and a mitigation.
- [Canonical serialization](https://github.com/inertialabsxyz/proveno-core/blob/main/docs/canonical-serialization.md)
  lives in core, because the algorithm is core's.

## History

This repository was the monorepo until September 2026. It was split so that the
runtime could be used without dragging the oracle application along; the plan
and the tooling are in `planning/repo-split-plan.md` in each of the three
repositories. The full pre-split history is preserved here and, filtered, in
each of the three.
