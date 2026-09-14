# Stage 1 split tooling

Executes the split described in `../repo-split-plan.md`.

```bash
brew install git-filter-repo
./planning/split/split.sh          # local only, nothing is pushed
PUSH=1 ./planning/split/split.sh   # also creates the repos and pushes
```

`REF` selects the commit to split from (default `main`); `SOURCE` the source
clone (default `/Users/andy/devel/proveno`); `ORG` the GitHub owner.

## What it does

`git filter-repo --paths-from-file` against three path manifests, producing
three clones with history preserved back to the first commit. Every tracked
file is assigned to exactly one repository except `.gitignore`, `LICENSE` and
`repo-split-plan.md`, which are deliberately in all three.

`inertialabsxyz/proveno` is **not** touched. Core lands in a new
`proveno-core`, so no published history is rewritten and no existing clone,
open PR or commit permalink breaks. Archive the monorepo by hand afterwards.

## What it does not do

Only `proveno-core`'s manifest rewrite is automated, because it is purely
subtractive: drop four modules from `src/lib.rs`, drop the members and the TLS
dependency block from `Cargo.toml`, drop the Makefile targets whose crates
left. That result is verified: `make check` passes, 667 tests, and the
dependency tree is 245 crates by default and 22 with none.

`proveno-zk` and `proveno-oracle` additionally need source edits, which are
judgement calls and should be reviewed rather than generated:

**proveno-zk** — `policy`, `zkvm` and `noir` become modules of a new
`proveno-zk` crate that depends on `proveno`. Every `crate::{host,types,vm,
compiler,isa,bytecode,parser}` path becomes `proveno::…`, including splitting
grouped `use crate::{…}` statements that mix core and local modules (seven
files). Manifest:

```toml
[features]
default  = ["std", "poseidon"]
std      = ["dep:serde_json", "proveno/std"]
serde    = ["dep:serde", "proveno/serde"]
zkvm     = []
poseidon = ["proveno/poseidon"]

[dependencies]
proveno = { git = "https://github.com/inertialabsxyz/proveno-core", tag = "v0.2.0", default-features = false }
```

`default-features = false` is load-bearing for the same reason it is on
`proveno-openvm` today: `poseidon` pulls cranelift, whose build script panics
on custom RISC-V triples.

This configuration was verified against a scratch tree: builds, clippy clean,
92 tests pass, and the zkVM guest config
(`--no-default-features --features zkvm,serde`) builds in 34 crates.

**proveno-oracle** — `tls` plus the orchestrator and demo. Depends on both
`proveno` and `proveno-zk` by tag. Not yet dry-run.

## Afterwards

- Each repository needs its own CI workflow. `make test` is a bare
  `cargo test`, so coverage shrinks silently when members leave.
- `CLAUDE.md` is currently written for the monorepo and needs splitting.
- The scripts that span the whole pipeline (`prove-openvm.sh`, `demo-*.sh`)
  invoke crates by `-p` across what become three repositories, and need
  rewriting against installed binaries.
