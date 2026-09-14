#!/usr/bin/env bash
# Stage 1 of planning/repo-split-plan.md: split this monorepo into three
# history-preserving repositories.
#
#   ./planning/split/split.sh            # local only, inspect the result
#   PUSH=1 ./planning/split/split.sh     # also create the repos and push
#
# Requires git-filter-repo (brew install git-filter-repo) and gh.
# inertialabsxyz/proveno is deliberately left untouched: core lands in a new
# proveno-core so no published history is rewritten.
set -euo pipefail

SOURCE=${SOURCE:-/Users/andy/devel/proveno}
WORK=${WORK:-/tmp/proveno-split}
ORG=${ORG:-inertialabsxyz}
REF=${REF:-main}
SPEC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v git-filter-repo >/dev/null || { echo "git-filter-repo not installed"; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK"

split_one() {
  local name=$1 spec=$2
  echo "=== $name ==="
  git clone --no-local --quiet --branch "$REF" "$SOURCE" "$WORK/$name"
  ( cd "$WORK/$name"
    git filter-repo --force --quiet --paths-from-file "$SPEC/$spec"
    git remote remove origin 2>/dev/null || true
    echo "  commits: $(git rev-list --count HEAD)  files: $(git ls-files | wc -l | tr -d ' ')"
  )
}

split_one proveno-core   core-paths.txt
split_one proveno-zk     zk-paths.txt
split_one proveno-oracle oracle-paths.txt

# ── Post-split fixups for core ───────────────────────────────────────────────
# Only core is automated here: its rewrite is purely subtractive. proveno-zk
# and proveno-oracle additionally need `crate::{host,types,vm,compiler,isa}`
# rewritten to `proveno::…`, which is a judgement call per file. See README.md.
( cd "$WORK/proveno-core"
  python3 - <<'PY'
import pathlib
p = pathlib.Path('src/lib.rs'); s = p.read_text()
for m in ['pub mod noir;\n', 'pub mod policy;\n', 'pub mod tls;\n']:
    s = s.replace(m, '')
s = s.replace('\n#[cfg(feature = "zkvm")]\npub mod zkvm;\n', '')
p.write_text(s)

p = pathlib.Path('Cargo.toml'); s = p.read_text()
import re
s = re.sub(r'members = \[[^\]]*\]', 'members = ["proveno-compiler"]', s, count=1)
s = s.replace('zkvm = []\n\n', '')
i, j = s.index('# TLS attestation producer.'), s.index('\n[dependencies]')
s = s[:i].rstrip() + '\n' + s[j:]
for d in ['p256', 'p384', 'x509-cert', 'webpki-roots', 'rsa', 'rustls',
          'reqwest', 'openvm', 'hex', 'dotenvy', 'tempfile']:
    s = '\n'.join(l for l in s.split('\n') if not l.startswith(d + ' ='))
p.write_text(s)

p = pathlib.Path('Makefile'); s = p.read_text()
s = '\n\n'.join(b for b in s.split('\n\n') if not any(
    t in b for t in ['test-prove:', 'build-openvm:', 'prove-openvm:', 'prove-examples:', 'test-tls:']))
s = s.replace('check: lint test test-tls test-nostd', 'check: lint test test-nostd')
s = s.replace('cargo test -p proveno --no-default-features --features "std,zkvm"',
              'cargo test -p proveno --no-default-features --features "std"')
s = s.replace('\tRUSTFLAGS="-D warnings" cargo build -p proveno --no-default-features --features zkvm\n', '')
s = s.replace('cargo build -p proveno --no-default-features --features "std,zkvm"',
              'cargo build -p proveno --no-default-features --features "std"')
s = '\n'.join(l for l in s.split('\n')
              if not any(t in l for t in ['test-prove ', 'build-openvm ', 'prove-openvm ',
                                          'prove-examples ', 'test-tls ']))
p.write_text(s)
PY
  cargo fmt --all >/dev/null 2>&1 || true
  cargo generate-lockfile >/dev/null 2>&1 || true
)

echo
echo "Local split under $WORK. proveno-core is buildable; verify with:"
echo "  (cd $WORK/proveno-core && make check)"
echo "proveno-zk and proveno-oracle still need their manifests written; see README.md."
echo
if [ "${PUSH:-0}" = "1" ]; then
  for r in proveno-core proveno-zk proveno-oracle; do
    gh repo create "$ORG/$r" --private --source "$WORK/$r" --remote origin --push
  done
  echo "Archive the monorepo by hand when ready:  gh repo archive $ORG/proveno"
else
  echo "PUSH not set: nothing was created or pushed."
fi
