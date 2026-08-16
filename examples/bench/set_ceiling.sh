#!/usr/bin/env bash
# Set the circuit's step ceiling (MAX_STEPS) and rebuild everything that
# depends on it: the Noir circuit constant and the mirrored Rust witness
# constant. This is the ONLY knob that changes the circuit, and therefore the
# only knob that changes the gate count.
#
# Usage: set_ceiling.sh <MAX_STEPS>
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

N="${1:?usage: set_ceiling.sh <MAX_STEPS>}"

# 1. Noir circuit constant
perl -0pi -e "s/global MAX_STEPS: u32 = \d+;/global MAX_STEPS: u32 = $N;/" noir/src/main.nr
# 2. Rust witness mirror
perl -0pi -e "s/pub const MAX_STEPS: usize = \d+;/pub const MAX_STEPS: usize = $N;/" proveno-noir/src/witness.rs

echo "MAX_STEPS set to $N"
grep -n 'MAX_STEPS' noir/src/main.nr | head -1
grep -n 'pub const MAX_STEPS' proveno-noir/src/witness.rs | head -1

# 3. rebuild the witness writer (compile-time constant) and recompile the circuit
echo "rebuilding proveno-noir ..."
cargo build -q -p proveno-noir
echo "compiling circuit (nargo) ..."
( cd noir && nargo compile 2>&1 | grep -vE 'unused|warning|^\s*[0-9]+ \||^\s*│|^\s*-+$|policy_hash' || true )
echo "done."
