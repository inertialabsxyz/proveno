#!/usr/bin/env bash
# Set the circuit's oracle-tape bounds (MAX_TOOL_CALLS, MAX_TAPE_ENTRY_BYTES) and
# rebuild everything that depends on them: the Noir circuit constants and the
# mirrored Rust witness constants.
#
# Sibling of set_ceiling.sh, which does the same for MAX_STEPS. Together these are
# the only knobs that change the circuit, and therefore the gate count.
#
# The tape hash in noir/src/main.nr absorbs MAX_TOOL_CALLS * (MAX_TAPE_ENTRY_BYTES + 2)
# field positions unconditionally, so the cost is the product of the two.
#
# Usage: set_caps.sh <MAX_TOOL_CALLS> <MAX_TAPE_ENTRY_BYTES>
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

CALLS="${1:?usage: set_caps.sh <MAX_TOOL_CALLS> <MAX_TAPE_ENTRY_BYTES>}"
BYTES="${2:?usage: set_caps.sh <MAX_TOOL_CALLS> <MAX_TAPE_ENTRY_BYTES>}"

# 1. Noir circuit constants
perl -0pi -e "s/global MAX_TOOL_CALLS: u32 = \d+;/global MAX_TOOL_CALLS: u32 = $CALLS;/" noir/src/main.nr
perl -0pi -e "s/global MAX_TAPE_ENTRY_BYTES: u32 = \d+;/global MAX_TAPE_ENTRY_BYTES: u32 = $BYTES;/" noir/src/main.nr
# 2. Rust witness mirrors
perl -0pi -e "s/pub const MAX_TOOL_CALLS: usize = \d+;/pub const MAX_TOOL_CALLS: usize = $CALLS;/" proveno-noir/src/witness.rs
perl -0pi -e "s/pub const MAX_TAPE_ENTRY_BYTES: usize = \d+;/pub const MAX_TAPE_ENTRY_BYTES: usize = $BYTES;/" proveno-noir/src/witness.rs

echo "MAX_TOOL_CALLS=$CALLS MAX_TAPE_ENTRY_BYTES=$BYTES"

# 3. recompile the circuit (the witness writer is rebuilt lazily by callers)
( cd noir && nargo compile 2>&1 | grep -vE 'unused|warning|^\s*[0-9]+ \||^\s*│|^\s*-+$|policy_hash' || true )
