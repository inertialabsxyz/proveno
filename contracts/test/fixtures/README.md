# Proveno test fixtures

Real UltraHonk proof + public inputs over a tiny Lua program (`return 42`),
plus a representative `outputPayload` for the consumer-decode tests.

## Files

| File | Contents |
|---|---|
| `proof.bin` | UltraHonk proof bytes produced by `bb prove -t evm` |
| `public_inputs.bin` | Wire-format public inputs (194 × 32-byte words) as `bb prove` writes them |
| `public_inputs.json` | The same 8 logical fields in the order declared by `noir/src/main.nr` (field 7 is `attestationHash` — the bind-only per-call provenance commitment) |
| `policy_hash` | The 32-byte policy hash (hex-prefixed string, 66 chars) committed by the proof |
| `output_payload.bin` | The canonical output payload `abi.encode(int256(return_value))` (here `int256(42)`); `keccak256` of it equals `outputHash` |

## Regenerating

Run from the repo root. Requires the pinned toolchain on `PATH`: `nargo`
`1.0.0-beta.22`, `bb` `5.0.0-nightly.20260522`, `poseidon` `v0.3.0`
(`noir/Nargo.toml`). Other versions emit incompatible verifier/proof artifacts.

```bash
# 1. Pick any Lua program (here: return 42)
echo 'return 42' > /tmp/proveno-fixture/simple.lua

# 2. Compile -> bytecode JSON
cargo run -p proveno-compiler -- /tmp/proveno-fixture/simple.lua /tmp/proveno-fixture/compiled.json

# 3. Dry-run -> oracle tape + public inputs JSON
cargo run -p proveno_prover -- /tmp/proveno-fixture/compiled.json /tmp/proveno-fixture/dry_result.json

# 4. Build Noir witness (writes noir/Prover.toml)
cargo run -p proveno-noir -- /tmp/proveno-fixture/compiled.json /tmp/proveno-fixture/dry_result.json

# 5. Compile + execute the circuit
nargo execute --program-dir noir

# 6. Regenerate vk targeting the EVM (keccak random oracle, ZK)
bb write_vk -b noir/target/trace_verifier.json -o noir/target -t evm

# 7. Regenerate the Solidity verifier (required whenever the circuit changes —
#    the VK is embedded in HonkVerifier.sol)
bb write_solidity_verifier -k noir/target/vk -o noir/target/HonkVerifier.sol
cp noir/target/HonkVerifier.sol contracts/src/HonkVerifier.sol

# 8. Prove
bb prove -b noir/target/trace_verifier.json -w noir/target/trace_verifier.gz \
  -k noir/target/vk -o noir/target -t evm

# 9. Copy artifacts into this directory
cp noir/target/proof          contracts/test/fixtures/proof.bin
cp noir/target/public_inputs  contracts/test/fixtures/public_inputs.bin
# Regenerate public_inputs.json from public_inputs.bin (194 × 32-byte words; the
# six hash fields are byte-expanded, one byte per word) and policy_hash to match.
```

## About `output_payload.bin`

`output_payload.bin` is `abi.encode(int256(return_value))` — for this fixture
`abi.encode(int256(42))`, the 32-byte word `0x..2a`. It satisfies
`keccak256(outputPayload) == outputHash` **by construction**: the circuit binds
`outputHash` in-circuit to `keccak256(abi.encode(int256(return_value)))`
(`noir/src/main.nr`), the exact preimage and algorithm `ProvenoConsumer`
checks. The consumer's canonical-success test feeds this payload to the real
verifier and proof; the tamper test flips a byte to drive the
`OutputPayloadMismatch` path.
