# Proveno test fixtures

Real UltraHonk proof + public inputs over a tiny Lua program (`return 42`),
plus a representative `outputPayload` for the consumer-decode tests.

## Files

| File | Contents |
|---|---|
| `proof.bin` | UltraHonk proof bytes produced by `bb prove -t evm` |
| `public_inputs.bin` | Wire-format public inputs (194 × 32-byte words) as `bb prove` writes them |
| `public_inputs.json` | The same 8 logical fields in the order declared by `noir/src/main.nr` |
| `policy_hash` | The 32-byte policy hash (hex-prefixed string, 66 chars) committed by the proof |
| `output_payload.bin` | A demo `abi.encode(uint256, uint8, uint64)` price payload used by `ProvenoConsumer` tests |

## Regenerating

Run from the repo root. Requires `nargo` and `bb` on `PATH`.

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

# 7. Prove
bb prove -b noir/target/trace_verifier.json -w noir/target/trace_verifier.gz \
  -k noir/target/vk -o noir/target -t evm

# 8. Copy artifacts into this directory
cp noir/target/proof          contracts/test/fixtures/proof.bin
cp noir/target/public_inputs  contracts/test/fixtures/public_inputs.bin
# Update public_inputs.json and policy_hash to match the new run
```

## About `output_payload.bin`

`output_payload.bin` is `abi.encode(2000e18, uint8(3), uint64(1716000000))`. It
is **not** required to satisfy `keccak256(outputPayload) == outputHash` for
this proof — the current proveno pipeline commits `outputHash` as
`SHA-256(canonical_serialize(return_value) || logs || transcript)`, so a real
proof cannot produce a payload whose keccak256 matches `outputHash` without an
encoding bridge in the Lua program itself. The consumer tests deploy a passing
mock verifier alongside the real one so the keccak256 → `outputHash` assertion
can be exercised on crafted inputs while the real proof still drives the
`ProofInvalid` path.
