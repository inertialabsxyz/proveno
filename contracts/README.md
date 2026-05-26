# luai Contracts

Solidity contracts for verifying luai Noir UltraHonk proofs on-chain and
consuming their outputs.

## Contracts

| Contract | Description |
|---|---|
| `src/HonkVerifier.sol` | UltraHonk verifier generated from the Noir VK by `bb write_solidity_verifier` |
| `src/Types.sol` | `PublicInputs` struct + `PublicInputsLib.pack` (wire-format expansion) |
| `src/LuaiVerifier.sol` | Enforces `policyHash` and forwards the proof + packed public inputs to `HonkVerifier` |
| `src/LuaiConsumer.sol` | Example consumer: verifies, then asserts `keccak256(outputPayload) == outputHash`, then decodes a price-feed payload |

## Regenerating `HonkVerifier.sol`

`HonkVerifier.sol` is generated from the Noir circuit's verification key — it
is committed to the repo for reproducibility but is not hand-written. Whenever
`noir/src/main.nr` changes, regenerate the verifier:

```bash
# 1. Compile + execute the circuit (writes noir/target/trace_verifier.{json,gz}):
nargo execute --program-dir noir

# 2. Re-derive the verification key targeting the EVM (keccak random oracle, ZK):
bb write_vk -b noir/target/trace_verifier.json -o noir/target -t evm

# 3. Emit the Solidity verifier:
bb write_solidity_verifier -k noir/target/vk -o contracts/src/HonkVerifier.sol -t evm
```

The generated contract exposes
`verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)`.
Public inputs are passed in the wire format produced by `bb prove -t evm`:
194 × 32-byte words, with each `[u8; 32]` field byte-expanded into 32
single-byte entries.

## PublicInputs ordering

`PublicInputs` (in `Types.sol`) holds the eight `pub` parameters of
`noir/src/main.nr` in **declaration order**:

```solidity
struct PublicInputs {
    uint32  numSteps;
    bytes32 programHash;
    int64   returnValue;
    bytes32 toolResponsesHash;
    bytes32 inputHash;
    bytes32 outputHash;
    bytes32 tlsAttestationHash;
    bytes32 policyHash;
}
```

`PublicInputsLib.pack` produces the corresponding 194-element `bytes32[]`:

```text
[0]            numSteps
[1 .. 33)      programHash bytes
[33]           returnValue (int64 -> uint64 two's-complement -> bytes32)
[34 .. 66)     toolResponsesHash bytes
[66 .. 98)     inputHash bytes
[98 .. 130)    outputHash bytes
[130 .. 162)   tlsAttestationHash bytes
[162 .. 194)   policyHash bytes
```

Reordering fields breaks verification.

## Output payload schema

`LuaiConsumer.consumeResult` expects `outputPayload` to be:

```solidity
abi.encode(uint256 price, uint8 sourcesUsed, uint64 blockTimestamp)
```

| Field | Type | Description |
|---|---|---|
| `price` | `uint256` | Asset price scaled to 18 decimal places |
| `sourcesUsed` | `uint8` | Number of oracle sources that contributed |
| `blockTimestamp` | `uint64` | Unix timestamp of the observation |

The consumer asserts `keccak256(outputPayload) == inputs.outputHash`. Producing
an `outputHash` that matches `keccak256` of an abi-encoded payload is the
responsibility of the Lua program author — the circuit treats `outputHash`
opaquely and the consumer treats the payload opaquely.

## Usage

```bash
# Build
forge build --root contracts

# Test (loads the committed proof + public inputs from contracts/test/fixtures/)
forge test --root contracts

# Deploy (POLICY_HASH is the 0x-prefixed 32-byte policy commitment the
# verifier should accept):
POLICY_HASH=0x... forge script contracts/script/Deploy.s.sol \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```
