# luai Contracts

Solidity contracts for verifying luai zkVM proofs on-chain and consuming their outputs.

## Contracts

| Contract | Description |
|---|---|
| `src/Types.sol` | `PublicInputs` struct shared across contracts |
| `src/IOpenVmVerifier.sol` | Interface for the OpenVM on-chain proof verifier |
| `src/LuaiVerifier.sol` | Verifies a proof and enforces a `policyHash` constraint |
| `src/LuaiConsumer.sol` | Example consumer that stores the latest price feed result |

## PublicInputs ABI encoding

`PublicInputs` is a Solidity struct with six `bytes32` fields in this exact order:

```solidity
struct PublicInputs {
    bytes32 programHash;       // SHA-256 of the compiled Lua bytecode
    bytes32 inputHash;         // SHA-256 of the task input
    bytes32 toolResponsesHash; // SHA-256 of the oracle tape commitment
    bytes32 outputHash;        // SHA-256 of the program output
    bytes32 tlsAttestationHash;// SHA-256 of the TLS attestation record
    bytes32 policyHash;        // SHA-256 of the OraclePolicy JSON
}
```

This matches the Rust `PublicInputs` layout in `src/zkvm/commitment.rs`. Each field is the
32-byte raw SHA-256 digest — **not** hex-encoded.

When `LuaiVerifier` calls the OpenVM verifier it hashes all six fields via:

```solidity
bytes32 piHash = keccak256(abi.encode(
    inputs.programHash,
    inputs.inputHash,
    inputs.toolResponsesHash,
    inputs.outputHash,
    inputs.tlsAttestationHash,
    inputs.policyHash
));
```

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

## Usage

```bash
# Build
forge build

# Test
forge test

# Deploy (replace placeholders)
forge script script/Deploy.s.sol \
  --rpc-url <RPC_URL> \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

## OpenVM verifier address

`LuaiVerifier` is constructed with the address of the deployed OpenVM on-chain verifier.
Until that address is known, deploy a stub that implements `IOpenVmVerifier`. Update the
constructor argument when the verifier is available on the target network.

## Real OpenVM Verifier

To use a real Groth16 proof verifiable on-chain, follow these steps.

### 1. Generate an EVM-compatible proving key

```bash
cargo openvm keygen --evm
```

This produces an EVM-compatible proving key alongside the standard app key.

### 2. Prove with EVM output

```bash
# Compile the Lua program
cargo run -p luai-compiler -- source.lua compiled.json

# Dry-run to produce oracle tape + public inputs
cargo run -p luai-prover -- compiled.json dry_result.json

# Encode for OpenVM
luai-openvm-encoder compiled.json dry_result.json

# Prove with EVM Groth16 wrapper (produces proof.json)
cargo openvm prove evm --input encoded_input.bin
```

`proof.json` contains the Groth16 calldata targeting the generated `Groth16Verifier.sol`.

### 3. Deploy the Groth16 verifier

OpenVM emits a `Groth16Verifier.sol` alongside the proof. Deploy it on the target network:

```bash
forge create contracts/src/Groth16Verifier.sol:Groth16Verifier \
  --rpc-url $RPC_URL --private-key $PRIVATE_KEY
# note the deployed address as GROTH16_ADDR
```

### 4. Deploy the OpenVmGroth16Verifier adapter

`OpenVmGroth16Verifier` wraps the gnark-generated verifier and implements `IOpenVmVerifier`:

```bash
forge create contracts/src/OpenVmGroth16Verifier.sol:OpenVmGroth16Verifier \
  --constructor-args $GROTH16_ADDR \
  --rpc-url $RPC_URL --private-key $PRIVATE_KEY
# note the deployed address as OPENVM_VERIFIER_ADDR
```

### 5. Deploy LuaiVerifier with the real verifier

```bash
OPENVM_VERIFIER_ADDR=0x... POLICY_HASH=0x... \
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

When `OPENVM_VERIFIER_ADDR` is set, the deploy script uses it directly and skips deploying
`StubOpenVmVerifier`. When unset, the stub is deployed as before.

### publicInputsHash computation

`LuaiVerifier` computes:

```solidity
bytes32 piHash = keccak256(abi.encode(
    inputs.programHash, inputs.inputHash, inputs.toolResponsesHash,
    inputs.outputHash, inputs.tlsAttestationHash, inputs.policyHash
));
```

For six `bytes32` values, `abi.encode` is plain concatenation (192 bytes total), so this equals
`keccak256(raw_public_values)` — matching the 192 bytes committed via OpenVM's `reveal_bytes32`.

### Known limitation: BN254 field reduction

Groth16 public signals must be BN254 field elements (< 2^254). The `OpenVmGroth16Verifier`
adapter reduces `piHash` modulo the BN254 field order before forwarding it to the gnark
verifier. OpenVM's prover must produce the proof with the same reduction applied to the
public inputs hash. If the generated `Groth16Verifier.sol` uses a different encoding (e.g.
top-byte mask instead of modular reduction), update `OpenVmGroth16Verifier.verify` to match.
