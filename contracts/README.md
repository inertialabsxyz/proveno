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
