// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Six 32-byte commitments produced by the luai zkVM, in canonical order.
/// Matches the Rust `PublicInputs` layout in `src/zkvm/commitment.rs`.
struct PublicInputs {
    bytes32 programHash;
    bytes32 inputHash;
    bytes32 toolResponsesHash;
    bytes32 outputHash;
    bytes32 tlsAttestationHash;
    bytes32 policyHash;
}
