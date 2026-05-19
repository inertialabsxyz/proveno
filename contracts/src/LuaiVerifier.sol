// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PublicInputs} from "./Types.sol";
import {IOpenVmVerifier} from "./IOpenVmVerifier.sol";

/// @notice Verifies a luai zkVM proof and enforces a policy hash constraint.
contract LuaiVerifier {
    error PolicyHashMismatch();
    error ProofInvalid();

    bytes32 public immutable expectedPolicyHash;
    IOpenVmVerifier public immutable openVmVerifier;

    constructor(bytes32 _expectedPolicyHash, address _openVmVerifier) {
        expectedPolicyHash = _expectedPolicyHash;
        openVmVerifier = IOpenVmVerifier(_openVmVerifier);
    }

    /// @notice Verify a luai proof.
    /// @param proof       Raw OpenVM proof bytes.
    /// @param inputs      The six public-input commitments produced by the luai zkVM.
    /// @return            Always true on success; reverts on any failure.
    function verify(bytes calldata proof, PublicInputs calldata inputs) external view returns (bool) {
        if (inputs.policyHash != expectedPolicyHash) revert PolicyHashMismatch();

        // Hash the six fields in canonical order to form the single public-inputs hash
        // expected by the OpenVM verifier.
        bytes32 piHash = keccak256(abi.encode(
            inputs.programHash,
            inputs.inputHash,
            inputs.toolResponsesHash,
            inputs.outputHash,
            inputs.tlsAttestationHash,
            inputs.policyHash
        ));

        if (!openVmVerifier.verify(proof, piHash)) revert ProofInvalid();

        return true;
    }
}
