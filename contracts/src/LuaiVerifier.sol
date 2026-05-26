// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PublicInputs, PublicInputsLib} from "./Types.sol";

interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}

/// @notice Verifies a luai UltraHonk proof against the expected policy hash.
contract LuaiVerifier {
    using PublicInputsLib for PublicInputs;

    error PolicyHashMismatch();
    error ProofInvalid();

    /// @notice Policy hash that every accepted proof must commit to.
    bytes32 public immutable expectedPolicyHash;

    /// @notice Underlying UltraHonk Solidity verifier produced by
    /// `bb write_solidity_verifier`.
    IHonkVerifier public immutable honkVerifier;

    constructor(bytes32 _expectedPolicyHash, address _honkVerifier) {
        expectedPolicyHash = _expectedPolicyHash;
        honkVerifier = IHonkVerifier(_honkVerifier);
    }

    /// @notice Verify a luai proof. Reverts with `PolicyHashMismatch` if the
    /// proof commits to a different policy than this contract enforces, or
    /// with `ProofInvalid` if the UltraHonk verifier rejects the proof.
    ///
    /// @dev The generated `HonkVerifier` reverts with its own `Errors.*`
    /// selectors (e.g. `SumcheckFailed`, `ProofLengthWrong`) on malformed
    /// proofs rather than returning `false`. We translate every rejection —
    /// whether a `false` return or a revert — into a uniform `ProofInvalid`
    /// so callers only need to match one selector.
    function verify(bytes calldata proof, PublicInputs calldata inputs)
        external
        view
        returns (bool)
    {
        if (inputs.policyHash != expectedPolicyHash) revert PolicyHashMismatch();

        bytes32[] memory packed = PublicInputsLib.pack(inputs);
        try honkVerifier.verify(proof, packed) returns (bool ok) {
            if (!ok) revert ProofInvalid();
        } catch {
            revert ProofInvalid();
        }

        return true;
    }
}
