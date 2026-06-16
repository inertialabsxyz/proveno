// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ProvenoVerifier} from "./ProvenoVerifier.sol";
import {PublicInputs} from "./Types.sol";

/// @notice Example consumer that decodes and stores a proven result after the
/// proveno proof and the output-payload commitment both verify on-chain.
contract ProvenoConsumer {
    error OutputPayloadMismatch();

    event ResultConsumed(int256 result);

    ProvenoVerifier public immutable provenoVerifier;

    int256 public lastResult;

    constructor(address _provenoVerifier) {
        provenoVerifier = ProvenoVerifier(_provenoVerifier);
    }

    /// @notice Verify a proveno proof, then decode and store the asserted result.
    ///
    /// @dev `outputPayload` is the canonical output payload
    /// `abi.encode(int256(return_value))`, and its `keccak256` must equal
    /// `inputs.outputHash`. The match holds by construction: the circuit binds
    /// `outputHash` in-circuit to `keccak256(abi.encode(int256(return_value)))`
    /// (`noir/src/main.nr`), so this contract checks the same preimage and
    /// algorithm and decodes the single proven `int256`.
    ///
    /// Order of checks is important: the proof is verified BEFORE the payload
    /// check, so a bogus proof always reverts with `ProofInvalid` regardless of
    /// the payload.
    function consumeResult(
        bytes calldata proof,
        PublicInputs calldata inputs,
        bytes calldata outputPayload
    ) external {
        provenoVerifier.verify(proof, inputs);

        if (keccak256(outputPayload) != inputs.outputHash) revert OutputPayloadMismatch();

        int256 result = abi.decode(outputPayload, (int256));

        lastResult = result;

        emit ResultConsumed(result);
    }
}
