// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ProvenoVerifier} from "./ProvenoVerifier.sol";
import {PublicInputs} from "./Types.sol";

/// @notice Example consumer that decodes and stores a price-feed payload after
/// the proveno proof and the payload commitment both verify on-chain.
contract ProvenoConsumer {
    error OutputPayloadMismatch();

    event PriceUpdated(uint256 price, uint8 sourcesUsed, uint64 blockTimestamp);

    ProvenoVerifier public immutable provenoVerifier;

    uint256 public lastPrice;
    uint8   public lastSourcesUsed;
    uint64  public lastBlockTimestamp;

    constructor(address _provenoVerifier) {
        provenoVerifier = ProvenoVerifier(_provenoVerifier);
    }

    /// @notice Verify a proveno proof, then decode and store the asserted price-feed
    /// payload.
    ///
    /// @dev `outputPayload` must abi-decode as `(uint256 price, uint8 sourcesUsed,
    /// uint64 blockTimestamp)` and its `keccak256` must equal `inputs.outputHash`.
    /// Achieving that match is the responsibility of the Lua program author:
    /// the program must arrange for its `outputHash` commitment to equal
    /// `keccak256(outputPayload)` — i.e. the program emits a result whose
    /// canonical encoding is the payload, and pins `outputHash` accordingly.
    /// This contract treats the payload bytes opaquely and only enforces the
    /// keccak256 binding.
    ///
    /// Order of checks is important: the proof is verified BEFORE
    /// the payload check, so a bogus proof always reverts with `ProofInvalid`
    /// regardless of the payload.
    function consumeResult(
        bytes calldata proof,
        PublicInputs calldata inputs,
        bytes calldata outputPayload
    ) external {
        provenoVerifier.verify(proof, inputs);

        if (keccak256(outputPayload) != inputs.outputHash) revert OutputPayloadMismatch();

        (uint256 price, uint8 sourcesUsed, uint64 blockTimestamp) =
            abi.decode(outputPayload, (uint256, uint8, uint64));

        lastPrice = price;
        lastSourcesUsed = sourcesUsed;
        lastBlockTimestamp = blockTimestamp;

        emit PriceUpdated(price, sourcesUsed, blockTimestamp);
    }
}
