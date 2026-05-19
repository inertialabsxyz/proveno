// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PublicInputs} from "./Types.sol";
import {LuaiVerifier} from "./LuaiVerifier.sol";

/// @notice Example consumer that stores the latest price feed result from a verified luai proof.
contract LuaiConsumer {
    LuaiVerifier public immutable verifier;

    uint256 public lastPrice;
    uint8 public lastSourcesUsed;
    uint64 public lastBlockTimestamp;

    constructor(address _verifier) {
        verifier = LuaiVerifier(_verifier);
    }

    /// @notice Submit a verified luai result and store the decoded price data.
    /// @param proof         Raw OpenVM proof bytes forwarded to LuaiVerifier.
    /// @param inputs        The six public-input commitments.
    /// @param outputPayload ABI-encoded `(uint256 price, uint8 sourcesUsed, uint64 blockTimestamp)`.
    function consumeResult(
        bytes calldata proof,
        PublicInputs calldata inputs,
        bytes calldata outputPayload
    ) external {
        verifier.verify(proof, inputs);

        (uint256 price, uint8 sourcesUsed, uint64 blockTimestamp) =
            abi.decode(outputPayload, (uint256, uint8, uint64));

        lastPrice = price;
        lastSourcesUsed = sourcesUsed;
        lastBlockTimestamp = blockTimestamp;
    }
}
