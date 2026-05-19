// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IOpenVmVerifier} from "./IOpenVmVerifier.sol";

/// @notice Always-pass stub verifier for testnet benchmarking.
/// Replaces the real OpenVM on-chain verifier until it is deployed on the
/// target network. Do NOT use in production.
contract StubOpenVmVerifier is IOpenVmVerifier {
    function verify(bytes calldata, bytes32) external pure override returns (bool) {
        return true;
    }
}
