// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Minimal interface for the OpenVM on-chain proof verifier.
/// Replace `address(0)` in LuaiVerifier with the deployed contract address once known.
interface IOpenVmVerifier {
    /// @return true iff `proof` is a valid OpenVM proof for `publicInputsHash`.
    function verify(bytes calldata proof, bytes32 publicInputsHash) external view returns (bool);
}
