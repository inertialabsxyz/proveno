// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenVmGroth16Verifier, IGroth16Verifier} from "../src/OpenVmGroth16Verifier.sol";
import {IOpenVmVerifier} from "../src/IOpenVmVerifier.sol";

/// @dev Minimal stub for the gnark-generated Groth16Verifier — controllable pass/fail.
contract MockGroth16Verifier is IGroth16Verifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[1] calldata
    ) external view override returns (bool) {
        return result;
    }
}

contract OpenVmGroth16VerifierTest is Test {
    MockGroth16Verifier passingGroth16;
    MockGroth16Verifier failingGroth16;
    OpenVmGroth16Verifier passingAdapter;
    OpenVmGroth16Verifier failingAdapter;

    function setUp() public {
        passingGroth16 = new MockGroth16Verifier(true);
        failingGroth16 = new MockGroth16Verifier(false);
        passingAdapter = new OpenVmGroth16Verifier(address(passingGroth16));
        failingAdapter = new OpenVmGroth16Verifier(address(failingGroth16));
    }

    /// Compile-time check: OpenVmGroth16Verifier implements IOpenVmVerifier.
    function test_implements_IOpenVmVerifier() public view {
        IOpenVmVerifier asInterface = IOpenVmVerifier(address(passingAdapter));
        assertTrue(address(asInterface) != address(0));
    }

    function test_delegates_pass_to_groth16_verifier() public view {
        bytes memory proof = _makeProof();
        bytes32 piHash = keccak256("test-inputs");
        assertTrue(passingAdapter.verify(proof, piHash));
    }

    function test_delegates_fail_to_groth16_verifier() public view {
        bytes memory proof = _makeProof();
        bytes32 piHash = keccak256("test-inputs");
        assertFalse(failingAdapter.verify(proof, piHash));
    }

    /// bytes32 all-ones exceeds BN254 field size; reduction must not revert.
    function test_reduces_large_hash_to_field_element() public view {
        bytes32 largeHash = bytes32(type(uint256).max);
        bytes memory proof = _makeProof();
        passingAdapter.verify(proof, largeHash);
    }

    /// groth16Verifier address is stored immutably.
    function test_stores_groth16_verifier_address() public view {
        assertEq(address(passingAdapter.groth16Verifier()), address(passingGroth16));
    }

    function _makeProof() internal pure returns (bytes memory) {
        uint[2] memory pA = [uint(1), uint(2)];
        uint[2][2] memory pB = [[uint(3), uint(4)], [uint(5), uint(6)]];
        uint[2] memory pC = [uint(7), uint(8)];
        return abi.encode(pA, pB, pC);
    }
}
