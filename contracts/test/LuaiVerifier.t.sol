// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LuaiVerifier} from "../src/LuaiVerifier.sol";
import {IOpenVmVerifier} from "../src/IOpenVmVerifier.sol";
import {PublicInputs} from "../src/Types.sol";

/// @dev Controllable stub that accepts or rejects any proof.
contract MockOpenVmVerifier is IOpenVmVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function verify(bytes calldata, bytes32) external view returns (bool) {
        return shouldPass;
    }
}

contract LuaiVerifierTest is Test {
    bytes32 constant POLICY_HASH = keccak256("test-policy");

    LuaiVerifier verifier;
    MockOpenVmVerifier passingMock;
    MockOpenVmVerifier failingMock;

    function setUp() public {
        passingMock = new MockOpenVmVerifier(true);
        failingMock = new MockOpenVmVerifier(false);
        verifier = new LuaiVerifier(POLICY_HASH, address(passingMock));
    }

    function _makeInputs(bytes32 policyHash) internal pure returns (PublicInputs memory) {
        return PublicInputs({
            programHash: keccak256("program"),
            inputHash: keccak256("input"),
            toolResponsesHash: keccak256("tools"),
            outputHash: keccak256("output"),
            tlsAttestationHash: keccak256("tls"),
            policyHash: policyHash
        });
    }

    function test_valid_proof_passes() public view {
        PublicInputs memory inputs = _makeInputs(POLICY_HASH);
        bool ok = verifier.verify(hex"", inputs);
        assertTrue(ok);
    }

    function test_wrong_policy_hash_reverts() public {
        PublicInputs memory inputs = _makeInputs(keccak256("wrong-policy"));
        vm.expectRevert(LuaiVerifier.PolicyHashMismatch.selector);
        verifier.verify(hex"", inputs);
    }

    function test_invalid_proof_reverts() public {
        LuaiVerifier failVerifier = new LuaiVerifier(POLICY_HASH, address(failingMock));
        PublicInputs memory inputs = _makeInputs(POLICY_HASH);
        vm.expectRevert(LuaiVerifier.ProofInvalid.selector);
        failVerifier.verify(hex"", inputs);
    }
}
