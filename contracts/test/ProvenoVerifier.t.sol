// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

import {HonkVerifier} from "../src/HonkVerifier.sol";
import {ProvenoVerifier} from "../src/ProvenoVerifier.sol";
import {PublicInputs} from "../src/Types.sol";

contract ProvenoVerifierTest is Test {
    HonkVerifier internal honk;
    ProvenoVerifier internal verifier;

    bytes internal proof;
    PublicInputs internal inputs;
    bytes32 internal policyHash;

    function setUp() public {
        proof = vm.readFileBinary("test/fixtures/proof.bin");
        inputs = _loadInputs();
        policyHash = inputs.policyHash;

        honk = new HonkVerifier();
        verifier = new ProvenoVerifier(policyHash, address(honk));
    }

    function test_verify_succeeds() public {
        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(proof, inputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertTrue(ok, "verify should return true on a valid proof");
        console.log("ProvenoVerifier.verify gas:", gasUsed);
    }

    function test_proof_tampered_reverts_with_proof_invalid() public {
        bytes memory tampered = bytes.concat(proof);
        tampered[0] = bytes1(uint8(tampered[0]) ^ 0xFF);
        vm.expectRevert(ProvenoVerifier.ProofInvalid.selector);
        verifier.verify(tampered, inputs);
    }

    function test_policy_hash_mismatch_reverts() public {
        PublicInputs memory bad = inputs;
        bad.policyHash = keccak256("not-the-real-policy");
        vm.expectRevert(ProvenoVerifier.PolicyHashMismatch.selector);
        verifier.verify(proof, bad);
    }

    function _loadInputs() internal view returns (PublicInputs memory pi) {
        string memory json = vm.readFile("test/fixtures/public_inputs.json");
        pi = PublicInputs({
            numSteps: uint32(vm.parseJsonUint(json, ".numSteps")),
            programHash: vm.parseJsonBytes32(json, ".programHash"),
            returnValue: int64(vm.parseJsonInt(json, ".returnValue")),
            toolResponsesHash: vm.parseJsonBytes32(json, ".toolResponsesHash"),
            inputHash: vm.parseJsonBytes32(json, ".inputHash"),
            outputHash: vm.parseJsonBytes32(json, ".outputHash"),
            attestationHash: vm.parseJsonBytes32(json, ".attestationHash"),
            policyHash: vm.parseJsonBytes32(json, ".policyHash")
        });
    }
}
