// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {HonkVerifier} from "../src/HonkVerifier.sol";
import {ProvenoVerifier} from "../src/ProvenoVerifier.sol";
import {ProvenoConsumer} from "../src/ProvenoConsumer.sol";
import {PublicInputs} from "../src/Types.sol";

contract ProvenoConsumerTest is Test {
    // Real proof + verifier path: the circuit now binds outputHash in-circuit to
    // keccak256(abi.encode(int256(return_value))), the exact commitment the
    // consumer checks, so every test runs against the real UltraHonk verifier.
    HonkVerifier internal honk;
    ProvenoVerifier internal verifier;
    ProvenoConsumer internal consumer;

    bytes internal proof;
    PublicInputs internal realInputs;

    // The fixture proves `return 42`; its canonical payload is abi.encode(int256(42)).
    int256 internal constant DEMO_RESULT = 42;

    function setUp() public {
        proof = vm.readFileBinary("test/fixtures/proof.bin");
        realInputs = _loadInputs();

        honk = new HonkVerifier();
        verifier = new ProvenoVerifier(realInputs.policyHash, address(honk));
        consumer = new ProvenoConsumer(address(verifier));
    }

    /// Canonical path: real proof, real public inputs, and the canonical output
    /// payload abi.encode(int256(return_value)) whose keccak256 the circuit bound
    /// to outputHash in-circuit. consumeResult must succeed and store the result.
    function test_consumes_canonical_payload_succeeds() public {
        bytes memory payload = abi.encode(int256(realInputs.returnValue));
        // The payload matches the checked-in fixture and the proven outputHash.
        assertEq(payload, vm.readFileBinary("test/fixtures/output_payload.bin"));
        assertEq(keccak256(payload), realInputs.outputHash);

        vm.expectEmit(false, false, false, true, address(consumer));
        emit ProvenoConsumer.ResultConsumed(DEMO_RESULT);
        consumer.consumeResult(proof, realInputs, payload);

        assertEq(consumer.lastResult(), DEMO_RESULT);
    }

    function test_output_payload_mismatch_reverts() public {
        // The proof verifies, but a tampered payload no longer matches outputHash.
        bytes memory payload = abi.encode(int256(realInputs.returnValue));
        bytes memory tampered = bytes.concat(payload);
        tampered[0] = bytes1(uint8(tampered[0]) ^ 0xFF);

        vm.expectRevert(ProvenoConsumer.OutputPayloadMismatch.selector);
        consumer.consumeResult(proof, realInputs, tampered);
    }

    function test_proof_tampered_reverts_with_proof_invalid() public {
        // Proof check runs before the payload check, so any payload triggers
        // `ProofInvalid` once the proof is bogus.
        bytes memory tamperedProof = bytes.concat(proof);
        tamperedProof[0] = bytes1(uint8(tamperedProof[0]) ^ 0xFF);

        bytes memory payload = abi.encode(int256(realInputs.returnValue));

        vm.expectRevert(ProvenoVerifier.ProofInvalid.selector);
        consumer.consumeResult(tamperedProof, realInputs, payload);
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
