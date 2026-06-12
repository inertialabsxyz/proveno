// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

import {HonkVerifier} from "../src/HonkVerifier.sol";
import {IHonkVerifier, ProvenoVerifier} from "../src/ProvenoVerifier.sol";
import {ProvenoConsumer} from "../src/ProvenoConsumer.sol";
import {PublicInputs} from "../src/Types.sol";

/// @dev Passes any proof. Used to exercise consumer logic that lives downstream
/// of the proof check — the encoding bridge from `outputHash` to `outputPayload`
/// is the responsibility of the Lua program author and cannot be satisfied by
/// the current pipeline against a real proof (the circuit commits `outputHash`
/// via SHA-256, the consumer enforces it via keccak256). The real proof still
/// drives the `ProofInvalid` revert test below.
contract PassingHonkVerifier is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract ProvenoConsumerTest is Test {
    // Real proof + verifier path — exercises the actual UltraHonk verifier.
    HonkVerifier internal honk;
    ProvenoVerifier internal realVerifier;
    ProvenoConsumer internal realConsumer;

    // Mock-backed path — bypasses proof verification so the consumer's payload
    // and decode logic can be exercised on crafted inputs.
    PassingHonkVerifier internal passingHonk;
    ProvenoVerifier internal mockVerifier;
    ProvenoConsumer internal mockConsumer;

    bytes internal proof;
    PublicInputs internal realInputs;

    // Demo price-feed values matching `output_payload.bin`.
    uint256 internal constant DEMO_PRICE = 2000e18;
    uint8   internal constant DEMO_SOURCES = 3;
    uint64  internal constant DEMO_TS = 1716000000;

    function setUp() public {
        proof = vm.readFileBinary("test/fixtures/proof.bin");
        realInputs = _loadInputs();

        honk = new HonkVerifier();
        realVerifier = new ProvenoVerifier(realInputs.policyHash, address(honk));
        realConsumer = new ProvenoConsumer(address(realVerifier));

        passingHonk = new PassingHonkVerifier();
        mockVerifier = new ProvenoVerifier(realInputs.policyHash, address(passingHonk));
        mockConsumer = new ProvenoConsumer(address(mockVerifier));
    }

    function test_consumes_result_and_stores_price() public {
        bytes memory payload = abi.encode(DEMO_PRICE, DEMO_SOURCES, DEMO_TS);
        PublicInputs memory pi = realInputs;
        pi.outputHash = keccak256(payload);

        vm.expectEmit(false, false, false, true, address(mockConsumer));
        emit ProvenoConsumer.PriceUpdated(DEMO_PRICE, DEMO_SOURCES, DEMO_TS);
        mockConsumer.consumeResult(proof, pi, payload);

        assertEq(mockConsumer.lastPrice(), DEMO_PRICE);
        assertEq(mockConsumer.lastSourcesUsed(), DEMO_SOURCES);
        assertEq(mockConsumer.lastBlockTimestamp(), DEMO_TS);
    }

    function test_output_payload_mismatch_reverts() public {
        bytes memory payload = abi.encode(DEMO_PRICE, DEMO_SOURCES, DEMO_TS);
        PublicInputs memory pi = realInputs;
        pi.outputHash = keccak256(payload);

        bytes memory tampered = bytes.concat(payload);
        tampered[0] = bytes1(uint8(tampered[0]) ^ 0xFF);

        vm.expectRevert(ProvenoConsumer.OutputPayloadMismatch.selector);
        mockConsumer.consumeResult(proof, pi, tampered);
    }

    function test_proof_tampered_reverts_with_proof_invalid() public {
        // Proof check runs before the payload check, so any payload triggers
        // `ProofInvalid` once the proof is bogus.
        bytes memory tamperedProof = bytes.concat(proof);
        tamperedProof[0] = bytes1(uint8(tamperedProof[0]) ^ 0xFF);

        bytes memory payload = abi.encode(DEMO_PRICE, DEMO_SOURCES, DEMO_TS);

        vm.expectRevert(ProvenoVerifier.ProofInvalid.selector);
        realConsumer.consumeResult(tamperedProof, realInputs, payload);
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
