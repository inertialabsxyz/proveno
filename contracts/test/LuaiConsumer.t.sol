// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LuaiVerifier} from "../src/LuaiVerifier.sol";
import {LuaiConsumer} from "../src/LuaiConsumer.sol";
import {IOpenVmVerifier} from "../src/IOpenVmVerifier.sol";
import {PublicInputs} from "../src/Types.sol";

contract MockOpenVmVerifier is IOpenVmVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function verify(bytes calldata, bytes32) external view returns (bool) {
        return shouldPass;
    }
}

contract LuaiConsumerTest is Test {
    bytes32 constant POLICY_HASH = keccak256("test-policy");

    MockOpenVmVerifier passingMock;
    MockOpenVmVerifier failingMock;
    LuaiVerifier verifier;
    LuaiVerifier failVerifier;
    LuaiConsumer consumer;
    LuaiConsumer failConsumer;

    function setUp() public {
        passingMock = new MockOpenVmVerifier(true);
        failingMock = new MockOpenVmVerifier(false);
        verifier = new LuaiVerifier(POLICY_HASH, address(passingMock));
        failVerifier = new LuaiVerifier(POLICY_HASH, address(failingMock));
        consumer = new LuaiConsumer(address(verifier));
        failConsumer = new LuaiConsumer(address(failVerifier));
    }

    function _makeInputs() internal pure returns (PublicInputs memory) {
        return PublicInputs({
            programHash: keccak256("program"),
            inputHash: keccak256("input"),
            toolResponsesHash: keccak256("tools"),
            outputHash: keccak256("output"),
            tlsAttestationHash: keccak256("tls"),
            policyHash: POLICY_HASH
        });
    }

    function test_stores_price_on_valid_proof() public {
        uint256 price = 3_000e18;
        uint8 sources = 3;
        uint64 ts = 1_700_000_000;
        bytes memory payload = abi.encode(price, sources, ts);

        consumer.consumeResult(hex"", _makeInputs(), payload);

        assertEq(consumer.lastPrice(), price);
        assertEq(consumer.lastSourcesUsed(), sources);
        assertEq(consumer.lastBlockTimestamp(), ts);
    }

    function test_reverts_on_invalid_proof() public {
        bytes memory payload = abi.encode(uint256(1e18), uint8(1), uint64(1));
        vm.expectRevert(LuaiVerifier.ProofInvalid.selector);
        failConsumer.consumeResult(hex"", _makeInputs(), payload);
    }

    function test_reverts_on_wrong_policy_hash() public {
        PublicInputs memory inputs = _makeInputs();
        inputs.policyHash = keccak256("wrong-policy");
        bytes memory payload = abi.encode(uint256(1e18), uint8(1), uint64(1));
        vm.expectRevert(LuaiVerifier.PolicyHashMismatch.selector);
        consumer.consumeResult(hex"", inputs, payload);
    }
}
