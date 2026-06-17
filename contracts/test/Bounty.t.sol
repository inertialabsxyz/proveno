// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {Bounty} from "../src/Bounty.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {ProvenoVerifier} from "../src/ProvenoVerifier.sol";
import {PublicInputs} from "../src/Types.sol";

contract BountyTest is Test {
    HonkVerifier internal honk;
    ProvenoVerifier internal verifier;
    Bounty internal bounty;

    bytes internal proof;
    PublicInputs internal realInputs;

    uint256 internal constant REWARD = 1 ether;
    address internal solver = makeAddr("solver");

    function setUp() public {
        proof = vm.readFileBinary("test/fixtures/proof.bin");
        realInputs = _loadInputs();

        honk = new HonkVerifier();
        verifier = new ProvenoVerifier(realInputs.policyHash, address(honk));
        bounty = new Bounty(address(verifier));
    }

    function test_PostEscrowsReward() public {
        uint256 id = bounty.postBounty{value: REWARD}(realInputs.programHash);

        (address poster, uint256 reward, bytes32 programHash, bool claimed, address bSolver) =
            bounty.bounties(id);
        assertEq(poster, address(this));
        assertEq(reward, REWARD);
        assertEq(programHash, realInputs.programHash);
        assertEq(claimed, false);
        assertEq(bSolver, address(0));

        assertEq(address(bounty).balance, REWARD);
    }

    function test_ValidProofPaysSolver() public {
        uint256 id = bounty.postBounty{value: REWARD}(realInputs.programHash);

        uint256 solverBalanceBefore = solver.balance;

        vm.expectEmit(true, true, false, true, address(bounty));
        emit Bounty.BountyClaimed(id, solver, REWARD);

        vm.prank(solver);
        bounty.claim(id, proof, realInputs);

        assertEq(solver.balance, solverBalanceBefore + REWARD);

        (,,, bool claimed, address bSolver) = bounty.bounties(id);
        assertEq(claimed, true);
        assertEq(bSolver, solver);
    }

    function test_WrongTaskReverts() public {
        bytes32 otherProgram = bytes32(uint256(realInputs.programHash) ^ 0x1);
        uint256 id = bounty.postBounty{value: REWARD}(otherProgram);

        vm.prank(solver);
        vm.expectRevert(Bounty.WrongTask.selector);
        bounty.claim(id, proof, realInputs);
    }

    function test_TamperedProofReverts() public {
        uint256 id = bounty.postBounty{value: REWARD}(realInputs.programHash);

        bytes memory tamperedProof = bytes.concat(proof);
        tamperedProof[0] = bytes1(uint8(tamperedProof[0]) ^ 0xFF);

        vm.prank(solver);
        vm.expectRevert(ProvenoVerifier.ProofInvalid.selector);
        bounty.claim(id, tamperedProof, realInputs);
    }

    function test_DoubleClaimReverts() public {
        uint256 id = bounty.postBounty{value: REWARD}(realInputs.programHash);

        vm.prank(solver);
        bounty.claim(id, proof, realInputs);

        vm.prank(solver);
        vm.expectRevert(Bounty.AlreadyClaimed.selector);
        bounty.claim(id, proof, realInputs);
    }

    function test_NoRewardReverts() public {
        vm.expectRevert(Bounty.NoReward.selector);
        bounty.postBounty{value: 0}(realInputs.programHash);
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
