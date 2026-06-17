// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ProvenoVerifier} from "./ProvenoVerifier.sol";
import {PublicInputs} from "./Types.sol";

/// @notice Generic bounty board for verifiable tasks. A poster escrows ETH
/// against a committed `programHash`; any caller who supplies a valid proveno
/// proof of that exact program claims the reward.
///
/// @dev The trust model is execution integrity over a requester-committed task:
/// the bounty commits the exact `programHash`, and any valid proof of that
/// program claims the reward. Outputs and external data are not gated here
/// (provenance is out of scope). Modeled on `ProvenoConsumer.sol`; in
/// particular `claim` verifies the proof BEFORE checking `programHash`, so a
/// bogus proof always reverts `ProofInvalid` regardless of the other args.
contract Bounty {
    struct BountyData {
        address poster;
        uint256 reward;
        bytes32 programHash;
        bool claimed;
        address solver;
    }

    error AlreadyClaimed();
    error WrongTask();
    error NoReward();

    event BountyPosted(
        uint256 indexed id, address indexed poster, uint256 reward, bytes32 programHash
    );
    event BountyClaimed(uint256 indexed id, address indexed solver, uint256 reward);

    ProvenoVerifier public immutable provenoVerifier;

    mapping(uint256 => BountyData) public bounties;
    uint256 public nextId;

    constructor(address _provenoVerifier) {
        provenoVerifier = ProvenoVerifier(_provenoVerifier);
    }

    /// @notice Post a bounty for a task, escrowing `msg.value` as the reward.
    function postBounty(bytes32 programHash) external payable returns (uint256 id) {
        if (msg.value == 0) revert NoReward();

        id = nextId++;
        bounties[id] = BountyData({
            poster: msg.sender,
            reward: msg.value,
            programHash: programHash,
            claimed: false,
            solver: address(0)
        });

        emit BountyPosted(id, msg.sender, msg.value, programHash);
    }

    /// @notice Claim a bounty with a valid proof of its committed program.
    ///
    /// @dev Order of checks matches `ProvenoConsumer`: the proof is verified
    /// BEFORE the `programHash` check, so a bogus proof always reverts
    /// `ProofInvalid` regardless of which task it targets.
    function claim(uint256 id, bytes calldata proof, PublicInputs calldata inputs)
        external
    {
        BountyData storage b = bounties[id];
        if (b.claimed) revert AlreadyClaimed();

        provenoVerifier.verify(proof, inputs);

        if (inputs.programHash != b.programHash) revert WrongTask();

        b.claimed = true;
        b.solver = msg.sender;

        uint256 reward = b.reward;
        emit BountyClaimed(id, msg.sender, reward);

        (bool ok,) = msg.sender.call{value: reward}("");
        require(ok, "reward transfer failed");
    }
}
