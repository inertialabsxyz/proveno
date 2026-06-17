// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";

import {Bounty} from "../src/Bounty.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {ProvenoConsumer} from "../src/ProvenoConsumer.sol";
import {ProvenoVerifier} from "../src/ProvenoVerifier.sol";

contract Deploy is Script {
    function run() external {
        bytes32 policyHash = vm.envBytes32("POLICY_HASH");

        vm.startBroadcast();

        HonkVerifier honk = new HonkVerifier();
        ProvenoVerifier provenoVerifier = new ProvenoVerifier(policyHash, address(honk));
        ProvenoConsumer consumer = new ProvenoConsumer(address(provenoVerifier));
        Bounty bounty = new Bounty(address(provenoVerifier));

        vm.stopBroadcast();

        console.log("HonkVerifier:", address(honk));
        console.log("ProvenoVerifier:", address(provenoVerifier));
        console.log("ProvenoConsumer:", address(consumer));
        console.log("Bounty:", address(bounty));
    }
}
