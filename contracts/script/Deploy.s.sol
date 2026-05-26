// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";

import {HonkVerifier} from "../src/HonkVerifier.sol";
import {LuaiConsumer} from "../src/LuaiConsumer.sol";
import {LuaiVerifier} from "../src/LuaiVerifier.sol";

contract Deploy is Script {
    function run() external {
        bytes32 policyHash = vm.envBytes32("POLICY_HASH");

        vm.startBroadcast();

        HonkVerifier honk = new HonkVerifier();
        LuaiVerifier luaiVerifier = new LuaiVerifier(policyHash, address(honk));
        LuaiConsumer consumer = new LuaiConsumer(address(luaiVerifier));

        vm.stopBroadcast();

        console.log("HonkVerifier:", address(honk));
        console.log("LuaiVerifier:", address(luaiVerifier));
        console.log("LuaiConsumer:", address(consumer));
    }
}
