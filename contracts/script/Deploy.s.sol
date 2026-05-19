// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {StubOpenVmVerifier} from "../src/StubOpenVmVerifier.sol";
import {LuaiVerifier} from "../src/LuaiVerifier.sol";
import {LuaiConsumer} from "../src/LuaiConsumer.sol";

/// @notice Deploys LuaiVerifier + LuaiConsumer with a StubOpenVmVerifier.
///
/// Required environment variables:
///   POLICY_HASH  — 32-byte policy hash as a 0x-prefixed hex string
///                  (output of `cargo run -p luai-verifier --bin policy-hash`)
///
/// Usage:
///   POLICY_HASH=0x$(cargo run -p luai-verifier --bin policy-hash) \
///   forge script script/Deploy.s.sol \
///     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
contract Deploy is Script {
    function run() external {
        bytes32 policyHash = vm.envBytes32("POLICY_HASH");

        vm.startBroadcast();

        StubOpenVmVerifier stub = new StubOpenVmVerifier();
        LuaiVerifier verifier = new LuaiVerifier(policyHash, address(stub));
        LuaiConsumer consumer = new LuaiConsumer(address(verifier));

        vm.stopBroadcast();

        console.log("StubOpenVmVerifier:", address(stub));
        console.log("LuaiVerifier:      ", address(verifier));
        console.log("LuaiConsumer:      ", address(consumer));
        console.log("Policy hash:       ");
        console.logBytes32(policyHash);
    }
}
