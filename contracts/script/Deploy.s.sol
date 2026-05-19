// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {StubOpenVmVerifier} from "../src/StubOpenVmVerifier.sol";
import {LuaiVerifier} from "../src/LuaiVerifier.sol";
import {LuaiConsumer} from "../src/LuaiConsumer.sol";

/// @notice Deploys LuaiVerifier + LuaiConsumer with a real or stub OpenVM verifier.
///
/// Required environment variables:
///   POLICY_HASH           — 32-byte policy hash as a 0x-prefixed hex string
///                           (output of `cargo run -p luai-verifier --bin policy-hash`)
///
/// Optional environment variables:
///   OPENVM_VERIFIER_ADDR  — address of an already-deployed IOpenVmVerifier
///                           (e.g. OpenVmGroth16Verifier). When set, that contract
///                           is used and StubOpenVmVerifier is not deployed.
///                           When unset, a StubOpenVmVerifier is deployed instead.
///
/// Usage (stub — for testing / testnet):
///   POLICY_HASH=0x... \
///   forge script script/Deploy.s.sol \
///     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
///
/// Usage (real Groth16 verifier):
///   OPENVM_VERIFIER_ADDR=0x... POLICY_HASH=0x... \
///   forge script script/Deploy.s.sol \
///     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
contract Deploy is Script {
    function run() external {
        bytes32 policyHash = vm.envBytes32("POLICY_HASH");
        address openVmVerifierAddr = vm.envOr("OPENVM_VERIFIER_ADDR", address(0));

        vm.startBroadcast();

        if (openVmVerifierAddr == address(0)) {
            StubOpenVmVerifier stub = new StubOpenVmVerifier();
            openVmVerifierAddr = address(stub);
            console.log("StubOpenVmVerifier:", openVmVerifierAddr);
        } else {
            console.log("Using OpenVM verifier:", openVmVerifierAddr);
        }

        LuaiVerifier verifier = new LuaiVerifier(policyHash, openVmVerifierAddr);
        LuaiConsumer consumer = new LuaiConsumer(address(verifier));

        vm.stopBroadcast();

        console.log("LuaiVerifier:      ", address(verifier));
        console.log("LuaiConsumer:      ", address(consumer));
        console.log("Policy hash:       ");
        console.logBytes32(policyHash);
    }
}
