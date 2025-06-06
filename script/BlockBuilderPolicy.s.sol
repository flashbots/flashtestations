// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";

/// @title BlockBuilderPolicyScript
/// @notice Deploy the block builder policy contract, which is a simple contract that allows an organization
/// (such as Flashbots) to permission TEE's and their registered Ethereum addresses + workloadIds
/// @dev the FLASHTESTATION_REGISTRY_ADDRESS env var is the address of the contract deployed by the FlashtestationRegistryScript
/// @dev the OWNER_BLOCK_BUILDER_POLICY env var is the address that can add and remove workloads from the policy
contract BlockBuilderPolicyScript is Script {
    BlockBuilderPolicy public policy;
    FlashtestationRegistry public registry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        policy = new BlockBuilderPolicy(
            vm.envAddress("FLASHTESTATION_REGISTRY_ADDRESS"), vm.envAddress("OWNER_BLOCK_BUILDER_POLICY")
        );
        vm.stopBroadcast();
    }
}
