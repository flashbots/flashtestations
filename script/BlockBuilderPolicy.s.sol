// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";

/// @title BlockBuilderPolicyScript
/// @notice Deploy the block builder policy contract, which is a simple contract that allows an organization
/// (such as Flashbots) to permission TEE's and their registered Ethereum addresses + workloadIds
/// @dev the FLASHTESTATION_REGISTRY_ADDRESS env var is the address of the contract deployed by the FlashtestationRegistryScript
/// @dev the OWNER_BLOCK_BUILDER_POLICY env var is the address that can add and remove workloads from the policy
contract BlockBuilderPolicyScript is Script {
    function setUp() public {}

    function run() public {
        // this is the address that stores all of the TEE-controlled addresses and their associated workloadIds
        address registry = vm.envAddress("FLASHTESTATION_REGISTRY_ADDRESS");

        // this is the address that can add and remove workloads from the policy, and upgrade the policy contract
        address owner = vm.envAddress("OWNER_BLOCK_BUILDER_POLICY");
        doRun(owner, registry);
    }

    function doRun(address owner, address registry) public returns (address) {
        console.log("OWNER_BLOCK_BUILDER_POLICY:", owner);
        console.log("FLASHTESTATION_REGISTRY_ADDRESS:", registry);

        vm.startBroadcast();
        address policy = Upgrades.deployUUPSProxy(
            "BlockBuilderPolicy.sol", abi.encodeCall(BlockBuilderPolicy.initialize, (owner, registry))
        );
        console.log("BlockBuilderPolicy deployed at:", policy);
        vm.stopBroadcast();

        return policy;
    }
}
