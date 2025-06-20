// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";

/// @title BlockBuilderPolicyScript
/// @notice Deploy the block builder policy contract, which is a simple contract that allows an organization
/// (such as Flashbots) to permission TEE's and their registered Ethereum addresses + workloadIds
/// @dev the FLASHTESTATION_REGISTRY_ADDRESS env var is the address of the contract deployed by the FlashtestationRegistryScript
/// @dev the OWNER_BLOCK_BUILDER_POLICY env var is the address that can add and remove workloads from the policy
contract BlockBuilderPolicyScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        // this is the address that stores all of the TEE-controlled addresses and their associated workloadIds
        address registry = vm.envAddress("FLASHTESTATION_REGISTRY_ADDRESS");
        console.log("registry", registry);
        // do some safety checks to make sure this is indeed a registry contract
        require(registry != address(0), "FLASHTESTATION_REGISTRY_ADDRESS address is 0x0");
        FlashtestationRegistry registryContract = FlashtestationRegistry(registry);
        require(
            registryContract.owner() == vm.envAddress("FLASHTESTATION_REGISTRY_OWNER"),
            "FLASHTESTATION_REGISTRY_ADDRESS owner mismatch"
        );

        // this is the address that can add and remove workloads from the policy, and upgrade the policy contract
        address owner = vm.envAddress("OWNER_BLOCK_BUILDER_POLICY");
        console.log("owner", owner);

        Upgrades.deployUUPSProxy(
            "BlockBuilderPolicy.sol", abi.encodeCall(BlockBuilderPolicy.initialize, (owner, registry))
        );
        vm.stopBroadcast();
    }
}
