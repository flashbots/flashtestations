// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Upgrades, Options} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";

/**
 * @title UpgradeBlockBuilderFromV1
 * @notice Upgrade script for BlockBuilderPolicy contract from V1 (the original version of the contract)
 * @notice This is nearly identical to the latest version of the policy contract located at
 * src/BlockBuilderPolicy contract, except in the latest has had the logic around the xfam and tdattributes bit
 * masking removed. This was done because there was a bug in the bit masking logic, and we want to fix the bug
 * and simplify the contract by removing the bit masking logic
 * @dev This script does not require any reinitialization of the contract, as the the only changes to
 * the contract are removing constant variables and changing the workloadIdForTDRegistration function logic
 * @dev This script:
 *      1. Deploys a new BlockBuilderPolicy implementation contract
 *      2. Upgrades the existing UUPS proxy to point to the new implementation
 */
contract UpgradeBlockBuilderPolicyV1 is Script {
    /**
     * @notice uses environment variables to get the proxy address of the BlockBuilderPolicy contract
     * @dev the BLOCK_BUILDER_POLICY_PROXY_ADDRESS env var is the address of the proxy contract for the BlockBuilderPolicy contract
     */
    function run() external {
        address proxyAddress = vm.envAddress("BLOCK_BUILDER_POLICY_PROXY_ADDRESS");
        run(proxyAddress);
    }

    function run(address proxyAddress) public {
        console.log("=== UpgradeBlockBuilderFromV1 Configuration ===");
        console.log("Proxy address:", proxyAddress);
        console.log("");

        // Spot check the proxy contract by calling the registry function
        // This is a safety check to ensure the contract at the proxy address
        // implements IBlockBuilderPolicy as expected
        address proxyRegistry = BlockBuilderPolicy(proxyAddress).registry();
        require(proxyRegistry != address(0), "proxyAddress is not a BlockBuilderPolicy contract");

        vm.startBroadcast();

        // Upgrade the proxy to the new implementation
        Options memory opts;
        opts.referenceContract = "V1BlockBuilderPolicy.sol:V1BlockBuilderPolicy";
        Upgrades.upgradeProxy(proxyAddress, "BlockBuilderPolicy.sol", bytes(""), opts);

        vm.stopBroadcast();

        console.log("=== Upgrade Complete ===");
        console.log("");
    }
}
