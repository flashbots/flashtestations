// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {BlockBuilderPolicy, WorkloadId} from "../src/BlockBuilderPolicy.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {DeploymentUtils} from "./utils/DeploymentUtils.sol";
import {StringUtils} from "../src/utils/StringUtils.sol";

/// @title AddWorkloadToPolicyScript
/// @notice A simple helper script to add a workload to the policy
contract AddWorkloadToPolicyScript is Script {
    BlockBuilderPolicy public policy;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        policy = BlockBuilderPolicy(vm.envAddress("ADDRESS_BLOCK_BUILDER_POLICY"));
        console.log("ADDRESS_BLOCK_BUILDER_POLICY:");
        console.logAddress(address(policy));
        bytes32 workloadId = vm.envBytes32("WORKLOAD_ID");
        string memory commitHash = vm.envString("COMMIT_HASH");
        console.log("WORKLOAD_ID:");
        console.logBytes32(workloadId);
        console.log("COMMIT_HASH:");
        console.log(commitHash);
        string memory sourceLocatorsRaw = vm.envString("RECORD_LOCATORS");
        string[] memory recordLocators = StringUtils.splitCommaSeparated(sourceLocatorsRaw);
        console.log("RECORD_LOCATORS:");
        for (uint256 i = 0; i < recordLocators.length; i++) {
            console.log(recordLocators[i]);
            if (StringUtils.isEmpty(recordLocators[i])) {
                revert("one of the RECORD_LOCATORS is empty, make sure to use a comma-separated list of URLs");
            }
        }

        policy.addWorkloadToPolicy(WorkloadId.wrap(workloadId), commitHash, recordLocators);
        console.log("WorkloadId added to policy");
        vm.stopBroadcast();
    }
}

contract RemoveWorkloadFromPolicyScript is Script {
    BlockBuilderPolicy public policy;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        policy = BlockBuilderPolicy(vm.envAddress("ADDRESS_BLOCK_BUILDER_POLICY"));
        console.log("ADDRESS_BLOCK_BUILDER_POLICY:");
        console.logAddress(address(policy));
        bytes32 workloadId = vm.envBytes32("WORKLOAD_ID");
        console.log("WORKLOAD_ID:");
        console.logBytes32(workloadId);
        policy.removeWorkloadFromPolicy(WorkloadId.wrap(workloadId));
        console.log("WorkloadId removed from policy");
        vm.stopBroadcast();
    }
}

/// @title RegisterTEEScript
/// @notice A simple helper script to register a TEE to the registry
contract RegisterTEEScript is Script, DeploymentUtils {
    function run() public {
        vm.startBroadcast();

        etchECDSAPrecompile();

        string memory pathToAttestationQuote = vm.envString("PATH_TO_ATTESTATION_QUOTE");
        console.log("PATH_TO_ATTESTATION_QUOTE:");
        console.log(pathToAttestationQuote);

        address registryAddress = vm.envAddress("FLASHTESTATION_REGISTRY_ADDRESS");
        console.log("FLASHTESTATION_REGISTRY_ADDRESS:");
        console.logAddress(registryAddress);

        FlashtestationRegistry registry = FlashtestationRegistry(registryAddress);
        registry.registerTEEService(vm.readFileBinary(pathToAttestationQuote), bytes("") /* currently not used */ );

        // fetch the TEE-related data we just added, so the caller of this script can use
        // the outputs in future scripts (like Interactions.s.sol:AddWorkloadToPolicyScript)
        address sender = vm.getWallets()[0];
        (, FlashtestationRegistry.RegisteredTEE memory teeRegistration) = registry.getRegistration(sender);

        BlockBuilderPolicy policy = BlockBuilderPolicy(vm.envAddress("ADDRESS_BLOCK_BUILDER_POLICY"));
        WorkloadId workloadId = policy.workloadIdForTDRegistration(teeRegistration);

        console.log("workloadId:");
        console.logBytes32(WorkloadId.unwrap(workloadId));

        vm.stopBroadcast();
    }
}
