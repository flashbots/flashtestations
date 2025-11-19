// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {FlashtestationRegistryScript} from "./FlashtestationRegistry.s.sol";
import {BlockBuilderPolicyScript} from "./BlockBuilderPolicy.s.sol";
import {DeploymentUtils} from "./utils/DeploymentUtils.sol";

/// @title DeployAllScript
/// @notice Deploys FlashtestationRegistry and BlockBuilderPolicy
/// @notice This should be your go to script for deploying all contracts fresh on a new chain that already has an
/// @notice Automata DCAP attestation contract deployed
/// @notice It will use the same owner for all contracts
/// @notice Example usage:
/// @notice forge script script/DeployAll.s.sol:DeployAllScript \
/// @notice --sig "run(address,address)" <FLASHTESTATIONS CONTRACT OWNER ADDRESS> <AutomataDcapAttestationFee CONTRACT ADDRESS> \
/// @notice --rpc-url <RPC_URL> --interactives 1 -vvvv --broadcast --verify
contract DeployAllScript is Script, DeploymentUtils {
    function setUp() public {}

    function run(address owner, address automataAttestationContract) public {
        FlashtestationRegistryScript registryScript = new FlashtestationRegistryScript();
        BlockBuilderPolicyScript policyScript = new BlockBuilderPolicyScript();

        if (owner == address(0)) {
            revert("owner must not be the 0 address");
        }

        // sanity check that the automataAttestationContract is a contract that implements the
        // AutomataDcapAttestationFee interface
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(automataAttestationContract)
        }
        if (codeSize == 0) {
            revert(
                "automataAttestationContract has no code; please pass in a valid AutomataDcapAttestationFee contract address"
            );
        }
        (bool success, bytes memory returnData) =
            automataAttestationContract.staticcall(abi.encodeWithSignature("getBp()"));
        if (!success || returnData.length == 0) {
            revert(
                "automataAttestationContract does not implement the correct interface; please pass in a valid AutomataDcapAttestationFee contract address"
            );
        }

        address registryAddress = registryScript.doRun(owner, automataAttestationContract);
        address policyAddress = policyScript.doRun(owner, registryAddress);
    }
}
