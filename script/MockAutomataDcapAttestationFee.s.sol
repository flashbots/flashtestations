// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {MockAutomataDcapAttestationFee} from "../test/mocks/MockAutomataDcapAttestationFee.sol";

/**
 * @title MockAutomataDcapAttestationFeeScript
 * @dev Script to deploy the MockAutomataDcapAttestationFee contract for testing purposes
 * @dev This mock allows us to control the output of the verifyAndAttestOnChain function,
 *      and skip dealing with the vast complexity of Automata's DCAP Attestation contract
 * @dev This is useful for testing the FlashtestationRegistry contract with different quote and output values
 *      without having to deploy the AutomataDcapAttestationFee contract
 * @dev This is also useful for unblocking Unichain + Flashbots from testing in a devnet, where we do not
 *      want to deal with the complexity of deploying the many contracts that are required for the DCAP Attestation
 */
contract MockAutomataDcapAttestationFeeScript is Script {
    MockAutomataDcapAttestationFee public mockAttestation;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        console.log("Deploying MockAutomataDcapAttestationFee contract...");

        // Deploy the mock attestation contract
        mockAttestation = new MockAutomataDcapAttestationFee();

        vm.stopBroadcast();

        console.log("Successfully deployed MockAutomataDcapAttestationFee contract");
        console.log("Contract address:", address(mockAttestation));
    }
}
