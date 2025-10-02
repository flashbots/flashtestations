// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";

// deploy the FlashtestationRegistry contract with the AutomataDcapAttestationFee contract
// (which is critical to TEE attestation verification) set using an envvar. You can see which
// AutomataDcapAttestationFee is appropriate for your network here:
// https://github.com/automata-network/automata-dcap-attestation/tree/72349dafbf3bd4861eb56fd9d22b21f538adbfe0?tab=readme-ov-file#deployment
contract FlashtestationRegistryScript is Script {
    FlashtestationRegistry public registry;

    function setUp() public {}

    function run() public {
        // this is the address that can upgrade the code of the deployed registry
        address owner = vm.envAddress("FLASHTESTATION_REGISTRY_OWNER");
        // this is the address of the Automata DCAP Attestation contract, which verifies TEE quotes
        address attestationContract = vm.envAddress("AUTOMATA_DCAP_ATTESTATION_FEE_ADDRESS");

        doRun(owner, attestationContract);
    }

    function doRun(address owner, address attestationContract) public returns (address) {
        console.log("AUTOMATA_DCAP_ATTESTATION_FEE_ADDRESS:", attestationContract);
        console.log("FLASHTESTATION_REGISTRY_OWNER:", owner);

        vm.startBroadcast();

        address registryAddress = Upgrades.deployUUPSProxy(
            "FlashtestationRegistry.sol",
            abi.encodeCall(FlashtestationRegistry.initialize, (owner, attestationContract))
        );
        console.log("FlashtestationRegistry deployed at:", registryAddress);
        vm.stopBroadcast();

        return registryAddress;
    }
}
