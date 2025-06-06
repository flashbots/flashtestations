// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {AutomataDcapAttestationFee} from "automata-dcap-attestation/contracts/AutomataDcapAttestationFee.sol";

// deploy the FlashtestationRegistry contract with the AutomataDcapAttestationFee contract
// (which is critical to TEE attestation verification) set using an envvar. You can see which
// AutomataDcapAttestationFee is appropriate for your network here:
// https://github.com/automata-network/automata-dcap-attestation/tree/72349dafbf3bd4861eb56fd9d22b21f538adbfe0?tab=readme-ov-file#deployment
contract FlashtestationRegistryScript is Script {
    FlashtestationRegistry public registry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        registry = new FlashtestationRegistry(vm.envAddress("AUTOMATA_DCAP_ATTESTATION_FEE_ADDRESS"));
        vm.stopBroadcast();
    }
}
