// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {AutomataDcapAttestationFee} from "automata-dcap-attestation/contracts/AutomataDcapAttestationFee.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {TD_REPORT10_LENGTH} from "automata-dcap-attestation/contracts/types/Constants.sol";

// This is an example script that shows how to register a TEE service with the FlashtestationRegistry.
// It is not meant to be used in production, but rather as a reference for how to use the FlashtestationRegistry.
// In fact, deploying is impossible from a laptop or regular server, and can only be successfully executed (without
// cheatcodes) from a v4 TDX machine that has generated a valid TDX attestation quote. We use `vm.prank` here simply
// to simulate the TEE service registering itself.
contract FlashtestationRegistryScript is Script {
    FlashtestationRegistry public registry;

    function setUp() public {}

    // note, this currently only works on Ethereum Sepolia chain
    address public constant ETHEREUM_SEPOLIA_ATTESTATION_FEE_ADDRESS = 0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF;

    function run() public {
        registry = new FlashtestationRegistry(ETHEREUM_SEPOLIA_ATTESTATION_FEE_ADDRESS);

        // Test trying to register a TEE
        vm.prank(0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03);
        bytes memory sampleQuote = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        );

        registry.registerTEEService(sampleQuote);
    }
}
