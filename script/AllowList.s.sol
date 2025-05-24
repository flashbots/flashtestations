// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {AllowList} from "../src/AllowList.sol";
import {AutomataDcapAttestationFee} from "automata-dcap-attestation/contracts/AutomataDcapAttestationFee.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {TD_REPORT10_LENGTH} from "automata-dcap-attestation/contracts/types/Constants.sol";

contract AllowListScript is Script {
    AllowList public allowlist;

    function setUp() public {}

    address public constant ETHEREUM_SEPOLIA_ATTESTATION_FEE_ADDRESS = 0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF;

    // note, this currently only works on Ethereum Sepolia chain
    function run() public {
        vm.startBroadcast();

        allowlist = new AllowList(ETHEREUM_SEPOLIA_ATTESTATION_FEE_ADDRESS);

        // Example: Call registerTEEService with a sample quote whose user data is simply `00`
        bytes memory sampleQuote = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        );

        allowlist.registerTEEService(sampleQuote);

        vm.stopBroadcast();
    }
}
