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

        // Example: Call registerTEEService with a sample quote
        bytes memory sampleQuote = vm.readFileBinary("test/quote.raw");

        allowlist.registerTEEService(sampleQuote);

        vm.stopBroadcast();
    }
}
