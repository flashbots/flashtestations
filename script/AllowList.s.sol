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

        // Test trying to register a TEE
        bytes memory sampleQuote = vm.readFileBinary(
            string(
                abi.encodePacked(
                    "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/",
                    "quote2.bin"
                )
            )
        );

        allowlist.registerTEEService(sampleQuote);

        vm.stopBroadcast();
    }
}
