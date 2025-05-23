// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {AllowList} from "../src/AllowList.sol";
import {AutomataDcapAttestationFee} from "automata-dcap-attestation/contracts/AutomataDcapAttestationFee.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {TD_REPORT10_LENGTH} from "automata-dcap-attestation/contracts/types/Constants.sol";

contract AllowListScript is Script {
    AllowList public registry;
    AutomataDcapAttestationFee public attestationFee;

    function setUp() public {}

    address public constant ETHEREUM_SEPOLIA_ATTESTATION_FEE_ADDRESS = 0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF;

    // note, this currently only works on Ethereum Sepolia chain
    function run() public {
        vm.startBroadcast();

        address initialOwner;
        try vm.envAddress("REGISTRY_INITIAL_OWNER") returns (address owner) {
            initialOwner = owner;
        } catch {
            console.log("Warning: REGISTRY_INITIAL_OWNER not found in environment variables, using msg.sender");
            initialOwner = msg.sender;
        }

        console.log("REGISTRY_INITIAL_OWNER:", initialOwner);

        registry = new AllowList(initialOwner);

        // Deploy AutomataDcapAttestationFee with deployer as owner
        console.log("msg.sender:", msg.sender);
        attestationFee = new AutomataDcapAttestationFee(msg.sender);

        // Example: Call verifyQuoteWithAttestationFee with a sample quote
        bytes memory sampleQuote = vm.readFileBinary("test/quote.raw");

        (bool success, bytes memory output) =
            registry.verifyQuoteWithAttestationFee(address(ETHEREUM_SEPOLIA_ATTESTATION_FEE_ADDRESS), sampleQuote);

        if (!success) {
            console.log(string(output));
        }

        vm.stopBroadcast();
    }
}
