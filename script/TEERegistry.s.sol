// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TEERegistry} from "../src/TEERegistry.sol";
import {AutomataDcapAttestationFee} from "automata-dcap-attestation/contracts/AutomataDcapAttestationFee.sol";


contract TEERegistryScript is Script {
    TEERegistry public registry;
    AutomataDcapAttestationFee public attestationFee;

    function setUp() public {}

    address public constant UNICHAIN_SEPOLIA_ATTESTATION_FEE_ADDRESS = 0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF;

    // TODO: this currently only works on Unichain Sepolia chain, generalize it with a proper .env file later on
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

        registry = new TEERegistry(initialOwner);

        // Deploy AutomataDcapAttestationFee with deployer as owner
        console.log("msg.sender:", msg.sender);
        attestationFee = new AutomataDcapAttestationFee(msg.sender);

        // Example: Call verifyQuoteWithAttestationFee with a sample quote
        bytes memory sampleQuote = vm.readFileBinary("test/quote.raw");

        try registry.verifyQuoteWithAttestationFee(address(UNICHAIN_SEPOLIA_ATTESTATION_FEE_ADDRESS), sampleQuote) returns (bool success, bytes memory output) {
            if (!success) {
                console.log("verifyQuoteWithAttestationFee failed");
                console.log("error output:", string(output));
            } else {
                console.log("verifyQuoteWithAttestationFee succeeded");
            }
        } catch (bytes memory errorOutput) {
            console.log("verifyQuoteWithAttestationFee reverted");
            console.log("error output:", string(errorOutput));
        }
        console.log("TEERegistry isVerified:", registry.isVerified());

        vm.stopBroadcast();
    }
}
