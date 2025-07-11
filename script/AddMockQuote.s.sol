// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {MockAutomataDcapAttestationFee} from "../test/mocks/MockAutomataDcapAttestationFee.sol";
import {AutomataDcapAttestationFee} from "automata-dcap-attestation/contracts/AutomataDcapAttestationFee.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {DeploymentUtils} from "./utils/DeploymentUtils.sol";

/**
 * @title AddMockQuote
 * @dev Script to add a mock quote to the MockAutomataDcapAttestationFee contract deployed on unichain experimental
 * @dev This script calls the real attestation contract (i.e. the AutomataDcapAttestationFee.sol deployed by Automata)
 * on Unichain Sepolia to get the output from AttestationSubmitted event, then uses that output to set up the mock
 * contract to return the same output for the same quote.
 * @dev This is useful for when we do not want to deploy the full set of Automata DCAP Attestation contracts.
 */
contract AddMockQuoteScript is Script, DeploymentUtils {
    // Event definition from AttestationEntrypointBase.sol
    event AttestationSubmitted(bool success, uint8 verifierType, bytes output);

    function setUp() public {}

    function run() public {
        // Get the mock quote from environment variable
        string memory pathToMockQuote = vm.envString("PATH_TO_ATTESTATION_QUOTE");
        console.log("PATH_TO_ATTESTATION_QUOTE: ", pathToMockQuote);
        bytes memory mockQuote = vm.readFileBinary(pathToMockQuote);

        // Get contract addresses from environment
        address mockAttestationAddress = vm.envAddress("MOCK_AUTOMATA_DCAP_ATTESTATION_FEE_ADDRESS");
        address realAttestationAddress = vm.envAddress("REAL_AUTOMATA_DCAP_ATTESTATION_FEE_ADDRESS");

        // get fork RPC url from environment
        string memory unichainSepoliaRpcUrl = vm.envString("UNICHAIN_SEPOLIA_RPC_URL");
        string memory experimentalRpcUrl = vm.envString("EXPERIMENTAL_RPC_URL");
        console.log("Experimental RPC URL:", experimentalRpcUrl);

        console.log("Adding mock quote to MockAutomataDcapAttestationFee");
        console.log("Mock quote length:", mockQuote.length);
        console.log("Mock attestation address:", mockAttestationAddress);
        console.log("Real attestation address:", realAttestationAddress);

        uint256 unichainSepoliaForkId = vm.createFork(unichainSepoliaRpcUrl);
        uint256 experimentalForkId = vm.createFork(experimentalRpcUrl);

        vm.selectFork(unichainSepoliaForkId);

        // Step 1: Call the real attestation contract to get the output
        AutomataDcapAttestationFee realAttestation = AutomataDcapAttestationFee(realAttestationAddress);

        // Call the real attestation contract with the fee
        etchECDSAPrecompile(); // this is required to get the output from the real attestation contract
        (bool success, bytes memory output) = realAttestation.verifyAndAttestOnChain(mockQuote);

        console.log("Real attestation result - success:", success);
        console.log("Real attestation output length:", output.length);

        if (!success) {
            console.log("Attestation failed with output:", string(output));
        }

        // now that we've got the output, we can set up the mock attestation contract
        vm.selectFork(experimentalForkId);

        vm.startBroadcast();

        // Step 2: Set up the mock attestation contract with the same return value as
        // if the real Automata attestation contract had returned it
        MockAutomataDcapAttestationFee mockAttestation = MockAutomataDcapAttestationFee(mockAttestationAddress);
        mockAttestation.setQuoteResult(mockQuote, success, output);

        vm.stopBroadcast();

        console.log("Successfully added mock quote to MockAutomataDcapAttestationFee");

        TD10ReportBody memory td10ReportBodyStruct = QuoteParser.parseV4VerifierOutput(output);
        bytes memory publicKey = QuoteParser.extractPublicKey(td10ReportBodyStruct);
        address teeAddress = address(uint160(uint256(keccak256(publicKey))));
        WorkloadId workloadId = QuoteParser.extractWorkloadId(td10ReportBodyStruct);

        console.log("TEE address:");
        console.logAddress(teeAddress);
        console.log("Workload ID (hex):");
        console.logBytes32(WorkloadId.unwrap(workloadId));
        console.log("Public key (hex):");
        console.logBytes(publicKey);
    }
}
