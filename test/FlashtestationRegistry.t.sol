// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {FlashtestationRegistry, RegisteredTEE} from "../src/FlashtestationRegistry.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {Helper} from "./helpers/Helper.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {Output} from "automata-dcap-attestation/contracts/types/CommonStruct.sol";

// a simple struct to store related mocked quote data for testing
struct MockQuote {
    bytes output;
    bytes quote;
    address teeAddress;
    WorkloadId workloadId;
}

contract FlashtestationRegistryTest is Test {
    FlashtestationRegistry public registry;
    MockAutomataDcapAttestationFee public attestationContract;
    MockQuote bf42Mock = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        ),
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e)
    });
    MockQuote d204Mock = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/quote.bin"
        ),
        teeAddress: 0x12c14e56d585Dcf3B36f37476c00E78bA9363742,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e)
    });

    WorkloadId wrongWorkloadId = WorkloadId.wrap(0x20ab431377d40de192f7c754ac0f1922de05ab2f73e74204f0b3ab73a8856876);

    function setUp() public {
        // deploy a fresh set of test contracts before each test
        attestationContract = new MockAutomataDcapAttestationFee();
        registry = new FlashtestationRegistry(address(attestationContract));
    }

    function test_successful_registerTEEService() public {
        // first get a valid attestation quote stored

        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;
        WorkloadId expectedWorkloadId = bf42Mock.workloadId;

        // set the attestation contract to return a successful attestation
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.expectEmit(address(registry));
        emit FlashtestationRegistry.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote, false);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        (WorkloadId workloadId, bytes memory rawQuote, bool isValid) = registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
    }

    // test that we can register the same TEEService again with a different quote
    function test_successful_re_registerTEEService() public {
        // do the first register of the TEEService with a valid quote
        bytes memory mockOutput = d204Mock.output;
        bytes memory mockQuote = d204Mock.quote;
        address expectedAddress = d204Mock.teeAddress;
        WorkloadId expectedWorkloadId = d204Mock.workloadId;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.expectEmit(address(registry));
        emit FlashtestationRegistry.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote, false);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        (WorkloadId workloadId, bytes memory rawQuote, bool isValid) = registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");

        // now register the same TEEService again with a different quote

        bytes memory mockOutput2 = vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/output2.bin"
        );
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput2);

        bytes memory mockQuote2 = vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/quote2.bin"
        );
        vm.expectEmit(address(registry));
        emit FlashtestationRegistry.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote2, true);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote2);

        (WorkloadId workloadId2, bytes memory rawQuote2, bool isValid2) = registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid2, true, "TEE should be valid");
        vm.assertEq(WorkloadId.unwrap(workloadId2), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote2, mockQuote2, "Raw quote mismatch");
        vm.assertNotEq(mockQuote, mockQuote2, "Quotes should not be the same");
    }

    function test_reverts_with_invalid_quote_registerTEEService() public {
        attestationContract.setSuccess(false);
        // don't bother setting the output, since it should revert before it's used

        vm.expectPartialRevert(FlashtestationRegistry.InvalidQuote.selector); // the "partial" just means we don't care about the bytes argument to InvalidQuote(bytes)
        bytes memory quote = bf42Mock.quote;
        registry.registerTEEService(quote);
    }

    function test_reverts_with_registering_same_quote_twice() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;
        WorkloadId expectedWorkloadId = bf42Mock.workloadId;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        vm.expectRevert(
            abi.encodeWithSelector(
                FlashtestationRegistry.TEEServiceAlreadyRegistered.selector, expectedAddress, expectedWorkloadId
            )
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);
    }

    function test_reverts_with_invalid_quote_version_quote_parsing_helper() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.quoteVersion = 0x0000;
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setSuccess(true);
        attestationContract.setOutput(serializedOutput);
        vm.expectRevert(QuoteParser.InvalidTEEVersion.selector, 0);
        registry.registerTEEService(mockQuote);
    }

    function test_reverts_with_invalid_tee_type() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.tee = bytes4(0x00000000);
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setSuccess(true);
        attestationContract.setOutput(serializedOutput);
        vm.expectRevert(QuoteParser.InvalidTEEType.selector, 0);
        registry.registerTEEService(mockQuote);
    }

    function test_reverts_with_too_large_quote() public {
        bytes memory mockQuote = bf42Mock.quote;

        // take a 4.9K file and concatenate it 5 times to make it over the 20KB limit
        bytes memory tooLargeQuote = abi.encodePacked(mockQuote, mockQuote, mockQuote, mockQuote, mockQuote);
        vm.expectRevert(abi.encodeWithSelector(FlashtestationRegistry.ByteSizeExceeded.selector, tooLargeQuote.length));
        registry.registerTEEService(tooLargeQuote);
    }

    function test_reverts_when_sender_does_not_match_tee_address() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        // Call with a different address than the one in the quote
        address differentAddress = address(0x1234);
        vm.prank(differentAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                FlashtestationRegistry.SenderMustMatchTEEAddress.selector, differentAddress, expectedAddress
            )
        );
        registry.registerTEEService(mockQuote);
    }

    function test_isValidWorkload_returns_true_for_valid_combination() public {
        // First register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;
        WorkloadId expectedWorkloadId = bf42Mock.workloadId;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        // Now check that isValidWorkload returns true for this combination
        bool isValid = registry.isValidWorkload(expectedWorkloadId, expectedAddress);
        assertTrue(isValid, "isValidWorkload should return true for valid TEE/workloadId combination");
    }

    function test_isValidWorkload_returns_false_for_unregistered_tee() public view {
        // Use an address that hasn't been registered
        address unregisteredAddress = address(0xdead);

        bool isValid = registry.isValidWorkload(wrongWorkloadId, unregisteredAddress);
        assertFalse(isValid, "isValidWorkload should return false for unregistered TEE address");
    }

    function test_isValidWorkload_returns_false_for_wrong_workloadId() public {
        // First register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        // Now check with a different workloadId
        bool isValid = registry.isValidWorkload(wrongWorkloadId, expectedAddress);
        assertFalse(isValid, "isValidWorkload should return false for wrong workloadId");
    }

    function test_invalidateAttestation_reverts_if_not_registered() public {
        address unregisteredAddress = address(0xdeadbeef);
        vm.expectRevert(
            abi.encodeWithSelector(FlashtestationRegistry.TEEServiceNotRegistered.selector, unregisteredAddress)
        );
        registry.invalidateAttestation(unregisteredAddress);
    }

    function test_invalidateAttestation_reverts_if_already_invalid() public {
        // Register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote);

        // Now, invalidate with success==false (should invalidate)
        attestationContract.setSuccess(false);
        vm.prank(address(0x123));
        registry.invalidateAttestation(teeAddress);

        // Now, calling again should revert with TEEServiceAlreadyInvalid
        vm.expectRevert(abi.encodeWithSelector(FlashtestationRegistry.TEEServiceAlreadyInvalid.selector, teeAddress));
        registry.invalidateAttestation(teeAddress);
    }

    function test_invalidateAttestation_reverts_if_still_valid() public {
        // Register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote);
        // Now, invalidate with success==true (still valid)
        attestationContract.setSuccess(true);
        vm.expectRevert(abi.encodeWithSelector(FlashtestationRegistry.TEEIsStillValid.selector, teeAddress));
        registry.invalidateAttestation(teeAddress);
    }

    function test_invalidateAttestation_invalidates_and_emits_event() public {
        // Register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote);
        // Now, invalidate with success==false (should invalidate)
        attestationContract.setSuccess(false);
        vm.expectEmit(address(registry));
        emit FlashtestationRegistry.TEEServiceInvalidated(teeAddress);
        registry.invalidateAttestation(teeAddress);
        // Check isValid is now false
        (,, bool isValid) = registry.registeredTEEs(teeAddress);
        assertFalse(isValid, "TEE should be invalid after invalidate");
    }
}
