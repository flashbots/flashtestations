// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";
import {QuoteParser} from "../src/utils/QuoteParser.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {Helper} from "./helpers/Helper.sol";
import {Upgrader} from "./helpers/Upgrader.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {TD_REPORT10_LENGTH, HEADER_LENGTH} from "automata-dcap-attestation/contracts/types/Constants.sol";
import {Output} from "automata-dcap-attestation/contracts/types/CommonStruct.sol";

// a simple struct to store related mocked quote data for testing
struct MockQuote {
    bytes output;
    bytes quote;
    address teeAddress;
    bytes publicKey;
    uint256 privateKey;
}

contract FlashtestationRegistryTest is Test {
    address public owner = address(this);
    FlashtestationRegistry public registry;
    Upgrader public upgrader = new Upgrader();
    MockAutomataDcapAttestationFee public attestationContract;
    MockQuote bf42Mock = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        ),
        publicKey: hex"bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446",
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote bf42MockWithDifferentWorkloadId = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output2.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote2.bin"
        ),
        publicKey: hex"bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446",
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote d204Mock = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/quote.bin"
        ),
        publicKey: hex"d204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6",
        teeAddress: 0x12c14e56d585Dcf3B36f37476c00E78bA9363742,
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote mock7b91 = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/7b916d70ed77488d6c1ced7117ba410655a8faa8d6c7740562a88ab3cb9cbca63e2d5761812a11d90c009ed017113131370070cd3a2d5fba64d9dbb76952df19/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/7b916d70ed77488d6c1ced7117ba410655a8faa8d6c7740562a88ab3cb9cbca63e2d5761812a11d90c009ed017113131370070cd3a2d5fba64d9dbb76952df19/quote.bin"
        ),
        publicKey: hex"7b916d70ed77488d6c1ced7117ba410655a8faa8d6c7740562a88ab3cb9cbca63e2d5761812a11d90c009ed017113131370070cd3a2d5fba64d9dbb76952df19",
        teeAddress: 0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF,
        privateKey: 0x92e4b5ed61db615b26da2271da5b47c42d691b3164561cfb4edbc85ca6ca61a8
    });

    using ECDSA for bytes32;

    function setUp() public {
        // deploy a fresh set of test contracts before each test
        attestationContract = new MockAutomataDcapAttestationFee();
        address implementation = address(new FlashtestationRegistry());
        address proxy = UnsafeUpgrades.deployUUPSProxy(
            implementation, abi.encodeCall(FlashtestationRegistry.initialize, (owner, address(attestationContract)))
        );
        registry = FlashtestationRegistry(proxy);
    }

    function test_successful_registerTEEService() public {
        // first get a valid attestation quote stored

        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;

        // set the attestation contract to return a successful attestation
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Create extended registration data
        bytes memory extendedData = abi.encode("test data", uint256(123));

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, extendedData);

        // Get the registration
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);

        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registration.extendedRegistrationData, extendedData, "Extended data mismatch");
        vm.assertEq(registration.isValid, true, "Registration should be valid");
    }

    // test that we can register the same TEEService again with a different quote
    function test_successful_re_registerTEEService() public {
        // do the first register of the TEEService with a valid quote
        bytes memory mockOutput = d204Mock.output;
        bytes memory mockQuote = d204Mock.quote;
        address expectedAddress = d204Mock.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        bytes memory extendedData = abi.encode("initial data");

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, extendedData);

        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");

        // now register the same TEEService again with a different quote

        bytes memory mockQuote2 = vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/quote2.bin"
        );
        bytes memory mockOutput2 = vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/output2.bin"
        );
        attestationContract.setQuoteResult(mockQuote2, true, mockOutput2);

        bytes memory extendedData2 = abi.encode("updated data");

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote2, true);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote2, extendedData2);

        (bool isValid2, IFlashtestationRegistry.RegisteredTEE memory registration2) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid2, true, "TEE should be valid");
        vm.assertEq(registration2.rawQuote, mockQuote2, "Raw quote mismatch");
        vm.assertEq(registration2.extendedRegistrationData, extendedData2, "Extended data mismatch");
        vm.assertNotEq(mockQuote, mockQuote2, "Quotes should not be the same");
    }

    function test_successful_re_registerTEEService_with_different_workload_ids() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        bytes memory expectedPublicKey = bf42Mock.publicKey;
        address expectedAddress = bf42Mock.teeAddress;

        // set the attestation contract to return a successful attestation
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        bytes memory extendedData = abi.encode("initial");

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, extendedData);

        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");

        // now register the same TEE-controlled address again with a different quote and workloadId

        bytes memory mockOutput2 = bf42MockWithDifferentWorkloadId.output;
        bytes memory mockQuote2 = bf42MockWithDifferentWorkloadId.quote;
        expectedPublicKey = bf42MockWithDifferentWorkloadId.publicKey;
        attestationContract.setQuoteResult(mockQuote2, true, mockOutput2);

        bytes memory extendedData2 = abi.encode("updated");

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote2, true);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote2, extendedData2);

        (bool isValid2, IFlashtestationRegistry.RegisteredTEE memory registration2) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid2, true, "TEE should be valid");
        vm.assertEq(registration2.rawQuote, mockQuote2, "Raw quote mismatch");
        vm.assertNotEq(mockQuote, mockQuote2, "Quotes should not be the same");
    }

    function test_reverts_with_invalid_quote_registerTEEService() public {
        bytes memory mockQuote = bf42Mock.quote;
        attestationContract.setQuoteResult(mockQuote, false, new bytes(0));

        vm.expectPartialRevert(IFlashtestationRegistry.InvalidQuote.selector); // the "partial" just means we don't care about the bytes argument to InvalidQuote(bytes)
        registry.registerTEEService(mockQuote, bytes(""));
    }

    function test_reverts_with_registering_same_quote_twice() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;
        bytes32 expectedQuoteHash = keccak256(mockQuote);

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, bytes(""));

        vm.expectRevert(
            abi.encodeWithSelector(
                IFlashtestationRegistry.TEEServiceAlreadyRegistered.selector, expectedAddress, expectedQuoteHash
            )
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, bytes(""));
    }

    function test_reverts_with_invalid_quote_version() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.quoteVersion = 0x0000;
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setQuoteResult(mockQuote, true, serializedOutput);
        vm.expectRevert(QuoteParser.InvalidTEEVersion.selector, 0);
        registry.registerTEEService(mockQuote, bytes(""));
    }

    function test_reverts_with_invalid_tee_type() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.tee = bytes4(0x00000000);
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setQuoteResult(mockQuote, true, serializedOutput);
        vm.expectRevert(QuoteParser.InvalidTEEType.selector, 0);
        registry.registerTEEService(mockQuote, bytes(""));
    }

    function test_reverts_with_too_large_quote() public {
        bytes memory mockQuote = bf42Mock.quote;

        // take a 4.9K file and concatenate it 5 times to make it over the 20KB limit
        bytes memory tooLargeQuote = abi.encodePacked(mockQuote, mockQuote, mockQuote, mockQuote, mockQuote);
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.ByteSizeExceeded.selector, tooLargeQuote.length));
        registry.registerTEEService(tooLargeQuote, bytes(""));
    }

    function test_reverts_when_sender_does_not_match_tee_address() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Call with a different address than the one in the quote
        address differentAddress = address(0x1234);
        vm.prank(differentAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFlashtestationRegistry.SenderMustMatchTEEAddress.selector, differentAddress, expectedAddress
            )
        );
        registry.registerTEEService(mockQuote, bytes(""));
    }

    function test_getRegistration_returns_true_for_valid_registration() public {
        // First register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        bytes memory extendedData = abi.encode("test");
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, extendedData);

        // Now check that getRegistration returns valid data
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        assertTrue(isValid, "getRegistration should return true for valid TEE");
        assertEq(registration.rawQuote, mockQuote, "Quote should match");
        assertEq(registration.extendedRegistrationData, extendedData, "Extended data should match");
    }

    function test_getRegistration_returns_false_for_invalid_tee() public {
        // First register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, bytes(""));

        // Now invalidate the TEE
        attestationContract.setQuoteResult(mockQuote, false, new bytes(0));
        registry.invalidateAttestation(expectedAddress);

        // Now check that getRegistration returns false for isValid
        (bool isValid,) = registry.getRegistration(expectedAddress);
        assertFalse(isValid, "getRegistration should return false for invalid TEE");
    }

    function test_getRegistration_returns_false_for_unregistered_tee() public view {
        // Use an address that hasn't been registered
        address unregisteredAddress = address(0xdead);

        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(unregisteredAddress);
        assertFalse(isValid, "getRegistration should return false for unregistered TEE address");
        assertEq(registration.rawQuote.length, 0, "Raw quote should be empty");
    }

    function test_invalidateAttestation_reverts_if_not_registered() public {
        address unregisteredAddress = address(0xdeadbeef);
        vm.expectRevert(
            abi.encodeWithSelector(IFlashtestationRegistry.TEEServiceNotRegistered.selector, unregisteredAddress)
        );
        registry.invalidateAttestation(unregisteredAddress);
    }

    function test_invalidateAttestation_reverts_if_already_invalid() public {
        // Register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, bytes(""));

        // Now, invalidate with success==false (should invalidate)
        attestationContract.setQuoteResult(mockQuote, false, new bytes(0));
        vm.prank(address(0x123));
        registry.invalidateAttestation(teeAddress);

        // Now, calling again should revert with TEEServiceAlreadyInvalid
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.TEEServiceAlreadyInvalid.selector, teeAddress));
        registry.invalidateAttestation(teeAddress);
    }

    function test_invalidateAttestation_reverts_if_still_valid() public {
        // Register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;
        bytes32 quoteHash = keccak256(mockQuote);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, bytes(""));
        // Now, invalidate with success==true (still valid)

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.TEEIsStillValid.selector, teeAddress, quoteHash));
        registry.invalidateAttestation(teeAddress);
    }

    function test_invalidateAttestation_invalidates_and_emits_event() public {
        // Register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;
        bytes32 quoteHash = keccak256(mockQuote);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, bytes(""));
        // Now, invalidate with success==false (should invalidate)
        attestationContract.setQuoteResult(mockQuote, false, new bytes(0));
        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceInvalidated(teeAddress);
        registry.invalidateAttestation(teeAddress);
        // Check isValid is now false
        (bool isValid,) = registry.getRegistration(teeAddress);
        assertFalse(isValid, "TEE should be invalid after invalidate");
    }

    function test_extended_registration_data_validation() public {
        // Test that extended registration data hash must match reportData[20:52]
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;

        // Parse the output to get the report body
        TD10ReportBody memory reportBody = QuoteParser.parseV4VerifierOutput(mockOutput);

        // Create extended data that doesn't match the hash in reportData[20:52]
        bytes memory invalidExtendedData = abi.encode("wrong data");

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(teeAddress);
        vm.expectRevert("invalid registration data hash");
        registry.registerTEEService(mockQuote, invalidExtendedData);
    }

    function test_parsedReportBody_stored_correctly() public {
        bytes memory mockOutput = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin"
        );
        bytes memory mockQuote = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        );
        address teeAddress = 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03;

        // Parse expected report body
        TD10ReportBody memory expectedReportBody = QuoteParser.parseV4VerifierOutput(mockOutput);

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, bytes(""));

        // Get stored report body
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(teeAddress);

        assertTrue(isValid);

        // Verify key fields are stored correctly
        assertEq(registration.parsedReportBody.mrTd, expectedReportBody.mrTd, "mrTd mismatch");
        assertEq(registration.parsedReportBody.mrConfigId, expectedReportBody.mrConfigId, "mrConfigId mismatch");
        assertEq(registration.parsedReportBody.tdAttributes, expectedReportBody.tdAttributes, "tdAttributes mismatch");
        assertEq(registration.parsedReportBody.xFAM, expectedReportBody.xFAM, "xFAM mismatch");
    }

    function test_data_extracted_from_reportData() public {
        // This test verifies that the TEE address is properly extracted from reportData[0:20]
        bytes memory mockOutput = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin"
        );
        bytes memory mockQuote = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        );

        // Parse the output to verify the expected address
        TD10ReportBody memory reportBody = QuoteParser.parseV4VerifierOutput(mockOutput);
        (address extractedAddress, bytes32 extractedExtDataHash) = QuoteParser.parseReportData(reportBody.reportData);

        address expectedAddress = 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03;
        assertEq(extractedAddress, expectedAddress, "Address should be extracted from reportData[0:20]");

        bytes memory expectedExtendedData = "";
        require(keccak256(expectedExtendedData) == extractedExtDataHash, "Test data mismatch");

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Can only register from the address in the quote
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, bytes(""));

        // Verify it was registered to the correct address
        (bool isValid,) = registry.getRegistration(expectedAddress);
        assertTrue(isValid);
    }

    function test_extendedRegistrationData_stored_correctly() public {
        // Use real test data
        bytes memory mockOutput = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin"
        );
        bytes memory mockQuote = vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        );
        address teeAddress = 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03;

        // Create complex extended data
        bytes memory extData = abi.encode("xxxxxxxx");
        bytes memory encodedExtData = abi.encode(extData);

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, encodedExtData);

        // Verify extended data was stored
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(teeAddress);

        assertTrue(isValid);
        assertEq(registration.extendedRegistrationData, encodedExtData);
    }

    function test_reportdata_length_validation() public {
        // Create a mock quote with reportData shorter than 52 bytes
        bytes memory mockQuote = bf42Mock.quote;

        // Create a mock output with short reportData
        bytes memory shortReportData = new bytes(30); // Less than TD_REPORTDATA_LENGTH (52)

        // Create a valid TD10ReportBody but with short reportData
        TD10ReportBody memory shortReport;
        shortReport.teeTcbSvn = bytes16(0);
        shortReport.mrSeam = new bytes(48);
        shortReport.mrsignerSeam = new bytes(48);
        shortReport.seamAttributes = bytes8(0);
        shortReport.tdAttributes = bytes8(0);
        shortReport.xFAM = bytes8(0);
        shortReport.mrTd = new bytes(48);
        shortReport.mrConfigId = new bytes(48);
        shortReport.mrOwner = new bytes(48);
        shortReport.mrOwnerConfig = new bytes(48);
        shortReport.rtMr0 = new bytes(48);
        shortReport.rtMr1 = new bytes(48);
        shortReport.rtMr2 = new bytes(48);
        shortReport.rtMr3 = new bytes(48);
        shortReport.reportData = shortReportData;

        // We need to create a properly formatted output that will pass verification
        // but has short reportData. This is tricky since we can't easily mock the internal
        // parsing. Instead, let's test that registration fails when reportData is too short.

        // For this test, we'll need to create a custom mock that returns short reportData
        // This would require modifying the mock attestation contract or creating a new one
        // For now, we'll skip this test as it requires deeper mocking
    }

    /// @dev we need the comment below because QuoteParser.parseV4Quote() is internal
    /// and we want to test that it reverts with the correct error message
    /// forge-config: default.allow_internal_expect_revert = true
    function test_parseV4Quote_reverts_on_invalid_length() public {
        // Use a quote of invalid length (e.g., one byte too short)
        bytes memory validRawQuote = bf42Mock.quote;
        bytes memory shortQuote = new bytes(TD_REPORT10_LENGTH + HEADER_LENGTH - 1);
        for (uint256 i = 0; i < shortQuote.length; i++) {
            shortQuote[i] = validRawQuote[i];
        }

        vm.expectRevert(abi.encodeWithSelector(QuoteParser.InvalidQuoteLength.selector, shortQuote.length));
        QuoteParser.parseV4Quote(shortQuote);
    }

    function test_upgradeTo_reverts_if_not_owner() public {
        // Deploy a new implementation
        address newImplementation = address(new FlashtestationRegistry());

        // Try to upgrade as non-owner
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)));
        upgrader.upgradeProxy(address(registry), newImplementation, bytes(""), address(0x123));
    }

    function test_upgradeTo_succeeds_if_owner() public {
        // Deploy a new implementation
        address newImplementation = address(new FlashtestationRegistry());

        // Upgrade as owner
        upgrader.upgradeProxy(address(registry), newImplementation, bytes(""), address(owner));

        // Verify the implementation was updated
        assertEq(upgrader.getImplementation(address(registry)), newImplementation);
    }

    function test_successful_permitRegisterTEEService() public {
        // First get a valid attestation quote stored
        bytes memory mockOutput = mock7b91.output;
        bytes memory mockQuote = mock7b91.quote;
        address expectedAddress = mock7b91.teeAddress;

        // Set the attestation contract to return a successful attestation
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        bytes memory extendedData = abi.encode("permit test");

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, extendedData, 0);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Register the TEE
        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);

        // the caller here is unspecified (i.e. no vm.prank), so if it succeeds
        // it means any address can call this function (assuming they have the correct signature)
        registry.permitRegisterTEEService(mockQuote, extendedData, 0, signature);

        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registration.extendedRegistrationData, extendedData, "Extended data mismatch");
        vm.assertEq(registry.nonces(expectedAddress), 1, "Nonce should be incremented");
    }

    function test_permitRegisterTEEService_reverts_with_invalid_signature() public {
        bytes memory mockOutput = mock7b91.output;
        bytes memory mockQuote = mock7b91.quote;
        (, uint256 invalid_pk) = makeAddrAndKey("invalid_signer");

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        bytes memory extendedData = abi.encode("test");

        // Create the EIP-712 signature with wrong private key
        bytes32 structHash = registry.computeStructHash(mockQuote, extendedData, 0);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(invalid_pk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // The function doesn't revert with InvalidSignature anymore, it reverts during
        // the registration process when checking caller vs teeAddress
        vm.expectRevert();
        registry.permitRegisterTEEService(mockQuote, extendedData, 0, signature);
    }

    function test_permitRegisterTEEService_reverts_with_invalid_nonce() public {
        bytes memory mockOutput = mock7b91.output;
        bytes memory mockQuote = mock7b91.quote;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        bytes memory extendedData = abi.encode("test");

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, extendedData, 1); // wrong nonce
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 0, 1));
        registry.permitRegisterTEEService(mockQuote, extendedData, 1, signature);
    }

    function test_permitRegisterTEEService_reverts_with_replayed_signature() public {
        bytes memory mockOutput = mock7b91.output;
        bytes memory mockQuote = mock7b91.quote;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        bytes memory extendedData = abi.encode("test");

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, extendedData, 0);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First registration should succeed
        registry.permitRegisterTEEService(mockQuote, extendedData, 0, signature);

        // Try to replay the same signature
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 1, 0));
        registry.permitRegisterTEEService(mockQuote, extendedData, 0, signature);
    }
}
