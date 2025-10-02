// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

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
    bytes extData;
    address teeAddress;
    uint256 privateKey;
}

contract FlashtestationRegistryTest is Test {
    address public owner = address(this);
    FlashtestationRegistry public registry;
    Upgrader public upgrader = new Upgrader();
    MockAutomataDcapAttestationFee public attestationContract;
    MockQuote mockf200 = MockQuote({
        output: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/quote.bin"),
        extData: bytes(""),
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote mockc200 = MockQuote({ // non-empty ext data
        output: vm.readFileBinary("test/raw_tdx_quotes/0xc200F222043C5BC6c70aA6e35f5c5fDE079f3A04/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0xc200F222043C5BC6c70aA6e35f5c5fDE079f3A04/quote.bin"),
        extData: bytes("xxxxxxxx"),
        teeAddress: 0xc200F222043C5BC6c70aA6e35f5c5fDE079f3A04,
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote mock12c1 = MockQuote({
        output: vm.readFileBinary("test/raw_tdx_quotes/0x12c14e56d585Dcf3B36f37476c00E78bA9363742/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0x12c14e56d585Dcf3B36f37476c00E78bA9363742/quote.bin"),
        extData: bytes(""),
        teeAddress: 0x12c14e56d585Dcf3B36f37476c00E78bA9363742,
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote mock46f6 = MockQuote({
        output: vm.readFileBinary("test/raw_tdx_quotes/0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF/quote.bin"),
        extData: bytes(""),
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

        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        // set the attestation contract to return a successful attestation
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);

        // Get the registration
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);

        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registration.extendedRegistrationData, mockf200.extData, "Extended data mismatch");
        vm.assertEq(registration.isValid, true, "Registration should be valid");
    }

    // test that we can register the same TEEService again with a different quote
    function test_successful_re_registerTEEService() public {
        // do the first register of the TEEService with a valid quote
        bytes memory mockOutput = mock12c1.output;
        bytes memory mockQuote = mock12c1.quote;
        address expectedAddress = mock12c1.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, mock12c1.extData);

        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");

        // now register the same TEEService again with a different quote

        bytes memory mockQuote2 =
            vm.readFileBinary("test/raw_tdx_quotes/0x12c14e56d585Dcf3B36f37476c00E78bA9363742/quote2.bin");
        bytes memory mockOutput2 =
            vm.readFileBinary("test/raw_tdx_quotes/0x12c14e56d585Dcf3B36f37476c00E78bA9363742/output2.bin");
        attestationContract.setQuoteResult(mockQuote2, true, mockOutput2);

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote2, true);
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote2, mock12c1.extData);

        (bool isValid2, IFlashtestationRegistry.RegisteredTEE memory registration2) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid2, true, "TEE should be valid");
        vm.assertEq(registration2.rawQuote, mockQuote2, "Raw quote mismatch");
        vm.assertEq(registration2.extendedRegistrationData, mock12c1.extData, "Extended data mismatch");
        vm.assertNotEq(mockQuote, mockQuote2, "Quotes should not be the same");
    }

    function test_reverts_with_invalid_quote_registerTEEService() public {
        bytes memory mockQuote = mockf200.quote;
        attestationContract.setQuoteResult(mockQuote, false, new bytes(0));

        vm.expectPartialRevert(IFlashtestationRegistry.InvalidQuote.selector); // the "partial" just means we don't care about the bytes argument to InvalidQuote(bytes)
        registry.registerTEEService(mockQuote, mockf200.extData);
    }

    function test_reverts_with_invalid_attestation_contract() public {
        address implementation = address(new FlashtestationRegistry());
        vm.expectRevert(IFlashtestationRegistry.InvalidAttestationContract.selector);
        UnsafeUpgrades.deployUUPSProxy(
            implementation, abi.encodeCall(FlashtestationRegistry.initialize, (owner, address(0x0)))
        );
    }

    function test_reverts_with_registering_same_quote_twice() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);

        vm.expectRevert(
            abi.encodeWithSelector(IFlashtestationRegistry.TEEServiceAlreadyRegistered.selector, expectedAddress)
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);
    }

    function test_reverts_with_invalid_quote_version() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.quoteVersion = 0x0000;
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setQuoteResult(mockQuote, true, serializedOutput);
        vm.expectRevert(abi.encodeWithSelector(QuoteParser.InvalidTEEVersion.selector, 0));
        registry.registerTEEService(mockQuote, mockf200.extData);
    }

    function test_reverts_with_invalid_tee_type() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.tee = bytes4(0x00000000);
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setQuoteResult(mockQuote, true, serializedOutput);
        vm.expectRevert(abi.encodeWithSelector(QuoteParser.InvalidTEEType.selector, 0));
        registry.registerTEEService(mockQuote, mockf200.extData);
    }

    function test_reverts_with_too_large_quote() public {
        bytes memory mockQuote = mockf200.quote;

        // take a 4.9K file and concatenate it 5 times to make it over the 20KB limit
        bytes memory tooLargeQuote = abi.encodePacked(mockQuote, mockQuote, mockQuote, mockQuote, mockQuote);
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.ByteSizeExceeded.selector, tooLargeQuote.length));
        registry.registerTEEService(tooLargeQuote, mockf200.extData);
    }

    function test_reverts_when_sender_does_not_match_tee_address() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Call with a different address than the one in the quote
        address differentAddress = address(0x1234);
        vm.prank(differentAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFlashtestationRegistry.SignerMustMatchTEEAddress.selector, differentAddress, expectedAddress
            )
        );
        registry.registerTEEService(mockQuote, mockf200.extData);
    }

    function test_getRegistration_returns_true_for_valid_registration() public {
        // First register a valid TEE
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);

        // Now check that getRegistration returns valid data
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        assertTrue(isValid, "getRegistration should return true for valid TEE");
        assertEq(registration.rawQuote, mockQuote, "Quote should match");
    }

    function test_getRegistration_returns_false_for_invalid_tee() public {
        // First register a valid TEE
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);

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
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address teeAddress = mockf200.teeAddress;
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);

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
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address teeAddress = mockf200.teeAddress;
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);
        // Now, invalidate with success==true (still valid)

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.TEEIsStillValid.selector, teeAddress));
        registry.invalidateAttestation(teeAddress);
    }

    function test_invalidateAttestation_invalidates_and_emits_event() public {
        // Register a valid TEE
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address teeAddress = mockf200.teeAddress;
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);
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
        bytes memory mockOutput = mockc200.output;
        bytes memory mockQuote = mockc200.quote;
        address teeAddress = mockc200.teeAddress;

        // Create extended data that doesn't match the hash in reportData[20:52]
        bytes memory invalidExtendedData = abi.encode("wrong data");

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(teeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFlashtestationRegistry.InvalidRegistrationDataHash.selector,
                keccak256(mockc200.extData),
                keccak256(invalidExtendedData)
            )
        );
        registry.registerTEEService(mockQuote, invalidExtendedData);
    }

    function test_parsedReportBody_stored_correctly() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address teeAddress = mockf200.teeAddress;

        // Parse expected report body
        TD10ReportBody memory expectedReportBody = QuoteParser.parseV4VerifierOutput(mockOutput);

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote, mockf200.extData);

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
        bytes memory mockOutput = mockc200.output;
        bytes memory mockQuote = mockc200.quote;

        // Parse the output to verify the expected address
        TD10ReportBody memory reportBody = QuoteParser.parseV4VerifierOutput(mockOutput);
        (address extractedAddress, bytes32 extractedExtDataHash) = QuoteParser.parseReportData(reportBody.reportData);

        address expectedAddress = mockc200.teeAddress;
        assertEq(extractedAddress, expectedAddress, "Address should be extracted from reportData[0:20]");

        require(keccak256(mockc200.extData) == extractedExtDataHash, "Test data mismatch");

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Can only register from the address in the quote
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote, mockc200.extData);

        // Verify it was registered to the correct address
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        assertTrue(isValid);
        assertEq(registration.extendedRegistrationData, mockc200.extData);
    }

    function test_extDataMismatch() public {
        // This test verifies that using a mismatched extendedRegistrationData will result in an error
        bytes memory mockOutput = mockc200.output;
        bytes memory mockQuote = mockc200.quote;

        // Parse the output to verify the expected address
        TD10ReportBody memory reportBody = QuoteParser.parseV4VerifierOutput(mockOutput);
        (address extractedAddress, bytes32 extractedExtDataHash) = QuoteParser.parseReportData(reportBody.reportData);
        assertEq(extractedExtDataHash, keccak256(mockc200.extData));

        address expectedAddress = 0xc200F222043C5BC6c70aA6e35f5c5fDE079f3A04;
        assertEq(extractedAddress, expectedAddress, "Address should be extracted from reportData[0:20]");

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // keccak hash of extendedRegistrationData must match the 32 byte hash in the reportData
        vm.prank(expectedAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFlashtestationRegistry.InvalidRegistrationDataHash.selector,
                keccak256(mockc200.extData),
                keccak256(bytes("xxxx"))
            )
        );
        registry.registerTEEService(mockQuote, bytes("xxxx"));
    }

    /// @dev we need the comment below because QuoteParser.parseV4Quote() is internal
    /// and we want to test that it reverts with the correct error message
    /// forge-config: default.allow_internal_expect_revert = true
    function test_parseV4Quote_reverts_on_invalid_length() public {
        // Use a quote of invalid length (e.g., one byte too short)
        bytes memory validRawQuote = mockf200.quote;
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
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;
        address expectedAddress = mock46f6.teeAddress;

        // Set the attestation contract to return a successful attestation
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, 0, block.timestamp);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Register the TEE
        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);

        // the caller here is unspecified (i.e. no vm.prank), so if it succeeds
        // it means any address can call this function (assuming they have the correct signature)
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, 0, block.timestamp, signature);

        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registration.extendedRegistrationData, mock46f6.extData, "Extended data mismatch");
        vm.assertEq(registry.nonces(expectedAddress), 1, "Nonce should be incremented");
    }

    function test_permitRegisterTEEService_reverts_with_invalid_signature() public {
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;
        (, uint256 invalid_pk) = makeAddrAndKey("invalid_signer");

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Create the EIP-712 signature with wrong private key
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, 0, block.timestamp);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(invalid_pk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // The function doesn't revert with InvalidSignature anymore, it reverts during
        // the registration process when checking caller vs teeAddress
        vm.expectRevert();
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, 0, block.timestamp, signature);
    }

    function test_permitRegisterTEEService_reverts_with_invalid_nonce() public {
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, 1, block.timestamp); // wrong nonce
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 0, 1));
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, 1, block.timestamp, signature);
    }

    function test_permitRegisterTEEService_reverts_with_signature_past_deadline() public {
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, 0, block.timestamp - 1);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.ExpiredSignature.selector, block.timestamp - 1));
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, 0, block.timestamp - 1, signature);
    }

    function test_permitRegisterTEEService_reverts_with_replayed_signature() public {
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, 0, block.timestamp);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First registration should succeed
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, 0, block.timestamp, signature);

        // Try to replay the same signature
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 1, 0));
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, 0, block.timestamp, signature);
    }

    function test_invalidatePreviousSignature_reverts_if_nonce_does_not_match() public {
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 0, 1));
        registry.invalidatePreviousSignature(1);
    }

    function test_invalidatePreviousSignature_reverts_for_nonzero_nonce() public {
        // first register a valid TEE
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        // Create the EIP-712 signature
        uint256 nonce = 0;
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, nonce, block.timestamp);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Register the TEE, which consumes nonce == 0
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, nonce, block.timestamp, signature);

        // now invalidate the nonce == 1, and make sure it is indeed invalidated

        vm.prank(mock46f6.teeAddress);
        registry.invalidatePreviousSignature(nonce + 1);

        // try and fail to use the invalidated nonce + 1;
        structHash = registry.computeStructHash(mockQuote, mock46f6.extData, nonce + 1, block.timestamp);
        digest = registry.hashTypedDataV4(structHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);

        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 2, nonce + 1));
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, nonce + 1, block.timestamp, signature2);
    }

    function test_invalidatePreviousSignature_increments_nonce() public {
        // Prepare a valid permit signature with nonce 0
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;

        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 1000;
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, nonce, deadline);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Invalidate the current nonce (0)
        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.PreviousSignatureInvalidated(mock46f6.teeAddress, 0);
        vm.prank(mock46f6.teeAddress);
        registry.invalidatePreviousSignature(nonce);

        // Now, a permit with nonce 0 should revert with InvalidNonce(1, 0)
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 1, 0));
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, nonce, deadline, signature);

        // and finally, make sure that we can use the newest nonce
        structHash = registry.computeStructHash(mockQuote, mock46f6.extData, nonce + 1, deadline);
        digest = registry.hashTypedDataV4(structHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        registry.permitRegisterTEEService(mockQuote, mock46f6.extData, nonce + 1, deadline, signature2);
    }
}
