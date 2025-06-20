// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
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
    WorkloadId workloadId;
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
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
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
        workloadId: WorkloadId.wrap(0x5e6be81f9e5b10d15a6fa69b19ab0269cd943db39fa1f0d38a76eb76146948cb),
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
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
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
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
        privateKey: 0x92e4b5ed61db615b26da2271da5b47c42d691b3164561cfb4edbc85ca6ca61a8
    });

    // this is some random workloadId that is not the same as the one in the mock quotes
    WorkloadId wrongWorkloadId = WorkloadId.wrap(0x20ab431377d40de192f7c754ac0f1922de05ab2f73e74204f0b3ab73a8856876);

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
        WorkloadId expectedWorkloadId = bf42Mock.workloadId;

        // set the attestation contract to return a successful attestation
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(
            expectedAddress, expectedWorkloadId, mockQuote, bf42Mock.publicKey, false
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        (WorkloadId workloadId, bytes memory rawQuote, bool isValid, bytes memory publicKey) =
            registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(publicKey, bf42Mock.publicKey, "Public key mismatch");
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
        emit IFlashtestationRegistry.TEEServiceRegistered(
            expectedAddress, expectedWorkloadId, mockQuote, d204Mock.publicKey, false
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        (WorkloadId workloadId, bytes memory rawQuote, bool isValid, bytes memory publicKey) =
            registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(publicKey, d204Mock.publicKey, "Public key mismatch");
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
        emit IFlashtestationRegistry.TEEServiceRegistered(
            expectedAddress, expectedWorkloadId, mockQuote2, d204Mock.publicKey, true
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote2);

        (WorkloadId workloadId2, bytes memory rawQuote2, bool isValid2, bytes memory publicKey2) =
            registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid2, true, "TEE should be valid");
        vm.assertEq(WorkloadId.unwrap(workloadId2), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote2, mockQuote2, "Raw quote mismatch");
        vm.assertEq(publicKey2, d204Mock.publicKey, "Public key mismatch");
        vm.assertNotEq(mockQuote, mockQuote2, "Quotes should not be the same");
    }

    function test_successful_re_registerTEEService_with_different_workload_ids() public {
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        bytes memory expectedPublicKey = bf42Mock.publicKey;
        address expectedAddress = bf42Mock.teeAddress;
        WorkloadId expectedWorkloadId = bf42Mock.workloadId;

        // set the attestation contract to return a successful attestation
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.expectEmit(address(registry));

        emit IFlashtestationRegistry.TEEServiceRegistered(
            expectedAddress, expectedWorkloadId, mockQuote, bf42Mock.publicKey, false
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        (WorkloadId workloadId, bytes memory rawQuote, bool isValid, bytes memory publicKey) =
            registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(publicKey, bf42Mock.publicKey, "Public key mismatch");

        // now register the same TEE-contraolled address again with a different quote and workloadId

        bytes memory mockOutput2 = bf42MockWithDifferentWorkloadId.output;
        bytes memory mockQuote2 = bf42MockWithDifferentWorkloadId.quote;
        expectedPublicKey = bf42MockWithDifferentWorkloadId.publicKey;
        expectedWorkloadId = bf42MockWithDifferentWorkloadId.workloadId;
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput2);

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(
            expectedAddress, expectedWorkloadId, mockQuote2, expectedPublicKey, true
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote2);

        (WorkloadId workloadId2, bytes memory rawQuote2, bool isValid2, bytes memory publicKey2) =
            registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid2, true, "TEE should be valid");
        vm.assertEq(WorkloadId.unwrap(workloadId2), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote2, mockQuote2, "Raw quote mismatch");
        vm.assertEq(publicKey2, expectedPublicKey, "Public key mismatch");
        vm.assertNotEq(mockQuote, mockQuote2, "Quotes should not be the same");
    }

    function test_reverts_with_invalid_quote_registerTEEService() public {
        attestationContract.setSuccess(false);
        // don't bother setting the output, since it should revert before it's used

        vm.expectPartialRevert(IFlashtestationRegistry.InvalidQuote.selector); // the "partial" just means we don't care about the bytes argument to InvalidQuote(bytes)
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
                IFlashtestationRegistry.TEEServiceAlreadyRegistered.selector, expectedAddress, expectedWorkloadId
            )
        );
        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);
    }

    function test_reverts_with_invalid_quote_version() public {
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
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.ByteSizeExceeded.selector, tooLargeQuote.length));
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
                IFlashtestationRegistry.SenderMustMatchTEEAddress.selector, differentAddress, expectedAddress
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

    function test_isValidWorkload_returns_false_for_invalid_tee() public {
        // First register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address expectedAddress = bf42Mock.teeAddress;
        WorkloadId expectedWorkloadId = bf42Mock.workloadId;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService(mockQuote);

        // Now invalidate the TEE
        attestationContract.setSuccess(false);
        registry.invalidateAttestation(expectedAddress);

        // Now check that isValidWorkload returns false for this combination
        bool isValid = registry.isValidWorkload(expectedWorkloadId, expectedAddress);
        assertFalse(isValid, "isValidWorkload should return false for invalid TEE");

        // also make sure isValidWorkload returns false for a different workloadId
        isValid = registry.isValidWorkload(wrongWorkloadId, expectedAddress);
        assertFalse(isValid, "isValidWorkload should return false for invalid TEE");
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
            abi.encodeWithSelector(IFlashtestationRegistry.TEEServiceNotRegistered.selector, unregisteredAddress)
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
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.TEEServiceAlreadyInvalid.selector, teeAddress));
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
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.TEEIsStillValid.selector, teeAddress));
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
        emit IFlashtestationRegistry.TEEServiceInvalidated(teeAddress);
        registry.invalidateAttestation(teeAddress);
        // Check isValid is now false
        (,, bool isValid,) = registry.registeredTEEs(teeAddress);
        assertFalse(isValid, "TEE should be invalid after invalidate");
    }

    function test_parseV4Quote_parses_valid_quote() public {
        // Register a valid TEE
        bytes memory mockOutput = bf42Mock.output;
        bytes memory mockQuote = bf42Mock.quote;
        address teeAddress = bf42Mock.teeAddress;
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);
        vm.prank(teeAddress);
        registry.registerTEEService(mockQuote);

        // Should not revert and should return a TD10ReportBody
        TD10ReportBody memory report = registry.getReportBody(teeAddress);

        assertEq(report.reportData.length, 64, "reportData should be 64 bytes");
        assertEq(report.reportData, bf42Mock.publicKey, "reportData should match the public key");
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
        WorkloadId expectedWorkloadId = mock7b91.workloadId;

        // Set the attestation contract to return a successful attestation
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, 0);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Register the TEE
        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(
            expectedAddress, expectedWorkloadId, mockQuote, mock7b91.publicKey, false
        );

        // the caller here is unspecified (i.e. no vm.prank), so if it succeeds
        // it means any address can call this function (assuming they have the correct signature)
        registry.permitRegisterTEEService(mockQuote, 0, signature);

        (WorkloadId workloadId, bytes memory rawQuote, bool isValid, bytes memory publicKey) =
            registry.registeredTEEs(expectedAddress);
        vm.assertEq(isValid, true, "TEE should be valid");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(publicKey, mock7b91.publicKey, "Public key mismatch");
        vm.assertEq(registry.nonces(expectedAddress), 1, "Nonce should be incremented");
    }

    function test_permitRegisterTEEService_reverts_with_invalid_signature() public {
        bytes memory mockOutput = mock7b91.output;
        bytes memory mockQuote = mock7b91.quote;
        (, uint256 invalid_pk) = makeAddrAndKey("invalid_signer");

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        // Create the EIP-712 signature with wrong private key (i.e. 0x1)
        bytes32 structHash = registry.computeStructHash(mockQuote, 0);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(invalid_pk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(IFlashtestationRegistry.InvalidSignature.selector);
        registry.permitRegisterTEEService(mockQuote, 0, signature);
    }

    function test_permitRegisterTEEService_reverts_with_invalid_nonce() public {
        bytes memory mockOutput = mock7b91.output;
        bytes memory mockQuote = mock7b91.quote;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, 1); // wrong nonce
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 0, 1));
        registry.permitRegisterTEEService(mockQuote, 1, signature);
    }

    function test_permitRegisterTEEService_reverts_with_replayed_signature() public {
        bytes memory mockOutput = mock7b91.output;
        bytes memory mockQuote = mock7b91.quote;

        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        // Create the EIP-712 signature
        bytes32 structHash = registry.computeStructHash(mockQuote, 0);
        bytes32 digest = registry.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First registration should succeed
        registry.permitRegisterTEEService(mockQuote, 0, signature);

        // Try to replay the same signature
        vm.expectRevert(abi.encodeWithSelector(IFlashtestationRegistry.InvalidNonce.selector, 1, 0));
        registry.permitRegisterTEEService(mockQuote, 0, signature);
    }
}
