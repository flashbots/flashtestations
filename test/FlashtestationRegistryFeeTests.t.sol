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
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

// a simple struct to store related mocked quote data for testing
struct MockQuote {
    bytes output;
    bytes quote;
    bytes extData;
    address teeAddress;
    uint256 privateKey;
}

contract FlashtestationRegistryFeeTest is Test {
    address public owner = address(this);
    FlashtestationRegistry public registry;
    MockAutomataDcapAttestationFee public attestationContract;

    uint256 public constant TEST_FEE = 0.01 ether;

    MockQuote mockf200 = MockQuote({
        output: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/quote.bin"),
        extData: bytes(""),
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
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

    // HAPPY PATH TESTS

    function test_registerTEEService_withCorrectFee() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        // Set fee and configure attestation
        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.deal(expectedAddress, 1 ether);

        // Record initial balances
        uint256 initialRegistryBalance = address(registry).balance;
        uint256 initialAttestationBalance = address(attestationContract).balance;
        uint256 initialCallerBalance = expectedAddress.balance;

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);

        vm.prank(expectedAddress);
        registry.registerTEEService{value: TEST_FEE}(mockQuote, mockf200.extData);

        // Verify registration succeeded
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);

        assertTrue(isValid, "TEE should be valid");
        assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");

        // Verify fee was forwarded
        assertEq(
            address(attestationContract).balance,
            initialAttestationBalance + TEST_FEE,
            "Attestation contract should receive fee"
        );
        assertEq(address(registry).balance, initialRegistryBalance, "Registry should not retain fee");
        assertLe(address(registry).balance, initialCallerBalance - TEST_FEE, "caller should have sent the fee");
    }

    function test_permitRegisterTEEService_withCorrectFee() public {
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;
        address expectedAddress = mock46f6.teeAddress;
        uint256 privateKey = mock46f6.privateKey;

        // Set fee and configure attestation
        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        uint256 nonce = registry.nonces(expectedAddress);
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, nonce);
        bytes32 digest = registry.hashTypedDataV4(structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.deal(address(this), 1 ether);

        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceRegistered(expectedAddress, mockQuote, false);

        registry.permitRegisterTEEService{value: TEST_FEE}(mockQuote, mock46f6.extData, nonce, signature);

        // Verify registration succeeded
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(expectedAddress);

        assertTrue(isValid, "TEE should be valid");
        assertEq(registration.rawQuote, mockQuote, "Raw quote mismatch");
    }

    function test_invalidateAttestation_withCorrectFee() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        // First register the TEE
        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.deal(expectedAddress, 1 ether);
        vm.prank(expectedAddress);
        registry.registerTEEService{value: TEST_FEE}(mockQuote, mockf200.extData);

        // Now simulate attestation becoming invalid
        attestationContract.setQuoteResult(mockQuote, false, bytes(""));

        vm.deal(address(this), 1 ether);
        vm.expectEmit(address(registry));
        emit IFlashtestationRegistry.TEEServiceInvalidated(expectedAddress);

        registry.invalidateAttestation{value: TEST_FEE}(expectedAddress);

        // Verify TEE is now invalid
        (bool isValid,) = registry.getRegistration(expectedAddress);
        assertFalse(isValid, "TEE should be invalid");
    }

    // SAD PATH TESTS

    function test_registerTEEService_insufficientFee() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.deal(expectedAddress, 1 ether);
        vm.prank(expectedAddress);

        vm.expectRevert(
            abi.encodeWithSelector(MockAutomataDcapAttestationFee.InsufficientFee.selector, TEST_FEE, TEST_FEE - 1)
        );
        registry.registerTEEService{value: TEST_FEE - 1}(mockQuote, mockf200.extData);
    }

    function test_permitRegisterTEEService_insufficientFee() public {
        bytes memory mockOutput = mock46f6.output;
        bytes memory mockQuote = mock46f6.quote;
        address expectedAddress = mock46f6.teeAddress;
        uint256 privateKey = mock46f6.privateKey;

        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        uint256 nonce = registry.nonces(expectedAddress);
        bytes32 structHash = registry.computeStructHash(mockQuote, mock46f6.extData, nonce);
        bytes32 digest = registry.hashTypedDataV4(structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.deal(address(this), 1 ether);

        vm.expectRevert(
            abi.encodeWithSelector(MockAutomataDcapAttestationFee.InsufficientFee.selector, TEST_FEE, TEST_FEE - 1)
        );
        registry.permitRegisterTEEService{value: TEST_FEE - 1}(mockQuote, mock46f6.extData, nonce, signature);
    }

    function test_invalidateAttestation_insufficientFee() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        // First register the TEE
        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.deal(expectedAddress, 1 ether);
        vm.prank(expectedAddress);
        registry.registerTEEService{value: TEST_FEE}(mockQuote, mockf200.extData);

        // Now simulate attestation becoming invalid
        attestationContract.setQuoteResult(mockQuote, false, bytes(""));

        vm.deal(address(this), 1 ether);

        vm.expectRevert(
            abi.encodeWithSelector(MockAutomataDcapAttestationFee.InsufficientFee.selector, TEST_FEE, TEST_FEE - 1)
        );
        registry.invalidateAttestation{value: TEST_FEE - 1}(expectedAddress);
    }

    function test_registerTEEService_zeroFee_whenFeeRequired() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(expectedAddress);

        vm.expectRevert(abi.encodeWithSelector(MockAutomataDcapAttestationFee.InsufficientFee.selector, TEST_FEE, 0));
        registry.registerTEEService{value: 0}(mockQuote, mockf200.extData);
    }

    // EDGE CASE TESTS

    function test_registerTEEService_zeroFee_whenNoFeeSet() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        // No fee set (baseFee = 0)
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.prank(expectedAddress);
        registry.registerTEEService{value: 0}(mockQuote, mockf200.extData);

        // Verify registration succeeded
        (bool isValid,) = registry.getRegistration(expectedAddress);
        assertTrue(isValid, "TEE should be valid");
    }

    function test_registerTEEService_excessiveFee() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        attestationContract.setBaseFee(TEST_FEE);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        uint256 excessiveFee = TEST_FEE * 2;
        vm.deal(expectedAddress, 1 ether);
        vm.prank(expectedAddress);

        // Should succeed (excess fee is accepted)
        registry.registerTEEService{value: excessiveFee}(mockQuote, mockf200.extData);

        // Verify registration succeeded
        (bool isValid,) = registry.getRegistration(expectedAddress);
        assertTrue(isValid, "TEE should be valid");
    }

    function test_fee_changes_between_registration_and_invalidation() public {
        bytes memory mockOutput = mockf200.output;
        bytes memory mockQuote = mockf200.quote;
        address expectedAddress = mockf200.teeAddress;

        // Register with one fee
        uint256 registrationFee = 0.005 ether;
        attestationContract.setBaseFee(registrationFee);
        attestationContract.setQuoteResult(mockQuote, true, mockOutput);

        vm.deal(expectedAddress, 1 ether);
        vm.prank(expectedAddress);
        registry.registerTEEService{value: registrationFee}(mockQuote, mockf200.extData);

        // Change fee for invalidation
        uint256 invalidationFee = 0.015 ether;
        attestationContract.setBaseFee(invalidationFee);
        attestationContract.setQuoteResult(mockQuote, false, bytes(""));

        vm.deal(address(this), 1 ether);
        registry.invalidateAttestation{value: invalidationFee}(expectedAddress);

        // Verify TEE is now invalid
        (bool isValid,) = registry.getRegistration(expectedAddress);
        assertFalse(isValid, "TEE should be invalid");
    }

    function test_multiple_registrations_with_different_fees() public {
        bytes memory mockOutputF200 = mockf200.output;
        bytes memory mockQuoteF200 = mockf200.quote;
        address expectedAddressF200 = mockf200.teeAddress;

        bytes memory mockOutput46f6 = mock46f6.output;
        bytes memory mockQuote46f6 = mock46f6.quote;
        address expectedAddress46f6 = mock46f6.teeAddress;

        // Set up different fees for different registrations
        uint256 fee1 = 0.005 ether;
        uint256 fee2 = 0.01 ether;

        // First registration
        attestationContract.setBaseFee(fee1);
        attestationContract.setQuoteResult(mockQuoteF200, true, mockOutputF200);

        vm.deal(expectedAddressF200, 1 ether);
        vm.prank(expectedAddressF200);
        registry.registerTEEService{value: fee1}(mockQuoteF200, mockf200.extData);

        // Change fee for second registration
        attestationContract.setBaseFee(fee2);
        attestationContract.setQuoteResult(mockQuote46f6, true, mockOutput46f6);

        vm.deal(expectedAddress46f6, 1 ether);
        vm.prank(expectedAddress46f6);
        registry.registerTEEService{value: fee2}(mockQuote46f6, mock46f6.extData);

        // Verify both registrations succeeded
        (bool isValid1,) = registry.getRegistration(expectedAddressF200);
        (bool isValid2,) = registry.getRegistration(expectedAddress46f6);

        assertTrue(isValid1, "First TEE should be valid");
        assertTrue(isValid2, "Second TEE should be valid");
    }
}
