// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuardTransientUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IAttestation} from "./interfaces/IAttestation.sol";
import {IFlashtestationRegistry} from "./interfaces/IFlashtestationRegistry.sol";
import {QuoteParser} from "./utils/QuoteParser.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

/**
 * @title FlashtestationRegistry
 * @dev A contract for managing trusted execution environment (TEE) identities and configurations
 * using Automata's Intel DCAP attestation
 */
contract FlashtestationRegistry is
    IFlashtestationRegistry,
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardTransientUpgradeable
{
    using ECDSA for bytes32;

    // ============ Constants ============

    /// @notice Minimum length of the td reportdata field: tee address (20 bytes) and hash of extendedRegistrationData(32 bytes)
    /// @dev This is the minimum length of the td reportdata field, which is required by the TDX specification
    /// @dev The remaining 12 bytes of the 64 byte reportdata field is left unused, it does not matter what is put there
    uint256 public constant TD_REPORTDATA_LENGTH = 52;

    /// @notice Maximum size for byte arrays to prevent DoS attacks
    /// @dev 20KB limit
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024;

    /// @notice EIP-712 Typehash, used in the permitRegisterTEEService function
    bytes32 public constant override REGISTER_TYPEHASH =
        keccak256("RegisterTEEService(bytes rawQuote,bytes extendedRegistrationData,uint256 nonce,uint256 deadline)");

    // ============ Storage Variables ============

    /// @inheritdoc IFlashtestationRegistry
    IAttestation public override attestationContract;

    /**
     * @notice Returns the registered TEE for a given address
     * @dev This is used to get the registered TEE for a given address
     */
    mapping(address teeAddress => RegisteredTEE) public registeredTEEs;

    /// @inheritdoc IFlashtestationRegistry
    mapping(address teeAddress => uint256 permitNonce) public override nonces;

    /// @dev Storage gap to allow for future storage variable additions in upgrades
    /// @dev This reserves 47 storage slots (out of 50 total - 3 used for attestationContract, registeredTEEs and nonces)
    uint256[47] __gap;

    /// @inheritdoc IFlashtestationRegistry
    function initialize(address owner, address _attestationContract) external override initializer {
        __Ownable_init(owner);
        __EIP712_init("FlashtestationRegistry", "1");
        __ReentrancyGuardTransient_init();
        __UUPSUpgradeable_init();
        require(_attestationContract != address(0), InvalidAttestationContract());
        attestationContract = IAttestation(_attestationContract);
    }

    /**
     * @notice Internal function to authorize contract upgrades to the contract
     * @dev Only the owner can authorize upgrades
     * @dev This function is required by the UUPSUpgradeable contract
     * @dev Once there are no bugs in the code for a safe amount of time, we plan to transfer ownership
     * to the 0x0 address, so that the contract is no longer upgradeable
     * @param newImplementation The address of the new implementation contract
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Modifier to check if input bytes size is within limits
     * to protect against DoS attacks
     * @param data The bytes to check the size of
     */
    modifier limitBytesSize(bytes memory data) {
        require(data.length <= MAX_BYTES_SIZE, ByteSizeExceeded(data.length));
        _;
    }

    /// @inheritdoc IFlashtestationRegistry
    function registerTEEService(bytes calldata rawQuote, bytes calldata extendedRegistrationData)
        external
        payable
        override
        nonReentrant
    {
        doRegister(msg.sender, rawQuote, extendedRegistrationData);
    }

    /// @inheritdoc IFlashtestationRegistry
    function permitRegisterTEEService(
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable override nonReentrant {
        // Create the digest using EIP712Upgradeable's _hashTypedDataV4
        bytes32 digest = hashTypedDataV4(computeStructHash(rawQuote, extendedRegistrationData, nonce, deadline));

        // Recover the signer, and ensure it matches the TEE-controlled address, otherwise we have no proof
        // whoever created the attestation quote has access to the private key
        address signer = digest.recover(signature);

        // Verify the nonce
        uint256 expectedNonce = nonces[signer];
        require(nonce == expectedNonce, InvalidNonce(expectedNonce, nonce));

        require(block.timestamp <= deadline, ExpiredSignature(deadline));

        // Increment the nonce so that any attempts at replaying this transaction will fail
        nonces[signer]++;

        doRegister(signer, rawQuote, extendedRegistrationData);
    }

    /**
     * @notice Verifies + Registers a TEE workload with a specific TEE-controlled address in the FlashtestationRegistry
     * @dev In order to mitigate DoS attacks, the quote must be less than 20KB
     * @dev This is a costly operation (5 million gas) and should be used sparingly.
     * @param signer The address from which registration request originates, must match the one in the quote
     * @param rawQuote The raw quote from the TEE device. Must be a V4 TDX quote
     * @param extendedRegistrationData Abi-encoded application specific attested data
     */
    function doRegister(address signer, bytes calldata rawQuote, bytes calldata extendedRegistrationData)
        internal
        limitBytesSize(rawQuote)
        limitBytesSize(extendedRegistrationData)
    {
        (bool success, bytes memory output) = attestationContract.verifyAndAttestOnChain{value: msg.value}(rawQuote);
        require(success, InvalidQuote(output));

        // now we know the quote is valid, we can safely parse the output into the TDX report body,
        // from which we'll extract the data we need to register the TEE
        TD10ReportBody memory td10ReportBody = QuoteParser.parseV4VerifierOutput(output);

        // Binding the tee address and extended report data to the quote
        require(
            td10ReportBody.reportData.length >= TD_REPORTDATA_LENGTH,
            InvalidReportDataLength(td10ReportBody.reportData.length)
        );

        (address teeAddress, bytes32 extendedDataReportHash) = QuoteParser.parseReportData(td10ReportBody.reportData);

        // Ensure that the caller is the TEE-controlled address, otherwise we have no guarantees that
        // the TEE-controlled address is the one that is registering the TEE
        require(signer == teeAddress, SignerMustMatchTEEAddress(signer, teeAddress));

        // Verify that the extended registration data matches the hash in the TDX report data
        // This is to ensure that the values in extendedRegistrationData are the same as the values
        // in the TDX report data, which cannot be forged by the TEE-controlled address
        bytes32 extendedRegistrationDataHash = keccak256(extendedRegistrationData);
        require(
            extendedRegistrationDataHash == extendedDataReportHash,
            InvalidRegistrationDataHash(extendedDataReportHash, extendedRegistrationDataHash)
        );

        bytes32 newQuoteHash = keccak256(rawQuote);
        bool previouslyRegistered = checkPreviousRegistration(teeAddress, newQuoteHash);

        // Register the address in the registry with the raw quote so later on if the TEE has its
        // underlying DCAP endorsements updated, we can invalidate the TEE's attestation
        registeredTEEs[teeAddress] = RegisteredTEE({
            rawQuote: rawQuote,
            parsedReportBody: td10ReportBody,
            extendedRegistrationData: extendedRegistrationData,
            isValid: true,
            quoteHash: newQuoteHash
        });

        emit TEEServiceRegistered(teeAddress, rawQuote, previouslyRegistered);
    }

    /**
     * @notice Checks if a TEE is already registered with the same quote
     * @dev We use the quoteHash instead of the rawQuote to avoid unnecessary SLOADs
     * @dev If a user is trying to add the same address, and quote, this is a no-op
     * and we should revert to signal that the user may be making a mistake (why would
     * they be trying to add the same TEE twice?).
     * @dev If the TEE is already registered and we're using a different quote,
     * that is fine and indicates the TEE-controlled address is either re-attesting
     * (with a new quote) or has moved its private key to a new TEE device
     * @dev We do not need to check the public key, because the address has a cryptographically-ensured
     * 1-to-1 relationship with the public key, so checking it would be redundant
     * @param teeAddress The TEE-controlled address of the TEE
     * @param newQuoteHash The hash of registration's new raw quote
     * @return Whether the TEE is already registered but is updating its quote
     */
    function checkPreviousRegistration(address teeAddress, bytes32 newQuoteHash) internal view returns (bool) {
        bytes32 existingQuoteHash = registeredTEEs[teeAddress].quoteHash;
        require(newQuoteHash != existingQuoteHash, TEEServiceAlreadyRegistered(teeAddress));

        // if the TEE is already registered, but we're using a different quote,
        // return true to signal that the TEE is already registered but is updating its quote
        return existingQuoteHash != 0;
    }

    /// @inheritdoc IFlashtestationRegistry
    function getRegistration(address teeAddress) public view override returns (bool, RegisteredTEE memory) {
        return (registeredTEEs[teeAddress].isValid, registeredTEEs[teeAddress]);
    }

    /// @inheritdoc IFlashtestationRegistry
    function getRegistrationStatus(address teeAddress)
        external
        view
        override
        returns (bool isValid, bytes32 quoteHash)
    {
        RegisteredTEE storage tee = registeredTEEs[teeAddress];
        return (tee.isValid, tee.quoteHash);
    }

    /// @inheritdoc IFlashtestationRegistry
    function invalidateAttestation(address teeAddress) external payable override nonReentrant {
        // check to make sure it even makes sense to invalidate the TEE-controlled address
        // if the TEE-controlled address is not registered with the FlashtestationRegistry,
        // it doesn't make sense to invalidate the attestation
        RegisteredTEE memory registeredTEE = registeredTEEs[teeAddress];
        require(registeredTEE.rawQuote.length > 0, TEEServiceNotRegistered(teeAddress));
        require(registeredTEE.isValid, TEEServiceAlreadyInvalid(teeAddress));

        // now we check the attestation, and invalidate the TEE if it's no longer valid.
        // This will only happen if the DCAP Endorsements associated with the TEE's quote
        // have been updated
        (bool success,) = attestationContract.verifyAndAttestOnChain{value: msg.value}(registeredTEE.rawQuote);
        require(!success, TEEIsStillValid(teeAddress));

        registeredTEEs[teeAddress].isValid = false;
        emit TEEServiceInvalidated(teeAddress);
    }

    /// @inheritdoc IFlashtestationRegistry
    function invalidatePreviousSignature(uint256 _nonce) external override {
        uint256 nonce = nonces[msg.sender];
        require(_nonce == nonce, InvalidNonce(nonce, _nonce));
        nonces[msg.sender]++;
        emit PreviousSignatureInvalidated(msg.sender, nonce);
    }

    /// @inheritdoc IFlashtestationRegistry
    function hashTypedDataV4(bytes32 structHash) public view override returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    /// @inheritdoc IFlashtestationRegistry
    function computeStructHash(
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData,
        uint256 nonce,
        uint256 deadline
    ) public pure override returns (bytes32) {
        return keccak256(
            abi.encode(REGISTER_TYPEHASH, keccak256(rawQuote), keccak256(extendedRegistrationData), nonce, deadline)
        );
    }

    /// @inheritdoc IFlashtestationRegistry
    function domainSeparator() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }
}
