// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
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
    ReentrancyGuardTransient
{
    using ECDSA for bytes32;

    // Constants

    // Minimum length of the td reportdata field: tee address (20) and hash of extended data (32)
    uint256 public constant TD_REPORTDATA_LENGTH = 52;

    // Maximum size for byte arrays to prevent DoS attacks
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024; // 20KB limit

    // EIP-712 Constants
    bytes32 public constant REGISTER_TYPEHASH =
        keccak256("RegisterTEEService(bytes rawQuote,bytes extendedRegistrationData,uint256 nonce)");

    // Storage Variables

    // The address of the Automata DCAP Attestation contract, which verifies TEE quotes.
    // This is deployed by Automata, and once set on the FlashtestationRegistry, it cannot be changed
    IAttestation public attestationContract;

    // Tracks the TEE-controlled address that registered a particular attestation quote and app data.
    // This enables efficient O(1) lookup in `getRegistration`, so that apps can quickly verify the
    // output of a TEE workload
    mapping(address => RegisteredTEE) public registeredTEEs;

    // Tracks nonces for EIP-712 signatures to prevent replay attacks
    mapping(address => uint256) public nonces;

    // Gap for future contract upgrades
    uint256[48] __gap;

    /**
     * Initializer to set the Automata DCAP Attestation contract, which verifies TEE quotes
     * @param _attestationContract The address of the attestation contract
     */
    function initialize(address owner, address _attestationContract) external initializer {
        __Ownable_init(owner);
        __EIP712_init("FlashtestationRegistry", "1");
        attestationContract = IAttestation(_attestationContract);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Modifier to check if input bytes size is within limits
     * to protect against DoS attacks
     */
    modifier limitBytesSize(bytes memory data) {
        require(data.length <= MAX_BYTES_SIZE, ByteSizeExceeded(data.length));
        _;
    }

    /**
     * @notice Registers a TEE workload with a specific TEE-controlled address in the FlashtestationRegistry
     * @notice The TEE must be registered with a quote whose validity is verified by the attestationContract
     * @dev In order to mitigate DoS attacks, the quote must be less than 20KB
     * @dev This is a costly operation (5 million gas) and should be used sparingly.
     * @param rawQuote The raw quote from the TEE device. Must be a V4 TDX quote
     * @param extendedRegistrationData Abi-encoded attested data, application specific
     */
    function registerTEEService(bytes calldata rawQuote, bytes calldata extendedRegistrationData)
        external
        limitBytesSize(rawQuote)
        nonReentrant
    {
        doRegister(msg.sender, rawQuote, extendedRegistrationData);
    }

    /**
     * @notice Registers a TEE workload with a specific TEE-controlled address using EIP-712 signatures
     * @notice The TEE must be registered with a quote whose validity is verified by the attestationContract
     * @dev In order to mitigate DoS attacks, the quote must be less than 20KB
     * @dev This function exists so that the TEE does not need to be funded with gas for transaction fees, and
     * instead can rely on any EOA to execute the transaction, but still only allow quotes from attested TEEs
     * @dev Replay is implicitly shielded against through the transaction's nonce (TEE must sign the new nonce)
     * @param rawQuote The raw quote from the TEE device. Must be a V4 TDX quote
     * @param extendedRegistrationData Abi-encoded attested data, application specific
     * @param nonce The nonce to use for the EIP-712 signature (to prevent replay attacks)
     * @param signature The EIP-712 signature of the registration message
     */
    function permitRegisterTEEService(
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData,
        uint256 nonce,
        bytes calldata signature
    ) external limitBytesSize(rawQuote) limitBytesSize(extendedRegistrationData) nonReentrant {
        // Create the digest using EIP712Upgradeable's _hashTypedDataV4
        bytes32 digest = hashTypedDataV4(computeStructHash(rawQuote, extendedRegistrationData, nonce));

        // Recover the signer, and ensure it matches the TEE-controlled address, otherwise we have no proof
        // whoever created the attestation quote has access to the private key
        address signer = digest.recover(signature);

        // Verify the nonce
        uint256 expectedNonce = nonces[signer];
        require(nonce == expectedNonce, InvalidNonce(expectedNonce, nonce));

        // Increment the nonce so that any attempts at replaying this transaction will fail
        nonces[signer]++;

        doRegister(signer, rawQuote, extendedRegistrationData);
    }

    /**
     * @notice Registers a TEE workload with a specific TEE-controlled address in the FlashtestationRegistry
     * @notice The TEE must be registered with a quote whose validity is verified by the attestationContract
     * @dev In order to mitigate DoS attacks, the quote must be less than 20KB
     * @dev This is a costly operation (5 million gas) and should be used sparingly.
     * @param caller The address from which registration request originates, must match the one in the quote
     * @param rawQuote The raw quote from the TEE device. Must be a V4 TDX quote
     * @param extendedRegistrationData Abi-encoded attested data, application specific
     */
    function doRegister(address caller, bytes calldata rawQuote, bytes calldata extendedRegistrationData) internal {
        (bool success, bytes memory output) = attestationContract.verifyAndAttestOnChain(rawQuote);
        if (!success) {
            revert InvalidQuote(output);
        }

        // now we know the quote is valid, we can safely parse the output into the TDX report body,
        // from which we'll extract the data we need to register the TEE
        TD10ReportBody memory td10ReportBody = QuoteParser.parseV4VerifierOutput(output);

        // Binding the tee address and extended report data to the quote
        if (td10ReportBody.reportData.length < TD_REPORTDATA_LENGTH) {
            revert InvalidReportDataLength(td10ReportBody.reportData.length);
        }

        (address teeAddress, bytes32 extendedDataReportHash) = QuoteParser.parseReportData(td10ReportBody.reportData);
        if (caller != teeAddress) {
            revert SenderMustMatchTEEAddress(caller, teeAddress);
        }
        bytes32 extendedRegistrationDataHash = keccak256(extendedRegistrationData);
        if (extendedRegistrationDataHash != extendedDataReportHash) {
            revert InvalidRegistrationDataHash(extendedDataReportHash, extendedRegistrationDataHash);
        }

        bytes32 quoteHash = keccak256(rawQuote);
        bool previouslyRegistered = checkPreviousRegistration(teeAddress, quoteHash);

        // Register the address in the registry with the raw quote so later on if the TEE has its
        // underlying DCAP endorsements updated, we can invalidate the TEE's attestation
        registeredTEEs[teeAddress] = RegisteredTEE({
            rawQuote: rawQuote,
            parsedReportBody: td10ReportBody,
            extendedRegistrationData: extendedRegistrationData,
            isValid: true
        });

        emit TEEServiceRegistered(teeAddress, rawQuote, previouslyRegistered);
    }

    /**
     * @notice Checks if a TEE is already registered with the same quote
     * @dev If a user is trying to add the same address, and quote, this is a no-op
     * and we should revert to signal that the user may be making a mistake (why would
     * they be trying to add the same TEE twice?).
     * @dev If the TEE is already registered and we're using a different quote,
     * that is fine and indicates the TEE-controlled address is either re-attesting
     * (with a new quote) or has moved its private key to a new TEE device
     * @dev We do not need to check the public key, because the address has a cryptographically-ensured
     * 1-to-1 relationship with the public key, so checking it would be redundant
     * @param teeAddress The TEE-controlled address of the TEE
     * @param quoteHash The hash of registration's raw quote
     * @return Whether the TEE is already registered but is updating its quote
     */
    function checkPreviousRegistration(address teeAddress, bytes32 quoteHash) internal view returns (bool) {
        if (keccak256(registeredTEEs[teeAddress].rawQuote) == quoteHash) {
            revert TEEServiceAlreadyRegistered(teeAddress);
        }

        // if the TEE is already registered, but we're using a different quote,
        // return true to signal that the TEE is already registered but is updating its quote
        return registeredTEEs[teeAddress].rawQuote.length > 0;
    }

    /**
     * @notice Fetches TEE registration for a given address
     * @param teeAddress The TEE-controlled address to check
     * @return Raw quote, and whether the TEE quote, td attributes, or xfam have not been invalidated
     * @dev getRegistration will only return true if a valid TEE quote containing
     * teeAddress in its reportData field was previously registered with the FlashtestationRegistry
     * using the registerTEEService function.
     */
    function getRegistration(address teeAddress) public view returns (bool, RegisteredTEE memory) {
        return (registeredTEEs[teeAddress].isValid, registeredTEEs[teeAddress]);
    }

    /**
     * @notice Invalidates the attestation of a TEE
     * @param teeAddress The TEE-controlled address to invalidate
     * @dev This is a costly operation (5 million gas) and should be used sparingly.
     * @dev Will always revert except if the attestation is valid and the attestation re-verification
     * fails. This is to prevent a user needlessly calling this function and for a no-op to occur
     * @dev This function exists to handle an important security requirement: occasionally Intel
     * will release a new set of DCAP Endorsements for a particular TEE setup (for instance if a
     * TDX vulnerability was discovered), which invalidates all prior quotes generated by that TEE.
     * By invalidates we mean that the outputs generated by the TEE-controlled address associated
     * with these invalid quotes are no longer secure and cannot be relied upon. This fact needs to be
     * reflected onchain, so that any upstream contracts that try to call `getRegistration` will
     * correctly return `false` for the TEE-controlled addresses associated with these invalid quotes.
     * This is a security requirement to ensure that no downstream contracts can be exploited by
     * a malicious TEE that has been compromised
     * @dev Note: this function is callable by anyone, so that offchain monitoring services can
     * quickly mark TEEs as invalid
     * @dev Note: rather than relying on invalidation of specific quotes, we can cover all the cases
     * in which a quote can be invalidated (tcbrecovery, certificate revocation etc). This would allow
     * much cheaper, bulk invalidation of all quotes using a now-outdated tcbinfo for example.
     */
    function invalidateAttestation(address teeAddress) external {
        // check to make sure it even makes sense to invalidate the TEE-controlled address
        // if the TEE-controlled address is not registered with the FlashtestationRegistry,
        // it doesn't make sense to invalidate the attestation
        RegisteredTEE memory registeredTEE = registeredTEEs[teeAddress];
        if (registeredTEE.rawQuote.length == 0) {
            revert TEEServiceNotRegistered(teeAddress);
        }

        if (!registeredTEE.isValid) {
            revert TEEServiceAlreadyInvalid(teeAddress);
        }

        // now we check the attestation, and invalidate the TEE if it's no longer valid.
        // This will only happen if the DCAP Endorsements associated with the TEE's quote
        // have been updated
        (bool success,) = attestationContract.verifyAndAttestOnChain(registeredTEE.rawQuote);
        if (success) {
            // if the attestation is still valid, then this function call is a no-op except for
            // wasting the caller's gas. So we revert here to signal that the TEE is still valid.
            // Offchain users who want to monitor for potential invalid TEEs can do so by calling
            // this function and checking for the `TEEIsStillValid` error
            revert TEEIsStillValid(teeAddress);
        } else {
            registeredTEEs[teeAddress].isValid = false;
            emit TEEServiceInvalidated(teeAddress);
        }
    }

    /**
     * @notice Computes the digest for the EIP-712 signature
     * @dev This is useful for when both onchain and offchain users want to compute the digest
     * for the EIP-712 signature, and then use it to verify the signature
     * @param structHash The struct hash for the EIP-712 signature
     * @return The digest for the EIP-712 signature
     */
    function hashTypedDataV4(bytes32 structHash) public view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    /**
     * @notice Computes the struct hash for the EIP-712 signature
     * @dev This is useful for when both onchain and offchain users want to compute the struct hash
     * for the EIP-712 signature, and then use it to verify the signature
     * @param rawQuote The raw quote from the TEE device
     * @param extendedRegistrationData Abi-encoded attested data, application specific
     * @param nonce The nonce to use for the EIP-712 signature
     * @return The struct hash for the EIP-712 signature
     */
    function computeStructHash(bytes calldata rawQuote, bytes calldata extendedRegistrationData, uint256 nonce)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(REGISTER_TYPEHASH, keccak256(rawQuote), keccak256(extendedRegistrationData), nonce));
    }
}
