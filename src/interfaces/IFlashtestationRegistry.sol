// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestation} from "./IAttestation.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

/**
 * @title IFlashtestationRegistry
 * @dev Interface for the FlashtestationRegistry contract which manages trusted execution environment (TEE)
 * identities and configurations using Automata's Intel DCAP attestation
 */
interface IFlashtestationRegistry {
    /// @notice TEE identity and status tracking
    struct RegisteredTEE {
        bool isValid; // true upon first registration, and false after a quote invalidation
        bytes rawQuote; // The raw quote from the TEE device, which is stored to allow for future quote quote invalidation
        TD10ReportBody parsedReportBody; // Parsed form of the quote to avoid unnecessary parsing
        bytes extendedRegistrationData; // Any additional attested data for application purposes. This data is attested by a bytes32 in the attestation's reportData, where that bytes32 is a hash of the ABI-encoded values in the extendedRegistrationData. This registration data can be anything that's needed for your app, for instance an vmOperatorIdPublicKey that allows you to verify signatures from your TEE operator, parts of runtime configuration of the VM, configuration submitted by the VM operator, for example the public IP of the instance,
        bytes32 quoteHash; // keccak256 hash of rawQuote for caching purposes
    }

    // ============ Events ============

    /// @notice Emitted when a TEE service is registered
    /// @param teeAddress The address of the TEE service
    /// @param rawQuote The raw quote from the TEE device
    /// @param alreadyExists Whether the TEE service is already registered
    event TEEServiceRegistered(address indexed teeAddress, bytes rawQuote, bool alreadyExists);
    /// @notice Emitted when a TEE service is invalidated
    /// @param teeAddress The address of the TEE service
    event TEEServiceInvalidated(address indexed teeAddress);
    /// @notice Emitted when a previous signature is invalidated
    /// @param teeAddress The address of the TEE service
    /// @param invalidatedNonce The nonce of the invalidated signature
    event PreviousSignatureInvalidated(address indexed teeAddress, uint256 invalidatedNonce);

    // ============ Errors ============

    /// @notice Emitted when the attestation contract is the 0x0 address
    error InvalidAttestationContract();
    /// @notice Emitted when the signature is expired because the deadline has passed
    error ExpiredSignature(uint256 deadline);
    /// @notice Emitted when the quote is invalid according to the Automata DCAP Attestation contract
    error InvalidQuote(bytes output);
    /// @notice Emitted when the report data length is too short
    error InvalidReportDataLength(uint256 length);
    /// @notice Emitted when the registration data hash does not match the expected hash
    error InvalidRegistrationDataHash(bytes32 expected, bytes32 received);
    /// @notice Emitted when the byte size is exceeded
    error ByteSizeExceeded(uint256 size);
    /// @notice Emitted when the TEE service is already registered when registering
    error TEEServiceAlreadyRegistered(address teeAddress);
    /// @notice Emitted when the signer doesn't match the TEE address
    error SignerMustMatchTEEAddress(address signer, address teeAddress);
    /// @notice Emitted when the TEE service is not registered
    error TEEServiceNotRegistered(address teeAddress);
    /// @notice Emitted when the TEE service is already invalid when trying to invalidate a TEE registration
    error TEEServiceAlreadyInvalid(address teeAddress);
    /// @notice Emitted when the TEE service is still valid when trying to invalidate a TEE registration
    error TEEIsStillValid(address teeAddress);
    /// @notice Emitted when the nonce is invalid when verifying a signature
    error InvalidNonce(uint256 expected, uint256 provided);

    // ============ Functions ============

    /**
     * Initializer to set the Automata DCAP Attestation contract, which verifies TEE quotes
     * @param owner The address of the initial owner of the contract, who is able to upgrade the contract
     * @param _attestationContract The address of the Automata DCAP attestation contract, used to verify TEE quotes
     */
    function initialize(address owner, address _attestationContract) external;

    /**
     * @notice Registers a TEE workload with a specific TEE-controlled address in the FlashtestationRegistry
     * @notice The TEE must be registered with a quote whose validity is verified by the attestationContract
     * @dev In order to mitigate DoS attacks, the quote must be less than 20KB
     * @dev This is a costly operation (5 million gas) and should be used sparingly.
     * @param rawQuote The raw quote from the TEE device. Must be a V4 TDX quote
     * @param extendedRegistrationData Abi-encoded application specific attested data, reserved for future upgrades
     */
    function registerTEEService(bytes calldata rawQuote, bytes calldata extendedRegistrationData) external payable;

    /**
     * @notice Registers a TEE workload with a specific TEE-controlled address using EIP-712 signatures
     * @notice The TEE must be registered with a quote whose validity is verified by the attestationContract
     * @dev In order to mitigate DoS attacks, the quote must be less than 20KB
     * @dev This function exists so that the TEE does not need to be funded with gas for transaction fees, and
     * instead can rely on any EOA to execute the transaction, but still only allow quotes from attested TEEs
     * @dev Replay is implicitly shielded against replay attacks through the transaction's nonce (TEE must sign the new nonce)
     * @param rawQuote The raw quote from the TEE device. Must be a V4 TDX quote
     * @param extendedRegistrationData Abi-encoded application specific attested data, this is arbitrary app-related
     * data that the app wants to associate with the TEE-controlled address. Even though it's passed in as a parameter,
     * we can trust that it comes from the TEE because we verify that the hash derived from all of the variables in
     * extendedRegistrationData matches the hash in the TDX report data.
     * @param nonce The nonce to use for the EIP-712 signature (to prevent replay attacks)
     * @param deadline The blocktime after which this signature is no longer valid
     * @param signature The EIP-712 signature of the registration message
     */
    function permitRegisterTEEService(
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable;

    /**
     * @notice Fetches only the validity status and quote hash for a given TEE address
     * @dev This is a gas-optimized version of getRegistration that only returns the minimal data
     * needed for caching optimizations in policy contracts
     * @param teeAddress The TEE-controlled address to check
     * @return isValid True if the TEE is registered and the attestation is valid
     * @return registeredTEE The registered TEE
     */
    function getRegistration(address teeAddress)
        external
        view
        returns (bool isValid, RegisteredTEE memory registeredTEE);

    /**
     * @notice Fetches only the validity status and quote hash for a given TEE address
     * @dev This is a gas-optimized version of getRegistration that only returns the minimal data
     * needed for caching optimizations in policy contracts
     * @param teeAddress The TEE-controlled address to check
     * @return isValid True if the TEE is registered and the attestation is valid
     * @return quoteHash The keccak256 hash of the raw quote
     */
    function getRegistrationStatus(address teeAddress) external view returns (bool isValid, bytes32 quoteHash);

    /**
     * @notice Invalidates the attestation of a TEE
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
     * @param teeAddress The TEE-controlled address to invalidate
     */
    function invalidateAttestation(address teeAddress) external payable;

    /**
     * @notice Allows a user to increment their EIP-712 signature nonce, invalidating any previously signed but unexecuted permit signatures.
     * @dev This function provides a way for users to proactively invalidate old signatures by incrementing their nonce,
     * without needing to execute a valid permit.
     * This is particularly useful if a user suspects a signature may have been compromised or simply wants to ensure
     * that any outstanding, unused signatures with the current nonce can no longer be executed.
     * @dev The function requires the provided nonce to match the user's current nonce, as a defense against the caller
     * mistakenly invalidating a nonce that they did not intend to invalidate
     * @param _nonce The expected current nonce for the caller; must match the stored nonce
     */
    function invalidatePreviousSignature(uint256 _nonce) external;

    /**
     * @notice Computes the digest for the EIP-712 signature
     * @dev This is useful for when both onchain and offchain users want to compute the digest
     * for the EIP-712 signature, and then use it to verify the signature
     * @param structHash The struct hash for the EIP-712 signature
     * @return The digest for the EIP-712 signature
     */
    function hashTypedDataV4(bytes32 structHash) external view returns (bytes32);

    /**
     * @notice Computes the struct hash for the EIP-712 signature
     * @dev This is useful for when both onchain and offchain users want to compute the struct hash
     * for the EIP-712 signature, and then use it to verify the signature
     * @param rawQuote The raw quote from the TEE device
     * @param extendedRegistrationData Abi-encoded attested data, application specific
     * @param nonce The nonce to use for the EIP-712 signature
     * @param deadline The blocktime after which this signature is no longer valid
     * @return The struct hash for the EIP-712 signature
     */
    function computeStructHash(
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData,
        uint256 nonce,
        uint256 deadline
    ) external pure returns (bytes32);

    /**
     * @notice Returns the domain separator for the EIP-712 signature
     * @dev This is useful for when both onchain and offchain users want to compute the domain separator
     * for the EIP-712 signature, and then use it to verify the signature
     * @return The domain separator for the EIP-712 signature
     */
    function domainSeparator() external view returns (bytes32);

    /**
     * @notice Returns the current nonce for a given TEE-controlled address
     * @dev This is used in the permitRegisterTEEService function to prevent replay attacks
     * @param teeAddress The TEE-controlled address
     * @return The current nonce
     */
    function nonces(address teeAddress) external view returns (uint256);

    /**
     * @notice EIP-712 Typehash, used in the permitRegisterTEEService function
     * @dev This is used in the permitRegisterTEEService function to prevent replay attacks
     * @return The EIP-712 Typehash
     */
    function REGISTER_TYPEHASH() external view returns (bytes32);

    /**
     * @notice Returns the address of the Automata DCAP Attestation contract
     * @dev This is used to verify TEE quotes
     * @return The address of the Automata DCAP Attestation contract
     */
    function attestationContract() external view returns (IAttestation);
}
