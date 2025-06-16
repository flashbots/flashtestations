// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IAttestation} from "./interfaces/IAttestation.sol";
import {QuoteParser, WorkloadId} from "./utils/QuoteParser.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {TD_REPORT10_LENGTH, HEADER_LENGTH} from "automata-dcap-attestation/contracts/types/Constants.sol";

// TEE identity and status tracking
struct RegisteredTEE {
    WorkloadId workloadId; // The workloadID of the TEE device
    bytes rawQuote; // The raw quote from the TEE device, which is stored to allow for future quote quote invalidation
    bool isValid; // true upon first registration, and false after a quote invalidation
    bytes publicKey; // The 64-byte uncompressed public key of TEE-controlled address, used to encrypt messages to the TEE
}

/**
 * @title FlashtestationRegistry
 * @dev A contract for managing trusted execution environment (TEE) identities and configurations
 * using Automata's Intel DCAP attestation
 */
contract FlashtestationRegistry is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardTransient
{
    using ECDSA for bytes32;

    // Constants

    // Maximum size for byte arrays to prevent DoS attacks
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024; // 20KB limit

    // EIP-712 Constants
    bytes32 public constant REGISTER_TYPEHASH = keccak256("RegisterTEEService(bytes rawQuote,uint256 nonce)");

    // Storage Variables

    // The address of the Automata DCAP Attestation contract, which verifies TEE quotes.
    // This is deployed by Automata, and once set on the FlashtestationRegistry, it cannot be changed
    IAttestation public attestationContract;

    // Tracks the TEE-controlled address that registered a particular WorkloadId and attestation quote.
    // This enables efficient O(1) lookup in `isValidWorkload`, so that apps can quickly verify the
    // output of a TEE workload
    mapping(address => RegisteredTEE) public registeredTEEs;

    // Tracks nonces for EIP-712 signatures to prevent replay attacks
    mapping(address => uint256) public nonces;

    // Events

    event TEEServiceRegistered(
        address teeAddress, WorkloadId workloadId, bytes rawQuote, bytes publicKey, bool alreadyExists
    );
    event TEEServiceInvalidated(address teeAddress);

    // Errors

    error InvalidQuote(bytes output);
    error ByteSizeExceeded(uint256 size);
    error TEEServiceAlreadyRegistered(address teeAddress, WorkloadId workloadId);
    error SenderMustMatchTEEAddress(address sender, address teeAddress);
    error TEEServiceNotRegistered(address teeAddress);
    error TEEServiceAlreadyInvalid(address teeAddress);
    error TEEIsStillValid(address teeAddress);
    error InvalidSignature();
    error InvalidNonce(uint256 expected, uint256 provided);

    /**
     * Intializer to set the the Automata DCAP Attestation contract, which verifies TEE quotes
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
     */
    function registerTEEService(bytes calldata rawQuote) external limitBytesSize(rawQuote) nonReentrant {
        (bool success, bytes memory output) = attestationContract.verifyAndAttestOnChain(rawQuote);

        if (!success) {
            revert InvalidQuote(output);
        }

        // now we know the quote is valid, we can safely parse the output into the TDX report body,
        // from which we'll extract the data we need to register the TEE
        TD10ReportBody memory td10ReportBodyStruct = QuoteParser.parseV4VerifierOutput(output);
        bytes memory publicKey = QuoteParser.extractPublicKey(td10ReportBodyStruct);
        address teeAddress = address(uint160(uint256(keccak256(publicKey))));
        WorkloadId workloadId = QuoteParser.extractWorkloadId(td10ReportBodyStruct);

        // we must ensure the TEE-controlled address is the same as the one calling the function
        // otherwise we have no proof that the TEE that generated this quote intends to register
        // with the FlashtestationRegistry. This protects against a malicious TEE that generates a quote for a
        // different address, and then calls this function to register itself with the FlashtestationRegistry
        if (teeAddress != msg.sender) {
            revert SenderMustMatchTEEAddress(msg.sender, teeAddress);
        }

        // Register the address in the registry with the raw quote so later on if the TEE has its
        // underlying DCAP endorsements updated, we can invalidate the TEE's attestation
        bool previouslyRegistered = addAddress(workloadId, teeAddress, rawQuote, publicKey);
        emit TEEServiceRegistered(teeAddress, workloadId, rawQuote, publicKey, previouslyRegistered);
    }

    /**
     * @notice Registers a TEE workload with a specific TEE-controlled address using EIP-712 signatures
     * @notice The TEE must be registered with a quote whose validity is verified by the attestationContract
     * @dev In order to mitigate DoS attacks, the quote must be less than 20KB
     * @dev This function exists so that the TEE does not need to be funded with gas for transaction fees, and
     * instead can rely on any EOA to execute the transaction, but still only allow quotes from attested TEEs
     * @param rawQuote The raw quote from the TEE device. Must be a V4 TDX quote
     * @param nonce The nonce to use for the EIP-712 signature (to prevent replay attacks)
     * @param eip712Sig The EIP-712 signature of the registration message
     */
    function permitRegisterTEEService(bytes calldata rawQuote, uint256 nonce, bytes calldata eip712Sig)
        external
        limitBytesSize(rawQuote)
        nonReentrant
    {
        // Verify the quote with the attestation contract
        (bool success, bytes memory output) = attestationContract.verifyAndAttestOnChain(rawQuote);

        if (!success) {
            revert InvalidQuote(output);
        }

        // now we know the quote is valid, we can safely parse the output into the TDX report body,
        // from which we'll extract the data we need to register the TEE
        TD10ReportBody memory td10ReportBodyStruct = QuoteParser.parseV4VerifierOutput(output);
        bytes memory publicKey = QuoteParser.extractPublicKey(td10ReportBodyStruct);
        address teeAddress = address(uint160(uint256(keccak256(publicKey))));
        WorkloadId workloadId = QuoteParser.extractWorkloadId(td10ReportBodyStruct);

        // we must ensure the TEE-controlled address is the same as the who signed the EIP-712 signature
        // otherwise we have no proof that the TEE that generated this quote intends to register
        // with the FlashtestationRegistry. This protects against a malicious TEE that generates a quote for a
        // different address, and then calls this function to register itself with the FlashtestationRegistry

        // Verify the nonce
        uint256 expectedNonce = nonces[teeAddress];
        require(nonce == expectedNonce, InvalidNonce(expectedNonce, nonce));

        // Increment the nonce so that any attempts at replaying this transaction will fail
        nonces[teeAddress]++;

        // Create the digest using EIP712Upgradeable's _hashTypedDataV4
        bytes32 digest = _hashTypedDataV4(computeStructHash(rawQuote, nonce));

        // Recover the signer, and ensure it matches the TEE-controlled address, otherwise we have no proof
        // that the TEE that generated this quote intends to register with the FlashtestationRegistry
        address signer = digest.recover(eip712Sig);
        if (signer != teeAddress) {
            revert InvalidSignature();
        }

        // Register the address in the registry with the raw quote so later on if the TEE has its
        // underlying DCAP endorsements updated, we can invalidate the TEE's attestation
        bool previouslyRegistered = addAddress(workloadId, teeAddress, rawQuote, publicKey);
        emit TEEServiceRegistered(teeAddress, workloadId, rawQuote, publicKey, previouslyRegistered);
    }

    /**
     * @notice Adds a TEE to the registry
     * @dev It's possible that a TEE has already registered with this address, but with a different workloadId.
     * This is expected if the TEE gets restarted or upgraded and generates a new workloadId.
     * It's also possible that the address and workloadId are the same, but the quote
     * is different. This is expected if Intel releases a new set of DCAP Endorsements (i.e.
     * a new TCB), in which case the quotes the TEE generates will be different.
     * In both cases, we need to update the registry with the new quote.
     * @param workloadId The workloadId of the TEE
     * @param teeAddress The TEE-controlled address of the TEE
     * @param rawQuote The raw quote from the TEE device
     * @return previouslyRegistered Whether the TEE was previously registered
     */
    function addAddress(WorkloadId workloadId, address teeAddress, bytes calldata rawQuote, bytes memory publicKey)
        internal
        returns (bool previouslyRegistered)
    {
        // if a user is trying to add the same address, workloadId, and quote, this is a no-op
        // and we should revert to signal that the user may be making a mistake (why would
        // they be trying to add the same TEE twice?). We do not need to check the public key,
        // because the address has a cryptographically-ensured 1-to-1 relationship with the
        // public key, so checking it would be redundant
        if (
            WorkloadId.unwrap(registeredTEEs[teeAddress].workloadId) == WorkloadId.unwrap(workloadId)
                && keccak256(registeredTEEs[teeAddress].rawQuote) == keccak256(rawQuote)
        ) {
            revert TEEServiceAlreadyRegistered(teeAddress, workloadId);
        }

        if (WorkloadId.unwrap(registeredTEEs[teeAddress].workloadId) != 0) {
            previouslyRegistered = true;
        }
        registeredTEEs[teeAddress] =
            RegisteredTEE({workloadId: workloadId, rawQuote: rawQuote, isValid: true, publicKey: publicKey});
    }

    /**
     * @notice Checks if a TEE is registered with a given workloadId
     * @param workloadId The workloadId to check
     * @param teeAddress The TEE-controlled address to check
     * @return Whether the TEE is registered with the given workloadId and has not been invalidated
     * @dev isValidWorkload will only return true if a valid TEE quote containing
     * teeAddress in its reportData field was previously registered with the FlashtestationRegistry
     * using the registerTEEService function.
     */
    function isValidWorkload(WorkloadId workloadId, address teeAddress) public view returns (bool) {
        return registeredTEEs[teeAddress].isValid
            && WorkloadId.unwrap(registeredTEEs[teeAddress].workloadId) == WorkloadId.unwrap(workloadId);
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
     * reflected onchain, so that any upstream contracts that try to call `isValidWorkload` will
     * correctly return `false` for the TEE-controlled addresses associated with these invalid quotes.
     * This is a security requirement to ensure that no downstream contracts can be exploited by
     * a malicious TEE that has been compromised
     * @dev Note: this function is callable by anyone, so that offchain monitoring services can
     * quickly mark TEEs as invalid
     */
    function invalidateAttestation(address teeAddress) external {
        // check to make sure it even makes sense to invalidate the TEE-controlled address
        // if the TEE-controlled address is not registered with the FlashtestationRegistry,
        // it doesn't make sense to invalidate the attestation
        RegisteredTEE memory registeredTEE = registeredTEEs[teeAddress];
        if (WorkloadId.unwrap(registeredTEE.workloadId) == 0) {
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
     * @notice Returns the TD10ReportBody for the quote used to register a given TEE-controlled address
     * @param teeAddress The TEE-controlled address to get the TD10ReportBody for
     * @return reportBody The TD10ReportBody for the given TEE-controlled address
     * @dev this is useful for when both onchain and offchain users want more
     * information about the registered TEE than just the workloadId
     */
    function getReportBody(address teeAddress) public view returns (TD10ReportBody memory) {
        bytes memory rawQuote = registeredTEEs[teeAddress].rawQuote;
        require(rawQuote.length > 0, TEEServiceNotRegistered(teeAddress));
        return QuoteParser.parseV4Quote(rawQuote);
    }

    /**
     * @notice Computes the digest for the EIP-712 signature
     * @dev This is useful for when both onchain and offchain users want to compute the digest
     * for the EIP-712 signature, and then use it to verify the signature
     * @param structHash The struct hash for the EIP-712 signature
     * @return The digest for the EIP-712 signature
     */
    function getHashedTypeDataV4(bytes32 structHash) public view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    /**
     * @notice Computes the struct hash for the EIP-712 signature
     * @dev This is useful for when both onchain and offchain users want to compute the struct hash
     * for the EIP-712 signature, and then use it to verify the signature
     * @param rawQuote The raw quote from the TEE device
     * @param nonce The nonce to use for the EIP-712 signature
     * @return The struct hash for the EIP-712 signature
     */
    function computeStructHash(bytes calldata rawQuote, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(REGISTER_TYPEHASH, keccak256(rawQuote), nonce));
    }
}
