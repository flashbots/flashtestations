// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

/**
 * @title IFlashtestationRegistry
 * @dev Interface for the FlashtestationRegistry contract which manages trusted execution environment (TEE)
 * identities and configurations using Automata's Intel DCAP attestation
 */
interface IFlashtestationRegistry {
    struct RegistrationExtendedReportData {
        uint256 chainId; /* Quotes are only valid for a single chain */
        uint256 blockNumber; /* Require TEE's client to be synced */
        address registryAddress; /* Disalow reuse of reports across registries */
        bytes32 nonce; /* Replay protection for operators */
        bytes appData; /* Abi-encoded application-specific data */
        bytes teeSignature; /* TEE's signature over the fields above */
        bytes vmOperatorSignature; /* Extra signature from whoever is running the VM over the fields above for authentication (no authorization) */
    }

    // TEE identity and status tracking
    struct RegisteredTEE {
        bool isValid; // true upon first registration, and false after a quote invalidation
        address vmOperatorAddress; // Address recovered from vmOperatorSignature
        bytes rawQuote; // The raw quote from the TEE device, which is stored to allow for future quote quote invalidation
        TD10ReportBody parsedReportBody; // Parsed form of the quote to avoid parsing
        RegistrationExtendedReportData registrationData; // Extended report data whose hash is embedded in the quote's reportdata
    }

    // Events
    event TEEServiceRegistered( /* dev: could be hash of the quote */
        address teeAddress, bytes32 quoteHash, bool alreadyExists
    );
    event TEEServiceInvalidated(address teeAddress, bytes32 quoteHash);

    // Errors
    error InvalidQuote(bytes output);
    error ByteSizeExceeded(uint256 size);
    error TEEServiceAlreadyRegistered(address teeAddress, bytes32 quoteHash);
    error SenderMustMatchTEEAddress(address sender, address teeAddress);
    error TEEServiceNotRegistered(address teeAddress);
    error TEEServiceAlreadyInvalid(address teeAddress);
    error TEEIsStillValid(address teeAddress, bytes32 quoteHash);
    error InvalidSignature();
    error InvalidNonce(uint256 expected, uint256 provided);
}
