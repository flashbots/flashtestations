// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

/**
 * @title IFlashtestationRegistry
 * @dev Interface for the FlashtestationRegistry contract which manages trusted execution environment (TEE)
 * identities and configurations using Automata's Intel DCAP attestation
 */
interface IFlashtestationRegistry {
    // TEE identity and status tracking
    struct RegisteredTEE {
        bool isValid; // true upon first registration, and false after a quote invalidation
        bytes rawQuote; // The raw quote from the TEE device, which is stored to allow for future quote quote invalidation
        TD10ReportBody parsedReportBody; // Parsed form of the quote to avoid unnecessary parsing
        bytes extendedRegistrationData; // Any additional attested data for application purposes
    }

    // Events
    event TEEServiceRegistered(address teeAddress, bytes32 quoteHash, bool alreadyExists);
    event TEEServiceInvalidated(address teeAddress, bytes32 quoteHash);

    // Errors
    error InvalidQuote(bytes output);
    error InvalidReportDataLength(uint256 length);
    error ByteSizeExceeded(uint256 size);
    error TEEServiceAlreadyRegistered(address teeAddress, bytes32 quoteHash);
    error SenderMustMatchTEEAddress(address sender, address teeAddress);
    error TEEServiceNotRegistered(address teeAddress);
    error TEEServiceAlreadyInvalid(address teeAddress);
    error TEEIsStillValid(address teeAddress, bytes32 quoteHash);
    error InvalidSignature();
    error InvalidNonce(uint256 expected, uint256 provided);
}
