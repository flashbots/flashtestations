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
        bytes32 registrationHash; // Used as a downstream caching key
        TD10ReportBody parsedReportBody; // Parsed form of the quote to avoid parsing
        bytes rawQuote; // The raw quote from the TEE device, which is stored to allow for future quote quote invalidation
        bytes appData; // The application-specific attested to data
        bool isValid; // true upon first registration, and false after a quote invalidation
    }

    // Events
    event TEEServiceRegistered( /* dev: could be hash of the quote */
        address teeAddress, bytes rawQuote, bytes appData, bool alreadyExists
    );
    event TEEServiceInvalidated(address teeAddress);

    // Errors
    error InvalidQuote(bytes output);
    error ByteSizeExceeded(uint256 size);
    error TEEServiceAlreadyRegistered(address teeAddress, bytes rawQuote /* dev: could be hash of the quote */ );
    error SenderMustMatchTEEAddress(address sender, address teeAddress);
    error TEEServiceNotRegistered(address teeAddress);
    error TEEServiceAlreadyInvalid(address teeAddress);
    error TEEIsStillValid(address teeAddress);
    error InvalidSignature();
    error InvalidNonce(uint256 expected, uint256 provided);
}
