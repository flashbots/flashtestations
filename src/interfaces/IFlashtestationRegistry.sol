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
        bytes extendedRegistrationData; // Any additional attested data for application purposes. This data is attested by a bytes32 in the attestation's reportData, where that bytes32 is a hash of the ABI-encoded values in the extendedRegistrationData. This registration data can be anything that's needed for your app, for instance an vmOperatorIdPublicKey that allows you to verify signatures from your TEE operator, parts of runtime configuration of the VM, configuration submitted by the VM operator, for example the public IP of the instance,
    }

    // Events
    event TEEServiceRegistered(address teeAddress, bytes rawQuote, bool alreadyExists);
    event TEEServiceInvalidated(address teeAddress);

    // Errors
    error InvalidQuote(bytes output);
    error InvalidReportDataLength(uint256 length);
    error InvalidRegistrationDataHash(bytes32 expected, bytes32 received);
    error ByteSizeExceeded(uint256 size);
    error TEEServiceAlreadyRegistered(address teeAddress);
    error SenderMustMatchTEEAddress(address sender, address teeAddress);
    error TEEServiceNotRegistered(address teeAddress);
    error TEEServiceAlreadyInvalid(address teeAddress);
    error TEEIsStillValid(address teeAddress);
    error InvalidSignature();
    error InvalidNonce(uint256 expected, uint256 provided);
}
