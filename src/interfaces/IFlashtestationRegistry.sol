// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {WorkloadId} from "../utils/QuoteParser.sol";

/**
 * @title IFlashtestationRegistry
 * @dev Interface for the FlashtestationRegistry contract which manages trusted execution environment (TEE)
 * identities and configurations using Automata's Intel DCAP attestation
 */
interface IFlashtestationRegistry {
    // TEE identity and status tracking
    struct RegisteredTEE {
        WorkloadId workloadId; // The workloadID of the TEE device
        bytes rawQuote; // The raw quote from the TEE device, which is stored to allow for future quote quote invalidation
        bool isValid; // true upon first registration, and false after a quote invalidation
        bytes publicKey; // The 64-byte uncompressed public key of TEE-controlled address, used to encrypt messages to the TEE
    }

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
}
