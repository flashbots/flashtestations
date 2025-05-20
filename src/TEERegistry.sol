// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "solmate/src/auth/Owned.sol";
import {TDXLibrary} from "./utils/TDXLibrary.sol";
import {AutomataDcapAttestationFee} from "../lib/automata-dcap-attestation/evm/contracts/AutomataDcapAttestationFee.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

/**
 * @title TEERegistry
 * @dev A contract for managing trusted execution environment (TEE) identities and configurations
 * using Intel DCAP attestation
 */
contract TEERegistry is Owned {
    // Maximum size for byte arrays to prevent DoS attacks
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024; // 20KB limit

    // TEE identity and status tracking
    struct TEEDevice {
        bytes32 publicKey; // Public key of the TEE device
        uint64 lastActiveTime; // Timestamp of last activity
        bool isActive; // Whether the device is currently active
    }

    bool public isVerified;

    // Mapping from TEE identity to device information
    mapping(bytes32 => TEEDevice) public teeDevices;

    // State variables
    string[] public instanceDomainNames;

    // Notes config and secrets locations
    string[] public storageBackends;
    // Maps config hash to config data and secrets for onchain DA
    mapping(bytes32 => bytes) public artifacts;
    // Maps identity to config hash
    mapping(bytes32 => bytes32) public identityConfigMap;

    // Events
    event InstanceDomainRegistered(string domain, address registrar);
    event StorageBackendSet(string location, address setter);
    event StorageBackendRemoved(string location, address remover);
    event ArtifactAdded(bytes32 configHash, address adder);
    event IdentityConfigSet(bytes32 identity, bytes32 configHash, address setter);

    error ByteSizeExceeded(uint256 size);

    /**
     * @notice Constructor to set the the governance address, which
     * is the only address that can register and de-register TEE devices
     * and wipe the registry in case of a compromise
     * @param governance The address of the governance contract
     */
    constructor(address governance) Owned(governance) {}

    /**
     * @dev Modifier to check if input bytes size is within limits
     * to protect against DoS attacks
     */
    modifier limitBytesSize(bytes memory data) {
        require(data.length <= MAX_BYTES_SIZE, ByteSizeExceeded(data.length));
        _;
    }

    function registerTEE(bytes memory quote) external onlyOwner {
        // TODO: Implement
    }

    function deregisterTEE(bytes memory quote) external onlyOwner {
        // TODO: Implement
    }

    function verifyFlashestationTransaction(bytes memory attestationTransaction) external {
        // TODO: Implement
        // 1. check signature against live builder keys
        // 2. update liveness
    }

    function _updateLiveness() internal {
        // TODO: Implement
    }

    /**
     * @notice Verifies a quote using AutomataDcapAttestationFee and sets isVerified if successful
     * @param attestationFeeContract The address of the AutomataDcapAttestationFee contract
     * @param quote The DCAP quote to verify
     */
    function verifyQuoteWithAttestationFee(address attestationFeeContract, bytes calldata quote)
        external
        onlyOwner
        limitBytesSize(quote)
        returns (bool, bytes memory)
    {
        (bool success, bytes memory output) =
            AutomataDcapAttestationFee(attestationFeeContract).verifyAndAttestOnChain(quote);

        if (success) {
            isVerified = true; // TODO: delete this once done testing

            // TODO: check that quote is v4 and for TDX, look at AttestationEntrypointBase._parseQuoteHeader
            // for how to get these values from the quote header

            // since the verifyAndAttestOnChain call has succeeded, we can safely
            // decode the output into the report body struct. We implicitly assume
            // only V4 TDX quotes will be used here, and not SGX quotes. If you use
            // anything else, you're on your own
            TD10ReportBody memory td10ReportBody = abi.decode(output, (TD10ReportBody));

            // TODO do flashtestations protocol, so far we've only verified that the quote is valid
        }

        return (success, output);
    }
}
