// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "solmate/src/auth/Owned.sol";
import {AutomataDcapAttestationFee} from "../lib/automata-dcap-attestation/evm/contracts/AutomataDcapAttestationFee.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {TD_REPORT10_LENGTH, TDX_TEE} from "automata-dcap-attestation/contracts/types/Constants.sol";
import {BytesUtils} from "@automata-network/on-chain-pccs/utils/BytesUtils.sol";

/**
 * @title AllowList
 * @dev A contract for managing trusted execution environment (TEE) identities and configurations
 * using Intel DCAP attestation
 */
contract AllowList is Owned {
    using BytesUtils for bytes;

    // This is the number of bytes in the Output struct that come before the quoteBody.
    // See the Output struct definition in the Automata DCAP Attestation repo:
    // https://github.com/automata-network/automata-dcap-attestation/blob/evm-v1.0.0/evm/contracts/types/CommonStruct.sol#L113
    // 13 bytes = quoteVersion (2 bytes) + tee (4 byte) + tcbStatus (1 byte) + fmspcBytes (6 bytes)
    uint256 public constant SERIALIZED_OUTPUT_OFFSET = 13;

    // Maximum size for byte arrays to prevent DoS attacks
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024; // 20KB limit

    // The TDX version of the quote Flashtestation's accepts
    uint256 public constant ACCEPTED_TDX_VERSION = 4;

    // TEE identity and status tracking
    struct TEEDevice {
        bytes32 publicKey; // Public key of the TEE device
        uint64 lastActiveTime; // Timestamp of last activity
        bool isActive; // Whether the device is currently active
    }

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
     * @notice Verifies a quote using AutomataDcapAttestationFee
     * @dev TODO: move this logic into registerTEE
     * @param attestationFeeContract The address of the AutomataDcapAttestationFee contract
     * @param quote The DCAP quote to verify
     */
    function verifyQuoteWithAttestationFee(address attestationFeeContract, bytes calldata quote)
        external
        limitBytesSize(quote)
        returns (bool, bytes memory)
    {
        (bool success, bytes memory output) =
            AutomataDcapAttestationFee(attestationFeeContract).verifyAndAttestOnChain(quote);

        if (success) {
            // check that quote is v4 and for TDX, otherwise in the next
            // step the output will not have the byte length we expect and we'll fail
            // to parse it, returning a unhelpful error message
            checkTEEVersion(output);
            checkTEEType(output);

            // now we can safely decode the output into the TDX report body, from which we can extract
            // the ethereum public key and compute the workloadID
            TD10ReportBody memory td10ReportBodyStruct = parseTD10ReportBody(output);


            // TODO do flashtestations protocol, so far we've only verified that the quote is valid
        }

        return (success, output);
    }

    /**
     * @notice Parses a TD10ReportBody which contains all the data we need for
     * registering a TEE, using the serializedOutput bytes generated by Automata's verification logic
     * @param serializedOutput The serializedOutput bytes generated by Automata's verification logic
     * @return report The parsed TD10ReportBody
     * @dev Taken from Automata's DCAP Attestation repo:
     * https://github.com/automata-network/automata-dcap-attestation/blob/evm-v1.0.0/evm/contracts/verifiers/V4QuoteVerifier.sol#L309
     */
    function parseTD10ReportBody(bytes memory serializedOutput)
        internal
        pure
        returns (TD10ReportBody memory report)
    {
        bytes memory rawReportBody = output.substring(SERIALIZED_OUTPUT_OFFSET, TD_REPORT10_LENGTH);

        // note: because of the call to .substring above, we know that the length of rawReportBody is
        // exactly TD_REPORT10_LENGTH, so we can safely call substring without checking the length

        if (success) {
            report.teeTcbSvn = bytes16(rawReportBody.substring(0, 16));
            report.mrSeam = rawReportBody.substring(16, 48);
            report.mrsignerSeam = rawReportBody.substring(64, 48);
            report.seamAttributes = bytes8(rawReportBody.substring(112, 8));
            report.tdAttributes = bytes8(rawReportBody.substring(120, 8));
            report.xFAM = bytes8(rawReportBody.substring(128, 8));
            report.mrTd = rawReportBody.substring(136, 48);
            report.mrConfigId = rawReportBody.substring(184, 48);
            report.mrOwner = rawReportBody.substring(232, 48);
            report.mrOwnerConfig = rawReportBody.substring(280, 48);
            report.rtMr0 = rawReportBody.substring(328, 48);
            report.rtMr1 = rawReportBody.substring(376, 48);
            report.rtMr2 = rawReportBody.substring(424, 48);
            report.rtMr3 = rawReportBody.substring(472, 48);
            report.reportData = rawReportBody.substring(520, 64);
        }
    }

    /**
     * Parses and checks that the uint16 version from the quote header is one we accept
     * @param rawReportBody The rawQuote bytes generated by Automata's verification logic
     * @dev Automata currently only supports V3 and V4 TDX quotes
     */
    function checkTEEVersion(bytes memory rawReportBody) internal pure {
        version = uint16(rawReportBody.substring(0, 2)); // uint16 is 2 bytes
        if (version != ACCEPTED_TDX_VERSION) {
            revert InvalidTEEVersion(version);
        }
    }

    /**
     * Parses and checks that the bytes4 tee type from the quote header is of type TDX
     * @param rawReportBody The rawQuote bytes generated by Automata's verification logic
     * @dev Automata currently only supports SGX and TDX TEE types
     */
    function checkTEEType(bytes memory rawReportBody) internal pure {
        teeType = bytes4(rawReportBody.substring(2, 6)); // 4 bytes
        if (teeType != TDX_TEE) {
            revert InvalidTEEType(teeType);
        }
    }
}
