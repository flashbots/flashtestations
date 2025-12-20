// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// NOTE: The parsing approach and offsets here are taken from Automata's DCAP attestation
// https://github.com/automata-network/automata-dcap-attestation/tree/main

import {BytesUtils} from "@automata-network/on-chain-pccs/utils/BytesUtils.sol";
import {HEADER_LENGTH} from "automata-dcap-attestation/contracts/types/Constants.sol";

import {IWorkloadDeriver} from "../src/interfaces/IWorkloadDeriver.sol";
import {WorkloadId} from "../src/interfaces/IPolicyCommon.sol";

/// @notice "TDX 1.5" report body example with two additional fields.
/// @dev This is NOT a canonical flashtestations type; it is an example format to demonstrate how to swap derivation logic.
struct TD15ReportBody {
    bytes16 teeTcbSvn;
    bytes mrSeam; // 48 bytes
    bytes mrsignerSeam; // 48 bytes
    bytes8 seamAttributes;
    bytes8 tdAttributes;
    bytes8 xFAM;
    bytes mrTd; // 48 bytes
    bytes mrConfigId; // 48 bytes
    bytes mrOwner; // 48 bytes
    bytes mrOwnerConfig; // 48 bytes
    bytes rtMr0; // 48 bytes
    bytes rtMr1; // 48 bytes
    bytes rtMr2; // 48 bytes
    bytes rtMr3; // 48 bytes
    bytes reportData; // 64 bytes
    bytes16 teeTcbSvn2;
    bytes mrServiceTd; // 48 bytes
}

library TD15ReportParser {
    using BytesUtils for bytes;

    // 584-byte TD10 report body + 16 + 48 extra bytes.
    uint256 internal constant TD_REPORT15_LENGTH = 648;

    function parse(bytes memory reportBytes) internal pure returns (bool success, TD15ReportBody memory report) {
        success = reportBytes.length == TD_REPORT15_LENGTH;
        if (!success) return (false, report);

        report.teeTcbSvn = bytes16(reportBytes.substring(0, 16));
        report.mrSeam = reportBytes.substring(16, 48);
        report.mrsignerSeam = reportBytes.substring(64, 48);
        report.seamAttributes = bytes8(reportBytes.substring(112, 8));
        report.tdAttributes = bytes8(reportBytes.substring(120, 8));
        report.xFAM = bytes8(reportBytes.substring(128, 8));
        report.mrTd = reportBytes.substring(136, 48);
        report.mrConfigId = reportBytes.substring(184, 48);
        report.mrOwner = reportBytes.substring(232, 48);
        report.mrOwnerConfig = reportBytes.substring(280, 48);
        report.rtMr0 = reportBytes.substring(328, 48);
        report.rtMr1 = reportBytes.substring(376, 48);
        report.rtMr2 = reportBytes.substring(424, 48);
        report.rtMr3 = reportBytes.substring(472, 48);
        report.reportData = reportBytes.substring(520, 64);
        report.teeTcbSvn2 = bytes16(reportBytes.substring(584, 16));
        report.mrServiceTd = reportBytes.substring(600, 48);
    }
}

/// @notice Example deriver that expects a TD15 report body and hashes the two additional fields.
contract TDXTD15WorkloadDeriver is IWorkloadDeriver {
    using BytesUtils for bytes;

    // Same constants as the current TDX deriver.
    bytes8 internal constant TD_XFAM_FPU = 0x0000000000000001;
    bytes8 internal constant TD_XFAM_SSE = 0x0000000000000002;
    bytes8 internal constant TD_TDATTRS_VE_DISABLED = 0x0000000010000000;
    bytes8 internal constant TD_TDATTRS_PKS = 0x0000000040000000;
    bytes8 internal constant TD_TDATTRS_KL = 0x0000000080000000;

    error InvalidTD15ReportLength(uint256 length);

    function workloadIdForReportBody(TD15ReportBody memory reportBody) public pure returns (WorkloadId) {
        bytes8 expectedXfamBits = TD_XFAM_FPU | TD_XFAM_SSE;
        bytes8 ignoredTdAttributesBitmask = TD_TDATTRS_VE_DISABLED | TD_TDATTRS_PKS | TD_TDATTRS_KL;

        return WorkloadId.wrap(
            keccak256(
                bytes.concat(
                    reportBody.mrTd,
                    reportBody.rtMr0,
                    reportBody.rtMr1,
                    reportBody.rtMr2,
                    reportBody.rtMr3,
                    // VMM configuration
                    reportBody.mrConfigId,
                    reportBody.xFAM ^ expectedXfamBits,
                    reportBody.tdAttributes & ~ignoredTdAttributesBitmask,
                    // TD15 extensions
                    bytes16(reportBody.teeTcbSvn2),
                    reportBody.mrServiceTd
                )
            )
        );
    }

    /// @inheritdoc IWorkloadDeriver
    /// @dev Accepts either:
    ///      - the raw TD15 report body bytes (length == TD_REPORT15_LENGTH), or
    ///      - a quote-like blob where the report body starts at HEADER_LENGTH.
    function workloadIdForQuote(bytes calldata rawQuote) external pure returns (WorkloadId) {
        bytes memory raw = rawQuote;

        // Try raw report body first.
        (bool ok, TD15ReportBody memory report) = TD15ReportParser.parse(raw);
        if (ok) return workloadIdForReportBody(report);

        // Try treating `rawQuote` as a quote with a header prefix.
        if (raw.length >= HEADER_LENGTH + TD15ReportParser.TD_REPORT15_LENGTH) {
            bytes memory reportBytes = raw.substring(HEADER_LENGTH, TD15ReportParser.TD_REPORT15_LENGTH);
            (ok, report) = TD15ReportParser.parse(reportBytes);
            if (ok) return workloadIdForReportBody(report);
        }

        revert InvalidTD15ReportLength(raw.length);
    }
}

