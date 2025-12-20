// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {IWorkloadDeriver} from "../interfaces/IWorkloadDeriver.sol";
import {WorkloadId} from "../interfaces/IPolicyCommon.sol";
import {QuoteParser} from "../utils/QuoteParser.sol";

/// @notice Pure TDX workload-id derivation helpers.
/// @dev Kept alongside `TDXWorkloadDeriver` so policies can reuse the exact same logic without
///      having to make an external call.
library TDXWorkloadDeriverLib {
    /// @dev See section 11.5.3 in TDX Module v1.5 Base Architecture Specification.
    bytes8 internal constant TD_XFAM_FPU = 0x0000000000000001;
    bytes8 internal constant TD_XFAM_SSE = 0x0000000000000002;

    /// @dev See section 3.4.1 in TDX Module ABI specification.
    bytes8 internal constant TD_TDATTRS_VE_DISABLED = 0x0000000010000000;
    bytes8 internal constant TD_TDATTRS_PKS = 0x0000000040000000;
    bytes8 internal constant TD_TDATTRS_KL = 0x0000000080000000;

    function workloadIdForReportBody(TD10ReportBody memory reportBody) internal pure returns (WorkloadId) {
        // We expect FPU and SSE xfam bits to be set, and anything else should be handled by explicitly allowing
        // the workloadId (by governance).
        bytes8 expectedXfamBits = TD_XFAM_FPU | TD_XFAM_SSE;

        // We don't mind VE_DISABLED, PKS, and KL tdattributes bits being set either way; anything else requires
        // explicitly allowing the workloadId.
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
                    reportBody.tdAttributes & ~ignoredTdAttributesBitmask
                )
            )
        );
    }
}

/// @notice Workload deriver that matches the current onchain TDX derivation logic.
contract TDXWorkloadDeriver is IWorkloadDeriver {
    /// @notice Pure helper to derive a workload ID from a parsed TDX report body.
    /// @dev Makes it easy to compute workload IDs pre-registration (e.g. governance approvals).
    function workloadIdForReportBody(TD10ReportBody memory reportBody) public pure returns (WorkloadId) {
        return TDXWorkloadDeriverLib.workloadIdForReportBody(reportBody);
    }

    /// @inheritdoc IWorkloadDeriver
    function workloadIdForQuote(bytes calldata rawQuote) external pure returns (WorkloadId) {
        bytes memory raw = rawQuote;
        TD10ReportBody memory reportBody = QuoteParser.parseV4Quote(raw);
        return TDXWorkloadDeriverLib.workloadIdForReportBody(reportBody);
    }
}

