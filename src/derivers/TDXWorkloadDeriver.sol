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
    function workloadIdForReportBody(TD10ReportBody memory reportBody) internal pure returns (WorkloadId) {
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
                    reportBody.xFAM,
                    reportBody.tdAttributes
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
