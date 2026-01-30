// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {WorkloadId} from "./IPolicyCommon.sol";

/// @notice Computes a workload ID from a parsed TDX report body.
/// @dev policies delegate workload derivation to an injected deriver.
interface IWorkloadDeriver {
    /// @notice Derive a workload ID from a raw attestation quote.
    /// @dev Policies can pass `registration.rawQuote` from the registry.
    /// @dev The concrete deriver may parse the quote and internally call a report-body helper.
    function workloadIdForQuote(bytes calldata rawQuote) external pure returns (WorkloadId);
}

