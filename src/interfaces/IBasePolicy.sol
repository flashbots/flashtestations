// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPolicyCommon} from "./IPolicyCommon.sol";
import {WorkloadId} from "./IPolicyCommon.sol";

/// @notice Shared policy interface (workload allowlist + registry binding).
interface IBasePolicy is IPolicyCommon {
    /// @notice Check if this TEE-controlled address has a valid registry registration and
    /// whether its workload is approved under this policy.
    /// @param teeAddress The TEE-controlled address.
    /// @return allowed True if the TEE is using an approved workload in the policy.
    /// @return workloadId The workloadId of the TEE that is using an approved workload, or 0 if not allowed.
    function isAllowedPolicy(address teeAddress) external view returns (bool allowed, WorkloadId workloadId);

    /// @notice Add a workload to a policy (governance only).
    function addWorkloadToPolicy(WorkloadId workloadId, string calldata commitHash, string[] calldata sourceLocators)
        external;

    /// @notice Remove a workload from a policy (governance only).
    function removeWorkloadFromPolicy(WorkloadId workloadId) external;

    /// @notice Get metadata for an approved workload.
    function getWorkloadMetadata(WorkloadId workloadId) external view returns (WorkloadMetadata memory);

    /// @notice Address of the FlashtestationRegistry contract.
    function registry() external view returns (address);
}

