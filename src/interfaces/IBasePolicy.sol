// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPolicyCommon} from "./IPolicyCommon.sol";
import {WorkloadId} from "./IPolicyCommon.sol";

/// @notice Shared policy interface (workload allowlist + registry binding).
interface IBasePolicy is IPolicyCommon {
    // ============ Functions ============

    /// @notice Check if this TEE-controlled address has a valid registry registration and
    /// whether its workload is approved under this policy.
    /// @param teeAddress The TEE-controlled address.
    /// @return allowed True if the TEE is using an approved workload in the policy.
    /// @return workloadId The workloadId of the TEE that is using an approved workload, or 0 if not allowed.
    function isAllowedPolicy(address teeAddress) external view returns (bool allowed, WorkloadId workloadId);

    /// @notice Add a workload to a policy (governance only).
    /// @notice Only the policy authority can add workloads to the policy, and it is the responsibility of the
    /// authority to ensure that the workload is valid; otherwise the address associated with this workload has
    /// full power to do anything whose authorization is based on this policy.
    /// @dev The commitHash solves the following problem; The only way for a smart contract like BlockBuilderPolicy
    /// to verify that a TEE (identified by its workloadId) is running a specific piece of code (for instance,
    /// op-rbuilder) is to reproducibly build that workload onchain. This is prohibitively expensive, so instead
    /// we rely on a permissioned multisig (the policy authority) to add a commit hash to the policy whenever
    /// it adds a new workloadId. We're already relying on the authority to verify that the workloadId is valid, so
    /// we can also assume the authority will not add a commit hash that is not associated with the workloadId. If
    /// the authority did act maliciously, this can easily be determined offchain by an honest actor building the
    /// TEE image from the given commit hash, deriving the image's workloadId, and then comparing it to the
    /// workloadId stored on the policy that is associated with the commit hash. If the workloadId is different,
    /// this can be used to prove that the authority acted maliciously. In the honest case, this Policy serves as a
    /// source of truth for which source code of build software (i.e. the commit hash) is used to build the TEE image
    /// identified by the workloadId.
    /// @param workloadId The workload identifier.
    /// @param commitHash The 40-character hexadecimal commit hash of the git repository whose source code is used
    /// to build the TEE image identified by the workloadId.
    /// @param sourceLocators An array of URIs pointing to the source code.
    function addWorkloadToPolicy(WorkloadId workloadId, string calldata commitHash, string[] calldata sourceLocators)
        external;

    /// @notice Remove a workload from a policy (governance only).
    function removeWorkloadFromPolicy(WorkloadId workloadId) external;

    /// @notice Get metadata for an approved workload.
    /// @dev This is only updateable by governance (i.e. the policy authority). Adding and removing a workload is O(1).
    /// @param workloadId The workload identifier to query.
    /// @return The metadata associated with the workload.
    function getWorkloadMetadata(WorkloadId workloadId) external view returns (WorkloadMetadata memory);

    /// @notice Address of the FlashtestationRegistry contract.
    function registry() external view returns (address);
}
