// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice WorkloadID uniquely identifies a TEE workload. A workload is roughly equivalent to a version of an
/// application's code, can be reproduced from source code, and is derived from a combination of the TEE's
/// measurement registers.
/// The TDX platform provides several registers that capture cryptographic hashes of code, data, and configuration
/// loaded into the TEE's environment. This means that whenever a TEE device changes anything about its compute stack
/// (e.g. user code, firmware, OS, etc), the workloadID will change.
/// See the Flashtestation specification for more details:
/// https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md#workload-identity-derivation
/// @dev Shared type used across policies and derivers.
type WorkloadId is bytes32;

/// @notice Common policy surface shared across policy implementations.
/// @dev This is intentionally small and reusable (no block-builder-specific concerns).
interface IPolicyCommon {
    // ============ Types ============

    /**
     * @notice Metadata associated with a workload.
     * @dev Used to track the source code used to build the TEE image identified by the workloadId.
     */
    struct WorkloadMetadata {
        string commitHash;
        string[] sourceLocators;
    }

    // ============ Events ============

    /// @notice Emitted when a workload is added to the policy.
    /// @param workloadId The workload identifier.
    event WorkloadAddedToPolicy(bytes32 indexed workloadId);

    /// @notice Emitted when a workload is removed from the policy.
    /// @param workloadId The workload identifier.
    event WorkloadRemovedFromPolicy(bytes32 indexed workloadId);

    /// @notice Emitted when the registry is set (initialization).
    /// @param registry The address of the registry.
    event RegistrySet(address indexed registry);

    // ============ Errors ============

    /// @notice Emitted when the registry is the 0x0 address.
    error InvalidRegistry();

    /// @notice Emitted when a workload to be added is already in the policy.
    error WorkloadAlreadyInPolicy();

    /// @notice Emitted when a workload to be removed is not in the policy.
    error WorkloadNotInPolicy();

    /// @notice Emitted when the commit hash is empty.
    error EmptyCommitHash();

    /// @notice Emitted when the source locators array is empty.
    error EmptySourceLocators();
}
