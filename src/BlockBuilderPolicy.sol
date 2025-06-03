// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "solmate/src/auth/Owned.sol";
import {WorkloadId} from "./utils/QuoteParser.sol";
import {FlashtestationRegistry} from "./FlashtestationRegistry.sol";

/**
 * @title BlockBuilderPolicy
 * @notice A reference implementation of a policy contract for the FlashtestationRegistry
 * @notice A Policy is a collection of related WorkloadIds. A Policy exists to specify which
 * WorkloadIds are valid for a particular purpose, in this case for remote block building. It also
 * exists to handle the problem that TEE workloads will need to change multiple times a year, either because
 * of Intel DCAP Endorsement updates or updates to the TEE configuration (and thus its WorkloadId). Without
 * Policies, consumer contracts that makes use of Flashtestations would need to be updated every time a TEE workload
 * changes, which is a costly and error-prone process. Instead, consumer contracts need only check if a TEE address
 * is allowed under any workload in a Policy, and the FlashtestationRegistry will handle the rest
 */
contract BlockBuilderPolicy is Owned {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // The set of workloadIds that are allowed under this policy
    // This is only updateable by governance (i.e. the owner) of the Policy contract.
    // Adding, and removing a workload is O(1).
    // NOTE: The critical `isAllowedPolicy` function is O(n) where n is the number of workloadIds in the policy
    // This is because it needs to iterate over all workloadIds in the policy to check if the TEE is allowed
    // This is not a problem for small policies, but it is a problem for large policies.
    // The governance of this Policy must ensure that the number of workloadIds in the policy is small
    // to ensure that calling `isAllowedPolicy` is not so expensive that it becomes uncallable due to
    // block gas limits
    EnumerableSet.Bytes32Set internal workloadIds;

    address public immutable registry;

    // Errors

    error WorkloadAlreadyInPolicy();
    error WorkloadNotInPolicy();

    // Events

    event WorkloadAddedToPolicy(WorkloadId workloadId);
    event WorkloadRemovedFromPolicy(WorkloadId workloadId);
    event RegistrySet(address registry);

    constructor(address _registry, address initialOwner) Owned(initialOwner) {
        registry = _registry;
        emit RegistrySet(_registry);
    }

    /// @notice Check if an address is allowed under any workload in the policy
    /// @param teeAddress The TEE-controlled address
    /// @return allowed True if the TEE is valid for any workload in the policy
    function isAllowedPolicy(address teeAddress) external view returns (bool allowed) {
        for (uint256 i = 0; i < workloadIds.length(); ++i) {
            WorkloadId workloadId = WorkloadId.wrap(workloadIds.at(i));
            if (FlashtestationRegistry(registry).isValidWorkload(workloadId, teeAddress)) {
                return true;
            }
        }
        return false;
    }

    /// @notice Add a workload to a policy (governance only)
    /// @param workloadId The workload identifier
    function addWorkloadToPolicy(WorkloadId workloadId) external onlyOwner {
        bool added = workloadIds.add(WorkloadId.unwrap(workloadId));
        require(added, WorkloadAlreadyInPolicy());
        emit WorkloadAddedToPolicy(workloadId);
    }

    /// @notice Remove a workload from a policy (governance only)
    /// @param workloadId The workload identifier
    function removeWorkloadFromPolicy(WorkloadId workloadId) external onlyOwner {
        bool removed = workloadIds.remove(WorkloadId.unwrap(workloadId));
        require(removed, WorkloadNotInPolicy());
        emit WorkloadRemovedFromPolicy(workloadId);
    }

    /// @notice Get all workloads in the policy
    /// @return workloads The workloadIds in the policy
    /// @dev this exists because we need to make workloadIds internal due to a solc
    /// constraint, and so we need to make our own public getter
    function getWorkloads() external view returns (bytes32[] memory) {
        return workloadIds.values();
    }

    /// @notice Get a workload from the policy
    /// @param index The index of the workload
    /// @return workload The workloadId at the given index
    /// @dev this exists because we need to make workloadIds internal due to a solc
    /// constraint, and so we need to make our own public getter
    function getWorkload(uint256 index) external view returns (bytes32) {
        return workloadIds.at(index);
    }
}
