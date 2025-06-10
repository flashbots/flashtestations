// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "solmate/src/auth/Owned.sol";
import {WorkloadId} from "./utils/QuoteParser.sol";
import {FlashtestationRegistry} from "./FlashtestationRegistry.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

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

    // only v1 supported for now, but this will change with a contract upgrade
    // Note: we use an array instead of a mapping so that it can be instantiated as a constant
    uint8[] public constant SUPPORTED_VERSIONS = [1];

    // Errors

    error WorkloadAlreadyInPolicy();
    error WorkloadNotInPolicy();
    error UnauthorizedBlockBuilder(address caller); // the teeAddress is not associated with a valid TEE workload
    error UnsupportedVersion(uint8 version); // see SUPPORTED_VERSIONS for supported versions

    // Events

    event WorkloadAddedToPolicy(WorkloadId workloadId);
    event WorkloadRemovedFromPolicy(WorkloadId workloadId);
    event RegistrySet(address registry);
    event BlockBuilderProofVerified(address caller, uint256 blockNumber, uint8 version, bytes32 blockContentHash);

    constructor(address _registry, address initialOwner) Owned(initialOwner) {
        registry = _registry;
        emit RegistrySet(_registry);
    }

    /// @notice Verify a block builder proof
    /// @param version The version of the flashtestation's protocol used to generate the block builder proof
    /// @param blockContentHash The hash of the block content
    /// @notice This function will only succeed if the caller is a registered TEE-controlled address from an attested TEE
    /// and the TEE is running an approved block builder workload (see BlockBuilderPolicy.addWorkloadToPolicy)
    /// @notice The blockContentHash is a keccak256 hash of a subset of the block header, as specified by the version.
    /// See the [flashtestations spec](https://github.com/flashbots/rollup-boost/blob/77fc19f785eeeb9b4eb5fb08463bc556dec2c837/specs/flashtestations.md) for more details
    function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external {
        require(isSupportedVersion(version), UnsupportedVersion(version));
        // Check if the caller is an authorized TEE block builder for our Policy
        require(
            isAllowedPolicy(msg.sender),
            UnauthorizedBlockBuilder(msg.sender)
        );
        
        // At this point, we know:
        // 1. The caller is a registered TEE-controlled address from an attested TEE
        // 2. The TEE is running an approved block builder workload (via policy)
        
        // Note: Due to EVM limitations (no retrospection), we cannot validate the blockContentHash
        // onchain. We rely on the TEE workload to correctly compute this hash according to the
        // specified version of the calculation method.
        
        emit BlockBuilderProofVerified(
            msg.sender,
            block.number,
            version,
            blockContentHash
        );
    }

    /// @notice Helper function to check if a given version is supported by this Policy
    /// @param version The version to check
    /// @return True if the version is supported, false otherwise
    function isSupportedVersion(uint8 version) public view returns (bool) {
        for (uint256 i = 0; i < SUPPORTED_VERSIONS.length; ++i) {
            if (SUPPORTED_VERSIONS[i] == version) {
                return true;
            }
        }
        return false;
    }

    /// @notice Check if an address is allowed under any workload in the policy
    /// @param teeAddress The TEE-controlled address
    /// @return allowed True if the TEE is valid for any workload in the policy
    function isAllowedPolicy(address teeAddress) public view returns (bool allowed) {
        for (uint256 i = 0; i < workloadIds.length(); ++i) {
            WorkloadId workloadId = WorkloadId.wrap(workloadIds.at(i));
            if (FlashtestationRegistry(registry).isValidWorkload(workloadId, teeAddress)) {
                return true;
            }
        }
        return false;
    }

    /// @notice An alternative implementation of isAllowedPolicy that verifies more than just
    /// the workloadId's matching and if the attestation is still valid
    /// @param teeAddress The TEE-controlled address
    /// @param expectedTeeTcbSvn The expected teeTcbSvn of the TEE's attestation
    /// @return allowed True if the TEE's attestation is part of the policy, is still valid, and
    /// the teeTcbSvn matches the expected value
    /// @dev This exists to show how different Policies can be implemented, based on what
    /// properties of the TEE's attestation are important to verify.
    function isAllowedPolicy2(address teeAddress, bytes16 expectedTeeTcbSvn) external view returns (bool allowed) {
        for (uint256 i = 0; i < workloadIds.length(); ++i) {
            WorkloadId workloadId = WorkloadId.wrap(workloadIds.at(i));
            TD10ReportBody memory reportBody = FlashtestationRegistry(registry).getReportBody(teeAddress);
            if (
                FlashtestationRegistry(registry).isValidWorkload(workloadId, teeAddress)
                    && reportBody.teeTcbSvn == expectedTeeTcbSvn
            ) {
                return true;
            }
        }
        return false;
    }

    /// @notice Add a workload to a policy (governance only)
    /// @param workloadId The workload identifier
    /// @notice Only the owner of this contract can add workloads to the policy
    /// and it is the responsibility of the owner to ensure that the workload is valid
    /// otherwise the address associated with this workload has full power to do anything
    /// who's authorization is based on this policy
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
