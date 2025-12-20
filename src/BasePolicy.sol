// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IBasePolicy} from "./interfaces/IBasePolicy.sol";
import {IFlashtestationRegistry} from "./interfaces/IFlashtestationRegistry.sol";
import {IWorkloadDeriver} from "./interfaces/IWorkloadDeriver.sol";
import {WorkloadId} from "./interfaces/IPolicyCommon.sol";

/// @notice Shared policy implementation holding common workload/registry logic.
/// @dev IMPORTANT: This contract is designed to be inherited by upgradeable policies without
///      breaking `BlockBuilderPolicy` storage layout. It MUST NOT introduce additional storage
///      beyond `approvedWorkloads` and `registry` (in that order).
abstract contract BasePolicy is IBasePolicy {
    // ============ Types ============

    /**
     * @notice Cached workload information for gas optimization.
     * @dev Stored in the derived contract; BasePolicy only defines the type + logic hooks.
     */
    struct CachedWorkload {
        WorkloadId workloadId;
        bytes32 quoteHash;
    }

    // ============ Storage (DO NOT REORDER / ADD) ============

    /// @notice Mapping from workloadId to its metadata (commit hash and source locators).
    mapping(bytes32 workloadId => WorkloadMetadata) internal approvedWorkloads;

    /// @inheritdoc IBasePolicy
    address public override registry;

    // ============ Initialization ============

    /// @dev Shared initializer helper for derived contracts.
    function _basePolicyInit(address _registry) internal {
        if (_registry == address(0)) revert InvalidRegistry();
        registry = _registry;
        emit RegistrySet(_registry);
    }

    // ============ Required hooks (implemented by derived policy) ============

    /// @dev Access-control hook (typically maps to `OwnableUpgradeable._checkOwner()`).
    /// @dev `BasePolicy` is intentionally not `OwnableUpgradeable` to preserve `BlockBuilderPolicy`'s
    ///      storage layout and keep the authorization mechanism flexible for downstream policies.
    function _checkPolicyAuthority() internal view virtual;

    /// @dev Workload deriver hook
    /// @return The configured workload deriver (or address(0) if not configured).
    function _workloadDeriver() internal view virtual returns (IWorkloadDeriver);

    /// @dev Cache read hook.
    function _getCachedWorkload(address teeAddress) internal view virtual returns (CachedWorkload memory);

    /// @dev Cache write hook.
    function _setCachedWorkload(address teeAddress, CachedWorkload memory cached) internal virtual;

    // ============ Common policy logic ============

    /// @inheritdoc IBasePolicy
    function addWorkloadToPolicy(WorkloadId workloadId, string calldata commitHash, string[] calldata sourceLocators)
        external
        virtual
        override
    {
        _checkPolicyAuthority();

        require(bytes(commitHash).length > 0, EmptyCommitHash());
        require(sourceLocators.length > 0, EmptySourceLocators());

        bytes32 workloadKey = WorkloadId.unwrap(workloadId);

        // Check if workload already exists
        require(bytes(approvedWorkloads[workloadKey].commitHash).length == 0, WorkloadAlreadyInPolicy());

        // Store the workload metadata
        approvedWorkloads[workloadKey] = WorkloadMetadata({commitHash: commitHash, sourceLocators: sourceLocators});

        emit WorkloadAddedToPolicy(workloadKey);
    }

    /// @inheritdoc IBasePolicy
    function removeWorkloadFromPolicy(WorkloadId workloadId) external virtual override {
        _checkPolicyAuthority();

        bytes32 workloadKey = WorkloadId.unwrap(workloadId);

        // Check if workload exists
        require(bytes(approvedWorkloads[workloadKey].commitHash).length > 0, WorkloadNotInPolicy());

        // Remove the workload metadata
        delete approvedWorkloads[workloadKey];

        emit WorkloadRemovedFromPolicy(workloadKey);
    }

    /// @inheritdoc IBasePolicy
    function getWorkloadMetadata(WorkloadId workloadId) external view override returns (WorkloadMetadata memory) {
        return approvedWorkloads[WorkloadId.unwrap(workloadId)];
    }

    /// @inheritdoc IBasePolicy
    function isAllowedPolicy(address teeAddress) public view virtual override returns (bool allowed, WorkloadId) {
        // Get full registration data
        (, IFlashtestationRegistry.RegisteredTEE memory registration) =
            IFlashtestationRegistry(registry).getRegistration(teeAddress);

        // Invalid Registrations means the attestation used to register the TEE is no longer valid
        // and so we cannot trust any input from the TEE.
        if (!registration.isValid) {
            return (false, WorkloadId.wrap(0));
        }

        IWorkloadDeriver deriver = _workloadDeriver();
        if (address(deriver) == address(0)) {
            // Treat missing deriver as "not allowed" to avoid bricking callers during upgrades.
            return (false, WorkloadId.wrap(0));
        }
        WorkloadId workloadId = deriver.workloadIdForQuote(registration.rawQuote);

        // Check if the workload exists in our approved workloads mapping
        if (bytes(approvedWorkloads[WorkloadId.unwrap(workloadId)].commitHash).length > 0) {
            return (true, workloadId);
        }

        return (false, WorkloadId.wrap(0));
    }

    /// @notice Cached variant of `isAllowedPolicy` for gas-sensitive call paths.
    /// @dev Why this exists:
    ///      - `isAllowedPolicy` is `view` but can be expensive because workloadId derivation can be costly.
    ///      - Some policies (notably `BlockBuilderPolicy`) need an O(1)-ish authorization check on the hot path
    ///        (e.g. `verifyBlockBuilderProof`), so we cache the derived workloadId keyed by the TEE's quoteHash.
    ///
    /// @dev How it is expected to be used:
    ///      - Derived policies call `_cachedIsAllowedPolicy(teeAddress)` from their hot path.
    ///      - Cache storage lives in the derived policy; `BasePolicy` only implements the algorithm and calls the
    ///        `_getCachedWorkload` / `_setCachedWorkload` hooks.
    ///      - The function checks registry validity + quoteHash; on cache hit it avoids recomputing derivation.
    ///      - On cache miss (or quote change), it falls back to `isAllowedPolicy` and updates the cache if allowed.
    ///
    /// @dev Cache cleanup:
    ///      - This function does not proactively delete stale cache entries. On invalid registrations it returns
    ///        `(false, 0)` and callers typically revert, so cleanup is intentionally skipped to keep the hot path cheap.
    ///
    /// @param teeAddress The TEE-controlled address to check.
    /// @return allowed True if the TEE is registered, valid, and running an approved workload.
    /// @return workloadId The approved workloadId for this TEE (or 0 if not allowed).
    function _cachedIsAllowedPolicy(address teeAddress) internal returns (bool, WorkloadId) {
        // Get the current registration status (fast path)
        (bool isValid, bytes32 quoteHash) = IFlashtestationRegistry(registry).getRegistrationStatus(teeAddress);
        if (!isValid) {
            return (false, WorkloadId.wrap(0));
        }

        // Now, check if we have a cached workload for this TEE
        CachedWorkload memory cached = _getCachedWorkload(teeAddress);
        bytes32 cachedWorkloadKey = WorkloadId.unwrap(cached.workloadId);

        // Check if we've already fetched and computed the workloadId for this TEE
        if (cachedWorkloadKey != 0 && cached.quoteHash == quoteHash) {
            // Cache hit - verify the workload is still a part of this policy's approved workloads
            if (bytes(approvedWorkloads[cachedWorkloadKey].commitHash).length > 0) {
                return (true, cached.workloadId);
            }
            // The workload is no longer approved, so the policy is no longer valid for this TEE
            return (false, WorkloadId.wrap(0));
        } else {
            // Cache miss or quote changed - use the view function to get the result
            //
            // Correctness note: even if a downstream policy "disables" caching by implementing the cache hooks as
            // no-ops (e.g. always returning zero and never persisting), this function still behaves correctly:
            // it simply falls back to the canonical `isAllowedPolicy` check every time.
            (bool allowed, WorkloadId workloadId) = isAllowedPolicy(teeAddress);

            if (allowed) {
                // Update cache with the new workload ID
                _setCachedWorkload(teeAddress, CachedWorkload({workloadId: workloadId, quoteHash: quoteHash}));
            }

            return (allowed, workloadId);
        }
    }
}

