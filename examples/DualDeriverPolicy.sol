// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BasePolicy} from "../src/BasePolicy.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";
import {IWorkloadDeriver} from "../src/interfaces/IWorkloadDeriver.sol";
import {WorkloadId} from "../src/interfaces/IPolicyCommon.sol";
import {HEADER_LENGTH} from "automata-dcap-attestation/contracts/types/Constants.sol";

/// @notice Example policy that supports two workload derivation strategies during a migration.
/// @dev Demonstrates how to inherit `BasePolicy` and override `isAllowedPolicy` to accept
///      workloads derived by either an "old" deriver or a "new" deriver.
///
///      WARNING: This contract is an UNAUDITED EXAMPLE and is NOT intended for production use.
///      It is provided to illustrate one possible migration pattern; do not deploy without
///      a thorough security review
///
/// Quote format detection:
/// - You *can* sometimes distinguish formats by length (e.g. TD10 vs a hypothetical TD15 report body),
///   but real quote payload sizes can vary and some derivers accept both "raw report body" and "quote-like" blobs.
/// - This example uses a light length-based hint to decide which deriver to try first, but still falls back to
///   trying both with `try/catch` to remain robust.
contract DualDeriverPolicy is BasePolicy {
    address public immutable OWNER;
    IWorkloadDeriver public immutable OLD_DERIVER;
    IWorkloadDeriver public immutable NEW_DERIVER;

    // For the example TD15 report-body format: 584 (TD10) + 16 + 48.
    uint256 internal constant TD_REPORT15_LENGTH = 648;

    constructor(address owner_, address registry_, IWorkloadDeriver oldDeriver_, IWorkloadDeriver newDeriver_) {
        OWNER = owner_;
        OLD_DERIVER = oldDeriver_;
        NEW_DERIVER = newDeriver_;
        _basePolicyInit(registry_);
    }

    function _checkPolicyAuthority() internal view override {
        require(msg.sender == OWNER, "NotOwner");
    }

    // Not used by this example (we override `isAllowedPolicy`), but required by BasePolicy.
    function _workloadDeriver() internal view override returns (IWorkloadDeriver) {
        return NEW_DERIVER;
    }

    // This example policy does not use caching, so the cache hooks are implemented as no-ops.
    function _getCachedWorkload(address) internal pure override returns (CachedWorkload memory) {
        return CachedWorkload({workloadId: WorkloadId.wrap(0), quoteHash: bytes32(0)});
    }

    function _setCachedWorkload(address, CachedWorkload memory) internal override {}

    /// @inheritdoc BasePolicy
    function isAllowedPolicy(address teeAddress)
        public
        view
        override
        returns (bool allowed, WorkloadId)
    {
        (, IFlashtestationRegistry.RegisteredTEE memory registration) =
            IFlashtestationRegistry(registry).getRegistration(teeAddress);
        if (!registration.isValid) return (false, WorkloadId.wrap(0));

        bytes memory rawQuote = registration.rawQuote;

        // Hint: if it looks like a TD15 report body or a quote containing one, try NEW first.
        bool preferNew = rawQuote.length == TD_REPORT15_LENGTH || rawQuote.length == HEADER_LENGTH + TD_REPORT15_LENGTH;

        (bool okNew, WorkloadId idNew) = (false, WorkloadId.wrap(0));
        (bool okOld, WorkloadId idOld) = (false, WorkloadId.wrap(0));

        if (preferNew) {
            try NEW_DERIVER.workloadIdForQuote(rawQuote) returns (WorkloadId id) {
                okNew = true;
                idNew = id;
            } catch {}

            try OLD_DERIVER.workloadIdForQuote(rawQuote) returns (WorkloadId id) {
                okOld = true;
                idOld = id;
            } catch {}
        } else {
            try OLD_DERIVER.workloadIdForQuote(rawQuote) returns (WorkloadId id) {
                okOld = true;
                idOld = id;
            } catch {}

            try NEW_DERIVER.workloadIdForQuote(rawQuote) returns (WorkloadId id) {
                okNew = true;
                idNew = id;
            } catch {}
        }

        // Prefer NEW workload IDs during migration if both are approved.
        if (okNew && bytes(approvedWorkloads[WorkloadId.unwrap(idNew)].commitHash).length > 0) {
            return (true, idNew);
        }
        if (okOld && bytes(approvedWorkloads[WorkloadId.unwrap(idOld)].commitHash).length > 0) {
            return (true, idOld);
        }

        return (false, WorkloadId.wrap(0));
    }
}

