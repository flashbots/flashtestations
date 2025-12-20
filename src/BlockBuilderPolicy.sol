// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IFlashtestationRegistry} from "./interfaces/IFlashtestationRegistry.sol";
import {IBasePolicy} from "./interfaces/IBasePolicy.sol";
import {IBlockBuilderPolicy} from "./interfaces/IBlockBuilderPolicy.sol";
import {IWorkloadDeriver} from "./interfaces/IWorkloadDeriver.sol";
import {WorkloadId} from "./interfaces/IPolicyCommon.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {BasePolicy} from "./BasePolicy.sol";
import {TDXWorkloadDeriver} from "./derivers/TDXWorkloadDeriver.sol";

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
contract BlockBuilderPolicy is
    BasePolicy,
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    EIP712Upgradeable,
    IBlockBuilderPolicy
{
    using ECDSA for bytes32;

    // ============ EIP-712 Constants ============

    /// @inheritdoc IBlockBuilderPolicy
    bytes32 public constant VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH =
        keccak256("VerifyBlockBuilderProof(uint8 version,bytes32 blockContentHash,uint256 nonce)");

    // ============ Storage Variables ============

    /// @inheritdoc IBlockBuilderPolicy
    mapping(address teeAddress => uint256 permitNonce) public nonces;

    /// @notice Cache of computed workloadIds to avoid expensive recomputation
    /// @dev Maps teeAddress to cached workload information for gas optimization
    mapping(address teeAddress => CachedWorkload) private cachedWorkloads;

    /// @notice Workload deriver used by the shared base policy logic (Option B).
    IWorkloadDeriver public workloadDeriver;

    /// @notice Emitted when the workload deriver is set or updated.
    event WorkloadDeriverSet(address indexed deriver);

    /// @dev Storage gap to allow for future storage variable additions in upgrades
    /// @dev This reserves 45 storage slots (out of 50 total - 5 used for approvedWorkloads, registry, nonces, cachedWorkloads, and workloadDeriver)
    uint256[45] __gap;

    /// @inheritdoc IBlockBuilderPolicy
    function initialize(address _initialOwner, address _registry, address deriver) external override initializer {
        __Ownable_init(_initialOwner);
        __UUPSUpgradeable_init();
        __EIP712_init("BlockBuilderPolicy", "1");
        _basePolicyInit(_registry);
        _setWorkloadDeriver(deriver);
    }

    /// @notice Set the workload deriver (governance only).
    /// @dev This is needed for proxy upgrade flows where a new storage variable is introduced.
    function setWorkloadDeriver(address deriver) external override onlyOwner {
        _setWorkloadDeriver(deriver);
    }

    function _setWorkloadDeriver(address deriver) internal {
        require(deriver != address(0), "InvalidWorkloadDeriver");
        require(deriver.code.length > 0, "InvalidWorkloadDeriver");

        // Guard: this policy's `isAllowedPolicy` override assumes the configured deriver supports
        // `workloadIdForReportBody(TD10ReportBody)` (to avoid re-parsing raw quotes).
        //
        // Solidity "type safety" is not enforced at runtime, so we proactively verify the method exists and succeeds.
        TD10ReportBody memory empty;
        (bool ok, bytes memory ret) =
            deriver.staticcall(abi.encodeCall(TDXWorkloadDeriver.workloadIdForReportBody, (empty)));
        require(ok && ret.length == 32, "DeriverMissingWorkloadIdForReportBody");

        workloadDeriver = IWorkloadDeriver(deriver);
        emit WorkloadDeriverSet(deriver);
    }

    /// @notice Restricts upgrades to owner only
    /// @param newImplementation The address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ============ BasePolicy hooks ============

    function _checkPolicyAuthority() internal view override {
        _checkOwner();
    }

    function _workloadDeriver() internal view override returns (IWorkloadDeriver) {
        return workloadDeriver;
    }

    function _getCachedWorkload(address teeAddress) internal view override returns (CachedWorkload memory) {
        return cachedWorkloads[teeAddress];
    }

    function _setCachedWorkload(address teeAddress, CachedWorkload memory cached) internal override {
        cachedWorkloads[teeAddress] = cached;
    }

    // ============ Block-builder proof verification ============

    /// @inheritdoc IBlockBuilderPolicy
    function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external override {
        _verifyBlockBuilderProof(msg.sender, version, blockContentHash);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function permitVerifyBlockBuilderProof(
        uint8 version,
        bytes32 blockContentHash,
        uint256 nonce,
        bytes calldata eip712Sig
    ) external override {
        // Get the TEE address from the signature
        bytes32 digest = getHashedTypeDataV4(computeStructHash(version, blockContentHash, nonce));
        address teeAddress = digest.recover(eip712Sig);

        // Verify the nonce
        uint256 expectedNonce = nonces[teeAddress];
        require(nonce == expectedNonce, InvalidNonce(expectedNonce, nonce));

        // Increment the nonce
        nonces[teeAddress]++;

        // Verify the block builder proof
        _verifyBlockBuilderProof(teeAddress, version, blockContentHash);
    }

    /// @notice Internal function to verify a block builder proof
    /// @dev This function is internal because it is only used by the permitVerifyBlockBuilderProof function
    /// and it is not needed to be called by other contracts
    /// @param teeAddress The TEE-controlled address
    /// @param version The version of the flashtestation's protocol
    /// @param blockContentHash The hash of the block content
    function _verifyBlockBuilderProof(address teeAddress, uint8 version, bytes32 blockContentHash) internal {
        // Check if the caller is an authorized TEE block builder for our Policy and update cache
        (bool allowed, WorkloadId workloadId) = _cachedIsAllowedPolicy(teeAddress);
        require(allowed, UnauthorizedBlockBuilder(teeAddress));

        // At this point, we know:
        // 1. The caller is a registered TEE-controlled address from an attested TEE
        // 2. The TEE is running an approved block builder workload (via policy)

        // Note: Due to EVM limitations (no retrospection), we cannot validate the blockContentHash
        // onchain. We rely on the TEE workload to correctly compute this hash according to the
        // specified version of the calculation method.

        bytes32 workloadKey = WorkloadId.unwrap(workloadId);
        string memory commitHash = approvedWorkloads[workloadKey].commitHash;
        emit BlockBuilderProofVerified(teeAddress, workloadKey, version, blockContentHash, commitHash);
    }

    /// @inheritdoc BasePolicy
    /// @dev Override to avoid re-parsing `registration.rawQuote` on cache misses. We already have the parsed report body
    ///      stored in the registry registration.
    function isAllowedPolicy(address teeAddress)
        public
        view
        override(BasePolicy, IBasePolicy)
        returns (bool allowed, WorkloadId)
    {
        (, IFlashtestationRegistry.RegisteredTEE memory registration) =
            IFlashtestationRegistry(registry).getRegistration(teeAddress);

        if (!registration.isValid) {
            return (false, WorkloadId.wrap(0));
        }

        // NOTE: This policy assumes the configured deriver supports TDX report-body derivation.
        WorkloadId workloadId =
            TDXWorkloadDeriver(address(workloadDeriver)).workloadIdForReportBody(registration.parsedReportBody);

        if (bytes(approvedWorkloads[WorkloadId.unwrap(workloadId)].commitHash).length > 0) {
            return (true, workloadId);
        }

        return (false, WorkloadId.wrap(0));
    }

    /// @notice Derive a workloadId from a parsed report body via the configured deriver.
    /// @dev This is `view` because it performs an external call to the configured deriver contract.
    /// @dev We intentionally call `workloadIdForReportBody` directly to avoid re-parsing the quote when the report body
    ///      is already available.
    function workloadIdForReportBody(TD10ReportBody memory reportBody) public view returns (WorkloadId) {
        return TDXWorkloadDeriver(address(workloadDeriver)).workloadIdForReportBody(reportBody);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function workloadIdForTDRegistration(IFlashtestationRegistry.RegisteredTEE memory registration)
        public
        view
        override
        returns (WorkloadId)
    {
        return workloadIdForReportBody(registration.parsedReportBody);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function getHashedTypeDataV4(bytes32 structHash) public view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function computeStructHash(uint8 version, bytes32 blockContentHash, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH, version, blockContentHash, nonce));
    }

    /// @inheritdoc IBlockBuilderPolicy
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
