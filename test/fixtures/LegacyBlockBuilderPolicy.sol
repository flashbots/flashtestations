// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {FlashtestationRegistry} from "../../src/FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "../../src/interfaces/IFlashtestationRegistry.sol";
import {IBlockBuilderPolicy} from "../../src/interfaces/IBlockBuilderPolicy.sol";
import {WorkloadId} from "../../src/interfaces/IPolicyCommon.sol";

/// @notice Legacy (pre-refactor) BlockBuilderPolicy used for upgrade regression tests.
/// @dev Intentionally mirrors the historical storage layout:
///      approvedWorkloads (slot 0), registry (slot 1), nonces (slot 2), cachedWorkloads (slot 3), gap.
contract LegacyBlockBuilderPolicy is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    EIP712Upgradeable,
    IBlockBuilderPolicy
{
    using ECDSA for bytes32;

    struct CachedWorkload {
        WorkloadId workloadId;
        bytes32 quoteHash;
    }

    bytes32 public constant VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH =
        keccak256("VerifyBlockBuilderProof(uint8 version,bytes32 blockContentHash,uint256 nonce)");

    // TDX workload constants (legacy)
    bytes8 constant TD_XFAM_FPU = 0x0000000000000001;
    bytes8 constant TD_XFAM_SSE = 0x0000000000000002;
    bytes8 constant TD_TDATTRS_VE_DISABLED = 0x0000000010000000;
    bytes8 constant TD_TDATTRS_PKS = 0x0000000040000000;
    bytes8 constant TD_TDATTRS_KL = 0x0000000080000000;

    // ===== Storage =====
    mapping(bytes32 workloadId => WorkloadMetadata) private approvedWorkloads;
    address public registry;
    mapping(address teeAddress => uint256 permitNonce) public nonces;
    mapping(address teeAddress => CachedWorkload) private cachedWorkloads;
    uint256[46] __gap;

    function initialize(address _initialOwner, address _registry, address) external initializer {
        __Ownable_init(_initialOwner);
        __UUPSUpgradeable_init();
        __EIP712_init("BlockBuilderPolicy", "1");
        if (_registry == address(0)) revert InvalidRegistry();
        registry = _registry;
        emit RegistrySet(_registry);
    }

    function setCachedWorkload(address teeAddress, WorkloadId workloadId, bytes32 quoteHash) external onlyOwner {
        cachedWorkloads[teeAddress] = CachedWorkload({workloadId: workloadId, quoteHash: quoteHash});
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external override {
        _verifyBlockBuilderProof(msg.sender, version, blockContentHash);
    }

    function permitVerifyBlockBuilderProof(
        uint8 version,
        bytes32 blockContentHash,
        uint256 nonce,
        bytes calldata eip712Sig
    ) external override {
        bytes32 digest = getHashedTypeDataV4(computeStructHash(version, blockContentHash, nonce));
        address teeAddress = digest.recover(eip712Sig);

        uint256 expectedNonce = nonces[teeAddress];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
        nonces[teeAddress]++;

        _verifyBlockBuilderProof(teeAddress, version, blockContentHash);
    }

    function _verifyBlockBuilderProof(address teeAddress, uint8 version, bytes32 blockContentHash) internal {
        (bool allowed, WorkloadId workloadId) = _cachedIsAllowedPolicy(teeAddress);
        if (!allowed) revert UnauthorizedBlockBuilder(teeAddress);

        bytes32 workloadKey = WorkloadId.unwrap(workloadId);
        string memory commitHash = approvedWorkloads[workloadKey].commitHash;
        emit BlockBuilderProofVerified(teeAddress, workloadKey, version, blockContentHash, commitHash);
    }

    function isAllowedPolicy(address teeAddress) public view override returns (bool allowed, WorkloadId) {
        (, IFlashtestationRegistry.RegisteredTEE memory registration) =
            FlashtestationRegistry(registry).getRegistration(teeAddress);
        if (!registration.isValid) return (false, WorkloadId.wrap(0));

        WorkloadId workloadId = workloadIdForTDRegistration(registration);
        if (bytes(approvedWorkloads[WorkloadId.unwrap(workloadId)].commitHash).length > 0) return (true, workloadId);
        return (false, WorkloadId.wrap(0));
    }

    function _cachedIsAllowedPolicy(address teeAddress) private returns (bool, WorkloadId) {
        (bool isValid, bytes32 quoteHash) = FlashtestationRegistry(registry).getRegistrationStatus(teeAddress);
        if (!isValid) return (false, WorkloadId.wrap(0));

        CachedWorkload memory cached = cachedWorkloads[teeAddress];
        bytes32 cachedWorkloadId = WorkloadId.unwrap(cached.workloadId);
        if (cachedWorkloadId != 0 && cached.quoteHash == quoteHash) {
            if (bytes(approvedWorkloads[cachedWorkloadId].commitHash).length > 0) {
                return (true, cached.workloadId);
            }
            return (false, WorkloadId.wrap(0));
        }

        (bool allowed, WorkloadId workloadId) = isAllowedPolicy(teeAddress);
        if (allowed) {
            cachedWorkloads[teeAddress] = CachedWorkload({workloadId: workloadId, quoteHash: quoteHash});
        }
        return (allowed, workloadId);
    }

    function workloadIdForTDRegistration(IFlashtestationRegistry.RegisteredTEE memory registration)
        public
        pure
        override
        returns (WorkloadId)
    {
        bytes8 expectedXfamBits = TD_XFAM_FPU | TD_XFAM_SSE;
        bytes8 ignoredTdAttributesBitmask = TD_TDATTRS_VE_DISABLED | TD_TDATTRS_PKS | TD_TDATTRS_KL;

        return WorkloadId.wrap(
            keccak256(
                bytes.concat(
                    registration.parsedReportBody.mrTd,
                    registration.parsedReportBody.rtMr0,
                    registration.parsedReportBody.rtMr1,
                    registration.parsedReportBody.rtMr2,
                    registration.parsedReportBody.rtMr3,
                    registration.parsedReportBody.mrConfigId,
                    registration.parsedReportBody.xFAM ^ expectedXfamBits,
                    registration.parsedReportBody.tdAttributes & ~ignoredTdAttributesBitmask
                )
            )
        );
    }

    function addWorkloadToPolicy(WorkloadId workloadId, string calldata commitHash, string[] calldata sourceLocators)
        external
        override
        onlyOwner
    {
        if (bytes(commitHash).length == 0) revert EmptyCommitHash();
        if (sourceLocators.length == 0) revert EmptySourceLocators();

        bytes32 workloadKey = WorkloadId.unwrap(workloadId);
        if (bytes(approvedWorkloads[workloadKey].commitHash).length != 0) revert WorkloadAlreadyInPolicy();
        approvedWorkloads[workloadKey] = WorkloadMetadata({commitHash: commitHash, sourceLocators: sourceLocators});
        emit WorkloadAddedToPolicy(workloadKey);
    }

    function removeWorkloadFromPolicy(WorkloadId workloadId) external override onlyOwner {
        bytes32 workloadKey = WorkloadId.unwrap(workloadId);
        if (bytes(approvedWorkloads[workloadKey].commitHash).length == 0) revert WorkloadNotInPolicy();
        delete approvedWorkloads[workloadKey];
        emit WorkloadRemovedFromPolicy(workloadKey);
    }

    function getWorkloadMetadata(WorkloadId workloadId) external view override returns (WorkloadMetadata memory) {
        return approvedWorkloads[WorkloadId.unwrap(workloadId)];
    }

    function setWorkloadDeriver(address) external pure override {
        revert("Legacy: no deriver");
    }

    function getHashedTypeDataV4(bytes32 structHash) public view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    function computeStructHash(uint8 version, bytes32 blockContentHash, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH, version, blockContentHash, nonce));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}

