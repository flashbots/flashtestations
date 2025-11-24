// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {FlashtestationRegistry} from "./FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "./interfaces/IFlashtestationRegistry.sol";
import {IBlockBuilderPolicy, WorkloadId} from "./interfaces/IBlockBuilderPolicy.sol";

/**
 * @notice Cached workload information for gas optimization
 * @dev Stores computed workloadId and associated quoteHash to avoid expensive recomputation
 */
struct CachedWorkload {
    /// @notice The computed workload identifier
    WorkloadId workloadId;
    /// @notice The keccak256 hash of the raw quote used to compute this workloadId
    bytes32 quoteHash;
}

/**
 * @title V1BlockBuilderPolicy
 * @notice This is nearly identical to the latest version of the policy contract located at
 * src/BlockBuilderPolicy contract, except in the latest has had the logic around the xfam and tdattributes bit
 * masking removed. This was done because there was a bug in the bit masking logic, and we want to fix the bug
 * and simplify the contract by removing the bit masking logic
 *
 */
contract V1BlockBuilderPolicy is
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

    // ============ TDX workload constants ============

    /// @dev See section 11.5.3 in TDX Module v1.5 Base Architecture Specification https://www.intel.com/content/www/us/en/content-details/733575/intel-tdx-module-v1-5-base-architecture-specification.html
    /// @notice Enabled FPU (always enabled)
    bytes8 constant TD_XFAM_FPU = 0x0000000000000001;
    /// @notice Enabled SSE (always enabled)
    bytes8 constant TD_XFAM_SSE = 0x0000000000000002;

    /// @dev See section 3.4.1 in TDX Module ABI specification https://cdrdv2.intel.com/v1/dl/getContent/733579
    /// @notice Allows disabling of EPT violation conversion to #VE on access of PENDING pages. Needed for Linux
    bytes8 constant TD_TDATTRS_VE_DISABLED = 0x0000000010000000;
    /// @notice Enabled Supervisor Protection Keys (PKS)
    bytes8 constant TD_TDATTRS_PKS = 0x0000000040000000;
    /// @notice Enabled Key Locker (KL)
    bytes8 constant TD_TDATTRS_KL = 0x0000000080000000;

    // ============ Storage Variables ============

    /// @notice Mapping from workloadId to its metadata (commit hash and source locators)
    /// @dev This is only updateable by governance (i.e. the owner) of the Policy contract
    /// Adding and removing a workload is O(1).
    /// This means the critical `_cachedIsAllowedPolicy` function is O(1) since we can directly check if a workloadId exists
    /// in the mapping
    mapping(bytes32 workloadId => WorkloadMetadata) private approvedWorkloads;

    /// @inheritdoc IBlockBuilderPolicy
    address public registry;

    /// @inheritdoc IBlockBuilderPolicy
    mapping(address teeAddress => uint256 permitNonce) public nonces;

    /// @notice Cache of computed workloadIds to avoid expensive recomputation
    /// @dev Maps teeAddress to cached workload information for gas optimization
    mapping(address teeAddress => CachedWorkload) private cachedWorkloads;

    /// @dev Storage gap to allow for future storage variable additions in upgrades
    /// @dev This reserves 46 storage slots (out of 50 total - 4 used for approvedWorkloads, registry, nonces, and cachedWorkloads)
    uint256[46] __gap;

    /// @inheritdoc IBlockBuilderPolicy
    function initialize(address _initialOwner, address _registry) external override initializer {
        __Ownable_init(_initialOwner);
        __UUPSUpgradeable_init();
        __EIP712_init("BlockBuilderPolicy", "1");
        require(_registry != address(0), InvalidRegistry());

        registry = _registry;
        emit RegistrySet(_registry);
    }

    /// @notice Restricts upgrades to owner only
    /// @param newImplementation The address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

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

    /// @inheritdoc IBlockBuilderPolicy
    function isAllowedPolicy(address teeAddress) public view override returns (bool allowed, WorkloadId) {
        // Get full registration data and compute workload ID
        (, IFlashtestationRegistry.RegisteredTEE memory registration) =
            FlashtestationRegistry(registry).getRegistration(teeAddress);

        // Invalid Registrations means the attestation used to register the TEE is no longer valid
        // and so we cannot trust any input from the TEE
        if (!registration.isValid) {
            return (false, WorkloadId.wrap(0));
        }

        WorkloadId workloadId = workloadIdForTDRegistration(registration);

        // Check if the workload exists in our approved workloads mapping
        if (bytes(approvedWorkloads[WorkloadId.unwrap(workloadId)].commitHash).length > 0) {
            return (true, workloadId);
        }

        return (false, WorkloadId.wrap(0));
    }

    /// @notice isAllowedPolicy but with caching to reduce gas costs
    /// @dev This function is only used by the verifyBlockBuilderProof function, which needs to be as efficient as possible
    /// because it is called onchain for every flashblock. The workloadId is cached to avoid expensive recomputation
    /// @dev A careful reader will notice that this function does not delete stale cache entries. It overwrites them
    /// if the underlying TEE registration is still valid. But for stale cache entries in every other scenario, the
    /// cache entry persists indefinitely. This is because every other instance results in a return value of (false, 0)
    /// to the caller (which is always the verifyBlockBuilderProof function) and it immediately reverts. This is an unfortunate
    /// consequence of our need to make this function as gas-efficient as possible, otherwise we would try to cleanup
    /// stale cache entries
    /// @param teeAddress The TEE-controlled address
    /// @return True if the TEE is using an approved workload in the policy
    /// @return The workloadId of the TEE that is using an approved workload in the policy, or 0 if
    /// the TEE is not using an approved workload in the policy
    function _cachedIsAllowedPolicy(address teeAddress) private returns (bool, WorkloadId) {
        // Get the current registration status (fast path)
        (bool isValid, bytes32 quoteHash) = FlashtestationRegistry(registry).getRegistrationStatus(teeAddress);
        if (!isValid) {
            return (false, WorkloadId.wrap(0));
        }

        // Now, check if we have a cached workload for this TEE
        CachedWorkload memory cached = cachedWorkloads[teeAddress];

        // Check if we've already fetched and computed the workloadId for this TEE
        bytes32 cachedWorkloadId = WorkloadId.unwrap(cached.workloadId);
        if (cachedWorkloadId != 0 && cached.quoteHash == quoteHash) {
            // Cache hit - verify the workload is still a part of this policy's approved workloads
            if (bytes(approvedWorkloads[cachedWorkloadId].commitHash).length > 0) {
                return (true, cached.workloadId);
            } else {
                // The workload is no longer approved, so the policy is no longer valid for this TEE\
                return (false, WorkloadId.wrap(0));
            }
        } else {
            // Cache miss or quote changed - use the view function to get the result
            (bool allowed, WorkloadId workloadId) = isAllowedPolicy(teeAddress);

            if (allowed) {
                // Update cache with the new workload ID
                cachedWorkloads[teeAddress] = CachedWorkload({workloadId: workloadId, quoteHash: quoteHash});
            }

            return (allowed, workloadId);
        }
    }

    /// @inheritdoc IBlockBuilderPolicy
    function workloadIdForTDRegistration(IFlashtestationRegistry.RegisteredTEE memory registration)
        public
        pure
        override
        returns (WorkloadId)
    {
        // We expect FPU and SSE xfam bits to be set, and anything else should be handled by explicitly allowing the workloadid
        bytes8 expectedXfamBits = TD_XFAM_FPU | TD_XFAM_SSE;

        // We don't mind VE_DISABLED, PKS, and KL tdattributes bits being set either way, anything else requires explicitly allowing the workloadid
        bytes8 ignoredTdAttributesBitmask = TD_TDATTRS_VE_DISABLED | TD_TDATTRS_PKS | TD_TDATTRS_KL;

        return WorkloadId.wrap(
            keccak256(
                bytes.concat(
                    registration.parsedReportBody.mrTd,
                    registration.parsedReportBody.rtMr0,
                    registration.parsedReportBody.rtMr1,
                    registration.parsedReportBody.rtMr2,
                    registration.parsedReportBody.rtMr3,
                    // VMM configuration
                    registration.parsedReportBody.mrConfigId,
                    registration.parsedReportBody.xFAM ^ expectedXfamBits,
                    registration.parsedReportBody.tdAttributes & ~ignoredTdAttributesBitmask
                )
            )
        );
    }

    /// @inheritdoc IBlockBuilderPolicy
    function addWorkloadToPolicy(WorkloadId workloadId, string calldata commitHash, string[] calldata sourceLocators)
        external
        override
        onlyOwner
    {
        require(bytes(commitHash).length > 0, EmptyCommitHash());
        require(sourceLocators.length > 0, EmptySourceLocators());

        bytes32 workloadKey = WorkloadId.unwrap(workloadId);

        // Check if workload already exists
        require(bytes(approvedWorkloads[workloadKey].commitHash).length == 0, WorkloadAlreadyInPolicy());

        // Store the workload metadata
        approvedWorkloads[workloadKey] = WorkloadMetadata({commitHash: commitHash, sourceLocators: sourceLocators});

        emit WorkloadAddedToPolicy(workloadKey);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function removeWorkloadFromPolicy(WorkloadId workloadId) external override onlyOwner {
        bytes32 workloadKey = WorkloadId.unwrap(workloadId);

        // Check if workload exists
        require(bytes(approvedWorkloads[workloadKey].commitHash).length > 0, WorkloadNotInPolicy());

        // Remove the workload metadata
        delete approvedWorkloads[workloadKey];

        emit WorkloadRemovedFromPolicy(workloadKey);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function getWorkloadMetadata(WorkloadId workloadId) external view override returns (WorkloadMetadata memory) {
        return approvedWorkloads[WorkloadId.unwrap(workloadId)];
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
