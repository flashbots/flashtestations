// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {FlashtestationRegistry} from "./FlashtestationRegistry.sol";

// WorkloadID uniquely identifies a TEE workload. A workload is roughly equivalent to a version of an application's
// code, can be reproduced from source code, and is derived from a combination of the TEE's measurement registers.
// The TDX platform provides several registers that capture cryptographic hashes of code, data, and configuration
// loaded into the TEE's environment. This means that whenever a TEE device changes anything about its compute stack
// (e.g. user code, firmware, OS, etc), the workloadID will change.
// See the [Flashtestation's specification](https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md#workload-identity-derivation) for more details
type WorkloadId is bytes32;

/**
 * @notice Metadata associated with a workload
 * @dev Used to track the source code used to build the TEE image identified by the workloadId
 */
struct WorkloadMetadata {
    /// @notice The Git commit hash of the source code repository
    string commitHash;
    /// @notice An array of URLs pointing to the source code repository
    string[] sourceLocators;
}

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
contract BlockBuilderPolicy is Initializable, UUPSUpgradeable, OwnableUpgradeable, EIP712Upgradeable {
    using ECDSA for bytes32;

    // EIP-712 Constants
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

    // Storage Variables

    /// @notice Mapping from workloadId to its metadata (commit hash and source locators)
    /// @dev This is only updateable by governance (i.e. the owner) of the Policy contract
    /// Adding and removing a workload is O(1).
    /// This means the critical `isAllowedPolicy` function is O(1) since we can directly check if a workloadId exists
    /// in the mapping
    mapping(bytes32 => WorkloadMetadata) public approvedWorkloads;

    /// @notice Address of the FlashtestationRegistry contract that verifies TEE quotes
    address public registry;

    /// @notice Tracks nonces for EIP-712 signatures to prevent replay attacks
    mapping(address => uint256) public nonces;

    /// @notice Cache of computed workloadIds to avoid expensive recomputation
    /// @dev Maps teeAddress to cached workload information for gas optimization
    mapping(address => CachedWorkload) private cachedWorkloads;

    /// @dev Storage gap to allow for future storage variable additions in upgrades

    /// @dev This reserves 46 storage slots (out of 50 total - 4 used for approvedWorkloads, registry, nonces, and cachedWorkloads)
    uint256[46] __gap;

    // ============ Errors ============

    error InvalidRegistry();
    error WorkloadAlreadyInPolicy();
    error WorkloadNotInPolicy();
    error UnauthorizedBlockBuilder(address caller); // the teeAddress is not associated with a valid TEE workload
    error InvalidNonce(uint256 expected, uint256 provided);
    error EmptyCommitHash();
    error EmptySourceLocators();

    // ============ Events ============

    event WorkloadAddedToPolicy(WorkloadId workloadId);
    event WorkloadRemovedFromPolicy(WorkloadId workloadId);
    event RegistrySet(address registry);
    /// @notice Emitted when a block builder proof is successfully verified
    /// @param caller The address that called the verification function (TEE address)
    /// @param workloadId The workload identifier of the TEE
    /// @param blockNumber The block number when the verification occurred
    /// @param version The flashtestation protocol version used
    /// @param blockContentHash The hash of the block content
    /// @param commitHash The git commit hash associated with the workload
    event BlockBuilderProofVerified(
        address caller,
        WorkloadId workloadId,
        uint256 blockNumber,
        uint8 version,
        bytes32 blockContentHash,
        string commitHash
    );

    /**
     * @notice Initializer to set the FlashtestationRegistry contract which verifies TEE quotes and the initial owner of the contract
     * @param _initialOwner The address of the initial owner of the contract
     * @param _registry The address of the registry contract
     */
    function initialize(address _initialOwner, address _registry) external initializer {
        __Ownable_init(_initialOwner);
        __EIP712_init("BlockBuilderPolicy", "1");
        require(_registry != address(0), InvalidRegistry());

        registry = _registry;
        emit RegistrySet(_registry);
    }

    /// @notice Restricts upgrades to owner only
    /// @param newImplementation The address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Verify a block builder proof with a Flashtestation Transaction
    /// @param version The version of the flashtestation's protocol used to generate the block builder proof
    /// @param blockContentHash The hash of the block content
    /// @notice This function will only succeed if the caller is a registered TEE-controlled address from an attested TEE
    /// and the TEE is running an approved block builder workload (see `addWorkloadToPolicy`)
    /// @notice The blockContentHash is a keccak256 hash of a subset of the block header, as specified by the version.
    /// See the [flashtestations spec](https://github.com/flashbots/rollup-boost/blob/77fc19f785eeeb9b4eb5fb08463bc556dec2c837/specs/flashtestations.md) for more details
    /// @dev If you do not want to deal with the operational difficulties of keeping your TEE-controlled
    /// addresses funded, you can use the permitVerifyBlockBuilderProof function instead which costs
    /// more gas, but allows any EOA to submit a block builder proof on behalf of a TEE
    function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external {
        _verifyBlockBuilderProof(msg.sender, version, blockContentHash);
    }

    /// @notice Verify a block builder proof with a Flashtestation Transaction using EIP-712 signatures
    /// @param version The version of the flashtestation's protocol used to generate the block builder proof
    /// @param blockContentHash The hash of the block content
    /// @param nonce The nonce to use for the EIP-712 signature
    /// @param eip712Sig The EIP-712 signature of the verification message
    /// @notice This function allows any EOA to submit a block builder proof on behalf of a TEE
    /// @notice The TEE must sign a proper EIP-712-formatted message, and the signer must match a TEE-controlled address
    /// whose associated workload is approved under this policy
    /// @dev This function is useful if you do not want to deal with the operational difficulties of keeping your
    /// TEE-controlled addresses funded, but note that because of the larger number of function arguments, will cost
    /// more gas than the non-EIP-712 verifyBlockBuilderProof function
    function permitVerifyBlockBuilderProof(
        uint8 version,
        bytes32 blockContentHash,
        uint256 nonce,
        bytes calldata eip712Sig
    ) external {
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
    /// @param teeAddress The TEE-controlled address
    /// @param version The version of the flashtestation's protocol
    /// @param blockContentHash The hash of the block content
    /// @dev This function is internal because it is only used by the permitVerifyBlockBuilderProof function
    /// and it is not needed to be called by other contracts
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

        string memory commitHash = approvedWorkloads[WorkloadId.unwrap(workloadId)].commitHash;
        emit BlockBuilderProofVerified(teeAddress, workloadId, block.number, version, blockContentHash, commitHash);
    }

    /// @notice Check if this TEE-controlled address has registered a valid TEE workload with the registry, and
    /// if the workload is approved under this policy
    /// @param teeAddress The TEE-controlled address
    /// @return allowed True if the TEE is using an approved workload in the policy
    /// @return workloadId The workloadId of the TEE that is using an approved workload in the policy, or 0 if
    /// the TEE is not using an approved workload in the policy
    function isAllowedPolicy(address teeAddress) public view returns (bool allowed, WorkloadId) {
        // Get full registration data and compute workload ID
        (, FlashtestationRegistry.RegisteredTEE memory registration) =
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

    /// @notice Application specific mapping of registration data to a workload identifier
    /// @dev Think of the workload identifier as the version of the application for governance.
    /// The workloadId verifiably maps to a version of source code that builds the TEE VM image
    /// @param registration The registration data from a TEE device
    /// @return The computed workload identifier
    function workloadIdForTDRegistration(FlashtestationRegistry.RegisteredTEE memory registration)
        public
        pure
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

    /// @notice Add a workload to a policy (governance only)
    /// @param workloadId The workload identifier
    /// @param commitHash The 40-character hexadecimal commit hash of the git repository
    /// whose source code is used to build the TEE image identified by the workloadId
    /// @param sourceLocators An array of URIs pointing to the source code
    /// @notice Only the owner of this contract can add workloads to the policy
    /// and it is the responsibility of the owner to ensure that the workload is valid
    /// otherwise the address associated with this workload has full power to do anything
    /// who's authorization is based on this policy
    /// @dev The commitHash solves the following problem; The only way for a smart contract like BlockBuilderPolicy
    /// to verify that a TEE (identified by its workloadId) is running a specific piece of code (for instance,
    /// op-rbuilder) is to reproducibly build that workload onchain. This is prohibitively expensive, so instead
    /// we rely on a permissioned multisig (the owner of this contract) to add a commit hash to the policy whenever
    /// it adds a new workloadId. We're already relying on the owner to verify that the workloadId is valid, so
    /// we can also assume the owner will not add a commit hash that is not associated with the workloadId. If
    /// the owner did act maliciously, this can easily be determined offchain by an honest actor building the
    /// TEE image from the given commit hash, deriving the image's workloadId, and then comparing it to the
    /// workloadId stored on the policy that is associated with the commit hash. If the workloadId is different,
    /// this can be used to prove that the owner acted maliciously. In the honest case, this Policy serves as a
    /// source of truth for which source code of build software (i.e. the commit hash) is used to build the TEE image
    /// identified by the workloadId.
    function addWorkloadToPolicy(WorkloadId workloadId, string calldata commitHash, string[] calldata sourceLocators)
        external
        onlyOwner
    {
        require(bytes(commitHash).length > 0, EmptyCommitHash());
        require(sourceLocators.length > 0, EmptySourceLocators());

        bytes32 workloadKey = WorkloadId.unwrap(workloadId);

        // Check if workload already exists
        require(bytes(approvedWorkloads[workloadKey].commitHash).length == 0, WorkloadAlreadyInPolicy());

        // Store the workload metadata
        approvedWorkloads[workloadKey] = WorkloadMetadata({commitHash: commitHash, sourceLocators: sourceLocators});

        emit WorkloadAddedToPolicy(workloadId);
    }

    /// @notice Remove a workload from a policy (governance only)
    /// @param workloadId The workload identifier
    function removeWorkloadFromPolicy(WorkloadId workloadId) external onlyOwner {
        bytes32 workloadKey = WorkloadId.unwrap(workloadId);

        // Check if workload exists
        require(bytes(approvedWorkloads[workloadKey].commitHash).length > 0, WorkloadNotInPolicy());

        // Remove the workload metadata
        delete approvedWorkloads[workloadKey];

        emit WorkloadRemovedFromPolicy(workloadId);
    }

    /// @notice Get the metadata for a workload
    /// @param workloadId The workload identifier to query
    /// @return The metadata associated with the workload
    function getWorkloadMetadata(WorkloadId workloadId) external view returns (WorkloadMetadata memory) {
        return approvedWorkloads[WorkloadId.unwrap(workloadId)];
    }

    /// @notice Computes the digest for the EIP-712 signature
    /// @param structHash The struct hash for the EIP-712 signature
    /// @return The digest for the EIP-712 signature
    function getHashedTypeDataV4(bytes32 structHash) public view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    /// @notice Computes the struct hash for the EIP-712 signature
    /// @param version The version of the flashtestation's protocol
    /// @param blockContentHash The hash of the block content
    /// @param nonce The nonce to use for the EIP-712 signature
    /// @return The struct hash for the EIP-712 signature
    function computeStructHash(uint8 version, bytes32 blockContentHash, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH, version, blockContentHash, nonce));
    }
}
