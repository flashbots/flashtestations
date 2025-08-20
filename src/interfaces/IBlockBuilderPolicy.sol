// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IFlashtestationRegistry} from "./IFlashtestationRegistry.sol";

/// @notice WorkloadID uniquely identifies a TEE workload. A workload is roughly equivalent to a version of an application's
/// code, can be reproduced from source code, and is derived from a combination of the TEE's measurement registers.
/// The TDX platform provides several registers that capture cryptographic hashes of code, data, and configuration
/// loaded into the TEE's environment. This means that whenever a TEE device changes anything about its compute stack
/// (e.g. user code, firmware, OS, etc), the workloadID will change.
/// See the [Flashtestation's specification](https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md#workload-identity-derivation) for more details
type WorkloadId is bytes32;

/**
 * @title IBlockBuilderPolicy
 * @dev Interface exposing errors, events, and external/public functions of BlockBuilderPolicy
 */
interface IBlockBuilderPolicy {
    // ============ Types ============

    /**
     * @notice Metadata associated with a workload
     * @dev Used to track the source code used to build the TEE image identified by the workloadId
     */
    struct WorkloadMetadata {
        string commitHash;
        string[] sourceLocators;
    }

    // ============ Events ============

    /// @notice Emitted when a workload is added to the policy
    /// @param workloadId The workload identifier
    event WorkloadAddedToPolicy(bytes32 workloadId);
    /// @notice Emitted when a workload is removed from the policy
    /// @param workloadId The workload identifier
    event WorkloadRemovedFromPolicy(bytes32 workloadId);
    /// @notice Emitted when the registry is set in the initializer
    /// @param registry The address of the registry
    event RegistrySet(address registry);
    /// @notice Emitted when a block builder proof is successfully verified
    /// @param caller The address that called the verification function (TEE address)
    /// @param workloadId The workload identifier of the TEE
    /// @param version The flashtestation protocol version used
    /// @param blockContentHash The hash of the block content
    /// @param commitHash The git commit hash associated with the workload
    event BlockBuilderProofVerified(
        address caller, bytes32 workloadId, uint8 version, bytes32 blockContentHash, string commitHash
    );

    // ============ Errors ============

    /// @notice Emitted when the registry is the 0x0 address
    error InvalidRegistry();
    /// @notice Emitted when a workload to be added is already in the policy
    error WorkloadAlreadyInPolicy();
    /// @notice Emitted when a workload to be removed is not in the policy
    error WorkloadNotInPolicy();
    /// @notice Emitted when the address is not in the approvedWorkloads mapping
    error UnauthorizedBlockBuilder(address caller);
    /// @notice Emitted when the nonce is invalid
    error InvalidNonce(uint256 expected, uint256 provided);
    /// @notice Emitted when the commit hash is empty
    error EmptyCommitHash();
    /// @notice Emitted when the source locators array is empty
    error EmptySourceLocators();

    // ============ Functions ============

    /// @notice Initializer to set the FlashtestationRegistry contract which verifies TEE quotes and the initial owner of the contract
    /// @param _initialOwner The address of the initial owner of the contract
    /// @param _registry The address of the registry contract
    function initialize(address _initialOwner, address _registry) external;

    /// @notice Verify a block builder proof with a Flashtestation Transaction
    /// @param version The version of the flashtestation's protocol used to generate the block builder proof
    /// @param blockContentHash The hash of the block content
    /// @notice This function will only succeed if the caller is a registered TEE-controlled address from an attested TEE
    /// and the TEE is running an approved block builder workload (see `addWorkloadToPolicy`)
    /// @notice The blockContentHash is a keccak256 hash of a subset of the block header, as specified by the version.
    /// See the [flashtestations spec](https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md) for more details
    /// @dev If you do not want to deal with the operational difficulties of keeping your TEE-controlled
    /// addresses funded, you can use the permitVerifyBlockBuilderProof function instead which costs
    /// more gas, but allows any EOA to submit a block builder proof on behalf of a TEE
    function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external;

    /// @notice Verify a block builder proof with a Flashtestation Transaction using EIP-712 signatures
    /// @notice This function allows any EOA to submit a block builder proof on behalf of a TEE
    /// @notice The TEE must sign a proper EIP-712-formatted message, and the signer must match a TEE-controlled address
    /// whose associated workload is approved under this policy
    /// @dev This function is useful if you do not want to deal with the operational difficulties of keeping your
    /// TEE-controlled addresses funded, but note that because of the larger number of function arguments, will cost
    /// more gas than the non-EIP-712 verifyBlockBuilderProof function
    /// @param version The version of the flashtestation's protocol used to generate the block builder proof
    /// @param blockContentHash The hash of the block content
    /// @param nonce The nonce to use for the EIP-712 signature
    /// @param eip712Sig The EIP-712 signature of the verification message
    function permitVerifyBlockBuilderProof(
        uint8 version,
        bytes32 blockContentHash,
        uint256 nonce,
        bytes calldata eip712Sig
    ) external;

    /// @notice Check if this TEE-controlled address has registered a valid TEE workload with the registry, and
    /// if the workload is approved under this policy
    /// @param teeAddress The TEE-controlled address
    /// @return allowed True if the TEE is using an approved workload in the policy
    /// @return workloadId The workloadId of the TEE that is using an approved workload in the policy, or 0 if
    /// the TEE is not using an approved workload in the policy
    function isAllowedPolicy(address teeAddress) external view returns (bool, WorkloadId workloadId);

    /// @notice Application specific mapping of registration data to a workload identifier
    /// @dev Think of the workload identifier as the version of the application for governance.
    /// The workloadId verifiably maps to a version of source code that builds the TEE VM image
    /// @param registration The registration data from a TEE device
    /// @return workloadId The computed workload identifier
    function workloadIdForTDRegistration(IFlashtestationRegistry.RegisteredTEE memory registration)
        external
        pure
        returns (WorkloadId);

    /// @notice Add a workload to a policy (governance only)
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
    /// @param workloadId The workload identifier
    /// @param commitHash The 40-character hexadecimal commit hash of the git repository
    /// whose source code is used to build the TEE image identified by the workloadId
    /// @param sourceLocators An array of URIs pointing to the source code
    function addWorkloadToPolicy(WorkloadId workloadId, string calldata commitHash, string[] calldata sourceLocators)
        external;

    /// @notice Remove a workload from a policy (governance only)
    /// @param workloadId The workload identifier
    function removeWorkloadFromPolicy(WorkloadId workloadId) external;

    /// @notice Get the metadata for a workload
    /// @param workloadId The workload identifier to query
    /// @return The metadata associated with the workload
    function getWorkloadMetadata(WorkloadId workloadId) external view returns (WorkloadMetadata memory);

    /// @notice Computes the digest for the EIP-712 signature
    /// @param structHash The struct hash for the EIP-712 signature
    /// @return The digest for the EIP-712 signature
    function getHashedTypeDataV4(bytes32 structHash) external view returns (bytes32);

    /// @notice Computes the struct hash for the EIP-712 signature
    /// @param version The version of the flashtestation's protocol
    /// @param blockContentHash The hash of the block content
    /// @param nonce The nonce to use for the EIP-712 signature
    /// @return The struct hash for the EIP-712 signature
    function computeStructHash(uint8 version, bytes32 blockContentHash, uint256 nonce)
        external
        pure
        returns (bytes32);

    /// @notice Returns the domain separator for the EIP-712 signature
    /// @dev This is useful for when both onchain and offchain users want to compute the domain separator
    /// for the EIP-712 signature, and then use it to verify the signature
    /// @return The domain separator for the EIP-712 signature
    function domainSeparator() external view returns (bytes32);

    // ============ Auto-generated getters for public state ============

    /// @notice Mapping from workloadId to its metadata (commit hash and source locators)
    /// @dev This is only updateable by governance (i.e. the owner) of the Policy contract
    /// Adding and removing a workload is O(1).
    /// This means the critical `_cachedIsAllowedPolicy` function is O(1) since we can directly check if a workloadId exists
    /// in the mapping
    function getApprovedWorkloads(bytes32 workloadId)
        external
        view
        returns (string memory commitHash, string[] memory sourceLocators);

    /// @notice Address of the FlashtestationRegistry contract that verifies TEE quotes
    function registry() external view returns (address);

    /// @notice Tracks nonces for EIP-712 signatures to prevent replay attacks
    function nonces(address teeAddress) external view returns (uint256);

    /// @notice EIP-712 Typehash, used in the permitVerifyBlockBuilderProof function
    function VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH() external view returns (bytes32);
}
