// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IFlashtestationRegistry} from "./IFlashtestationRegistry.sol";
import {IBasePolicy} from "./IBasePolicy.sol";
import {WorkloadId} from "./IPolicyCommon.sol";

/**
 * @title IBlockBuilderPolicy
 * @dev Interface exposing errors, events, and external/public functions of BlockBuilderPolicy
 */
interface IBlockBuilderPolicy is IBasePolicy {
    // ============ Events ============

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
    /// @notice Emitted when the address is not in the approvedWorkloads mapping
    error UnauthorizedBlockBuilder(address caller);
    /// @notice Emitted when the nonce is invalid
    error InvalidNonce(uint256 expected, uint256 provided);

    // ============ Functions ============

    /// @notice Initializer to set the FlashtestationRegistry contract which verifies TEE quotes and the initial owner of the contract
    /// @param _initialOwner The address of the initial owner of the contract
    /// @param _registry The address of the registry contract
    /// @param _workloadDeriver Address of the workload deriver used for workloadId computation
    function initialize(address _initialOwner, address _registry, address _workloadDeriver) external;

    /// @notice Set the workload deriver (governance only).
    /// @dev Useful for proxy upgrade flows introducing the deriver variable.
    function setWorkloadDeriver(address _workloadDeriver) external;

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

    /// @notice Application specific mapping of registration data to a workload identifier
    /// @dev Think of the workload identifier as the version of the application for governance.
    /// The workloadId verifiably maps to a version of source code that builds the TEE VM image
    /// @param registration The registration data from a TEE device
    /// @return workloadId The computed workload identifier
    function workloadIdForTDRegistration(IFlashtestationRegistry.RegisteredTEE memory registration)
        external
        view
        returns (WorkloadId);

    /// @notice Computes the digest for the EIP-712 signature
    /// @param structHash The struct hash for the EIP-712 signature
    /// @return The digest for the EIP-712 signature
    function getHashedTypeDataV4(bytes32 structHash) external view returns (bytes32);

    /// @notice Computes the struct hash for the EIP-712 signature
    /// @param version The version of the flashtestation's protocol
    /// @param blockContentHash The hash of the block content
    /// @param nonce The nonce to use for the EIP-712 signature
    /// @return The struct hash for the EIP-712 signature
    function computeStructHash(uint8 version, bytes32 blockContentHash, uint256 nonce) external pure returns (bytes32);

    /// @notice Returns the domain separator for the EIP-712 signature
    /// @dev This is useful for when both onchain and offchain users want to compute the domain separator
    /// for the EIP-712 signature, and then use it to verify the signature
    /// @return The domain separator for the EIP-712 signature
    function domainSeparator() external view returns (bytes32);

    // ============ Auto-generated getters for public state ============

    /// @notice Tracks nonces for EIP-712 signatures to prevent replay attacks
    function nonces(address teeAddress) external view returns (uint256);

    /// @notice EIP-712 Typehash, used in the permitVerifyBlockBuilderProof function
    function VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH() external view returns (bytes32);
}
