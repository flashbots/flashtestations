// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {FlashtestationRegistry} from "./FlashtestationRegistry.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

// WorkloadID uniquely identifies a TEE workload. A workload is derived from a combination
// of the TEE's measurement registers. The TDX platform provides several registers that
// capture cryptographic hashes of code, data, and configuration loaded into the TEE's environment.
// This means that whenever a TEE device changes anything about its compute stack (e.g. user code,
// firmware, OS, etc), the workloadID will change.
// See the [Flashtestation's specification](https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md#workload-identity-derivation) for more details
type WorkloadId is bytes32;

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
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ECDSA for bytes32;

    // EIP-712 Constants
    bytes32 public constant VERIFY_BLOCK_BUILDER_PROOF_TYPEHASH =
        keccak256("VerifyBlockBuilderProof(uint8 version,bytes32 blockContentHash,uint256 nonce)");

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

    address public registry;

    // only v1 supported for now, but this will change with a contract upgrade
    // Note: we have to use a non-constant array because solidity only supports constant arrays
    // of value or bytes type. This means in future upgrades the upgrade logic will need to
    // account for adding new versions to the array
    uint256[] public SUPPORTED_VERSIONS;

    // Tracks nonces for EIP-712 signatures to prevent replay attacks
    mapping(address => uint256) public nonces;

    // Gap for future contract upgrades
    uint256[48] __gap;

    // Errors

    error WorkloadAlreadyInPolicy();
    error WorkloadNotInPolicy();
    error UnauthorizedBlockBuilder(address caller); // the teeAddress is not associated with a valid TEE workload
    error UnsupportedVersion(uint8 version); // see SUPPORTED_VERSIONS for supported versions
    error InvalidNonce(uint256 expected, uint256 provided);

    // Events

    event WorkloadAddedToPolicy(WorkloadId workloadId);
    event WorkloadRemovedFromPolicy(WorkloadId workloadId);
    event RegistrySet(address registry);
    event BlockBuilderProofVerified(
        address caller, WorkloadId workloadId, uint256 blockNumber, uint8 version, bytes32 blockContentHash
    );

    /**
     * Initializer to set the FlashtestationRegistry contract, which verifies TEE quotes
     * @param _initialOwner The address of the initial owner of the contract
     * @param _registry The address of the registry contract
     */
    function initialize(address _initialOwner, address _registry) external initializer {
        __Ownable_init(_initialOwner);
        __EIP712_init("BlockBuilderPolicy", "1");
        registry = _registry;
        SUPPORTED_VERSIONS.push(1);
        emit RegistrySet(_registry);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Verify a block builder proof
    /// @param version The version of the flashtestation's protocol used to generate the block builder proof
    /// @param blockContentHash The hash of the block content
    /// @notice This function will only succeed if the caller is a registered TEE-controlled address from an attested TEE
    /// and the TEE is running an approved block builder workload (see BlockBuilderPolicy.addWorkloadToPolicy)
    /// @notice The blockContentHash is a keccak256 hash of a subset of the block header, as specified by the version.
    /// See the [flashtestations spec](https://github.com/flashbots/rollup-boost/blob/77fc19f785eeeb9b4eb5fb08463bc556dec2c837/specs/flashtestations.md) for more details
    /// @dev If you do not want to deal with the operational difficulties of keeping your TEE-controlled
    /// addresses funded, you can use the permitVerifyBlockBuilderProof function instead which costs
    /// more gas, but allows any EOA to submit a block builder proof on behalf of a TEE
    function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external {
        _verifyBlockBuilderProof(msg.sender, version, blockContentHash);
    }

    /// @notice Verify a block builder proof using EIP-712 signatures
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
        require(isSupportedVersion(version), UnsupportedVersion(version));

        // Check if the caller is an authorized TEE block builder for our Policy
        (bool allowed, WorkloadId workloadId) = isAllowedPolicy(teeAddress);
        require(allowed, UnauthorizedBlockBuilder(teeAddress));

        // At this point, we know:
        // 1. The caller is a registered TEE-controlled address from an attested TEE
        // 2. The TEE is running an approved block builder workload (via policy)

        // Note: Due to EVM limitations (no retrospection), we cannot validate the blockContentHash
        // onchain. We rely on the TEE workload to correctly compute this hash according to the
        // specified version of the calculation method.

        emit BlockBuilderProofVerified(teeAddress, workloadId, block.number, version, blockContentHash);
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
    /// @return workloadId The workloadId of the TEE that is valid for the policy, or 0 if the TEE is not valid for any workload in the policy
    function isAllowedPolicy(address teeAddress) public view returns (bool allowed, WorkloadId) {
        (bool isValid, FlashtestationRegistry.RegisteredTEE memory registration) =
            FlashtestationRegistry(registry).getRegistration(teeAddress);
        if (!isValid) {
            return (false, WorkloadId.wrap(0));
        }
        WorkloadId workloadId = workloadIdFromRegistration(registration);

        for (uint256 i = 0; i < workloadIds.length(); ++i) {
            if (workloadId == WorkloadId.wrap(workloadIds.at(i))) {
                return (true, workloadId);
            }
        }
        return (false, WorkloadId.wrap(0));
    }

    // Application specific mapping of registration data, in particular the quote and attested app data, to a workload identifier
    function workloadIdFromRegistration(FlashtestationRegistry.RegisteredTEE memory registration)
        internal
        pure
        returns (WorkloadId)
    {
        return WorkloadId.wrap(
            keccak256(
                abi.encode(
                    registration.parsedReportBody.mrTd,
                    registration.parsedReportBody.rtMr0,
                    registration.parsedReportBody.rtMr1,
                    registration.parsedReportBody.rtMr2,
                    registration.parsedReportBody.rtMr3,
                    registration.parsedReportBody.mrOwner,
                    registration.parsedReportBody.mrOwnerConfig,
                    registration.parsedReportBody.mrConfigId,
                    registration.parsedReportBody.tdAttributes,
                    registration.parsedReportBody.xFAM
                )
            )
        );
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
        (bool isValid, FlashtestationRegistry.RegisteredTEE registration) =
            FlashtestationRegistry(registry).getRegistration(teeAddress);
        if (!isValid) {
            return (false, WorkloadId.wrap(0));
        }
        WorkloadId workloadId = workloadIdFromRegistration(registration);

        for (uint256 i = 0; i < workloadIds.length(); ++i) {
            if (workloadId == WorkloadId.wrap(workloadIds.at(i))) {
                TD10ReportBody memory reportBody = FlashtestationRegistry(registry).getReportBody(teeAddress);
                if (reportBody.teeTcbSvn == expectedTeeTcbSvn) {
                    return true;
                }
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
