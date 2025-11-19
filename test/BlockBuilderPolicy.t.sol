// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";
import {IBlockBuilderPolicy, WorkloadId} from "../src/interfaces/IBlockBuilderPolicy.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";
import {Upgrader} from "./helpers/Upgrader.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {Helper} from "./helpers/Helper.sol";

contract BlockBuilderPolicyTest is Test {
    // Helper function to create dynamic string arrays
    function createStringArray(string memory a, string memory b) internal pure returns (string[] memory) {
        string[] memory arr = new string[](2);
        arr[0] = a;
        arr[1] = b;
        return arr;
    }

    FlashtestationRegistry public registry;
    MockAutomataDcapAttestationFee public attestationContract;
    BlockBuilderPolicy public policy;
    Upgrader public upgrader = new Upgrader();
    address public owner = address(this);

    uint8 version = 1;

    // Extended MockQuote struct with workloadId for policy tests
    struct PolicyMockQuote {
        bytes output;
        bytes quote;
        address teeAddress;
        WorkloadId workloadId;
        uint256 privateKey;
        string commitHash;
        string[] sourceLocators;
    }

    PolicyMockQuote mockf200 = PolicyMockQuote({
        output: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/quote.bin"),
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000, // unused for this mock
        commitHash: "1234567890abcdef1234567890abcdef12345678",
        sourceLocators: createStringArray(
            "https://github.com/flashbots/flashbots-images/commit/a5aa6c75fbecc4b88faf4886cbd3cb2c667f4a8c",
            "https://ipfs.io/ipfs/bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly"
        )
    });
    PolicyMockQuote mockf200WithDifferentWorkloadId = PolicyMockQuote({ // TODO!
        output: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/output2.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03/quote2.bin"),
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        workloadId: WorkloadId.wrap(0x5e6be81f9e5b10d15a6fa69b19ab0269cd943db39fa1f0d38a76eb76146948cb),
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000, // unused for this mock
        commitHash: "1234567890abcdef1234567890abcdef12345678",
        sourceLocators: createStringArray(
            "https://github.com/flashbots/flashbots-images/commit/a5aa6c75fbecc4b88faf4886cbd3cb2c667f4a8c",
            "https://ipfs.io/ipfs/bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly"
        )
    });
    PolicyMockQuote mock12c1 = PolicyMockQuote({
        output: vm.readFileBinary("test/raw_tdx_quotes/0x12c14e56d585Dcf3B36f37476c00E78bA9363742/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0x12c14e56d585Dcf3B36f37476c00E78bA9363742/quote.bin"),
        teeAddress: 0x12c14e56d585Dcf3B36f37476c00E78bA9363742,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000, // unused for this mock
        commitHash: "1234567890abcdef1234567890abcdef12345678",
        sourceLocators: createStringArray(
            "https://github.com/flashbots/flashbots-images/commit/a5aa6c75fbecc4b88faf4886cbd3cb2c667f4a8c",
            "https://ipfs.io/ipfs/bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly"
        )
    });
    PolicyMockQuote mock46f6 = PolicyMockQuote({
        output: vm.readFileBinary("test/raw_tdx_quotes/0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF/quote.bin"),
        teeAddress: 0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
        privateKey: 0x92e4b5ed61db615b26da2271da5b47c42d691b3164561cfb4edbc85ca6ca61a8,
        commitHash: "1234567890abcdef1234567890abcdef12345678",
        sourceLocators: createStringArray(
            "https://github.com/flashbots/flashbots-images/commit/a5aa6c75fbecc4b88faf4886cbd3cb2c667f4a8c",
            "https://ipfs.io/ipfs/bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly"
        )
    });

    WorkloadId arbitraryWorkloadId =
        WorkloadId.wrap(0x1dd337a1486a84a7d4200553584996abec87a87473d445262d5562f84ec456a8);
    WorkloadId wrongWorkloadId = WorkloadId.wrap(0x20ab431377d40de192f7c754ac0f1922de05ab2f73e74204f0b3ab73a8856876);

    using ECDSA for bytes32;

    function setUp() public {
        attestationContract = new MockAutomataDcapAttestationFee();
        address registryImplementation = address(new FlashtestationRegistry());
        address registryProxy = UnsafeUpgrades.deployUUPSProxy(
            registryImplementation,
            abi.encodeCall(FlashtestationRegistry.initialize, (owner, address(attestationContract)))
        );
        registry = FlashtestationRegistry(registryProxy);
        address policyImplementation = address(new BlockBuilderPolicy());
        address policyProxy = UnsafeUpgrades.deployUUPSProxy(
            policyImplementation, abi.encodeCall(BlockBuilderPolicy.initialize, (owner, address(registry)))
        );
        policy = BlockBuilderPolicy(policyProxy);
    }

    function _registerTEE(PolicyMockQuote memory mock) internal {
        attestationContract.setQuoteResult(mock.quote, true, mock.output);
        vm.prank(mock.teeAddress);
        registry.registerTEEService(mock.quote, bytes("")); // Add empty extended data
    }

    function test_initialize_reverts_if_invalid_owner() public {
        attestationContract = new MockAutomataDcapAttestationFee();
        address registryImplementation = address(new FlashtestationRegistry());
        address registryProxy = UnsafeUpgrades.deployUUPSProxy(
            registryImplementation,
            abi.encodeCall(FlashtestationRegistry.initialize, (owner, address(attestationContract)))
        );
        registry = FlashtestationRegistry(registryProxy);
        address policyImplementation = address(new BlockBuilderPolicy());

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableInvalidOwner.selector, address(0x0)));
        UnsafeUpgrades.deployUUPSProxy(
            policyImplementation, abi.encodeCall(BlockBuilderPolicy.initialize, (address(0), address(registry)))
        );
    }

    function test_initialize_reverts_if_invalid_registry() public {
        attestationContract = new MockAutomataDcapAttestationFee();
        address registryImplementation = address(new FlashtestationRegistry());
        address registryProxy = UnsafeUpgrades.deployUUPSProxy(
            registryImplementation,
            abi.encodeCall(FlashtestationRegistry.initialize, (owner, address(attestationContract)))
        );
        registry = FlashtestationRegistry(registryProxy);
        address policyImplementation = address(new BlockBuilderPolicy());

        vm.expectRevert(abi.encodeWithSelector(IBlockBuilderPolicy.InvalidRegistry.selector));
        UnsafeUpgrades.deployUUPSProxy(
            policyImplementation, abi.encodeCall(BlockBuilderPolicy.initialize, (owner, address(0)))
        );
    }

    function test_addWorkloadToPolicy_and_getter_for_workload_metadata() public {
        // Add a workload
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);

        IBlockBuilderPolicy.WorkloadMetadata memory workload = policy.getWorkloadMetadata(mockf200.workloadId);
        assertEq(workload.commitHash, mockf200.commitHash);
        assertEq(workload.sourceLocators.length, 2);
        assertEq(workload.sourceLocators[0], mockf200.sourceLocators[0]);
        assertEq(workload.sourceLocators[1], mockf200.sourceLocators[1]);
    }

    function test_addWorkloadToPolicy_with_multiple_workloads() public {
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
        policy.addWorkloadToPolicy(
            mockf200WithDifferentWorkloadId.workloadId,
            mockf200WithDifferentWorkloadId.commitHash,
            mockf200WithDifferentWorkloadId.sourceLocators
        );

        IBlockBuilderPolicy.WorkloadMetadata memory workload = policy.getWorkloadMetadata(mockf200.workloadId);
        assertEq(workload.commitHash, mockf200.commitHash);
        assertEq(workload.sourceLocators.length, 2);
        assertEq(workload.sourceLocators[0], mockf200.sourceLocators[0]);
        assertEq(workload.sourceLocators[1], mockf200.sourceLocators[1]);

        workload = policy.getWorkloadMetadata(mockf200WithDifferentWorkloadId.workloadId);
        assertEq(workload.commitHash, mockf200WithDifferentWorkloadId.commitHash);
        assertEq(workload.sourceLocators.length, 2);
        assertEq(workload.sourceLocators[0], mockf200WithDifferentWorkloadId.sourceLocators[0]);
        assertEq(workload.sourceLocators[1], mockf200WithDifferentWorkloadId.sourceLocators[1]);
    }

    function test_addWorkloadToPolicy_reverts_if_duplicate() public {
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
        vm.expectRevert(IBlockBuilderPolicy.WorkloadAlreadyInPolicy.selector);
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
    }

    function test_addWorkloadToPolicy_reverts_if_empty_commit_hash() public {
        vm.expectRevert(abi.encodeWithSelector(IBlockBuilderPolicy.EmptyCommitHash.selector, 0));
        policy.addWorkloadToPolicy(mockf200.workloadId, "", mockf200.sourceLocators);
    }

    function test_addWorkloadToPolicy_reverts_if_empty_source_locators() public {
        vm.expectRevert(abi.encodeWithSelector(IBlockBuilderPolicy.EmptySourceLocators.selector, 0));
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, new string[](0));
    }

    function test_addWorkloadToPolicy_reverts_if_not_owner() public {
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)));
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
    }

    function test_removeWorkloadFromPolicy() public {
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
        policy.removeWorkloadFromPolicy(mockf200.workloadId);
        IBlockBuilderPolicy.WorkloadMetadata memory workload = policy.getWorkloadMetadata(mockf200.workloadId);
        assertEq(workload.commitHash, "");
        assertEq(workload.sourceLocators.length, 0);
    }

    function test_removeWorkloadFromPolicy_with_multiple_workloads() public {
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
        policy.addWorkloadToPolicy(
            mockf200WithDifferentWorkloadId.workloadId,
            mockf200WithDifferentWorkloadId.commitHash,
            mockf200WithDifferentWorkloadId.sourceLocators
        );
        policy.removeWorkloadFromPolicy(mockf200.workloadId);
        IBlockBuilderPolicy.WorkloadMetadata memory workload =
            policy.getWorkloadMetadata(mockf200WithDifferentWorkloadId.workloadId);
        assertEq(workload.commitHash, mockf200WithDifferentWorkloadId.commitHash);
        assertEq(workload.sourceLocators.length, 2);
        assertEq(workload.sourceLocators[0], mockf200WithDifferentWorkloadId.sourceLocators[0]);
        assertEq(workload.sourceLocators[1], mockf200WithDifferentWorkloadId.sourceLocators[1]);

        workload = policy.getWorkloadMetadata(mockf200.workloadId);
        assertEq(workload.commitHash, "");
        assertEq(workload.sourceLocators.length, 0);

        // now remove the other workload
        policy.removeWorkloadFromPolicy(mockf200WithDifferentWorkloadId.workloadId);
        workload = policy.getWorkloadMetadata(mockf200WithDifferentWorkloadId.workloadId);
        assertEq(workload.commitHash, "");
        assertEq(workload.sourceLocators.length, 0);

        // now add the workloads back
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
        workload = policy.getWorkloadMetadata(mockf200.workloadId);
        assertEq(workload.commitHash, mockf200.commitHash);
        assertEq(workload.sourceLocators.length, 2);
        assertEq(workload.sourceLocators[0], mockf200.sourceLocators[0]);
        assertEq(workload.sourceLocators[1], mockf200.sourceLocators[1]);
        policy.addWorkloadToPolicy(
            mockf200WithDifferentWorkloadId.workloadId,
            mockf200WithDifferentWorkloadId.commitHash,
            mockf200WithDifferentWorkloadId.sourceLocators
        );
        workload = policy.getWorkloadMetadata(mockf200WithDifferentWorkloadId.workloadId);
        assertEq(workload.commitHash, mockf200WithDifferentWorkloadId.commitHash);
        assertEq(workload.sourceLocators.length, 2);
        assertEq(workload.sourceLocators[0], mockf200WithDifferentWorkloadId.sourceLocators[0]);
        assertEq(workload.sourceLocators[1], mockf200WithDifferentWorkloadId.sourceLocators[1]);
    }

    function test_removeWorkloadFromPolicy_reverts_if_not_present() public {
        vm.expectRevert(IBlockBuilderPolicy.WorkloadNotInPolicy.selector);
        policy.removeWorkloadFromPolicy(mockf200.workloadId);
    }

    function test_removeWorkloadFromPolicy_reverts_if_not_owner() public {
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)));
        policy.removeWorkloadFromPolicy(mockf200.workloadId);
    }

    function test_isAllowedPolicy_returns_true_for_valid_tee() public {
        // Register TEE and add workload to policy
        _registerTEE(mockf200);

        // Get the actual workloadId from the registration
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(mockf200.teeAddress);
        WorkloadId actualWorkloadId = policy.workloadIdForTDRegistration(registration);

        // Add the actual workloadId to the policy
        policy.addWorkloadToPolicy(actualWorkloadId, mockf200.commitHash, mockf200.sourceLocators);

        // Should return true
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(mockf200.teeAddress);
        assertTrue(allowed);
        assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(actualWorkloadId));
    }

    function test_isAllowedPolicy_returns_false_for_unregistered_tee() public {
        // Add workload but do not register TEE
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(mockf200.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_isAllowedPolicy_returns_false_for_invalid_quote() public {
        // Register TEE
        _registerTEE(mockf200);

        // Get the actual workloadId and add to policy
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(mockf200.teeAddress);
        WorkloadId actualWorkloadId = policy.workloadIdForTDRegistration(registration);
        policy.addWorkloadToPolicy(actualWorkloadId, mockf200.commitHash, mockf200.sourceLocators);

        // Now invalidate the TEE
        attestationContract.setQuoteResult(mockf200.quote, false, new bytes(0));
        registry.invalidateAttestation(mockf200.teeAddress);

        // Should return false
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(mockf200.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_isAllowedPolicy_returns_false_for_wrong_workload() public {
        _registerTEE(mockf200);
        policy.addWorkloadToPolicy(wrongWorkloadId, mockf200.commitHash, mockf200.sourceLocators);
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(mockf200.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_isAllowedPolicy_returns_false_for_invalid_tee_when_multiple_workloads_present() public {
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);
        policy.addWorkloadToPolicy(wrongWorkloadId, mockf200.commitHash, mockf200.sourceLocators);
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(mockf200.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_workloadIdForTDRegistration() public {
        // Register a TEE
        _registerTEE(mockf200);

        // Get the registration
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(mockf200.teeAddress);

        // Compute the workloadId
        WorkloadId computedWorkloadId = policy.workloadIdForTDRegistration(registration);

        // The computed workloadId should be deterministic based on the TD report fields
        assertTrue(WorkloadId.unwrap(computedWorkloadId) != 0, "WorkloadId should not be zero");
    }

    function test_workloadIdForTDRegistration_is_deterministic() public {
        // Register a TEE
        _registerTEE(mockf200);
        _registerTEE(mock12c1);

        // Get the registration
        (, IFlashtestationRegistry.RegisteredTEE memory registrationF200) =
            registry.getRegistration(mockf200.teeAddress);
        (, IFlashtestationRegistry.RegisteredTEE memory registration12c1) =
            registry.getRegistration(mock12c1.teeAddress);

        // Compute the workloadId
        WorkloadId computedWorkloadIdF200 = policy.workloadIdForTDRegistration(registrationF200);
        WorkloadId computedWorkloadId12c1 = policy.workloadIdForTDRegistration(registration12c1);

        // Same measurements, different addresses and ext data. workloadId should match.
        assertEq(WorkloadId.unwrap(computedWorkloadIdF200), WorkloadId.unwrap(computedWorkloadId12c1));
    }

    // Add these test functions to BlockBuilderPolicyTest contract

    function test_workloadId_tdAttributes_allowed_bits_ignored() public {
        // Register a TEE to get a baseline
        _registerTEE(mockf200);
        (, IFlashtestationRegistry.RegisteredTEE memory baseRegistration) =
            registry.getRegistration(mockf200.teeAddress);
        WorkloadId baseWorkloadId = policy.workloadIdForTDRegistration(baseRegistration);

        // Test that all combinations of allowed bits don't affect workloadId
        // We test: none set, all set, and one intermediate case
        bytes8[3] memory allowedBitCombos = [
            bytes8(0x00000000D0000000), // All three allowed bits set (VE_DISABLED | PKS | KL)
            bytes8(0x0000000050000000), // VE_DISABLED | PKS
            bytes8(0x0000000000000000) // None set
        ];

        for (uint256 i = 0; i < allowedBitCombos.length; i++) {
            IFlashtestationRegistry.RegisteredTEE memory modifiedRegAllowed = baseRegistration;
            // Clear the allowed bits first, then set the specific combination
            modifiedRegAllowed.parsedReportBody.tdAttributes =
                (baseRegistration.parsedReportBody.tdAttributes & ~bytes8(0x00000000D0000000)) | allowedBitCombos[i];

            WorkloadId workloadId = policy.workloadIdForTDRegistration(modifiedRegAllowed);
            assertEq(
                WorkloadId.unwrap(baseWorkloadId),
                WorkloadId.unwrap(workloadId),
                "Allowed tdAttributes bits should not affect workloadId"
            );
        }

        // Test that a non-allowed bit DOES change workloadId
        IFlashtestationRegistry.RegisteredTEE memory modifiedReg = baseRegistration;
        modifiedReg.parsedReportBody.tdAttributes =
            baseRegistration.parsedReportBody.tdAttributes | bytes8(0x0000000000000001);
        WorkloadId differentWorkloadId = policy.workloadIdForTDRegistration(modifiedReg);
        assertNotEq(
            WorkloadId.unwrap(baseWorkloadId),
            WorkloadId.unwrap(differentWorkloadId),
            "Non-allowed tdAttributes bits should affect workloadId"
        );
    }

    function test_workloadId_xfam_expected_bits_required() public {
        // Register a TEE to get a baseline
        _registerTEE(mockf200);
        (, IFlashtestationRegistry.RegisteredTEE memory baseRegistration) =
            registry.getRegistration(mockf200.teeAddress);
        WorkloadId baseWorkloadId = policy.workloadIdForTDRegistration(baseRegistration);

        // Test removing FPU bit changes workloadId
        IFlashtestationRegistry.RegisteredTEE memory modifiedReg1 = baseRegistration;
        modifiedReg1.parsedReportBody.xFAM = baseRegistration.parsedReportBody.xFAM ^ bytes8(0x0000000000000001);
        WorkloadId workloadIdNoFPU = policy.workloadIdForTDRegistration(modifiedReg1);
        assertNotEq(
            WorkloadId.unwrap(baseWorkloadId),
            WorkloadId.unwrap(workloadIdNoFPU),
            "Missing FPU bit should change workloadId"
        );

        // Test removing SSE bit changes workloadId
        IFlashtestationRegistry.RegisteredTEE memory modifiedReg2 = baseRegistration;
        modifiedReg2.parsedReportBody.xFAM = baseRegistration.parsedReportBody.xFAM ^ bytes8(0x0000000000000002);
        WorkloadId workloadIdNoSSE = policy.workloadIdForTDRegistration(modifiedReg2);
        assertNotEq(
            WorkloadId.unwrap(baseWorkloadId),
            WorkloadId.unwrap(workloadIdNoSSE),
            "Missing SSE bit should change workloadId"
        );

        // Test adding an extra bit changes workloadId
        IFlashtestationRegistry.RegisteredTEE memory modifiedReg3 = baseRegistration;
        modifiedReg3.parsedReportBody.xFAM = baseRegistration.parsedReportBody.xFAM | bytes8(0x0000000000000008);
        WorkloadId workloadIdExtraBit = policy.workloadIdForTDRegistration(modifiedReg3);
        assertNotEq(
            WorkloadId.unwrap(baseWorkloadId),
            WorkloadId.unwrap(workloadIdExtraBit),
            "Additional xFAM bits should change workloadId"
        );
    }

    function test_verifyBlockBuilderProof_fails_with_unregistered_tee() public {
        // Add workload to policy but don't register TEE
        policy.addWorkloadToPolicy(mockf200.workloadId, mockf200.commitHash, mockf200.sourceLocators);

        vm.prank(mockf200.teeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(IBlockBuilderPolicy.UnauthorizedBlockBuilder.selector, mockf200.teeAddress)
        );
        policy.verifyBlockBuilderProof(1, bytes32(0));
    }

    function test_verifyBlockBuilderProof_succeeds_with_valid_tee_and_version() public {
        _registerTEE(mockf200);

        // Get actual workloadId and add to policy
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(mockf200.teeAddress);
        WorkloadId actualWorkloadId = policy.workloadIdForTDRegistration(registration);
        policy.addWorkloadToPolicy(actualWorkloadId, mockf200.commitHash, mockf200.sourceLocators);

        bytes32 blockContentHash = bytes32(hex"1234");
        vm.expectEmit(address(policy));
        emit IBlockBuilderPolicy.BlockBuilderProofVerified(
            mockf200.teeAddress, WorkloadId.unwrap(actualWorkloadId), 1, blockContentHash, mockf200.commitHash
        );

        vm.prank(mockf200.teeAddress);
        policy.verifyBlockBuilderProof(1, blockContentHash);
    }

    function test_upgradeTo_reverts_if_not_owner() public {
        // Deploy a new implementation
        address newImplementation = address(new BlockBuilderPolicy());

        // Try to upgrade as non-owner
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)));
        upgrader.upgradeProxy(address(policy), newImplementation, bytes(""), address(0x123));
    }

    function test_upgradeTo_succeeds_if_owner() public {
        // Deploy a new implementation
        address newImplementation = address(new BlockBuilderPolicy());

        // Upgrade as owner
        upgrader.upgradeProxy(address(policy), newImplementation, bytes(""), address(owner));

        // Verify the implementation was updated
        assertEq(upgrader.getImplementation(address(policy)), newImplementation);
    }

    function test_successful_permitVerifyBlockBuilderProof() public {
        address teeAddress = mock46f6.teeAddress;
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Register TEE
        _registerTEE(mock46f6);

        // Get actual workloadId and add to policy
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(teeAddress);
        WorkloadId actualWorkloadId = policy.workloadIdForTDRegistration(registration);
        policy.addWorkloadToPolicy(actualWorkloadId, mock46f6.commitHash, mock46f6.sourceLocators);

        // Create the EIP-712 signature
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect the event to be emitted
        vm.expectEmit(address(policy));
        emit IBlockBuilderPolicy.BlockBuilderProofVerified(
            teeAddress, WorkloadId.unwrap(actualWorkloadId), version, blockContentHash, mock46f6.commitHash
        );

        // Call the function
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);

        // Verify nonce was incremented
        assertEq(policy.nonces(teeAddress), 1, "Nonce should be incremented");
    }

    function test_successful_permitVerifyBlockBuilderProof_multiple_times() public {
        address teeAddress = mock46f6.teeAddress;
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Register TEE
        _registerTEE(mock46f6);

        // Get actual workloadId and add to policy
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(teeAddress);
        WorkloadId actualWorkloadId = policy.workloadIdForTDRegistration(registration);
        policy.addWorkloadToPolicy(actualWorkloadId, mock46f6.commitHash, mock46f6.sourceLocators);

        // Create the EIP-712 signature
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect the event to be emitted
        vm.expectEmit(address(policy));
        emit IBlockBuilderPolicy.BlockBuilderProofVerified(
            teeAddress, WorkloadId.unwrap(actualWorkloadId), version, blockContentHash, mock46f6.commitHash
        );

        // Call the function
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);

        // Verify nonce was incremented
        assertEq(policy.nonces(teeAddress), 1, "Nonce should be incremented");

        // now build the sign and call the function again with the subsequent nonce

        structHash = policy.computeStructHash(version, blockContentHash, 1);
        digest = policy.getHashedTypeDataV4(structHash);
        (v, r, s) = vm.sign(mock46f6.privateKey, digest);
        signature = abi.encodePacked(r, s, v);

        // Expect the event to be emitted
        vm.expectEmit(address(policy));
        emit IBlockBuilderPolicy.BlockBuilderProofVerified(
            teeAddress, WorkloadId.unwrap(actualWorkloadId), version, blockContentHash, mock46f6.commitHash
        );

        // Call the function
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 1, signature);

        // Verify nonce was incremented
        assertEq(policy.nonces(teeAddress), 2, "Nonce should be incremented");
    }

    function test_permitVerifyBlockBuilderProof_reverts_with_unauthorized_block_builder() public {
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Create signature with wrong private key
        (address invalid_signer, uint256 invalid_pk) = makeAddrAndKey("invalid_signer");

        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(invalid_pk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IBlockBuilderPolicy.UnauthorizedBlockBuilder.selector, invalid_signer));
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);
    }

    function test_permitVerifyBlockBuilderProof_reverts_with_invalid_nonce() public {
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Create signature with wrong nonce
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 1); // wrong nonce
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IBlockBuilderPolicy.InvalidNonce.selector, 0, 1));
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 1, signature);
    }

    function test_permitVerifyBlockBuilderProof_reverts_with_replayed_signature() public {
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Register TEE
        _registerTEE(mock46f6);

        // Get actual workloadId and add to policy
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(mock46f6.teeAddress);
        WorkloadId actualWorkloadId = policy.workloadIdForTDRegistration(registration);
        policy.addWorkloadToPolicy(actualWorkloadId, mock46f6.commitHash, mock46f6.sourceLocators);

        // Create the EIP-712 signature
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First verification should succeed
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);

        // Try to replay the same signature
        vm.expectRevert(abi.encodeWithSelector(IBlockBuilderPolicy.InvalidNonce.selector, 1, 0));
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);
    }
}
