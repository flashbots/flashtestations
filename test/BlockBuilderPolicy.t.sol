// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";
import {MockQuote} from "../test/FlashtestationRegistry.t.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
import {Upgrader} from "./helpers/Upgrader.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {Helper} from "./helpers/Helper.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

contract BlockBuilderPolicyTest is Test {
    FlashtestationRegistry public registry;
    MockAutomataDcapAttestationFee public attestationContract;
    BlockBuilderPolicy public policy;
    Upgrader public upgrader = new Upgrader();
    address public owner = address(this);

    uint8 version = 1;

    MockQuote bf42Mock = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        ),
        publicKey: hex"bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446",
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote bf42MockWithDifferentWorkloadId = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output2.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote2.bin"
        ),
        publicKey: hex"bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446",
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        workloadId: WorkloadId.wrap(0x5e6be81f9e5b10d15a6fa69b19ab0269cd943db39fa1f0d38a76eb76146948cb),
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote d204Mock = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/quote.bin"
        ),
        publicKey: hex"d204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6",
        teeAddress: 0x12c14e56d585Dcf3B36f37476c00E78bA9363742,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
        privateKey: 0x0000000000000000000000000000000000000000000000000000000000000000 // unused for this mock
    });
    MockQuote mock7b91 = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/7b916d70ed77488d6c1ced7117ba410655a8faa8d6c7740562a88ab3cb9cbca63e2d5761812a11d90c009ed017113131370070cd3a2d5fba64d9dbb76952df19/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/7b916d70ed77488d6c1ced7117ba410655a8faa8d6c7740562a88ab3cb9cbca63e2d5761812a11d90c009ed017113131370070cd3a2d5fba64d9dbb76952df19/quote.bin"
        ),
        publicKey: hex"7b916d70ed77488d6c1ced7117ba410655a8faa8d6c7740562a88ab3cb9cbca63e2d5761812a11d90c009ed017113131370070cd3a2d5fba64d9dbb76952df19",
        teeAddress: 0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e),
        privateKey: 0x92e4b5ed61db615b26da2271da5b47c42d691b3164561cfb4edbc85ca6ca61a8
    });

    WorkloadId arbitraryWorkloadId = WorkloadId.wrap(0x1dd337a1486a84a7d4200553584996abec87a87473d445262d5562f84ec456a8);
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

    function _registerTEE(MockQuote memory mock) internal {
        attestationContract.setQuoteResult(mock.quote, true, mock.output);
        vm.prank(mock.teeAddress);
        registry.registerTEEService(mock.quote);
    }

    function test_addWorkloadToPolicy_and_getters() public {
        // Add a workload
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // getWorkloads should return the workload
        bytes32[] memory workloads = policy.getWorkloads();
        assertEq(workloads.length, 1);
        assertEq(workloads[0], WorkloadId.unwrap(bf42Mock.workloadId));
        // getWorkload(0) should return the same
        bytes32 workload = policy.getWorkload(0);
        assertEq(workload, WorkloadId.unwrap(bf42Mock.workloadId));
    }

    function test_addWorkloadToPolicy_with_multiple_workloads() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        policy.addWorkloadToPolicy(bf42MockWithDifferentWorkloadId.workloadId);
        bytes32[] memory workloads = policy.getWorkloads();
        assertEq(workloads.length, 2);
        assertEq(workloads[0], WorkloadId.unwrap(bf42Mock.workloadId));
        assertEq(workloads[1], WorkloadId.unwrap(bf42MockWithDifferentWorkloadId.workloadId));
    }

    function test_addWorkloadToPolicy_reverts_if_duplicate() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        vm.expectRevert(BlockBuilderPolicy.WorkloadAlreadyInPolicy.selector);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
    }

    function test_addWorkloadToPolicy_reverts_if_not_owner() public {
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)));
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
    }

    function test_removeWorkloadFromPolicy() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        policy.removeWorkloadFromPolicy(bf42Mock.workloadId);
        bytes32[] memory workloads = policy.getWorkloads();
        assertEq(workloads.length, 0);
    }

    function test_removeWorkloadFromPolicy_with_multiple_workloads() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        policy.addWorkloadToPolicy(bf42MockWithDifferentWorkloadId.workloadId);
        policy.removeWorkloadFromPolicy(bf42Mock.workloadId);
        bytes32[] memory workloads = policy.getWorkloads();
        assertEq(workloads.length, 1);
        assertEq(workloads[0], WorkloadId.unwrap(bf42MockWithDifferentWorkloadId.workloadId));

        // now remove the other workload
        policy.removeWorkloadFromPolicy(bf42MockWithDifferentWorkloadId.workloadId);
        workloads = policy.getWorkloads();
        assertEq(workloads.length, 0);

        // now add the workloads back
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        workloads = policy.getWorkloads();
        assertEq(workloads.length, 1);
        assertEq(workloads[0], WorkloadId.unwrap(bf42Mock.workloadId));
        policy.addWorkloadToPolicy(bf42MockWithDifferentWorkloadId.workloadId);
        workloads = policy.getWorkloads();
        assertEq(workloads.length, 2);
        assertEq(workloads[0], WorkloadId.unwrap(bf42Mock.workloadId));
        assertEq(workloads[1], WorkloadId.unwrap(bf42MockWithDifferentWorkloadId.workloadId));
    }

    function test_removeWorkloadFromPolicy_with_multiple_workloads_present() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        policy.addWorkloadToPolicy(arbitraryWorkloadId);
        policy.removeWorkloadFromPolicy(bf42Mock.workloadId);
        bytes32[] memory workloads = policy.getWorkloads();
        assertEq(workloads.length, 1);
        assertEq(workloads[0], WorkloadId.unwrap(arbitraryWorkloadId));
        policy.removeWorkloadFromPolicy(arbitraryWorkloadId);
        workloads = policy.getWorkloads();
        assertEq(workloads.length, 0);
    }

    function test_removeWorkloadFromPolicy_reverts_if_not_present() public {
        vm.expectRevert(BlockBuilderPolicy.WorkloadNotInPolicy.selector);
        policy.removeWorkloadFromPolicy(bf42Mock.workloadId);
    }

    function test_removeWorkloadFromPolicy_reverts_if_not_owner() public {
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)));
        policy.removeWorkloadFromPolicy(bf42Mock.workloadId);
    }

    function test_isAllowedPolicy_returns_true_for_valid_tee() public {
        // Register TEE and add workload to policy
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // Should return true
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertTrue(allowed);
        assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(bf42Mock.workloadId));
    }

    function test_isAllowedPolicy_returns_false_for_unregistered_tee() public {
        // Add workload but do not register TEE
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_isAllowedPolicy_returns_false_for_invalid_quote() public {
        // Register TEE and add workload to policy
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // Now invalidate the TEE
        attestationContract.setQuoteResult(bf42Mock.quote, false, new bytes(0));
        registry.invalidateAttestation(bf42Mock.teeAddress);
        // Should return false
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_isAllowedPolicy_returns_false_for_wrong_workload() public {
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(wrongWorkloadId);
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_isAllowedPolicy_returns_false_for_invalid_tee_when_multiple_workloads_present() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        policy.addWorkloadToPolicy(wrongWorkloadId);
        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertFalse(allowed);
        assertEq(WorkloadId.unwrap(workloadId), 0);
    }

    function test_isAllowedPolicy2_returns_true_for_valid_tee_and_tcb() public {
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        TD10ReportBody memory report = registry.getReportBody(bf42Mock.teeAddress);
        bool allowed = policy.isAllowedPolicy2(bf42Mock.teeAddress, report.teeTcbSvn);
        assertTrue(allowed);
    }

    function test_isAllowedPolicy2_returns_false_for_wrong_tcb() public {
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // Use a random bytes16 for tcb
        bool allowed = policy.isAllowedPolicy2(bf42Mock.teeAddress, bytes16(hex"deadbeef"));
        assertFalse(allowed);
    }

    function test_isAllowedPolicy2_returns_false_for_unregistered_tee() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        TD10ReportBody memory report = QuoteParser.parseV4Quote(bf42Mock.quote);
        vm.expectRevert(
            abi.encodeWithSelector(IFlashtestationRegistry.TEEServiceNotRegistered.selector, bf42Mock.teeAddress)
        );
        policy.isAllowedPolicy2(bf42Mock.teeAddress, report.teeTcbSvn);
    }

    function test_isAllowedPolicy2_returns_false_for_invalid_tee() public {
        // Register TEE and add workload to policy
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // Now invalidate the TEE
        attestationContract.setQuoteResult(bf42Mock.quote, false, new bytes(0));
        registry.invalidateAttestation(bf42Mock.teeAddress);
        // Should return false
        TD10ReportBody memory report = registry.getReportBody(bf42Mock.teeAddress);
        bool allowed = policy.isAllowedPolicy2(bf42Mock.teeAddress, report.teeTcbSvn);
        assertFalse(allowed);
    }

    function test_getWorkload_reverts_on_out_of_bounds() public {
        // Should revert if index is out of bounds
        vm.expectRevert();
        policy.getWorkload(0);
    }

    function test_verifyBlockBuilderProof_fails_with_incorrect_version() public {
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);

        // Try with unsupported version 2
        vm.prank(bf42Mock.teeAddress);
        vm.expectRevert(abi.encodeWithSelector(BlockBuilderPolicy.UnsupportedVersion.selector, 2));
        policy.verifyBlockBuilderProof(2, bytes32(0));
    }

    function test_verifyBlockBuilderProof_fails_with_unregistered_tee() public {
        // Add workload to policy but don't register TEE
        policy.addWorkloadToPolicy(bf42Mock.workloadId);

        vm.prank(bf42Mock.teeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(BlockBuilderPolicy.UnauthorizedBlockBuilder.selector, bf42Mock.teeAddress)
        );
        policy.verifyBlockBuilderProof(1, bytes32(0));
    }

    function test_verifyBlockBuilderProof_succeeds_with_valid_tee_and_version() public {
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);

        bytes32 blockContentHash = bytes32(hex"1234");
        vm.expectEmit(address(policy));
        emit BlockBuilderPolicy.BlockBuilderProofVerified(
            bf42Mock.teeAddress, bf42Mock.workloadId, 1, 1, blockContentHash
        );

        vm.prank(bf42Mock.teeAddress);
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
        address teeAddress = mock7b91.teeAddress;
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Register TEE and add workload to policy
        _registerTEE(mock7b91);
        policy.addWorkloadToPolicy(mock7b91.workloadId);

        // Create the EIP-712 signature
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect the event to be emitted
        vm.expectEmit(address(policy));
        emit BlockBuilderPolicy.BlockBuilderProofVerified(
            teeAddress, mock7b91.workloadId, block.number, version, blockContentHash
        );

        // Call the function
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);

        // Verify nonce was incremented
        assertEq(policy.nonces(teeAddress), 1, "Nonce should be incremented");
    }

    function test_successful_permitVerifyBlockBuilderProof_multiple_times() public {
        address teeAddress = mock7b91.teeAddress;
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Register TEE and add workload to policy
        _registerTEE(mock7b91);
        policy.addWorkloadToPolicy(mock7b91.workloadId);

        // Create the EIP-712 signature
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect the event to be emitted
        vm.expectEmit(address(policy));
        emit BlockBuilderPolicy.BlockBuilderProofVerified(
            teeAddress, mock7b91.workloadId, block.number, version, blockContentHash
        );

        // Call the function
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);

        // Verify nonce was incremented
        assertEq(policy.nonces(teeAddress), 1, "Nonce should be incremented");

        // now build the sign and call the function again with the subsequent nonce

        structHash = policy.computeStructHash(version, blockContentHash, 1);
        digest = policy.getHashedTypeDataV4(structHash);
        (v, r, s) = vm.sign(mock7b91.privateKey, digest);
        signature = abi.encodePacked(r, s, v);

        // Expect the event to be emitted
        vm.expectEmit(address(policy));
        emit BlockBuilderPolicy.BlockBuilderProofVerified(
            teeAddress, mock7b91.workloadId, block.number, version, blockContentHash
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

        vm.expectRevert(abi.encodeWithSelector(BlockBuilderPolicy.UnauthorizedBlockBuilder.selector, invalid_signer));
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);
    }

    function test_permitVerifyBlockBuilderProof_reverts_with_invalid_nonce() public {
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Create signature with wrong nonce
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 1); // wrong nonce
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(BlockBuilderPolicy.InvalidNonce.selector, 0, 1));
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 1, signature);
    }

    function test_permitVerifyBlockBuilderProof_reverts_with_replayed_signature() public {
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Register TEE and add workload to policy
        _registerTEE(mock7b91);
        policy.addWorkloadToPolicy(mock7b91.workloadId);

        // Create the EIP-712 signature
        bytes32 structHash = policy.computeStructHash(version, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First verification should succeed
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);

        // Try to replay the same signature
        vm.expectRevert(abi.encodeWithSelector(BlockBuilderPolicy.InvalidNonce.selector, 1, 0));
        policy.permitVerifyBlockBuilderProof(version, blockContentHash, 0, signature);
    }

    function test_permitVerifyBlockBuilderProof_reverts_with_unsupported_version() public {
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();

        // Create signature with unsupported version
        uint8 unsupportedVersion = 2;
        bytes32 structHash = policy.computeStructHash(unsupportedVersion, blockContentHash, 0);
        bytes32 digest = policy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock7b91.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(BlockBuilderPolicy.UnsupportedVersion.selector, unsupportedVersion));
        policy.permitVerifyBlockBuilderProof(unsupportedVersion, blockContentHash, 0, signature);
    }
}
