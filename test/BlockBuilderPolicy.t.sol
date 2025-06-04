// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";
import {FlashtestationRegistry, RegisteredTEE} from "../src/FlashtestationRegistry.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {Helper} from "./helpers/Helper.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

contract BlockBuilderPolicyTest is Test {
    FlashtestationRegistry public registry;
    MockAutomataDcapAttestationFee public attestationContract;
    BlockBuilderPolicy public policy;
    address public owner = address(this);

    // Use the same mock quote structure as FlashtestationRegistry.t.sol
    struct MockQuote {
        bytes output;
        bytes quote;
        address teeAddress;
        bytes publicKey;
        WorkloadId workloadId;
    }

    MockQuote bf42Mock = MockQuote({
        output: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin"
        ),
        quote: vm.readFileBinary(
            "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin"
        ),
        publicKey: hex"bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446",
        teeAddress: 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03,
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e)
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
        workloadId: WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e)
    });
    WorkloadId wrongWorkloadId = WorkloadId.wrap(0x20ab431377d40de192f7c754ac0f1922de05ab2f73e74204f0b3ab73a8856876);

    function setUp() public {
        attestationContract = new MockAutomataDcapAttestationFee();
        registry = new FlashtestationRegistry(address(attestationContract));
        policy = new BlockBuilderPolicy(address(registry), owner);
    }

    function _registerTEE(MockQuote memory mock) internal {
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mock.output);
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

    function test_addWorkloadToPolicy_reverts_if_duplicate() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        vm.expectRevert(BlockBuilderPolicy.WorkloadAlreadyInPolicy.selector);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
    }

    function test_removeWorkloadFromPolicy() public {
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        policy.removeWorkloadFromPolicy(bf42Mock.workloadId);
        bytes32[] memory workloads = policy.getWorkloads();
        assertEq(workloads.length, 0);
    }

    function test_removeWorkloadFromPolicy_reverts_if_not_present() public {
        vm.expectRevert(BlockBuilderPolicy.WorkloadNotInPolicy.selector);
        policy.removeWorkloadFromPolicy(bf42Mock.workloadId);
    }

    function test_isAllowedPolicy_returns_true_for_valid_tee() public {
        // Register TEE and add workload to policy
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // Should return true
        bool allowed = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertTrue(allowed);
    }

    function test_isAllowedPolicy_returns_false_for_unregistered_tee() public {
        // Add workload but do not register TEE
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        bool allowed = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertFalse(allowed);
    }

    function test_isAllowedPolicy_returns_false_for_invalid_quote() public {
        // Register TEE and add workload to policy
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // Now invalidate the TEE
        attestationContract.setSuccess(false);
        registry.invalidateAttestation(bf42Mock.teeAddress);
        // Should return false
        bool allowed = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertFalse(allowed);
    }

    function test_isAllowedPolicy_returns_false_for_wrong_workload() public {
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(wrongWorkloadId);
        bool allowed = policy.isAllowedPolicy(bf42Mock.teeAddress);
        assertFalse(allowed);
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
            abi.encodeWithSelector(FlashtestationRegistry.TEEServiceNotRegistered.selector, bf42Mock.teeAddress)
        );
        policy.isAllowedPolicy2(bf42Mock.teeAddress, report.teeTcbSvn);
    }

    function test_isAllowedPolicy2_returns_false_for_invalid_tee() public {
        // Register TEE and add workload to policy
        _registerTEE(bf42Mock);
        policy.addWorkloadToPolicy(bf42Mock.workloadId);
        // Now invalidate the TEE
        attestationContract.setSuccess(false);
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
}
