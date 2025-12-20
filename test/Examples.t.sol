// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {DualDeriverPolicy} from "../examples/DualDeriverPolicy.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";
import {WorkloadId} from "../src/interfaces/IPolicyCommon.sol";
import {TDXTD15WorkloadDeriver} from "../examples/TDXTD15WorkloadDeriver.sol";
import {TDXWorkloadDeriver} from "../src/derivers/TDXWorkloadDeriver.sol";

contract MockRegistryAlwaysValid {
    bytes32 public quoteHash;
    bytes public rawQuote;

    constructor(bytes32 quoteHash_, bytes memory rawQuote_) {
        quoteHash = quoteHash_;
        rawQuote = rawQuote_;
    }

    function getRegistration(address)
        external
        view
        returns (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registeredTEE)
    {
        IFlashtestationRegistry.RegisteredTEE memory reg;
        reg.isValid = true;
        reg.quoteHash = quoteHash;
        reg.rawQuote = rawQuote;
        return (true, reg);
    }

    function getRegistrationStatus(address) external view returns (bool isValid, bytes32 quoteHash_) {
        return (true, quoteHash);
    }
}

contract ExamplesTest is Test {
    function test_example_dual_deriver_policy_allows_td10_quote_via_old_deriver() public {
        TDXWorkloadDeriver oldDeriver = new TDXWorkloadDeriver();
        TDXTD15WorkloadDeriver newDeriver = new TDXTD15WorkloadDeriver();

        bytes memory td10Quote =
            vm.readFileBinary("test/raw_tdx_quotes/0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF/quote.bin");
        MockRegistryAlwaysValid registry = new MockRegistryAlwaysValid(keccak256(td10Quote), td10Quote);

        DualDeriverPolicy policy = new DualDeriverPolicy(address(this), address(registry), oldDeriver, newDeriver);

        WorkloadId idToApprove = oldDeriver.workloadIdForQuote(td10Quote);
        string[] memory locators = new string[](1);
        locators[0] = "ipfs://example";
        policy.addWorkloadToPolicy(idToApprove, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", locators);

        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(address(0xBEEF));
        assertTrue(allowed);
        assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(idToApprove));
    }

    function test_example_dual_deriver_policy_allows_td15_report_via_new_deriver() public {
        TDXWorkloadDeriver oldDeriver = new TDXWorkloadDeriver();
        TDXTD15WorkloadDeriver newDeriver = new TDXTD15WorkloadDeriver();

        // Build a synthetic TD15 report body (648 bytes) and store it as the registry's "rawQuote" for the example.
        bytes memory td15Report = new bytes(648);
        // Set mrConfigId (48 bytes) to a non-zero value for determinism.
        for (uint256 i = 0; i < 48; i++) {
            td15Report[184 + i] = bytes1(uint8(i + 1));
        }
        // Set mrServiceTd (48 bytes) to a different non-zero value.
        for (uint256 i = 0; i < 48; i++) {
            td15Report[600 + i] = bytes1(uint8(0xAA));
        }

        MockRegistryAlwaysValid registry = new MockRegistryAlwaysValid(keccak256(td15Report), td15Report);
        DualDeriverPolicy policy = new DualDeriverPolicy(address(this), address(registry), oldDeriver, newDeriver);

        WorkloadId workloadIdToApprove = newDeriver.workloadIdForQuote(td15Report);
        string[] memory locators = new string[](1);
        locators[0] = "ipfs://example";
        policy.addWorkloadToPolicy(workloadIdToApprove, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", locators);

        (bool allowed, WorkloadId workloadId) = policy.isAllowedPolicy(address(0xBEEF));
        assertTrue(allowed);
        assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(workloadIdToApprove));
    }

    function test_example_dual_deriver_policy_rejects_non_owner_updates() public {
        TDXWorkloadDeriver oldDeriver = new TDXWorkloadDeriver();
        TDXTD15WorkloadDeriver newDeriver = new TDXTD15WorkloadDeriver();

        bytes memory td15Report = new bytes(648);
        for (uint256 i = 0; i < 48; i++) {
            td15Report[184 + i] = bytes1(uint8(i + 1));
        }
        for (uint256 i = 0; i < 48; i++) {
            td15Report[600 + i] = bytes1(uint8(0xAA));
        }

        MockRegistryAlwaysValid registry = new MockRegistryAlwaysValid(keccak256(td15Report), td15Report);
        DualDeriverPolicy policy = new DualDeriverPolicy(address(this), address(registry), oldDeriver, newDeriver);

        WorkloadId workloadIdToApprove = newDeriver.workloadIdForQuote(td15Report);
        string[] memory locators = new string[](1);
        locators[0] = "ipfs://example";

        vm.prank(address(0x123));
        vm.expectRevert(bytes("NotOwner"));
        policy.addWorkloadToPolicy(workloadIdToApprove, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", locators);
    }

    function test_example_td15_derivation_hashes_extra_fields() public {
        TDXTD15WorkloadDeriver deriver = new TDXTD15WorkloadDeriver();

        bytes memory td15ReportA = new bytes(648);
        bytes memory td15ReportB = new bytes(648);

        // Make base measurements identical...
        for (uint256 i = 0; i < 48; i++) {
            td15ReportA[184 + i] = bytes1(uint8(i + 1)); // mrConfigId
            td15ReportB[184 + i] = bytes1(uint8(i + 1));
            td15ReportA[600 + i] = bytes1(uint8(0x11)); // mrServiceTd
            td15ReportB[600 + i] = bytes1(uint8(0x11));
        }
        // ...but flip teeTcbSvn2 (16 bytes at offset 584).
        td15ReportB[584] = bytes1(uint8(0xFF));

        WorkloadId idA = deriver.workloadIdForQuote(td15ReportA);
        WorkloadId idB = deriver.workloadIdForQuote(td15ReportB);
        assertNotEq(WorkloadId.unwrap(idA), WorkloadId.unwrap(idB));
    }
}

