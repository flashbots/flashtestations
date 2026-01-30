// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";
import {IBlockBuilderPolicy} from "../src/interfaces/IBlockBuilderPolicy.sol";
import {TDXWorkloadDeriver} from "../src/derivers/TDXWorkloadDeriver.sol";
import {WorkloadId} from "../src/interfaces/IPolicyCommon.sol";

import {LegacyBlockBuilderPolicy} from "./fixtures/LegacyBlockBuilderPolicy.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {Upgrader} from "./helpers/Upgrader.sol";
import {Helper} from "./helpers/Helper.sol";

contract UpgradeRegressionTest is Test {
    using ECDSA for bytes32;

    MockAutomataDcapAttestationFee public attestationContract;
    FlashtestationRegistry public registry;
    Upgrader public upgrader = new Upgrader();

    address public owner = address(this);

    struct QuoteFixture {
        bytes output;
        bytes quote;
        address teeAddress;
        uint256 privateKey;
    }

    QuoteFixture mock46f6 = QuoteFixture({
        output: vm.readFileBinary("test/raw_tdx_quotes/0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF/output.bin"),
        quote: vm.readFileBinary("test/raw_tdx_quotes/0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF/quote.bin"),
        teeAddress: 0x46f6b3ACF1dD8Ac0085e30192741336c4aF6EdAF,
        privateKey: 0x92e4b5ed61db615b26da2271da5b47c42d691b3164561cfb4edbc85ca6ca61a8
    });

    function setUp() public {
        attestationContract = new MockAutomataDcapAttestationFee();
        address registryImplementation = address(new FlashtestationRegistry());
        address registryProxy = UnsafeUpgrades.deployUUPSProxy(
            registryImplementation,
            abi.encodeCall(FlashtestationRegistry.initialize, (owner, address(attestationContract)))
        );
        registry = FlashtestationRegistry(registryProxy);
    }

    function _registerTEE(QuoteFixture memory q) internal {
        attestationContract.setQuoteResult(q.quote, true, q.output);
        vm.prank(q.teeAddress);
        registry.registerTEEService(q.quote, bytes(""));
    }

    function test_upgrade_preserves_storage_layout_and_behavior() public {
        // 1) Deploy legacy policy behind a proxy
        address legacyImpl = address(new LegacyBlockBuilderPolicy());
        address policyProxy = UnsafeUpgrades.deployUUPSProxy(
            legacyImpl, abi.encodeCall(LegacyBlockBuilderPolicy.initialize, (owner, address(registry), address(0)))
        );
        LegacyBlockBuilderPolicy legacy = LegacyBlockBuilderPolicy(policyProxy);

        // 2) Register TEE and approve its workload in the legacy policy
        _registerTEE(mock46f6);
        (, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(mock46f6.teeAddress);
        WorkloadId workloadId = legacy.workloadIdForTDRegistration(registration);

        string[] memory locators = new string[](1);
        locators[0] = "ipfs://example";
        string memory commitHash = "1234567890abcdef1234567890abcdef12345678";
        legacy.addWorkloadToPolicy(workloadId, commitHash, locators);

        // 3) Exercise nonce storage in legacy via permit flow
        bytes32 blockContentHash = Helper.computeFlashtestationBlockContentHash();
        bytes32 structHash = legacy.computeStructHash(1, blockContentHash, 0);
        bytes32 digest = legacy.getHashedTypeDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(mock46f6.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        legacy.permitVerifyBlockBuilderProof(1, blockContentHash, 0, signature);
        assertEq(legacy.nonces(mock46f6.teeAddress), 1);

        // 4) Upgrade to the new implementation
        address newImpl = address(new BlockBuilderPolicy());
        upgrader.upgradeProxy(policyProxy, newImpl, bytes(""), owner);

        BlockBuilderPolicy policy = BlockBuilderPolicy(policyProxy);

        // 5) Configure the new deriver (new storage variable added in gap slot)
        TDXWorkloadDeriver deriver = new TDXWorkloadDeriver();
        policy.setWorkloadDeriver(address(deriver));

        // 6) Storage assertions
        assertEq(policy.registry(), address(registry));
        assertEq(policy.nonces(mock46f6.teeAddress), 1, "nonce should be preserved across upgrade");

        IBlockBuilderPolicy.WorkloadMetadata memory meta = policy.getWorkloadMetadata(workloadId);
        assertEq(meta.commitHash, commitHash, "workload metadata should be preserved across upgrade");

        // 7) Behavioral assertion: isAllowedPolicy still works after upgrade
        (bool allowed, WorkloadId derivedId) = policy.isAllowedPolicy(mock46f6.teeAddress);
        assertTrue(allowed);
        assertEq(WorkloadId.unwrap(derivedId), WorkloadId.unwrap(workloadId));

        // 8) Permit flow still works post-upgrade (nonce increments from preserved value)
        structHash = policy.computeStructHash(1, blockContentHash, 1);
        digest = policy.getHashedTypeDataV4(structHash);
        (v, r, s) = vm.sign(mock46f6.privateKey, digest);
        signature = abi.encodePacked(r, s, v);
        policy.permitVerifyBlockBuilderProof(1, blockContentHash, 1, signature);
        assertEq(policy.nonces(mock46f6.teeAddress), 2);
    }
}

