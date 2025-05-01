// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TEERegistry, AppPKI} from "../src/TEERegistry.sol";

contract TEERegistryTest is Test {
    TEERegistry public registry;
    AppPKI public appPKI = AppPKI({
        ca: bytes("0x42"),
        pubkey: bytes("0x42"),
        attestation: bytes("0x42")
    });

    function setUp() public {
        registry = new TEERegistry(address(this));
    }

    function test_SetPKI() public {
        registry.setPKI(appPKI);
        AppPKI memory retrievedPKI = registry.getPKI();
        assertEq0(retrievedPKI.ca, appPKI.ca);
        assertEq0(retrievedPKI.pubkey, appPKI.pubkey);
        assertEq0(retrievedPKI.attestation, appPKI.attestation);
    }

    function testFuzz_SetPKI(bytes memory _ca, bytes memory _pubkey, bytes memory _attestation) public {
        appPKI = AppPKI({
            ca: _ca,
            pubkey: _pubkey,
            attestation: _attestation
        });
        registry.setPKI(appPKI);
        AppPKI memory retrievedPKI = registry.getPKI();
        assertEq0(retrievedPKI.ca, appPKI.ca);
        assertEq0(retrievedPKI.pubkey, appPKI.pubkey);
        assertEq0(retrievedPKI.attestation, appPKI.attestation);
    }
}
