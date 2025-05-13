// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TEERegistry} from "../src/TEERegistry.sol";

contract TEERegistryTest is Test {
    TEERegistry public registry;

    function setUp() public {
        registry = new TEERegistry(address(this));
    }

    function test_SetPKI() public {
    }

    function testFuzz_SetPKI(bytes memory _ca, bytes memory _pubkey, bytes memory _attestation) public {
    }
}
