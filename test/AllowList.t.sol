// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AllowList} from "../src/AllowList.sol";

contract AllowListTest is Test {
    AllowList public registry;

    function setUp() public {
        registry = new AllowList(address(this));
    }

    function test_SetPKI() public {}

    function testFuzz_SetPKI(bytes memory _ca, bytes memory _pubkey, bytes memory _attestation) public {}
}
