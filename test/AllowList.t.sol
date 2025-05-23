// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AllowList} from "../src/AllowList.sol";

contract AllowListTest is Test {
    AllowList public registry;

    function setUp() public {
        registry = new AllowList(address(this));
    }

    function test_registerTEEService() public {}

    function testFuzz_registerTEEService(bytes memory _quote) public {}
}
