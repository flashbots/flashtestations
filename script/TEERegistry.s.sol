// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TEERegistry} from "../src/TEERegistry.sol";

contract TEERegistryScript is Script {
    TEERegistry public registry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address initialOwner = vm.envAddress("REGISTRY_INITIAL_OWNER");
        console.log("REGISTRY_INITIAL_OWNER:", initialOwner);

        registry = new TEERegistry(initialOwner);

        vm.stopBroadcast();
    }
}
