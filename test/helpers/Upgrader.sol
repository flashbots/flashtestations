pragma solidity 0.8.28;

import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Test, console} from "forge-std/Test.sol";

// this is a workaround to allow testing of the upgradeProxy function
// which is internal in the Upgrades contract. See this foundry issue for more context:
// https://github.com/foundry-rs/foundry/issues/10230
contract Upgrader is Test {
    bytes32 public constant IMPLEMENTATION_SLOT =
        bytes32(uint256(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc));

    function upgradeProxy(address proxy, address newImpl, bytes memory data, address tryCaller) external {
        UnsafeUpgrades.upgradeProxy(
            proxy,
            newImpl,
            data,
            tryCaller // Simulate the call coming from nonOwner
        );
    }

    function getImplementation(address proxy) external view returns (address) {
        return address(uint160(uint256(vm.load(address(proxy), IMPLEMENTATION_SLOT))));
    }
}
