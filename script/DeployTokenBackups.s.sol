// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {TokenBackups} from "../src/TokenBackups.sol";

contract DeployTokenBackups is Script {
    address permit2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    function setUp() public {}

    function run() public returns (TokenBackups tokenBackup) {
        vm.startBroadcast();
        tokenBackup = new TokenBackups(permit2);
        vm.stopBroadcast();
        console2.log("TokenBackup deployed:", address(tokenBackup));
    }
}
