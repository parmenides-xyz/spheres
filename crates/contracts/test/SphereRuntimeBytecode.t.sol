// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Test } from "forge-std/Test.sol";
import { ARC_STATE } from "../src/runtime/interfaces/ISphere.sol";
import { SphereInbox } from "../src/runtime/sphere/SphereInbox.sol";
import { SphereOutbox } from "../src/runtime/sphere/SphereOutbox.sol";

contract SphereRuntimeBytecodeTest is Test {
    function testGenesisRuntimeMatchesConstructors() public {
        assertEq(
            address(new SphereInbox(address(0), ARC_STATE)).code,
            vm.readFileBinary("assets/runtime/SphereInbox.bin")
        );
        assertEq(
            address(new SphereOutbox(address(0), ARC_STATE)).code,
            vm.readFileBinary("assets/runtime/SphereOutbox.bin")
        );
    }
}
