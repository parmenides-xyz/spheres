// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { SphereFactory } from "../src/runtime/arc/SphereFactory.sol";
import { Test } from "forge-std/Test.sol";

abstract contract PortalRuntimeTest is Test {

    SphereFactory internal factory;

    function setUp() public virtual {
        factory = SphereFactory(deployCode("SphereFactory.sol:SphereFactory"));
    }

}
