// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Verifier } from "../../src/runtime/arc/Verifier.sol";
import {
    BlockTransition,
    DepositQueueTransition,
    SphereInfo,
    TokenEnablementTransition
} from "../../src/runtime/interfaces/ISphere.sol";
import { Test } from "forge-std/Test.sol";

contract VerifierTest is Test {

    address internal constant PORTAL = address(0x1234);

    function spheres(uint32 id) external pure returns (SphereInfo memory info) {
        if (id == 1) info.portal = PORTAL;
    }

    function _verify(
        Verifier verifier,
        address caller,
        uint32 sphereId,
        bytes memory config,
        bytes memory proof
    )
        internal
        returns (bool)
    {
        vm.prank(caller);
        return verifier.verify(
            sphereId,
            1,
            1,
            bytes32("anchor"),
            1,
            10,
            BlockTransition({ prevBlockHash: bytes32("prev"), nextBlockHash: bytes32("next") }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32("deposits"),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            TokenEnablementTransition({ prevProcessedTokenCount: 0, nextProcessedTokenCount: 0 }),
            bytes32("withdrawals"),
            config,
            proof
        );
    }

    function test_noProofRequiresCanonicalPortalAndEmptyProof() public {
        Verifier verifier = new Verifier();
        assertTrue(_verify(verifier, PORTAL, 1, hex"02", ""));
        assertFalse(_verify(verifier, address(this), 1, hex"02", ""));
        assertFalse(_verify(verifier, PORTAL, 2, hex"02", ""));
        assertFalse(_verify(verifier, PORTAL, 1, hex"02", hex"01"));
        assertFalse(_verify(verifier, PORTAL, 1, "", ""));
        assertFalse(_verify(verifier, PORTAL, 1, hex"00", ""));
        assertFalse(_verify(verifier, PORTAL, 1, hex"0102", ""));
        assertFalse(_verify(verifier, PORTAL, 1, hex"03", ""));
    }

}
