// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FIAT_TOKEN_PROXY, ISphereFactory, SphereInfo } from "../../src/runtime/interfaces/ISphere.sol";
import { SpherePortal } from "../../src/runtime/arc/SpherePortal.sol";
import { SpherePortalFixture } from "./SpherePortal.t.sol";
import { Vm } from "forge-std/Vm.sol";

contract SphereFactoryTest is SpherePortalFixture {

    address internal admin;
    address internal sequencer;
    address internal alice;

    function setUp() public override {
        super.setUp();
        _mockToken(FIAT_TOKEN_PROXY);
        admin = makeAddr("admin");
        sequencer = makeAddr("sequencer");
        alice = makeAddr("alice");
    }

    function _sequencers(address member) internal pure returns (address[] memory members) {
        members = new address[](1);
        members[0] = member;
    }

    function _defaultParams() internal returns (ISphereFactory.CreateSphereParams memory) {
        return _params(FIAT_TOKEN_PROXY, _sequencers(sequencer), 1);
    }

    function test_createSphere_success() public {
        ISphereFactory.CreateSphereParams memory params = _defaultParams();
        params.rpcUrl = "https://sphere.example";

        vm.recordLogs();
        (uint32 sphereId, address portal) = factory.createSphere(params);

        assertEq(sphereId, 1);
        assertEq(factory.nextSphereId(), 2);
        assertTrue(factory.isSpherePortal(portal));

        SphereInfo memory info = factory.spheres(sphereId);
        assertEq(info.sphereId, sphereId);
        assertEq(info.portal, portal);
        assertEq(info.admin, admin);
        assertEq(info.sequencers, params.sequencers);
        assertEq(info.threshold, 1);
        assertEq(info.verifier, factory.verifier());
        assertEq(info.rpcUrl, params.rpcUrl);

        SpherePortal created = SpherePortal(portal);
        assertEq(created.admin(), admin);
        assertEq(created.sequencerAt(0), sequencer);
        assertEq(created.sequencerThreshold(), 1);
        assertEq(created.verifier(), factory.verifier());
        assertEq(created.messenger(), factory.messenger());
        assertEq(created.blockHash(), bytes32(0));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 signature =
            keccak256("SphereCreated(uint32,address,address,bool,bool,address,address[],uint8,address)");
        bool found;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == signature) found = true;
        }
        assertTrue(found, "SphereCreated event not found");
    }

    function test_createSphere_revertsForNonOwner() public {
        ISphereFactory.CreateSphereParams memory params = _defaultParams();
        vm.prank(alice);
        vm.expectRevert(ISphereFactory.NotOwner.selector);
        factory.createSphere(params);
    }

    function test_createSphere_revertsForInvalidInputs() public {
        ISphereFactory.CreateSphereParams memory params = _defaultParams();
        params.initialToken = address(0);
        vm.expectRevert(ISphereFactory.InvalidToken.selector);
        factory.createSphere(params);

        params = _defaultParams();
        params.admin = address(0);
        vm.expectRevert(ISphereFactory.InvalidAdmin.selector);
        factory.createSphere(params);

        params = _defaultParams();
        params.sequencers[0] = address(0);
        vm.expectRevert(ISphereFactory.InvalidSequencerSet.selector);
        factory.createSphere(params);

        params = _defaultParams();
        params.threshold = 2;
        vm.expectRevert(ISphereFactory.InvalidSequencerSet.selector);
        factory.createSphere(params);
    }

    function test_createSphere_acceptsUnsortedUniqueSequencers() public {
        ISphereFactory.CreateSphereParams memory params = _defaultParams();
        params.sequencers = new address[](2);
        params.sequencers[0] = address(0x200);
        params.sequencers[1] = address(0x100);
        params.threshold = 2;

        (uint32 sphereId,) = factory.createSphere(params);
        assertEq(factory.spheres(sphereId).sequencers, params.sequencers);
    }

    function test_transferOwnership_allowsZeroAddress() public {
        vm.expectEmit(true, true, false, false);
        emit ISphereFactory.OwnershipTransferred(address(this), address(0));
        factory.transferOwnership(address(0));
        assertEq(factory.owner(), address(0));
    }

    function test_spheres_areCreationSnapshots() public {
        (uint32 id, address portal) = factory.createSphere(_defaultParams());
        address[] memory replacement = new address[](2);
        replacement[0] = alice;
        replacement[1] = sequencer;

        vm.prank(admin);
        SpherePortal(portal).setSequencerSet(replacement, 1);

        assertEq(SpherePortal(portal).sequencerAt(0), alice);
        assertEq(factory.spheres(id).sequencers[0], sequencer);
    }

}
