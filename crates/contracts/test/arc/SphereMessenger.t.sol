// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    IWithdrawalReceiver,
    ISpherePortal,
    MAX_WITHDRAWAL_CALLBACK_GAS,
    Role,
    SphereInfo
} from "../../src/runtime/interfaces/ISphere.sol";
import { SphereMessenger } from "../../src/runtime/arc/SphereMessenger.sol";
import { Test } from "forge-std/Test.sol";
import { MockERC20 } from "../mocks/MockERC20.sol";
contract MockSphereFactoryForMessenger {

    mapping(uint32 => SphereInfo) internal _spheres;

    function setPortal(uint32 sphereId, address portal) external {
        _spheres[sphereId].sphereId = sphereId;
        _spheres[sphereId].portal = portal;
    }

    function spheres(uint32 id) external view returns (SphereInfo memory) {
        return _spheres[id];
    }

}

contract AcceptingWithdrawalReceiver is IWithdrawalReceiver {

    uint32 public lastSphereId;
    address public lastSourcePortal;
    bytes32 public lastSenderTag;
    address public lastToken;
    uint128 public lastAmount;
    bytes public lastData;

    function onWithdrawalReceived(
        uint32 sphereId,
        address sourcePortal,
        bytes32 senderTag,
        address token,
        uint128 amount,
        bytes calldata callbackData
    )
        external
        returns (bytes4)
    {
        lastSphereId = sphereId;
        lastSourcePortal = sourcePortal;
        lastSenderTag = senderTag;
        lastToken = token;
        lastAmount = amount;
        lastData = callbackData;
        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}

contract SphereMessengerTest is Test {

    uint32 internal constant SPHERE_ID = 1;
    uint32 internal constant OTHER_SPHERE_ID = 2;
    uint64 internal constant CALLBACK_GAS_LIMIT = MAX_WITHDRAWAL_CALLBACK_GAS;

    MockSphereFactoryForMessenger public messengerFactory;
    SphereMessenger public messenger;
    MockERC20 public sphereToken;

    address public portal = address(0x700);
    address public otherPortal = address(0x702);
    address public token = 0x3600000000000000000000000000000000000000;
    address public alice = address(0x200);

    function setUp() public {
        messengerFactory = new MockSphereFactoryForMessenger();
        messengerFactory.setPortal(SPHERE_ID, portal);
        messengerFactory.setPortal(OTHER_SPHERE_ID, otherPortal);

        messenger = new SphereMessenger(address(messengerFactory));
        vm.mockCall(
            portal, abi.encodeWithSelector(ISpherePortal.isGatewayOpen.selector), abi.encode(false)
        );
        vm.etch(token, vm.getDeployedCode("MockERC20.sol:MockERC20"));
        sphereToken = MockERC20(token);
    }

    function _allowGateway(address target) internal {
        vm.mockCall(
            portal,
            abi.encodeWithSelector(ISpherePortal.hasRole.selector, target, Role.CallbackGateway),
            abi.encode(true)
        );
    }

    function _callback() internal pure returns (bytes memory) {
        return hex"010203";
    }

    function test_sphereFactoryConstant() public view {
        assertEq(address(messenger.sphereFactory()), address(messengerFactory));
    }

    function test_relayMessage_revertsUnauthorizedPortalForNonPortalCaller() public {
        vm.expectRevert(SphereMessenger.UnauthorizedPortal.selector);
        messenger.relayMessage(SPHERE_ID, token, bytes32("sender"), alice, 1, 50_000, "");
    }

    function test_relayMessage_revertsUnauthorizedPortalForWrongSphereId() public {
        vm.prank(portal);
        vm.expectRevert(SphereMessenger.UnauthorizedPortal.selector);
        messenger.relayMessage(OTHER_SPHERE_ID, token, bytes32("sender"), alice, 1, 50_000, "");
    }

    function test_relayMessage_successWithFlattenedFactoryGetter() public {
        AcceptingWithdrawalReceiver receiver = new AcceptingWithdrawalReceiver();
        bytes32 senderTag = keccak256("sender");
        bytes memory data = _callback();
        deal(token, address(messenger), 123);
        _allowGateway(address(receiver));

        vm.prank(portal);
        messenger.relayMessage(
            SPHERE_ID, address(sphereToken), senderTag, address(receiver), 123, CALLBACK_GAS_LIMIT, data
        );

        assertEq(sphereToken.balanceOf(address(receiver)), 123);
        assertEq(receiver.lastSphereId(), SPHERE_ID);
        assertEq(receiver.lastSourcePortal(), portal);
        assertEq(receiver.lastSenderTag(), senderTag);
        assertEq(receiver.lastToken(), address(sphereToken));
        assertEq(receiver.lastAmount(), 123);
        assertEq(receiver.lastData(), data);
    }

    function test_relayMessage_revertsForUnregisteredGateway() public {
        AcceptingWithdrawalReceiver receiver = new AcceptingWithdrawalReceiver();
        vm.mockCall(
            portal,
            abi.encodeWithSelector(
                ISpherePortal.hasRole.selector, address(receiver), Role.CallbackGateway
            ),
            abi.encode(false)
        );

        vm.prank(portal);
        vm.expectRevert(SphereMessenger.InvalidCallbackTarget.selector);
        messenger.relayMessage(
            SPHERE_ID,
            address(sphereToken),
            bytes32("sender"),
            address(receiver),
            1,
            50_000,
            _callback()
        );
    }

}
