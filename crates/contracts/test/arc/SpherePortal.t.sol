// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Capability, Deposit, DepositPayload, DepositType, ISpherePortal, ISphereFactory, FIAT_TOKEN_PROXY } from "../../src/runtime/interfaces/ISphere.sol";
import { INativeFiatToken, SpherePortal } from "../../src/runtime/arc/SpherePortal.sol";
import { MockERC20 } from "../mocks/MockERC20.sol";
import { Vm } from "forge-std/Vm.sol";
import { PortalRuntimeTest } from "../PortalRuntimeTest.sol";

abstract contract SpherePortalFixture is PortalRuntimeTest {

    function _createSpherePortal() internal returns (SpherePortal portal, address initialToken) {
        address[] memory sequencers = new address[](1);
        sequencers[0] = makeAddr("sequencer");
        return _createSpherePortal(sequencers, 1);
    }

    function _createSpherePortal(address[] memory sequencers, uint8 threshold) internal returns (SpherePortal portal, address initialToken) {
        initialToken = FIAT_TOKEN_PROXY;
        _mockToken(initialToken);
        (, address proxy) = factory.createSphere(_params(initialToken, sequencers, threshold));
        portal = SpherePortal(proxy);
    }

    function _mockToken(address initialToken) internal {
        vm.mockCall(
            initialToken, abi.encodeWithSelector(INativeFiatToken.name.selector), abi.encode("USD Coin")
        );
        vm.mockCall(
            initialToken, abi.encodeWithSelector(INativeFiatToken.symbol.selector), abi.encode("USDC")
        );
        vm.mockCall(
            initialToken, abi.encodeWithSelector(INativeFiatToken.currency.selector), abi.encode("USD")
        );
    }

    function _params(address initialToken, address[] memory sequencers, uint8 threshold)
        internal returns (ISphereFactory.CreateSphereParams memory)
    {
        return ISphereFactory.CreateSphereParams({
            initialToken: initialToken,
            accessMode: true,
            gatewayMode: true,
            allowedAccounts: new address[](0),
            sphereGateways: new address[](0),
            admin: makeAddr("admin"),
            sequencers: sequencers,
            threshold: threshold,
            rpcUrl: ""
        });
    }

}

contract SpherePortalProxyStorageTest is SpherePortalFixture {

    function test_pause_blocksClaimRefund() public {
        (SpherePortal portal, address initialToken) = _createSpherePortal();
        vm.prank(makeAddr("sequencer"));
        portal.pause();
        vm.prank(makeAddr("alice"));
        vm.expectRevert(ISpherePortal.PortalIsPaused.selector);
        portal.claimRefund(initialToken);
    }

    function test_setTransfersEnabled_defaultsOffAndToggles() public {
        (SpherePortal portal,) = _createSpherePortal();
        address admin = makeAddr("admin");
        assertFalse(portal.transfersEnabled());

        vm.expectEmit(false, false, false, true);
        emit ISpherePortal.TransfersEnabledUpdated(true);
        vm.prank(admin);
        portal.setTransfersEnabled(true);
        assertTrue(portal.transfersEnabled());

        vm.expectEmit(false, false, false, true);
        emit ISpherePortal.TransfersEnabledUpdated(false);
        vm.prank(admin);
        portal.setTransfersEnabled(false);
        assertFalse(portal.transfersEnabled());
    }

    function test_setTransfersEnabled_revertsIfNotAdmin() public {
        (SpherePortal portal,) = _createSpherePortal();
        vm.prank(makeAddr("alice"));
        vm.expectRevert(ISpherePortal.NotAdmin.selector);
        portal.setTransfersEnabled(true);
    }

    function test_setTransfersEnabled_revertsAfterAccessPolicyAbdication() public {
        (SpherePortal portal,) = _createSpherePortal();
        address admin = makeAddr("admin");
        vm.prank(admin);
        portal.abdicate(Capability.AccessPolicy);
        vm.warp(block.timestamp + 30 days);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISpherePortal.CapabilityAbdicated.selector, Capability.AccessPolicy
            )
        );
        portal.setTransfersEnabled(true);
        assertFalse(portal.transfersEnabled());
    }

    function test_initializeEnablesUSDC() public {
        (SpherePortal portal, address initialToken) = _createSpherePortal();
        assertTrue(portal.isTokenEnabled(initialToken));
    }

    function test_initializeRevertsForOtherToken() public {
        address initialToken = makeAddr("initial token");
        address[] memory sequencers = new address[](1);
        sequencers[0] = makeAddr("sequencer");
        ISphereFactory.CreateSphereParams memory params = _params(initialToken, sequencers, 1);
        vm.expectRevert(ISphereFactory.InvalidToken.selector);
        factory.createSphere(params);
    }

    bytes32 internal constant VALID_SECP256K1_X =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;

    function _makeDepositPayload() internal pure returns (DepositPayload memory) {
        return DepositPayload({
            ephemeralPubkeyX: VALID_SECP256K1_X,
            ephemeralPubkeyYParity: 0x02,
            ciphertext: new bytes(64),
            nonce: bytes12(0),
            tag: bytes16(0)
        });
    }

    function test_deposit_revertsWhenBouncebackRecipientBlocked() public {
        (SpherePortal portal, address initialToken) = _createSpherePortal();
        uint128 depositAmount = 1000e6;
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        vm.startPrank(makeAddr("admin"));
        portal.setAllowedAccount(alice, true);
        portal.setAllowedAccount(bob, true);
        vm.stopPrank();

        bytes memory callData = abi.encodeCall(INativeFiatToken.isBlacklisted, (bob));
        vm.mockCall(initialToken, callData, abi.encode(true));
        vm.expectCall(initialToken, callData);
        vm.prank(alice);
        vm.expectRevert(ISpherePortal.InvalidBouncebackRecipient.selector);
        portal.deposit(initialToken, depositAmount, 0, _makeDepositPayload(), bob);
    }

    uint256 internal constant ENC_KEY_1 = 1; // pubkey = G (generator point)

    function _setEncKeyWithPoP(SpherePortal portal, uint256 privateKey) internal returns (bytes32 x, uint8 yParity) {
        Vm.Wallet memory w = vm.createWallet(privateKey);
        x = bytes32(w.publicKeyX);
        yParity = w.publicKeyY % 2 == 0 ? 0x02 : 0x03;
        bytes32 message = keccak256(abi.encode(address(portal), x, yParity));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(w.privateKey, message);
        portal.setSequencerEncryptionKey(x, yParity, v, r, s);
    }

    function test_deposit_success() public {
        (SpherePortal portal, address initialToken) = _createSpherePortal();
        address alice = makeAddr("alice");
        vm.startPrank(makeAddr("admin"));
        portal.setAllowedAccount(alice, true);
        _setEncKeyWithPoP(portal, ENC_KEY_1);
        vm.stopPrank();

        uint128 depositAmount = 1000e6;
        vm.etch(initialToken, vm.getDeployedCode("MockERC20.sol:MockERC20"));
        MockERC20 usdc = MockERC20(initialToken);
        deal(initialToken, alice, depositAmount);
        vm.mockCall(initialToken, abi.encodeCall(INativeFiatToken.isBlacklisted, (alice)), abi.encode(false));
        uint128 fee = portal.calculateDepositFee();
        uint128 netAmount = depositAmount - fee;

        DepositPayload memory encrypted = _makeDepositPayload();

        vm.startPrank(alice);
        usdc.approve(address(portal), depositAmount);
        bytes32 hash =
            portal.deposit(address(usdc), depositAmount, 0, encrypted, alice);
        vm.stopPrank();

        assertEq(usdc.balanceOf(address(portal)), depositAmount);
        assertEq(portal.depositCount(), 1);
        assertEq(portal.currentDepositQueueHash(), hash);
        assertTrue(hash != bytes32(0));

        // Reconstruct expected hash using the same encoding as DepositQueueLib
        Deposit memory ed = Deposit({
            token: address(usdc),
            sender: alice,
            amount: netAmount,
            arcRefundRecipient: alice,
            keyIndex: 0,
            encrypted: encrypted
        });
        bytes32 expectedHash = keccak256(abi.encode(DepositType.Deposit, ed, bytes32(0)));
        assertEq(hash, expectedHash);
    }

}
